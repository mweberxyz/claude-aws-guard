// A throwaway project for one `claude` run: the guard installed the manual way (examples/settings.json),
// a logging hook beside it, a fake `aws` that only records that it ran, and a mock API in place of the
// real one. No credentials exist anywhere, and the child gets a minimal environment.
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Observation } from "./lib";
import { startMockApi, type MockApi } from "./mock_api";

const ROOT = join(import.meta.dir, "..", "..");

export interface Sandbox {
  dir: string;
  project: string;
  // Environment for the `claude` child: only what it needs.
  env: Record<string, string>;
  mock: MockApi;
  observe(): Observation;
  // Stops the mock API.
  close(): void;
}

const read = (path: string) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
};

// The prompt is irrelevant: the mock API asks for `command` whatever it says.
export const PROMPT = "Run the command.";

export function makeSandbox(command: string): Sandbox {
  const dir = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), "aws-guard-compat-"));
  const home = join(dir, "home");
  const project = join(dir, "project");
  const bin = join(dir, "bin");
  const hookLog = join(dir, "hook.log");
  const shimLog = join(dir, "shim.log");
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(join(project, ".claude", "hooks", "aws-guard"), { recursive: true });
  mkdirSync(bin);

  // The built file, where examples/settings.json expects it.
  copyFileSync(
    join(ROOT, "plugins", "aws-guard", "dist", "aws_guard.mjs"),
    join(project, ".claude", "hooks", "aws-guard", "aws_guard.mjs"),
  );

  // examples/settings.json without its permissions.deny layer, which would stop some commands before
  // the hook decides and hide what we want to see. Plus a logging hook, so every Bash call's stdin
  // JSON (including permission_mode) is captured whatever the guard decides.
  const settings = JSON.parse(readFileSync(join(ROOT, "examples", "settings.json"), "utf8"));
  const group = settings.hooks?.PreToolUse?.[0];
  if (group?.matcher !== "Bash" || !Array.isArray(group.hooks)) {
    throw new Error("examples/settings.json no longer has a PreToolUse Bash hook group at index 0; update the harness");
  }
  delete settings.permissions;
  group.hooks.unshift({ type: "command", command: `{ cat; echo; } >> '${hookLog}'` });
  writeFileSync(join(project, ".claude", "settings.json"), JSON.stringify(settings, null, 2));

  // Fake aws: record the arguments, do nothing else.
  const shim = join(bin, "aws");
  writeFileSync(shim, `#!/bin/sh\necho "$*" >> '${shimLog}'\nexit 0\n`);
  chmodSync(shim, 0o755);

  const mock = startMockApi(command);
  const env: Record<string, string> = {
    PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
    HOME: home,
    ANTHROPIC_BASE_URL: mock.url,
    ANTHROPIC_API_KEY: "mock-key-not-a-secret",
    // The version under test must stay the version under test, and nothing should leave the machine.
    DISABLE_AUTOUPDATER: "1",
    DISABLE_TELEMETRY: "1",
    DISABLE_ERROR_REPORTING: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
  };

  return {
    dir,
    project,
    env,
    mock,
    observe: () => ({
      hookLog: read(hookLog),
      auditLog: read(join(home, ".claude", "aws-audit.log")),
      shimLog: read(shimLog),
      toolResult: mock.toolResult(),
    }),
    close: () => mock.stop(),
  };
}
