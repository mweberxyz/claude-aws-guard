import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const PLUGIN = join(ROOT, "plugins", "aws-guard");
const SCRIPT = join(PLUGIN, "src", "aws_guard.ts");
const DIST = join(PLUGIN, "dist", "aws_guard.mjs");
const HOOKS = join(ROOT, "plugins", "aws-guard", "hooks", "hooks.json");
const EXAMPLE_SETTINGS = join(ROOT, "examples", "settings.json");

// Runs the script the way Claude Code does: JSON on stdin, decision on stdout, audit line on stderr.
async function run(stdin: string, argv: string[] = ["bun", "run", SCRIPT], env: Record<string, string> = {}) {
  const proc = Bun.spawn(argv, {
    env: { ...process.env, ...env },
    stdin: new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  const out = stdout.trim() ? JSON.parse(stdout) : null;
  return {
    exitCode,
    stderr,
    decision: out?.hookSpecificOutput?.permissionDecision as string | undefined,
    reason: out?.hookSpecificOutput?.permissionDecisionReason as string | undefined,
    out,
  };
}

const hook = (command: string) => run(JSON.stringify({ tool_input: { command } }));

const P = "aws --profile sandbox";

describe("passthrough", () => {
  test.each(["ls -la", "echo hello", "git status", "cat awsome.txt", "echo laws"])(
    "%s prints nothing, exits 0, writes no audit line",
    async (cmd) => {
      const r = await hook(cmd);
      expect(r.exitCode).toBe(0);
      expect(r.out).toBeNull();
      expect(r.stderr).toBe("");
    },
  );

  test("empty input command passes through", async () => {
    const r = await run(JSON.stringify({ tool_input: {} }));
    expect(r.out).toBeNull();
    expect(r.exitCode).toBe(0);
  });
});

describe("decisions", () => {
  // Smoke set: the full policy matrix lives in aws_guard_lib.test.ts. These check that each
  // decision type survives the real stdin -> stdout path.
  const cases: [string, string, "allow" | "deny" | "ask"][] = [
    ["allow: read with narrowing query", `${P} ec2 describe-instances --query Foo`, "allow"],
    ["allow: s3 ls", `${P} s3 ls`, "allow"],
    ["deny: read without query", `${P} ec2 describe-instances`, "deny"],
    ["deny: hard deny", `${P} iam delete-user --user-name x`, "deny"],
    ["deny: no profile", "aws ec2 describe-instances --query Foo", "deny"],
    ["deny: prod profile", "aws --profile prod s3 ls", "deny"],
    ["ask: mutation", `${P} ec2 run-instances`, "ask"],
    ["ask: compound command", `${P} s3 ls; echo hi`, "ask"],
    ["ask: unterminated quote", `${P} ec2 describe-instances --query "Foo`, "ask"],
    ["ask: path-prefixed aws", "/usr/local/bin/aws --profile sandbox s3 ls", "ask"],
  ];

  test.each(cases)("%s", async (_name, cmd, expected) => {
    const r = await hook(cmd);
    expect(r.exitCode).toBe(0);
    expect(r.decision).toBe(expected);
    expect(r.reason).toBeTruthy();
  });

  test("output shape", async () => {
    const r = await hook(`${P} s3 ls`);
    expect(r.out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
  });
});

describe("configuration from CLAUDE_PLUGIN_OPTION_* variables", () => {
  const withEnv = (command: string, env: Record<string, string>) =>
    run(JSON.stringify({ tool_input: { command } }), ["bun", "run", SCRIPT], env);

  test("blocked profile pattern", async () => {
    const env = { CLAUDE_PLUGIN_OPTION_BLOCKED_PROFILE_PATTERN: "^live-" };
    expect((await withEnv(`${P} s3 ls`.replace("sandbox", "live-main"), env)).decision).toBe("deny");
    expect((await withEnv("aws --profile prod s3 ls", env)).decision).toBe("allow");
  });

  test("extra denied commands and require_query", async () => {
    const r = await withEnv(`${P} rds describe-db-instances --query Foo`, {
      CLAUDE_PLUGIN_OPTION_EXTRA_DENIED_COMMANDS: "rds",
    });
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("blocked by configuration");
    const q = await withEnv(`${P} ec2 describe-instances`, { CLAUDE_PLUGIN_OPTION_REQUIRE_QUERY: "false" });
    expect(q.decision).toBe("allow");
  });

  test("environment profile", async () => {
    const env = { CLAUDE_PLUGIN_OPTION_USE_ENVIRONMENT_PROFILE: "true", AWS_PROFILE: "dev" };
    expect((await withEnv("aws s3 ls", env)).decision).toBe("allow");
    expect((await withEnv("aws s3 ls", { AWS_PROFILE: "dev" })).decision).toBe("deny");
  });

  test("a bad setting denies aws calls but leaves other commands alone", async () => {
    const env = { CLAUDE_PLUGIN_OPTION_BLOCKED_PROFILE_PATTERN: "(" };
    const a = await withEnv(`${P} s3 ls`, env);
    expect(a.decision).toBe("deny");
    expect(a.reason).toContain("configuration error");
    const ls = await withEnv("ls -la", env);
    expect(ls.out).toBeNull();
    expect(ls.exitCode).toBe(0);
  });
});

describe("fail closed", () => {
  test.each([["not json"], [""], ["{"]])("malformed stdin %p is denied with the error", async (stdin) => {
    const r = await run(stdin);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("aws_guard script failed");
  });

  test("a non-string command is denied, not passed through", async () => {
    const r = await run(JSON.stringify({ tool_input: { command: 42 } }));
    expect(r.decision).toBe("deny");
  });
});

describe("audit log", () => {
  test("one JSON line per aws call with ts, decision, reason, cmd", async () => {
    const cmd = `${P} iam delete-user --user-name x`;
    const r = await hook(cmd);
    const lines = r.stderr.trim().split("\n");
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.decision).toBe("deny");
    expect(entry.reason).toBe(r.reason);
    expect(entry.cmd).toBe(cmd);
    expect(new Date(entry.ts).toString()).not.toBe("Invalid Date");
  });
});

// The built file is what the plugin ships and what runs under Node, so check it directly.
describe.skipIf(!Bun.which("node"))("built dist under node", () => {
  const node = (command: string) =>
    run(JSON.stringify({ tool_input: { command } }), ["node", DIST]);

  test.each([
    ["allow", `${P} s3 ls`],
    ["deny", `${P} iam delete-user --user-name x`],
    ["ask", `${P} ec2 run-instances`],
  ])("%s", async (expected, cmd) => {
    const r = await node(cmd);
    expect(r.exitCode).toBe(0);
    expect(r.decision).toBe(expected);
    expect(JSON.parse(r.stderr.trim()).decision).toBe(expected);
  });

  test("passthrough prints nothing", async () => {
    const r = await node("ls -la");
    expect(r.out).toBeNull();
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toBe("");
  });

  test("malformed stdin is denied", async () => {
    const r = await run("not json", ["node", DIST]);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("aws_guard script failed");
  });
});

// Exercises the exact command string from hooks.json, so the shell wrapper is covered too.
describe("hooks.json wrapper", () => {
  const hooks = JSON.parse(readFileSync(HOOKS, "utf8"));
  const hookCfg = hooks.hooks.PreToolUse[0].hooks[0];

  async function wrapper(home: string, command: string) {
    const proc = Bun.spawn(["sh", "-c", hookCfg.command], {
      stdin: new Blob([JSON.stringify({ tool_input: { command } })]),
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, HOME: home, CLAUDE_PLUGIN_ROOT: PLUGIN },
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { stdout, stderr, exitCode };
  }

  test("registration: Bash matcher, timeout, onFailure block", () => {
    expect(hooks.hooks.PreToolUse[0].matcher).toBe("Bash");
    expect(hookCfg.timeout).toBe(10);
    expect(hookCfg.onFailure).toBe("block");
  });

  test("appends audit lines to ~/.claude/aws-audit.log, none for non-aws", async () => {
    const home = mkdtempSync(join(tmpdir(), "aws-guard-"));
    mkdirSync(join(home, ".claude"));
    await wrapper(home, `${P} s3 ls`);
    await wrapper(home, `${P} iam delete-user --user-name x`);
    await wrapper(home, "ls -la");
    const log = readFileSync(join(home, ".claude", "aws-audit.log"), "utf8").trim().split("\n");
    expect(log.map((l) => JSON.parse(l).decision)).toEqual(["allow", "deny"]);
  });

  test("exits 2 with a clear message when neither node nor bun is on PATH", async () => {
    const home = mkdtempSync(join(tmpdir(), "aws-guard-"));
    mkdirSync(join(home, ".claude"));
    const proc = Bun.spawn(["/bin/sh", "-c", hookCfg.command], {
      stdin: new Blob([JSON.stringify({ tool_input: { command: "ls" } })]),
      stdout: "pipe",
      stderr: "pipe",
      env: { HOME: home, CLAUDE_PLUGIN_ROOT: PLUGIN, PATH: "/nonexistent" },
    });
    const stderr = await new Response(proc.stderr).text();
    expect(await proc.exited).toBe(2);
    expect(stderr).toContain("needs node or bun");
  });

  test("exits 2 (blocks) when the audit log can't be opened", async () => {
    const home = mkdtempSync(join(tmpdir(), "aws-guard-")); // no .claude dir
    const r = await wrapper(home, "ls -la");
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("aws_guard failed");
  });

  test("examples/settings.json lists the hard-deny commands", () => {
    const settings = JSON.parse(readFileSync(EXAMPLE_SETTINGS, "utf8"));
    expect(settings.permissions.deny).toEqual(
      expect.arrayContaining([
        "Bash(aws iam:*)",
        "Bash(aws organizations:*)",
        "Bash(aws sts assume-role:*)",
        "Bash(aws configure:*)",
        "Bash(aws secretsmanager get-secret-value:*)",
      ]),
    );
  });
});
