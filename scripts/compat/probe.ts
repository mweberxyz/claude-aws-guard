// Phase 1: runs the installed `claude` headless (`claude -p`) against the guard, in normal and
// --dangerously-skip-permissions mode, with a mock API instead of a model, and asserts on side
// effects only. See README, "Compatibility checks".
//
//   bun scripts/compat/probe.ts --version 2.1.303 --labels latest --out results
//
// Needs `claude` on PATH at that exact version, and must not run as root (the bypass flag is refused).
// No API key is needed: Claude Code talks to the mock.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { makeSandbox, PROMPT } from "./harness";
import { CASES, evaluate, legStatus, SEMVER, type Case, type CheckResult, type LegResult, type Mode, type VersionLabel } from "./lib";

const { values } = parseArgs({
  options: {
    version: { type: "string" },
    labels: { type: "string", default: "" },
    out: { type: "string", default: "compat-results" },
  },
});
const version = values.version ?? "";
if (!SEMVER.test(version)) throw new Error("--version x.y.z is required");

async function run(argv: string[], env: Record<string, string | undefined>, cwd: string, timeout = 120_000) {
  const proc = Bun.spawn(argv, { env, cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout, killSignal: "SIGKILL" });
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  return { stdout, stderr, code };
}

async function check(c: Case, mode: Mode): Promise<CheckResult> {
  const sandbox = makeSandbox(c.command);
  try {
    const argv = ["claude", "-p", PROMPT, "--tools", "Bash", "--no-session-persistence"];
    if (mode === "bypass") argv.push("--dangerously-skip-permissions");
    const r = await run(argv, sandbox.env, sandbox.project);
    const result = evaluate(c, mode, sandbox.observe());
    if (result.status === "error") console.error(`claude exited ${r.code} for ${mode}/${c.id} without reporting on the call: ${r.stderr.trim().slice(-500)}`);
    console.log(`${mode}/${c.id}: ${result.status}${result.failed.length ? ` (${result.failed.join(", ")})` : ""}`);
    return result;
  } finally {
    sandbox.close();
  }
}

const leg: LegResult = { version, labels: values.labels!.split(",").filter(Boolean) as VersionLabel[], checks: [] };
const { stdout: versionOut } = await run(["claude", "--version"], process.env, process.cwd(), 30_000);
leg.observedVersion = versionOut.match(/^(\d+\.\d+\.\d+)/)?.[1];
console.log(`claude --version: ${versionOut.trim()}`);

if (leg.observedVersion !== version) {
  leg.error = "version_mismatch";
} else {
  for (const mode of ["normal", "bypass"] as Mode[]) {
    for (const c of CASES) leg.checks.push(await check(c, mode));
  }
}

mkdirSync(values.out!, { recursive: true });
writeFileSync(join(values.out!, `probe-${version}.json`), JSON.stringify(leg, null, 2));
const status = legStatus(leg);
console.log(`${version}: ${status}`);
process.exit(status === "pass" ? 0 : 1);
