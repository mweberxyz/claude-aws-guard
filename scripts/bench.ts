// Times the exact command from hooks/hooks.json for each kind of decision.
// Run from the repo root: bun run bench
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const RUNS = 40;
const WARMUP = 5;
const plugin = join(import.meta.dir, "..", "plugins", "aws-guard");
const hooks = JSON.parse(readFileSync(join(plugin, "hooks", "hooks.json"), "utf8"));
const wrapper: string = hooks.hooks.PreToolUse[0].hooks[0].command;

// Throwaway HOME so audit lines go to a scratch log.
const home = mkdtempSync(join(tmpdir(), "aws-guard-bench-"));
mkdirSync(join(home, ".claude"));
const env = { ...process.env, HOME: home, CLAUDE_PLUGIN_ROOT: plugin };

const P = "aws --profile sandbox";
const cases: [string, string][] = [
  ["passthrough: ls -la", "ls -la"],
  ["passthrough: git status", "git status"],
  ["allow: read + query", `${P} ec2 describe-instances --query Foo`],
  ["allow: s3 ls", `${P} s3 ls`],
  ["deny: no query", `${P} ec2 describe-instances`],
  ["deny: hard deny", `${P} iam delete-user --user-name x`],
  ["deny: no profile", "aws s3 ls"],
  ["ask: mutation", `${P} ec2 run-instances`],
  ["ask: compound", `${P} s3 ls; echo hi`],
  ["ask: path-prefixed", "/usr/local/bin/aws s3 ls"],
];

async function once(argv: string[], stdin: string) {
  const start = performance.now();
  const proc = Bun.spawn(argv, { stdin: new Blob([stdin]), stdout: "ignore", stderr: "ignore", env });
  await proc.exited;
  return performance.now() - start;
}

async function bench(label: string, argv: string[], stdin = "") {
  for (let i = 0; i < WARMUP; i++) await once(argv, stdin);
  const times: number[] = [];
  for (let i = 0; i < RUNS; i++) times.push(await once(argv, stdin));
  times.sort((a, b) => a - b);
  const mean = times.reduce((a, b) => a + b) / RUNS;
  const f = (n: number) => n.toFixed(1).padStart(6);
  console.log(
    `${label.padEnd(28)} mean ${f(mean)}  p50 ${f(times[RUNS / 2])}  p95 ${f(times[Math.floor(RUNS * 0.95)])}  max ${f(times[RUNS - 1])} ms`,
  );
}

await bench("baseline: sh -c true", ["sh", "-c", "true"]);
await bench("baseline: node -e ''", ["node", "-e", ""]);
if (Bun.which("bun")) await bench("baseline: bun -e ''", ["bun", "-e", ""]);
for (const [label, command] of cases) {
  await bench(label, ["sh", "-c", wrapper], JSON.stringify({ tool_input: { command } }));
}
