# aws_guard benchmarking

Per-call latency of the `aws_guard` PreToolUse hook, measured through the exact command string in `../../settings.json`.

## Summary

The hook costs about 8 to 10 ms per Bash call, whatever the decision. Passthrough costs the same as a deny, because starting Bun, loading the two modules and reading stdin is nearly all of the time. Decision logic is negligible.

## Method

- 40 timed runs per case after 5 warm-up runs, run sequentially.
- Each run spawns `sh -c "<wrapper from settings.json>"` with the tool-call JSON on stdin, stdout and stderr discarded.
- `HOME` points at a temporary directory with an empty `.claude/`, so audit lines go to a throwaway log.
- `CLAUDE_PROJECT_DIR=/home/user`.
- Wall-clock time from spawn to exit, taken with `performance.now()`.

## Results

Measured on 2026-10-18 in a cloud container (4 cores, Bun 1.4.2, warm disk). Times in ms.

| Case | mean | p50 | p95 | max |
|---|---|---|---|---|
| baseline: `sh -c true` | 1.5 | 1.4 | 2.0 | 2.6 |
| baseline: `bun -e ''` | 1.9 | 1.9 | 2.3 | 2.4 |
| passthrough: `ls -la` | 8.2 | 8.1 | 9.4 | 10.0 |
| passthrough: `git status` | 8.5 | 8.3 | 11.5 | 13.7 |
| allow: read with query | 8.6 | 8.5 | 10.4 | 11.0 |
| allow: `s3 ls` | 8.9 | 8.4 | 12.2 | 12.9 |
| deny: no query | 9.7 | 9.3 | 13.4 | 14.5 |
| deny: hard deny | 9.0 | 8.9 | 10.7 | 10.9 |
| deny: no profile | 9.0 | 9.1 | 10.0 | 10.3 |
| ask: mutation | 9.2 | 8.8 | 14.2 | 14.7 |
| ask: compound | 8.5 | 8.1 | 13.3 | 14.8 |
| ask: path-prefixed | 9.6 | 9.8 | 11.8 | 13.2 |

## Reading the numbers

- The spread between decision types is about 1.5 ms, within run-to-run noise (p95 varies by more than that).
- The overhead is about 7 ms over a bare Bun start (1.9 ms): the wrapper shell, loading `aws_guard.ts` and `aws_guard_lib.ts`, `Bun.stdin.json()`, and the audit write.
- These are lower bounds. A cold disk or a slower machine will be worse.
- The hook's `timeout` is 10 s, far above anything measured.

## Not measured

- Cold start (first run after boot, or after the page cache is dropped).
- An `if` filter on the hook to skip non-`aws` commands before Bun starts. It would save at most about 8 ms per non-`aws` Bash call, and it would move the "is this aws?" check out of the tested code. Whether the hooks docs support such a field has not been checked.
- Concurrent calls.

## Reproducing

Save as `bench.ts` and run `bun run bench.ts`. It reads `/home/user/.claude/settings.json`; change the path and `CLAUDE_PROJECT_DIR` if the project lives elsewhere.

```ts
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const N = 40;
const home = mkdtempSync(join(tmpdir(), "bench-")); mkdirSync(join(home, ".claude"));
const settings = JSON.parse(readFileSync("/home/user/.claude/settings.json", "utf8"));
const wrapper = settings.hooks.PreToolUse[0].hooks[0].command;
const env = { ...process.env, HOME: home, CLAUDE_PROJECT_DIR: "/home/user" };
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
async function time(argv: string[], stdin: string) {
  const t = performance.now();
  const p = Bun.spawn(argv, { stdin: new Blob([stdin]), stdout: "ignore", stderr: "ignore", env });
  await p.exited;
  return performance.now() - t;
}
async function bench(label: string, argv: string[], stdin: string) {
  for (let i = 0; i < 5; i++) await time(argv, stdin); // warm-up
  const xs: number[] = [];
  for (let i = 0; i < N; i++) xs.push(await time(argv, stdin));
  xs.sort((a, b) => a - b);
  const mean = xs.reduce((a, b) => a + b) / N;
  console.log(`${label.padEnd(28)} mean ${mean.toFixed(1).padStart(6)}  p50 ${xs[N / 2].toFixed(1).padStart(6)}  p95 ${xs[Math.floor(N * 0.95)].toFixed(1).padStart(6)}  max ${xs[N - 1].toFixed(1).padStart(6)} ms`);
}
await bench("baseline: sh -c true", ["sh", "-c", "true"], "");
await bench("baseline: bun -e ''", ["bun", "-e", ""], "");
for (const [label, cmd] of cases)
  await bench(label, ["sh", "-c", wrapper], JSON.stringify({ tool_input: { command: cmd } }));
```
