# Benchmarking

Per-call latency of the aws-guard hook, measured through the exact command string in `plugins/aws-guard/hooks/hooks.json`.

## Summary

With Bun on the `PATH`, the hook costs about 10 to 11 ms per Bash call. With only Node, it costs about 41 to 46 ms. The decision type makes no measurable difference: a passthrough costs the same as a deny, because starting the runtime and loading the script is nearly all of the time. The policy itself is negligible.

The hook command prefers `bun` and falls back to `node`, for this reason.

## Method

- 40 timed runs per case after 5 warm-up runs, run sequentially.
- Each run spawns `sh -c "<command from hooks.json>"` with the tool-call JSON on stdin, stdout and stderr discarded.
- `HOME` points at a throwaway directory with an empty `.claude/`, so audit lines go to a scratch log.
- Wall-clock time from spawn to exit, taken with `performance.now()`.
- The "Node only" run removes Bun from the `PATH`, so the wrapper falls back to `node`.

## Results

Measured on 2026-10-18 in a cloud container (4 cores, Bun 1.4.2, Node 22.22, warm disk). Times in ms.

| Case | Bun on PATH: mean | p50 | p95 | Node only: mean | p50 | p95 |
|---|---|---|---|---|---|---|
| baseline: `sh -c true` | 1.3 | 1.3 | 1.4 | 1.3 | 1.3 | 1.5 |
| baseline: `bun -e ''` | 1.9 | 1.8 | 2.3 | | | |
| baseline: `node -e ''` | 25.8 | 24.6 | 33.5 | 24.5 | 23.2 | 31.7 |
| passthrough: `ls -la` | 11.4 | 10.9 | 14.6 | 43.6 | 40.5 | 62.4 |
| passthrough: `git status` | 10.8 | 10.2 | 14.6 | 41.4 | 39.9 | 50.1 |
| allow: read with query | 11.7 | 10.9 | 15.3 | 44.3 | 43.4 | 51.0 |
| allow: `s3 ls` | 10.3 | 10.3 | 10.9 | 46.2 | 44.2 | 59.8 |
| deny: no query | 10.7 | 10.5 | 11.8 | 45.6 | 45.0 | 54.5 |
| deny: hard deny | 11.3 | 10.5 | 14.0 | 43.5 | 42.4 | 48.4 |
| deny: no profile | 10.3 | 10.3 | 10.9 | 43.7 | 42.6 | 56.2 |
| ask: mutation | 10.7 | 10.2 | 13.8 | 45.0 | 43.8 | 58.9 |
| ask: compound | 11.5 | 10.7 | 14.7 | 43.9 | 41.6 | 56.2 |
| ask: path-prefixed | 10.8 | 10.6 | 13.6 | 44.2 | 42.5 | 58.7 |

## Reading the numbers

- Bun adds about 9 ms over its own bare start (1.9 ms): the wrapper shell, loading the script, reading stdin and writing the audit line.
- Node adds about 19 ms over its own bare start (about 24 ms), which is why it is the fallback and not the first choice.
- These are lower bounds. A cold disk or a slower machine will be worse. The hook's `timeout` is 10 s, far above anything measured.

## What the numbers taught us

The first Node-compatible version took about 25 ms with Bun, against 8 to 10 ms for the Bun-only original. Profiling the pieces found that `process.stdin`'s stream setup alone cost about 17 ms on Bun (21.6 ms against 4.1 ms for a script that never touches stdin). Reading fd 0 with `readSync` costs about 3 ms and brought the hook back to about 10 ms. If you change how the script reads input, re-run the benchmark.

## Not measured

- Cold start (first run after boot, or after the page cache is dropped).
- Concurrent calls.

## Reproducing

```sh
bun run bench
# Node only: run with Bun off the PATH, for example
PATH=/path/to/node/bin:/usr/bin:/bin /path/to/bun scripts/bench.ts
```

The script is [`scripts/bench.ts`](../scripts/bench.ts).
