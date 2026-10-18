// PreToolUse hook: guard `aws` CLI calls made through Claude Code's Bash tool.
// Single-shot script: reads one tool call from stdin, prints one decision, exits.
// Fails closed on errors inside the script: any thrown error becomes a deny.
//
// Runs on Node or Bun (the plugin ships a built copy in dist/). Must be invoked with the wrapper
// from hooks/hooks.json, which provides two things:
//   - the audit log: this script writes one JSON line per aws call to stderr, and the
//     shell appends stderr to ~/.claude/aws-audit.log (if that can't be opened, the
//     command fails and the wrapper blocks the call);
//   - fail-closed crashes: a non-zero exit from this script becomes exit 2 (block).
// Run bare, a crash outside the try/catch below would fail open.

import { readSync } from "node:fs";
import { evaluate, loadConfig, type Verdict } from "./aws_guard_lib";

export {}; // marks this file as a module so tsc accepts the top-level await

function warnIfDangerouslySkipPermissions(): void {
  const argv = process.argv ?? [];
  const claudeFlags = process.env.CLAUDE_FLAGS ?? "";
  const startedWithDangerousFlag =
    argv.includes("--dangerously-skip-permissions") ||
    claudeFlags.includes("--dangerously-skip-permissions");

  if (!startedWithDangerousFlag) return;

  console.error(
    "aws-guard: WARNING: Claude was started with --dangerously-skip-permissions; " +
      "this bypasses permissions enforcement and disables the aws-guard plugin for Bash/aws calls.",
  );
}

// Reads all of stdin with plain reads on fd 0. process.stdin's stream machinery costs about 17 ms of
// startup on Bun, which would be added to every Bash call. A non-blocking pipe can report EAGAIN
// when no data is ready yet, so wait briefly and retry instead of failing or dropping input.
function readStdin(): string {
  const chunks: Buffer[] = [];
  const buf = Buffer.alloc(65536);
  for (;;) {
    let n: number;
    try {
      n = readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "EAGAIN") {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
        continue;
      }
      if (code === "EOF") break;
      throw e;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
  }
  return Buffer.concat(chunks).toString("utf8");
}

warnIfDangerouslySkipPermissions();

let result: Verdict;
try {
  const input = JSON.parse(readStdin()) as { tool_input?: { command?: string } };
  const cmd = input.tool_input?.command ?? "";
  if (typeof cmd !== "string") throw new Error("tool_input.command is not a string");
  result = evaluate(cmd, loadConfig(process.env));
  // One audit line per aws call; the wrapper in hooks.json appends stderr to the log file.
  if (result.decision !== "passthrough") {
    console.error(JSON.stringify({ ts: new Date().toISOString(), ...result, cmd }));
  }
} catch (e) {
  result = { decision: "deny", reason: `aws_guard script failed: ${e}` };
}

// Exit 0 with no output means "no opinion": Claude Code falls back to its normal permission flow.
if (result.decision === "passthrough") process.exit(0);

console.log(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: result.decision,
      permissionDecisionReason: result.reason,
    },
  }),
);
