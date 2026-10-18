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

import { evaluate, loadConfig, type Verdict } from "./aws_guard_lib";

export {}; // marks this file as a module so tsc accepts the top-level await

async function readStdin(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

let result: Verdict;
try {
  const input = JSON.parse(await readStdin()) as { tool_input?: { command?: string } };
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
