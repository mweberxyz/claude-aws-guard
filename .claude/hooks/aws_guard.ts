#!/usr/bin/env bun
// PreToolUse hook: guard `aws` CLI calls made through Claude Code's Bash tool.
// Emits allow / deny / ask. Anything unrecognized falls through to "ask".

import { appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type Decision = "allow" | "deny" | "ask";

const AUDIT_LOG = join(homedir(), ".claude", "aws-audit.log");

const input = (await Bun.stdin.json()) as {
  tool_input?: { command?: string };
};
const cmd = input.tool_input?.command ?? "";

function decide(decision: Decision, reason: string): never {
  try {
    appendFileSync(
      AUDIT_LOG,
      JSON.stringify({ ts: new Date().toISOString(), decision, reason, cmd }) + "\n",
    );
  } catch {
    // logging must never break the hook
  }
  console.log(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }),
  );
  process.exit(0);
}

// Minimal shlex.split: handles single quotes, double quotes, backslash escapes.
function shellSplit(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inTok = false;
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote === "'") {
      if (c === "'") quote = null;
      else cur += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === "\\" && i + 1 < s.length && '"\\$`'.includes(s[i + 1])) cur += s[++i];
      else cur += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      inTok = true;
    } else if (c === "\\" && i + 1 < s.length) {
      cur += s[++i];
      inTok = true;
    } else if (/\s/.test(c)) {
      if (inTok) {
        out.push(cur);
        cur = "";
        inTok = false;
      }
    } else {
      cur += c;
      inTok = true;
    }
  }
  if (quote) throw new Error("unterminated quote");
  if (inTok) out.push(cur);
  return out;
}

// Not an aws call? Stay out of the way (no output = normal permission flow).
if (!/(^|[\s;&|(`])aws(\s|$)/.test(cmd)) process.exit(0);

// 1. Compound / indirect commands: can't reason about them, so ask.
if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
  decide("ask", "aws inside a compound or indirect command");
}

let argv: string[];
try {
  argv = shellSplit(cmd);
} catch {
  decide("ask", "Unparseable command");
}

// Strip leading VAR=value assignments (e.g. AWS_PROFILE=sandbox aws ...).
const env: Record<string, string> = {};
while (argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0])) {
  const [k, ...v] = argv.shift()!.split("=");
  env[k] = v.join("=");
}
if (argv[0] !== "aws") decide("ask", "aws is not the command being run directly");
argv = argv.slice(1);

// Global flags that consume a value, so we don't mistake the value for the service.
const VALUE_FLAGS = new Set([
  "--profile", "--region", "--output", "--endpoint-url", "--query",
  "--ca-bundle", "--color", "--cli-read-timeout", "--cli-connect-timeout",
  "--cli-binary-format", "--cli-auto-prompt",
]);

const positional: string[] = [];
let profile: string | undefined = env.AWS_PROFILE;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith("--")) {
    const [name, inline] = a.split(/=(.*)/s);
    let value = inline;
    if (inline === undefined && VALUE_FLAGS.has(name)) value = argv[++i];
    if (name === "--profile") profile = value;
  } else if (!a.startsWith("-")) {
    positional.push(a);
  }
}
const [service = "", op = ""] = positional;
const has = (flag: string) => argv.some((a) => a === flag || a.startsWith(flag + "="));

// 2. Hard denies
const DENY: [string, RegExp][] = [
  ["iam", /^(create|attach|put|update|delete|add)-/],
  ["sts", /^assume-role/],
  ["organizations", /.*/],
  ["kms", /^(schedule-key-deletion|disable-key|put-key-policy)/],
  ["s3api", /^(delete-bucket|put-bucket-policy|put-public-access-block|put-bucket-acl)/],
  ["s3", /^rb$/],
  ["secretsmanager", /^get-secret-value$/],
  ["configure", /.*/],
];
for (const [svc, pat] of DENY) {
  if (service === svc && pat.test(op)) decide("deny", `aws ${service} ${op} is blocked by policy`);
}
if (service === "ssm" && has("--with-decryption")) {
  decide("deny", "Decrypting SSM parameters is blocked");
}
if (profile && /prod/i.test(profile)) {
  decide("deny", "Prod profiles are off-limits from Claude Code");
}

// 3. Require explicit identity so we never hit a default/prod account.
if (!profile) decide("deny", "Add --profile <sandbox-profile> (and --region)");

// 4. Auto-allow read-only verbs.
if (/^(describe|list|get|head|lookup|batch-get)-/.test(op) || (service === "s3" && op === "ls")) {
  decide("allow", "Read-only aws call");
}
if (has("--dry-run")) decide("allow", "Dry run");

// 5. Everything else (create/update/delete/s3 cp/rm/sync...) -> human decides.
decide("ask", `Mutating or unrecognized: aws ${service} ${op}`);
