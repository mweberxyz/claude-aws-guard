#!/usr/bin/env bun
// PreToolUse hook: guard `aws` CLI calls made through Claude Code's Bash tool.
// Emits allow / deny / ask. Anything unrecognized falls through to "ask".
// Fails closed: if the hook itself breaks (bad input, logging failure, bug),
// it returns a deny that says so, instead of crashing into a non-blocking error.

import { appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type Decision = "allow" | "deny" | "ask";

const AUDIT_LOG = join(homedir(), ".claude", "aws-audit.log");

function emit(decision: Decision, reason: string): never {
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

// Logs, then emits. The audit log is part of the control: if it can't be
// written, the call is denied rather than going through unrecorded.
function decide(cmd: string, decision: Decision, reason: string): never {
  try {
    appendFileSync(
      AUDIT_LOG,
      JSON.stringify({ ts: new Date().toISOString(), decision, reason, cmd }) + "\n",
    );
  } catch (e) {
    emit("deny", `aws_guard failed to write audit log (${AUDIT_LOG}): ${errMsg(e)}`);
  }
  emit(decision, reason);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
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

// Global flags that consume a value, so we don't mistake the value for the service.
const VALUE_FLAGS = new Set([
  "--profile", "--region", "--output", "--endpoint-url", "--query",
  "--ca-bundle", "--color", "--cli-read-timeout", "--cli-connect-timeout",
  "--cli-binary-format", "--cli-auto-prompt",
]);

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

async function main(): Promise<void> {
  const input = (await Bun.stdin.json()) as { tool_input?: { command?: string } };
  const cmd = input.tool_input?.command ?? "";
  const d = (decision: Decision, reason: string): never => decide(cmd, decision, reason);

  // Not an aws call? Stay out of the way (no output = normal permission flow).
  if (!/(^|[\s;&|(`])aws(\s|$)/.test(cmd)) process.exit(0);

  // 1. Compound / indirect commands: can't reason about them, so ask.
  if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
    d("ask", "aws inside a compound or indirect command");
  }

  let argv: string[];
  try {
    argv = shellSplit(cmd);
  } catch {
    return d("ask", "Unparseable command");
  }

  // Strip leading VAR=value assignments (e.g. AWS_PROFILE=sandbox aws ...).
  const env: Record<string, string> = {};
  while (argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0])) {
    const [k, ...v] = argv.shift()!.split("=");
    env[k] = v.join("=");
  }
  if (argv[0] !== "aws") d("ask", "aws is not the command being run directly");
  argv = argv.slice(1);

  const positional: string[] = [];
  let profile: string | undefined = env.AWS_PROFILE;
  let query: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [name, inline] = a.split(/=(.*)/s);
      let value = inline;
      if (inline === undefined && VALUE_FLAGS.has(name)) value = argv[++i];
      if (name === "--profile") profile = value;
      if (name === "--query") query = value;
    } else if (!a.startsWith("-")) {
      positional.push(a);
    }
  }
  const [service = "", op = ""] = positional;
  const has = (flag: string) => argv.some((a) => a === flag || a.startsWith(flag + "="));

  // 2. Hard denies
  for (const [svc, pat] of DENY) {
    if (service === svc && pat.test(op)) d("deny", `aws ${service} ${op} is blocked by policy`);
  }
  if (service === "ssm" && has("--with-decryption")) {
    d("deny", "Decrypting SSM parameters is blocked");
  }
  if (profile && /prod/i.test(profile)) {
    d("deny", "Prod profiles are off-limits from Claude Code");
  }

  // 3. Require explicit identity so we never hit a default/prod account.
  if (!profile) d("deny", "Add --profile <sandbox-profile> (and --region)");

  // 4. Read-only verbs: require a --query that actually narrows the output,
  //    so the caller has to decide what it needs instead of pulling everything.
  //    (`aws s3 ls` doesn't support --query, so it's exempt.)
  if (/^(describe|list|get|head|lookup|batch-get)-/.test(op)) {
    const q = query?.trim();
    if (!q) {
      d(
        "deny",
        "Read calls need --query selecting only the fields you need " +
          "(e.g. --query 'Reservations[].Instances[].[InstanceId,State.Name]')",
      );
    }
    // "@" (JMESPath identity) and bare wildcards return everything: not a real narrowing.
    if (/^(@|\*|\[\*\]|\[\]|\*\.\*)$/.test(q!)) {
      d("deny", `--query '${q}' selects everything; choose specific fields`);
    }
    d("allow", "Read-only aws call with a narrowing --query");
  }
  if (service === "s3" && op === "ls") d("allow", "Read-only aws call");
  if (has("--dry-run")) d("allow", "Dry run");

  // 5. Everything else (create/update/delete/s3 cp/rm/sync...) -> human decides.
  d("ask", `Mutating or unrecognized: aws ${service} ${op}`);
}

// Any unexpected failure (malformed stdin, a bug above) becomes an explicit deny.
main().catch((e) => emit("deny", `aws_guard script failed: ${errMsg(e)}`));
