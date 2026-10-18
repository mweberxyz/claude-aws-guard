#!/usr/bin/env bun
// PreToolUse hook: guard `aws` CLI calls made through Claude Code's Bash tool.
// Single-shot script: reads one tool call from stdin, prints one decision, exits.
// Fails closed on errors inside the script: any thrown error becomes a deny.
//
// Must be invoked with the wrapper from settings.json, which provides two things:
//   - the audit log: this script writes one JSON line per aws call to stderr, and the
//     shell appends stderr to ~/.claude/aws-audit.log (if that can't be opened, the
//     command fails and the wrapper blocks the call);
//   - fail-closed crashes: a non-zero exit from this script becomes exit 2 (block).
// Run bare, a crash outside the try/catch below would fail open.

type Verdict =
  | { decision: "allow" | "deny" | "ask"; reason: string }
  | { decision: "passthrough" }; // not an aws call: print nothing, normal permission flow

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

type ParsedAws = {
  service: string;
  op: string;
  profile: string | undefined; // from --profile, falling back to a leading AWS_PROFILE=
  query: string | undefined;
  has: (flag: string) => boolean; // whether a flag appears, as `--flag` or `--flag=value`
};

// Parses `[VAR=value ...] aws [global flags] <service> <op> [flags]`.
function parseAws(tokens: string[]): ParsedAws | { error: string } {
  const argv = [...tokens];

  // Strip leading VAR=value assignments (e.g. AWS_PROFILE=sandbox aws ...).
  const env: Record<string, string> = {};
  while (argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0])) {
    const [k, ...v] = argv.shift()!.split("=");
    env[k] = v.join("=");
  }
  if (argv.shift() !== "aws") return { error: "aws is not the command being run directly" };

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
  return { service, op, profile, query, has };
}

function evaluate(cmd: string): Verdict {
  // Not an aws call? Stay out of the way.
  if (!/(^|[\s;&|(`])aws(\s|$)/.test(cmd)) return { decision: "passthrough" };

  // 1. Compound / indirect commands: can't reason about them, so ask.
  if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
    return { decision: "ask", reason: "aws inside a compound or indirect command" };
  }

  let argv: string[];
  try {
    argv = shellSplit(cmd);
  } catch {
    return { decision: "ask", reason: "Unparseable command" };
  }

  const parsed = parseAws(argv);
  if ("error" in parsed) return { decision: "ask", reason: parsed.error };
  const { service, op, profile, query, has } = parsed;

  // 2. Hard denies
  for (const [svc, pat] of DENY) {
    if (service === svc && pat.test(op)) {
      return { decision: "deny", reason: `aws ${service} ${op} is blocked by policy` };
    }
  }
  if (service === "ssm" && has("--with-decryption")) {
    return { decision: "deny", reason: "Decrypting SSM parameters is blocked" };
  }
  if (profile && /prod/i.test(profile)) {
    return { decision: "deny", reason: "Prod profiles are off-limits from Claude Code" };
  }

  // 3. Require explicit identity so we never hit a default/prod account.
  if (!profile) {
    return { decision: "deny", reason: "Add --profile <sandbox-profile> (and --region)" };
  }

  // 4. Read-only verbs: require a --query that actually narrows the output,
  //    so the caller has to decide what it needs instead of pulling everything.
  //    (`aws s3 ls` doesn't support --query, so it's exempt.)
  if (/^(describe|list|get|head|lookup|batch-get)-/.test(op)) {
    const q = query?.trim();
    if (!q) {
      return {
        decision: "deny",
        reason:
          "Read calls need --query selecting only the fields you need " +
          "(e.g. --query 'Reservations[].Instances[].[InstanceId,State.Name]')",
      };
    }
    // "@" (JMESPath identity) and bare wildcards return everything: not a real narrowing.
    if (/^(@|\*|\[\*\]|\[\]|\*\.\*)$/.test(q)) {
      return { decision: "deny", reason: `--query '${q}' selects everything; choose specific fields` };
    }
    return { decision: "allow", reason: "Read-only aws call with a narrowing --query" };
  }
  if (service === "s3" && op === "ls") return { decision: "allow", reason: "Read-only aws call" };
  if (has("--dry-run")) return { decision: "allow", reason: "Dry run" };

  // 5. Everything else (create/update/delete/s3 cp/rm/sync...) -> human decides.
  return { decision: "ask", reason: `Mutating or unrecognized: aws ${service} ${op}` };
}

let result: Verdict;
try {
  const input = (await Bun.stdin.json()) as { tool_input?: { command?: string } };
  const cmd = input.tool_input?.command ?? "";
  result = evaluate(cmd);
  // One audit line per aws call; the wrapper in settings.json appends stderr to the log file.
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
