// plugins/aws-guard/src/aws_guard_lib.ts
function shellSplit(s) {
  const out = [];
  let cur = "";
  let inTok = false;
  let quote = null;
  for (let i = 0;i < s.length; i++) {
    const c = s[i];
    if (quote === "'") {
      if (c === "'")
        quote = null;
      else
        cur += c;
    } else if (quote === '"') {
      if (c === '"')
        quote = null;
      else if (c === "\\" && i + 1 < s.length && '"\\$`'.includes(s[i + 1]))
        cur += s[++i];
      else
        cur += c;
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
  if (quote)
    return { error: "Unparseable command (unterminated quote)" };
  if (inTok)
    out.push(cur);
  return out;
}
var VALUE_FLAGS = new Set([
  "--profile",
  "--region",
  "--output",
  "--endpoint-url",
  "--query",
  "--ca-bundle",
  "--color",
  "--cli-read-timeout",
  "--cli-connect-timeout",
  "--cli-binary-format",
  "--cli-auto-prompt"
]);
var DENY = [
  ["iam", /^(create|attach|put|update|delete|add)-/],
  ["sts", /^assume-role/],
  ["organizations", /.*/],
  ["kms", /^(schedule-key-deletion|disable-key|put-key-policy)/],
  ["s3api", /^(delete-bucket|put-bucket-policy|put-public-access-block|put-bucket-acl)/],
  ["s3", /^rb$/],
  ["secretsmanager", /^get-secret-value$/],
  ["configure", /.*/]
];
function parseAws(cmd) {
  const tokens = shellSplit(cmd);
  if ("error" in tokens)
    return tokens;
  const argv = [...tokens];
  const env = {};
  while (argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0])) {
    const [k, ...v] = argv.shift().split("=");
    env[k] = v.join("=");
  }
  if (argv.shift() !== "aws")
    return { error: "aws is not the command being run directly" };
  const positional = [];
  let profile = env.AWS_PROFILE;
  let query;
  for (let i = 0;i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [name, inline] = a.split(/=(.*)/s);
      let value = inline;
      if (inline === undefined && VALUE_FLAGS.has(name))
        value = argv[++i];
      if (name === "--profile")
        profile = value;
      if (name === "--query")
        query = value;
    } else if (!a.startsWith("-")) {
      positional.push(a);
    }
  }
  const [service = "", op = ""] = positional;
  const has = (flag) => argv.some((a) => a === flag || a.startsWith(flag + "="));
  return { service, op, profile, query, has };
}
function evaluate(cmd) {
  if (!/(^|[\s;&|(`'"/])aws(['"\s]|$)/.test(cmd))
    return { decision: "passthrough" };
  if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
    return { decision: "ask", reason: "aws inside a compound or indirect command" };
  }
  const parsed = parseAws(cmd);
  if ("error" in parsed)
    return { decision: "ask", reason: parsed.error };
  const { service, op, profile, query, has } = parsed;
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
  if (!profile) {
    return { decision: "deny", reason: "Add --profile <sandbox-profile> (and --region)" };
  }
  if (/^(describe|list|get|head|lookup|batch-get)-/.test(op)) {
    const q = query?.trim();
    if (!q) {
      return {
        decision: "deny",
        reason: "Read calls need --query selecting only the fields you need " + "(e.g. --query 'Reservations[].Instances[].[InstanceId,State.Name]')"
      };
    }
    if (/^(@|\*|\[\*\]|\[\]|\*\.\*)$/.test(q)) {
      return { decision: "deny", reason: `--query '${q}' selects everything; choose specific fields` };
    }
    return { decision: "allow", reason: "Read-only aws call with a narrowing --query" };
  }
  if (service === "s3" && op === "ls")
    return { decision: "allow", reason: "Read-only aws call" };
  if (has("--dry-run"))
    return { decision: "allow", reason: "Dry run" };
  return { decision: "ask", reason: `Mutating or unrecognized: aws ${service} ${op}` };
}

// plugins/aws-guard/src/aws_guard.ts
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin)
    chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}
var result;
try {
  const input = JSON.parse(await readStdin());
  const cmd = input.tool_input?.command ?? "";
  if (typeof cmd !== "string")
    throw new Error("tool_input.command is not a string");
  result = evaluate(cmd);
  if (result.decision !== "passthrough") {
    console.error(JSON.stringify({ ts: new Date().toISOString(), ...result, cmd }));
  }
} catch (e) {
  result = { decision: "deny", reason: `aws_guard script failed: ${e}` };
}
if (result.decision === "passthrough")
  process.exit(0);
console.log(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: result.decision,
    permissionDecisionReason: result.reason
  }
}));
