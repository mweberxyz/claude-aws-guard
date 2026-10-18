// plugins/aws-guard/src/aws_guard.ts
import { readSync } from "node:fs";

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
var DEFAULT_CONFIG = {
  blockedProfile: /prod/i,
  extraDenied: [],
  requireQuery: true,
  envProfile: undefined
};
function parseBool(raw, fallback, name) {
  const v = raw?.trim().toLowerCase();
  if (!v)
    return fallback;
  if (["true", "1", "yes"].includes(v))
    return true;
  if (["false", "0", "no"].includes(v))
    return false;
  return { error: `${name} must be true or false, got '${raw}'` };
}
function loadConfig(env) {
  const opt = (key) => env[`CLAUDE_PLUGIN_OPTION_${key}`];
  let blockedProfile = DEFAULT_CONFIG.blockedProfile;
  const pattern = opt("BLOCKED_PROFILE_PATTERN")?.trim();
  if (pattern) {
    try {
      blockedProfile = new RegExp(pattern, "i");
    } catch (e) {
      return { error: `blocked_profile_pattern is not a valid regular expression: ${e}` };
    }
  }
  const extraDenied = [];
  for (const raw of (opt("EXTRA_DENIED_COMMANDS") ?? "").split(",")) {
    const entry = raw.trim();
    if (!entry)
      continue;
    const [service, ...rest] = entry.split(":");
    const prefix = rest.join(":");
    if (!/^[a-z0-9-]+$/.test(service) || rest.length > 0 && !/^[a-z0-9-]+$/.test(prefix)) {
      return { error: `extra_denied_commands entry '${entry}' must look like 'service' or 'service:operation-prefix'` };
    }
    extraDenied.push([service, new RegExp(`^${prefix}`)]);
  }
  const requireQuery = parseBool(opt("REQUIRE_QUERY"), DEFAULT_CONFIG.requireQuery, "require_query");
  if (typeof requireQuery === "object")
    return requireQuery;
  const useEnvProfile = parseBool(opt("USE_ENVIRONMENT_PROFILE"), false, "use_environment_profile");
  if (typeof useEnvProfile === "object")
    return useEnvProfile;
  return {
    blockedProfile,
    extraDenied,
    requireQuery,
    envProfile: useEnvProfile ? env.AWS_PROFILE?.trim() || undefined : undefined
  };
}
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
function evaluate(cmd, config = DEFAULT_CONFIG) {
  if (!/(^|[\s;&|(`'"/])aws(['"\s]|$)/.test(cmd))
    return { decision: "passthrough" };
  if ("error" in config) {
    return { decision: "deny", reason: `aws-guard configuration error: ${config.error}` };
  }
  if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
    return { decision: "ask", reason: "aws inside a compound or indirect command" };
  }
  const parsed = parseAws(cmd);
  if ("error" in parsed)
    return { decision: "ask", reason: parsed.error };
  const { service, op, query, has } = parsed;
  const profile = parsed.profile ?? config.envProfile;
  for (const [svc, pat] of DENY) {
    if (service === svc && pat.test(op)) {
      return { decision: "deny", reason: `aws ${service} ${op} is blocked by policy` };
    }
  }
  for (const [svc, pat] of config.extraDenied) {
    if (service === svc && pat.test(op)) {
      return { decision: "deny", reason: `aws ${service} ${op} is blocked by configuration` };
    }
  }
  if (service === "ssm" && has("--with-decryption")) {
    return { decision: "deny", reason: "Decrypting SSM parameters is blocked" };
  }
  if (profile && config.blockedProfile.test(profile)) {
    return { decision: "deny", reason: `Profile '${profile}' is blocked (it matches the blocked profile pattern)` };
  }
  if (!profile) {
    return { decision: "deny", reason: "No AWS profile given. Add --profile <name>, or prefix the command with AWS_PROFILE=<name>." };
  }
  if (/^(describe|list|get|head|lookup|batch-get)-/.test(op)) {
    if (!config.requireQuery) {
      return { decision: "allow", reason: "Read-only aws call (--query not required by configuration)" };
    }
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
function readStdin() {
  const chunks = [];
  const buf = Buffer.alloc(65536);
  for (;; ) {
    let n;
    try {
      n = readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      const code = e.code;
      if (code === "EAGAIN") {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
        continue;
      }
      if (code === "EOF")
        break;
      throw e;
    }
    if (n === 0)
      break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
  }
  return Buffer.concat(chunks).toString("utf8");
}
var result;
try {
  const input = JSON.parse(readStdin());
  const cmd = input.tool_input?.command ?? "";
  if (typeof cmd !== "string")
    throw new Error("tool_input.command is not a string");
  result = evaluate(cmd, loadConfig(process.env));
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
