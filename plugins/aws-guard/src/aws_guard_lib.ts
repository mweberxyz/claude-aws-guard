// Policy logic for aws_guard.ts, kept free of I/O so it can be unit tested in-process.

export type Verdict =
  | { decision: "allow" | "deny" | "ask"; reason: string }
  | { decision: "passthrough" }; // not an aws call: print nothing, normal permission flow

// Minimal shlex.split: handles single quotes, double quotes, backslash escapes.
export function shellSplit(s: string): string[] | { error: string } {
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
  if (quote) return { error: "Unparseable command (unterminated quote)" };
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

// Settings a user can change through the plugin's userConfig. Claude Code hands them to the hook as
// CLAUDE_PLUGIN_OPTION_<KEY> environment variables.
export type Config = {
  blockProfiles: boolean; // apply blockedProfile at all; off skips the blocked-profile rule entirely
  blockedProfile: RegExp; // profiles matching this are always denied
  extraDenied: [string, RegExp][]; // extra [service, operation] pairs to always deny
  requireQuery: boolean; // read-only verbs need a narrowing --query
  envProfile: string | undefined; // AWS_PROFILE from the environment, when use_environment_profile is on
};

export const DEFAULT_CONFIG: Config = {
  blockProfiles: true,
  blockedProfile: /prod/i,
  extraDenied: [],
  requireQuery: true,
  envProfile: undefined,
};

function parseBool(raw: string | undefined, fallback: boolean, name: string): boolean | { error: string } {
  const v = raw?.trim().toLowerCase();
  if (!v) return fallback;
  if (["true", "1", "yes"].includes(v)) return true;
  if (["false", "0", "no"].includes(v)) return false;
  return { error: `${name} must be true or false, got '${raw}'` };
}

// Builds a Config from the environment. Anything unparseable is an error, never a silent default,
// so a typo can't quietly loosen the policy.
export function loadConfig(env: Record<string, string | undefined>): Config | { error: string } {
  const opt = (key: string) => env[`CLAUDE_PLUGIN_OPTION_${key}`];

  let blockedProfile = DEFAULT_CONFIG.blockedProfile;
  const pattern = opt("BLOCKED_PROFILE_PATTERN")?.trim();
  if (pattern) {
    try {
      blockedProfile = new RegExp(pattern, "i");
    } catch (e) {
      return { error: `blocked_profile_pattern is not a valid regular expression: ${e}` };
    }
  }

  const extraDenied: [string, RegExp][] = [];
  for (const raw of (opt("EXTRA_DENIED_COMMANDS") ?? "").split(",")) {
    const entry = raw.trim();
    if (!entry) continue;
    const [service, ...rest] = entry.split(":");
    const prefix = rest.join(":");
    if (!/^[a-z0-9-]+$/.test(service) || (rest.length > 0 && !/^[a-z0-9-]+$/.test(prefix))) {
      return { error: `extra_denied_commands entry '${entry}' must look like 'service' or 'service:operation-prefix'` };
    }
    extraDenied.push([service, new RegExp(`^${prefix}`)]);
  }

  const blockProfiles = parseBool(opt("BLOCK_PROFILES"), DEFAULT_CONFIG.blockProfiles, "block_profiles");
  if (typeof blockProfiles === "object") return blockProfiles;
  const requireQuery = parseBool(opt("REQUIRE_QUERY"), DEFAULT_CONFIG.requireQuery, "require_query");
  if (typeof requireQuery === "object") return requireQuery;
  const useEnvProfile = parseBool(opt("USE_ENVIRONMENT_PROFILE"), false, "use_environment_profile");
  if (typeof useEnvProfile === "object") return useEnvProfile;

  return {
    blockProfiles,
    blockedProfile,
    extraDenied,
    requireQuery,
    envProfile: useEnvProfile ? env.AWS_PROFILE?.trim() || undefined : undefined,
  };
}

export type ParsedAws = {
  service: string;
  op: string;
  profile: string | undefined; // from --profile, falling back to a leading AWS_PROFILE=
  query: string | undefined;
  has: (flag: string) => boolean; // whether a flag appears, as `--flag` or `--flag=value`
};

// Parses `[VAR=value ...] aws [global flags] <service> <op> [flags]`.
export function parseAws(cmd: string): ParsedAws | { error: string } {
  const tokens = shellSplit(cmd);
  if ("error" in tokens) return tokens;
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

export function evaluate(cmd: string, config: Config | { error: string } = DEFAULT_CONFIG): Verdict {
  // Not an aws call? Stay out of the way. A path prefix (/usr/local/bin/aws, ./aws, ~/bin/aws)
  // or a quote ("aws") still counts as an aws call; parseAws sends path-prefixed ones to ask.
  if (!/(^|[\s;&|(`'"/])aws(['"\s]|$)/.test(cmd)) return { decision: "passthrough" };

  // A broken configuration only matters for aws calls: it must never block other commands.
  if ("error" in config) {
    return { decision: "deny", reason: `aws-guard configuration error: ${config.error}` };
  }

  // 1. Compound / indirect commands: can't reason about them, so ask.
  if (/[;&|`\n]|\$\(|\beval\b|\bbash\s+-c\b|\bxargs\b/.test(cmd)) {
    return { decision: "ask", reason: "aws inside a compound or indirect command" };
  }

  const parsed = parseAws(cmd);
  if ("error" in parsed) return { decision: "ask", reason: parsed.error };
  const { service, op, query, has } = parsed;
  const profile = parsed.profile ?? config.envProfile;

  // 2. Hard denies
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
  if (profile && config.blockProfiles && config.blockedProfile.test(profile)) {
    return { decision: "deny", reason: `Profile '${profile}' is blocked (it matches the blocked profile pattern)` };
  }

  // 3. Require explicit identity so we never hit a default/prod account.
  if (!profile) {
    return { decision: "deny", reason: "No AWS profile given. Add --profile <name>, or prefix the command with AWS_PROFILE=<name>." };
  }

  // 4. Read-only verbs: require a --query that actually narrows the output,
  //    so the caller has to decide what it needs instead of pulling everything.
  //    (`aws s3 ls` doesn't support --query, so it's exempt.)
  if (/^(describe|list|get|head|lookup|batch-get)-/.test(op)) {
    if (!config.requireQuery) {
      return { decision: "allow", reason: "Read-only aws call (--query not required by configuration)" };
    }
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
