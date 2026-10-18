#!/usr/bin/env python3
import json, re, shlex, sys

data = json.load(sys.stdin)
cmd = data.get("tool_input", {}).get("command", "")

def decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,          # allow | deny | ask
        "permissionDecisionReason": reason}}))
    sys.exit(0)

# Not an aws call? Stay out of the way.
if not re.search(r"(^|[\s;&|(`])aws(\s|$)", cmd):
    sys.exit(0)

# 1. Compound/obfuscated commands: can't reason about them, so ask.
if re.search(r"[;&|`]|\$\(|\n|\beval\b|\bbash -c\b|\bxargs\b", cmd):
    decide("ask", "aws inside a compound or indirect command")

try:
    argv = shlex.split(cmd)
except ValueError:
    decide("ask", "Unparseable command")

args = [a for a in argv[1:] if not a.startswith("-")]
service, op = (args + ["", ""])[:2]
flags = " ".join(a for a in argv if a.startswith("-"))

# 2. Hard denies
DENY_SERVICE_OPS = {
    ("iam", r"^(create|attach|put|update|delete|add)-"),
    ("sts", r"^assume-role"),
    ("organizations", r".*"),
    ("kms", r"^(schedule-key-deletion|disable-key|put-key-policy)"),
    ("s3api", r"^(delete-bucket|put-bucket-policy|put-public-access-block|put-bucket-acl)"),
    ("s3", r"^(rb)$"),
    ("secretsmanager", r"^get-secret-value$"),
    ("configure", r".*"),
}
for svc, pat in DENY_SERVICE_OPS:
    if service == svc and re.match(pat, op):
        decide("deny", f"aws {service} {op} is blocked by policy")
if service == "ssm" and "--with-decryption" in argv:
    decide("deny", "Decrypting SSM parameters is blocked")
if re.search(r"--profile[= ]+\S*prod", cmd, re.I):
    decide("deny", "Prod profiles are off-limits from Claude Code")

# 3. Require explicit identity so we never hit a default/prod account
if "--profile" not in cmd and "AWS_PROFILE=" not in cmd:
    decide("deny", "Add --profile <sandbox-profile> (and --region)")

# 4. Auto-allow read-only verbs
if re.match(r"^(describe|list|get|head|lookup|batch-get)-", op) or (service, op) == ("s3", "ls"):
    decide("allow", "Read-only aws call")
if "--dry-run" in argv:
    decide("allow", "Dry run")

# 5. Everything else (create/update/delete/s3 cp/rm/sync...) -> human decides
decide("ask", f"Mutating or unrecognized: aws {service} {op}")
