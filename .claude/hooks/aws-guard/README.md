# aws-guard

A [Claude Code hook](https://code.claude.com/docs/en/hooks) that makes `aws` CLI calls safer when Claude runs them through its Bash tool.

Before every Bash command, the hook checks whether it is an `aws` call. If it isn't, the hook stays out of the way. If it is, the hook allows it, denies it, or asks you, based on a fixed set of rules. Every `aws` decision is written to an audit log.

It is a guard rail, not a sandbox. See [What it doesn't protect against](#what-it-doesnt-protect-against).

## What it does

| Situation | Decision |
|---|---|
| Not an `aws` command (`ls`, `git status`, …) | Nothing: Claude Code's normal permission flow applies |
| Read-only call with a narrowing `--query` | **allow** |
| `aws s3 ls` with a profile | **allow** |
| Any call with `--dry-run` | **allow** |
| Create, update, delete, `s3 cp/sync/rm`, anything unrecognized | **ask** |
| Compound or indirect commands (`;`, `&`, `\|`, backticks, newlines, `$(`, `eval`, `bash -c`, `xargs`) | **ask** |
| Wrappers (`sudo aws`, `time aws`), path-prefixed `aws` (`/usr/local/bin/aws`), unterminated quotes | **ask** |
| No profile given | **deny** |
| Profile name contains `prod` (any case) | **deny** |
| Read-only call with no `--query`, or a `--query` that selects everything | **deny** |
| A hard-denied command (below) | **deny** |
| Anything goes wrong inside the hook | **deny** |

### Hard denies

- `iam` `create-*`, `attach-*`, `put-*`, `update-*`, `delete-*`, `add-*`
- `sts assume-role*`
- everything under `organizations`
- `kms schedule-key-deletion`, `disable-key`, `put-key-policy`
- `s3api delete-bucket*`, `put-bucket-policy`, `put-public-access-block`, `put-bucket-acl`
- `s3 rb`
- `secretsmanager get-secret-value`
- everything under `configure`
- any `ssm` call with `--with-decryption`

### Profiles

Every `aws` call needs an explicit profile, either `--profile NAME` or a leading `AWS_PROFILE=NAME` assignment. This stops a call from landing in whatever default account is configured. `--profile` wins if both are present.

### The `--query` rule

Operations starting with `describe-`, `list-`, `get-`, `head-`, `lookup-` or `batch-get-` must include a `--query` that narrows the output. The point is to make the caller decide which fields it needs instead of pulling everything. These are rejected as "selects everything": `@`, `*`, `[*]`, `[]`, `*.*`. `aws s3 ls` is exempt because high-level `s3` commands don't support `--query`.

### Examples

```sh
# allowed
aws --profile sandbox ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'
AWS_PROFILE=sandbox aws s3 ls

# denied: no query
aws --profile sandbox ec2 describe-instances
# denied: no profile
aws sts get-caller-identity
# denied: hard deny
aws --profile sandbox iam delete-user --user-name x
# denied: prod profile
aws --profile prod-admin s3 ls

# asks: a mutation
aws --profile sandbox ec2 run-instances
# asks: compound command
aws --profile sandbox s3 ls && echo done
```

When a call is denied, Claude sees the reason and can correct itself, for example by adding a profile.

## Install

The hook needs [Bun](https://bun.sh) on the `PATH` and a `~/.claude/` directory. It assumes a POSIX shell, so on Windows use Git Bash or WSL.

1. Put this directory at `.claude/hooks/aws-guard/` in your project.
2. Merge this into `.claude/settings.json`:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [
             {
               "type": "command",
               "command": "bun run \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/aws-guard/aws_guard.ts 2>>\"$HOME/.claude/aws-audit.log\" || { echo 'aws_guard failed' >&2; exit 2; }",
               "timeout": 10,
               "onFailure": "block"
             }
           ]
         }
       ]
     },
     "permissions": {
       "deny": [
         "Bash(aws iam:*)",
         "Bash(aws organizations:*)",
         "Bash(aws sts assume-role:*)",
         "Bash(aws configure:*)",
         "Bash(aws secretsmanager get-secret-value:*)"
       ]
     }
   }
   ```

3. Run `bun test` in this directory to check the install.

The command wrapper matters. It makes the shell write the audit log, and it turns a crash of the script into exit code 2, which blocks the call. Run the script bare and a crash would let the command through. `onFailure` needs Claude Code v2.1.295 or later; it makes timeouts and other hook failures block too.

The `permissions.deny` entries are a second layer. Claude Code enforces them itself, so they still apply if the hook crashes or `bun` is missing. They repeat the hard denies on purpose.

## The audit log

Every `aws` decision is appended to `~/.claude/aws-audit.log` as one JSON line:

```json
{"ts":"2026-10-18T02:01:49.069Z","decision":"deny","reason":"Add --profile <sandbox-profile> (and --region)","cmd":"aws sts get-caller-identity"}
```

Commands that aren't `aws` calls are not logged. The shell opens the log, not the script. If it can't be opened (for example `~/.claude/` doesn't exist), the hook fails and the command is blocked. The log can also pick up non-JSON error text if the hook itself breaks, so filter with care.

## Failing closed

The hook is designed so that a problem blocks a command, not lets it through:

- An error inside the script (bad input, a bug) becomes a **deny** with the error in the reason.
- A crash outside the script's own error handling makes the wrapper exit 2, which blocks.
- A timeout or other hook failure blocks, through `onFailure`.
- An unwritable audit log blocks.

The flip side: if `bun` isn't installed, or the script path in `settings.json` is wrong, **every Bash command is blocked**, not just `aws` ones. If Claude Code starts refusing everything with `aws_guard failed`, check those two things first. Edit `settings.json` with a tool that isn't a Bash command, since Bash is what's blocked.

## What it doesn't protect against

- **Anything that isn't a Bash command string.** A script that calls AWS through boto3 or another SDK bypasses the hook.
- **Commands it can't parse.** Compound and indirect commands go to `ask`, so a human decides, and the hook doesn't try to reason about them.
- **Loose matching.** Any command that mentions `aws` after whitespace, a quote or a `/` is treated as an `aws` call, so even a heredoc that only contains the word gets an `ask` and an audit line. This is noisy on purpose.

Back the profile with a read-only IAM role or SSO permission set so the hook isn't your only protection.

## Performance

About 8 to 10 ms per Bash call, whatever the decision, mostly Bun's startup. See [benchmarking.md](benchmarking.md).

## Development

```sh
bun test              # all tests
bun test --coverage   # coverage of aws_guard_lib.ts
```

| File | Role |
|---|---|
| `aws_guard.ts` | Entry point: reads stdin, prints the decision, writes the audit line, fails closed |
| `aws_guard_lib.ts` | The policy: `shellSplit`, `parseAws`, `evaluate`. No I/O |
| `aws_guard_lib.test.ts` | In-process tests: the full policy table and parser edge cases |
| `aws_guard.test.ts` | Subprocess tests: end-to-end smoke cases, fail-closed behavior, audit log, the `settings.json` wrapper |
| `benchmarking.md` | Latency numbers and the script that produced them |
| `CLAUDE.md` | Notes for Claude when editing this directory |

To change a rule, edit `aws_guard_lib.ts`, add or update its row in the policy table in `aws_guard_lib.test.ts`, and mirror hard denies in `permissions.deny`.
