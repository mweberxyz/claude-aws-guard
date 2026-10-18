# aws-guard

[![CI](https://github.com/mweberxyz/claude-aws-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mweberxyz/claude-aws-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A [Claude Code](https://code.claude.com) plugin that makes `aws` CLI calls safer when Claude runs them through its Bash tool.

Before every Bash command, a [PreToolUse hook](https://code.claude.com/docs/en/hooks) checks whether it is an `aws` call. If it isn't, the hook stays out of the way. If it is, the hook **allows**, **denies** or **asks you**, using a fixed set of rules, and writes the decision to an audit log. When it denies a call, Claude sees the reason and can correct itself.

```text
Claude:  aws ec2 describe-instances
Hook:    denied - No AWS profile given. Add --profile <name>, or prefix the command with AWS_PROFILE=<name>.

Claude:  aws --profile sandbox ec2 describe-instances
Hook:    denied - Read calls need --query selecting only the fields you need
         (e.g. --query 'Reservations[].Instances[].[InstanceId,State.Name]')

Claude:  aws --profile sandbox ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'
Hook:    allowed
```

It is a guard rail, not a sandbox: see [What it doesn't protect against](#what-it-doesnt-protect-against).

## Install

```text
/plugin install aws-guard --marketplace mweberxyz/claude-aws-guard
```

You can also add the marketplace first with `/plugin marketplace add mweberxyz/claude-aws-guard` and then `/plugin install aws-guard@aws-guard`. When the plugin is enabled, Claude Code prompts for the [options](#configuration); the defaults are sensible.

Requirements:

- **Claude Code 2.1.295 or later.** The hook sets `onFailure: block`, which earlier versions don't know.
- **`bun` or `node` on your `PATH`.** The hook prefers Bun, which starts about four times faster (see [docs/benchmarking.md](docs/benchmarking.md)).
- **A POSIX shell.** On Windows, use WSL or Git Bash.
- **A `~/.claude/` directory,** which exists once Claude Code has run. The audit log is appended there.

If neither `bun` nor `node` is installed, the hook blocks Bash commands with the message `aws-guard needs node or bun on PATH`. See [Troubleshooting](#troubleshooting).

### Recommended: add the deny rules

A plugin can't ship permission rules, so add this second layer to your own `.claude/settings.json` (or `~/.claude/settings.json`). Claude Code enforces it itself, so it still applies if the hook crashes or can't run:

```json
{
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

### Manual install, without the plugin

Copy `plugins/aws-guard/dist/aws_guard.mjs` to `.claude/hooks/aws-guard/aws_guard.mjs` in your project and merge [`examples/settings.json`](examples/settings.json) into `.claude/settings.json`. A manual install has no options, so it always uses the defaults.

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
| Profile name matches the blocked pattern (default: contains `prod`) | **deny** |
| Read-only call with no `--query`, or a `--query` that selects everything | **deny** |
| A hard-denied command (below) | **deny** |
| Anything goes wrong inside the hook | **deny** |

### Hard denies

These can't be configured away:

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

Every `aws` call needs an explicit profile, either `--profile NAME` or a leading `AWS_PROFILE=NAME` assignment, so a call can't land in whatever default account is configured. `--profile` wins if both are present. If you would rather rely on an `AWS_PROFILE` already set in Claude Code's environment, turn on the `use_environment_profile` [option](#configuration).

### The `--query` rule

Operations starting with `describe-`, `list-`, `get-`, `head-`, `lookup-` or `batch-get-` must include a `--query` that narrows the output, so the caller decides which fields it needs instead of pulling everything. These are rejected as "selects everything": `@`, `*`, `[*]`, `[]`, `*.*`. `aws s3 ls` is exempt because high-level `s3` commands don't support `--query`.

### Examples

```sh
# allowed
aws --profile sandbox ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'
AWS_PROFILE=sandbox aws s3 ls

# denied: no query / no profile / hard deny / prod profile
aws --profile sandbox ec2 describe-instances
aws sts get-caller-identity
aws --profile sandbox iam delete-user --user-name x
aws --profile prod-admin s3 ls

# asks: a mutation / a compound command
aws --profile sandbox ec2 run-instances
aws --profile sandbox s3 ls && echo done
```

## Configuration

Claude Code prompts for these when the plugin is enabled and passes them to the hook as `CLAUDE_PLUGIN_OPTION_<NAME>` environment variables. Change them from the `/plugin` panel or `/config`.

| Option | Default | What it does |
|---|---|---|
| `blocked_profile_pattern` | `prod` | Case-insensitive regular expression. Calls using a profile whose name matches are always denied. |
| `extra_denied_commands` | none | Comma-separated commands to always deny, written `service` or `service:operation-prefix`, for example `rds,ec2:terminate-`. |
| `require_query` | `true` | Deny read-only calls without a narrowing `--query`. |
| `use_environment_profile` | `false` | Use `AWS_PROFILE` from Claude Code's environment when a call names no profile. The profile is still checked against the blocked pattern. |

A setting that can't be parsed (an invalid regular expression, a malformed denied-command entry, a boolean that isn't `true` or `false`) is an error and not a silent default, so a typo can't loosen the policy. While a setting is broken, every `aws` call is denied with `aws-guard configuration error: …`; other commands are unaffected.

## The audit log

Every `aws` decision is appended to `~/.claude/aws-audit.log` as one JSON line:

```json
{"ts":"2026-10-18T02:01:49.069Z","decision":"deny","reason":"No AWS profile given. Add --profile <name>, or prefix the command with AWS_PROFILE=<name>.","cmd":"aws sts get-caller-identity"}
```

Commands that aren't `aws` calls are not logged. The shell opens the log, not the script. If it can't be opened (for example `~/.claude/` doesn't exist), the hook fails and the command is blocked. The log can also pick up non-JSON error text if the hook itself breaks, so filter with care.

## Failing closed

The hook is built so that a problem blocks a command instead of letting it through:

- An error inside the script (bad input, a bug) becomes a **deny** with the error in the reason.
- A crash outside the script's own error handling makes the wrapper exit 2, which blocks.
- A timeout or other hook failure blocks, through `onFailure: block`.
- An unwritable audit log blocks.
- A missing `bun` and `node` blocks, with a message saying so.

## What it doesn't protect against

- **Anything that isn't a Bash command string.** A script that calls AWS through boto3 or another SDK bypasses the hook.
- **Commands it can't parse.** Compound and indirect commands go to `ask`, so a human decides; the hook doesn't try to reason about them.
- **Claude changing the hook itself.** The Edit tool isn't a Bash command, so the hook can't see it. See [docs/hardening.md](docs/hardening.md).
- **Loose matching.** Any command that mentions `aws` after whitespace, a quote or a `/` is treated as an `aws` call, so even a heredoc that only contains the word gets an `ask` and an audit line. This is noisy on purpose.

Back the profile with a read-only IAM role or SSO permission set so the hook isn't your only protection. To report a way around the hook, see [SECURITY.md](SECURITY.md).

## Troubleshooting

**Every Bash command is blocked.** The hook fails closed, so a missing runtime or a broken install blocks everything, not only `aws` calls. Check that `bun` or `node` is on the `PATH` Claude Code uses, and that Claude Code is 2.1.295 or later. To get unblocked, run `claude plugin uninstall aws-guard` in a normal terminal, or use the `/plugin` panel. Neither is a Bash tool call, so the hook doesn't see them.

**A command was asked about that you expected to pass.** Compound commands, wrappers and path-prefixed `aws` all go to `ask` by design. Look at the `reason` in the audit log.

**A command was denied for a profile you expected to be allowed.** Check `blocked_profile_pattern`: the default `prod` matches any profile containing it, such as `reproduction`.

## Development

```sh
bun install
bun run typecheck       # tsc --strict
bun test                # all tests
bun test --coverage     # coverage of the policy lib
bun run build           # rebuild plugins/aws-guard/dist after changing src/
bun run check-dist      # fail if dist/ is out of date
bun run validate        # claude plugin validate, plugin and marketplace
bun run bench           # per-call latency
```

`dist/aws_guard.mjs` is committed because the plugin ships it; always rebuild it when you change `src/`. See [CLAUDE.md](CLAUDE.md) for the layout and the rules to preserve.

## License

[MIT](LICENSE)
