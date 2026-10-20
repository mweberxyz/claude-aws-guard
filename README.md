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
| Profile name matches the blocked pattern (default: contains `prod`; can be turned off with `block_profiles`) | **deny** |
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
| `block_profiles` | `true` | Apply the blocked profile pattern. Set to `false` to disable the rule entirely; calls must still name a profile. |
| `blocked_profile_pattern` | `prod` | Case-insensitive regular expression. Calls using a profile whose name matches are always denied. Ignored when `block_profiles` is `false`. |
| `extra_denied_commands` | none | Comma-separated commands to always deny, written `service` or `service:operation-prefix`, for example `rds,ec2:terminate-`. |
| `require_query` | `true` | Deny read-only calls without a narrowing `--query`. |
| `use_environment_profile` | `false` | Use `AWS_PROFILE` from Claude Code's environment when a call names no profile. The profile is still checked against the blocked pattern, unless `block_profiles` is `false`. |

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

### `--dangerously-skip-permissions`

The hook still runs when Claude Code is started with `--dangerously-skip-permissions` (`permission_mode` is `bypassPermissions`). Observed on Claude Code in October 2026: a `deny` still blocks the call and an `ask` still prompts you. Don't rely on that alone, since the flag exists to skip prompts and the hooks docs don't promise it. Keep the `permissions.deny` rules from [Recommended: add the deny rules](#recommended-add-the-deny-rules); Claude Code enforces them in every mode.

Back the profile with a read-only IAM role or SSO permission set so the hook isn't your only protection. To report a way around the hook, see [SECURITY.md](SECURITY.md).

## Troubleshooting

**Every Bash command is blocked.** The hook fails closed, so a missing runtime or a broken install blocks everything, not only `aws` calls. Check that `bun` or `node` is on the `PATH` Claude Code uses, and that Claude Code is 2.1.295 or later. To get unblocked, run `claude plugin uninstall aws-guard` in a normal terminal, or use the `/plugin` panel. Neither is a Bash tool call, so the hook doesn't see them.

**A command was asked about that you expected to pass.** Compound commands, wrappers and path-prefixed `aws` all go to `ask` by design. Look at the `reason` in the audit log.

**A command was denied for a profile you expected to be allowed.** Check `blocked_profile_pattern`: the default `prod` matches any profile containing it, such as `reproduction`. To drop the rule altogether, set `block_profiles` to `false`.

## Development

```sh
bun install
bun run typecheck       # tsc --strict
bun test                # all tests
bun test --coverage     # coverage of the policy lib
bun run test:node       # only the tests that run the built file under your Node
bun run build           # rebuild plugins/aws-guard/dist after changing src/
bun run check-dist      # fail if dist/ is out of date
bun run validate        # claude plugin validate, plugin and marketplace
bun run bench           # per-call latency
```

`dist/aws_guard.mjs` is committed because the plugin ships it; always rebuild it when you change `src/`. See [CLAUDE.md](CLAUDE.md) for the layout and the rules to preserve.

### Compatibility checks

Some of what these docs say about Claude Code is observed behavior, not documented behavior, so it could change in a release without anyone noticing. A workflow, [`compat.yml`](.github/workflows/compat.yml), checks it against the real `claude`. It runs on pull requests, on pushes to `main`, weekly, on release tags and on demand.

Each run covers three Claude Code versions: the minimum this README requires, the newest release and the release before it. For each version it starts `claude -p` with the guard installed the [manual way](#manual-install-without-the-plugin), in normal mode and with `--dangerously-skip-permissions`, and has Claude Code run four fixed commands:

| Command | Expected |
|---|---|
| `aws s3 ls --profile test` | allowed: the fake `aws` runs, the audit log says `allow` |
| `aws iam list-users --profile prod` | denied: the fake `aws` does not run, the audit log says `deny`, and Claude is told the reason |
| `aws s3 cp ./x s3://b/x --profile test` | asks: the fake `aws` does not run, the audit log says `ask` |
| `echo hello` | passes through: no audit line |

A second hook logs every Bash call's input, so the check also asserts that `permission_mode` is `bypassPermissions` with the flag and a different documented value without it.

`claude -p` has no prompt to show, so it can only prove that the `ask`ed command did not run, not that a user would have been asked. A second script, [`scripts/compat/ask_sdk.ts`](scripts/compat/ask_sdk.ts), closes that gap with the [Agent SDK](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk), using the SDK release that bundles the same Claude Code version. The SDK calls its `canUseTool` callback where Claude Code would show a permission prompt, so the check asserts that the `ask` reaches the callback, with `--dangerously-skip-permissions` and in normal mode as a control. The callback always denies, so nothing runs. (The SDK warns that `canUseTool` "will not be invoked" under `bypassPermissions`; a hook's `ask` still reaches it, which is what this check watches.)

**There is no model and no API key.** What the docs claim is about Claude Code's own handling of a tool call (hooks, permission modes, what it reports back), not about what a model says. So `ANTHROPIC_BASE_URL` points at a small mock of the Messages API, [`scripts/compat/mock_api.ts`](scripts/compat/mock_api.ts), that asks for one scripted Bash command and records the result Claude Code sends back. The run is deterministic, costs nothing and holds no secrets, which is why it can run on pull requests from forks. Nothing touches AWS: the `aws` on `PATH` is a shim that records its arguments and exits.

Assertions use side effects only: what the hook saw, the audit log, whether the fake `aws` ran, and the result sent back to the mock. If Claude Code never reports back on the call, that is a harness error (usually the mock lacks something a new release needs), and it is reported apart from a behavior failure. If it reports back but the hook never saw the call, that is a failure.

#### What each claim rests on

Check names are `<mode>/<command>`, as they appear in the run summary: `normal` is without the flag, `bypass` is with `--dangerously-skip-permissions`.

| What these docs say | Checked by | What it doesn't cover |
|---|---|---|
| The hook runs for every Bash call, also with `--dangerously-skip-permissions` | every check: it fails with `hook_not_run` if Claude Code ran the call and the logging hook next to the guard never saw it | |
| The hook payload's `permission_mode` is `bypassPermissions` with the flag, and another documented value without it | the `permission_mode` assertion on every check | modes other than the two above |
| A hard deny still blocks under the flag, is audited, and Claude is told why | `normal/deny` and `bypass/deny`: the fake `aws` doesn't run, the audit line says `deny`, and the result sent back to the mock contains the reason as an error | how a real model reacts to the reason |
| An allowed call runs, and a non-`aws` command passes through silently | `*/allow` and `*/passthrough` | |
| An `ask` doesn't run silently under the flag | `bypass/ask`: the fake `aws` doesn't run, the audit line says `ask` | |
| An `ask` still prompts the user under the flag | `bypass/ask_prompt`: the `ask` reaches the Agent SDK's `canUseTool` callback, with `normal/ask_prompt` as the control | the wording or look of the prompt, and how an interactive terminal shows it |
| The plugin needs Claude Code 2.1.295 or later | all of the above, on that exact version | |

The checks use the manual install (`examples/settings.json`), which is the same hook command and the same decisions as the plugin install, but they don't exercise `hooks/hooks.json` or the plugin options, or whether plugin hooks honor `onFailure` the way settings hooks do. They establish that the three Claude Code versions tested behave as above on every change and every week; they don't promise it for versions that don't exist yet. And because the model is a mock, they say nothing about how a real model behaves: they are about what Claude Code does with a tool call.

To run it yourself, with `claude` of the version you want on your `PATH`, as a user that isn't root (Claude Code refuses the bypass flag as root):

```sh
bun scripts/compat/probe.ts --version "$(claude --version | cut -d' ' -f1)" --out /tmp/compat
```

The Agent SDK check needs the SDK release that bundles that Claude Code version (`bun scripts/compat/versions.ts` prints the match as `sdk`):

```sh
npm install --prefix /tmp/sdk --ignore-scripts @anthropic-ai/claude-agent-sdk@<sdk version>
bun scripts/compat/ask_sdk.ts --version <claude version> --sdk-dir /tmp/sdk --out /tmp/compat
```

#### When a check fails

On a pull request, a failing check just turns the run red, and each version's table is in its run summary. On every other run (`main`, release tags, weekly, manual) a last job, `Report`, writes one table for all versions to the run summary. When any check fails, or a version produces no usable results, it opens an issue labeled `compat-check`, or comments on the one that is already open. The text says which versions failed: if only the newest release does, Claude Code's behavior most likely changed upstream, and the docs or the plugin need a look. When a later run passes everything, the job comments and closes the issue.

That job is separate from the probe jobs because it is the only one that can write issues, so the token that can write never runs code from npm or from the pull request under test. The probe results are read back through an allow-list, and the issue text is assembled from fixed strings, so nothing a probe wrote can reach an issue.

## License

[MIT](LICENSE)
