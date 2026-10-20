# Security policy

aws-guard is a security control, so how it can fail matters as much as what it does.

## What it is, and isn't

aws-guard is a **guard rail** for an AI agent that is well-intentioned but fallible, or that has been steered by a prompt injection. It reads the Bash command string Claude is about to run and decides allow, deny or ask. It is **not** a sandbox, and it is not a substitute for least-privilege credentials.

What it assumes:

- The agent's `aws` calls go through the Bash tool as a command string.
- Claude Code runs the hook and honors its decision. That includes under `--dangerously-skip-permissions`, which isn't documented behavior; a CI check re-verifies it against real Claude Code releases on every change and every week, and opens an issue if it changes. See [Compatibility checks](README.md#compatibility-checks) for what it covers and what it doesn't.
- Nothing has modified the hook's files, its registration, or the audit log. By default Claude *can* modify them; [docs/hardening.md](docs/hardening.md) covers locking that down.

## Reporting a vulnerability

Please report privately, not in a public issue, using GitHub's
[private vulnerability reporting](https://github.com/mweberxyz/claude-aws-guard/security/advisories/new).

Include the exact command string (and plugin options) that gets the wrong decision, the decision you expected, and the audit log line if you have one.

Reports are handled on a best-effort basis by a single maintainer. Only the latest release is supported.

## In scope

- A command string the hook should deny or ask about but **allows**. Quoting, flag-spelling, environment-variable, shell-syntax and path tricks all count.
- The hook **failing open**: any situation where a failure, crash, timeout, bad input or bad configuration lets an `aws` call (or any command) through instead of blocking it.
- A configuration value that **loosens** the policy when it should have been rejected.
- The audit log missing an `aws` decision, or recording the wrong one.

## Out of scope (known limits)

These are documented in the [README](README.md#what-it-doesnt-protect-against), not vulnerabilities:

- AWS access that doesn't go through a Bash command string: SDKs such as boto3, other tools that call AWS, or an MCP server.
- Claude (or anything else running as your user) editing the hook, its settings, or the audit log. Use [docs/hardening.md](docs/hardening.md).
- Commands that mention `aws` but that the hook sends to `ask` because it can't parse them. A human decides those by design.
- Running Claude Code with `--dangerously-skip-permissions`. Hooks are still run and their denies and asks still apply (observed, not documented), but the flag is meant to skip approvals. Keep the `permissions.deny` rules.
- Native Windows. The wrapper needs a POSIX shell.
- What a permitted profile is allowed to do in AWS. Use a read-only IAM role or SSO permission set.

## Defense in depth

Don't rely on this hook alone. At minimum: use a read-only role behind the profile you let Claude use, add the `permissions.deny` rules from the README, and consider the hardening steps if Claude shouldn't be able to turn the hook off.
