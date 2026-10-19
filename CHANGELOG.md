# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org). Because the policy decides what Claude may run, tightening a default (a new hard deny, a stricter rule) is treated as a breaking change.

## [0.1.1] - 2026-10-19

### Added

- `block_profiles` option (default `true`). Set it to `false` to disable the blocked-profile rule entirely. Calls must still name a profile, and every other rule still applies.

## [0.1.0] - 2026-10-18

First public release.

### Policy

- Allows, denies or asks for `aws` CLI calls made through the Bash tool; all other commands pass through untouched.
- Requires an explicit profile (`--profile`, or a leading `AWS_PROFILE=`) and denies profiles matching a blocked pattern (default `prod`).
- Read-only verbs (`describe-`, `list-`, `get-`, `head-`, `lookup-`, `batch-get-`) need a narrowing `--query`; `@`, `*`, `[*]`, `[]` and `*.*` are rejected.
- Hard denies: IAM writes, `sts assume-role*`, all of `organizations`, destructive `kms` operations, risky `s3api` and `s3 rb` operations, `secretsmanager get-secret-value`, `configure`, and `ssm … --with-decryption`.
- Compound or indirect commands, wrappers such as `sudo aws`, path-prefixed `aws` and unterminated quotes ask.
- `--dry-run` and `aws s3 ls` are allowed.

### Packaging and configuration

- Ships as a Claude Code plugin and marketplace (`aws-guard`); also installable by hand with `examples/settings.json`.
- Four options through the plugin's `userConfig`: `blocked_profile_pattern`, `extra_denied_commands`, `require_query`, `use_environment_profile`. A setting that can't be parsed denies `aws` calls instead of falling back to a default.
- Runs on Bun or Node from a committed build (`dist/aws_guard.mjs`). Prefers Bun: about 10.5 ms per Bash call, against about 43 ms on Node.

### Reliability

- Fails closed: script errors become denies, a crash or timeout blocks through exit 2 and `onFailure: block`, and an unwritable audit log blocks.
- Appends one JSON line per `aws` decision to `~/.claude/aws-audit.log`.
- Reads stdin with plain reads so startup stays cheap, and handles late and very large input.

### Docs and tooling

- README, [security policy](SECURITY.md), [hardening guide](docs/hardening.md) and [benchmarks](docs/benchmarking.md).
- 190 tests (100% function and line coverage of the policy lib), `tsc --strict`, and CI that checks the build is current and runs `claude plugin validate --strict`.

[0.1.1]: https://github.com/mweberxyz/claude-aws-guard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mweberxyz/claude-aws-guard/releases/tag/v0.1.0
