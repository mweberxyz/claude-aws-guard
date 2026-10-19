# claude-aws-guard

A Claude Code plugin (`aws-guard`) containing a PreToolUse hook that guards `aws` CLI calls made through the Bash tool. Written in TypeScript, developed and tested with Bun, shipped as a built file that runs on Bun or Node.

## Layout

| Path | Purpose |
|---|---|
| `plugins/aws-guard/src/aws_guard.ts` | Entry point. Reads the tool call as JSON on fd 0, prints one decision, exits. Owns all I/O: stdin, the audit line on stderr, the fail-closed `catch`. |
| `plugins/aws-guard/src/aws_guard_lib.ts` | Pure policy logic (`shellSplit`, `parseAws`, `loadConfig`, `evaluate`). No I/O, so it is unit tested in-process. |
| `plugins/aws-guard/dist/aws_guard.mjs` | The built file the plugin actually runs. **Committed.** Rebuild after any change under `src/`. |
| `plugins/aws-guard/hooks/hooks.json` | Hook registration and the shell wrapper command. |
| `plugins/aws-guard/.claude-plugin/plugin.json` | Plugin manifest, including the `userConfig` options. |
| `.claude-plugin/marketplace.json` | Marketplace listing for the plugin. |
| `examples/settings.json` | Manual-install settings plus the `permissions.deny` second layer (a plugin can't ship those). |
| `test/aws_guard_lib.test.ts` | In-process tests. Owns the full policy matrix, the parser and the config. |
| `test/aws_guard.test.ts` | Subprocess tests: a small smoke set, config through env vars, stdin handling, the built file under Node, fail-closed, audit log, the `hooks.json` wrapper. |
| `scripts/bench.ts` | Latency benchmark. Results in `docs/benchmarking.md`. |
| `scripts/compat/` | The Claude Code compatibility check: `lib.ts` (pure: versions, assertions, report text), `mock_api.ts` (the stand-in for the Anthropic API), `harness.ts` (the throwaway project and fake `aws`), `probe.ts` (`claude -p`), `ask_sdk.ts` (Agent SDK `canUseTool`), `versions.ts`, `report.ts` (summary and issue). |
| `.github/workflows/compat.yml` | Runs the above on pull requests, pushes to `main`, release tags, weekly and on demand. No secrets. |
| `test/compat.test.ts` | Unit tests for `scripts/compat/lib.ts` and `mock_api.ts`, and a dry run of `report.ts`. |
| `docs/hardening.md` | How to stop Claude changing the hook. Not applied by default. |
| `SECURITY.md`, `CHANGELOG.md`, `README.md` | Public docs. |
| `.claude/skills/release/SKILL.md` | The release process: whether to release, which version, the release commit and the `gh release create` command. |

This `CLAUDE.md` is deliberately at the repo root, outside `plugins/aws-guard/`: a `CLAUDE.md` inside a plugin isn't loaded as context and `claude plugin validate` warns about it.

## Commands

```sh
bun install
bun run typecheck         # tsc --strict
bun test                  # all tests
bun test --coverage       # coverage covers the lib only
bun run test:node         # only the tests that run dist/ under the Node on PATH (the CI matrix runs this)
bun run build             # rebuild dist/ (use Bun 1.4.2: CI pins it)
bun run check-dist        # fail if dist/ differs from a fresh build
bun run validate          # claude plugin validate, plugin and marketplace
bun run bench             # latency
```

Coverage only sees `aws_guard_lib.ts`, `scripts/compat/lib.ts` and `scripts/compat/mock_api.ts`, because `aws_guard.ts` and the other scripts run in subprocesses in the tests. Keep all three at 100% function and line coverage.

## Rules to preserve

- **Fail closed.** Any error inside the script becomes a deny. The `hooks.json` wrapper turns a crash into exit 2 and sets `"onFailure": "block"`, so timeouts and other hook failures block too. Don't weaken either.
- **Non-`aws` commands pass through** with no output, exit 0 and no audit line. There is no `passthrough` value for `permissionDecision`; silence is how it is expressed.
- **The audit log is written by the shell**, not the script. The script writes one JSON line per `aws` call to stderr (`ts`, `decision`, `reason`, `cmd`), and the wrapper appends stderr to `~/.claude/aws-audit.log`. If that file can't be opened, the wrapper blocks the call.
- **Configuration fails closed too.** Anything in `loadConfig` that can't be parsed is an error, never a default. A config error denies `aws` calls only and must never affect other commands. The built-in hard denies and the explicit-profile requirement cannot be configured away.
- **Keep `aws_guard_lib.ts` free of I/O**, and keep `aws_guard.ts` thin.
- **`compat.yml` holds no secrets and uses a mock API, not a model.** What it checks is Claude Code's handling of a tool call, which a model doesn't influence. That is what lets it run on pull requests, forks included: never add a secret to it, and never trigger it with `pull_request_target`. Only the `report` job may have `issues: write`, and it must not run on pull requests or run code from npm. Report text is assembled from fixed strings (`sanitizeLeg` in `scripts/compat/lib.ts`). Keep the mock minimal: if a new Claude Code release stops reporting back, fix the mock, and that shows up as a harness error, not a failure. A change to the documented Claude Code behavior in the README or `SECURITY.md` should change the claims table under "Compatibility checks" too. If the README's minimum Claude Code version changes, change `MIN_CLAUDE_CODE` in the workflow (a test checks they match).
- **Keep startup cheap.** The hook runs before every Bash call. Don't read stdin through `process.stdin` (about 17 ms extra on Bun) and don't add imports with heavy startup. Re-run `bun run bench` if you change how the script starts.
- **Runtime preference is Bun, then Node.** Bun starts about four times faster. The hook must keep working on Node, and the tests run the built file under Node.
- **Decision order in `evaluate()` matters:** configuration error, then compound/indirect commands ask, then hard denies (built-in, then configured), then the blocked-profile pattern (skipped when `block_profiles` is off), then missing profile, then the read-verb `--query` rules, then `s3 ls` and `--dry-run`, then ask for everything else.

## When changing a rule

1. Change `plugins/aws-guard/src/aws_guard_lib.ts`.
2. Add or update the row in the policy table in `test/aws_guard_lib.test.ts`.
3. Update `permissions.deny` in `examples/settings.json` and in the README if it is a hard deny, since they duplicate the script's denies on purpose.
4. Only touch the smoke set in `test/aws_guard.test.ts` if a decision type or the I/O path changed.
5. `bun run build`, then `bun run typecheck && bun test --coverage && bun run validate`.
6. Update `README.md` and `CHANGELOG.md` if behavior or options changed.

## Versioning

Semver, read the way pre-1.0 software is usually read. While the version is `0.x.y`:

- **Patch (`0.x.Y`)**: bug fixes, and new features or options that are completely backwards compatible. A new option must default to the old behavior, and existing configs and commands must decide exactly as before.
- **Minor (`0.X.0`)**: anything that is not completely backwards compatible, including tightening a default (a new hard deny, a stricter rule), as `CHANGELOG.md` says.

### Releasing

Invoke the `release` skill (`.claude/skills/release/SKILL.md`) whenever a PR is close to merging, and whenever the user asks for a release. It decides whether the change needs a release at all, picks the version, prepares the release commit and gives the user a `gh release create` command to run. Many PRs won't need a release, and the skill ends quickly when they don't.

A release can be the last commit on the PR branch before it merges, or its own conversation and PR after several unreleased commits have landed on `main`. In the second case the skill reviews those commits to decide what belongs in the release notes.

The release commit sets the same version in `package.json` and `plugins/aws-guard/.claude-plugin/plugin.json` and dates the `CHANGELOG.md` section. Don't create or push tags or releases: the signer only signs commits and the session can't push tags. The user runs the `gh` command.

## Known limits

See "What it doesn't protect against" in the README and `SECURITY.md`. The ones that matter when editing:

- The hook only sees the Bash command string.
- Anything mentioning `aws` after whitespace, a quote or a `/` is treated as an `aws` call, so unrelated compound commands that merely contain the word get an `ask` and an audit line. That is intentional.
- The wrapper's `2>>` redirect and `||` assume a POSIX shell.
- Verified against the hooks docs: exit 2 blocks, other non-zero exits don't (hence `onFailure`), `permissionDecision` is `allow`/`deny`/`ask`/`defer`, `timeout` is in seconds. Observed working inside Claude Code: deny (reason shown to Claude), allow and hook-failure blocking. **Not yet observed:** how an `ask` prompts an interactive user, and whether plugin hooks honor `onFailure` exactly like settings hooks (`claude plugin validate` accepts it). The compatibility check (README, "Compatibility checks") re-verifies the deny, allow, `permission_mode` and `ask` behavior on every change and every week, under `--dangerously-skip-permissions` too, but not those two.
- `onFailure` needs Claude Code 2.1.295 or later.
