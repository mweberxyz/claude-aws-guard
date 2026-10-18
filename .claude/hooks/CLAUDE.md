# .claude/hooks

Holds `aws_guard`, a PreToolUse hook that guards `aws` CLI calls made through Claude Code's Bash tool. It runs on Bun (TypeScript).

## Files

| File | Purpose |
|---|---|
| `aws_guard.ts` | Entry point. Reads the tool call as JSON on stdin, prints one decision, exits. Owns all I/O: the audit line on stderr, the fail-closed `catch`. |
| `aws_guard_lib.ts` | Pure policy logic (`shellSplit`, `parseAws`, `evaluate`). No I/O, so it can be unit tested in-process. |
| `aws_guard_lib.test.ts` | In-process tests. Owns the full policy matrix and the parser edge cases. |
| `aws_guard.test.ts` | Subprocess tests. A small smoke set plus passthrough, fail-closed, audit-log and `settings.json` wrapper checks. |
| `benchmarking.md` | Latency measurements and how to reproduce them. |

The hook is registered in `../settings.json`, which also holds a second layer of `permissions.deny` entries.

## Commands

```sh
cd /home/user/.claude/hooks
bun test                  # all tests
bun test --coverage       # coverage covers aws_guard_lib.ts only
```

Coverage only sees the lib, because `aws_guard.ts` runs in a subprocess in the tests. Keep it at 100% function and line coverage for the lib.

## Rules to preserve

- **Fail closed.** Any error inside the script becomes a deny. The `settings.json` wrapper turns a crash into exit 2 and sets `"onFailure": "block"` so timeouts and other hook failures block the call too. Don't weaken either.
- **Non-`aws` commands pass through** with no output, exit 0 and no audit line. There is no `passthrough` value for `permissionDecision`; silence is how it is expressed.
- **The audit log is written by the shell**, not the script. The script writes one JSON line per `aws` call to stderr (`ts`, `decision`, `reason`, `cmd`), and the wrapper appends stderr to `~/.claude/aws-audit.log`. If that file can't be opened, the wrapper blocks the call.
- **Keep `aws_guard_lib.ts` free of I/O**, and keep `aws_guard.ts` thin.
- **Decision order in `evaluate()` matters:** compound/indirect commands ask, then hard denies, then prod profile, then missing profile, then the read-verb `--query` rules, then `s3 ls` and `--dry-run`, then ask for everything else.

## When changing a rule

1. Change `aws_guard_lib.ts`.
2. Add or update the row in the policy table in `aws_guard_lib.test.ts`.
3. Update the `permissions.deny` entries in `../settings.json` if it is a hard deny, since they duplicate the script's denies on purpose.
4. Only touch the smoke set in `aws_guard.test.ts` if a decision type or the I/O path changed.
5. Run `bun test --coverage`.

## Known limits

- The hook only sees the Bash command string. A script that calls AWS through boto3 or another SDK bypasses it, so the profile should also be backed by a read-only IAM role or SSO permission set.
- `aws` after a `/` or a quote counts as an aws call. Path-prefixed calls (`/usr/local/bin/aws`) go to `ask`, and so does any command ending in `/aws` such as `ls /var/aws`.
- The wrapper's `2>>` redirect and `||` assume a POSIX shell. It won't work as written on Windows without Git Bash or WSL.
- `bun` must be on the PATH. If it isn't, every Bash call is blocked, not just `aws` ones.
- The design relies on Claude Code's hook semantics (exit 2 blocks, `permissionDecision` is `allow`/`deny`/`ask`, `timeout` in seconds, `onFailure`). These were checked against the hooks docs but the hook has not been exercised inside Claude Code itself.
- `onFailure` needs Claude Code v2.1.295 or later.
