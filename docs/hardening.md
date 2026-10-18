# Making aws-guard more airtight

Out of the box, **Claude can change the things that protect you**: the hook's files, the settings that register it, and the audit log. The Edit tool isn't a Bash command, so a Bash hook never sees it. If the hook is meant to hold against Claude itself, or against a prompt injection that steers it, lock down who can change it.

These steps run from strongest to weakest, and you can combine them. None of them is applied by default.

## 1. Deploy the hook as managed settings

Managed settings have the highest precedence. Nothing in user, project, local or `--settings` values overrides them, apart from a few security-sensitive exceptions where a stricter lower-level value still counts. Put the hook registration and the deny list in `managed-settings.json` instead of leaving them in a plugin or a project file:

- Linux and WSL: `/etc/claude-code/managed-settings.json`
- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Windows: `C:\Program Files\ClaudeCode\managed-settings.json`

Point the managed hook at a copy of `aws_guard.mjs` that Claude can't write to (step 2). The command is the one in [`examples/settings.json`](../examples/settings.json), with an absolute path to the script.

Then add `"allowManagedHooksOnly": true`, which restricts which hooks run, and `"allowManagedPermissionRulesOnly": true`, which makes managed settings the only source of permission rules, so a project file can't add allow rules that loosen the denies. Run `/status` in a session and check that the settings sources include `Enterprise managed settings (file)`.

Two caveats:

- On WSL, `/etc/claude-code` is user-writable, per the docs. Use the Windows location or tighten its permissions.
- **Not verified:** whether `allowManagedHooksOnly` also stops a hook that comes from a user-installed plugin from running. The settings reference has a section called "What runs under `allowManagedHooksOnly`"; read it before turning the setting on, and test that the hook still fires. Deploying the hook directly in managed settings, as above, avoids the question.

## 2. Keep the script where Claude can't write to it

Claude Code keeps an installed plugin in its plugin cache, and a project's `.claude/` directory is inside the working directory. Both are places Claude can normally write. Install the script somewhere it can't, such as `/opt/aws-guard/`, owned by root and not writable by the user Claude runs as (`chown -R root:root`, `chmod -R go-w`), and point the managed hook command at that absolute path. Without this, managed settings protect only the registration, and Claude could still rewrite the script it points to.

## 3. Add permission deny rules for the files

If you keep the hook in a project, add `Edit` deny rules for its files and settings. Use `Edit(...)`: Claude Code checks file permissions against `Edit(path)` and `Read(path)` rules only, and accepts a `Write(path)` rule without ever consulting it.

```json
{
  "permissions": {
    "deny": [
      "Edit(/.claude/hooks/aws-guard/**)",
      "Edit(/.claude/settings.json)",
      "Edit(/.claude/settings.local.json)",
      "Edit(//home/YOU/.claude/aws-audit.log)"
    ]
  }
}
```

A rule path starting with `/` is relative to the settings file's source, and `//` is an absolute filesystem path, so adjust the last entry for your home directory. The docs say Edit deny rules apply to the built-in file tools and to file commands Claude Code recognizes in Bash (such as `sed` and `tee`) and Bash redirections. They do **not** cover an arbitrary subprocess that writes files itself, such as a Python or Node script. That gap is what the sandbox closes.

## 4. Turn on the Bash sandbox

The sandbox is off by default. It enforces limits at the operating-system level on shell commands and the processes they start (macOS, Linux and WSL2; native Windows runs unsandboxed). When it is on, it denies writes to the `.claude` settings files and the `.claude/hooks` directory by default, and nothing exempts those paths. It also denies writes to most of the contents of `~/.claude`. Recommended settings:

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false
  }
}
```

- `failIfUnavailable` makes Claude Code refuse to start if the sandbox can't run, instead of silently running commands unsandboxed.
- `allowUnsandboxedCommands: false` stops Claude retrying a failed command with `dangerouslyDisableSandbox`. If you leave the retry on, add an ask rule for `Bash(dangerouslyDisableSandbox:true)` so you get prompted.
- Add `sandbox.filesystem.denyWrite` entries for anything else you want frozen, such as the install directory from step 2.
- The sandbox covers shell commands only. Claude's file tools, MCP servers and hooks run outside it, which is why steps 1 to 3 are still needed.

## 5. Protect the audit log

The log is written by the hook's shell wrapper, outside the sandbox. To make it append-only, set the append-only attribute as root on Linux (`chattr +a ~/.claude/aws-audit.log`, filesystem permitting), or ship the lines to a remote log service. The hook only needs append access.

## 6. Back it with real credentials

None of the above limits what a permitted profile can do. Point `--profile` at a read-only IAM role or SSO permission set so that a bypass, whether of the hook or of the Bash tool, still can't change anything in AWS.

## Check that it worked

After locking down, test it from a Claude session: ask Claude to edit the installed script, to remove the hook from the settings, and to run a shell command that writes to the install directory. Each should be refused. The docs I checked don't say whether a lower-level `disableAllHooks` setting can switch off a hook that managed settings deploy, so test that case before relying on it.
