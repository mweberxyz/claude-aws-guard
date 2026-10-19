---
name: release
description: Decide whether a change needs a release, pick the version, prepare the release commit (version bump and changelog) and hand the user a `gh release create` command to run. Use when a PR is close to merging, when the user asks to cut or prepare a release, or when releases have piled up unreleased on main.
---

# Releasing claude-aws-guard

A release is a version bump, a dated `CHANGELOG.md` section, and a GitHub release with a tag. Claude prepares the first two and writes the third as a command for the user to run. Claude never creates or pushes the tag or the release itself: the session can't push tags (the push returns 403) and the signer only signs commits.

This skill runs in one of two modes. Work out which one applies before step 1.

- **In a PR branch.** A PR is close to merging and the release goes in as the branch's last commit. The merge commit doesn't exist yet, so the release target can't be known until the PR merges.
- **Standalone.** The work is already merged to `main`, possibly as several PRs since the last release. Start from a fresh branch off `main`; the release is its own small PR.

## 1. Decide whether to release at all

Find the last release: `git tag -l 'v*'`, and if there are no tags, the newest versioned section of `CHANGELOG.md`. Then list what would be in the release:

```sh
git log --no-merges --format='%h %s' <last-release-ref>..HEAD
```

In PR-branch mode that is the PR's own commits. In standalone mode it is everything since the last release, so read the commits and their diffs, not just the subjects.

Release when the change affects someone using the plugin: a policy change, a new or changed option, a bug fix, a change to `dist/aws_guard.mjs`, the hook wrapper, or a manifest field users see.

Don't release for changes that only touch tests, CI, docs, the benchmark script, `CLAUDE.md` or other internal files. Those stay under `[Unreleased]` or in no changelog entry at all, and ride along with the next real release.

Releases don't have to match PRs one to one. If the change is borderline, or the user may want to batch it with something else, say what you'd do in one line and ask. If you decide not to release, say so in one line and stop.

## 2. Pick the version

Follow "Versioning" in `CLAUDE.md`. While the version is `0.x.y`:

- Patch: bug fixes, and new features or options that are completely backwards compatible.
- Minor: anything not completely backwards compatible, including tightening a default.

To decide, ask of each user-visible change: could an existing config or command decide differently than before? If so, it is not backwards compatible. A new option only counts as compatible if its default keeps the old behavior. When a release mixes both kinds, the stricter kind wins. If the version is `1.0.0` or later, use plain semver and update `CLAUDE.md` to say so.

State the version and the one-line reason before writing anything.

## 3. Prepare the release commit

Make this the last commit (PR-branch mode) or the only commit (standalone mode).

1. Set the same version in `package.json` and `plugins/aws-guard/.claude-plugin/plugin.json`. The marketplace listing and `dist/` carry no version.
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - <today>`, or create the section if there is no `[Unreleased]`. Use Keep a Changelog headings (`Added`, `Changed`, `Fixed`, `Removed`). Add the link at the bottom, newest first: `[X.Y.Z]: https://github.com/mweberxyz/claude-aws-guard/compare/vPREV...vX.Y.Z`.
3. Look for user-facing text the change made stale, such as the plugin `description` in `plugin.json`, README tables and troubleshooting. Fix what is wrong. Don't reword text that is still true.
4. Run `bun run build`, then `bun run check-dist`, `bun run typecheck`, `bun test --coverage` and `bun run validate`. `check-dist` compares against the committed build, so it fails until `dist/` is committed; that is expected if a rebuild is pending, and not a release problem.
5. Commit as `Release vX.Y.Z`, with a short body saying what moved. Push the branch. In standalone mode, open the PR.

### Notes for a release that follows several non-release commits

When the release covers more than the change in front of you (standalone mode, or a PR branch that sits on top of unreleased commits), go through every commit in the range and classify it:

- **Include** anything a user of the plugin would notice or could be affected by: behavior, options, fixes, performance claims (for example a startup-time change), supported runtime versions, and security-relevant docs.
- **Leave out** internal work: test additions, CI tweaks, refactors with no behavior change, `CLAUDE.md` edits.
- **Judge** the in-between cases, such as README rewrites or new docs pages. Include them only if they change what someone installing or configuring the plugin needs to know.

Check that every included entry is true of the code at the release commit. Write entries in the existing changelog voice. If you left something out that the user may expect to see, say so in your reply.

## 4. Write the release fields

Prepare each of these and show them to the user:

- **Tag**: `vX.Y.Z`.
- **Target**: the full 40-character SHA of the commit being released. In standalone mode this is the merge commit of the release PR on `main`, and it is known after the merge: run `git fetch origin main && git rev-parse origin/main`, after checking that nothing else landed. In PR-branch mode it is also the merge commit, so give the command with a note to substitute the merge SHA, or offer to fill it in once the user says the PR has merged. Whatever the merge method, never use the PR branch's own SHA: a squash merge discards it.
- **Title**: `vX.Y.Z`.
- **Notes**: the changelog section for this version, without its heading. Add a single line if useful, such as "Fully backwards compatible", plus a link to `CHANGELOG.md` on `main`.
- **Latest flag**: `--latest` for the newest version. Use `--latest=false` for a backfilled older release.

If a release was missed, find the commit where it happened: the last commit on `main` whose `package.json` and `plugin.json` versions match it. Say it is a judgment call. Backfilled releases go out first, so the Releases page is in order.

## 5. Hand the command to the user

Present the command in a code block for the user to run. Don't run it. Use a quoted heredoc so backticks in the notes aren't expanded:

```sh
gh release create vX.Y.Z \
  --repo mweberxyz/claude-aws-guard \
  --target <full-sha> \
  --title "vX.Y.Z" \
  --latest \
  --notes "$(cat <<'EOF'
<changelog section, without its heading>

**Full changelog**: https://github.com/mweberxyz/claude-aws-guard/blob/main/CHANGELOG.md
EOF
)"
```

Add `--draft` if the user wants to look at it first. `gh` creates the tag on publish, so no separate tag push is needed. GitHub makes it an unsigned lightweight tag. The release page (`/releases/new`) does the same thing without the CLI. If a tag already exists for the version, stop and tell the user.
