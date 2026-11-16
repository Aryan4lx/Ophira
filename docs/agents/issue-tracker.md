# Issue tracker: GitHub

Issues and specs for this repo (Aryan4lx/Ophira) live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Make an issue a sub-issue of a parent**: `gh issue create --parent <parent> ...`, or `gh issue edit <parent> --add-sub-issue <child>` afterwards (`gh` 2.94+). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Blocking**: GitHub's native issue dependencies. Add an edge with `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>` (`gh` 2.94+). Older `gh`: `gh api --method POST repos/Aryan4lx/Ophira/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>` (database id via `gh api repos/Aryan4lx/Ophira/issues/<n> --jq .id`). Where dependencies aren't available, fall back to a `Blocked by: #<n>` line at the top of the child body.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: post the explanation with `gh issue comment <number> --body "..."`, then `gh issue close <number>`.

Infer the repo from `git remote -v`; `gh` does this automatically inside the clone.

## Pull requests as a triage surface

**PRs as a request surface: no.** This is a single-author repo; PRs are release artifacts of its own pushes, not incoming feature requests.

## Release convention (repo-specific)

Releases are tag-driven (`vN.N`), built by the GitHub Actions release workflow into `Ophira-vN.N.zip` + `SHA256SUMS`, marked **prerelease** until the user blesses the line (currently only v2.85 is a full release). Work items that ship across a version boundary should note the target tag in the issue body.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Read it as in **Read an issue** above.
