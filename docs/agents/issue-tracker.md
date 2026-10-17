# Issue tracker: GitHub

Issues and specs use GitHub Issues. Use the `gh` CLI with an explicit repository for every operation.

## Select the repository

An explicitly supplied issue or PR URL, or a named repository, retains that repository identity. For new planning issues and unqualified planning references, use the local `agentSkills.issueTracker` Git setting when present; otherwise use `laramies/theHarvester`.

Contributors who keep planning in their own fork can set this once in their clone:

```bash
git config --local agentSkills.issueTracker YOUR-ACCOUNT/theHarvester
```

Resolve the planning repository before using the examples below:

```bash
agent_tracker_repo=$(git config --get agentSkills.issueTracker || true)
agent_tracker_repo=${agent_tracker_repo:-laramies/theHarvester}
```

The setting is local Git configuration, not a committed account choice. For an explicitly referenced issue or PR, use its repository in place of the planning default.

## Conventions

- **Create an issue**: `gh issue create --repo "$agent_tracker_repo" --title "..." --body-file <body-file>`. Write multiline bodies to a file first.
- **Read an issue**: `gh issue view --repo "$agent_tracker_repo" <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --repo "$agent_tracker_repo" --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment --repo "$agent_tracker_repo" <number> --body "..."`
- **Apply / remove labels**: `gh issue edit --repo "$agent_tracker_repo" <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close --repo "$agent_tracker_repo" <number> --comment "..."`

Use the resolved repository in GitHub API paths as well as `gh issue` and `gh pr` commands. Contribution pull requests target `laramies/theHarvester:dev` under `CONTRIBUTING.md`; a planning override does not change the PR destination or authorize publication.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

This flag controls automatic PR intake. An explicitly requested PR review still uses the named repository, for example `gh pr view --repo laramies/theHarvester <number> --comments` and `gh pr diff --repo laramies/theHarvester <number>`.

GitHub shares one number space for issues and PRs within each repository. Resolve a bare number in the repository selected above, trying `gh pr view` and then `gh issue view` without switching repositories between attempts.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view --repo "$agent_tracker_repo" <number> --comments`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --repo "$agent_tracker_repo" --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh api` on the sub-issues endpoint). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh api --method POST repos/${agent_tracker_repo}/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/${agent_tracker_repo}/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). GitHub reports `issue_dependencies_summary.blocked_by` (open blockers only, the live gate). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open children (`gh issue list --repo "$agent_tracker_repo" --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (`issue_dependencies_summary.blocked_by > 0`, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit --repo "$agent_tracker_repo" <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment --repo "$agent_tracker_repo" <n> --body "<answer>"`, then `gh issue close --repo "$agent_tracker_repo" <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
