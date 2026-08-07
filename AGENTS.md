# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Essentials

- The project requires Python 3.12 or newer and uses `uv` for environments and commands.
- Install development dependencies with `uv sync --all-groups`.
- For code changes, follow [CONTRIBUTING.md](CONTRIBUTING.md).
- Make the smallest requested change, reuse existing code, and preserve unrelated worktree changes.

## Domain language

Read [CONTEXT.md](CONTEXT.md) when changing discovery terminology, evidence classification, scope handling, DNS validation, or P0/P1/P2 activity boundaries.

## Code review rules

- **External compatibility:** Flag changes that remove or rename CLI flags, output formats or fields, REST API response fields, or discovery source identifiers without a backward-compatible path and regression coverage. Preserve the existing contract or document and test the migration.
- **Sensitive-data boundary:** Flag committed credentials, real target or operator data, reconnaissance results, or unsanitized provider payloads, including in logs, fixtures, and examples. Keep only the diagnostic metadata needed, redact sensitive values, and use RFC-reserved domains and TEST-NET IP ranges.
- **Reconnaissance boundary:** Flag routine tests or CI that contact live third-party targets or providers. Use mocks or local fixtures; live reconnaissance belongs only in intentionally configured integration checks against explicitly authorized targets.

## Git mutation safety

A worktree path is a mutation boundary. After creating or switching a worktree, start a new command with that worktree as the explicit working directory. `git worktree add` creates a directory but does not move the shell into it.

Before a cherry-pick, rebase, commit, restore, or conflict resolution:

1. Run `pwd`, `git rev-parse --show-toplevel`, and `git status --short --branch` in the destination worktree.
2. Inspect any in-progress Git operation before changing it. If its ownership or intent is uncertain, preserve the sequencer metadata, conflict files, and untracked work, then request direction.
3. Keep user-owned changes in their existing worktree. Reconstruct or split published history in a clean worktree instead of rewriting a working branch.

Completion criterion: the agent can name the exact worktree, branch, HEAD, operation state, and files that the next mutation will affect.

## Review units and publication

A branch name identifies source material. The diff against the intended base defines the review unit.

Before opening, retargeting, or replacing a pull request:

1. Record the exact head, intended base, and write target. Refresh remote state only within the user's authorization.
2. Inspect `git log --oneline <base>..HEAD`, `git diff --stat <base>...HEAD`, and `git diff --name-only <base>...HEAD`.
3. State one observable outcome for the pull request. Account for every commit and changed file against that outcome. Keep its implementation, tests, and directly relevant documentation together.
4. Apply a **reviewability check**. Size is a signal, not a gate. Judge whether the diff tells one self-contained story, keeps related implementation, tests, and documentation together, and can be understood without reconstructing unrelated history. Broad file spread, multiple independent outcomes, and a large volume of human-authored code are reasons to consider a split, not automatic failures. Discount generated changes and whole-file deletions. Do not split a cohesive change merely to hit a number; when it is large but atomic, show the statistics and explain why splitting would make review or verification worse.
5. Show the proposed pull request or stack order, head, base, outcome, and diff statistics to the user before creating upstream pull requests.

For a larger change, map the review graph before implementation, or before publication when inheriting an existing branch. Record each slice's outcome, base or dependency, affected contract, and verification:

- Put independent outcomes on independent branches.
- Put dependent outcomes in a stack of cohesive branches, normally two to five. Each pull request must show only its layer and remain testable with its declared base.
- Group tightly coupled implementation, tests, and documentation. A stack is a review batch, not a reason to create one-file administrative pull requests.
- For fork-to-upstream work, keep dependent branches stacked on `origin`. When an upstream pull request cannot use an origin-only branch as its base, promote the bottom branch upstream first. After it merges, rebase the next branch onto the updated upstream target, inspect its diff again, and then open the next upstream pull request.

An exact branch named by the user is still subject to this gate. When its diff contains multiple review units, split the source branch before opening the pull request.

Completion criterion: the pull request tells one reviewable story, exposes every dependency and merge-order constraint, and explains why any unusually large atomic diff should stay together.

## Architecture migration checkpoint

An architecture program is a parent issue that creates dependent implementation issues or uses a branch that is not intended to merge directly into the target branch. Do not turn an architecture proposal or audit directly into an open-ended implementation backlog.

The freeze record on [fork issue #152](https://github.com/NotoriousRebel/theHarvester/issues/152) documents the parallel-architecture and review-debt failure that requires this checkpoint.

`codex/truthful-provider-integration` is immutable reference material at `22eb2d1966b39196c8a04e2793f5fd3e45277fb4`. Do not merge or extend it. Any authorized restart must be a new independent proposal from current `dev`.

Before the first dependent pull request merges:

1. Record the parent issue, its proposal pull request when one exists, intended merge target, exact current `origin/dev`, exact current `upstream/dev`, and proposed base. A requested fixed point does not replace this check.
2. Reconcile the proposal with `origin/dev` and `upstream/dev`. If the concept already exists, consolidate it instead of creating a parallel model.
3. Prove one representative end-to-end slice with an observable consumer. Internal status types and passing tests alone do not establish product value.
4. Record explicit human acceptance of the representative slice and permission for any additional dependent work on the parent issue.

After every dependent pull request, update the parent issue with the cumulative diff, remaining tickets, upstream overlap, and milestone fit before requesting permission for another. Stop the program if the proposal pull request named by the parent issue closes without merging or receives an unresolved compatibility finding. Restart only through a new independent proposal after the finding is reproduced and resolved.

Triage audit findings individually. Close or rewrite findings already satisfied by merged work instead of adding a second semantic migration by default.

Completion criterion: the named target architecture is accepted, the representative slice is useful and compatible, and the parent issue records permission for the next bounded step.

## Verification

- Focused tests: `uv run pytest <test-path>`
- Full tests: `uv run pytest`
- Lint: `uv run ruff check .`
- Formatting: `uv run ruff format --check .`
- Typing: `uv run mypy theHarvester`

Run focused checks first and expand according to risk. Report any skipped check and its reason.
