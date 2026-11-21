---
name: delete-comment
description: Review existing comments in a requested part of theHarvester and remove or relocate those whose purpose is better served elsewhere.
---

Use the requested paths, or the tracked first-party code and configuration for a repository-wide pass. Record the starting revision. Use Python's `tokenize` for Python files and entrypoints. For other languages, inspect candidate delimiters in context so strings, CSS colors and shell data stay intact.

Read the surrounding implementation and tests before classifying a comment. Preserve docstrings, interpreter and tooling directives, pinned action version tags, legal notices and attribution. Leave generated and tool-managed blocks with their owner.

| Category | What to do |
| --- | --- |
| Tautology | Delete a comment when the names or adjacent statements already convey everything it says. |
| Stale | Verify what changed against the current implementation, then delete the obsolete explanation. |
| Excuse | Identify the observable cost of the workaround. Follow the repository's issue tracker configuration to find existing work or file an authorized issue with a synthetic example and an acceptance check. Delete the comment once the work is tracked. |
| Decision Record | Preserve the choice and its rationale in the relevant ADR under `docs/adr/`, creating a short ADR if needed. Remove the migrated comment. |

Keep useful local explanations when they help a reader understand the code. If the evidence is inconclusive, keep the comment and note the uncertainty. Verify the affected behavior and report removed comment-only lines separately from inline edits, along with the issues and ADRs that capture the follow-up.
