# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Working boundaries

- Use `uv` for environments and commands.
- Preserve unrelated worktree changes.
- Use mocks or local fixtures for routine verification. Live reconnaissance requires explicit authorization for the target and activity.
- Keep credentials, real target/operator data, and unsanitized provider payloads out of commits, fixtures, diagnostic logs, and development or review artifacts.

## Read for the task

- For setup, coding conventions, contribution workflow, or release preparation, use the relevant section of [CONTRIBUTING.md](CONTRIBUTING.md).
- Read the [architecture guide](docs/architecture.md) before changing discovery, target scope, DNS validation, P0/P1/P2 activity, run lifecycle, scheduling, persistence, interchange, or reporting.
- For discovery provider or shared transport changes, follow [How to add a new discovery module](docs/wiki/How-to-add-a-new-module.md), including its provider conversation ownership audit.
- When reviewing a diff, read [CODING_STANDARDS.md](CODING_STANDARDS.md) and apply every section affected by the change.

## Verification

- Start with `uv run pytest <test-path>` for the changed behavior, then expand according to risk. Use [Test safely](CONTRIBUTING.md#test-safely) for the quality checks and verification boundaries. Report skipped checks and their reasons.
- For agent-guidance edits, run `uv run pytest tests/test_agent_guidance.py` to check links from this file.
- Run the full non-browser suite once at the publication head. Dependent stack layers do not need to repeat it unless they change Python behavior.
- Run the HarvestView browser suite once at the final UI head or rely on its GitHub workflow. Static UI edits should use focused UI tests and a JavaScript syntax check first.
- Before retrying a long-running test, confirm the previous process exited. Poll the existing command or stop only its exact owned process instead of starting an overlapping run.

## Publication and GitHub access

- Target every upstream pull request at `dev`.
- Treat `upstream/master` as maintainer-only and read-only for agents. Leave every `dev`-to-`master` promotion, merge, and direct update to upstream maintainers.
- When GitHub access fails, follow [GitHub CLI diagnostics](CONTRIBUTING.md#github-cli-diagnostics) before diagnosing credentials or switching to browser publication.

## Agent skills

### Issue tracker

Before issue or PR operations, read [the issue tracker configuration](docs/agents/issue-tracker.md) for repository selection and local planning overrides.

### Triage labels

Use the five default triage roles. Before triage, read [the label mapping](docs/agents/triage-labels.md).

### Domain docs

Before exploring a domain area or naming its concepts, read [the domain documentation rules](docs/agents/domain.md) for the root `GLOSSARY.md` and relevant ADRs.
