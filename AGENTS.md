# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Working boundaries

- Use `uv` for environments and commands. If `uv run` cannot reach the package index to sync, rerun with `uv run --no-sync` against the existing environment and report that dependencies were not re-synced.
- Preserve unrelated worktree changes.
- The code base targets Python 3.14 only. Its newer syntax is intentional: do not flag or rewrite unparenthesized multi-exception `except A, B:` clauses (PEP 758) or unquoted forward-reference annotations, which deferred annotation evaluation (PEP 649) allows.
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
- Run the full non-browser suite once on the final commit before publishing. Earlier commits in a stacked series do not need it unless they change Python behavior.
- Expect these failures and do not chase them as regressions:
  - `tests/test_provider_contract_coverage.py::test_every_canonical_source_has_one_offline_provider_contract` fails whenever only part of the suite runs, because the coverage gate needs every provider contract collected.
  - `tests/test_harness.py::test_loopback_network_remains_available` fails where the sandbox blocks Unix sockets.
  - `tests/test_release_artifacts.py::test_release_artifacts_include_the_canonical_license` fails when `uv build --offline` cannot find the `flit-core` build backend in the local cache.
- Run the HarvestView browser suite once at the final UI head or rely on its GitHub workflow. Static UI edits should use focused UI tests and a JavaScript syntax check first.
- Before retrying a long-running test, confirm the previous process exited. Poll the existing command or stop only its exact owned process instead of starting an overlapping run.

## Publication and GitHub access

- Target every upstream pull request at `dev`. Publish through a pull request; push directly to `dev` only when a maintainer explicitly asks for it in the current session.
- Treat `upstream/master` as maintainer-only and read-only for agents. Leave every `dev`-to-`master` promotion, merge, and direct update to upstream maintainers.
- When GitHub access fails, follow [GitHub CLI diagnostics](CONTRIBUTING.md#github-cli-diagnostics) before diagnosing credentials or switching to browser publication.

## Agent skills

### Issue tracker

Before issue or PR operations, read [the issue tracker configuration](docs/agents/issue-tracker.md) for repository selection and local planning overrides.

### Triage labels

Use the five default triage roles. Before triage, read [the label mapping](docs/agents/triage-labels.md).

### Domain docs

Before exploring a domain area or naming its concepts, read [the domain documentation rules](docs/agents/domain.md) for the root `GLOSSARY.md` and relevant ADRs.
