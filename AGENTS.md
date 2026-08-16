# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Essentials

- The project requires Python 3.12 or newer and uses `uv` for environments and commands.
- Install development dependencies with `uv sync --all-groups`.
- For code changes, follow [CONTRIBUTING.md](CONTRIBUTING.md).
- Make the smallest requested change, reuse existing code, and preserve unrelated worktree changes.

## Upstream publication

- Target every upstream pull request at `dev`.
- Treat `upstream/master` as maintainer-only and read-only for agents. Leave every `dev`-to-`master` promotion, merge, and direct update to upstream maintainers.

## Domain language

Read [CONTEXT.md](CONTEXT.md) before changing discovery semantics, result or evidence models, run lifecycle, interchange or persistence, target scope, DNS validation, or P0/P1/P2 activity boundaries.

## Code review rules

- **External compatibility:** Flag changes that remove or rename CLI flags, output formats or fields, REST API response fields, or discovery source identifiers without a backward-compatible path and regression coverage. Preserve the existing contract or document and test the migration.
- **Sensitive-data boundary:** Flag committed credentials, real target or operator data, reconnaissance results, or unsanitized provider payloads, including in logs, fixtures, and examples. Keep only the diagnostic metadata needed, redact sensitive values, and use RFC-reserved domains and TEST-NET IP ranges.
- **Reconnaissance boundary:** Flag routine tests or CI that contact live third-party targets or providers. Use mocks or local fixtures; live reconnaissance belongs only in intentionally configured integration checks against explicitly authorized targets.
- **State-lifetime audit:** When changing network, pagination, retry, proxy, cookie, or cancellation behavior, trace the entire provider conversation using [How to add a new discovery module](docs/wiki/How-to-add-a-new-module.md#own-the-provider-conversation). Account for every owned resource and every shared-helper caller before declaring the change complete.

## Verification

- Focused tests: `uv run pytest <test-path>`
- Full tests: `uv run pytest`
- Lint: `uv run ruff check .`
- Formatting: `uv run ruff format --check .`
- Typing: `uv run mypy theHarvester`

Run focused checks first and expand according to risk. Report any skipped check and its reason.

### Test budget

- During implementation, run the narrowest test that covers the changed behavior. Do not rerun the full suite after every small edit.
- Run the full non-browser suite once at the publication head. Dependent stack layers do not need to repeat it unless they change Python behavior.
- Run the HarvestView browser suite once at the final UI head or rely on its GitHub workflow. Static UI edits should use focused UI tests and a JavaScript syntax check first.
- Before retrying a long-running test, confirm the previous process exited. Poll the existing command or stop only its exact owned process instead of starting an overlapping run.

## GitHub CLI diagnostics

Before reporting broken GitHub authentication, distinguish connectivity from
credential failure. Run `gh api user --silent` in the same host execution
context used for `git push`, then inspect any error. A sandboxed `gh auth
status` failure alone is not credential evidence. Report DNS, network, and
GitHub service failures as connectivity blockers. Use browser publication only
when the host-side command specifically reports missing or invalid credentials.
