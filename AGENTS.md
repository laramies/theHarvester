# Agent guidance

## Before changing code

- Use `uv` for environments and commands. Follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup, coding conventions, and verification commands.
- Preserve unrelated worktree changes.
- Read [CONTEXT.md](CONTEXT.md) before changing domain names or the meaning of targets, runs, sources, results, evidence, or reports.
- Read the [release contract](docs/release-contract.md) before changing discovery, target scope, DNS validation, P0/P1/P2 activity, run lifecycle, persistence, or interchange. A behavior change is complete when code, tests, and operator documentation agree with the contract.

## Upstream publication

- Target every upstream pull request at `dev`.
- Treat `upstream/master` as maintainer-only and read-only for agents. Leave every `dev`-to-`master` promotion, merge, and direct update to upstream maintainers.

## Code review rules

- **External compatibility:** Flag changes that remove or rename CLI flags, output formats or fields, REST API response fields, or discovery source identifiers without a backward-compatible path and regression coverage. Preserve the existing contract or document and test the migration.
- **Sensitive-data boundary:** Flag committed credentials, real target or operator data, reconnaissance results, or unsanitized provider payloads, including in logs, fixtures, and examples. Keep only the diagnostic metadata needed, redact sensitive values, and use RFC-reserved domains and TEST-NET IP ranges.
- **Reconnaissance boundary:** Flag routine tests or CI that contact live third-party targets or providers. Use mocks or local fixtures; live reconnaissance belongs only in intentionally configured integration checks against explicitly authorized targets.
- **State-lifetime audit:** When changing network, pagination, retry, proxy, cookie, or cancellation behavior, trace the entire provider conversation using [How to add a new discovery module](docs/wiki/How-to-add-a-new-module.md#own-the-provider-conversation). Account for every owned resource and every shared-helper caller before declaring the change complete.

## Verification

- Start with `uv run pytest <test-path>` for the changed behavior, then expand according to risk. Report skipped checks and their reasons.
- Run the full non-browser suite once at the publication head. Dependent stack layers do not need to repeat it unless they change Python behavior.
- Run the HarvestView browser suite once at the final UI head or rely on its GitHub workflow. Static UI edits should use focused UI tests and a JavaScript syntax check first.
- Before retrying a long-running test, confirm the previous process exited. Poll the existing command or stop only its exact owned process instead of starting an overlapping run.

## GitHub CLI diagnostics

When GitHub access fails, run `gh api user --silent` in the same host context used for `git push`. Report DNS, network, and service errors as connectivity blockers. A sandboxed `gh auth status` failure alone does not establish a credential failure. Use browser publication only when the host command reports missing or invalid credentials.
