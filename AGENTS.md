# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Essentials

- The project requires Python 3.12 or newer and uses `uv` for environments and commands.
- Install development dependencies with `uv sync --all-groups`.
- For code changes, follow [README/CONTRIBUTING.md](README/CONTRIBUTING.md).
- Make the smallest requested change, reuse existing code, and preserve unrelated worktree changes.

## Domain language

Read [CONTEXT.md](CONTEXT.md) when changing discovery terminology, evidence classification, scope handling, DNS validation, or P0/P1/P2 activity boundaries.

## Code review rules

- **External compatibility:** Flag changes that remove or rename CLI flags, output formats or fields, REST API response fields, or discovery source identifiers without a backward-compatible path and regression coverage. Preserve the existing contract or document and test the migration.
- **Sensitive-data boundary:** Flag committed credentials, real target or operator data, reconnaissance results, or unsanitized provider payloads, including in logs, fixtures, and examples. Keep only the diagnostic metadata needed, redact sensitive values, and use RFC-reserved domains and TEST-NET IP ranges.
- **Reconnaissance boundary:** Flag routine tests or CI that contact live third-party targets or providers. Use mocks or local fixtures; live reconnaissance belongs only in intentionally configured integration checks against explicitly authorized targets.

## Verification

- Focused tests: `uv run pytest <test-path>`
- Full tests: `uv run pytest`
- Lint: `uv run ruff check .`
- Formatting: `uv run ruff format --check .`
- Typing: `uv run mypy theHarvester`

Run focused checks first and expand according to risk. Report any skipped check and its reason.
