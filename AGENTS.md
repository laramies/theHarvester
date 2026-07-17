# Agent guidance

theHarvester is a Python OSINT reconnaissance tool for collecting public information about domains, IPs, emails, names, and related assets.

## Essentials

- The project requires Python 3.12 or newer and uses `uv` for environments and commands.
- Install development dependencies with `uv sync --all-groups`.
- For code changes, follow [README/CONTRIBUTING.md](README/CONTRIBUTING.md).
- Make the smallest requested change, reuse existing code, and preserve unrelated worktree changes.
- Keep security-sensitive behavior fail-closed. Use mocks or local fixtures for routine verification; run live reconnaissance only in an intentionally configured integration check against an explicitly authorized target.
- Do not commit credentials, real target or operator data, reconnaissance results, or unsanitized provider payloads. Use RFC-reserved domains and TEST-NET IP ranges in tests and examples.

## Domain language

Read [CONTEXT.md](CONTEXT.md) when changing discovery terminology, evidence classification, scope handling, DNS validation, or P0/P1/P2 activity boundaries.

## Verification

- Focused tests: `uv run pytest <test-path>`
- Full tests: `uv run pytest`
- Lint: `uv run ruff check .`
- Formatting: `uv run ruff format --check .`
- Typing: `uv run mypy theHarvester`

Run focused checks first and expand according to risk. Report any skipped check and its reason.
