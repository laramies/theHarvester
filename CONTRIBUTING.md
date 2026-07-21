# Contributing to theHarvester

Thank you for helping improve theHarvester. This guide explains how to propose a focused change, test it safely, and submit evidence that makes review straightforward.

## Before you start

- Search the [issues](https://github.com/laramies/theHarvester/issues) and [pull requests](https://github.com/laramies/theHarvester/pulls) for existing work.
- Open an issue before investing in a large feature, dependency change, or user-visible behavior change.
- Keep each pull request to one logical change. Leave unrelated cleanup and reformatting for separate work.
- Base contribution branches on the current upstream `master` branch.

For a bug report, include a minimal reproduction, expected and actual behavior, operating system, Python version, and only the output needed to diagnose the problem. Remove credentials, account information, private target data, and raw API responses.

## Set up a development environment

theHarvester supports Python 3.12 and newer and uses [uv](https://docs.astral.sh/uv/) for dependency management.

Fork the repository, then clone your fork and add the upstream repository:

```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/theHarvester.git
cd theHarvester
git remote add upstream https://github.com/laramies/theHarvester.git
git fetch upstream
git switch -c fix/short-description upstream/master
uv sync --all-groups
```

Use a short branch name that describes the change, such as `fix/certspotter-pagination` or `feature/source-name`.

## Make a focused change

- Match the surrounding code and reuse existing configuration, transport, parsing, and result-normalization helpers.
- Tests are especially helpful for bug fixes and new behavior, but they are not required for every contribution. If you can add one, start with the nearest existing test.
- Use descriptive names and type annotations where they improve the changed code.
- Do not add dependencies or configuration options unless the change requires them.
- You are responsible for every submitted change, including AI-assisted code. Read it, understand it, and test it before opening a pull request.

### Discovery providers

If you can add coverage for a new or changed discovery provider, keep it focused and mock HTTP, DNS, and provider responses. Tests must not require API keys or external network access. [The Baidu discovery tests](tests/discovery/test_baidusearch.py) are a small example you can copy and adapt.

Useful cases include:

- missing credentials and configuration;
- non-success responses, timeouts, and malformed or empty data;
- pagination and retry termination;
- normalized, deduplicated results.

Use the shared transport when it can represent the request. If a provider requires behavior the shared transport does not support, keep the exception local and explain it in the pull request. Never log credentials, account information, private target data, or raw API responses.

## Test safely

Run the narrowest affected test first:

```bash
uv run pytest tests/path/to/test_file.py
```

Before submitting, run the non-mutating quality checks and full test suite:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

Changes to typed interfaces should also pass:

```bash
uv run mypy theHarvester
```

Routine verification must use mocks, local fixtures, and reserved example domains. Do not run broad or active reconnaissance against third-party targets. If live verification is essential, use only a target you own or are explicitly authorized to test, limit the request scope, and keep collected data out of commits, issues, and pull requests.

CI runs additional source smoke tests, CodeQL, dependency review, and container checks. Contributors do not need to reproduce broad live-source checks locally.

## Open a pull request

Push the topic branch to your fork and open a pull request against `laramies/theHarvester:master`.

The pull request should include:

- the problem and relevant issue;
- the behavior before and after the change;
- the exact tests and checks run;
- sanitized output or screenshots only when they help demonstrate the result;
- any compatibility, provider, rate-limit, or operational risk reviewers should know about.

Use a draft pull request when work is incomplete or verification is still pending. Keep the branch current, respond to review feedback, and ensure required checks pass before requesting a final review.

## Security-sensitive reports

Do not disclose suspected vulnerabilities in theHarvester, exploit details, credentials, or sensitive collected data in a public issue. Until the project publishes a private reporting channel, open a minimal issue asking the maintainers how to report the problem privately without including vulnerability details.
