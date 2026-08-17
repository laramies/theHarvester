# How to add a new discovery module

Start with [CONTRIBUTING.md](https://github.com/laramies/theHarvester/blob/dev/CONTRIBUTING.md) for branch, environment, testing, and pull-request guidance. Search existing issues and pull requests before implementing a provider.

## 1. Confirm the provider contract

Read the provider's current API documentation and terms. Identify:

- authentication fields and whether credentials are required;
- request limits, pagination, retries, and termination behavior;
- stable response fields that can become hosts, emails, IPs, ASNs, URLs, or people;
- the smallest request sequence needed for one domain.

Do not add provider prices or quotas to repository documentation; link to provider-owned documentation instead.

## 2. Implement the adapter

Create the adapter under [`theHarvester/discovery/`](https://github.com/laramies/theHarvester/tree/dev/theHarvester/discovery). Reuse the shared fetcher, configuration, parser, and result-normalization behavior where it fits.

An adapter normally provides:

- an initializer for the target and local result sets;
- an asynchronous `process()` method returning `SourceExecutionReport | None`;
- only the getters it actually supports, such as `get_hostnames()`, `get_emails()`, `get_ips()`, `get_asns()`, `get_urls()`, or `get_results()`.

Do not return fields the provider did not supply. Normalize and deduplicate before returning results.

Return `None` when the provider conversation completed normally, including a valid zero-result response. Return an immutable `SourceExecutionReport` with a stable provider-specific reason for another terminal condition: `completed` for a successful early stop such as reaching the requested result limit, `failed` for provider or transport failure, `rate-limited` for a terminal rate limit, or `partial` when the provider confirms incomplete coverage. Adapters must not define mutable `execution_status` or `stop_reason` fields. The source runner checks for either field before execution and again before evidence collection. It owns finalization, promotes incomplete reports with retained normalized evidence to `partial`, and records a normal zero-result completion as `completed` with `no-results`.

### Own the provider conversation

A provider conversation is the related request sequence for one source execution: initial request, pagination, retries or polling, and final response handling. Give that sequence one explicit owner.

- Reuse one `AsyncFetcher.open_session()` for related requests so the connection pool, headers, cookie jar, and chosen proxy identity remain stable. Pass the borrowed session to shared fetch methods with `session=` and let only the outer owner close it.
- Keep the default cookie jar when later provider requests may depend on earlier responses. Use `aiohttp.DummyCookieJar()` for deliberately independent probes, such as takeover candidates, so one target cannot influence another.
- Scope a session to one provider and authorized target. Never share cookies, authentication state, or proxy identity across source executions or unrelated targets.
- Preserve cancellation while closing every owned session, response, task, and connector. Cover both successful completion and interruption in focused tests.
- Treat session construction and teardown as adapter lifecycle stages. Preserve the existing TLS and timeout policy unless the source contract explicitly changes, return a `SourceExecutionReport` for ordinary lifecycle failures, and let native cancellation propagate.
- Before extending a shared fetcher interface, audit positional callers and every owned-versus-borrowed branch. New optional parameters must not reinterpret existing calls.

The completion check is an offline test in which a later page depends on state established by an earlier page, plus a cleanup assertion proving the provider session closes.

## 3. Register the source

Add one catalog entry in [`theHarvester/lib/source_catalog.py`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/lib/source_catalog.py) and one factory entry in [`theHarvester/lib/source_runner.py`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/lib/source_runner.py). The catalog supplies CLI help, source selection, and activity classification. The factory constructs the adapter. The runner collects declared result routes and persists them with the completed run.

Keep the public source identifier stable and use the same spelling everywhere.

## 4. Add credentials when needed

If the source accepts an API key:

1. Add the empty credential fields to [`theHarvester/data/api-keys.yaml`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/data/api-keys.yaml).
2. Register those fields in `Core._API_KEY_FIELDS`.
3. Add the matching `Core` accessor used by the adapter.
4. Fail clearly when required credentials are missing. If a key is optional, preserve the documented keyless behavior.

Never log credentials or include real keys in tests, examples, commits, issues, or pull requests.

## 5. Add focused coverage

[The Baidu discovery tests](https://github.com/laramies/theHarvester/blob/dev/tests/discovery/test_baidusearch.py) are a small example that can be copied and adapted. They replace network fetching with `pytest` `monkeypatch` and assert normalized results.

Useful cases include:

- successful parsing;
- missing required credentials;
- non-success, timeout, empty, or malformed responses;
- pagination and termination;
- the returned execution report for incomplete work and `None` for normal completion;
- normalized and deduplicated results.

Tests must not require external network access or real provider credentials.

## 6. Update operator documentation

Add the source to the README matrix with its result routes, activity class, and credential requirement. The matrix contract test checks those values against the catalog entry.

In the pull request, link the provider API documentation and explain any intentional exception to shared transport behavior.
