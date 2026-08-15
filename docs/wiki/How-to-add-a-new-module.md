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
- an asynchronous `process()` method;
- only the getters it actually supports, such as `get_hostnames()`, `get_emails()`, `get_ips()`, `get_asns()`, `get_urls()`, or `get_results()`.

Do not return fields the provider did not supply. Normalize and deduplicate before returning results.

## 3. Register the source

Add one catalog entry in [`theHarvester/lib/source_catalog.py`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/lib/source_catalog.py) and one factory entry in [`theHarvester/lib/source_runner.py`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/lib/source_runner.py). The catalog supplies CLI help, source selection, and activity classification; the factory constructs the adapter; the runner collects declared result routes and persists them through the existing completed-result flow.

Keep the public source identifier stable and use the same spelling everywhere.

## 4. Add credentials when needed

If the source accepts an API key:

1. Add the empty credential fields to [`theHarvester/data/api-keys.yaml`](https://github.com/laramies/theHarvester/blob/dev/theHarvester/data/api-keys.yaml).
2. Register those fields in `Core._API_KEY_FIELDS`.
3. Add the matching `Core` accessor used by the adapter.
4. Fail clearly when required credentials are missing. If a key is optional, preserve the documented keyless behavior.

Never log credentials or include real keys in tests, examples, commits, issues, or pull requests.

## 5. Add focused coverage when possible

[The Baidu discovery tests](https://github.com/laramies/theHarvester/blob/dev/tests/discovery/test_baidusearch.py) are a small example that can be copied and adapted. They replace network fetching with `pytest` `monkeypatch` and assert normalized results.

Useful cases include:

- successful parsing;
- missing required credentials;
- non-success, timeout, empty, or malformed responses;
- pagination and termination;
- normalized and deduplicated results.

Tests must not require external network access or real provider credentials.

## 6. Update operator documentation

Add the source to the README source/result matrix with its actual output columns and key requirement. The matrix contract test checks that documented result types match the catalog entry.

In the pull request, link the provider API documentation and explain any intentional exception to shared transport behavior.
