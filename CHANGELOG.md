# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added bounded, keyless APIs.guru discovery through exact target-domain directory lookups, retaining only target-scoped hostnames, contact emails, and URLs from preferred OpenAPI specifications.
- Added bounded virtual host discovery over harvested or operator-supplied literal-IP endpoints, with aligned HTTP `Host` and TLS SNI, synthetic unknown-host controls, hard request and runtime limits, and structured observations on canonical hostname results in JSONL, SQLite, the API, and HarvestView.
- Added HarvestView, an authenticated local browser workspace backed by a durable single-worker `/api/v1` run lifecycle with cancellation, deadlines, JSONL-only file interchange, retained partial evidence, and real-browser regression coverage.
- Added a pinned, non-root Docker Compose deployment for HarvestView and the REST API with localhost-only publishing, file-secret authentication, private durable run storage, and an authenticated API health check.
- Added bounded recursive DNS discovery with three-vantage consensus, closest-encloser wildcard controls, exact-address PTR evidence, and hard query, depth, runtime, and zero-yield limits.
- Added an authenticated HIBP verified-domain source for CLI and `/api/v1` runs that retains normalized account emails and stable breach names without retaining the raw account mapping.
- Added keyless Shodan Certificate Transparency hostname discovery with bounded requests and offline response contracts.
- Added bounded, keyless subdomain discovery through Arquivo.pt's public CDX API with offline response contracts.
- Added transactional SQLite storage and loading for completed full-pipeline runs without changing legacy result rows.
- Added deterministic JSONL report companions finalized after selected one-shot actions complete.
- Added a unified model and SQLite schema for active-action provenance and screenshot artifact metadata.
- Added authenticated bulk import for completed runs from validated theHarvester SQLite databases.
- Added bounded custom endpoint-path input for REST API scans without exposing server-side file paths.
- Recorded DNS resolution, recursive DNS, DNS brute force, and PTR lookup outcomes through the unified action model.
- Recorded takeover, Shodan, and API endpoint scan outcomes through the unified action model.
- Added normalized BuiltWith framework, language, server, CMS, and analytics findings to JSONL and completed-result SQLite output.
- Added DNSDB passive DNS discovery with API key configuration, shared transport handling, result parsing, and offline tests ([9b41b78e](https://github.com/laramies/theHarvester/commit/9b41b78e), [aba9fec6](https://github.com/laramies/theHarvester/commit/aba9fec6)).
- Added bounded anonymous Sourcegraph current-file search for descendant-hostname candidates mentioned in code.
- Added `-v` and `--verbose` diagnostic logging while keeping normal operator output available at the default log level ([8a7b8b71](https://github.com/laramies/theHarvester/commit/8a7b8b71)).
- Added an opt-in passive-provider smoke workflow and a network guard that keeps routine tests offline by default ([72e5820f](https://github.com/laramies/theHarvester/commit/72e5820f)).
- Added root contributor and security policies, structured issue forms, repository agent guidance, discovery terminology, and an operator-focused documentation wiki ([d090a29a](https://github.com/laramies/theHarvester/commit/d090a29a), [7c491ef5](https://github.com/laramies/theHarvester/commit/7c491ef5), [8b9d420b](https://github.com/laramies/theHarvester/commit/8b9d420b)).

### Changed
- Removed the transport-wide delay before reading ready HTTP responses, bounded Wayback Archive to 30 seconds and Common Crawl to 120 seconds, kept both sources within the requested result limit, and made long-source progress visible in verbose mode. Common Crawl now requests one 50-record page at a time instead of bursting page batches.
- Made Baidu, crt.sh, HackerTarget, Have I Been Pwned, Mojeek, OTX, and Robtex report blocked, malformed, or transport failures truthfully. Also fixed HackerTarget CSV parsing and Robtex AAAA results.
- Hardened BufferOver, Chaos, DNSDumpster, ONYPHE, and URLScan parsing and result attribution, including scoped typed results and bounded URLScan pagination.
- Made `harvestview` the sole launcher for the local web application and REST API.
- Standardized SQLite, JSONL, API, and HarvestView result names on `hostname` and `ip` without a presentation alias.
- Standardized URL-producing adapters, JSON, JSONL, SQLite, and API evidence on one `url` result kind while preserving producer provenance.
- Replaced the unversioned and provider-specific REST routes with one authenticated `/api/v1` source and run contract shared with CLI execution semantics.
- Fixed proxied POST requests so they retain the request method, body, and query parameters.
- Migrated Pentest-Tools discovery to its API v2 Bearer-authenticated scan, status, and output endpoints.
- Included HIBP verified-domain in `all` and matching capability selectors like every other P0 source.
- Changed `-b all` to select every cataloged P0 passive source once while leaving P1 DNS and P2 direct sources available through explicit selection.
- Expanded Common Crawl discovery to use every unique crawl ending within one year of the newest catalog entry, validate catalog endpoints, batch requests, cap each query at 100 pages, and enforce the CLI result limit across page requests ([249ce64b](https://github.com/laramies/theHarvester/commit/249ce64b), [70470cd8](https://github.com/laramies/theHarvester/commit/70470cd8)).
- Completed bounded pagination for Wayback Archive and Cert Spotter, including continuation handling, truncation diagnostics, and preservation of partial results on provider failures ([df6ff2c9](https://github.com/laramies/theHarvester/commit/df6ff2c9), [f85a08ff](https://github.com/laramies/theHarvester/commit/f85a08ff)).
- Routed operator messages and diagnostics through logging, preserved host logging policy and existing handlers, and configured logging for the API service ([8a7b8b71](https://github.com/laramies/theHarvester/commit/8a7b8b71)).
- Added credential configuration adapters, deferred proxy configuration loading until required, and retained compatibility accessors such as `Core.brave_key()` ([ccd91176](https://github.com/laramies/theHarvester/commit/ccd91176)).
- Centralized hostname scope normalization for parser and storage boundaries, including case-insensitive targets, trailing dots, optional `www.` prefixes, and exact DNS-label matching ([c0a0b653](https://github.com/laramies/theHarvester/commit/c0a0b653), [a474f086](https://github.com/laramies/theHarvester/commit/a474f086), [70470cd8](https://github.com/laramies/theHarvester/commit/70470cd8)).
- Replaced deprecated hostname resolution with `getaddrinfo`-based handling ([6a847435](https://github.com/laramies/theHarvester/commit/6a847435)).
- Reworked routine CI to use read-only permissions, non-mutating Ruff checks, offline tests, and explicit opt-in live provider checks ([72e5820f](https://github.com/laramies/theHarvester/commit/72e5820f)).
- Grouped GitHub Actions, Python, and Docker Dependabot updates with a seven-day cooldown, and added a seven-day `uv` dependency freshness window ([7a947b66](https://github.com/laramies/theHarvester/commit/7a947b66), [52a79cdb](https://github.com/laramies/theHarvester/commit/52a79cdb)).
- Updated runtime dependencies: `aiohttp` to `3.14.1`, `beautifulsoup4` to `4.15.0`, `certifi` to `2026.6.17`, `fastapi` to `0.138.1`, `ujson` to `5.13.0`, and `uvicorn` to `0.49.0`.
- Updated development dependencies: `pytest` to `9.1.1`, `ruff` to `0.15.20`, and `ty` to `0.0.54`.
- Updated CI and container maintenance pins, including `actions/checkout`, `astral-sh/setup-uv`, `astral-sh/ruff-action`, `github/codeql-action`, StepSecurity Harden-Runner, Docker actions, and the Python base image.
- Expanded offline regression coverage for discovery providers, configuration contracts, logging, output, documentation, workflow policy, and scope boundaries.

### Removed
- Removed the obsolete bundled IP-range and resolver snapshots.
- Removed the REST API's built-in SlowAPI request limiter and its launcher option without adding a replacement.
- Removed Bitbucket domain discovery because its current REST APIs require workspace, repository, or user scope that the domain-only CLI contract cannot provide.
- Removed the nonfunctional ThreatCrowd source because its service hostnames terminate at deleted AWS load balancers and return NXDOMAIN; OTX remains available through its separate adapter.

### Fixed
- Sent a stable, versioned theHarvester identity with provider and API requests while preserving explicit browser identities for sources that require them.
- Kept API endpoint scan URLs canonical instead of prefixing targets onto already complete URLs.
- Made DeHashed pagination honor the CLI limit, retain only normalized email and IP evidence, and discard raw breach rows; aligned LeakIX with its authenticated subdomain endpoint and documented rate-limit retry.
- Added offline contracts for explicitly selected DNS and direct sources, retained normalized Pentest-Tools host and IP results, and hardened Shodan InternetDB, SubdomainFinder C99, and Windvane evidence boundaries.
- Retained relevant GitLab project, profile, and website URLs in consolidated JSONL and SQLite results while excluding unrelated user URLs.
- Standardized BuiltWith and every other URL-producing adapter on `get_urls()`.
- Made no-filename REST `/query` executions reach completed-result construction and SQLite persistence without changing the legacy response fields.
- Made Chaos reject empty credentials, report HTTP and malformed-response failures, and preserve supported subdomain response shapes.
- Made Fofa reject incomplete credentials, report HTTP and malformed-response failures, normalize scoped hosts, and discard invalid IP values.
- Made FullHunt reject empty credentials, report HTTP and malformed-response failures, and isolate malformed host records.
- Made Hudson Rock HTTP failures status-aware, bounded rate-limit retries, removed trailing request delays, isolated malformed provider items, and retained infostealer details in completed JSONL and SQLite results.
- Made the public Have I Been Pwned breach catalogue keyless, added offline response contracts, and retained stable breach names in completed JSONL and SQLite results.
- Fixed THC rate-limit exhaustion so terminal failures are reported without sleeping after the final attempt, with offline recovery, non-success, and malformed-response contracts.
- Made RapidDNS, Robtex, and Subdomain Center HTTP failures report the source and response status before parsing.
- Fixed GitHub code-search fragment limits, boundary separation, and malformed-page termination with offline provider tests.
- Fixed GitLab public discovery scope normalization, request bounds, and default-branch README requests.
- Fixed Baidu, Mojeek, and Yahoo page-response separation and Brave missing-credential reporting, with offline web-search provider contract coverage.
- Fixed DNS candidate validation to omit names without usable A, AAAA, or CNAME evidence, normalize and deduplicate IPv4, IPv6, and canonical-name records, and preserve the existing `Checker.check()` and `DnsForce.run()` return shape.
- Fixed REST `/query` requests with a filename so they no longer fail with an unbound local value and HTTP 500 response ([c358df80](https://github.com/laramies/theHarvester/commit/c358df80)).
- Fixed Brave result limits, malformed Mojeek responses, DuckDuckGo provider and parser boundaries, Baidu verification status reporting, invalid Robtex reverse lookups, and transient crt.sh failures ([72c0d9eb](https://github.com/laramies/theHarvester/commit/72c0d9eb), [48be3ccd](https://github.com/laramies/theHarvester/commit/48be3ccd), [6e7945b5](https://github.com/laramies/theHarvester/commit/6e7945b5), [48f959cc](https://github.com/laramies/theHarvester/commit/48f959cc), [1d56dc78](https://github.com/laramies/theHarvester/commit/1d56dc78), [e8d5278b](https://github.com/laramies/theHarvester/commit/e8d5278b), [26adbc49](https://github.com/laramies/theHarvester/commit/26adbc49)).
- Fixed IntelX hostname, email, IP, and URL result normalization and kept its routing source-scoped ([281f6d45](https://github.com/laramies/theHarvester/commit/281f6d45)).
- Fixed Wayback resume-key encoding and made page-limit truncation visible without discarding collected results ([df6ff2c9](https://github.com/laramies/theHarvester/commit/df6ff2c9)).
- Fixed Cert Spotter pagination termination, malformed response handling, provider error reporting, and partial-result preservation ([f85a08ff](https://github.com/laramies/theHarvester/commit/f85a08ff)).
- Fixed Common Crawl handling for malformed JSON lines, malformed or non-string record URLs, invalid page counts, oversized provider pagination, and result-limit accounting; also resolved the associated `ty` catalog access diagnostic ([249ce64b](https://github.com/laramies/theHarvester/commit/249ce64b), [70470cd8](https://github.com/laramies/theHarvester/commit/70470cd8), [d634d835](https://github.com/laramies/theHarvester/commit/d634d835)).
- Fixed parser scope edge cases and uppercase encoded slashes so normalized in-scope hosts and emails are retained without admitting lookalike domains ([c0a0b653](https://github.com/laramies/theHarvester/commit/c0a0b653), [6d4f196c](https://github.com/laramies/theHarvester/commit/6d4f196c)).
- Fixed verbose logging state restoration, handler preservation, diagnostic visibility, and separation from operator-facing output ([8a7b8b71](https://github.com/laramies/theHarvester/commit/8a7b8b71)).

### Security
- Removed Dehashed credential rows and passwords from operator output and prevented secrets or raw provider payloads from flowing into verbose logs ([8a7b8b71](https://github.com/laramies/theHarvester/commit/8a7b8b71)).
- Hardened GitHub Actions with least-privilege permissions, immutable action pins, disabled checkout credential persistence, non-mutating CI, and isolation of live reconnaissance from routine tests ([6e233db0](https://github.com/laramies/theHarvester/commit/6e233db0), [72e5820f](https://github.com/laramies/theHarvester/commit/72e5820f)).

## [4.11.1] - 2026-06-03

### Added
- Added Sherlockeye reverse lookup and AI-powered OSINT support, including source registration, API key configuration, README documentation, and discovery tests ([2f5ba88b](https://github.com/laramies/theHarvester/commit/2f5ba88b)).

### Changed
- Updated runtime dependencies: `aiohttp` to `3.14.0`, `fastapi` to `0.136.3`, and `uvicorn` to `0.48.0`.
- Updated development dependencies: `pytest-asyncio` to `1.4.0`, `ruff` to `0.15.15`, and `ty` to `0.0.42`.
- Updated CI and container maintenance pins, including `actions/checkout`, `github/codeql-action`, Docker build/login/metadata actions, and the Python Docker base image digest.
- Updated the package version to `4.11.1`.

## [4.11.0] - 2026-05-23

### Added
- Added Mojeek search engine support, including module registration, API key configuration, and tests ([06d8fc48](https://github.com/laramies/theHarvester/commit/06d8fc48), [cbc1a48a](https://github.com/laramies/theHarvester/commit/cbc1a48a), [0d0adfce](https://github.com/laramies/theHarvester/commit/0d0adfce), [ee4f8707](https://github.com/laramies/theHarvester/commit/ee4f8707)).
- Added Dymo API data verifier source with API key configuration and discovery tests ([131e2381](https://github.com/laramies/theHarvester/commit/131e2381)).
- Added Shodan InternetDB as a discovery data source ([a379d54d](https://github.com/laramies/theHarvester/commit/a379d54d)).
- Added Repology packaging status badge to the README ([912cfd5a](https://github.com/laramies/theHarvester/commit/912cfd5a)).

### Changed
- Replaced API `UJSONResponse` usage with `JSONResponse` and centralized API key field handling in `Core` ([acf099f6](https://github.com/laramies/theHarvester/commit/acf099f6)).
- Expanded Ruff lint coverage and applied related formatting and lint fixes across the codebase ([ba0fd5df](https://github.com/laramies/theHarvester/commit/ba0fd5df), [cdda0d1c](https://github.com/laramies/theHarvester/commit/cdda0d1c), [f334c489](https://github.com/laramies/theHarvester/commit/f334c489), [40933a4f](https://github.com/laramies/theHarvester/commit/40933a4f), [31f9c932](https://github.com/laramies/theHarvester/commit/31f9c932)).
- Updated README packaging/version layout and badge spacing ([4fa1431c](https://github.com/laramies/theHarvester/commit/4fa1431c), [b7e3ca27](https://github.com/laramies/theHarvester/commit/b7e3ca27), [255cd8b5](https://github.com/laramies/theHarvester/commit/255cd8b5)).
- Updated the package version to `4.11.0` ([31dd70d5](https://github.com/laramies/theHarvester/commit/31dd70d5)).
- Updated dependencies and CI actions, including `aiohttp`, `fastapi`, `lxml`, `mypy`, `playwright`, `requests`, `ruff`, `ty`, `uvicorn`, `winloop`, Docker actions, CodeQL, `setup-uv`, and StepSecurity Harden-Runner.

### Removed
- Removed `qwant` from the service list ([6370063f](https://github.com/laramies/theHarvester/commit/6370063f)).

### Fixed
- Fixed BuiltWith handling for `text/json` responses by passing `content_type=None` ([e4da0efa](https://github.com/laramies/theHarvester/commit/e4da0efa)).
- Surfaced underlying worker exceptions when work items fail ([4fb1ad7e](https://github.com/laramies/theHarvester/commit/4fb1ad7e)).

### Security
- Hardened API authentication handling and fixed related type lint issues ([98dbda9a](https://github.com/laramies/theHarvester/commit/98dbda9a)).
- Hardened GitHub Actions with StepSecurity remediation and follow-up Harden-Runner updates ([f108bf65](https://github.com/laramies/theHarvester/commit/f108bf65)).

## [4.10.1] - 2026-02-22

### Changed
- Updated Censys integration to align with current API documentation ([67419190](https://github.com/laramies/theHarvester/commit/67419190)).
- Updated RocketReach integration to align with latest API documentation and tests ([ffc7420d](https://github.com/laramies/theHarvester/commit/ffc7420d)).
- Refactored async file handling in CLI paths: replace blocking path calls with awaited operations and improve path sanitization ([e98bf5bb](https://github.com/laramies/theHarvester/commit/e98bf5bb), [607016a1](https://github.com/laramies/theHarvester/commit/607016a1)).
- Migrated packaging/build configuration to `flit-core` and updated entrypoint/version wiring ([d2cae0be](https://github.com/laramies/theHarvester/commit/d2cae0be)).
- Refactored and standardized output utilities, with new regression tests for output formatting and dedup helpers ([fa2dedd3](https://github.com/laramies/theHarvester/commit/fa2dedd3)).
- Updated dependencies: bump `fastapi`, `playwright`, `ruff`, `ty`, and `uvicorn` ([1dfa6e98](https://github.com/laramies/theHarvester/commit/1dfa6e98), [46865337](https://github.com/laramies/theHarvester/commit/46865337), [c1ac137d](https://github.com/laramies/theHarvester/commit/c1ac137d), [7eaec4da](https://github.com/laramies/theHarvester/commit/7eaec4da)).
- Updated packaging dependency `wheel` to `0.46.3` ([46865337](https://github.com/laramies/theHarvester/commit/46865337)).

### Fixed
- Fixed CriminalIP integration for current API behavior, including safer scan/report handling and hostname normalization (issue #2229) ([06c2fbd9](https://github.com/laramies/theHarvester/commit/06c2fbd9)).
- Fixed Shodan engine processing to return hostnames consistently and avoid worker processing errors (issue #2227) ([419291a3](https://github.com/laramies/theHarvester/commit/419291a3)).
- Fixed Bitbucket search flow so discovery runs successfully ([a1968f71](https://github.com/laramies/theHarvester/commit/a1968f71)).
- Improved module API key error messages for clearer diagnostics ([e1b775e3](https://github.com/laramies/theHarvester/commit/e1b775e3)).
- Improved BuiltWith URL handling logic in CLI processing ([15872350](https://github.com/laramies/theHarvester/commit/15872350)).

## [4.10.0] - 2026-01-18

### Added
- LeakIX API key support and improved request header configuration ([31861c19](https://github.com/laramies/theHarvester/commit/31861c19)).
- Bitbucket API key entry in `theHarvester/data/api-keys.yaml` ([6be673fa](https://github.com/laramies/theHarvester/commit/6be673fa)).
- Fix issue #469 Add socks proxy support ([e38bb8fb](https://github.com/laramies/theHarvester/commit/e38bb8fb)).

### Changed
- CI: switch GitHub workflow to `ruff-action` for linting and formatting ([8ddcd1a8](https://github.com/laramies/theHarvester/commit/8ddcd1a8)).
- Dockerfile: add `apt-get update/upgrade` and clean up apt cache layers ([3a5d504b](https://github.com/laramies/theHarvester/commit/3a5d504b)).
- Dependencies updated: bump `aiodns`, `ruff`, `ty`, `filelock`, and `librt` ([40759146](https://github.com/laramies/theHarvester/commit/40759146)).
- Codebase formatting and lint fixes applied (Ruff) ([7c6dec53](https://github.com/laramies/theHarvester/commit/7c6dec53)).
- Tests: expand proxy parameter default structure to include both `http` and `socks5` fields ([bc2fce07](https://github.com/laramies/theHarvester/commit/bc2fce07)).
- `api-keys.yaml` synchronized with `Core` API key references; add consistency test coverage ([ffe1f3a8](https://github.com/laramies/theHarvester/commit/ffe1f3a8)).

### Removed
- `Core.bing_key()` removed ([814c7811](https://github.com/laramies/theHarvester/commit/814c7811)).

### Fixed
- Fix mypy type-checking errors ([0991356b](https://github.com/laramies/theHarvester/commit/0991356b)).

### Security
- Improve input sanitization and add security-focused tests ([3d7489c9](https://github.com/laramies/theHarvester/commit/3d7489c9)).

[Unreleased]: https://github.com/laramies/theHarvester/compare/4.11.1...master
[4.11.1]: https://github.com/laramies/theHarvester/compare/4.11.0...4.11.1
[4.11.0]: https://github.com/laramies/theHarvester/compare/4.10.1...4.11.0
[4.10.1]: https://github.com/laramies/theHarvester/compare/4.10.0...06520b40
[4.10.0]: https://github.com/laramies/theHarvester/compare/4.9.2...4.10.0
