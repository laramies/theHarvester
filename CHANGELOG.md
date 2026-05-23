# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/laramies/theHarvester/compare/4.11.0...master
[4.11.0]: https://github.com/laramies/theHarvester/compare/4.10.1...4.11.0
[4.10.1]: https://github.com/laramies/theHarvester/compare/4.10.0...06520b40
[4.10.0]: https://github.com/laramies/theHarvester/compare/4.9.2...4.10.0
