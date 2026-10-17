# Coding standards

Use this document when reviewing a change. Apply the sections touched by the diff and trace affected callers and consumers beyond it. Each finding should identify a concrete consequence, the relevant contract, and the evidence supporting it.

These standards cover judgment calls. [CONTRIBUTING.md](CONTRIBUTING.md#test-safely) owns verification commands; [pyproject.toml](pyproject.toml) and [CI](.github/workflows/theHarvester.yml) own formatting, lint, and typing rules. Add a deterministic check for a repeatable syntactic violation instead of another prose rule. The [research note](docs/coding-standards-research.md) records the rationale and source material for this document.

## Scope and operator intent

For target parsing, source selection, DNS, actions, or scheduling changes, trace the operator's selection through validation, execution, and persisted options. Evaluate activity by the network behavior it causes, including work delegated to a provider.

Flag a normalization or convenience path that broadens the authorized target, promotes relationship evidence into a discovery seed, or performs an unselected activity. Exact hostname identity matters: `www.example.test` and `example.test` have different scope boundaries. Importing, comparing, or displaying saved evidence must remain read-only with respect to discovery and DNS.

Authority: [authorization and scope](docs/architecture.md#authorization-and-scope), [domain language](GLOSSARY.md), and [exact-hostname decision](docs/adr/0007-keep-operator-hostname-as-exact-scope.md).

## External compatibility

Review CLI flags, output formats and fields, REST responses, source identifiers, configuration, and persisted records from the existing consumer's perspective. Trace changed values through producers, serializers, importers, and presentation code; matching names alone do not establish compatible meaning.

Flag removals, renames, or semantic changes without a backward-compatible path and regression coverage, or an explicit documented and tested migration. Base migration requirements on released interfaces and supported stored data; temporary development names do not by themselves create a release contract.

Authority: [architecture](docs/architecture.md), [released-version migration guide](docs/wiki/Moving-from-4.11-to-5.0.md), and the affected CLI help, type declarations, or OpenAPI schema.

## Provider conversations and shared helpers

For network, pagination, retry, proxy, cookie, or cancellation changes, perform the [provider conversation audit](docs/wiki/How-to-add-a-new-module.md#own-the-provider-conversation). Trace construction, every related request, termination, and teardown. Account for every owned resource and every shared-helper caller, including callers outside the edited adapter.

Assess whether the ownership boundary preserves the provider's required state while isolating unrelated sources and targets. Borrowing a session must preserve its owner's cleanup responsibility. Review failure and cancellation at setup, mid-conversation, and teardown; successful requests alone cannot establish correct lifetime behavior. Preserve explicit proxy intent through all fallback paths using the [proxy decision](docs/adr/0009-scope-proxy-mode-to-http-transport.md).

Check that pagination progress, deduplication, and limits agree on what is being counted. While provider and runtime bounds permit further requests, duplicate entries must not cause later eligible results to be skipped. Distinguish normal exhaustion, a requested limit, and incomplete coverage stopped by a provider or safety bound; preserve the explicit partial outcome and reason required by the runner contract. Verify changed behavior with state-dependent offline coverage where later requests rely on earlier state.

Keep provider-specific parsing in the adapter and shared execution policy in the catalog, runner, and transport. A local exception should identify the provider requirement the shared path cannot express. Evaluate new abstractions by whether they reduce duplicated policy across actual callers.

Authority: [provider implementation guide](docs/wiki/How-to-add-a-new-module.md), [source catalog](theHarvester/lib/source_catalog.py), [source runner](theHarvester/lib/source_runner.py), and [shared transport](theHarvester/lib/core.py).

## Evidence meaning and preservation

Follow changed evidence from collection through normalization, merging, storage, interchange, and display. Check that deduplication preserves attribution and supported observations, and that failure or cancellation retains already collected evidence with its incomplete outcome.

Keep lifecycle status, terminal evidence status, source outcomes, and operator-facing claims consistent with their distinct meanings. A completed task, a valid empty response, and a failed provider do not establish the same thing. Counts and DNS answers must support the claims made about them; they do not independently establish ownership, reachability, or corroboration.

For comparisons, inspect the source outcomes used to infer absence. For storage and interchange, assess round trips against canonical evidence, including partial and failed finalized runs; a successful parse or an equal result count is insufficient.

Authority: [evidence and portability](docs/architecture.md#evidence-and-portability), [results and local data](docs/wiki/Results-and-Local-Data.md), and [hostname comparison terminology](GLOSSARY.md#hostname-comparisons).

## Durable run and application ownership

For worker, scheduler, API lifespan, or persistence changes, trace submission, claiming, retry, restart, cancellation, and shutdown. Check that ownership remains provable, retries cannot duplicate a scheduled target's run, and a cancellation request is not presented as proof that execution stopped.

Review mutable state against the lifetime of the application or service that owns it. Tests with an independent application or restarted worker should exercise the same ownership boundaries as production. Retain the separation between private control state and portable finalized evidence.

Authority: [run-worker lifecycle](docs/adr/0003-run-worker-lifecycle.md), [schedule control plane](docs/adr/0006-schedule-finite-runs-through-a-private-control-plane.md), and [application lifespan ownership](docs/adr/0010-own-api-background-state-in-the-app-lifespan.md).

## Sensitive data and verification boundaries

Inspect fixtures, logs, examples, screenshots, and artifacts as well as executable code. Flag committed credentials, real target or operator data, reconnaissance results, and unsanitized provider payloads. Retain only diagnostic metadata needed to explain behavior, with RFC-reserved domains and TEST-NET addresses for examples and fixtures.

Routine tests and CI use mocks or local services. Evaluate whether a changed subprocess, browser, or helper escapes the Python socket guard. Live reconnaissance belongs only in intentionally configured integration checks against explicitly authorized targets; a fixture hostname or test marker alone does not grant authorization.

Authority: [safe testing](CONTRIBUTING.md#test-safely), [test harness](tests/conftest.py), and [responsible use and scope](docs/wiki/Responsible-Use-and-Scope.md).

## Verification quality and review findings

Assess whether tests exercise the changed contract at the boundary where consumers observe it. A provider-contract marker establishes coverage registration, not the quality of its assertions. Mocks should allow the state transition or failure being checked to occur; tests that replace that behavior cannot prove it. For constrained inputs, cover rejection before downstream work begins. For HarvestView behavior, assess the affected operator workflow in a real browser as required by the contributor guide.

Ground provider assumptions in current provider documentation or sanitized evidence. A synthetic malformed response demonstrates behavior for that input; it does not establish how often the provider sends it. State uncertainty and calibrate severity to the supported impact.

When behavior changes, check the relevant glossary, architecture decision, and operator documentation for consistency. Report what was verified and which checks remain unrun. Passing local tests, hosted checks, publication, deployment, and observed runtime behavior are separate claims.
