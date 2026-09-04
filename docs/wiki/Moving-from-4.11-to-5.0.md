# Moving from 4.11 to 5.0

Version 5.0 is still under development on `dev`. This guide covers the changes from 4.11 so you can prepare before the release.

## Update the runtime first

Version 5.0 requires Python 3.14. A source checkout uses `uv` for the environment and commands:

```console
uv sync
uv run theHarvester --help
```

See [Installation](Installation) for platform steps and browser dependencies.

## Use the right result format

For new automation, use JSONL for one finalized run or SQLite for several runs.

- JSONL starts with a summary record, followed by normalized findings. It retains terminal evidence status, source and action outcomes, provenance, and supported structured observations.
- SQLite is the local multi-run store and the portable bulk import and export format. Portable exports omit queue, cancellation, and worker state.
- JSON and XML remain available as grouped compatibility reports, but they do not contain the full evidence model.

Update JSONL consumers to use the canonical result types `hostname`, `ip`, and `url`. Use each finding's `sources` and `actions` fields for attribution.

```console
jq -r 'select(.type == "hostname") | .value' report.jsonl
jq -r 'select(.type == "ip") | .value' report.jsonl
jq -r 'select(.type == "url") | .value' report.jsonl
```

Read [Results and Local Data](Results-and-Local-Data) for the complete evidence and portability contract.

## Report on saved runs

Use `harvest-report` to list targets, summarize source contributions, or compare hostnames:

```console
harvest-report targets
harvest-report contributions --target example.test
harvest-report hostname-changes --target example.test
```

Contribution reports are target-scoped by default. A database with several targets requires `--target`, `--run-id`, or an intentional `--all-targets` aggregate. Hostname comparisons use the latest earlier run with the same canonical target and exact source list.

The comparison labels describe saved evidence:

- `newly_reported`
- `still_reported`
- `no_longer_reported`
- `uncertain`

`no_longer_reported` does not prove that a hostname disappeared or stopped resolving. `uncertain` means a relevant source did not complete reliably on the side where the hostname was absent.

### Earlier 5.0 development snapshots

These names replace the earlier development interfaces. Update scripts before installing this snapshot:

| Earlier command | Replacement |
| --- | --- |
| `harvest-yields --list-targets` | `harvest-report targets` |
| `harvest-yields` | `harvest-report contributions` |
| `harvest-yields --changes` | `harvest-report hostname-changes` |
| `--include-persisting` with `--changes` | `--include-still-reported` with `hostname-changes` |

Place `--database`, `--format`, and the target or run selector after the new subcommand. `contributions` also accepts `--kind` and `--all-targets`.

REST run details replace `source_yields` with `source_contributions` and `hostname_tracking` with `hostname_comparison`. Update nested fields as well:

| Earlier field or state | Replacement |
| --- | --- |
| `observed_result_count` | `reported_count` |
| `unique_result_count` | `unique_to_source_count` |
| `shared_result_count` | `shared_with_other_sources_count` |
| `resolved_hostname_count` | `hostnames_with_dns_answers_count` |
| `unique_resolved_hostname_count` | `unique_to_source_with_dns_answers_count` |
| `baseline_run_id` | `previous_comparable_run_id` |
| `baseline_completed_at` | `previous_comparable_run_completed_at` |
| `source_cohort` | `compared_sources` |
| `hostname_changes` | `hostname_differences` |
| `change` | `change_type` |
| `previous_sources`, `current_sources` | `sources_in_previous_run`, `sources_in_current_run` |
| `source_exclusive` | `reported_by_one_source` |
| `blocking_sources` | `incomplete_source_outcomes` |
| `new`, `persisting`, `missing`, `inconclusive` | `newly_reported`, `still_reported`, `no_longer_reported`, `uncertain` |

The CLI report JSON also replaces its `source_yields` array with `source_contributions`. Its per-source averages change from `unique_result_count_per_run` to `unique_to_source_count_per_run` and from `unique_resolved_hostname_count_per_run` to `unique_to_source_with_dns_answers_count_per_run`. These reports are derived from SQLite; JSONL and the saved evidence schema are unchanged.

## Choose CLI, API, or HarvestView

The CLI, authenticated REST API, and HarvestView use the same normalized terminal evidence.

- Use the CLI for one finite run and shell automation.
- Use the REST API for durable local run records, imports, exports, cancellation, and schedules.
- Use HarvestView to submit and review those same runs in a local browser.

HarvestView uses the same engine as the CLI. A schedule submits finite runs for explicit targets, and its control state stays separate from portable evidence.

## Review network activity before running

Version 5.0 labels activities by observable network behavior:

- P0 queries an existing provider or dataset.
- P1 performs DNS interaction about an authorized name or address.
- P2 contacts a target endpoint or causes equivalent direct interaction.

These labels do not express importance or confidence. Check [Responsible Use and Scope](Responsible-Use-and-Scope) and confirm the target and selected activities before submitting a run.

## Migration checklist

- Install Python 3.14 and refresh the `uv` environment.
- Move new automation to JSONL, SQLite, or the authenticated API.
- Update result-kind filters to `hostname`, `ip`, and `url`.
- Use `harvest-report` for saved-run contributions and hostname comparisons.
- Update REST consumers to `source_contributions` and `hostname_comparison`.
- Treat hostname differences as saved evidence, not current network truth.
- Recheck P0, P1, and P2 activity before running an existing workflow.
