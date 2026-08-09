# Results and local data

theHarvester can print findings, write reports, retain selected records in SQLite, save screenshots, and expose durable run records through the API. These outputs have different schemas and sensitivity.

## Terminal output

The CLI groups findings by result type. It can also print separate enrichment, such as Shodan output. Use terminal output for operators, not as a stable automation interface.

## JSON and XML reports

Use `-f NAME` to write both formats:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

This creates `report.json` and `report.xml`.

- **JSON** is one object and contains the broader result set. `cmd`, `hosts`, and `shodan` are always present; other fields appear when non-empty.
- **XML** contains the command, emails, hosts, and virtual hosts. Use JSON for other result types.
- Current JSON and XML reports do not record which source found each item.

Host values may be plain hostnames. When DNS resolution is enabled, they can also use the `hostname:IP` form.

The repository [README output section](https://github.com/laramies/theHarvester/blob/dev/README.md#report-formats) documents the current fields and provides copyable `jq` examples.

## SQLite database

Host, email, IP, and related records are stored at:

```text
~/.local/share/theHarvester/stash.sqlite
```

The database persists across runs. Account for it in engagement cleanup and retention procedures.

Completed CLI executions store one normalized terminal record keyed by run UUID. API executions use the same database by default and may override its path with `THEHARVESTER_RUN_DB`. Lifecycle rows keep queue, cancellation, and worker state separate from terminal evidence. Imported JSONL is stored without executing discovery, and source attribution is rebuilt from each finding's `sources` array.

The normalized persistence model can represent active-action provenance and artifact metadata through five core tables:

- `runs`: one finite enumeration run;
- `executions`: each passive source or active action represented by the model;
- `results`: deduplicated hostnames, IPs, emails, URLs, and structured outputs;
- `result_origins`: which execution produced each result; and
- `artifacts`: files such as screenshots, linked to their creating action and subject result.

Current runtime collection populates passive source executions plus DNS, takeover, Shodan, and API endpoint scan executions and origins. Screenshot actions attach file metadata to their captured hostname or URL without creating fake screenshot findings.

Two operational tables support the API without changing those five evidence concepts: `run_records` stores queue and lifecycle state, and `run_worker_leases` prevents two local workers from claiming the same queue. Older runless rows remain in `legacy_observations`. SQLite upgrades supported schemas automatically during normal initialization.

## Screenshots

`--screenshot DIR` writes browser captures to the selected directory. Screenshots may contain authentication pages, internal names, or other sensitive visual data even when no credentials were used.

## API results

`GET /api/v1/runs/{run_id}` returns lifecycle state plus a normalized `results` array. Each result has `type`, `value`, `sources`, and `actions`; DNS-backed results can also include `dns_status`. Run-level source and action outcomes remain available in `source_executions` and `action_executions`, while file metadata is returned through `artifacts`. API file import and export use only JSONL. Treat runtime `/docs`, `/redoc`, and OpenAPI as the exact request and response reference.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
