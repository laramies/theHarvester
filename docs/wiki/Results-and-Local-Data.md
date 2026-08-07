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

Completed CLI executions store one normalized terminal record keyed by run UUID. API executions use a separate run database configured by `THEHARVESTER_RUN_DB`; each record keeps lifecycle state, the submitted request, normalized results, and source outcomes. Imported JSON or JSONL evidence is stored as an imported run without executing discovery. Because CLI JSONL does not record source outcomes, its imported evidence status is `partial`.

## Screenshots

`--screenshot DIR` writes browser captures to the selected directory. Screenshots may contain authentication pages, internal names, or other sensitive visual data even when no credentials were used.

## API results

`GET /api/v1/runs/{run_id}` returns lifecycle state plus a normalized `results` array. Each result has a `type` and `value`; DNS-backed results can also include `dns_status`. Per-result source attribution is omitted until the collection seam can retain it truthfully. Run-level source outcomes remain available in `source_executions`. JSON and CSV exports use the same normalized results. Treat runtime `/docs`, `/redoc`, and OpenAPI as the exact request and response reference.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
