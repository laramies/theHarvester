# Results and local data

theHarvester can print findings, write reports, retain selected records in SQLite, save screenshots, and return REST JSON. These outputs have different schemas and sensitivity.

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

Completed CLI and REST `/query` executions also store one normalized terminal
record keyed by run UUID. REST keeps its existing response shape and does not
write report files unless a filename is requested.

The normalized persistence model can represent active-action provenance and artifact metadata through five core tables:

- `runs`: one finite enumeration run;
- `executions`: each passive source or active action represented by the model;
- `results`: deduplicated hostnames, IPs, emails, URLs, and structured outputs;
- `result_origins`: which execution produced each result; and
- `artifacts`: files such as screenshots, linked to their creating action and subject result.

Current runtime collection populates passive source executions plus DNS action executions and origins. Direct-action and artifact producers are integrated in a later slice. Older runless rows remain in `legacy_observations`. SQLite upgrades supported schemas automatically during normal initialization.

## Screenshots

`--screenshot DIR` writes browser captures to the selected directory. Screenshots may contain authentication pages, internal names, or other sensitive visual data even when no credentials were used.

## REST JSON

The REST `/query` response returns arrays for ASNs, interesting URLs, Twitter/LinkedIn data, Trello URLs, IPs, emails, and hosts. The corresponding normalized terminal record is retained in SQLite. Treat runtime `/docs`, `/redoc`, and OpenAPI as the exact request/response reference.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
