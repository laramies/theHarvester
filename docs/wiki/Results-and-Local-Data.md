# Results and local data

theHarvester can print findings, write reports, retain selected records in SQLite, save screenshots, and return REST JSON. These outputs have different schemas and sensitivity.

## Terminal output

The CLI prints consolidated result sections plus separately selected enrichment such as Shodan. Terminal output is intended for operators, not as a stable machine-readable contract.

## JSON and XML reports

Use `-f NAME` to write both formats:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

This creates `report.json` and `report.xml`.

- **JSON** is one object and contains the broader result set. `cmd`, `hosts`, and `shodan` are always present; other fields appear when non-empty.
- **XML** contains the command, emails, hosts, and virtual hosts. Use JSON for other result types.
- Consolidated reports do not retain per-source attribution.

Host values may be plain hostnames or `hostname:IP` pairs when DNS resolution is enabled. The repository [README output section](https://github.com/laramies/theHarvester/blob/dev/README.md#report-formats) documents the current fields and provides copyable `jq` examples.

## SQLite database

Host, email, IP, and related records are stored at:

```text
~/.local/share/theHarvester/stash.sqlite
```

The database persists across runs. Account for it in engagement cleanup and retention procedures.

## Screenshots

`--screenshot DIR` writes browser captures to the selected directory. Screenshots may contain authentication pages, internal names, or other sensitive visual data even when no credentials were used.

## REST JSON

The REST `/query` response returns arrays for ASNs, interesting URLs, Twitter/LinkedIn data, Trello URLs, IPs, emails, and hosts. Treat runtime `/docs`, `/redoc`, and OpenAPI as the exact request/response reference.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
