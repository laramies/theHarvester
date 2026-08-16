# Results and local data

theHarvester can print findings, write reports, retain selected records in SQLite, save screenshots, and expose durable run records through the API. These outputs have different schemas and sensitivity.

## Terminal output

The CLI groups findings by result type. It can also print separate enrichment, such as Shodan output. Use terminal output for operators, not as a stable automation interface.

## JSONL reports

Use `-f NAME` to write a durable run report:

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

The recommended automation output is `report.jsonl`. Its first record summarizes the run, evidence status, source and action outcomes, and artifacts. Each remaining record is one normalized finding with producer attribution. The API can import this file without executing discovery.

```bash
jq -c 'select(.type != "summary") | {type, value, sources, actions}' report.jsonl
```

The same `-f report` command also creates `report.json` and `report.xml` for compatibility.

## Legacy JSON and XML

- **JSON** is one object and contains the broader result set. `cmd`, `hosts`, and `shodan` are always present; other fields appear when non-empty.
- **XML** contains the command, emails, hosts, and virtual hosts. Use JSON for other result types.
- Current JSON and XML reports do not record which source found each item.

When virtual host discovery runs, JSON's `vhosts` array and XML's `<vhost>` entries contain confirmed hostnames only. They do not include endpoint or baseline evidence; use JSONL or API run details for that structured data.

Host values may be plain hostnames. When DNS resolution is enabled, they can also use the `hostname:IP` form.

The repository [README output section](https://github.com/laramies/theHarvester/blob/dev/README.md#report-formats) documents the current formats and provides copyable `jq` examples for JSONL.

## SQLite database

Host, email, IP, and related records are stored at:

```text
~/.local/share/theHarvester/stash.sqlite
```

The database persists across runs. Account for it in engagement cleanup and retention procedures.

Completed CLI executions store one normalized terminal record keyed by run UUID. API executions use the same database by default and may override its path with `THEHARVESTER_RUN_DB`. Lifecycle rows keep queue, cancellation, and worker state separate from terminal evidence. Imported JSONL is stored without executing discovery, and source attribution is rebuilt from each finding's `sources` array. A SQLite import copies every completed run after validating the database and keeps the original run IDs.

The normalized persistence model can represent active-action provenance and artifact metadata through six core tables:

- `runs`: one finite enumeration run;
- `executions`: each passive source or active action represented by the model;
- `results`: deduplicated hostnames, IPs, emails, URLs, and structured outputs;
- `result_origins`: which execution produced each result;
- `asn_attributions`: sourced organization labels linking an ASN result to the exact hostname or IP result supplied by the same execution; and
- `artifacts`: files such as screenshots, linked to their creating action and subject result.

Virtual-host evidence stays inside this model. `results` holds one `hostname` row, `result_origins` links it to the `vhost` action execution, and the result's `details_json` contains the canonical endpoint observation array. If one hostname is distinct on several IP endpoints, it remains one result with several observations.

Current runtime collection populates passive source executions plus DNS, takeover, Shodan, and API endpoint scan executions and origins. Screenshot actions attach file metadata to their captured hostname or URL without creating fake screenshot findings.

RouteViews creates `prefix` results with `scope: external-relationship` and `routeviews` action provenance. Native observations distinguish one ASN-prefix origin claim, one collector/peer BGP route, and one RPKI validation state. They are routing evidence, not registration, ownership, authorization, reachability, or expanded target scope.

URLScan, ONYPHE, and Shodan can attach a provider organization label to an ASN. SQLite stores each relationship in `asn_attributions`; JSONL, the API, CLI output, and HarvestView project the same typed observation. Labels remain time-bound provider evidence, so missing or conflicting values are retained rather than replaced by one ASN owner property. Shodan's documented `org` field is used for the organization label; its separate `isp` field remains part of the existing Shodan payload and is not treated as equivalent.

Every discovered URL is stored as the `url` result kind. Its source or action origins identify whether it came from BuiltWith, GitLab, RocketReach, API scanning, or another producer; provider-specific URL kinds are not stored.

Hostname and IP evidence use the `hostname` and `ip` result kinds in SQLite, JSONL, the API, and HarvestView. A hostname may be the authorized target itself or a subordinate name, so the result kind does not claim that every value is a subdomain.

Two operational tables support the API without changing those six evidence concepts: `run_records` stores queue and lifecycle state, and `run_worker_leases` prevents two local workers from claiming the same queue. Older runless rows remain in `legacy_observations`. SQLite upgrades supported schemas automatically during normal initialization.

## Screenshots

`--screenshot DIR` writes browser captures to the selected directory. Screenshots may contain authentication pages, internal names, or other sensitive visual data even when no credentials were used.

## API results

`GET /api/v1/runs/{run_id}` returns lifecycle state plus a normalized `results` array. Each result has `type`, `value`, `sources`, and `actions`. A `hostname` found through the `vhost` action has native endpoint observations; a `prefix` found through RouteViews has native origin, route, and RPKI observations with fixed external-relationship scope. Run-level source and action outcomes remain available in `source_executions` and `action_executions`, while file metadata is returned through `artifacts`. JSONL imports or exports one run. SQLite import and `GET /api/v1/runs/export-database` move completed runs in bulk without queue, cancellation, or worker-lease state. Treat runtime `/docs`, `/redoc`, and OpenAPI as the exact request and response reference.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
