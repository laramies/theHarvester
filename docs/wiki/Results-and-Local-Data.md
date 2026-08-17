# Results and local data

Choose the output that matches the next task:

| Output | Use it for | Important limit |
| --- | --- | --- |
| Terminal | Interactive review | Not a stable automation interface. |
| JSONL | Automation, one-run interchange, and provenance | One summary record followed by normalized findings. |
| SQLite | Local history and bulk transfer of completed runs | Contains sensitive evidence across runs. |
| JSON or XML | Compatibility with older consumers | Does not preserve per-item source attribution. |
| REST API | Lifecycle state, normalized results, and local integrations | Requires API authentication. |

## Terminal output

The CLI groups findings by result type. It can also print separate enrichment, such as Shodan output. Use terminal output for operators, not as a stable automation interface.

## JSONL reports

Use `-f NAME` to write a durable run report:

Network activity: provider-facing passive discovery plus local report writes.

```bash
uv run theHarvester -d example.com -b crtsh,certspotter -f report
```

The recommended automation output is `report.jsonl`. Its first record summarizes the run, evidence status, source and action outcomes, and artifacts. Each remaining record is one normalized finding with producer attribution. The API can import this file without executing discovery.

```bash
jq -c 'select(.type != "summary") | {type, value, sources, actions}' report.jsonl
```

The same `-f report` command creates `report.json` and `report.xml` compatibility reports.

## JSON and XML compatibility reports

- **JSON** is one object and contains the broader result set. `cmd`, `hosts`, and `shodan` are always present; other fields appear when non-empty.
- **XML** contains the command, emails, hosts, and virtual hosts. Use JSON for other result types.
- JSON and XML reports do not record which source found each item.

When virtual host discovery runs, JSON's `vhosts` array and XML's `<vhost>` entries contain confirmed hostnames only. They do not include endpoint or baseline evidence; use JSONL or API run details for that structured data.

Host values may be plain hostnames. When DNS resolution is enabled, they can also use the `hostname:IP` form.

The repository [README output section](https://github.com/laramies/theHarvester/blob/dev/README.md#output-and-local-data) summarizes the formats and provides copyable `jq` examples for JSONL.

## SQLite database

Host, email, IP, and related records are stored at:

```text
~/.local/share/theHarvester/stash.sqlite
```

The database persists across runs. Account for it in engagement cleanup and retention procedures.

Completed CLI executions store one normalized terminal record keyed by run UUID. API executions use the same database by default and may override its path with `THEHARVESTER_RUN_DB`. Lifecycle rows keep queue, cancellation, and worker state separate from terminal evidence. Imported JSONL is stored without executing discovery, and source attribution is rebuilt from each finding's `sources` array. A SQLite import copies every completed run after validating the database and keeps the original run IDs.

Six tables hold completed evidence:

- `runs`: one finite enumeration run.
- `executions`: each passive source or active action represented by the model.
- `results`: deduplicated hostnames, IPs, emails, URLs, and structured outputs.
- `result_origins`: the execution that produced each result.
- `asn_attributions`: sourced organization labels linking an ASN result to the exact hostname or IP supplied by the same execution.
- `artifacts`: files such as screenshots, linked to their creating action and subject result.

Virtual-host evidence uses the same model. `results` holds one `hostname` row, `result_origins` links it to the `vhost` action execution, and `details_json` contains the endpoint observations. A hostname that is distinct on several IP endpoints remains one result with several observations.

Runtime collection records passive source executions plus DNS, takeover, Shodan, and API endpoint scan executions and origins. Screenshot actions attach file metadata to their captured hostname or URL without creating screenshot findings.

RouteViews creates `prefix` results with `scope: external-relationship` and `routeviews` action provenance. Its observations distinguish ASN-prefix origin claims, collector/peer BGP routes, and RPKI validation states. Treat them as routing evidence, not registration, ownership, authorization, reachability, or expanded target scope.

URLScan, ONYPHE, and Shodan can attach a provider organization label to an ASN. SQLite stores each relationship in `asn_attributions`; JSONL, the API, CLI output, and HarvestView expose the same typed observation. These labels are time-bound provider evidence. Missing or conflicting values remain separate instead of being replaced by one ASN owner property. Shodan's documented `org` field supplies the organization label; its `isp` field remains part of the Shodan payload and is not treated as equivalent.

Every discovered URL is stored as the `url` result kind. Its source or action origins identify whether it came from BuiltWith, GitLab, RocketReach, API scanning, or another producer; provider-specific URL kinds are not stored.

Hostname and IP evidence use the `hostname` and `ip` result kinds in SQLite, JSONL, the API, and HarvestView. A hostname may be the authorized target itself or a subordinate name, so the result kind does not claim that every value is a subdomain.

Two operational tables support the API: `run_records` stores queue and lifecycle state, and `run_worker_leases` prevents two local workers from claiming the same queue. Runless rows are stored in `legacy_observations`. SQLite upgrades supported schemas during normal initialization.

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
