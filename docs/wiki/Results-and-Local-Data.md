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

### Action evidence examples

These synthetic reports use reserved names, ASNs, and addresses. Each block starts with a summary and passes the same JSONL parser that handles imports. The summary records action outcomes. Each finding's `actions` array identifies the action that produced it.

<details>
<summary>DNS resolution, reverse lookup, and brute force</summary>

Resolution contributes IP findings. Reverse lookup contributes hostnames, while brute force can contribute both hostnames and IP addresses.

```jsonl
{"action_executions":[{"action":"dns-brute","duration_ms":25.0,"error_type":null,"result_count":2,"status":"completed","stop_reason":null},{"action":"dns-lookup","duration_ms":31.0,"error_type":null,"result_count":1,"status":"completed","stop_reason":null},{"action":"dns-resolve","duration_ms":18.0,"error_type":null,"result_count":1,"status":"completed","stop_reason":null}],"artifacts":[],"completed_at":"2026-08-17T12:01:00Z","counts":{"hostname":3,"ip":2},"evidence_status":"complete","result_count":5,"run_id":"123e4567-e89b-12d3-a456-426614174101","source_executions":[{"duration_ms":12.0,"error_type":null,"result_count":1,"source":"crtsh","status":"completed","stop_reason":null},{"duration_ms":15.0,"error_type":null,"result_count":1,"source":"rapiddns","status":"completed","stop_reason":null}],"started_at":"2026-08-17T12:00:00Z","target":"example.com","type":"summary"}
{"actions":["dns-brute"],"sources":[],"type":"hostname","value":"admin.example.com"}
{"sources":["crtsh"],"type":"hostname","value":"api.example.com"}
{"actions":["dns-lookup"],"sources":[],"type":"hostname","value":"ptr.example.com"}
{"actions":["dns-resolve"],"sources":["rapiddns"],"type":"ip","value":"192.0.2.10"}
{"actions":["dns-brute"],"sources":[],"type":"ip","value":"192.0.2.20"}
```

</details>

<details>
<summary>Recursive DNS</summary>

Recursive DNS contributes ordinary hostname and IP findings. Its structured records keep the parent name, returned addresses, PTR values, depth, query count, and stop reason. The structured `value` fields contain JSON strings, so use `fromjson` when reading them with `jq`.

```jsonl
{"action_executions":[{"action":"dns-recursive","duration_ms":40.0,"error_type":null,"result_count":5,"status":"completed","stop_reason":"depth-limit"}],"artifacts":[],"completed_at":"2026-08-17T12:01:00Z","counts":{"dns-recursive-classification":1,"dns-recursive-finding":1,"dns-recursive-summary":1,"hostname":2,"ip":1},"evidence_status":"complete","result_count":6,"run_id":"123e4567-e89b-12d3-a456-426614174102","source_executions":[{"duration_ms":12.0,"error_type":null,"result_count":1,"source":"crtsh","status":"completed","stop_reason":null}],"started_at":"2026-08-17T12:00:00Z","target":"example.com","type":"summary"}
{"actions":["dns-recursive"],"sources":[],"type":"dns-recursive-classification","value":"{\"addressability\":\"not-currently-addressable\",\"addresses\":[],\"cnames\":[\"missing.vendor.test\"],\"hostname\":\"unused.api.example.com\",\"parent\":\"api.example.com\",\"ptrs\":[\"legacy-ptr.example.net\"]}"}
{"actions":["dns-recursive"],"sources":[],"type":"dns-recursive-finding","value":"{\"addresses\":[\"192.0.2.21\"],\"hostname\":\"dev.api.example.com\",\"parent\":\"api.example.com\",\"ptrs\":[\"ptr.example.net\"]}"}
{"actions":["dns-recursive"],"sources":[],"type":"dns-recursive-summary","value":"{\"depth_reached\":1,\"query_count\":24,\"stop_reason\":\"depth-limit\",\"zero_yield_batches\":0}"}
{"sources":["crtsh"],"type":"hostname","value":"api.example.com"}
{"actions":["dns-recursive"],"sources":[],"type":"hostname","value":"dev.api.example.com"}
{"actions":["dns-recursive"],"sources":[],"type":"ip","value":"192.0.2.21"}
```

</details>

<details>
<summary>Shodan host enrichment</summary>

A `shodan-host` finding uses the IP address as its value. JSONL keeps service details together rather than creating separate result kinds.

```jsonl
{"action_executions":[{"action":"shodan","duration_ms":22.0,"error_type":null,"result_count":1,"status":"completed","stop_reason":null}],"artifacts":[],"completed_at":"2026-08-17T12:01:00Z","counts":{"ip":1,"shodan-host":1},"evidence_status":"complete","result_count":2,"run_id":"123e4567-e89b-12d3-a456-426614174103","source_executions":[{"duration_ms":15.0,"error_type":null,"result_count":1,"source":"rapiddns","status":"completed","stop_reason":null}],"started_at":"2026-08-17T12:00:00Z","target":"example.com","type":"summary"}
{"sources":["rapiddns"],"type":"ip","value":"192.0.2.10"}
{"actions":["shodan"],"details":{"asn":"AS64500","domains":["example.com"],"hostnames":["api.example.com"],"organization":"Example Network","services":[{"http":{"components":["nginx"],"server":"nginx","title":"Example"},"observed_at":"2026-08-17T11:58:00Z","port":443,"product":"nginx","transport":"tcp","version":"1.24.0"}]},"sources":[],"type":"shodan-host","value":"192.0.2.10"}
```

</details>

<details>
<summary>RouteViews routing evidence</summary>

RouteViews keeps the ASN as a scalar finding and attaches origin, BGP route, and RPKI observations to a canonical prefix. The prefix remains an external relationship and does not expand target scope.

```jsonl
{"action_executions":[{"action":"routeviews","duration_ms":55.0,"error_type":null,"result_count":1,"status":"completed","stop_reason":null}],"artifacts":[],"completed_at":"2026-08-17T12:01:00Z","counts":{"asn":1,"prefix":1},"evidence_status":"complete","result_count":2,"run_id":"123e4567-e89b-12d3-a456-426614174104","source_executions":[],"started_at":"2026-08-17T12:00:00Z","target":"AS64500","type":"summary"}
{"sources":[],"type":"asn","value":"AS64500"}
{"actions":["routeviews"],"observations":[{"action":"routeviews","collected_at":"2026-08-17T12:01:00Z","origin_asn":"AS64500","type":"observed-origin"},{"action":"routeviews","as_path":"64496 64500","collected_at":"2026-08-17T12:01:00Z","collector":"route-views.example","communities":"64496:100 64500:200","observed_at":"2026-08-17T11:59:00Z","origin_asn":"AS64500","peer_address":"2001:db8::1","peer_asn":"AS64496","type":"bgp-route"},{"action":"routeviews","collected_at":"2026-08-17T12:01:00Z","observed_at":"2026-08-17T11:59:00Z","origin_asn":"AS64500","state":"valid","type":"rpki-validation"}],"scope":"external-relationship","sources":[],"type":"prefix","value":"192.0.2.0/24"}
```

</details>

The [full virtual-host JSONL finding](Virtual-Host-Discovery#one-finding-multiple-endpoint-observations) shows how one confirmed hostname retains evidence from more than one endpoint.

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

HarvestView keeps schedules, claims, and dispatch reservations in a separate mode-`0600` SQLite database managed through SQLAlchemy. Its default path is `~/.local/share/theHarvester/stash.schedules.sqlite`; set `THEHARVESTER_SCHEDULE_DB` to use another path. This database is local control state and is not included in portable SQLite evidence exports.

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

### Compare source hostname yield

Run details include `source_yields`, derived from persisted normalized hostname provenance. For every selected source it reports:

- `observed_result_count`: distinct hostnames attributed to the source;
- `unique_result_count`: hostnames no other source in that run reported;
- `shared_result_count`: hostnames also reported by at least one other source;
- `resolved_hostname_count`: attributed hostnames for which the run's `dns-resolve` action retained an A, AAAA, or CNAME answer;
- `unique_resolved_hostname_count`: resolved hostnames attributed to only this source.

`unique_result_count` measures a source's marginal coverage without depending on source order. `unique_resolved_hostname_count` narrows that count to hostnames with current DNS evidence. Neither proves that a provider is authoritative or independent, and a DNS answer does not prove service reachability. Check the matching `source_executions` status and stop reason. A source that failed, was rate-limited or skipped, or stopped at a provider boundary is not a comparable zero-yield result. Providers that use the same certificate-transparency or passive-DNS family can overlap or repeat the same upstream evidence.

For a reusable benchmark, keep the authorized target, source set, requested limit, release version, resolver set, and collection window fixed. Set the limit to `0` when the comparison should have no shared local result cap. Save the completed runs in SQLite and repeat the test across several authorized targets and dates. Compare median unique count, median unique-resolved count, resolution rate, and successful-run rate. Record provider and adapter ceilings as execution evidence instead of treating truncated runs as zero yield. Do not commit target results. Add cross-run aggregation only after you have enough comparable runs to justify it.

#### Analyze yields from SQLite

The installed `harvest-yields` command reads an existing results database. With no arguments, it reads `~/.local/share/theHarvester/stash.sqlite` and reports hostname yields. If the selected database does not exist, the command exits without creating it. You can select another database, result kind, or completed run:

```console
harvest-yields
harvest-yields --database results.sqlite
harvest-yields --database results.sqlite --kind hostname
harvest-yields --database results.sqlite --kind ip
harvest-yields --database results.sqlite --kind asn
harvest-yields --database results.sqlite --run-id 11111111-1111-4111-8111-111111111111
harvest-yields --database results.sqlite --format json
```

Without `--run-id`, the command adds each run's source yields. The top-level `run_count` shows how many runs were selected. Each source row has its own `run_count`, including executions that produced no results. `UNIQUE/RUN` divides the summed unique count by that source's run count and is the default ranking key. The JSON field is `unique_result_count_per_run`. "Unique" always means unique within one run, so aggregate totals add the per-run counts instead of recomputing uniqueness across targets or dates. Hostname output also includes resolved and unique-resolved counts plus `UNIQUE-RESOLVED/RUN`, named `unique_resolved_hostname_count_per_run` in JSON. Other result kinds omit the DNS-specific fields.

## Handling and sharing

- Store results only where the engagement permits.
- Remove reports, screenshots, and the SQLite database when retention expires.
- Do not commit collected output to theHarvester or attach raw target data to public issues.
- Share only the minimum sanitized output needed to reproduce a problem.
- Remove credentials, private targets, account details, and unnecessary provider response content.
