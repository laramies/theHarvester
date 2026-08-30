# REST API

`harvestview` serves the web application at `/` and one versioned API for local automation.

![HarvestView run desk architecture](https://raw.githubusercontent.com/laramies/theHarvester/dev/docs/images/harvestview-architecture.svg)

## Start the service

Set a long random API key before startup:

Network activity: local-only with the default loopback binding.

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run harvestview
```

The service binds to `127.0.0.1:5000` by default. Use `uv run harvestview -h` for launcher options.

Open:

- HarvestView: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- Schedules: [http://127.0.0.1:5000/schedules](http://127.0.0.1:5000/schedules)
- Swagger UI: [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs)
- ReDoc: [http://127.0.0.1:5000/redoc](http://127.0.0.1:5000/redoc)

Treat the runtime OpenAPI document as the exact request and response reference.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /api/v1/sources` | List discovery sources, capabilities, activity classes, and credential names. |
| `POST /api/v1/runs` | Submit one finite enumeration run. |
| `GET /api/v1/runs` | List run records with `limit` and `offset` pagination. |
| `GET /api/v1/runs/{run_id}` | Retrieve lifecycle state, options, results, source outcomes, source yields, hostname changes, and artifacts. |
| `POST /api/v1/runs/{run_id}/cancel` | Cancel queued work or request cancellation of running work. |
| `POST /api/v1/runs/import` | Import a JSONL result file without executing discovery. |
| `POST /api/v1/runs/import-database` | Import completed runs from a theHarvester SQLite database. |
| `GET /api/v1/runs/export-database` | Export all completed run evidence as a portable SQLite database. |
| `GET /api/v1/runs/{run_id}/export` | Export normalized results as JSONL. |
| `GET /api/v1/runs/{run_id}/screenshots/{name}` | Retrieve one managed screenshot. |
| `GET/POST /api/v1/schedules` | List or create persistent local schedules. |
| `GET /api/v1/schedules/health` | Report scheduler and execution-worker availability. |
| `GET/PUT/DELETE /api/v1/schedules/{schedule_id}` | Read, replace, or delete one schedule. |
| `POST /api/v1/schedules/{schedule_id}/pause` | Prevent future occurrences without cancelling submitted runs. |
| `POST /api/v1/schedules/{schedule_id}/resume` | Resume future occurrences. |
| `POST /api/v1/schedules/{schedule_id}/run-now` | Queue one extra occurrence without changing recurrence timing. |
| `GET /api/v1/schedules/{schedule_id}/dispatches` | List per-target dispatch reservations and lifecycle mirrors. |

There are no provider-specific routes. Sources such as `builtwith`, `haveibeenpwned`, `hibpverified`, `leaklookup`, and `securityscorecard` use the same run request as every other source.

The versioned API is asynchronous by design. A successful submission returns a durable run record instead of waiting for every provider and action to finish.

## Authentication

Every `/api/v1/*` route requires the configured key in `X-API-Key`:

```bash
curl -s http://127.0.0.1:5000/api/v1/sources \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq
```

HarvestView receives a derived HttpOnly browser-session cookie when loaded from localhost. The browser never stores or displays the configured API key. Cookie-authenticated mutations also require a matching same-origin request.

Provider credentials remain in theHarvester's server-side configuration. Requests cannot supply provider API keys.

## Schedule finite runs

HarvestView schedules persist an authorized target inventory, one validated run template, recurrence timing, and an overlap policy. Every occurrence creates one ordinary run per target through the existing queue; the default worker executes those runs serially. A single schedule accepts up to 10,000 normalized unique targets.

Daily, weekly, and monthly recurrences preserve local wall-clock time in the selected IANA timezone across daylight-saving changes. A monthly day that does not exist falls on that month’s final day. Hourly recurrences use elapsed UTC hours. After downtime, one due occurrence is dispatched and the recurrence advances to the next future time instead of replaying every missed interval.

Schedule responses include the next five derived `upcoming_occurrences`. HarvestView displays those occurrences on each schedule card and can edit future schedule settings through the existing replacement route without deleting submitted runs or dispatch history.

Network activity: schedule management is local. A due occurrence performs only the provider, DNS, or direct activity explicitly stored in its run template. P1 and P2 activity still requires explicit operator authorization for every listed target.

```bash
curl -s http://127.0.0.1:5000/api/v1/schedules \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Weekly external inventory",
    "targets": ["example.com", "example.org"],
    "run": {"target": "example.com", "sources": ["crtsh"], "limit": 500},
    "timing": {
      "frequency": "weekly",
      "start_at": "2026-08-24T09:00:00-04:00",
      "timezone": "America/New_York",
      "interval": 1,
      "weekdays": [1]
    },
    "enabled": true,
    "overlap_policy": "skip"
  }' \
  | jq
```

`skip` advances past an occurrence when an earlier batch from the same schedule remains reserved, queued, or running. `queue` submits another finite batch behind it. Pausing or deleting a schedule never cancels runs already submitted, and deleting one does not remove completed evidence. SQLAlchemy stores schedule control state in a separate mode-`0600` SQLite database. Portable SQLite exports contain finalized run evidence, not schedules, claims, or dispatch reservations. Set `THEHARVESTER_SCHEDULE_DB` to override the schedule database's default sibling path. Set `THEHARVESTER_SCHEDULER=disabled` only for a persistence-only preview or externally controlled startup.

## Submit and inspect a run

Source names and capability selectors share the `sources` array. Multiple capabilities select the union of matching sources and do not filter fields returned by those sources.

Network activity: the API request is local, but the queued run contacts the selected providers and any enabled action targets.

```bash
run_id="$(curl -s http://127.0.0.1:5000/api/v1/runs \
    -X POST \
    -H "X-API-Key: $THEHARVESTER_API_KEY" \
    -H 'Content-Type: application/json' \
    -d '{
      "target": "example.com",
      "sources": ["emails", "crtsh"],
      "limit": 500,
      "source_workers": 3,
      "deadline_seconds": 1800
    }' \
  | jq -r '.run_id')"

curl -s "http://127.0.0.1:5000/api/v1/runs/$run_id" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq '{status, evidence_status, results, source_executions, source_yields, hostname_tracking, action_executions, artifacts}'
```

Run submission is asynchronous. Read the two status fields separately:

| Field | Values | Meaning |
| --- | --- | --- |
| `status` | `queued`, `running`, `cancelling`, `cancelled`, `completed`, `failed` | Worker lifecycle state. |
| `evidence_status` | `complete`, `partial`, `failed` | Quality of terminal evidence when it exists. |

`source_workers` is the same positive concurrency used by CLI `-j` or `--source-workers` and HarvestView. It defaults to three, is reduced when fewer sources are selected, and never skips sources or limits their results.

`limit` defaults to 500 per source. A value of `0` removes the shared cap on results and pages, so adapters continue until their provider is exhausted. There is no numeric maximum. Provider quotas, protocol maxima, response-size guards, and runtime limits still apply. If a provider or safety limit stops a source after it retained results, the run keeps those results and records the source as partial with the stop reason.

`source_yields` reports normalized hostname contributions within the run. `unique_result_count` counts hostnames reported by exactly one selected source. When `dns_resolve` ran, `resolved_hostname_count` and `unique_resolved_hostname_count` show which of those hostnames had retained A, AAAA, or CNAME answers. Read these counts with the source's execution status and stop reason. The [results guide](Results-and-Local-Data#compare-source-hostname-yield) explains how to compare fixed runs over time.

### Read hostname changes

Finalized run details include an additive `hostname_tracking` object derived only from persisted SQLite evidence. Reading the endpoint never starts discovery or DNS. The selected run is compared with the previous finalized run that has the same canonical target and exact source cohort.

The object contains:

- `target` and `comparison_count`.
- `comparisons`, with the current and baseline run IDs and completion times, exact `source_cohort`, `new`, `persisting`, `missing`, and `inconclusive` counts, and a message when no baseline exists.
- `hostname_changes`, with change state, hostname, previous and current sources, relevant-side source exclusivity, blocking source outcomes, previous and current resolution evidence, DNS action statuses, and addressability classifications.

Run details include persisting rows so HarvestView can show or hide them locally. `new` requires every current contributing source to have completed in the baseline, while `missing` requires every previous contributing source to have completed in the selected run. Otherwise the one-sided observation is `inconclusive`, with the relevant partial, failed, rate-limited, or skipped outcomes retained in `blocking_sources`. Unrelated source failures do not change the row.

Resolution evidence is `positive`, `not-retained`, or `not-checked`; no ambiguous unknown state is emitted. Addressability is a separate retained recursive-DNS classification or `null` when no classification exists. See [Track hostname changes across finalized runs](Results-and-Local-Data#track-hostname-changes-across-finalized-runs) for CLI examples and full interpretation rules.

P1 DNS and P2 direct options are fields on the same run request. The OpenAPI schema shows their current defaults, limits, and descriptions. The server uses the operator-selected target and does not impose a public-only egress policy.

### Query RouteViews

RouteViews is the explicit P0 `routeviews` action.

- A domain run enriches only harvested IPs that have sourced IP-to-ASN attribution. Harvested IPs without that attribution are not sent, and bare ASN findings are not expanded into complete prefix inventories.
- A run may target an AS-prefixed ASN or IP address. The CLI also accepts a literal CIDR. An IP pivot keeps the most-specific matching prefix and every origin for a multi-origin prefix. An explicit ASN target requests its complete prefix inventory.
- The fixed budget is 300 sequential requests and 300 seconds. `limit` does not change it.
- A server-side `routeviews.key` selects PeeringDB-verified authenticated access at the documented 10-request-per-second allowance. Without a key, the action uses guest access at one request per second. Requests cannot supply provider credentials.
- Returned prefixes remain external relationships. They are never scheduled as DNS or P2 targets.

```json
{
  "target": "AS64500",
  "sources": [],
  "routeviews": true
}
```

### Run an action against one result

Screenshots and DNS brute force can run directly against an authorized hostname without repeating discovery. Submit an empty `sources` array and select one action:

Network activity: target-facing for screenshots and resolver-facing for DNS brute force. The API request itself is local.

```bash
curl -s http://127.0.0.1:5000/api/v1/runs \
    -X POST \
    -H "X-API-Key: $THEHARVESTER_API_KEY" \
    -H 'Content-Type: application/json' \
    -d '{
      "target": "replace-with-an-authorized-hostname",
      "sources": [],
      "screenshot": true
    }' \
  | jq
```

For DNS brute force, set `dns_brute` to `true`. You may also provide `dns_resolvers` as one or more distinct IPv4 or IPv6 addresses. Recursive DNS is the only action that requires exactly three resolver addresses.

The action catalog and run request use the same names. For example, set `takeover` to `true` for takeover checks. API endpoint scans can use the bundled paths or an explicit bounded list:

```json
{
  "target": "replace-with-an-authorized-hostname",
  "sources": [],
  "api_scan": true,
  "api_scan_paths": ["/api/v2", "/health"]
}
```

Every custom API scan entry must be a URL path beginning with `/`. The API does not accept a server-side file path.

Virtual host discovery is the `vhost` action. An action-only run must provide both a literal-IP endpoint and at least one in-scope hostname candidate:

Network activity: target-facing literal-IP requests with the candidate in SNI and HTTP `Host`.

```json
{
  "target": "authorized.example",
  "sources": [],
  "vhost_endpoint": "https://192.0.2.10:443/",
  "vhost_candidates": ["admin.authorized.example"]
}
```

Supplying either virtual host field enables the action, but a missing endpoint or candidate set must then come from selected-source results. Candidate names are sent as HTTP `Host` values and HTTPS SNI; this action never resolves them. It uses direct transport, does not follow redirects, rejects proxy settings, and applies request, runtime, timeout, and concurrency bounds. See [Virtual Host Discovery](Virtual-Host-Discovery) for the exact scope and evidence model.

HarvestView's subdomain action buttons call this route and create a separate run without changing the completed parent run.

## Import and export

These operations are local-only. Import records existing evidence without contacting providers or targets. For one run, send the same JSONL written by `theHarvester -f NAME`:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/import?filename=report.jsonl" \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @report.jsonl \
  | jq
```

JSONL is a terminal report, so an import is recorded as completed. The summary retains evidence status, source and action outcomes, and screenshot artifact metadata. Each finding's `sources` and `actions` arrays rebuild result attribution and must name an execution in the summary. Result kinds such as `hostname`, `ip`, and `url` use the same names in JSONL, SQLite, and the API.

An `asn` result may include `organization-attribution` observations from URLScan, ONYPHE, or Shodan. Each observation names its producer and related hostname or IP; it is provider attribution rather than ownership or engagement-scope evidence.

To load every completed run from another theHarvester database:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/import-database?filename=stash.sqlite" \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/vnd.sqlite3' \
  --data-binary @stash.sqlite \
  | jq
```

Before importing SQLite:

- Close the source process or checkpoint its WAL.
- Expect the server to check the SQLite header, integrity, schema, and each completed run before copying it.
- Original run IDs are preserved. Exact duplicates are skipped; a reused ID with different evidence is rejected.
- Screenshot metadata is imported, but screenshot files must be copied separately.
- The default upload ceiling is 1 GiB. Change it with `THEHARVESTER_MAX_DATABASE_IMPORT_BYTES`.

Export every completed run as a consistent database that can be imported elsewhere:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/export-database" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -o theharvester-completed-runs.sqlite
```

The export contains canonical completed evidence and screenshot metadata. It excludes queue state, cancellation state, worker leases, and legacy observations. Screenshot files are also excluded. The server checkpoints and closes the temporary database before download, so no manual WAL handling is required.

Export one normalized result set in the same streamable format:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/$run_id/export" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -o results.jsonl
```

The first line is the `summary` record, including evidence status, source and action outcomes, and artifacts. Each remaining line is one normalized finding with `type`, `value`, `sources`, and optional `actions`. A hostname confirmed by the `vhost` action adds native endpoint observations; a RouteViews `prefix` adds native origin, route, and RPKI observations with fixed external-relationship scope. The file can be streamed with `jq -c` or imported through the API without conversion. Lifecycle details and the submitted request are available from `GET /api/v1/runs/{run_id}`.

## Security boundary

Keep the default localhost binding. If remote access is required, add TLS, network access controls, request logging, and an appropriate rate limit. The supplied Docker Compose configuration publishes only to `127.0.0.1` by default.
