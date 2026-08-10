# REST API

`restfulHarvest` serves one versioned API for local automation.

## Start the service

Set a long random API key before startup:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run restfulHarvest
```

The service binds to `127.0.0.1:5000` by default. Use `uv run restfulHarvest -h` for launcher options.

Open:

- Swagger UI: [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs)
- ReDoc: [http://127.0.0.1:5000/redoc](http://127.0.0.1:5000/redoc)

Treat the runtime OpenAPI document as the exact request and response reference.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /api/v1/sources` | List discovery sources, capabilities, activity classes, and credential names. |
| `POST /api/v1/runs` | Submit one finite enumeration run. |
| `GET /api/v1/runs` | List run records with `limit` and `offset` pagination. |
| `GET /api/v1/runs/{run_id}` | Retrieve lifecycle state, options, results, source outcomes, and artifacts. |
| `POST /api/v1/runs/{run_id}/cancel` | Cancel queued work or request cancellation of running work. |
| `POST /api/v1/runs/import` | Import a JSONL result file without executing discovery. |
| `POST /api/v1/runs/import-database` | Import completed runs from a theHarvester SQLite database. |
| `GET /api/v1/runs/{run_id}/export` | Export normalized results as JSONL. |
| `GET /api/v1/runs/{run_id}/screenshots/{name}` | Retrieve one managed screenshot. |

There are no provider-specific routes. Sources such as `builtwith`, `haveibeenpwned`, `hibpverified`, `leaklookup`, and `securityscorecard` use the same run request as every other source.

The versioned API is asynchronous by design. A successful submission returns a durable run record instead of waiting for every provider and action to finish.

## Authentication

Every `/api/v1/*` route requires the configured key in `X-API-Key`:

```bash
curl -s http://127.0.0.1:5000/api/v1/sources \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq
```

Provider credentials remain in theHarvester's server-side configuration. Requests cannot supply provider API keys.

## Submit and inspect a run

Source names and capability selectors share the `sources` array. Multiple capabilities select the union of matching sources and do not filter fields returned by those sources.

```bash
run_id="$(curl -s http://127.0.0.1:5000/api/v1/runs \
    -X POST \
    -H "X-API-Key: $THEHARVESTER_API_KEY" \
    -H 'Content-Type: application/json' \
    -d '{
      "target": "example.com",
      "sources": ["emails", "crtsh"],
      "limit": 500,
      "deadline_seconds": 1800
    }' \
  | jq -r '.run_id')"

curl -s "http://127.0.0.1:5000/api/v1/runs/$run_id" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq '{status, evidence_status, results, source_executions, action_executions, artifacts}'
```

Run submission is asynchronous. Lifecycle status is `queued`, `running`, `cancelling`, `cancelled`, `completed`, or `failed`. Terminal evidence status is reported separately as `complete`, `partial`, or `failed` when evidence exists.

P1 DNS and P2 direct options are fields on the same run request. The OpenAPI schema shows their current defaults, limits, and descriptions. The server uses the operator-selected target and does not impose a public-only egress policy.

### Run an action against one result

Screenshots and DNS brute force can run directly against an authorized hostname without repeating discovery. Submit an empty `sources` array and select one action:

```bash
curl -s http://127.0.0.1:5000/api/v1/runs \
    -X POST \
    -H "X-API-Key: $THEHARVESTER_API_KEY" \
    -H 'Content-Type: application/json' \
    -d '{
      "target": "subdomain.example.com",
      "sources": [],
      "screenshot": true
    }' \
  | jq
```

For DNS brute force, set `dns_brute` to `true`. You may also provide `dns_resolvers` as one or more distinct IPv4 or IPv6 addresses. Recursive DNS is the only action that requires exactly three resolver addresses.

The action catalog and run request use the same names. For example, set `takeover` to `true` for takeover checks. API endpoint scans can use the bundled paths or an explicit bounded list:

```json
{
  "target": "api.example.com",
  "sources": [],
  "api_scan": true,
  "api_scan_paths": ["/api/v2", "/health"]
}
```

Every custom API scan entry must be a URL path beginning with `/`. The API does not accept a server-side file path.

## Import and export

Import records existing evidence and never contacts the target. For one run, send the same JSONL written by `theHarvester -f NAME`:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/import?filename=report.jsonl" \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @report.jsonl \
  | jq
```

JSONL is a terminal report, so an import is recorded as completed. The summary retains evidence status, source and action outcomes, and screenshot artifact metadata. Each finding's `sources` and `actions` arrays rebuild result attribution and must name an execution in the summary. Result kinds such as `hostname`, `ip`, and `url` use the same names in JSONL, SQLite, and the API.

To load every completed run from another theHarvester database:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/import-database?filename=stash.sqlite" \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/vnd.sqlite3' \
  --data-binary @stash.sqlite \
  | jq
```

The server checks the SQLite header, integrity, schema, and each completed run before copying it. Original run IDs are preserved. Exact duplicates are skipped, while a reused ID with different evidence is rejected. Close the source process or checkpoint its WAL before uploading the database. Screenshot metadata is imported, but screenshot files must be copied separately. The default upload ceiling is 1 GiB and can be changed with `THEHARVESTER_MAX_DATABASE_IMPORT_BYTES`.

Export one normalized result set in the same streamable format:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/$run_id/export" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -o results.jsonl
```

The first line is the `summary` record, including evidence status, source and action outcomes, and artifacts. Each remaining line is one normalized finding with `type`, `value`, `sources`, and optional `actions`. This keeps the file easy to stream with `jq -c` and makes API exports importable again without a format conversion. Lifecycle details and the submitted request remain available from `GET /api/v1/runs/{run_id}`.

## Security boundary

Keep the default localhost binding. If remote access is required, add TLS, network access controls, request logging, and an appropriate rate limit. The supplied Docker Compose configuration publishes only to `127.0.0.1` by default.
