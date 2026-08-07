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
| `GET /api/v1/runs` | List run records. |
| `GET /api/v1/runs/{run_id}` | Retrieve lifecycle state, options, results, source outcomes, and artifacts. |
| `POST /api/v1/runs/{run_id}/cancel` | Cancel queued work or request cancellation of running work. |
| `POST /api/v1/runs/import` | Import a JSON or JSONL result file without executing discovery. |
| `GET /api/v1/runs/{run_id}/exports/{format}` | Export normalized results as `json` or `csv`. |
| `GET /api/v1/runs/{run_id}/screenshots/{name}` | Retrieve one managed screenshot. |

There are no provider-specific routes. Sources such as `builtwith`, `haveibeenpwned`, `hibpverified`, `leaklookup`, and `securityscorecard` use the same run request as every other source.

## Fresh-start migration

The unversioned API was removed without compatibility routes or redirects. Update clients as follows:

| Removed route | Replacement |
| --- | --- |
| `GET /sources` | `GET /api/v1/sources` |
| `GET /query` | Submit with `POST /api/v1/runs`, then read `GET /api/v1/runs/{run_id}`. |
| `GET /dnsbrute` | Submit a run with `dns_brute: true`. |
| `POST /additional/*` | Select the corresponding provider through `POST /api/v1/runs`. |

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
  | jq '{status, evidence_status, results, source_executions}'
```

Run submission is asynchronous. Lifecycle status is `queued`, `running`, `cancelling`, `cancelled`, `completed`, or `failed`. Terminal evidence status is reported separately as `complete`, `partial`, or `failed` when evidence exists.

P1 DNS and P2 direct options are fields on the same run request. The OpenAPI schema shows their current defaults, limits, and descriptions. The server uses the operator-selected target and does not impose a public-only egress policy.

## Import and export

Import records existing evidence and never contacts the target. JSONL imports accept the same `theharvester-results-v1` report written by `theHarvester -f NAME`:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/import?filename=report.jsonl" \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @report.jsonl \
  | jq
```

That CLI JSONL format does not contain source outcomes, so its imported evidence status is `partial` rather than an invented success claim. `hostname` and `ip-address` findings are exposed through the API's canonical `subdomain` and `ip` result types.

Export one normalized result set:

```bash
curl -s "http://127.0.0.1:5000/api/v1/runs/$run_id/exports/json" \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -o results.json
```

The JSON export contains run and evidence IDs, target, lifecycle and evidence status, timestamps, the submitted request, source outcomes, and the normalized `results` array. The CSV export has a stable header:

```text
"type","value","dns_status"
```

Fields are quoted in the CSV response. Per-result source attribution is omitted until the collection seam can retain it truthfully; source outcomes remain available in the JSON export.

## Security boundary

Keep the default localhost binding. If remote access is required, add TLS, network access controls, request logging, and an appropriate rate limit. The supplied Docker Compose configuration publishes only to `127.0.0.1` by default.
