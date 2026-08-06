# REST API

`restfulHarvest` runs a FastAPI service for local automation and interactive Swagger/ReDoc documentation.

## Start the service

```bash
uv run restfulHarvest
```

Defaults:

- host: `127.0.0.1`
- port: `5000`
- log level: `info`
- rate limit: `5/minute` per client address

Use `uv run restfulHarvest -h` for current launcher options. For example:

```bash
uv run restfulHarvest --rate-limit 10/minute
```

Open:

- Swagger UI: [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs)
- ReDoc: [http://127.0.0.1:5000/redoc](http://127.0.0.1:5000/redoc)

Treat the runtime OpenAPI document as the exact request and response reference.

## Core routes

| Route | Purpose |
| --- | --- |
| `GET /sources` | List current discovery sources. |
| `GET /query` | Run selected discovery sources and return consolidated JSON. |
| `GET /dnsbrute` | Run active DNS brute force for an authorized domain. |
| `GET /runs` | List recent completed enumeration runs. |
| `GET /runs/{run_id}` | Retrieve one completed run and its normalized evidence. |

List sources:

```bash
curl -s http://127.0.0.1:5000/sources | jq -r '.sources[]'
```

Run a passive query:

```bash
curl -sG http://127.0.0.1:5000/query \
  --data-urlencode 'domain=example.com' \
  --data-urlencode 'source=crtsh' \
  --data-urlencode 'source=certspotter' \
  | jq
```

The `source` parameter also accepts the same capability selectors as the CLI:
`subdomains`, `emails`, `ips`, `asns`, `urls`, `people`, and `breaches`.
Repeat `source` to combine capabilities with explicit source names. Selection is
a union and does not filter fields returned by a selected source.

```bash
curl -sG http://127.0.0.1:5000/query \
  --data-urlencode 'domain=example.com' \
  --data-urlencode 'source=emails' \
  --data-urlencode 'source=certspotter' \
  | jq
```

A completed `/query` also retains its normalized terminal record in the local
SQLite database. The response fields remain unchanged, and no JSON, XML, or
JSONL report file is written unless `filename` is supplied.

Completed-run routes require the operator API key because retained evidence can
contain sensitive results:

```bash
curl -s http://127.0.0.1:5000/runs \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  | jq
```

## Additional API routes

The following `POST /additional/*` routes provide optional breach, leak, security-score, and technology-stack lookups:

- `/additional/breaches`
- `/additional/leaks`
- `/additional/security-score`
- `/additional/tech-stack`
- `/additional/all`

Set a server key before startup:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run restfulHarvest
```

Send that value in `X-API-Key`:

```bash
curl -s http://127.0.0.1:5000/additional/tech-stack \
  -X POST \
  -H "X-API-Key: $THEHARVESTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}' \
  | jq
```

These routes may also require provider credentials in the request body or local configuration. Consult `/docs` for the current schema.

## Security boundary

`THEHARVESTER_API_KEY` protects `/additional/*` and `/runs*`. It does not authenticate `/query`, `/sources`, or `/dnsbrute`.

Keep the default localhost binding. If you require remote access, add authentication, network allowlists, TLS, request logging, and an appropriate rate limit.

The supplied Docker Compose configuration binds host port `5000` on every interface unless you narrow the mapping.
