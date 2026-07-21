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

`THEHARVESTER_API_KEY` protects only `/additional/*`. It does not authenticate `/query`, `/sources`, or `/dnsbrute`.

Keep the default localhost binding. If remote access is required, place the service behind authentication, network allowlists, TLS, request logging, and an appropriate rate limit. The supplied Docker Compose configuration binds host port `5000` on every interface unless you narrow the mapping.
