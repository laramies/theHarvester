# Virtual host discovery

A web server can host several sites on one IP address. The site selected by the server depends on the HTTP `Host` header and, for HTTPS, the TLS Server Name Indication (SNI). Virtual host discovery checks whether an in-scope hostname produces a response that differs from the endpoint's default or wildcard response.

This is a P2 direct action. It sends requests to harvested IP addresses or to one literal-IP endpoint supplied by the operator. Use it only when the target, addresses, ports, and technique are covered by the assessment authorization.

## Run a bounded sweep

Network activity: provider-facing discovery followed by target-facing requests to harvested IP endpoints.

Harvest hostnames and IP addresses, then run the sweep with its bounded defaults:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'

uv run theHarvester \
  -d "$AUTHORIZED_DOMAIN" \
  -b rapiddns \
  --vhost \
  -f report
```

`rapiddns` is used here because it can return both hostnames and literal IP addresses. If the selected sources return only hostnames, enable a DNS action that contributes IP evidence or supply `--vhost-endpoint`.

Repeat `--vhost-candidate` to add names that are already authorized but were not returned by the selected sources:

```bash
uv run theHarvester \
  -d "$AUTHORIZED_DOMAIN" \
  -b rapiddns \
  --vhost \
  --vhost-candidate "admin.${AUTHORIZED_DOMAIN}" \
  --vhost-candidate "preview.${AUTHORIZED_DOMAIN}"
```

Virtual host discovery uses direct transport and rejects `--proxies`. HTTPS certificate verification is enabled by default. `--vhost-insecure` disables verification and records `tls_verified: false` in the evidence. Use it only when the engagement requires unverified TLS and the endpoint is authorized.

## What gets probed

`--vhost` uses the run's collected evidence:

- Literal IP addresses become endpoints. The sweep tries HTTPS port 443 across the address set before HTTP port 80.
- Harvested hostnames inside the exact target boundary become candidates.
- DNS brute-force IPs and names are included because virtual host discovery runs after DNS brute force.
- In-scope names found by reverse DNS become candidates. The reverse-DNS `/24` range does not become a new set of virtual host endpoints.

This is harvested-candidate testing, not wordlist-based virtual host brute forcing. Repeat `--vhost-candidate` to add a small authorized list that the selected sources did not return.

For a normal harvested run, `--vhost` is the only virtual-host option you need. The request, runtime, timeout, and concurrency options are advanced safety overrides; bounded defaults apply when you omit them.

The shared request cap may stop the sweep before it reaches every endpoint. When that happens, the `vhost` action is `partial` with the stop reason `request-limit`; it does not claim complete coverage.

An explicit endpoint replaces the harvested endpoint set:

Network activity: target-facing requests to the literal IP endpoint.

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
AUTHORIZED_IP='replace-with-an-authorized-ip'

uv run theHarvester \
  -d "$AUTHORIZED_DOMAIN" \
  --vhost-endpoint "https://${AUTHORIZED_IP}:443/" \
  --vhost-candidate "admin.${AUTHORIZED_DOMAIN}" \
  -f report
```

The endpoint must use `http` or `https`, a literal IPv4 or IPv6 address, and an optional port. Paths, query strings, fragments, credentials, hostnames, and CIDR ranges are rejected.

Candidate names are never resolved by this feature. Each candidate must be the target hostname or a descendant of it. The boundary is exact: authorization for `www.example.com` does not authorize `admin.example.com`.

## How the classifier works

For each endpoint, theHarvester makes a literal-IP context request and at least three synthetic unknown-host control requests. Controls match the label shape of the candidate being tested. This matters on servers whose wildcard behavior changes with label depth.

HTTPS candidate and control requests send the same hostname in TLS SNI and the HTTP `Host` header. HTTP requests send the hostname only in `Host`. Redirects are recorded as evidence but are not followed.

The sweep first turns harvested evidence and any operator override into one bounded set of comparable requests:

![Bounded virtual-host sweep](https://raw.githubusercontent.com/laramies/theHarvester/dev/docs/images/vhost-sweep-overview.svg)

The response set then enters a separate classifier. A status, redirect, or request-phase difference can be accepted immediately. A body-only difference must repeat before it becomes a finding:

![Virtual-host response classifier](https://raw.githubusercontent.com/laramies/theHarvester/dev/docs/images/vhost-classifier.svg)

Before comparison, the classifier replaces an exact reflection of the current authority in the response body or `Location` header. A generic error page that merely repeats the requested hostname should not become a discovery.

The comparison can use these signals:

| Signal | Meaning |
| --- | --- |
| `status` | The HTTP status differs from both baselines. |
| `location` | The normalized redirect location differs. |
| `body_size` | The bounded response body has a different size. |
| `body_sha256` | The bounded response body has different content. |

The classifier returns one of three states:

| Classification | Meaning |
| --- | --- |
| `default` | The candidate matches either the literal-IP context response or a stable unknown-host control. |
| `distinct` | The candidate differs from both baselines. Body-only differences require a matching second candidate response. |
| `indeterminate` | A baseline is unusable, the controls disagree, the candidate matches only one baseline, body evidence is incomplete, or a required confirmation did not repeat. |

Completed results retain only confirmed `distinct` observations. Default and indeterminate responses still consume budget, but they are not reported as discoveries.

## Request and runtime limits

The defaults are:

| Control | CLI option | Default |
| --- | --- | ---: |
| Requests across the whole sweep | `--vhost-request-limit` | 100 |
| Runtime across the whole sweep | `--vhost-runtime-seconds` | 30 seconds |
| Timeout for one request | `--vhost-timeout-seconds` | 5 seconds |
| Concurrent candidate requests | `--vhost-concurrency` | 5 |

The request limit covers the context request, unknown controls, candidate requests, and any confirmation request. Unused requests and time from an early endpoint carry forward to later endpoints. A low cap favors breadth: HTTPS is attempted across harvested IPs before the sweep starts HTTP.

The `vhost` entry in `action_executions` records one of these action statuses:

| Action status | Meaning |
| --- | --- |
| `completed` | Every selected endpoint and candidate completed within the limits. |
| `partial` | A request or runtime limit stopped coverage, or a request, scan, or cancellation error occurred after a confirmed hostname was retained. |
| `skipped` | No candidate names or literal-IP endpoints were available. |
| `failed` | A request, scan, or cancellation error ended the action before it retained a confirmed hostname. |

Its `stop_reason` explains the outcome in more detail:

| Stop reason | Meaning |
| --- | --- |
| `completed` | Every selected endpoint and candidate completed within the limits. |
| `no-candidates` | The run had no in-scope hostnames to test. |
| `no-endpoints` | The run had no harvested literal IP and no endpoint override. |
| `request-limit` | The cap omitted an endpoint or candidate, or stopped before confirmation finished. |
| `request-errors` | Every candidate was attempted, but one or more requests failed. |
| `runtime-limit` | The shared wall-clock deadline expired. Completed partial evidence is retained. |
| `scan-error` | An unexpected probing error stopped the action. |
| `cancelled` | The operator cancelled the run. |

Cancellation requested by the operator is different from a runtime limit. It propagates through the worker lifecycle and closes active connections.

## Read terminal output

The summary reports confirmed endpoint observations and coverage:

```text
[*] Virtual hosts: confirmed=1; candidate-endpoints=18/48; endpoints=4/8; requests=100
[!] Coverage stopped at the request limit; raise --vhost-request-limit or narrow the scan.
admin.authorized.example at https://192.0.2.10:443/: status=401; signals=status
```

A candidate-endpoint is one hostname tested against one IP endpoint. This pair count avoids implying that a hostname tested against one IP was also tested against every other IP. When coverage stops early, the next line explains which limit was reached and which option controls it.

## HarvestView and REST API

HarvestView exposes a virtual host discovery checkbox plus optional endpoint and candidate inputs. Advanced safety controls contain the request, runtime, timeout, concurrency, and certificate-verification overrides. Leaving the endpoint blank uses harvested IPs.

The same run can be submitted to `POST /api/v1/runs`:

Network activity: the API request is local, but the queued run performs provider-facing discovery and target-facing virtual host requests.

```json
{
  "target": "authorized.example",
  "sources": ["rapiddns"],
  "vhost": true
}
```

Add `vhost_endpoint` or `vhost_candidates` only when harvested evidence does not supply them. The request, runtime, timeout, concurrency, and insecure-TLS fields override the same bounded defaults shown above.

Supplying `vhost_endpoint` or `vhost_candidates` enables the action even when `vhost` is omitted. A run with `sources: []` must supply both an endpoint and at least one candidate; otherwise the missing side must come from harvested results. The API rejects proxy use, hostname endpoints, out-of-scope candidates, and IP targets before it queues a run.

## One finding, multiple endpoint observations

JSONL is unversioned. After the summary line, it stores one canonical finding for each confirmed hostname. The normal `value` field contains the hostname, `actions` records `vhost` provenance, and `observations` is a native array rather than JSON hidden inside a string.

If a hostname is distinct on two endpoints, both endpoint records stay under that one hostname finding:

<details>
<summary>Full JSONL finding example</summary>

```json
{
  "type": "hostname",
  "value": "admin.authorized.example",
  "sources": [],
  "actions": ["vhost"],
  "observations": [
    {
      "endpoint": "https://192.0.2.10:443/",
      "http_host": "admin.authorized.example",
      "tls_server_name": "admin.authorized.example",
      "classification": "distinct",
      "phase": "body",
      "status": 401,
      "location": null,
      "body_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "body_size": 123,
      "body_truncated": false,
      "context_phase": "body",
      "context_status": 200,
      "context_location": null,
      "context_body_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "context_body_size": 123,
      "context_body_truncated": false,
      "control_phase": "body",
      "control_status": 200,
      "control_location": null,
      "control_body_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "control_body_size": 123,
      "control_body_truncated": false,
      "confirmation_body_sha256": null,
      "tls_verified": true,
      "distinct_signals": ["status"],
      "reflection_normalized": false
    },
    {
      "endpoint": "https://192.0.2.11:443/",
      "http_host": "admin.authorized.example",
      "tls_server_name": "admin.authorized.example",
      "classification": "distinct",
      "phase": "body",
      "status": 403,
      "location": null,
      "body_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "body_size": 87,
      "body_truncated": false,
      "context_phase": "body",
      "context_status": 404,
      "context_location": null,
      "context_body_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "context_body_size": 87,
      "context_body_truncated": false,
      "control_phase": "body",
      "control_status": 404,
      "control_location": null,
      "control_body_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "control_body_size": 87,
      "control_body_truncated": false,
      "confirmation_body_sha256": null,
      "tls_verified": true,
      "distinct_signals": ["status"],
      "reflection_normalized": false
    }
  ]
}
```

</details>

The `context_*` fields contain the literal-IP response, while `control_*` contains the stable unknown-host response. A distinct candidate must differ from both. `confirmation_body_sha256` is present only when a repeated response confirmed a body-only difference. These fields let a reviewer verify the recorded `distinct_signals` without retaining every synthetic control request. The source list is empty because virtual host discovery is an action, not a passive source.

SQLite uses the same shape without inventing another evidence concept: `results` holds one `hostname` row, `result_origins` links it to the `vhost` execution, and that result's details hold the endpoint observation array. JSONL export and API run details expose the array as native JSON. `vhost` is an action name, not a result kind.

JSON and XML compatibility reports contain virtual host name lists but not endpoint or response evidence. Use JSONL or `GET /api/v1/runs/{run_id}` when automation needs the structured observations.

## Troubleshooting

### The run says `no-candidates`

Select a source that returns hostnames or add an authorized name with `--vhost-candidate`. Check the exact target boundary if the run targets a hostname such as `www.example.com`.

### The run says `no-endpoints`

Select sources that can return IP addresses, enable a DNS action that contributes literal IP evidence, or supply `--vhost-endpoint`.

### The run says `request-limit`

The cap was too small for every endpoint, candidate shape, and confirmation request. Narrow the source set or candidate list before raising the cap. The terminal summary shows attempted endpoints as `attempted/total`.

### A candidate is missing from the results

Only confirmed `distinct` observations are retained. A candidate may have matched the default response, produced unstable controls, failed during transport, returned a truncated body, or failed a body-only confirmation.

### HTTPS results are indeterminate

Certificate verification or TLS negotiation may have failed before the server returned HTTP evidence. Check whether the certificate is valid for the candidate SNI. If the assessment permits unverified TLS, rerun the bounded test with `--vhost-insecure` and keep the recorded verification state with the result.

## Related pages

- [Responsible Use and Scope](Responsible-Use-and-Scope)
- [Operator Workflows](Operator-Workflows)
- [Results and Local Data](Results-and-Local-Data)
- [REST API](Rest-API)
- [Troubleshooting](Troubleshooting)
