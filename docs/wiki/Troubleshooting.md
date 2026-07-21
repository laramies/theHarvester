# Troubleshooting

Start with the smallest failing command and one source. Provider availability, authentication, quotas, and response formats can change independently of theHarvester.

## Confirm the installation

```bash
uv run theHarvester -h
uv run python --version
```

For a packaged installation:

```bash
theHarvester -h
python3 --version
```

theHarvester requires Python 3.12 or newer.

## Configuration file messages

On first use, messages saying that `api-keys.yaml` or `proxies.yaml` was created under `~/.theHarvester/` are expected.

If the wrong file is read, check the search order:

1. `~/.theHarvester/`
2. `/etc/theHarvester/`
3. `/usr/local/etc/theHarvester/`

The first existing file wins.

## Missing API key

Check the [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources). Configure credentials for that provider or choose a keyless source. `-q` suppresses missing-key notices; it does not make keyed providers work without credentials.

## Provider errors, timeouts, or empty results

Rerun one source with a small limit:

```bash
uv run theHarvester -d example.com -b source-name -l 10
```

Then check:

- provider status and current API documentation;
- credential validity and subscription access;
- provider rate limits or temporary blocking of shared CI/cloud addresses;
- whether the source legitimately has no results for the target.

Do not post credentials, private targets, account details, or raw provider responses in a public issue.

## DNS resolution

`-r` accepts no value, a resolver IP, comma-separated resolver IPs, or a file with one IP per line:

```bash
AUTHORIZED_DOMAIN='replace-with-a-domain-you-control'
uv run theHarvester -d "$AUTHORIZED_DOMAIN" -b crtsh -r resolvers.txt
```

If theHarvester reports invalid resolvers, remove hostnames, comments, blank values, or `host:port` entries; the resolver list accepts IP addresses only. Check local firewall and DNS policy before substituting public resolvers.

## Screenshots and Chromium

Install the browser used by Playwright:

```bash
uv run playwright install chromium
```

If Chromium reports missing Linux libraries, install the host dependencies recommended by Playwright. Confirm the target is authorized before retrying; screenshots open discovered web services directly.

## REST API

Start with:

```bash
uv run restfulHarvest --log-level debug
```

Then open [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs).

- `401` on `/additional/*`: the `X-API-Key` header is absent or does not match.
- `503` on `/additional/*`: `THEHARVESTER_API_KEY` was not configured before startup.
- `429`: the client exceeded the configured API rate limit.
- Core routes are intentionally not protected by that key; do not expose the service directly.

## Docker

```bash
docker compose ps
docker compose logs theharvester.svc.local
```

The container runs the REST API on container port `80`, published as host port `5000` by the supplied Compose file.

## File an actionable issue

Include:

- the smallest sanitized reproduction;
- expected and actual behavior;
- operating system, installation method, Python version, and theHarvester version or commit;
- the exact source and options used;
- only the output needed to diagnose the problem.

Use the repository [issue forms](https://github.com/laramies/theHarvester/issues/new/choose). Follow [SECURITY.md](https://github.com/laramies/theHarvester/blob/dev/SECURITY.md) for suspected vulnerabilities.
