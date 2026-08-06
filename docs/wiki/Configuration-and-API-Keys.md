# Configuration and API keys

theHarvester reads `api-keys.yaml` and `proxies.yaml` from the first matching directory:

1. `~/.theHarvester/`
2. `/etc/theHarvester/`
3. `/usr/local/etc/theHarvester/`

If no file exists, theHarvester creates the default template under `~/.theHarvester/`.

## Provider credentials

Run theHarvester once to create the user configuration, then edit:

```bash
${EDITOR:-vi} ~/.theHarvester/api-keys.yaml
chmod 600 ~/.theHarvester/api-keys.yaml
```

Keep the complete generated template and fill only the providers you intend to use. Some providers require more than one field:

```yaml
apikeys:
  censys:
    id: your-censys-id
    secret: your-censys-secret

  github:
    key: your-github-token

  hibpverified:
    key: your-hibp-api-key

  tomba:
    key: your-tomba-key
    secret: your-tomba-secret
```

Do not commit populated configuration files. Prefer provider credentials scoped to the minimum access the provider supports.

The [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) is the canonical source list. It shows whether each source requires a key, accepts an optional key, or has no key setting.

Provider pricing, quotas, and terms change frequently. Check the provider's current documentation for these details.

`hibpverified` queries [HIBP's authenticated verified-domain endpoint](https://haveibeenpwned.com/API/v3#BreachedDomain) only when explicitly named, either alone or in a combination such as `breaches,hibpverified`. Capability selectors and `all` exclude it. Live use requires a user-owned paid HIBP API key and a user-owned domain verified in that account. REST queries selecting it also require the operator `X-API-Key`; the keyless `haveibeenpwned` source continues to query only the public breach catalogue.

## Proxies

Edit `~/.theHarvester/proxies.yaml` using `host:port` entries:

```yaml
http:
  - 127.0.0.1:8080
socks5:
  - 127.0.0.1:9050
```

Enable configured proxies with `-p`:

```bash
uv run theHarvester -d example.com -b crtsh -p
```

A proxy does not make an assessment anonymous and does not change the authorization boundary.

## REST API protection

The `/additional/*` routes require a server-side key:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run restfulHarvest
```

Clients send the same value in the `X-API-Key` header. This key protects only `/additional/*`; the core query routes remain unauthenticated.
