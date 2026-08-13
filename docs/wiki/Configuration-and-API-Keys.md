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
    token: your-censys-personal-access-token
    organization_id: your-censys-organization-id

  github:
    key: your-github-token

  hibpverified:
    key: your-hibp-api-key

  routeviews:
    key: your-routeviews-api-key

  tomba:
    key: your-tomba-key
    secret: your-tomba-secret
```

Do not commit populated configuration files. Prefer provider credentials scoped to the minimum access the provider supports.

The [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) is the canonical source list. It shows whether each source requires a key, accepts an optional key, or has no key setting.

Provider pricing, quotas, and terms change frequently. Check the provider's current documentation for these details.

`censys.token` is a Censys Platform Personal Access Token. `organization_id` is optional; omit it to use the account's personal free wallet. The retired Search API ID and secret fields are not accepted.

`hibpverified` queries [HIBP's authenticated verified-domain endpoint](https://haveibeenpwned.com/API/v3#BreachedDomain). It is selected by its name, the `breaches` capability, and `all`. Without a configured HIBP API key it is skipped like other unavailable keyed sources. Live use requires a user-owned paid HIBP API key and a user-owned domain verified in that account. The keyless `haveibeenpwned` source continues to query only the public breach catalogue.

`routeviews.key` is optional. RouteViews provides authenticated API keys to verified PeeringDB users. `--routeviews` uses the authenticated endpoint and documented 10-request-per-second allowance when the key is configured; otherwise it uses guest access at one request per second. If RouteViews rejects a configured key, the action fails without retrying as a guest; remove the key to select guest access. RouteViews does not document this as a paid subscription.

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

## API protection

Every `/api/v1/*` route requires a server-side key:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run harvestview
```

API clients send the same value in the `X-API-Key` header. HarvestView receives a derived HttpOnly browser cookie when it is opened locally, so the key is never entered into or stored by the web app. Provider credentials remain in `api-keys.yaml` and cannot be supplied through an API request.
