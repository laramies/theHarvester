# Configuration and API keys

theHarvester reads `api-keys.yaml` and `proxies.yaml` from the first matching directory:

1. `~/.theHarvester/`
2. `/etc/theHarvester/`
3. `/usr/local/etc/theHarvester/`

If no file exists, theHarvester creates the default template under `~/.theHarvester/`.

## Provider credentials

Run theHarvester once to create the user configuration, then edit:

```bash
vi ~/.theHarvester/api-keys.yaml
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

  xquik:
    key: your-xquik-api-key
```

Do not commit populated configuration files. Prefer provider credentials scoped to the minimum access the provider supports.

The [README source matrix](https://github.com/laramies/theHarvester/blob/dev/README.md#discovery-sources) lists each source's result routes, activity class, and credential requirement. Every source name links to its provider's site or documentation for current plans, quotas, and terms. The executable source catalog is the authoritative inventory.

### Provider notes

| Provider | Configuration and behavior |
| --- | --- |
| Censys | `censys.token` is a Censys Platform Personal Access Token. Set `organization_id` to search through an entitled organization. The source uses the Global Search API, which Free accounts cannot access because they are limited to asset lookups. Search API ID and secret fields are not accepted. |
| HIBP verified domains | `hibpverified` queries [HIBP's authenticated verified-domain endpoint](https://haveibeenpwned.com/API/v3#BreachedDomain). Select it by name, through the `breaches` capability, or with `all`. Without a configured key, it is skipped like other unavailable keyed sources. Live use requires a user-owned paid HIBP API key and a domain verified in that account. The keyless `haveibeenpwned` source queries only the public breach catalogue. |
| RouteViews | `routeviews.key` is optional. A configured key selects the authenticated endpoint for PeeringDB-verified users and its documented 10-request-per-second allowance. Without a key, the action uses guest access at one request per second. If RouteViews rejects a configured key, the action fails instead of retrying as a guest. Remove the key to select guest access. RouteViews does not document this as a paid subscription. |
| Xquik | `xquik.key` authenticates the [Search Tweets API](https://docs.xquik.com/api-reference/x/search-tweets). The source returns canonical public X post URLs that match the authorized target. It does not retain post bodies or account data. |

## Proxies

Edit `~/.theHarvester/proxies.yaml` using `host:port` entries:

```yaml
http:
  - 127.0.0.1:8080
socks5:
  - 127.0.0.1:9050
```

Enable configured proxies with `-p`:

Network activity: provider-facing passive lookup through a configured proxy.

```bash
uv run theHarvester -d example.com -b crtsh -p
```

A proxy does not make an assessment anonymous and does not change the authorization boundary. When proxy mode is
enabled, every supported discovery source and action fails closed with `proxy-unavailable` instead of making a direct
request if no configured proxy is available.

## API protection

Every `/api/v1/*` route requires a server-side key:

```bash
export THEHARVESTER_API_KEY='replace-with-a-long-random-value'
uv run harvestview
```

API clients send the same value in the `X-API-Key` header. HarvestView receives a derived HttpOnly browser cookie when it is opened locally, so the key is never entered into or stored by the web app. Provider credentials remain in `api-keys.yaml` and cannot be supplied through an API request.
