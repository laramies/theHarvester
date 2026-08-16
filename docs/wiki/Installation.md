# Installation

theHarvester requires Python 3.14. The repository's `.python-version` lets `uv` select it automatically. Choose one installation lane and finish with its verification step. The README lists the [current distribution package versions](https://github.com/laramies/theHarvester#package-versions).

## Kali Linux package

Kali packages theHarvester directly:

```bash
sudo apt update
sudo apt install theharvester
theHarvester -h
```

If the installed command or available sources differ from the repository, update Kali first and check the packaged version. Distribution packages can lag behind the current stable release or `dev` branch.

## Source checkout

Clone the repository and install the locked runtime dependencies:

```bash
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
uv sync
uv run theHarvester -h
```

Contributors should install the development groups instead:

```bash
uv sync --all-groups
uv run pytest
```

The supported console commands are `theHarvester` and `harvestview`. There is no root `theHarvester.py` launcher.

### Self-host Tabulator

HarvestView loads Tabulator 6.5.2 from CDNjs by default. For an isolated deployment, download the same pinned files in a connected environment and copy them into `theHarvester/lib/api/static/harvestview/`:

| File | CDNjs source | SRI |
| --- | --- | --- |
| `tabulator.min.css` | `https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/css/tabulator.min.css` | `sha512-t8I/asqzdu/MRgVLxVanQ/c5bhUA1qZ/zA432a/3nUh0kkd7P8Qch35wQvTODivf9D6Xv3h7F8p7ezcUyBOQrQ==` |
| `tabulator.min.js` | `https://cdnjs.cloudflare.com/ajax/libs/tabulator-tables/6.5.2/js/tabulator.min.js` | `sha512-AF0YMSgc0Ui4IJPb4hJNSi16wFidZEQa6ZTCAeguF3h5glVnAPuz/JT2ai9ypKhsc9n6CEXBB+tMdxsv1q+rxg==` |

Then replace the two CDNjs tags in `theHarvester/lib/api/static/harvestview/index.html` with same-origin references:

```html
<link rel="stylesheet" href="/static/harvestview/tabulator.min.css?v=6.5.2">
<script src="/static/harvestview/tabulator.min.js?v=6.5.2"></script>
```

Remove the CDN-only `integrity`, `crossorigin`, and `referrerpolicy` attributes from those local tags. Rebuild the package or container after copying the assets.

### Screenshot support

The screenshot option requires a Playwright-compatible Chromium browser:

```bash
uv run playwright install chromium
```

On Linux, Playwright may report missing system libraries. Follow the host-specific dependency instructions printed by Playwright, then rerun the browser installation.

## Docker Compose HarvestView service

The Docker image starts `harvestview`; it does not open an interactive theHarvester CLI. Create the operator-key secret before the first start:

```bash
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
install -d -m 0700 .secrets
openssl rand -hex 32 > .secrets/operator-api-key
chmod 0444 .secrets/operator-api-key
docker compose up --build -d
docker compose ps
```

The `0700` directory protects the secret on the host, while the read-only `0444` file lets the unprivileged container process read its bind-mounted copy. Open [HarvestView](http://127.0.0.1:5000/) after the service starts. Swagger remains available at [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs).

The supplied configuration publishes container port `8000` only on host `127.0.0.1:5000`, runs as an unprivileged user with a read-only root filesystem, and stores run records in the `theharvester-data` volume. The image includes Chromium for optional screenshot capture.

```bash
docker compose logs -f theharvester.svc.local
docker compose down
```

Every `/api/v1/*` route is authenticated. Do not change the loopback port mapping or expose the service directly to an untrusted network without adding TLS and network access controls.

## Next step

Continue with the [Quick Start](Quick-Start). Configure provider credentials only when needed; see [Configuration and API Keys](Configuration-and-API-Keys).
