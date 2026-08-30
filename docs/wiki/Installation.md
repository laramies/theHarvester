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

### Offline HarvestView assets

HarvestView bundles its pinned Tabulator 6.5.2 JavaScript, default theme, and upstream license. Run Desk and Schedules load those files from the same local application, so ordinary source, wheel, and container installations need no external browser asset requests.

### Browser support

The screenshot option requires a Playwright-compatible Chromium browser. Baidu uses it when available and otherwise falls back to HTTP:

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

The supplied configuration publishes container port `8000` only on host `127.0.0.1:5000`, runs as an unprivileged user with a read-only root filesystem, and stores run records in the `theharvester-data` volume. The image includes Chromium for optional screenshot capture and the complete project license at `/usr/share/licenses/theharvester/LICENSE`.

```bash
docker compose logs -f theharvester.svc.local
docker compose down
```

Every `/api/v1/*` route is authenticated. Do not change the loopback port mapping or expose the service directly to an untrusted network without adding TLS and network access controls.

## Next step

Continue with the [Quick Start](Quick-Start). Configure provider credentials only when needed; see [Configuration and API Keys](Configuration-and-API-Keys).
