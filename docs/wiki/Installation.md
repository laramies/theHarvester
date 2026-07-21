# Installation

theHarvester requires Python 3.12 or newer. Choose one installation lane and finish with its verification step.

## Kali Linux package

Kali packages theHarvester directly:

```bash
sudo apt update
sudo apt install theharvester
theHarvester -h
```

If the installed command or available sources differ from the repository, update Kali first and check the packaged version. Package releases can lag behind the current `master` or `dev` branch.

## Source installation with uv

Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/), clone the repository, and install the locked runtime dependencies:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
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

The supported console commands are `theHarvester` and `restfulHarvest`. There is no root `theHarvester.py` launcher.

### Screenshot support

The screenshot option requires a Playwright-compatible Chromium browser:

```bash
uv run playwright install chromium
```

On Linux, Playwright may report missing system libraries. Follow the host-specific dependency instructions printed by Playwright, then rerun the browser installation.

## Docker Compose API service

The Docker image starts `restfulHarvest`; it does not open an interactive theHarvester CLI:

```bash
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
docker compose up --build
```

Open [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs) after the service starts.

The supplied Compose mapping publishes port `5000` on every host interface. For a local-only service, change it to:

```yaml
ports:
  - "127.0.0.1:5000:80"
```

Do not expose the service directly to an untrusted network. Core query routes are not authenticated.

## Next step

Continue with the [Quick Start](Quick-Start). Configure provider credentials only when needed; see [Configuration and API Keys](Configuration-and-API-Keys).
