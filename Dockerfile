ARG PYTHON_IMAGE=python:3.14-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6
FROM ${PYTHON_IMAGE} AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY theHarvester ./theHarvester

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=from=ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded,source=/uv,target=/usr/local/bin/uv \
    uv sync --locked --no-dev --no-editable --reinstall-package theharvester

FROM ${PYTHON_IMAGE} AS runtime

LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
LABEL org.opencontainers.image.title="theHarvester" \
      org.opencontainers.image.description="theHarvester API and HarvestView web application" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/laramies/theHarvester"

ENV HOME=/var/lib/theharvester \
    PATH=/opt/venv/bin:$PATH \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THEHARVESTER_RUN_ARTIFACTS=/var/lib/theharvester/run-artifacts \
    THEHARVESTER_RUN_DB=/var/lib/theharvester/runs.sqlite

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

RUN groupadd --gid 10001 theharvester \
    && useradd --uid 10001 --gid 10001 --home-dir "$HOME" --shell /usr/sbin/nologin theharvester \
    && install -d -o 10001 -g 10001 -m 0700 "$HOME" "$THEHARVESTER_RUN_ARTIFACTS" \
    && playwright install --with-deps --only-shell chromium \
    && chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH" \
    && rm -rf /var/lib/apt/lists/*

USER theharvester

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "from urllib.request import Request, urlopen; from theHarvester.lib.api.auth import _configured_api_key; key = _configured_api_key(); assert key; urlopen(Request('http://127.0.0.1:8000/api/v1/runs', headers={'X-API-Key': key}), timeout=3).close()"]

ENTRYPOINT ["restfulHarvest"]
CMD ["-H", "0.0.0.0", "-p", "8000"]
