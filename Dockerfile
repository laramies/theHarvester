FROM python:3.14-slim-trixie

LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"

RUN useradd -m -u 1000 -s /bin/bash theharvester

RUN apt-get update && apt-get upgrade -yqq && apt-get clean && \
    rm -rf /var/lib/apt/lists/*
# Set workdir and copy project files
WORKDIR /app
COPY . /app

# Create and sync environment using uv
# Compile bytecode for faster startup and install to system site-packages
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    UV_PROJECT_ENVIRONMENT=/usr/local uv sync --locked --no-dev --no-cache --compile-bytecode

# Use non-root user
USER theharvester

# Expose port if the service listens on 80
EXPOSE 80

# Run the application as theharvester user
ENTRYPOINT ["restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
