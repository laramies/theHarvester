FROM debian:trixie-slim

LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"

RUN useradd -m -u 1000 -s /bin/bash theharvester

# Install dependencies for building Python from source
RUN apt update && apt dist-upgrade -qqy && apt install -y \
    curl \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libffi-dev \
    liblzma-dev \
    python3-dev \
    git \
    gcc \
    vim \
    && apt clean && apt autoremove -qqy && rm -rf /var/lib/apt/lists/*

# Install Python 3.13.7 from source
RUN curl -fsSL https://www.python.org/ftp/python/3.13.7/Python-3.13.7.tgz -o Python-3.13.7.tgz \
    && tar -xvf Python-3.13.7.tgz \
    && cd Python-3.13.7 \
    && ./configure --enable-optimizations \
    && make -j 4 \
    && make altinstall \
    && cd / && rm -rf /Python-3.13.7 /Python-3.13.7.tgz

# Install uv
RUN curl -fsSL https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh

# Set workdir and copy project files
WORKDIR /app
COPY . /app

# Ensure files are owned by theharvester user (for uv cache/venv writes)
RUN chown -R theharvester:theharvester /app

# Use non-root user
USER theharvester

# Configure uv to use the freshly installed python
ENV UV_PYTHON=python3.13
# Ensure uv bin shims are on PATH for the user (uv places venv bins in .venv by default)
ENV PATH=/app/.venv/bin:$PATH

# Create and sync environment using uv
# Installs dependencies from pyproject.toml
RUN uv venv --python $UV_PYTHON && uv sync

# Expose port if the service listens on 80
EXPOSE 80

# Run the application as theharvester user
ENTRYPOINT ["python", "restfulHarvest.py", "-H", "0.0.0.0", "-p", "80"]
