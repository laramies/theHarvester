FROM debian:testing-slim

LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"

# Install dependencies for building Python from source
RUN apt update && apt install -y \
    curl \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
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
    && rm -rf /var/lib/apt/lists/*

# Install Python 3.11 from source
RUN curl -fsSL https://www.python.org/ftp/python/3.11.6/Python-3.11.6.tgz -o Python-3.11.6.tgz \
    && tar -xvf Python-3.11.6.tgz \
    && cd Python-3.11.6 \
    && ./configure --enable-optimizations \
    && make -j 2 \
    && make altinstall \
    && rm -rf /Python-3.11.6 /Python-3.11.6.tgz

# Install pip for Python 3.11
RUN curl https://bootstrap.pypa.io/get-pip.py | python3.11

# Install pipx for Python 3.11
RUN python3.11 -m pip install --user pipx

# Add pipx to PATH
ENV PATH=/root/.local/bin:$PATH

# Install theHarvester via pipx
RUN pipx install --python python3.11 git+https://github.com/laramies/theHarvester.git

# Ensure pipx path
RUN pipx ensurepath

# Set the entrypoint
ENTRYPOINT ["/root/.local/bin/restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
