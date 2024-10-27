FROM python:3.13-slim-bookworm
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
RUN apt update && apt install -y pipx git curl gcc && rm -rf /var/lib/apt/lists/*
RUN pipx install --python python3.13 git+https://github.com/laramies/theHarvester.git
RUN pipx ensurepath
ENTRYPOINT ["/root/.local/bin/restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
