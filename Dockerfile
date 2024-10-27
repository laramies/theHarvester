FROM python:3.12-slim-bookworm
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
RUN apt update && apt install -y pipx git && rm -rf /var/lib/apt/lists/*
RUN pipx install --python python3.12 git+https://github.com/laramies/theHarvester.git
RUN pipx ensurepath
ENTRYPOINT ["/root/.local/bin/restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
