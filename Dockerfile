FROM debian:testing-slim
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
RUN apt update && apt dist-upgrade -y && apt install -y pipx git curl gcc && rm -rf /var/lib/apt/lists/* && apt clean && apt autoremove -y
RUN pipx install --python python3.12 git+https://github.com/laramies/theHarvester.git
RUN pipx ensurepath
ENTRYPOINT ["/root/.local/bin/restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
