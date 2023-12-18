FROM alpine:3
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
RUN apk update && apk upgrade --available && apk add --no-cache musl-dev git libffi-dev gcc python3-dev pipx libxml2-dev libxslt-dev bash
RUN mkdir -p "~/.local/share/theHarvester/static/"
RUN pipx install git+https://github.com/laramies/theHarvester.git
RUN pipx ensurepath
ENTRYPOINT ["/root/.local/bin/restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
