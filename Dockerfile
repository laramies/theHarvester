FROM alpine:3
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1 (alpine @viardant)"
WORKDIR /app
COPY requirements.txt requirements.txt
COPY requirements requirements
RUN apk update && apk upgrade --available && apk add --no-cache musl-dev git libffi-dev gcc python3-dev py3-pip libxml2-dev libxslt-dev && python3 -m pip install --upgrade pip
RUN python3 --version && pip3 install --no-cache-dir -r requirements.txt
COPY . /app
RUN pip3 install --no-cache-dir .
ENTRYPOINT ["restfulHarvest", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
