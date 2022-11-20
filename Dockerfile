FROM python:3-alpine 
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1 (alpine @viardant)"
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apk update && apk upgrade --available && apk add git libffi-dev gcc python3-dev libxml2-dev libxslt-dev && python3 -m pip install --upgrade pip

RUN python3 --version && pip3 install --no-cache-dir -r requirements.txt && chmod +x ./*.py
ENTRYPOINT ["/app/theHarvester.py"]
ENTRYPOINT ["/app/restfulHarvest.py", "-H", "0.0.0.0", "-p", "80"]
EXPOSE 80
