FROM ubuntu:impish
LABEL maintainer="@jay_townsend1 & @NotoriousRebel1"
RUN mkdir /app
WORKDIR /app
COPY . /app
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt dist-upgrade -qy && apt install -qy python3 python3-pip libffi-dev libxml2-dev libxslt1-dev && /usr/bin/python3 -m pip install --upgrade pip && apt autoremove -qy
RUN /usr/bin/python3 --version && pip3 install --no-cache-dir -r requirements.txt && chmod +x ./*.py
ENTRYPOINT ["/app/theHarvester.py"]
ENTRYPOINT ["/app/restfulHarvest.py -H 0.0.0.0 -p 80"]
EXPOSE 80
