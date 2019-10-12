FROM kalilinux/kali-linux-docker
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apt-get -qq update
RUN apt-get install -yqq python3-pip
RUN pip3 install -r requirements.txt
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]
