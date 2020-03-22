FROM kalilinux/kali-rolling
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apt-get -qq update
RUN apt-get install -yqq theharvester
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]
