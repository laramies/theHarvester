FROM kalilinux/kali-linux-docker
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apt-get -qq update
RUN apt-get install -yqq pipenv
RUN pipenv install
RUN chmod +x *.py
ENTRYPOINT ["pipenv run /app/theHarvester.py"]
