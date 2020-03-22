FROM python:alpine3.11
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN apk add --update build-base libffi-dev libxml2-dev libxslt-dev
RUN pip3 install -r requirements.txt
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]