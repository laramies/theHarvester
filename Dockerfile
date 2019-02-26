FROM python:3.6-alpine3.7
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN pip3 install -r requirements.txt
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]
