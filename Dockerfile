FROM python:3.6-alpine3.7
RUN mkdir /app
RUN pip3 install requests beautifulsoup4 texttable plotly shodan
WORKDIR /app
COPY . /app
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]
