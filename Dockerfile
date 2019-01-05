FROM python:3.6-alpine
RUN mkdir /app
RUN pip install requests beautifulsoup4 texttable plotly shodan
WORKDIR /app
COPY . /app
RUN chmod +x *.py
ENTRYPOINT ["/app/theHarvester.py"]
