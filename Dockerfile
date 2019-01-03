FROM python:2-alpine
RUN mkdir /app
RUN pip install requests beautifulsoup4 texttable
WORKDIR /app
COPY . /app
RUN chmod +x *.py
 ENTRYPOINT ["/app/theHarvester.py"]
