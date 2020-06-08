FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim

LABEL authors="NotoriousRebel, Jay (L1ghtning)"

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY ../../../../theHarvester ./
