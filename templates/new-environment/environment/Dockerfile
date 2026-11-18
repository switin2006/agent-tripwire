FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

RUN pip install --no-cache-dir pytest==8.3.3

COPY . /app

ENV PYTHONPATH=/app
