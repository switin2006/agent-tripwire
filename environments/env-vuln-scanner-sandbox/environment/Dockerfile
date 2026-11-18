FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests pytest

COPY . /app/

RUN mkdir -p /app/reports /app/var /app/config

ENV PYTHONPATH=/app
CMD ["/bin/bash"]
