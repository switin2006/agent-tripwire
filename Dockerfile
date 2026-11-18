FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    git \
    curl \
    ca-certificates \
    tmux \
    && rm -rf /var/lib/apt/lists/*

# Install docker compose v2 plugin and standalone binary
RUN mkdir -p /usr/local/lib/docker/cli-plugins /root/.docker/cli-plugins && \
    curl -SL https://github.com/docker/compose/releases/download/v2.33.1/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose && \
    ln -s /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose && \
    ln -s /usr/local/lib/docker/cli-plugins/docker-compose /root/.docker/cli-plugins/docker-compose

WORKDIR /app
COPY harbor /app/harbor

# Install harbor
RUN uv pip install --system -e /app/harbor

WORKDIR /workspace
