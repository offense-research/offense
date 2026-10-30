FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global pnpm@10.32.1 --ignore-scripts --no-audit --no-fund
USER node
WORKDIR /work
