FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @earendil-works/pi-coding-agent@1.3.0 \
    && npm cache clean --force \
    && useradd --uid 10001 --create-home agent
COPY agent/cloudflare-run.mjs agent/npm-projects.mjs agent/verification-gate.mjs agent/verify-patch.mjs agent/test-observer.mjs agent/verification-prompt.mjs agent/verification-self-test.mjs /opt/purple/
USER agent
WORKDIR /work/repo
ENV HOME=/home/agent PI_OFFLINE=1 PI_TELEMETRY=0
ENTRYPOINT ["pi"]
