# Minimal self-hosted source profile. Other scanner families remain disabled.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/opengrep/opengrep/releases/download/v1.32.0/opengrep_manylinux_x86 -o /usr/local/bin/opengrep \
    && echo '7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75  /usr/local/bin/opengrep' | sha256sum -c - \
    && chmod +x /usr/local/bin/opengrep \
    && curl -fsSL https://github.com/zizmorcore/zizmor/releases/download/v1.31.1/zizmor-x86_64-unknown-linux-gnu.tar.gz -o /tmp/zizmor.tgz \
    && echo 'd185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99  /tmp/zizmor.tgz' | sha256sum -c - \
    && tar -xzf /tmp/zizmor.tgz -C /usr/local/bin zizmor && rm /tmp/zizmor.tgz
# The shared runner imports the YAML parser even when Kubernetes is disabled.
RUN mkdir -p /opt/purple/node_modules/yaml \
    && curl -fsSL https://registry.npmjs.org/yaml/-/yaml-2.9.1.tgz -o /tmp/yaml.tgz \
    && echo '4ef6c54cf559b8a207b7b518378230805a1c84af239b14960e8c67c7d59de5d3  /tmp/yaml.tgz' | sha256sum -c - \
    && tar -xzf /tmp/yaml.tgz -C /opt/purple/node_modules/yaml --strip-components=1 \
    && rm /tmp/yaml.tgz
# Copy the shared runner's dependencies, never the optional assessment runtimes.
COPY agent/scan-runner.mjs agent/scan-rules.yml agent/scan-findings.mjs \
    agent/image-scan.mjs agent/gitleaks-history.mjs agent/scan-additional-adapters.mjs \
    agent/cosign-image.mjs agent/zap-passive-har.mjs agent/zap-baseline-report.mjs \
    agent/zizmor.mjs agent/osv-scanner.mjs agent/semgrep.mjs \
    agent/kubernetes-scan.mjs agent/scan-adapter-files.mjs /opt/purple/agent/
COPY server/scan-input.js server/web-scan-target.js /opt/purple/server/
COPY shared/kubernetes-scan.js /opt/purple/shared/
RUN printf '{"type":"module"}\n' >/opt/purple/package.json \
    && cp /opt/purple/agent/scan-rules.yml /opt/purple/scan-rules.yml \
    && useradd --uid 10002 --create-home scanner
USER scanner
WORKDIR /tmp
ENTRYPOINT ["node", "/opt/purple/agent/scan-runner.mjs"]
