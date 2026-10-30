FROM node:24-bookworm-slim AS kubernetes-tools
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/purple/licenses/pluto /opt/purple/licenses/kubeconform /opt/purple/node_modules/yaml \
    && curl -fsSL https://github.com/FairwindsOps/pluto/releases/download/v5.24.4/pluto_5.24.4_linux_amd64.tar.gz -o /tmp/pluto.tgz \
    && echo '1e5077ce1016fb0bb8ce0103c12b7ca8666eb3959d787ecfc95d9b8acd507147  /tmp/pluto.tgz' | sha256sum -c - \
    && tar -xzf /tmp/pluto.tgz -C /usr/local/bin pluto \
    && tar -xzf /tmp/pluto.tgz -C /opt/purple/licenses/pluto LICENSE \
    && curl -fsSL https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz -o /tmp/kubeconform.tgz \
    && echo '9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883  /tmp/kubeconform.tgz' | sha256sum -c - \
    && tar -xzf /tmp/kubeconform.tgz -C /usr/local/bin kubeconform \
    && tar -xzf /tmp/kubeconform.tgz -C /opt/purple/licenses/kubeconform LICENSE \
    && curl -fsSL https://registry.npmjs.org/yaml/-/yaml-2.9.1.tgz -o /tmp/yaml.tgz \
    && echo '4ef6c54cf559b8a207b7b518378230805a1c84af239b14960e8c67c7d59de5d3  /tmp/yaml.tgz' | sha256sum -c - \
    && tar -xzf /tmp/yaml.tgz -C /opt/purple/node_modules/yaml --strip-components=1 \
    && rm /tmp/pluto.tgz /tmp/kubeconform.tgz /tmp/yaml.tgz
COPY shared/kubernetes-scan.js /opt/purple/shared/kubernetes-scan.js
# Fetch only reviewed schema releases at build time. Keep their upstream license.
RUN printf '{"type":"module"}\n' >/opt/purple/package.json \
    && git init /opt/purple/kubernetes-schemas \
    && git -C /opt/purple/kubernetes-schemas remote add origin https://github.com/yannh/kubernetes-json-schema.git \
    && git -C /opt/purple/kubernetes-schemas sparse-checkout init --cone \
    && node --input-type=module -e "import { KUBERNETES_VERSIONS } from '/opt/purple/shared/kubernetes-scan.js'; console.log(KUBERNETES_VERSIONS.map(v=>'v'+v+'-standalone-strict').join('\n'))" | git -C /opt/purple/kubernetes-schemas sparse-checkout set --stdin \
    && git -C /opt/purple/kubernetes-schemas fetch --depth 1 --filter=blob:none origin 89a35a5e9a1412a692a2603d79c3786f602238a4 \
    && git -C /opt/purple/kubernetes-schemas checkout --detach FETCH_HEAD \
    && rm -rf /opt/purple/kubernetes-schemas/.git \
    && chmod -R a-w /opt/purple/kubernetes-schemas

FROM node:24-bookworm-slim
COPY --from=kubernetes-tools /usr/local/bin/pluto /usr/local/bin/kubeconform /usr/local/bin/
COPY --from=kubernetes-tools /opt/purple/ /opt/purple/
COPY agent/kubernetes-scan.mjs /opt/purple/agent/kubernetes-scan.mjs
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/opengrep/opengrep/releases/download/v1.32.0/opengrep_manylinux_x86 -o /usr/local/bin/opengrep \
    && echo '7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75  /usr/local/bin/opengrep' | sha256sum -c - \
    && chmod +x /usr/local/bin/opengrep
RUN curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz -o /tmp/trivy.tgz \
    && echo 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0  /tmp/trivy.tgz' | sha256sum -c - \
    && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy && rm /tmp/trivy.tgz
RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz -o /tmp/gitleaks.tgz \
    && echo '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  /tmp/gitleaks.tgz' | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tgz
COPY agent/spectral/package*.json /opt/purple/spectral/
RUN npm ci --prefix /opt/purple/spectral --omit=dev --ignore-scripts --no-audit --no-fund
COPY agent/spectral-owasp.yaml /opt/purple/spectral/.spectral.yaml
COPY agent/guarddog-constraints.txt /opt/purple/guarddog-constraints.txt
RUN python3 -m venv /opt/purple/guarddog \
    && /opt/purple/guarddog/bin/pip install --no-cache-dir -c /opt/purple/guarddog-constraints.txt guarddog==3.2.0 \
    && mkdir -p /opt/purple/guarddog-cache
COPY agent/scan-additional-adapters.mjs agent/guarddog-cache-check.mjs /opt/purple/agent/
# Refresh this layer on every scanner image build, without enabling runtime egress.
ARG SCAN_DB_BUILD=development
RUN echo "$SCAN_DB_BUILD" >/opt/db-build \
    && cp /opt/purple/guarddog/lib/python3.11/site-packages/guarddog/analyzer/metadata/resources/top_*_packages.json /opt/purple/guarddog-cache/ \
    && GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/opt/purple/guarddog-cache /opt/purple/guarddog/bin/guarddog --version >/dev/null \
    && printf '{"type":"module"}\n' >/opt/purple/package.json \
    && node /opt/purple/agent/guarddog-cache-check.mjs /opt/purple/guarddog-cache \
    && trivy image --download-db-only --cache-dir /opt/trivy-cache \
    && mkdir -p /tmp/purple-checks-warm \
    && printf 'FROM alpine:3.21\n' >/tmp/purple-checks-warm/Dockerfile \
    && trivy config --cache-dir /opt/trivy-cache --format json --output /tmp/purple-checks-warm/report.json /tmp/purple-checks-warm \
    && rm -rf /tmp/purple-checks-warm \
    && useradd --uid 10002 --create-home scanner \
    && chown -R scanner:scanner /opt/trivy-cache \
    && chmod -R a-w /opt/purple/guarddog-cache
# ZAP 2.17.0 is used only for the offline, passive HAR import job.
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz -o /tmp/zap.tgz \
    && echo 'efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a  /tmp/zap.tgz' | sha256sum -c - \
    && mkdir -p /zap && tar -xzf /tmp/zap.tgz -C /zap --strip-components=1 \
    && rm /tmp/zap.tgz
COPY agent/zap-baseline-report.mjs agent/zap-passive-har.mjs /opt/purple/agent/
COPY server/web-scan-target.js /opt/purple/server/
RUN curl -fsSL https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && echo '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /usr/local/bin/cosign' | sha256sum -c - \
    && chmod +x /usr/local/bin/cosign
# Refresh Sigstore's authenticated trust root when SCAN_DB_BUILD changes.
RUN echo "$SCAN_DB_BUILD" >/dev/null \
    && mkdir -p /tmp/purple-cosign-home /opt/purple/sigstore \
    && HOME=/tmp/purple-cosign-home cosign initialize \
    && root_file="$(find /tmp/purple-cosign-home -type f -name trusted_root.json -print -quit)" \
    && test -n "$root_file" && cp "$root_file" /opt/purple/sigstore/trusted_root.json \
    && test -s /opt/purple/sigstore/trusted_root.json \
    && rm -rf /tmp/purple-cosign-home
COPY agent/cosign-image.mjs /opt/purple/agent/
RUN curl -fsSL https://github.com/zizmorcore/zizmor/releases/download/v1.31.1/zizmor-x86_64-unknown-linux-gnu.tar.gz -o /tmp/zizmor.tgz \
    && echo 'd185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99  /tmp/zizmor.tgz' | sha256sum -c - \
    && tar -xzf /tmp/zizmor.tgz -C /usr/local/bin zizmor && rm /tmp/zizmor.tgz
COPY agent/scan-runner.mjs agent/scan-findings.mjs agent/zizmor.mjs agent/image-scan.mjs agent/gitleaks-history.mjs agent/scan-additional-adapters.mjs agent/scan-rules.yml /opt/purple/agent/
COPY server/scan-input.js /opt/purple/server/scan-input.js
RUN cp /opt/purple/agent/scan-rules.yml /opt/purple/scan-rules.yml \
    && printf '{"type":"module"}\n' >/opt/purple/package.json \
    && printf '{}\n' >/opt/purple/trivy.yaml && touch /opt/purple/empty.ignore \
    && printf '[extend]\nuseDefault = true\n' >/opt/purple/gitleaks.toml
# These independent layers leave the existing scanners and their caches intact.
RUN curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner \
    && echo '160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b  /usr/local/bin/osv-scanner' | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner
COPY agent/semgrep-constraints.txt /opt/purple/semgrep-constraints.txt
RUN python3 -m venv /opt/purple/semgrep \
    && /opt/purple/semgrep/bin/pip install --no-cache-dir -c /opt/purple/semgrep-constraints.txt \
    'https://files.pythonhosted.org/packages/92/11/1bfd4abd746509ad90726397dd8e0d9e1150378ac329821757ea56d4ea4c/semgrep-1.182.1-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_x86_64.whl#sha256=bba25e5a38db5061d725c0920699ecee3e8137026427e722a271bd9bb8d25a40'
COPY agent/osv-scanner.mjs agent/semgrep.mjs agent/scan-adapter-files.mjs agent/semgrep-rules.yml agent/osv-cache-manifest.mjs /opt/purple/agent/
RUN mkdir /tmp/purple-semgrep-check \
    && printf 'const safe = 1;\n' >/tmp/purple-semgrep-check/safe.js \
    && printf 'safe = 1\n' >/tmp/purple-semgrep-check/safe.py \
    && SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 /opt/purple/semgrep/bin/semgrep scan \
    --oss-only --json --quiet --metrics=off --disable-version-check --config /opt/purple/agent/semgrep-rules.yml \
    /tmp/purple-semgrep-check/safe.js /tmp/purple-semgrep-check/safe.py >/tmp/purple-semgrep-check/report.json \
    && node -e "const r=JSON.parse(require('fs').readFileSync('/tmp/purple-semgrep-check/report.json'));if(!Array.isArray(r.results)||r.errors?.length)throw Error('Invalid operator rules')" \
    && rm -rf /tmp/purple-semgrep-check
# Refresh the public data at image-build time; runtime internet remains disabled.
# OSV 2.7's scalibr matcher uses osv-scalibr/{ecosystem}/all.zip, not the V1 cache layout.
ARG OSV_DB_BUILD=development
RUN echo "$OSV_DB_BUILD" >/opt/osv-db-build \
    && mkdir -p /opt/osv-cache/osv-scalibr/npm /opt/osv-cache/osv-scalibr/PyPI \
    && curl -fsSL --max-time 300 --max-filesize 536870912 https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip -o /opt/osv-cache/osv-scalibr/npm/all.zip \
    && curl -fsSL --max-time 300 --max-filesize 536870912 https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip -o /opt/osv-cache/osv-scalibr/PyPI/all.zip \
    && python3 -c "import zipfile; assert all(zipfile.ZipFile('/opt/osv-cache/osv-scalibr/'+name+'/all.zip').testzip() is None for name in ['npm','PyPI'])" \
    && node /opt/purple/agent/osv-cache-manifest.mjs /opt/osv-cache \
    && chmod -R a-w /opt/osv-cache
USER scanner
WORKDIR /tmp
ENTRYPOINT ["node", "/opt/purple/agent/scan-runner.mjs"]
