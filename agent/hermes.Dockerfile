# Dedicated dependency-fix runtime; the existing Pi image remains available.
FROM node:24-bookworm-slim AS node_runtime
FROM python:3.14-slim-bookworm
ARG HERMES_REVISION=c1600692ec30985e7c7e736b78b674283f94b8bb
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node_runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && npm install --global pnpm@10.32.1 && npm cache clean --force \
    && python -m pip install --no-cache-dir uv==0.10.10
RUN git init /opt/hermes && git -C /opt/hermes remote add origin https://github.com/NousResearch/hermes-agent.git \
    && git -C /opt/hermes fetch --depth=1 origin "${HERMES_REVISION}" \
    && git -C /opt/hermes checkout --detach FETCH_HEAD \
    && test "$(git -C /opt/hermes rev-parse HEAD)" = "${HERMES_REVISION}" \
    && printf '%s\n' "${HERMES_REVISION}" > /opt/hermes/.purple-revision \
    && cd /opt/hermes && uv sync --frozen --no-dev --no-install-project --python /usr/local/bin/python3.14 \
    && rm -rf /root/.cache/uv /root/.cache/pip /opt/hermes/.git \
    && useradd --uid 1000 --create-home purple \
    && useradd --uid 1001 --no-create-home --shell /usr/sbin/nologin purple-repository
COPY agent/ /opt/purple/agent/
COPY public/skills/purple/scripts/ /opt/purple/public/skills/purple/scripts/
COPY offense/ /opt/purple/offense/
COPY scripts/ci/ /opt/purple/scripts/ci/
COPY .github/offense/ /opt/purple/.github/offense/
RUN cd /opt/purple/offense && npm ci --ignore-scripts --no-audit --no-fund \
    && ln -s offense/node_modules /opt/purple/node_modules
# The trusted observer's default location is shared with the existing Pi image.
COPY agent/test-observer.mjs agent/drop-repository-privileges.mjs agent/verification-gate.mjs agent/npm-projects.mjs /opt/purple/
ENV PURPLE_HERMES_PATH=/opt/hermes PURPLE_HERMES_PYTHON=/opt/hermes/.venv/bin/python \
    PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 HF_HUB_DISABLE_TELEMETRY=1 \
    PURPLE_FIX_ISOLATE_COMMANDS=1
USER purple
WORKDIR /opt/purple
RUN node --disable-sigusr1 --input-type=module -e "import {preflightHermes} from './agent/hermes-runtime.mjs';const result=await preflightHermes();if(result.status!=='ready')throw new Error('Pinned Hermes embedding preflight failed');console.log(JSON.stringify(result));"
# The trusted controller drops repository commands to UID 1001. The launcher
# provides only the process/file capabilities needed to supervise those commands.
USER root
ENTRYPOINT ["node", "--disable-sigusr1", "/opt/purple/agent/dependency-fix-job.mjs"]
