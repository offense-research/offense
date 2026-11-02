FROM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205

# The application is staged at runtime. No checkout, credentials or project
# installation scripts enter the image build.
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/purple/api-venv \
    && /opt/purple/api-venv/bin/pip install --no-cache-dir 'pip==26.2' 'setuptools==84.1.0' \
    && /opt/purple/api-venv/bin/pip install --no-cache-dir 'schemathesis==4.32.4'
COPY schemathesis-sandbox.py /opt/purple/schemathesis-sandbox.py
# Generated contexts are private (0600); the sandbox UID must read this script.
RUN chmod 0644 /opt/purple/schemathesis-sandbox.py
ENV PATH=/opt/purple/api-venv/bin:/usr/local/bin:/usr/bin:/bin
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["python3", "/opt/purple/schemathesis-sandbox.py"]
