FROM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
WORKDIR /opt/purple
RUN printf '{"type":"module"}\n' >package.json && useradd --uid 10002 --create-home gateway
COPY server/assessment-egress-gateway.mjs server/web-scan-target.js ./server/
COPY shared/assessment-egress-auth.js ./shared/
USER gateway
ENV ASSESSMENT_EGRESS_BIND=0.0.0.0
EXPOSE 8788
ENTRYPOINT ["node", "/opt/purple/server/assessment-egress-gateway.mjs"]
