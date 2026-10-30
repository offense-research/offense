# Self-hosted source profile

This profile runs the full Node API and console with SQLite, a local operator
API key and isolated Docker source scanners. It requires no Offense account,
Whop balance, Cloudflare account, Infisical project or model provider.

Supported execution: dependency advisory intelligence (public OSV/npm metadata),
Opengrep 1.32.0 and Zizmor 1.31.1. **The other catalog tools are disabled in this
profile.** Included adapters/recipes are unsupported reference source, not
certified self-hosted workflows. The minimal export omits MobSF/SSLyze and the
shared network/offline assessment runners and their recipes, including Checkov;
see [release preparation](release-preparation.md). The first release is source only; local
scanner builds are not approved image, binary or dataset distribution artifacts.
The separate `offense/` package also supports local dependency analysis.

## Install on your own Linux amd64 machine

Use Node.js 24+, npm, Git and Docker Engine. Allow at least 2 GiB RAM per scanner
and additional memory for the API. The API's operating-system user needs Docker
access, which is effectively host-administrator access. Do not run it on a host
containing unrelated sensitive workloads or expose the Docker socket to clients.

```sh
npm ci
npm run build
docker build -f agent/source.Dockerfile -t offense-source:local .
node scripts/init-self-host.mjs "$HOME/offense-state"
node --env-file="$HOME/offense-state/server.env" server/index.js
```

The bootstrap refuses an existing state directory and does not print keys. It
creates mode-0700 private state with mode-0600 `server.env` and `api-key.json`.
The server binds to loopback on port 3217. Do not set conflicting inherited
environment variables: Node environment values take precedence over the env file.
Never run this bootstrap against an existing production database.

On that machine, set `OFFENSE_API_URL` to `http://127.0.0.1:3217` and load the
`key` field from private `api-key.json` into `OFFENSE_API_KEY` through your secret
manager or process environment. Do not put it in shell history, CLI arguments,
source control or MCP configuration. Then use the checked-out CLI:

```sh
node scripts/offense-cli.mjs tools --json
node scripts/offense-cli.mjs status --json
```

Use the same origin and bearer key with `/mcp`. The credential is bound to the
configured origin; the CLI rejects sending it to another endpoint. Quotes are
zero and calls still require idempotency and a maximum charge of zero. Hosted
billing and an external agent URL are rejected in self-hosted mode.

The web console is served by the same app. The local operator key is an API/MCP
credential, **not a browser-login bypass**. Browser account features need an
operator-owned GitHub OAuth app and callback configuration. No fresh-browser
OAuth acceptance is claimed by the source-profile test. Run behind a trusted
HTTPS reverse proxy before exposing the API beyond loopback; keep `PUBLIC_URL`
correct and preserve the app's origin/host protections. Internet multi-tenant
operation is outside this initial single-operator profile.

## Data and isolation

Source is sent only to your configured API, encrypted while queued in SQLite,
then passed to a fixed scanner container over stdin. Containers have no network,
host mounts or Docker socket; they use an unprivileged UID, read-only filesystem,
bounded tmpfs, CPU/memory/PID limits, no capabilities and no-new-privileges.
The runner applies timeouts; failed, truncated or partial coverage stays visible.
Submitted code is scanned, not executed. Docker isolation is not a guarantee
against every kernel or scanner vulnerability; keep the host and engines patched.

Temporary source is deleted after dispatch, container state/logs after report
collection, and report bodies expire after 30 days. Usage metadata persists.
Dependency audit sends sanitized package metadata to public advisory/registry
providers; it is not an offline scanner. The bootstrap disables diagnostic traces.
Ordinary HTTP access logs at your reverse proxy are your responsibility.

## Acceptance, upgrades and recovery

```sh
node scripts/test-self-host.mjs
```

This opt-in check uses real local engines, temporary SQLite state and API/MCP/CLI
requests. It verifies detection, safe controls, unsupported tools, zero charges,
idempotency, report persistence, source cleanup and key revocation. It does not
exercise payments, external sign-in or production infrastructure.

For an upgrade, stop the API, back up the entire private state directory and
record the source revision and scanner image ID. Build/test the new source and
image, then start with the same env file and database. **The encryption key and
database must be backed up/restored together.** Test restores on a disposable
host before relying on them. Do not run a restored copy concurrently against
the original Docker job namespace. If rolling back across schema changes,
restore the matching pre-upgrade database as well as the old code/image.

Revoke a compromised key by stopping the server and setting its `revoked_at`
timestamp in `scan_keys` using the key ID recorded in `api-key.json`; restart
and confirm authentication is rejected. The bootstrap intentionally refuses to
overwrite an installation. Additional local-user/key management is not yet a
supported bootstrap workflow; browser key management requires operator OAuth.

This recipe builds images locally. Publishing images is a separate licensing
review and release; see THIRD_PARTY_NOTICES.md. The recipe copies only its runner
dependencies, excluding the deferred MobSF/SSLyze integrations. Downloaded
engines retain their own licenses; do not label the image Apache-only.
Before enabling SSLyze or other network assessments, review their licensing and
deployment-matched source-offer obligations as well as their operational safety.
This self-hosted profile does not certify an existing hosted deployment's compliance.
