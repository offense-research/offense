# Self-hosted source profile

This profile runs the full Node API and console with SQLite, a local operator
API key and isolated Docker source scanners. It requires no Offense account,
Whop balance, Cloudflare account, Infisical project or model provider.

**Billing is off by default.** The setup command below configures it for you:
no payment credentials, subscription, credit purchase or code changes are needed.
You pay for your own infrastructure, not Offense tool credits. For an existing
source-profile installation, see [billing settings and verification](#billing-settings-and-verification).

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
configured origin; the CLI rejects sending it to another endpoint. Calls retain
authentication, idempotency and input limits even when billing is disabled.

The web console is served by the same app. The local operator key is an API/MCP
credential, **not a browser-login bypass**. Browser account features need an
operator-owned GitHub OAuth app and callback configuration. No fresh-browser
OAuth acceptance is claimed by the source-profile test. Run behind a trusted
HTTPS reverse proxy before exposing the API beyond loopback; keep `PUBLIC_URL`
correct and preserve the app's origin/host protections. Internet multi-tenant
operation is outside this initial single-operator profile.

## Billing settings and verification

### New installations: nothing extra to configure

`node scripts/init-self-host.mjs "$HOME/offense-state"` writes these values into
the private `server.env` automatically:

```dotenv
OFFENSE_SELF_HOSTED=true
SCAN_BILLING_ENABLED=false
WHOP_BILLING_ENABLED=false
```

| Setting | Effect |
| --- | --- |
| `OFFENSE_SELF_HOSTED=true` | Uses the local Docker source runtime and rejects hosted billing or an external `PURPLE_AGENT_URL` at startup |
| `SCAN_BILLING_ENABLED=false` | Scanner quotes and charges are zero; no prepaid balance is required |
| `WHOP_BILLING_ENABLED=false` | Disables hosted model/rehearsal payment flows, separate from scanner billing |

Leave payment credentials and `SCAN_TOOL_PRICES_JSON` unset. Do not enable
`WHOP_SANDBOX` as a substitute: test payments are not the billing-off setting.
Disabling payment flows does not enable unsupported hosted model/rehearsal tools.
Job reports, usage metadata, authentication, resource limits and tool availability
checks remain in place; billing off does not mean unrestricted execution.

### Existing source-profile installations

Edit the existing private `server.env` to match the three settings above and
leave `PURPLE_AGENT_URL` unset or empty. **Do not rerun the bootstrap or replace
the encryption key, database or operator API key.** Restart your API process
with that env file after changing configuration.

Check your shell, service manager or container environment too: inherited
variables override Node's `--env-file` values. If startup reports
“Self-hosted source execution cannot use hosted billing or an external agent
service,” remove the conflicting inherited settings. Do not turn off
`OFFENSE_SELF_HOSTED` to bypass that safeguard. This procedure is for the local
source profile, not a migration of an active paid hosted deployment.

### Confirm your client is using the unbilled server

Set `OFFENSE_API_URL` and load the private operator key as described above;
an installed CLI can otherwise still point at `https://offense.sh`. Installing
the CLI with Homebrew or npm does **not** change which service it calls.

```sh
node scripts/offense-cli.mjs status --json
node scripts/offense-cli.mjs tools --json
```

Confirm the status identifies your own API origin and the catalog reports
`billing.enabled: false`. To check a quote without executing a scan, save this
non-sensitive example as `request.json`:

```json
{"files":[{"path":"example.js","content":"const answer = 42;\n"}]}
```

```sh
node scripts/offense-cli.mjs quote opengrep --input request.json
```

Expect `billable: false` and `maximumMicros: 0`. The CLI sends dimensions, not
file contents, for this quote. If you choose to execute the scan afterward,
use `--max-price 0` with `call` and retain the idempotency key; direct HTTP/MCP
calls use `maxChargeMicros: 0`. This keeps a zero-cost ceiling even if a client
is accidentally pointed at a billable service. Completed scan receipts should
report `metering.chargeMicros: 0`. Do not top up a balance to fix an unexpected
payment requirement: check the API origin and server settings first.

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
