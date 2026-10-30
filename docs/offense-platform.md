# Offense account and tool platform

Offense is the first product from Offense Security. The canonical entrypoint is
https://offense.sh. Existing accounts, workspace connections, balances and legacy
API keys retain their identities; internal Purple database/Worker names remain
compatibility identifiers.

## Customer workflow

```sh
npm install --global https://offense.sh/downloads/offense-cli.tgz
offense login
offense whoami
offense tools
offense balance
offense topup
offense mcp install --client codex --project .
```

Use `--client claude` or `--client cursor` for those clients. Use `login --no-browser`
on a remote host. The person opens the first-party verification link, compares the
terminal code and explicitly approves the displayed workspace. No GitHub App
installation, Cloudflare connection or OpenRouter key is required for this API.

Start a **new coding-agent session** after skill/MCP installation or updates.
The local MCP proxy reads the CLI's private credential; project settings never
contain that credential. Existing customized or anonymous Offense settings are
preserved and reported incomplete. Review them before authorizing entry-only
replacement with `--replace-offense`. Native client trust prompts still apply.

Free `offense audit .` sends sanitized npm/pnpm dependency metadata and writes a
private report and remediation prompt outside the checkout. It does not spend
credit, change source, or establish exploitability. The agent retains responsibility
for source review, proposed edits, baseline/patch tests and publication authorization.
The existing optional Docker/Hermes dependency workflow remains available through
the repository's `npm run dependencies:*` commands; it is separate from this CLI
distribution.

## API and charging

- `GET /v1/catalog`: public tool catalog, availability and pricing.
- `GET /v1/account`: current API key's workspace and balance.
- `GET /v1/tools`, `POST /v1/quotes`: authenticated catalog and maximum-price quote.
- `POST /v1/call/:tool` or `POST /v1/scans`: submit with explicit maximum charge
  and an `Idempotency-Key`; changed input cannot reuse the same key.
- `GET /v1/scans/:id`, `GET /v1/usage`: workspace-scoped results and usage.
- `POST /v1/billing/topups`: empty JSON object; returns a Whop checkout link.

The same bearer key works across enabled tools and the authenticated MCP catalog.
Paid MCP discovery adds `offense.security_tools`, `offense.security_quote`,
`offense.security_call`, `offense.security_result`, `offense.account` and
`offense.topup`. Anonymous MCP retains the free `offense.audit_dependencies` tool.
Unavailable tools are labeled unavailable; they cannot be submitted or charged.

Prices and reservations use integer USD micros. Completed jobs settle their
reservation; failed/partial jobs release it. Repeated submissions with the same
workspace, idempotency key and input return the original job. Quotes do not charge.
Current beta limits remain two concurrent jobs per workspace, ten daily jobs per
workspace and fifty globally. Input, artifact ownership and network target
verification requirements remain part of each tool's contract.

Whop loads are currently one-time $10 USD purchases, with a $50 cap on new loads.
Creating a checkout or returning from its browser page never grants funds. A
signed durable webhook plus independent payment readback validates product,
amount, account and order before exactly-once credit. Late paid orders remain
reconcilable; refunds/disputes block spending for review. The old hosted-model
wallet is separate from security-tool credit.

## Credentials and deployment

Keys use 256 random bits, are shown once and stored only as hashes server-side.
New keys use `offense_sk_`; legacy `purple_scan_` keys continue to authenticate.
Every authenticated request checks current membership; revocation takes effect
on subsequent requests. Device grants store code hashes, expire after ten minutes,
enforce polling/guessing limits and issue one key transactionally. Inspection binds
the workspace before approval so another tab cannot change the consented account.

CLI credentials use owner-only directories/files. `OFFENSE_API_KEY` supports CI;
for self-hosting also set `OFFENSE_API_URL`. Credentials are bound to the configured
origin. `logout` removes the local credential; server revocation is at `/account`.

Production code and the community repository remain private. The downloadable
archive is a client distribution; the build does not publish to the npm registry.
Deployments load secrets from Infisical and preserve existing database/resource
bindings. Only public client downloads and share media live on the separate static
lander. Legacy URLs proxy those public bytes without forwarding credentials.
The existing site Worker forwards an explicit app page allowlist and the app API
namespaces through an internal service binding; the two production route patterns
remain unchanged. Publish matching static client assets before the app release.
The production deployment checks their exact bytes before uploading or activating
new code, preventing a skill manifest from pointing at an older CLI distribution.

GitHub OAuth callbacks use the trusted requesting origin, preserving old and new
hostnames. The new callback must be registered in the provider App settings.
GitHub App repository installation is separate: its provider-managed Setup URL
remains a distinct migration consideration. Existing payment webhook URLs can
continue to target the old hostname because both API hosts use the same state.

## Verification boundaries

Local tests cover real CLI/backend pairing, credential permissions, membership
changes, billing/idempotency, MCP discovery and calls, payment fixtures, migrations,
updater preservation and browser flows on desktop/phone. Synthetic payment fixtures
are not evidence of a live purchase. A real browser-approved device login and a
real or provider-sandbox checkout are still required to prove the complete paid
production journey. Do not create manual credit to stand in for payment verification.

The earlier Claude provider safeguard report remains separate. Configuring the
documented Claude project MCP transport does not establish that the previously
blocked model-driven bootstrap has been cleared; do not replay it to bypass the
provider refusal.

Product patterns were researched from Treg's primary documentation:
https://treg.to/llms.txt, https://treg.to/pricing, and
https://github.com/superdesigndev/treg. No implementation code was copied.
