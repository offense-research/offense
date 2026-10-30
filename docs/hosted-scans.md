# Hosted security scans

Purple reuses its Express API, SQLite-backed Durable Object, encrypted credential helper, periodic dispatch alarm and existing `purple-agent` container service. A separate named scanner image isolates scanner binaries/rules/database from the Pi investigation image. No OpenRouter key or paid model call is involved.

## Agent flow

Sign into Purple through the website and open [Billing & scan keys](https://app.purpleteam.sh/billing). Sign-in creates a workspace without requiring repository installation. Create a scan key there; keys are shown once, stored as SHA-256 hashes, and scoped to the issuing workspace. Set `PURPLE_SCAN_KEY` in the agent environment. Download `/skills/purple/scripts/hosted-scan.mjs` alongside the existing skill.

The eight additional bounded tools use `scripts/hosted-assessment.mjs`. Read [hosted security assessments](hosted-assessments.md) for Nuclei, Prowler Cloudflare, hosted Schemathesis, active ZAP API checks, SSLyze, Checkov, live TruffleHog verification, and MobSF static analysis. They share this wallet and job API but use a per-assessment quote, target-ownership proof where applicable, and separate execution images. The helper defaults to offline preview; `--run` is required to submit a new assessment.

```bash
node /installed/purple/scripts/hosted-scan.mjs /path/to/project --preview
node /installed/purple/scripts/hosted-scan.mjs /path/to/project
node /installed/purple/scripts/hosted-scan.mjs /path/to/project --tool trivy-config
node /installed/purple/scripts/hosted-scan.mjs /path/to/sbom-directory --tool trivy-sbom
node /installed/purple/scripts/hosted-scan.mjs /path/to/spec-only-checkout --tool spectral-owasp
node /installed/purple/scripts/hosted-scan.mjs /path/to/project --tool zizmor
node /installed/purple/scripts/hosted-scan.mjs --scan-id SCAN_ID
```

The source command explicitly uploads Git-tracked UTF-8 files at their current working versions. It skips symlinks, binaries, generated output and agent configuration directories, and records every omission. It does not include untracked files or Git history. It refuses uploads containing the current scan key. Preview lists paths and sizes, never source text. Read local `scan.json` and `scan.md` after completion; interrupted polling can resume with the saved ID. A narrowed upload covers only that directory.

Binary artifacts use `scripts/hosted-artifact-scan.mjs`. Preview checks the local file and shows its size and SHA-256 without uploading it. The helper submits one artifact for one tool, polls the scan, and writes `scan.json` and `scan.md` locally. Use `--scan-id ID` to resume polling. An OpenAPI scan uses the source API, with exactly one tracked JSON or YAML file in the selected directory; other tracked text files cause the request to fail.

```bash
node /installed/purple/scripts/hosted-artifact-scan.mjs image.tar --tool trivy-image --preview
node /installed/purple/scripts/hosted-artifact-scan.mjs image.tar --tool trivy-image
node /installed/purple/scripts/hosted-artifact-scan.mjs /path/to/repository --tool gitleaks-history --from-repo
node /installed/purple/scripts/hosted-artifact-scan.mjs package.tgz --tool guarddog-npm --package-name example --package-version 1.2.3
node /installed/purple/scripts/hosted-artifact-scan.mjs package.tar.gz --tool guarddog-pypi --package-name example --package-version 1.2.3
node /installed/purple/scripts/hosted-artifact-scan.mjs signed-image.tar.gz --tool cosign-image --expected-digest sha256:IMAGE_DIGEST --expected-identity SIGNER_IDENTITY --expected-issuer https://token.actions.githubusercontent.com
node /installed/purple/scripts/hosted-artifact-scan.mjs capture.har --tool zap-passive-har --target https://example.com
```

Create `image.tar` with a container image export such as `docker save`. Create the signed-image archive by running `cosign save --dir saved-image IMAGE@sha256:DIGEST` while connected to the registry, then `tar -czf signed-image.tar.gz -C saved-image .`. The expected digest is the signed OCI image manifest or index digest, not the tarball checksum. Supply registry npm `.tgz` or PyPI source `.tar.gz` archives directly; package installation and build scripts are outside this workflow.

### API

`GET /v1/tools` returns the scanner catalog, coverage, deployment availability and prices. The original thirteen tools are joined by eight separately enabled assessments. First request a quote for the selected tools and exact input size, then check scanner credit. `POST /v1/scans` accepts `{ "files": [{ "path": "src/app.js", "content": "..." }], "tools": ["opengrep", "trivy-vuln", "gitleaks", "trivy-config"], "maxChargeMicros": 200000 }`, where `maxChargeMicros` must equal the current quote. Omit `tools` for the original three checks. `trivy-sbom` runs alone on one uploaded CycloneDX or SPDX JSON file. Headers: `Authorization: Bearer PURPLE_SCAN_KEY`, `Content-Type: application/json`, and a unique `Idempotency-Key` (8–100 ASCII letters/numbers/underscore/hyphen). Returns HTTP 202 with an ID, status, selected tools, source fingerprint, usage and quote. Repeating a key with identical source and tool selection returns the existing job; changing either returns 409.

`POST /v1/quotes` accepts `{ "tools": ["opengrep"], "inputBytes": 1024, "fileCount": 1 }` and returns the per-tool price and maximum charge in USD micros. `GET /v1/usage` returns available scanner credit, reservations and recent jobs for the authenticated workspace. A quote is recomputed from the actual submitted files, so client-supplied dimensions cannot change the final charge; a changed price requires a new quote before submission. The helpers show the maximum charge and stop before source or artifact upload if paid credit is insufficient. All `/v1/` routes require the same workspace scan key.

For a binary scan, obtain the quote and check credit **before** uploading bytes with `POST /v1/artifacts`, then create the scan with `POST /v1/scans`. Upload headers are `Authorization: Bearer PURPLE_SCAN_KEY`, `Content-Type: application/octet-stream`, exact `Content-Length`, `X-Purple-Artifact-Kind`, and `X-Content-SHA256` containing the lowercase 64-character hex checksum of the uploaded bytes. A successful upload returns HTTP 201 and a single-use `id` that expires after 30 minutes. Scan creation requires `Authorization`, `Content-Type: application/json`, a fresh `Idempotency-Key`, and, for a first-MiB image example, `{ "artifactId": "UPLOAD_ID", "tools": ["trivy-image"], "maxChargeMicros": 100000 }` plus the fields below. The artifact kind and selected tool must match; artifact scans cannot be combined with source tools or another artifact tool.

| Artifact kind | Tool | Maximum upload | Extra `POST /v1/scans` fields |
| --- | --- | ---: | --- |
| `image-tar` | `trivy-image` | 80 MiB | None; upload one Docker image archive. |
| `git-bundle` | `gitleaks-history` | 32 MiB | None; upload one self-contained local Git bundle. |
| `package-archive` | `guarddog-npm` or `guarddog-pypi` | 16 MiB | `packageName`, `packageVersion` for the exact archive. |
| `cosign-save` | `cosign-image` | 32 MiB compressed | `expectedDigest` (`sha256:` and 64 lowercase hex digits), exact `expectedIdentity`, canonical HTTPS origin `expectedIssuer`. |
| `web-har` | `zap-passive-har` | 2 MiB | `target`, a public HTTPS origin matching the captured responses. |

`spectral-owasp` instead submits `{ "files": [{ "path": "openapi.yaml", "content": "..." }], "tools": ["spectral-owasp"], "maxChargeMicros": 50000 }` to `POST /v1/scans` for a first-MiB quote. The file must be one UTF-8 JSON or YAML OpenAPI document within the 256 KiB text-file limit. It cannot be combined with other tools. The helper selects tracked files; a direct API client can send exactly one file without a Git checkout.

`GET /v1/scans/{id}` uses the same workspace authorization. Statuses: queued, starting, running, completed, partial, failed. Results include normalized findings (`id`, `tool`, `ruleId`, `file`, nullable `line`, `severity`, `title`, `remediation`, optional package/version fields), per-tool status/version/duration, coverage and database timestamp. A partial or failed tool never establishes a complete clean scan. Findings are scanner signals and never enter the verified vulnerability discovery ledger.

Workspace cookie APIs `GET/POST /api/scan-keys` and `DELETE /api/scan-keys/{id}` list/create/revoke keys. The normal authenticated workspace and origin checks apply. The bearer API rejects browser Origin headers and authenticates before parsing source. Its `/v1/` routes are rejected on the ingestion hostname.

## Local-first security checks

The advanced Purple skill also provides `scripts/source-scan.mjs` for local Opengrep/Zizmor checks without source upload or a scan key. It stages only tracked supported files, applies fixed bundled rules, and saves private normalized reports outside the checkout. `--preview` remains offline; normal runs check installed skill updates first. Missing tools, relevant omissions and incomplete analysis are explicit.

`api-test.mjs` runs Schemathesis and an explicitly prepared application in a separate local image with Internet access disabled and a literal loopback target. It is not in the hosted catalog and does not enable Internet access on scanner containers. Read `public/skills/purple/references/api-testing.md` for setup and coverage. Reports stay local; server errors and scanner candidates are not automatically confirmed vulnerabilities.

## Execution and bounds

Each scan uses a unique `scan-ID` Durable Object and disposable container. Internet access is disabled; no connector credentials, provider keys or app environment variables enter the scan process. Source files are data only: no package install, application command, build or Git hook runs. Scanner configs are operator controlled; project Gitleaks/Opengrep ignore settings cannot suppress findings. Raw scanner output and source snippets are not stored in the app report. Gitleaks Match/Secret/context fields are discarded, including on scanner failures.

- Opengrep **1.32.0**: thirteen operator-maintained JS/TS/Python rules: the five original patterns plus eight within-file request-to-sink rules for SQL injection, shell-command injection, path traversal and SSRF. Supported source models include Express/Hono and Flask/Django. Parameterized SQL, fixed executable argument arrays and safe destination controls are covered by negative fixtures. This is bounded static analysis, not cross-file reachability or exploit proof. Parser recovery can silently accept malformed Python, so it is not independent syntax validation.
- Zizmor **1.31.1**, `zizmor`: supplied GitHub Actions workflows and action definitions with offline, fixed operator flags. Project configuration, ignore files and inline suppressions cannot hide findings. Titles/remediation are constructed from known rules; raw source expressions, scanner snippets and errors are not persisted. Online action history and advisory lookups are outside offline coverage. Missing workflows or collection/parse errors remain partial.
- Trivy **0.76.1**, `trivy-vuln`: supported dependency manifests/lockfiles. Its database is embedded at build time. Java archives that require a separate Java database are outside this initial snapshot workflow. File lines can be unavailable and are returned as null.
- Trivy `trivy-config`: supported infrastructure configuration files. The image build caches its checks bundle so runtime scanning has no internet access. A scan with no recognized configuration is partial, not clean.
- Trivy `trivy-sbom`: one uploaded CycloneDX or SPDX JSON SBOM. It checks components represented in that document, not the underlying image or filesystem.
- Gitleaks **8.30.1**: bundled default secret rules over uploaded files. `gitleaks-history` separately checks all refs present in one uploaded self-contained Git bundle. The `--from-repo` helper includes local refs, up to 1,000 commits and 32 refs; uncommitted changes and remote-only history are excluded. Server limits are 10,000 objects, 4 MiB per object and 128 MiB expanded objects. History findings retain file, line and commit SHA, with secret values removed. Rotate/revoke exposed credentials even after removing their source text.
- Trivy `trivy-image`: one digest-checked Docker image archive, up to 80 MiB. Image layers are inspected without running the image. A clean result covers that exported image and the build-time vulnerability database, not registry tags that later move.
- Spectral **6.17.0** with OWASP ruleset **2.0.1**, `spectral-owasp`: one uploaded OpenAPI JSON/YAML document. The operator ruleset is fixed; project config cannot replace it. It checks the specification, not a running API. Unresolved references or parse errors mark the scan partial. Raw specification values are not copied into finding titles.
- GuardDog **3.2.0**, `guarddog-npm` and `guarddog-pypi`: one exact-version npm tarball or PyPI source tarball. Declared name/version must match archive metadata; unverifiable identity or stale package-popularity data marks the result partial. GuardDog uses heuristic behavior checks, so a finding is not proof of malware and a clean result is not a trust guarantee. Wheels are not supported in this first pass. The scanner does not install packages or run their scripts. When the Cloudflare VM lacks GuardDog's Landlock support, Purple retries only that exact preflight failure with `no-new-privs` inside the separate, disposable, no-egress scanner VM; that fallback does not have GuardDog's own Landlock confinement.
- Cosign **3.1.4**, `cosign-image`: one bounded gzip archive of `cosign save` output (32 MiB compressed, 128 MiB expanded). It verifies the exact supplied OCI digest and exact certificate identity/issuer offline against a build-time Sigstore trusted root. It reports only digest and signer policy on success; no raw certificates. This does not prove the image is free of vulnerabilities or that the signer is the right party for the user's release policy.
- ZAP **2.17.0**, `zap-passive-har`: one recorded HAR containing 1–200 same-origin HTTPS GET/HEAD responses. The helper removes request headers, cookies, query strings, original paths, and request/response bodies, while retaining bounded security response headers and cookie flags. ZAP imports captured responses offline for passive checks; it does not crawl, authenticate, issue live requests or run active attacks. Coverage is mainly response headers and cookie attributes.

Release binaries have pinned SHA-256 digests in `agent/scan.Dockerfile`. The Trivy vulnerability database must be no older than seven days; stale/missing data fails vulnerability, SBOM and image checks rather than reporting no findings. Refresh `SCAN_DB_BUILD` in both agent Wrangler configs and rebuild/redeploy the image at least weekly. Rebuilds also refresh GuardDog's operator package-popularity cache and the Cosign trusted root. Scanner containers have no runtime internet access. Binary uploads use the separate artifact path with checksum verification and cleanup after transfer or expiry.

Bounds: 500 files, 256 KiB per file, 4 MiB decoded source, 6 MiB JSON body; binary upload caps are in the table above. Each workspace can have two pending artifact uploads, ten jobs per rolling day, and two pending jobs; the global pilot quota is fifty jobs per rolling day. A single scan dispatch queue serializes containers. Individual tools have bounded process timeouts (120–210 seconds); the runner has an eleven-minute limit; a twelve-minute durable cleanup alarm destroys the container independently of client polling. Queue jobs and unused artifact IDs expire after thirty minutes. Process/file/report budgets are explicit; reports are capped at 500 normalized findings, and truncation marks them partial.

Source is encrypted with the existing `ENCRYPTION_KEY` while queued, removed from the app store once container dispatch succeeds, and removed from the container after processing. Failed/expired queue entries are scrubbed. Container cleanup is retried from durable storage; the independent container alarm also bounds orphan lifetime. Reports expire after thirty days; job/key attribution, timestamps, byte counts and execution duration remain for metering. Private backup retention must account for encrypted queued source. Revoking a key prevents subsequent authenticated requests and pending dispatch for that key.

## Deployment and verification

Build and run the real local API-to-container fixture:

```bash
docker build --build-arg SCAN_DB_BUILD=YYYY-MM-DD -f agent/scan.Dockerfile -t purple-scan:local .
node scripts/e2e-hosted-scans.mjs
npm test
npm run build:worker
```

The original fixture uploads synthetic eval code, a known vulnerable lockfile, a fake credential, a Dockerfile and a CycloneDX SBOM through the real CLI/API. It runs the original five checks with no network, dropped capabilities, read-only root, bounded memory/CPU, and executable ephemeral `/tmp` (required by Opengrep's bundled executable). It asserts findings from every original tool, secret redaction, source deletion and zero scanner charge in free-pilot mode. No real credentials enter this fixture. Exercise the artifact and OpenAPI tools with their separate bounded fixtures before relying on a deployment.

Agent deploys use the existing staging/production Wrangler configs. Both include the separate `scan` image. Binary uploads additionally require the `SCAN_ARTIFACTS` R2 binding and its staging/production bucket to exist before the app release. The app reuses `PURPLE_AGENT_URL`, `PURPLE_AGENT_SHARED_KEY`, and `ENCRYPTION_KEY`; no new provider secret is required. Deploy the agent before the app. Test authenticated artifact upload, creation, polling, expiry/cleanup, key revocation and ingestion-host denial in staging before production.

Usage records support the spec's repeat-use milestone without equating scan findings with verified fixes:

```sql
SELECT user_id, COUNT(*) AS scans, COUNT(DISTINCT substr(datetime(created_at / 1000, 'unixepoch'), 1, 10)) AS active_days,
       SUM(input_bytes) AS source_bytes, SUM(finished_at - started_at) AS execution_ms
FROM scan_jobs WHERE created_at >= ? GROUP BY user_id;
```

The [provisional scanner rate card](scanner-pricing.md) sets a base price for the first MiB of each selected tool and a smaller amount for each additional started MiB. Customers can add $10 of scanner-only prepaid credit through Whop, up to a $50 balance for new loads. `POST /v1/quotes` shows the maximum charge before submission; job creation reserves that amount. Only a fully completed job is charged, while partial and failed jobs release their reservation. `GET /api/scanner-billing` shows the scanner balance and `POST /api/scanner-billing/checkout` starts the Whop load. Signed Whop webhook events trigger independent payment readback before credit is granted. Refunds and disputes freeze further scanner spending for review. Scanner credit remains separate from the hosted model balance. The workspace limit is ten hosted scans per rolling 24-hour period.

Scanner findings require the developer's agent to review applicability, reproduce where feasible, make authorized fixes, run tests and request another scan.

## Earlier free pilot checks

The original five-tool fixture exercised a valid SBOM, IaC, source and dependency checks. A separate production fixture exercised all seven later tool IDs, including both GuardDog ecosystems, image verification and passive HAR analysis. All of these saved canaries ran while scanner billing was disabled and recorded $0 charges. They establish scanner execution, redaction and key revocation, not paid checkout or wallet settlement. The existing one-container queue and quotas (ten per workspace and fifty globally per day) remain pilot bounds; raise them only after observing queue time, scanner duration and failure rates.

## Recorded verification

Evidence from the [original five-tool staging](e2e/hosted-scans-staging.json) and [production](e2e/hosted-scans-production.json) runs records successful Cloudflare checks on October 26, 2026. The later [seven-tool staging](e2e/hosted-scans-next-staging.json) and [production](e2e/hosted-scans-next-production.json) records cover images, Git history, npm/PyPI packages, OpenAPI, Cosign and passive HAR. The production fixture completed all seven through the public API at $0, omitted synthetic credential values and revoked its temporary key. Staging used a private operator path for the two GuardDog checks after the public test workspace reached its daily quota. These records demonstrate the hosted scanner workflow, not customer vulnerability discovery, exploit verification or paid wallet charging. Paid Whop checkout and charged-scan verification must be recorded separately.

The [scanner billing activation record](e2e/scanner-billing-production.json) confirms the live paid meter, twelve-tool rate card, signed webhook handling and protected billing routes. It does not include a real card purchase or charged scan.

The earlier free-pilot fixture can be repeated only while scanner billing is disabled:

```bash
node scripts/e2e-hosted-scans-live.mjs --session-file /private/test-session --base-url https://app.purpleteam.sh --report-file /tmp/hosted-scan-evidence.json
```

For paid acceptance, add $10 through the scanner credit panel in a test workspace, run one small scan with the paid-aware Purple helper, and compare its quoted maximum, completed job charge and new `/v1/usage` balance. Confirm the matching Whop event and independently verified payment in `scan_billing_events` and `scan_wallet_orders` before describing the purchase path as fully exercised.

## Rolling out the next security tools

Deploy the scanner image with Zizmor and the thirteen Opengrep rules before exposing `zizmor` in the app catalog. The explicit scanner price map must include its entry from `config/scanner-prices.json`; validate the entire map before publishing while retaining current runtime bindings. The local API-test image is built explicitly from the skill helper’s fixed image context; it is not a hosted scanner image. The current advanced skill release is Purple 1.13.0, which includes the hosted-assessment helper and reference, and requires a new coding-agent session after updating.

The [Purple 1.11 production rollout](e2e/security-tools-production.json) records the thirteen-tool catalog release, scanner-only image update, preserved investigation image/code/state, Infisical rate-map readback, real vulnerable/safe operator canaries and desktop/phone download checks. Operator canaries use synthetic source and bypass customer billing; they do not establish paid settlement or customer vulnerability discoveries.
