# Hosted security assessments

Purple's assessment tools use the existing workspace scan key, prepaid scanner wallet, quote API, job queue, and completion-based settlement. Sign in at [Billing & scan keys](https://app.purpleteam.sh/billing), add scanner credit, and create a scan key. Repository installation is optional for these uploads.

The downloadable helper is `/skills/purple/scripts/hosted-assessment.mjs`; keep its sibling `hosted-scan.mjs` and `update.mjs` from the same installed Purple skill release. It supports Node.js 20 or newer. Set `PURPLE_SCAN_KEY` through the agent's secret environment. Do not put scan keys or cloud tokens in command arguments or tracked files.

## Tools and pilot prices

Each assessment runs exactly one tool. These are provisional retail prices, not measured execution costs. The configured service quote is authoritative; the source rate card is `config/scanner-prices.json`.

| Tool ID | Scope | Maximum complete-job charge | Upstream license |
| --- | --- | ---: | --- |
| `nuclei` | Four fixed exposure checks on one verified HTTPS origin; no general CVE coverage | $0.25 | MIT |
| `prowler-cloudflare` | Read-only checks in one selected Cloudflare account | $0.25 | Apache-2.0 |
| `schemathesis` | Generated requests against one verified API and supplied OpenAPI JSON | $0.25 | MIT |
| `zap-api` | SQL injection, path traversal and CRLF injection checks, plus passive response checks, on one verified staging API | $0.50 | Apache-2.0 |
| `sslyze` | Certificate validation, Heartbleed and OpenSSL CCS injection on one verified HTTPS hostname | $0.05 | AGPL-3.0 |
| `checkov` | Uploaded infrastructure files; no live cloud access | $0.05 | Apache-2.0 |
| `trufflehog-verified` | Uploaded current files and a curated set of live credential verifiers | $0.125 | AGPL-3.0 |
| `mobsf-static` | Static analysis of one APK or IPA, at most 80 MiB | $0.50 | GPL-3.0 |
| `openssf-scorecard` | Published OpenSSF snapshot for one public GitHub repository; no fresh or private-repository scan | See current quote | Apache-2.0 |
| `katana` | Bounded endpoint discovery within one verified HTTPS origin | See current quote | MIT |
| `httpx` | HTTP service observations for one verified HTTPS origin | See current quote | MIT |

The billing unit is `bounded_assessment`, with no additional-MiB fee. The helper checks the advertised tool, requests a maximum-price quote, validates matching tool/unit/price and available credit, and prints the quote **before** it sends source, a mobile artifact, or a cloud token. The scan request includes the quoted `maxChargeMicros`. A price mismatch, insufficient credit, or invalid quote stops the upload. A selected tool must complete for the charge to settle; failed or partial jobs release their reservation. A completed assessment is charged whether or not it finds an issue. Existing workspace capacity and daily scan limits apply.

The execution budget is 120 seconds, or 480 seconds for mobile static analysis. Network assessment connections have a cap of 200. A connection cap does not imply an HTTP request cap: HTTPS keep-alive can carry multiple requests over one connection. Tool-specific limits and reported coverage describe how much testing actually ran. SSLyze runs the three named checks; it does not enumerate protocol/cipher combinations or test every TLS weakness. ZAP enables only active rules 40018, 6 and 40003 at Low strength and Medium threshold, alongside its passive response checks. Schemathesis runs finite examples and fuzzing with five examples per operation, subject to the request and execution caps. Timeouts or incomplete coverage cannot establish a clean scan.

## Preview and run

The helper defaults to offline preview. `--preview` is explicit and also performs no network request or skill update. It prints file names, byte counts, omissions, target/account identifiers, and bounds without printing file contents, the scan key, or the Cloudflare token value. `--run` authorizes a new quoted assessment.

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --tool checkov --project /path/to/infrastructure --preview

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool checkov --project /path/to/infrastructure --run
```

Source collection uses Git-tracked UTF-8 files at their current working versions. Untracked files, Git history, symlinks, binaries, generated output, dependency directories, and supported agent configuration directories are omitted. The source bounds are 500 files, 256 KiB per file, and 4 MiB total before the server's assessment envelope. Narrow the project directory if the normalized request exceeds its server-side limit. Review preview omissions before claiming coverage. A file containing the active scan key is rejected before upload.

## Verify target ownership

`nuclei`, `sslyze`, `schemathesis`, `zap-api`, `katana`, and `httpx` require a workspace-bound DNS ownership proof. Challenge and verification are separate commands; neither starts a scanner or purchases credit.

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --target https://staging.example.com --challenge
```

Publish the returned `recordValue` as a DNS TXT record at `recordName`. The helper saves the challenge in a private `target-challenge.json` file. Then verify that exact file:

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --verify-target /tmp/purple-assessment-EXAMPLE/target-challenge.json

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool nuclei --target https://staging.example.com --run

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool sslyze --target https://staging.example.com --run
```

The challenge expires after ten minutes; a successful verification is valid for at most five minutes. Start the assessment promptly or repeat verification while the challenge remains valid. The service checks both the TXT proof and public address resolution. The target is one canonical HTTPS origin on port 443, with no path, credentials, query, or fragment. IP literals and private/local hostnames are unsupported. The proof is scoped to the signed-in workspace; callers cannot supply their own resolved address list or a `verified` flag.

## Endpoint discovery and supply-chain evidence

The Offense CLI exposes the same assessment helper. Start with an offline preview:

```sh
offense assess katana --target https://staging.example.com --preview
offense assess httpx --target https://staging.example.com --preview
offense assess openssf-scorecard --repository owner/public-repository --preview
```

Katana and httpx use the ownership verification above. Their commands, request limits, timeout and same-origin network scope are controlled by the service. Discovery does not accept arbitrary scan arguments or production authentication credentials. Results are `observations`, separate from vulnerability `findings`: Katana reports endpoint URLs and httpx reports bounded service metadata. Reports omit raw response bodies, headers, URL queries and fragments. An endpoint or an HTTP status is not a confirmed vulnerability.

OpenSSF Scorecard accepts only an explicit `owner/repository` identifier for a public GitHub repository. It fetches the official published snapshot without receiving a GitHub connector token or a local checkout. The report records the assessed date, commit, aggregate score and available individual checks. It does not run a fresh Scorecard scan. A snapshot older than seven days remains partial; a missing snapshot is unavailable evidence, not a clean result. Scores and checks are supply-chain observations and do not count as vulnerabilities.

Inspect `offense tools show TOOL_ID` and its maximum-price quote before adding `--run --max-price USD`. The helper sends no target or repository assessment until explicitly run and the quote is accepted. A run still requires an Offense API key and any required prepaid balance.

## Active API testing

Supply one OpenAPI **3.0 or 3.1 JSON** document with 1–25 operations. Remote references, callbacks, webhooks, external examples, and external documentation references are unsupported. The service controls the execution origin rather than trusting schema server URLs.

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --tool schemathesis --target https://staging.example.com \
  --schema /path/to/openapi.json --preview

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool schemathesis --target https://staging.example.com \
  --schema /path/to/openapi.json --run --confirm-active-testing

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool zap-api --target https://staging.example.com \
  --schema /path/to/openapi.json --run --confirm-active-testing
```

Use an authorized staging target and synthetic data: these modes generate active requests and may exercise modifying operations. `--confirm-active-testing` is required in addition to `--run`. This first hosted API mode does not accept production authentication credentials; protected or otherwise unreachable operations remain outside demonstrated coverage. An HTTP 5xx or schema mismatch is a review candidate, not proof of a vulnerability. Use the existing local `api-test.mjs` when a disposable local application and synthetic authentication fixture are more appropriate.

## Cloudflare account audit

Use a separate Cloudflare token restricted to read-only permissions for the selected account and the checks being run. The client reads its value only from the environment variable named by `--token-env`; preview shows that variable's name without reading its value.

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --tool prowler-cloudflare --account-id 0123456789abcdef0123456789abcdef \
  --token-env PURPLE_CF_AUDIT_TOKEN --preview

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool prowler-cloudflare --account-id 0123456789abcdef0123456789abcdef \
  --token-env PURPLE_CF_AUDIT_TOKEN --run
```

Set `PURPLE_CF_AUDIT_TOKEN` through the existing secret manager before running. The API token is sent only in the assessment creation request after quote validation. The existing queued-input encryption and disposal lifecycle applies; it is not included in local reports. Missing permissions must remain explicit coverage failures rather than successful checks.

## Live secret verification and mobile artifacts

```sh
node /installed/purple/scripts/hosted-assessment.mjs \
  --tool trufflehog-verified --project /path/to/project --preview

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool trufflehog-verified --project /path/to/project \
  --run --confirm-live-verification

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool mobsf-static --artifact /path/to/app.apk --format apk --preview

node /installed/purple/scripts/hosted-assessment.mjs \
  --tool mobsf-static --artifact /path/to/app.apk --format apk --run
```

Live verification contacts supported credential providers using credentials detected in the selected files. The explicit confirmation is required. This mode does not inspect Git history and does not claim verification for unsupported credential types.

Mobile inputs must be regular local files without symlinks. Use `--format ipa` for an IPA. The helper hashes the artifact, obtains the quote, uploads bytes to `/v1/artifacts` with the size and SHA-256, and submits the single-use artifact ID. The server independently verifies transferred bytes. Mobile analysis is static: no emulator, app launch, or dynamic network exercise is included.

## Results and API contract

The helper polls the existing `/v1/scans/{id}` job and writes `assessment.json` plus `assessment.md` in a private directory. An explicit `--output` directory must have mode 0700; reports use mode 0600. Reports retain normalized findings, separate discovery or supply-chain observations, tool completion, limited coverage, and metering, while omitting raw scanner fields and redacting the active scan key and supplied Cloudflare token. Do not publish reports without reviewing their remaining repository or artifact metadata.

```sh
node /installed/purple/scripts/hosted-assessment.mjs --scan-id 0123456789abcdef0123456789abcdef
```

Resuming an existing job makes no upload, requests no new quote, and starts no second charge. Local omissions are unknown when resuming; consult the original report. Terminal `partial` or `failed` results exit with status 2. A polling deadline saves metadata and prints a resume command. Expired reports are not security results. Findings remain candidates; `confirmedVulnerabilities` is always zero in this client. Confirm application impact and run a focused regression before claiming a reproduced vulnerability or verified fix.

The helper uses the existing endpoints:

- `GET /v1/tools`, `POST /v1/quotes`, and `GET /v1/usage` for availability and credit.
- `POST /v1/targets/challenge` with `{ "target": "https://staging.example.com" }` and `POST /v1/targets/verify` with `{ "challenge": { ... } }` for target ownership.
- `POST /v1/scans` with one `tools` entry and the relevant `files`, `target`, `repository`, `accountId`/`apiToken`, or `artifactId`/`format`. Active API and credential checks also require `confirmActiveTesting: true` or `confirmLiveVerification: true` respectively.
- `GET /v1/scans/{id}` for completion and results. All requests use the workspace bearer scan key; scan creation includes an idempotency key.

## Hosting and license boundaries

Keep offline, network, and mobile assessment images separate from the existing no-egress scanner image. Network jobs require the configured controlled egress gateway and cannot fall back to unrestricted internet access. In particular, the deployment must provide its external gateway and matching credentials before enabling network execution; Cloudflare-hosted destinations such as `api.cloudflare.com` cannot rely on Workers TCP egress alone. Publish a tool's availability only with its execution image and required gateway configuration. A missing image, missing gateway, timeout, or incomplete run must fail or remain partial and release scanner reservations.

Pin engines, templates, and rule data, preserve their notices, and review the exact bundled components when updating. [Nuclei](https://github.com/projectdiscovery/nuclei) and [Schemathesis](https://github.com/schemathesis/schemathesis) use MIT; [Prowler](https://github.com/prowler-cloud/prowler) and [Checkov](https://github.com/bridgecrewio/checkov) use Apache-2.0. [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [SSLyze](https://github.com/nabla-c0d3/sslyze) use AGPL-3.0; [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) uses GPL-3.0. Their source, distribution, modification, and integration obligations must be handled for the shipped deployment. Open source licensing does not by itself establish third-party data or template rights.
