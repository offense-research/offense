# Offense

Offense is a product by [Offense Research, Inc.](https://offenseresearch.com):
one API key for hosted security tools, with prepaid per-tool prices. Basic
dependency advisory audits remain free. Node.js 20 or newer is required.

This package is the CLI client, not the self-hosted server, local dependency
engine or scanner binaries. Source and installation options are at
https://github.com/offense-research/offense#install-the-cli.

For a downloaded, verified versioned release archive, install locally:

```sh
npm install --global ./offense-cli-0.2.0.tgz
offense --version
offense --help
```

Check its SHA-256 against the release's `SHA256SUMS` before installation. The
mutable hosted download below is a separate channel and may be an older version.
No npm registry package is required; avoid assuming `npm install -g offense`
selects this project.

```sh
npm install --global https://offense.sh/downloads/offense-cli.tgz
offense login
offense tools
offense balance
offense topup
offense mcp install --client codex --project .
```

Start a **new coding-agent session** after installing the skill or MCP settings.
Claude Code and Cursor are also supported by `--client claude` and `--client cursor`.
Project MCP settings contain a local command, never an API key. Existing
customized Offense entries are preserved and reported as incomplete until reviewed.

`offense login --no-browser` prints a first-party verification URL and comparison
code for remote machines. Sign in and approve the displayed account in a browser.
The CLI receives its API key once and saves it privately under the user's Offense
configuration directory. It never requests a GitHub repository installation,
Cloudflare account or model key. `OFFENSE_API_KEY` is supported for automation;
set `OFFENSE_API_URL` alongside it when using a self-hosted origin. Existing
`PURPLE_SCAN_KEY` values remain supported during migration.

```sh
offense audit . --plan-limit 0
offense quote opengrep --input request.json
offense call opengrep --input request.json --max-price 0.10 --idempotency-key my-request-0001 --wait
```

`offense audit` saves one response and exits 2 when coverage or upgrade planning
is incomplete. It does not automatically follow `scanning.next` or
`remediation.planning.next`. For large audits, use the separate downloadable
`offense.mjs` helper's automatic continuation and `--resume` support, documented
in [the dependency API guide](https://github.com/offense-research/offense/blob/main/docs/offense-api.md#continue-large-advisory-scans-without-splitting-lockfiles).
Do not treat a partial report as a complete scan.

Input files are explicit JSON requests; preview uploaded source and artifact
scope first. The server checks the exact quote before reserving prepaid credit.
Keep the same idempotency key and input when recovering an uncertain submission.
Failed or partial hosted scans release their reservation. Advisory matches and
scanner findings are review signals, not confirmed exploitable vulnerabilities.

Generate a PDF from an existing hosted audit or job receipt, entirely offline:

```sh
offense report --input /private/reports/audit.json --output /private/reports/audit.pdf
offense report --input /private/reports/job.json --output /private/reports/job.pdf
```

Use a private output directory. The command refuses existing files and symbolic
links, does not read login configuration, and does not run or purchase scans.
Exit 0 means the PDF was generated; `reportStatus` in its JSON output preserves
the scan's status, including partial, running or failed. Findings, coverage and
planning blockers remain in the PDF. Retain the original JSON and review both
before sharing: PDFs are not redacted, encrypted or signed. Standard-font
limitations are represented as `[U+XXXX]`, not dropped text. Maximum input is
6 MB; exports exceeding 500 pages fail. Only `offense.audit.v1` and hosted job
receipts are supported, not local-engine or stack report schemas.

### Plain-English risk explanations

The PDF leads with a decision summary and an explanation for every finding:
what an attacker could do, required access and conditions, business impact,
recommended fix, priority, evidence and unknowns. Raw findings follow in a
technical appendix. Explanations are generated locally from advisory metadata
and known scanner rules; they do not invoke a model or invent deployment facts.

Scanner/advisory severity is **not application severity**. Without reviewed
context, application severity is undetermined and priority means investigation,
not a claim of confirmed exposure. A development dependency is not automatically
safe; a critical advisory is not proof of production compromise. Unknown attack
types remain unknown instead of being assigned a dramatic consequence.

To include an actual scoped assessment, preserve the original JSON and add a
`riskReview` object to the relevant finding in a **separate reviewed copy**.
All fields below are required; evidence must be a nonempty list of descriptions
or references, and `unknowns` must explicitly list remaining gaps (or be empty).
Do not invent a review, test result, reviewer or scope to populate these fields.
Example for a synthetic SQL-injection finding:

```json
{
  "riskReview": {
    "reviewer": "Example security reviewer",
    "reviewedAt": "2026-10-31T12:00:00Z",
    "scope": "Synthetic staging service, commit abc123; production not assessed",
    "exploitability": "reproduced",
    "severity": "high",
    "severityReason": "A crafted query returned another tenant's test records.",
    "attackerOutcome": "The test account read records outside its tenant.",
    "attackerAccess": "A signed-in account able to submit the affected search request.",
    "businessImpact": "If the same path is deployed, customer confidentiality could be breached.",
    "recommendedFix": "Bind query values using parameters; test cross-tenant and normal requests.",
    "evidence": ["Staging regression log: expected no other-tenant rows; observed synthetic other-tenant rows."],
    "unknowns": ["Production deployment equivalence has not been checked."]
  }
}
```

`exploitability` accepts `reproduced`, `not_tested`, or `not_applicable`.
`severity` accepts `critical`, `high`, `medium`, `low`, or `unknown`;
`not_applicable` requires `unknown` severity and a scoped justification, not a
claim that the underlying issue was fixed. High/critical reviewed risks get
urgent review and containment planning; medium risks get a maintenance-cycle
fix; low risks get a routine fix; unknown severity requires prioritization.
Agree an owner and deadline using service exposure and business requirements.

Reviews are **attributed, not authenticated**: the PDF says “Reviewer reports a
reproduced exploit,” not “Offense verified production compromise.” The exporter
does not open evidence references, execute tests or validate whether the review
still matches the deployment. Incomplete reviews cannot lower priority or
establish exploitability. A standalone `confirmed: true` flag is not proof.
Provider-listed fixed versions remain candidates requiring compatibility and
security verification, even when a review recommends them.

Inspect a repository → container → deployed-state chain locally, without login:

```sh
offense stack build --project /project --image example/app:rehearsal --preview
offense stack build --project /project --image example/app:rehearsal --run --output /reports/build
offense stack check --project /project --image example/app:rehearsal --container app-staging --build-receipt /reports/build/build.json --scan-report /reports/trivy-image.json --output /reports/stack
```

Track desired state in `offense-stack.json`: schema version 1, environment,
the exact built `sourceRevision`, Dockerfile path and `image` with `reference`,
immutable `digest`, and `digestKind` (`manifest`, `index` or `image-config`). Use
the receipt's `image.configDigest` for a local config identity; newer Docker
engine IDs may instead identify an index. Build
the source commit first, then commit the release declaration; later application
changes invalidate that source binding. Builds use committed Git archives and
disable Dockerfile RUN networking. Inspect the Dockerfile before `--run`.

Checks read actual Docker image/container identities and save private snapshots,
drift reports and a copyable remediation prompt. Optional `--sbom` and
`--scan-report` inputs must match the selected immutable image. No source or
container environment is uploaded. Exit 0 establishes an aligned identity chain,
not vulnerability absence; exit 2 retains drift/gaps. This slice supports local
Docker, not Kubernetes rollouts. Read the installed skill's
`references/stack.md` for the declaration, evidence limits and rebuild workflow.

Collect a Kubernetes/GPU inventory locally with a trusted `kubectl` and an
explicit read-only context:

```sh
offense k8s collect --context staging-gpu --preview
offense k8s collect --context staging-gpu --run --output /private/reports/staging-gpu
```

Preview is offline and is the default. `--run` saves a private
`kubernetes-inventory.json`, with Kubernetes/node versions, workload images,
jobs, disruption budgets, storage, NVIDIA discovery labels and GPU Operator
resources. Existing files are never overwritten. No login, upload, cluster
mutation, pod exec or software installation occurs. Exit 2 preserves missing
permissions/metadata and other coverage gaps; exit 0 means collection completed,
not that an upgrade is safe. MIG/shared units are not physical GPU counts.

Use `--kubeconfig FILE` to select a trusted file explicitly. Optional
`--with-nova` reads Helm release Secrets locally and contacts upstream chart
metadata; `--with-popeye` runs selected health linters, access reviews and
read/watch requests. Both require separately installed trusted binaries and
reviewed permissions. Neither is enabled by default. Reports omit environment
values, raw manifests and diagnostics, but retain sensitive names and image
references: review before sharing. Repository documentation in
`docs/kubernetes-collector.md` provides the RBAC template, schema and limits.

Binary artifacts and assessments use the same private login credential. Preview
is offline and is the default; `--run` plus an approved `--max-price` is required
for a paid job:

```sh
offense artifact trivy-image --file /path/to/image.tar --preview
offense artifact trivy-image --file /path/to/image.tar --run --max-price 0.10
offense artifact gitleaks-history --file /path/to/repo --from-repo --preview
offense assess checkov --project /path/to/infra --preview
offense assess mobsf-static --file /path/to/app.apk --format apk --preview
offense target challenge --target https://staging.example.com
offense target verify --input /path/from/challenge/target-challenge.json
offense assess nuclei --target https://staging.example.com --run --max-price 0.50
```

Publish the returned DNS TXT record yourself before verification. A challenge or
verification does not run a scan. Active API assessments also require
`--confirm-active-testing`; live secret verification requires
`--confirm-live-verification`. Provider assessments need an explicitly selected,
separate read-only token via `--account-id` and `--token-env`; your Offense key is
not a provider credential. Artifacts retain tool-specific size/checksum limits,
package identity, signer and ownership requirements. See the installed skill's
`references/tools.md` for the complete option mapping.

Binary submissions save a private `submission.json` with the uploaded artifact
ID and quote dimensions, never artifact bytes or credentials. If the response is
lost, use the printed `offense call` recovery command with the same idempotency
key and saved input. Do not rerun an artifact upload blindly. `offense job <id>`
resumes status without another submission or charge.

Top-ups open a Whop checkout for the advertised credit amount. The user approves
payment there; a browser return does not grant funds. `logout` removes the local
credential; revoke the server key at https://offense.sh/account to remove access.

The source is public under Apache-2.0, with third-party notices preserved in
this archive. The `private: true` package flag prevents accidental npm registry
publication; it does not prevent installation from a local archive or release URL.
Building a candidate does not publish a release or deploy the hosted service.
