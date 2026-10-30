# Offense

Offense is the first product from Offense Security: one API key for hosted
security tools, with prepaid per-tool prices. Basic dependency advisory audits
remain free. Node.js 20 or newer is required.

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

Input files are explicit JSON requests; preview uploaded source and artifact
scope first. The server checks the exact quote before reserving prepaid credit.
Keep the same idempotency key and input when recovering an uncertain submission.
Failed or partial hosted scans release their reservation. Advisory matches and
scanner findings are review signals, not confirmed exploitable vulnerabilities.

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

This archive is a client distribution. The production and community repositories
remain private; no npm registry publication is performed by the build.
