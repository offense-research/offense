# Local Offense capabilities

Use the current coding agent's authorized checkout, model and sandbox for local
work. An Offense API key unlocks enabled hosted tools; it is not required for
local source analysis, triage, API testing or container migration. Local checks
do not consume Offense scanner credit. They may need separately installed scanner
binaries, Docker, prepared dependencies or registry access.

## Choose the execution path

| Task | Available interface | Execution and requirements |
| --- | --- | --- |
| Dependency advisory audit | `offense audit /project`, free MCP audit, or installed `scripts/offense.mjs audit /project` | Sanitized npm/pnpm lockfile metadata goes to Offense; source stays local. No account or model key required. |
| Source and workflow checks | Advanced `source-scan.mjs` | Pinned Opengrep 1.32.0 / Zizmor 1.31.1 run locally on selected tracked files; no source upload or application execution. |
| Dependency applicability | Advanced `purple.mjs triage` | Local source and function-path evidence; unsupported/dynamic paths stay unknown, not safe. |
| Upgrade rehearsal | Advanced `purple.mjs rehearse` | Isolated baseline/candidate installs, existing checks and a final advisory rescan; requires a complete clean checkout and prepared sandbox. |
| API behavior testing | Advanced `api-test.mjs` | Explicitly prepared disposable application and OpenAPI schema inside a network-disabled local container, using synthetic data. |
| Hardened container base | Advanced `hardened-image.mjs` | Local Dockerfile inventory and migration proposal; an explicit pull uses existing Docker/registry access. Compatibility and provenance checks remain separate. |
| Repository, image and deployed-state chain | `offense stack check`, or installed `scripts/cli.mjs stack check` | Read-only Git/Docker collection, immutable image comparison, optional subject-bound SBOM/Trivy report and a remediation prompt. `stack build --run` can create a local image and receipt from committed source. Read [stack evidence](stack.md). |
| Hosted source, artifact, infrastructure, API, cloud and mobile tools | `offense tools`, `quote`, `call`, `job`, or authenticated MCP | One Offense key, deployment availability, reviewed price, explicit scope and each tool's upload/ownership requirements. |
| Apply fixes and open a PR | Current coding agent and existing authorized repository tools | Review source, make coordinated fixes, run matching checks/rescan, deliver a patch or requested PR. No automatic merge or deploy. |

The installed standalone Offense CLI bundles the hosted artifact/assessment
helpers, but does not bundle local scanner executables or the local advanced
workflows listed above. `offense audit` is not an entirely offline scan. There is
currently no generic hosted dependency-fix, reachability or PR tool. Do not invent
such a command or describe an available engine as a completed scan.

## Existing advanced helpers

First check whether the advanced helper package is already installed. It retains
the legacy directory name `purple` for compatibility. Its public release is at
https://offense.sh/skills/purple/manifest.json and its instructions are at
https://offense.sh/skills/purple/SKILL.md. Read those instructions and the manifest,
inspect executable files, download the complete manifest-listed release into the
chosen project skill scope, and validate it with its installed updater before
use. Preserve custom files and unrelated settings. Installing these optional
helpers does not require another account, a GitHub App installation or a new
model provider. A required skill update needs a new coding-agent session.

Resolve every path below against that actual installation. Do not run a helper
that is missing, or assume an isolated dependency snapshot is an executable app.

```sh
node /installed/purple/scripts/source-scan.mjs /project --preview
node /installed/purple/scripts/source-scan.mjs /project --tool opengrep
node /installed/purple/scripts/source-scan.mjs /project --tool zizmor

node /installed/purple/scripts/purple.mjs scan /project
node /installed/purple/scripts/purple.mjs triage /project --scan /reports/scan.json
node /installed/purple/scripts/purple.mjs rehearse /project --scan /reports/scan.json --sandboxed

node /installed/purple/scripts/api-test.mjs --help
node /installed/purple/scripts/hardened-image.mjs --help
```

The advanced triage/rehearsal helpers consume their own `scan.json`; the Offense
`audit.json` format is different. Obtain a compatible scan instead of renaming
files. `--sandboxed` acknowledges isolation the agent already provided; it does
not create a sandbox. Installs and repository tests execute untrusted code, so
use an isolated environment without production secrets. Keep reports outside
the checkout and preserve missing tools, failed baselines, unrun checks, remaining
advisories and unsupported coverage. A passing compatibility check or advisory
rescan is not exploit reproduction.

For executable API setup and bounds, read
https://offense.sh/skills/purple/references/api-testing.md. For container acquisition
and migration, read
https://offense.sh/skills/purple/references/hardened-containers.md. Hosted artifacts
and targets keep the distinct contracts in
https://offense.sh/skills/purple/references/hosted-assessments.md.

The source/community edition remains on its publication hold. These public client
downloads do not authorize publishing the repository, an npm package, a customer
report or a new scanner image.
