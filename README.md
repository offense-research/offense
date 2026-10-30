# Offense

**Security tools for coding agents. Open-source software, optional paid hosting.**

Offense gives your coding agent dependency intelligence, source-code checks and
security-tool execution through a CLI, the Model Context Protocol (MCP) and an
HTTP API. Your agent keeps its model and development workflow: it reviews
findings, proposes changes and runs tests. Offense supplies the tools and evidence.

[Hosted service](https://offense.sh) · [Self-hosting](docs/self-hosting.md) ·
[Local engine](offense/README.md) · [Contributing](CONTRIBUTING.md) ·
[Report a vulnerability](SECURITY.md)

## What you can do

- **Find vulnerable dependencies.** Inventory npm/pnpm lockfiles, query OSV
  advisories and inspect upgrade options with the independent local engine.
- **Give your agent actionable context.** Produce structured findings and a
  repository-specific remediation prompt; use explicit triage and rehearsal
  commands when you need deeper evidence.
- **Check source and GitHub Actions workflows.** Run pinned Opengrep and Zizmor
  engines through the self-hosted API/MCP profile in isolated Docker containers.
- **Discover tools before running them.** Inspect coverage, supported inputs,
  availability and price quotes. A directory listing is not a promise that a
  tool is enabled on your deployment.
- **Use the same job workflow across clients.** Submit bounded jobs, retrieve
  results and preserve partial/failed outcomes through the CLI, MCP or HTTP API.

Offense is not an autonomous permission grant. A finding is not a confirmed
exploit, an advisory match is not proof of reachability, and a partial scan is
not a clean bill of health. Your agent remains responsible for reviewing changes
and obtaining authorization before active testing, paid calls or publication.

## Choose how to run it

| Mode | Best for | Requirements | Execution and cost |
| --- | --- | --- | --- |
| **Local dependency engine** | Auditing a project from your terminal or coding agent | Node.js 24+, npm; no Docker or Offense account for dependency analysis | Runs on your machine; queries public OSV/npm metadata; no Offense usage charge |
| **Self-hosted platform** | Running your own API, MCP endpoint and isolated source scanners | Linux amd64, Node.js 24+, npm, Git and Docker Engine | Your infrastructure; dependency audits, Opengrep and Zizmor enabled; Offense billing disabled |
| **Hosted service** | Using managed tool execution without operating the scanner infrastructure | An Offense account for authenticated tools | Runs on the service; enabled paid tools use quoted prepaid credit |

The local engine and self-hosted profile do not require an Offense subscription
or model-provider key. Advisory lookup still needs network access; “local” does
not mean an offline advisory database. You pay your own infrastructure costs
when self-hosting.

## Quick start: local dependency analysis

Use **Node.js 24 or newer**, npm and Git. This path does not start a server,
install Docker scanners or require an account.

```sh
git clone https://github.com/offense-research/offense.git
cd offense
npm --prefix offense ci --ignore-scripts

# Inspect the runtime and preview supported dependency inputs without network calls.
node offense/bin/offense.mjs doctor /absolute/path/to/your-project
node offense/bin/offense.mjs scan /absolute/path/to/your-project --preview
```

When you are ready to query OSV/npm and write a report:

```sh
node offense/bin/offense.mjs scan /absolute/path/to/your-project \
  --output /absolute/path/outside-your-project/offense-report
```

The scan writes **`scan.json`** for structured evidence and **`remediation.md`**
for your agent. It does not edit the target project, install its dependencies,
execute its scripts or open a pull request. Review reports before sharing them;
they can contain private package names and local paths.

The top-level repository and the nested `offense/` package have separate
dependency installations. The commands above install only the local engine.
See the [local-engine README](offense/README.md) for triage, upgrade rehearsal
and optional scanner helpers, each with its own prerequisites.

### Connect your coding agent

The local engine exposes `offense.audit_dependencies` over stdio MCP:

```sh
node offense/bin/offense.mjs mcp
```

Configure your client to launch that command using the **absolute path** to the
entrypoint; it is an MCP server, not an interactive terminal session. The
[agent setup guide](offense/docs/install.md) covers project-scoped MCP and skill
installation for Codex, Claude Code and other clients. Preserve existing client
configuration and start a new agent session after installing.

Once connected, try: **“Use Offense to audit this project's dependencies and
explain the upgrade options. Do not change files yet.”**

## Run the self-hosted platform

The initial profile runs the Node API and console with SQLite, a local operator
API key and isolated Docker scanners. It supports **dependency advisory analysis,
Opengrep 1.32.0 and Zizmor 1.31.1**. Other catalog tools remain disabled.

From the repository root on your own **Linux amd64** machine:

```sh
npm ci
npm run build
docker build -f agent/source.Dockerfile -t offense-source:local .
node scripts/init-self-host.mjs "$HOME/offense-state"
node --env-file="$HOME/offense-state/server.env" server/index.js
```

The bootstrap creates a **new private state directory outside the checkout**
and refuses to overwrite an existing installation. It stores the API key,
encryption key and database there without printing credentials. The server
binds to loopback on port 3217; it is not an Internet-ready multi-tenant setup.

Follow the [self-hosting guide](docs/self-hosting.md) to load the operator key,
configure CLI/API/MCP access, back up state and run acceptance checks. Allow at
least 2 GiB RAM per scanner plus memory for the API. Docker access is effectively
host-administrator access: use a dedicated environment and never expose the
Docker socket to clients.

**The operator key is for API/MCP access, not browser login.** Browser account
features require your own GitHub OAuth setup. Review the guide's reverse-proxy,
credential and isolation requirements before exposing the service beyond loopback.

## Use the hosted service

[Hosted Offense](https://offense.sh) operates the infrastructure and charges for
enabled hosted execution. From a checkout with root dependencies installed:

```sh
node scripts/offense-cli.mjs login
node scripts/offense-cli.mjs tools
node scripts/offense-cli.mjs balance
```

The [hosted agent setup](https://offense.sh/skill) and
[account/API guide](docs/offense-platform.md) cover client configuration and the
quote → submit → result workflow. Discovery and quotes do not themselves run a
paid scan. Review the input, target authorization and maximum charge before
submitting; paid calls require credit and explicit spending approval.

You can use the local engine without logging into the hosted service. Its MCP
configuration uses `offense-community`, while the optional hosted client uses
`offense`, so the two can coexist.

## Data and security boundaries

| Operation | What leaves your machine? |
| --- | --- |
| Local `doctor`, `metadata`, and `scan --preview` | Nothing; these inspect local inputs without network calls |
| Local dependency analysis | Sanitized dependency names/versions go to OSV; public package metadata is queried from npm |
| Self-hosted source scanning | Submitted source goes to your configured API and its local scanner containers, not the Offense hosted service |
| Hosted execution | The selected inputs go to the hosted service; review the tool's scope and data requirements before submitting |

Self-hosted source scanner jobs have no network access, host mounts or Docker
socket. They run as an unprivileged user with a read-only filesystem and bounded
resources. Submitted code is scanned, not executed. Optional rehearsal and API
testing helpers **do execute code** when explicitly invoked; use disposable
environments and review their separate contracts.

These controls do not eliminate kernel, scanner or configuration risk. Keep
engines current, protect operator credentials and scan only authorized targets.
Report vulnerabilities through [private security reporting](SECURITY.md), not
public issues containing source, credentials or raw scan reports.

## Repository guide

| Path | Responsibility |
| --- | --- |
| [`offense/`](offense/) | Independent dependency engine, local CLI, stdio MCP and agent skill |
| [`server/`](server/), [`shared/`](shared/) | API, authentication, tool contracts, job lifecycle and shared analysis |
| [`agent/`](agent/) | Scanner adapters, pinned rules and container build recipes |
| [`workers/`](workers/) | Cloudflare orchestration and execution boundaries; not a configured production deployment |
| [`src/`](src/), [`site/`](site/) | React console, landing site and public tool directory |
| [`scripts/`](scripts/), [`sdk/`](sdk/), [`cli/`](cli/) | Bootstrap/build tools, SDK and client sources |
| [`test/`](test/), [`docs/`](docs/) | Synthetic regression tests, setup guides and security contracts |

Some paths and schemas retain **Purple** names for compatibility. They are not
a separate product you need to install.

## Develop and contribute

From the repository root:

```sh
npm ci
npm run build
npm test

npm --prefix offense ci --ignore-scripts
npm --prefix offense test
npm --prefix offense run check
```

`npm run dev` starts Vite and the watched API for development; configure your
local environment first. Default tests use synthetic fixtures and mocked
providers. The Docker-backed `node scripts/test-self-host.mjs` check is opt-in
after building the source scanner image; it exercises real local engines, not
payments or production infrastructure.

Good contributions include clearer tool coverage, reproducible positive/safe
fixtures, scanner adapters, dependency analysis improvements and better setup
documentation. Start with [CONTRIBUTING.md](CONTRIBUTING.md). For tool changes,
read the [tool contribution guide](docs/contributing-tools.md) and use the
[tool PR template](.github/PULL_REQUEST_TEMPLATE/tool.md). Describe upstream
licenses, input limits, data flow and failure behavior—not just a tool name.

## Current release scope

This first release is **source only**. Other scanner adapters and
container recipes, where included, are unsupported reference source in this
self-hosted profile. The MobSF/SSLyze integrations and shared network/offline
assessment runtimes are deferred from this export pending licensing review;
catalog listings and project-owned rules do not imply an included runtime.
No scanner images, engine binaries, package archives or downloaded datasets are
included or approved for publication. Local build outputs are validation products,
not release artifacts. Source inclusion does not certify hosted GPL/AGPL compliance.

See the [release scope and verification record](docs/release-preparation.md)
for the exact exclusions and the initial snapshot's provenance.

## License

Included Offense-owned code and the identified original artwork are licensed
under **Apache-2.0**. You can use, modify, fork and commercially host that code
under the license terms. Paid hosting is a service, not a restriction on those
rights. The `private: true` npm flags prevent accidental package publication;
they do not make this source proprietary.

Third-party code, fonts, rules and data retain their own licenses, and trademark
rights remain separate. Read [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the boundaries and attribution.
