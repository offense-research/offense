<p align="center">
  <img src="site/public/social/offense-preview.jpg" alt="Offense — security tools for coding agents" width="100%">
</p>

# Offense

[![CI](https://github.com/offense-research/offense/actions/workflows/ci.yml/badge.svg)](https://github.com/offense-research/offense/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/Docs-Get_started-ff2e17?style=flat-square)](#documentation)
[![Discord](https://img.shields.io/badge/Discord-Join_the_community-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/xP7GCnyF)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square)](LICENSE)

[![Add Offense to your repo](https://img.shields.io/badge/Add_Offense_to_your_repo-Open_an_installation_PR-ff2e17?style=for-the-badge&logo=github&logoColor=white)](https://offense.sh/install)

**Security tools your AI agent can discover, call and verify.**

Offense is a product by **[Offense Research, Inc.](https://offenseresearch.com)**.
Open-source software, optional paid hosting.

Give Pi, OMP, Hermes, Codex, Claude Code, Crush or another coding agent the tools
to audit dependencies, inspect source and workflows, and test a proposed fix.
Offense returns structured security evidence through **CLI, MCP and HTTP**.
Your agent reads that evidence, investigates your code, makes authorized changes
and runs your tests—with its existing model, repository access and permissions.

[Open-source repository](https://github.com/offense-research/offense) ·
[Discord](https://discord.gg/xP7GCnyF) · [Hosted service](https://offense.sh) ·
[Self-hosting](docs/self-hosting.md) · [Contributing](CONTRIBUTING.md) ·
[Report a vulnerability](SECURITY.md)

**Start here:** [Give this to your agent](#give-this-to-your-agent) ·
[Add with a PR](#add-offense-to-your-repository-with-a-pr) ·
[Recipes](#recipes-from-the-landing-page) ·
[Install the CLI](#install-the-cli) ·
[Agent installation](#choose-your-agent) · [Choose a mode](#choose-how-to-run-it) ·
[Local quick start](#quick-start-local-dependency-analysis) ·
[MCP setup](#connect-your-coding-agent) ·
[Self-hosted platform](#run-the-self-hosted-platform) ·
[Documentation](#documentation) · [Troubleshooting](#troubleshooting) ·
[Community](#community-and-support)

## Add Offense to your repository with a PR

[**Add Offense to your repo →**](https://offense.sh/install)

Enter your GitHub repository and base branch. The installer opens GitHub's
prefilled workflow editor; review the file, choose **Create a new branch**, then
open a pull request. No Offense account, API key or GitHub token is required.
Offense prepares the link; you create and approve the PR on GitHub.

The starter adds **free npm/pnpm dependency audits on pull requests** using
pinned, read-only GitHub Actions. It never installs or runs your app, edits code
or calls paid Offense tools. Dependency metadata goes to OSV/npm; reports are
retained as GitHub artifacts for seven days. Advisories are report-only;
coverage warnings and scan errors fail the check. GitHub Actions usage limits
and charges still apply. This is a dependency check, not the full tool catalog.

[Review the template](site/public/templates/offense.yml) ·
[Manual installation, privacy and updates](docs/add-to-repository.md)

## Give this to your agent

Paste this into your coding agent **in the project you want to check**:

```text
Set up Offense for this project. Read the installation instructions at
https://github.com/offense-research/offense#install-the-offensesh-agent-skill
and review the skill at
https://raw.githubusercontent.com/offense-research/offense/main/.agents/skills/scanning-with-offense/SKILL.md

Reuse an existing reviewed Offense checkout or connection if available.
Otherwise inspect the public source before using its helpers. Install the
skill in this agent's project-local skill directory, preserving custom files
and other agent settings. Tell me if a new session or project trust is needed.

Run only the offline dependency-input preview. Show the selected lockfiles,
unsupported inputs and which execution mode would perform the real audit.
Do not upload data, run a paid scan, install the target project's dependencies,
edit application code, commit or push.
```

The first success is **a real preview and an explicit scope**, not “installed”
without a command result. The agent needs terminal/filesystem access and Node;
copying a skill does not give a chat-only client those capabilities. If it cannot
read GitHub pages, use the raw skill URL or a reviewed local checkout.

Already configured? Ask: **“Use Offense to check my app for security problems,
explain the findings and consequences, and help me decide what to fix.”** Offense
infers relevant checks from the project, reports missing coverage, and asks only
for the inputs or authorization those checks need. Assessment alone does not
authorize application edits or paid calls. Narrow dependency and local-only
requests keep their scope.

Start with one of the [task prompts](#ask-for-the-outcome-you-want)
below. Prefer manual setup? Use the [per-agent instructions](#choose-your-agent).

## Recipes from the landing page

### Codex plugin

The native plugin is built from the same maintained skill and CLI in this repo.
To try a local checkout with Codex:

```sh
codex plugin marketplace add /absolute/path/to/offense
codex plugin add offense@offense
```

Start a new Codex session, then ask `$offense:offense` to check your app and
explain the findings. Installing does not log in, scan, buy credit or register
MCP. The plugin reuses existing connections or its bundled CLI. Codex owns
updates; credentials stay in the CLI's private configuration. If you already
installed a manual Offense skill, choose which entry point to keep; customized
skills and project instructions are never removed automatically.

Once these files are published on the repository's default branch, the intended
remote registration is `codex plugin marketplace add offense-research/offense`,
followed by `codex plugin add offense@offense`. The local path has been smoke
tested; the remote command requires verification against that published ref.
Public OpenAI directory listing is a separate submission, not part of this build.

Put the examples on [offense.sh](https://offense.sh) to work. Each recipe includes
an agent prompt, prerequisites, commands, approval boundaries and the evidence
to return. Start with a single reviewed run before adding recurring automation.

| Build or run | Recipe |
| --- | --- |
| Your dependency bot / a pre-release audit | [Audit dependencies and verify reviewed upgrades](docs/recipes.md#dependency-audit-and-reviewed-upgrades) |
| Your first reviewer | [Review a PR with source evidence](docs/recipes.md#review-a-pull-request) |
| Your secrets guard | [Check staged or tracked contents without confusing the snapshots](docs/recipes.md#check-staged-or-tracked-secrets) |
| A SQL-injection review | [Trace request input, parameterize and test](docs/recipes.md#review-a-sql-endpoint) |
| Your CI reviewer | [Review Actions YAML without executing workflows](docs/recipes.md#review-github-actions) |
| Your API tester | [Exercise a disposable local API with bounded requests](docs/recipes.md#test-a-disposable-local-api) |

These are recipes for your agent, **not installed schedules, hooks or bots**.
Local scanners need their pinned engines; hosted Gitleaks needs availability,
upload approval and a spending ceiling. See the [shared setup and limits](docs/recipes.md#before-running-a-recipe).

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

## From a finding to a reviewed fix

See [From a finding to a reviewed fix](docs/recipes.md#from-a-finding-to-a-reviewed-fix).

### Ask for the outcome you want

See [Ask for the outcome you want](docs/recipes.md#ask-for-the-outcome-you-want).

### What your agent should read and return

See [What your agent should read and return](docs/recipes.md#what-your-agent-should-read-and-return).

### Export a PDF report locally

See [Export a PDF report locally](docs/recipes.md#export-a-pdf-report-locally).

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

## Install the CLI

See [Install the CLI](docs/cli-installation.md#install-the-cli).

### Homebrew — macOS and Linux

See [Homebrew — macOS and Linux](docs/cli-installation.md#homebrew--macos-and-linux).

### Stable GitHub release — Node.js 20+

See [Stable GitHub release — Node.js 20+](docs/cli-installation.md#stable-github-release--nodejs-20).

### Ubuntu and Arch Linux

See [Ubuntu and Arch Linux](docs/cli-installation.md#ubuntu-and-arch-linux).

### npx / npm exec — run without a global install

See [npx / npm exec — run without a global install](docs/cli-installation.md#npx--npm-exec--run-without-a-global-install).

### npm — install the command globally

See [npm — install the command globally](docs/cli-installation.md#npm--install-the-command-globally).

### pnpm or Bun — one-off execution

See [pnpm or Bun — one-off execution](docs/cli-installation.md#pnpm-or-bun--one-off-execution).

### From a reviewed checkout — no package manager install

See [From a reviewed checkout — no package manager install](docs/cli-installation.md#from-a-reviewed-checkout--no-package-manager-install).

### After installation

See [After installation](docs/cli-installation.md#after-installation).

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

### Local CLI reference

Run these from the repository root, replacing `PROJECT` with your target's path:

| Command | Purpose | Important boundary |
| --- | --- | --- |
| `node offense/bin/offense.mjs doctor PROJECT` | Inspect runtime and optional executable availability | Offline; does not prove an engine version, Docker connection or active MCP registration |
| `node offense/bin/offense.mjs metadata PROJECT` | Inspect sanitized dependency metadata | Offline; no report writes or application execution |
| `node offense/bin/offense.mjs scan PROJECT --preview` | Preview the dependency inputs before an audit | No provider requests |
| `node offense/bin/offense.mjs scan PROJECT --output REPORT_DIRECTORY` | Audit dependencies and prepare upgrade/remediation context | Queries OSV/npm; writes reports outside the target checkout |
| `node offense/bin/offense.mjs triage --help` | Learn how to investigate an existing report | Read the required scan inputs and coverage limits before use |
| `node offense/bin/offense.mjs rehearse --help` | Learn how to rehearse an upgrade | Actual rehearsal executes project commands and requires an isolated environment |
| `node offense/bin/offense.mjs source-scan --help` | Inspect local source/workflow scanning options | Actual scans require separately installed engines |

**Read both findings and coverage.** `scan.json` contains machine-readable
analysis; `remediation.md` gives your agent the evidence and next checks. A
proposed upgrade still needs compatibility tests. Zero returned findings apply
only to the checked scope and available advisory data—not every dependency,
code path or future vulnerability.

### Connect your coding agent

See [Connect your coding agent](docs/agent-setup.md#connect-your-coding-agent).

### Install the offense.sh Agent Skill

See [Install the offense.sh Agent Skill](docs/agent-setup.md#install-the-offensesh-agent-skill).

#### Hermes Agent — native skill installation

See [Hermes Agent — native skill installation](docs/agent-setup.md#hermes-agent--native-skill-installation).

#### Choose your agent

See [Choose your agent](docs/agent-setup.md#choose-your-agent).

#### Copy the skill without replacing custom instructions

See [Copy the skill without replacing custom instructions](docs/agent-setup.md#copy-the-skill-without-replacing-custom-instructions).

#### Make the existing helpers available

See [Make the existing helpers available](docs/agent-setup.md#make-the-existing-helpers-available).

## Run the self-hosted platform

The initial profile runs the Node API and console with SQLite, a local operator
API key and isolated Docker scanners. It supports **dependency advisory analysis,
Opengrep 1.32.0 and Zizmor 1.31.1**. Other catalog tools remain disabled.

**Self-hosting has no Offense billing.** The bootstrap disables both scanner
credit and hosted model billing automatically—no subscription, prepaid balance
or payment credentials required. You cover your own infrastructure costs.

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

Already configured? Keep these values in your private `server.env` and restart
the API after changes; do not recreate the state directory:

```dotenv
OFFENSE_SELF_HOSTED=true
SCAN_BILLING_ENABLED=false
WHOP_BILLING_ENABLED=false
```

Point your client at your own `OFFENSE_API_URL`, not `https://offense.sh`.
The [billing-off checklist](docs/self-hosting.md#billing-settings-and-verification)
shows how to verify zero-priced quotes and resolve inherited environment conflicts.
Use `--max-price 0` when submitting CLI calls to retain a zero-cost ceiling.

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

## CLI, MCP and HTTP at a glance

Choose the interface that fits your workflow, not a different set of security
claims. The **local engine** is separate from the **platform API**:

| Task | Terminal | Coding agent | HTTP / application integration |
| --- | --- | --- | --- |
| Local dependency audit | `node offense/bin/offense.mjs scan PROJECT` | Local stdio `offense.audit_dependencies` | No local-engine HTTP server is required |
| Local TCP exposure (unreleased) | `node scripts/offense-cli.mjs ports scan --target IP --ports 22,80,443` previews only | Run the CLI locally with explicit scope and permission | No API, login, upload or charge; not in CLI 0.2.0 |
| Inspect platform tools | `node scripts/offense-cli.mjs tools` | Platform `offense.security_tools` | `GET /v1/catalog`; availability is deployment-specific |
| Quote a platform job | Use the checked-out CLI's `--help` for the selected input family | `offense.security_quote` | `POST /v1/quotes` |
| Run a platform job | Select the tool and reviewed inputs with an explicit maximum charge | `offense.security_call` | `POST /v1/call/:tool` with an idempotency key and charge cap |
| Retrieve a platform result | Use the CLI's result command for the job ID | `offense.security_result` | `GET /v1/scans/:id` |
| Check account balance | `node scripts/offense-cli.mjs balance` | `offense.account` | `GET /v1/account` |

For [local port exposure](cli/README.md#local-port-exposure-unreleased), select one
literal IP and up to 256 TCP ports. Review the preview, then add
`--run --confirm-active-testing` only with permission. An optional
`--expected-ports` allowlist flags unexpected reachability without claiming
exploitability; timeouts remain unknown. Results describe your current network
vantage point, not necessarily public internet exposure.

Platform MCP uses the configured server's `/mcp` endpoint and appropriate
authentication. Never paste tokens into a chat, commit them to MCP configuration
or substitute another connector's credentials. Self-hosted billing is disabled;
hosted quotes and account access depend on the selected account and deployment.

For application-controlled checks, the [SDK guide](sdk/README.md) and
[agent integration guide](docs/agent-security.md) describe explicit lifecycle
hooks. Making a tool available through MCP does not force an agent to call it,
and configuring a policy does not automatically install a deployment hook.

## Data and security boundaries

| Operation | What leaves your machine? |
| --- | --- |
| Local `doctor`, `metadata`, and `scan --preview` | Nothing; these inspect local inputs without network calls |
| Local dependency analysis | Sanitized dependency names/versions go to OSV; public package metadata is queried from npm |
| Local `ports scan` (unreleased) | Preview sends nothing; an authorized run makes bounded TCP connections only to the selected IP/ports. Reports stay local. |
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

For maintained sources and generated copies, see [Find the owning files](CONTRIBUTING.md#find-the-owning-files).

Some paths and schemas retain **Purple** names for compatibility. They are not
a separate product you need to install.

## Documentation

| Guide | What it covers |
| --- | --- |
| [CLI installation](docs/cli-installation.md) | Hosted client installation methods, runtime requirements and release channels |
| [Agent setup](docs/agent-setup.md) | Local MCP connection, portable skills and helper setup |
| [Agent recipes](docs/recipes.md) | Landing-page examples with prompts, scoped commands, evidence and automation boundaries |
| [Local engine](offense/README.md) | Dependency analysis, triage, rehearsal and optional local helpers |
| [Agent installation](offense/docs/install.md) | Project-scoped MCP configuration, skills and client coexistence |
| [offense.sh Agent Skill](.agents/skills/scanning-with-offense/SKILL.md) | Portable instructions for scoped audits, hosted-tool approval and verified remediation |
| [Self-hosting](docs/self-hosting.md) | Bootstrap, Docker isolation, operator credentials, backup and recovery |
| [Hosted account and API](docs/offense-platform.md) | Sign-in, tool discovery, quotes, jobs, usage and billing contracts |
| [SDK](sdk/README.md) | Programmatic dependency analysis and hosted-scan client interfaces |
| [Agent-host integration](docs/agent-security.md) | Explicit lifecycle checks and the difference between tools and enforced gates |
| [Public tool directory](https://offense.sh/tools) | Tool coverage, inputs and execution-mode descriptions; not a live availability guarantee |
| [Tool contributions](docs/contributing-tools.md) | Adapter ownership, licensing, limits, fixtures and verification expectations |
| [Security reporting](SECURITY.md) | Private reports and information that must not go into public issues |
| [Release scope](docs/release-preparation.md) | Source-only boundary, provenance, verification and deferred integrations |
| [CLI releases](docs/cli-release.md) | Versioned client candidates, macOS/Linux Homebrew checks and publication approval |

## Updating and moving from an existing setup

Updates are deliberate source updates, not an automatic background updater for
the local engine. Inspect upstream changes and preserve your local modifications
before updating a checkout:

```sh
git status --short
git pull --ff-only
npm --prefix offense ci --ignore-scripts
```

Run the engine's checks after updating, and restart the coding-agent session so
it loads the current skill and MCP configuration. For the platform, follow the
[self-hosted upgrade procedure](docs/self-hosting.md#acceptance-upgrades-and-recovery):
stop the API, back up the database and encryption key together, rebuild and test,
then restart. A source pull alone is not a completed platform upgrade.

- **Already using the hosted Offense connection?** Keep it. Add the local engine
  under `offense-community`; do not overwrite the hosted `offense` entry.
- **Already using a Purple skill or CLI?** Legacy entrypoints and report schemas
  remain for compatibility. Review customized instructions before adopting the
  documented Offense entrypoints; do not delete unrelated client settings.
- **Coming from another coding agent?** Keep that agent's model, tools and
  project instructions. Add Offense as a skill/MCP capability using the client's
  supported setup. There is no automatic import of conversations, memories,
  credentials or model-provider settings.

## Offense in its own CI

The [dependency agent example](docs/dependency-agent.md) provides secret-free PR
audits and opt-in, isolated Hermes repairs with independent verification and
draft PR delivery. Forks configure their own model key; no Offense account or
production credentials are required.

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

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Dependency analysis cannot start | Confirm `node --version` is 24+ and install the nested package with `npm --prefix offense ci --ignore-scripts`; root dependencies are a separate install |
| Preview finds no supported dependency inputs | Point it at the application, not the report folder; the local engine supports npm lockfile v2/v3 and pnpm v6/v9, not every package manager or manifest-only project |
| The agent cannot see the MCP tool | Check the absolute entrypoint, project configuration and client trust prompts; start a new session and verify tool discovery |
| An optional scanner is missing | `doctor` checks executable availability, not installation; follow the helper's version requirements or build the supported self-hosted image |
| Self-hosted bootstrap refuses the state directory | It intentionally refuses an existing directory or one inside the checkout; use a new external directory for a new installation, and preserve existing state for upgrades |
| A self-hosted catalog tool is unavailable | Only dependency audits, Opengrep and Zizmor are enabled in this profile; a directory entry does not enable a runtime |
| The web console asks you to sign in | The local operator key enables API/MCP access only; browser account features need an operator-owned GitHub OAuth app |
| A result is partial or a provider request fails | Retain the coverage warning or error, check the stated limit/provider requirement and retry only the affected scope; do not reinterpret it as a clean scan |

For upgrades, backups, key revocation and Docker isolation, use the
[self-hosting guide](docs/self-hosting.md). For agent-specific setup, use the
[local installation guide](offense/docs/install.md).

## Frequently asked questions

**Do I need an Offense account or an AI API key?**
Not for local dependency analysis or the supported self-hosted profile. Your
coding agent uses its own model and permissions. Authenticated hosted tools use
an Offense account; paid execution also needs credit.

**Is everything in the tool directory available when I self-host?**
No. The catalog describes more tools than the initial self-hosted profile enables.
Some adapters are reference source, and the deferred assessment runtimes are
not included. Check availability on your deployment and the release scope above.

**Can I use this commercially or operate my own hosted version?**
Yes, under Apache-2.0 for the included project-owned code. Preserve required
notices and comply with separately licensed components. The license does not
grant access to Offense's infrastructure, accounts or trademarks.

**Will it automatically fix and push changes?**
No. The dependency audit produces evidence and recommendations. Your agent can
make changes when authorized; rehearsal, testing, commits and publication are
separate actions, not side effects of an audit.

**Why are some files still named Purple?**
They preserve existing integrations, command aliases and report schemas. Use
the documented Offense entrypoints for new installations.

## Community and support

- **[Join the Discord](https://discord.gg/xP7GCnyF)** for setup questions,
  workflow discussion and feedback on tools you would like to contribute.
- **[Browse the open-source repository](https://github.com/offense-research/offense)**
  to inspect the implementation, fork it or follow development.
- **[Open a GitHub issue](https://github.com/offense-research/offense/issues)** for
  reproducible bugs or concrete feature requests. Include the revision, runtime,
  execution mode, expected/actual behavior and a minimal sanitized reproduction.
- **[Contribute a tool](docs/contributing-tools.md)** with its coverage, license,
  input/data boundaries and positive/safe test evidence. Discuss substantial
  new integrations before investing in a large implementation.

**Do not post vulnerabilities, credentials, customer source or raw security
reports in Discord or public issues.** Use
[private vulnerability reporting](https://github.com/offense-research/offense/security/advisories/new)
and follow [SECURITY.md](SECURITY.md). Community support has no guaranteed response
time or security-support SLA.

---

Built by **[Offense Research, Inc.](https://offenseresearch.com)** and
contributors. Offense integrates independently maintained security engines and
public advisory sources; their licenses and attribution remain in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
