# Offense

The independent dependency engine for **Offense**, the first product from
**Offense Security**. In your coding workflow: find vulnerable npm
and pnpm dependencies, check upgrade paths, rehearse a change and prepare a
repository-specific fix prompt.

The dependency engine runs locally and queries OSV and npm directly. Your coding
agent keeps its model, source checkout, repository connections, edits and tests.
No Offense account, GitHub App, Cloudflare connection or model key is required.

This **0.2.0 engine is available as source** in the `offense/` directory of
https://github.com/offense-research/offense. npm/package publication remains
on hold. Use the actual package directory in local client settings.

## Quick start

Requires Node.js 24 or newer and npm. From the checkout's `offense/` directory:

```sh
npm ci --ignore-scripts
node bin/offense.mjs doctor /absolute/path/to/application
node bin/offense.mjs scan /absolute/path/to/application --preview
node bin/offense.mjs scan /absolute/path/to/application --output /tmp/offense-report
```

Read `scan.json` for structured evidence and `remediation.md` for the prompt to
give your agent. Scanning does not edit the application, install its packages,
execute its scripts or open a PR. A complete executable checkout is needed for
source review and testing; lockfiles alone support dependency analysis.

This is a source release. The commands above run this checkout; they do not
depend on a globally installed or separately published npm package.

## What is included

| Capability | Command / behavior |
| --- | --- |
| Dependency inventory and advisory matching | `scan`; npm v2/v3 and pnpm v6/v9 lockfiles, with explicit coverage gaps |
| Coordinated upgrade paths | Plans review available targets, parent dependencies, peers and release changes; blockers remain visible |
| Repository remediation prompt | `remediation.md` includes findings and the available checked plans |
| Function-level evidence | `triage --scan ...`; bounded local applicability and reachability analysis |
| Upgrade rehearsal | `rehearse --scan ... --sandboxed`; matching baseline/candidate checks and a final rescan in an existing isolated environment |
| Local source/workflow checks | `source-scan`; separately installed pinned Opengrep and Zizmor |
| Sandbox API testing | `api-test`; an explicitly built local image and synthetic application, with Internet access disabled during testing |
| Hardened container bases | `hardened-image`; explicit acquisition using existing Docker access and a digest-pinned migration proposal |
| Agent integration | Project skill and stdio MCP tool `offense.audit_dependencies` |

Use `node bin/offense.mjs --help` and each command's `--help` for options. Optional
tools report missing requirements; installing this package does not install
scanners, start containers, change client permissions or deploy an application.

## Install in a coding agent

Paste this into your agent:

```text
Install the local Offense engine for this project from the offense/ directory
of https://github.com/offense-research/offense or an equivalent local checkout.
The following paths and commands are relative to that package directory.

Inspect the README, LICENSE, docs/install.md and skills/offense/SKILL.md. Reuse an
existing equivalent installation; otherwise obtain this repository through the
agent's preferred authorized GitHub connection or CLI. Install its locked npm
dependencies with npm ci --ignore-scripts. Keep installation project-scoped and
preserve customized skills, unrelated instructions and existing MCP settings.
A hosted Offense connection is not equivalent to this local engine; preserve it
and use the distinct offense-community name for this local server. Preserve an
existing customized Offense skill; review the edition and skill namespace before
choosing an installation location.

Install skills/offense in this client's documented project skill directory and
record the actual absolute package entrypoint so the skill can invoke it. If
MCP is supported, merge a project-scoped stdio server named offense-community
that runs node /actual/absolute/package/path/bin/offense.mjs mcp. Verify initialization
and discovery of offense.audit_dependencies without invoking an audit. If MCP
cannot reload in this session, report that limitation and use the local CLI
when requested. No credentials, source upload or model key is required.

This task installs and verifies the capability only. Do not scan, fix, publish
or deploy the application. Finish by telling me to start a new coding-agent
session in this same project to load the skill and MCP configuration; give an
exact client restart step if one is needed.
```

See [client setup](docs/install.md). After installation or an update, **start a
new coding-agent session in the same project**. Then ask:

> Use Offense to find and fix my vulnerable dependencies.

The `purple` CLI and `purple.audit_dependencies` MCP tool remain compatibility
aliases. Existing `skills/purple` installations can be reviewed and migrated;
keep customizations and unrelated client settings. The report schema remains
`purple.audit.v1` for compatibility.

The agent reviews applicability, makes authorized changes, runs checks and can
prepare or publish a PR when requested. The MCP audit tool itself analyzes
metadata; it does not execute applications or change repositories.

## Optional hosted security tools

The separate `offense-hosted` client can use the service at https://offense.sh.
It is optional: local `offense scan` and `offense mcp` continue to use the
independent engine without a company account.

From this checkout:

```sh
node bin/offense-hosted.mjs login
node bin/offense-hosted.mjs tools
node bin/offense-hosted.mjs balance
node bin/offense-hosted.mjs topup
node bin/offense-hosted.mjs mcp install --client codex --project /actual/project
```

Use `--client claude` or `--client cursor` for those clients and `login
--no-browser` on a remote host. The human compares the displayed browser code
and approves the account. Credentials stay in the client's private configuration,
not in project instructions or MCP settings. Whop top-ups require human payment
approval; creating a checkout link does not grant credit.

Review the enabled tool's scope and maximum-price quote before a paid call.
An explicit spending ceiling and stable idempotency key bound the submission.
Source or artifact uploads require the selected repository's authorization;
never extract or forward another connector's token. Advisory matches and hosted
scanner signals still require applicability and verification evidence.

The local server uses `offense-community`, while the hosted proxy uses
`offense`, so new installations can keep both. The hosted MCP installer preserves
an existing `offense` entry. A local engine
entry does not provide paid hosted tools. Review the intended connection before
using `--replace-offense`, or register the hosted proxy under a distinct reviewed
name. Start a **new coding-agent session** after changing skill or MCP settings.
See [client setup](docs/install.md) for this distinction. The hosted service,
billing backend and production deployment are outside the community package.

## Data and execution boundaries

| Operation | External data flow |
| --- | --- |
| `doctor`, metadata and previews | Local inspection only |
| Dependency scan/planning | Sanitized dependency names and versions go to OSV; public package names go to the npm registry for release metadata |
| Source and reachability analysis | Source and reports remain local; optional scanners run as local processes |
| Rehearsal | Executes reviewed package-manager and repository checks in temporary checkouts inside the agent's existing sandbox; npm installation and rescanning use their documented public providers |
| Hardened image acquisition | Selected image references go to the existing Docker daemon/registry; no application source is uploaded by the helper |
| API testing | Explicit synthetic app execution in isolated local containers; no production target or real credentials accepted |
| Optional `offense-hosted` commands | Explicit API requests go to Offense; paid tools use the selected account, reviewed inputs and prepaid credit |

The local engine has no company-hosted analysis dependency, automatic update
callback, shared model account or leaderboard submission. Optional hosted-client
requests use the service's own account, data and usage policies. Reports may contain private
package names and local paths: review them before sharing. OSV/npm are external
services; this edition does not claim to be an air-gapped advisory database.

Advisory matches are not confirmed vulnerabilities. Static reachability,
compatibility checks, provider signatures and issue-specific security
reproduction are different evidence. Incomplete checks remain incomplete.

If a coding provider blocks an operation, follow [provider safeguards](docs/provider-safeguards.md).
The deterministic scan and planner make no model requests; a provider's model,
permissions and account policies still apply to the agent's later work.

## Development and releases

```sh
npm ci --ignore-scripts
npm test
npm run check
npm pack --dry-run
```

Default tests use synthetic fixtures and mocked advisory providers. The package
is marked private to prevent npm publication; this does not restrict the public
source license. Packaging checks do not authorize registry publication. Optional
scanner/container integration requires its separately installed tools. CI has
no production secrets or deployment permissions. See [the scope and release
plan](docs/open-source-plan.md), [contribution guidance](CONTRIBUTING.md) and
[security reporting](SECURITY.md).

Updates are manual through reviewed source snapshots or separately approved
package releases. The original private repositories remain private. Preserve customized
skills and project MCP entries when updating; start a new agent session after
installing the updated skill. Forks do not automatically download another
publisher's managed files.

## License

Project-owned code is Apache 2.0. Third-party code and separately installed tools
retain their upstream licenses. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[third-party notices](THIRD_PARTY_NOTICES.md). This release does not redistribute
prebuilt third-party scanner binaries or scanner images.
