# Purple hosted skill

The new `/skill` build leads with [Offense's capability install](offense-api.md). For the existing advanced Purple workflow, open **Advanced Purple workflow** and copy its separate prompt into a coding agent with a filesystem and terminal. The Agent Skills package remains at `/skills/purple/SKILL.md`; download every supporting resource listed in that prompt. The parsers are bundled with their license notices; no runtime npm installation is required for scanning. Install in the agent's project skill directory. Ordinary ChatGPT connector access alone does not provide a shell or persistent skill installation; use a connected coding environment. See the Offense guide for the new build's release status.

After installation, start a **new coding-agent session in the same project** to load the installed skill and any MCP configuration. The install page, copied prompts and skill setup instructions all state this step explicitly. If the client also needs an application or extension restart, the installer must give its exact steps. A successful helper or separate MCP probe during installation does not establish active-session readiness.

In the new session, **Copy fix workflow** provides the complete “Use Purple to find and fix my vulnerable dependencies” request: discover, prioritize, remediate, verify and deliver a draft PR with evidence. The coding agent uses its existing model, repository connections and sandbox; the separate Docker/Hermes runner is optional. An Offense-only installation can use its MCP/HTTPS audit and local source review without downloading the advanced Purple helpers.

The full copied request explicitly asks for a draft PR. Installation and initial-scan prompts still stop at their stated result. The [delivery reference](../public/skills/purple/references/delivery.md) requires a verified candidate, an outcome for every advisory, exact check/rescan evidence, preferred authorized connection reuse, duplicate prevention and actual PR/CI readback. Missing access or incomplete verification produces a reviewable patch with the concrete blocker. A clean advisory scan with passing compatibility checks is distinguished from a security regression that fails before and passes after the fix.

The repository remains private. Publicly served instructions and the thin client are readable by anyone installing the skill; the scanning and upgrade-planning implementation runs on Purple's hosted API. No open source license is introduced by this release.

## Skill updates

Each normal installed helper run checks the public `manifest.json` at its fixed `https://app.purpleteam.sh/skills/offense/` or `/skills/purple/` location. For native MCP-only work, the skill instructs the agent to invoke its installed `scripts/update.mjs --skill offense|purple` first. Help and preview stay offline. The version check sends no repository files, hashes, credentials or dependency metadata; scans send their separate sanitized dependency payload as before.

Release manifests list managed file paths, sizes and SHA-256 checksums, plus bounded historical hashes. The updater records the installed baseline in `.skill-install.json` within that one skill directory. It promotes a complete verified release only when every managed file is unchanged or a known untouched legacy file. Unknown/custom files block promotion; the complete release is staged under `.skill-updates/` for review and the working installation remains intact. Unrelated instructions, application files, and MCP/client configuration are never rewritten.

After reviewing and merging a staged release, run `node scripts/update.mjs --skill offense --accept-local` (or `purple`). The receipt keeps customized files marked as custom so later updates cannot overwrite them. This command acknowledges a reviewed merge; it must not be run automatically to silence a warning.

Updates use atomic file replacements, an installation lock and a rollback journal. Checksum/download failures leave active files unchanged; replacement failures roll back prior replacements. Interrupted transactions recover before another automatic update; concurrent user edits are preserved and may require review. Path traversal, symlinked managed paths, unreviewed destination types, reused release versions and automatic downgrades are rejected. This verifies release consistency under the trusted HTTPS publisher, not an independent signing authority.

Applied or accepted updates exit **4**, stopping the current run before scan work and telling the user to start a new session in the same project. Exit **3** requires retrying after another update or reviewing recovery. A standalone check/update exits **2** for pending review or a check failure. Automatic network-check failures warn and retain the existing installation; they are reported separately from actual advisory scan results. No downloaded code is executed by the updater.

Existing installations without the updater need a one-time refresh from the install prompt. Merely starting a new session does not download it. Fresh installations inspect the updater, verify the release and record baseline hashes before normal use. Global skill directories are never selected implicitly.

## Agent workflow release 0.4 / 1.8

The public page names the product Purple and identifies Offense as its dependency capability. Generic dependency-security requests route to the installed skill. The read-only `offense.mjs doctor /repository` command reports managed-file presence, project configuration observations, public MCP initialization/tool discovery, and active-session readiness separately. Only the coding agent can observe its actual callable tool list. A saved config or a successful HTTP probe does not prove the current session loaded the tool.

The Offense helper retains the original full scan and automatically continues bounded planning pages (up to ten pages, with a shared three-minute request deadline). Pages bind to the same normalized fingerprint and stable package/version target IDs, recheck only selected targets, and detect shared-parent/root conflicts across the combined plan. Limits, truncated paths, upstream failures, real constraints and changed advisory evidence have distinct follow-up actions. Interrupted planning retains the last successful local report and continuation instead of claiming completion.

Local preparation inventories unsupported ecosystems, uncovered manifests and dependency patches without adding them to the hosted payload. Optional `--evidence` records are reviewed local artifacts bound to the current clean candidate, exact advisory/package, dependency fingerprint, patch and installed-file hashes, and matching normal/security check evidence. Git identity uses read-only listings and direct raw-file hashes so metadata collection never executes repository-defined clean filters. Runtime, behavior and mocked-test coverage changes stay explicit. These records never suppress original advisory matches or increment hosted confirmed-vulnerability counts.

Live release verification uses synthetic public fixtures only: official MCP, equivalent HTTP, downloaded helper, multi-page planning, public browser installs, and a one-time old-skill update. Existing installations still need one refresh to acquire the updater, followed by a new session. The narrowly scoped Browser Integrity Check exception is separately approval-gated; its proposed configuration is in `config/cloudflare-agent-clients.json`.

## Connection choice

The skill uses the user's or agent's preferred existing provider connection, including Composio, native connectors, MCP servers, authenticated CLIs, and local tools. It does not bundle a Composio SDK or mandate a connector. The host agent discovers and invokes its own tools, preserving the requested repository and provider account. It can fall back to another already authorized connection when the preferred tool lacks an operation or fails, and requests only the remaining missing capability. Connector tokens are never extracted or sent to Purple.

An existing checkout is sufficient. Without one, the agent can use its preferred GitHub connection to resolve a commit, enumerate files with pagination, and download supported lockfiles at that commit into a temporary directory. The existing helper scans this dependency snapshot without a full clone. The agent records repository/commit provenance locally and reports incomplete listings and missing files. Source inspection and test execution require additional source/runtime capabilities; a lockfile snapshot does not establish that those are available. Cloudflare context uses the preferred Cloudflare connection only when relevant to the task. Tool access does not authorize unrelated cloud changes or PR publication.

## Data flow

1. The helper reads npm v2/v3 package-lock/npm-shrinkwrap and pnpm v6/v9 lockfiles locally, skipping node_modules, build output, hidden directories, and symlinks. Shrinkwrap takes precedence over package-lock in a directory. pnpm workspaces, links within the lockfile root, aliases, catalogs, transitive dependencies and peer-context snapshots are represented in the graph. Other formats, unresolved references and missing importers are explicitly reported as coverage gaps. YAML aliases and duplicate keys are rejected. Registry resolution URLs, integrity values and scripts are never serialized.
2. A shared allowlist strips source, lifecycle scripts, repository names, remotes, resolved URLs, hashes, arbitrary package fields, and non-registry constraints. Only dependency names/versions/ranges, relative lockfile/package paths, and development flags are sent. Private package names can appear in this metadata. `--preview` shows the payload without a request.
3. `POST /api/skill/scan` performs an exact-version OSV check. `POST /api/skill/plan` checks one selected package against OSV and reuses Purple's existing planner and handoff generator. Each request includes the sanitized files, so no anonymous scan session or provider credential is needed.
4. Plans and advisory findings are returned to local `scan.json` and `remediation.md` files, in a private temporary output directory by default. A local SHA-256 fingerprint binds the lockfiles, package manifests and pnpm workspace settings to that report without uploading their raw contents. The initial scan does not edit application files, execute repository code, create PRs, or deploy.

## Coordinated rehearsal

`node /installed/purple/scripts/purple.mjs rehearse /isolated/repo --scan /path/to/scan.json --sandboxed`

The host agent must provision its preferred isolated environment before this command. `--sandboxed` is an acknowledgment, not sandbox creation or attestation. The checkout must be clean and committed, and the scan fingerprint must match. The repository's declared package-manager version must already be installed. A downloaded lockfile snapshot is insufficient for test execution.

The helper combines checked targets and required parent upgrades, blocks conflicting targets, creates pinned baseline and candidate clones, performs frozen installs, executes existing test/typecheck/build scripts, resolves the candidate lockfile, checks target coverage, and scans the entire resulting tree. Repository subprocesses receive a minimal environment without provider keys; package lifecycle scripts and pre/post hooks are disabled. No blanket pnpm override is introduced. Catalog/workspace range migrations are explicit blockers for the agent to inspect and implement separately. Source migrations and vulnerability-specific regression tests remain agent work.

Artifacts: `upgrade.patch`, `rehearsal.json`, `rehearsal.md`, `candidate-scan/`, and `handoff.md` combining the repository's upgrade plan, rehearsal evidence, and diff. The original checkout is untouched. The JSON retains baseline failures, candidate checks, final advisories, newly introduced advisories, the commit and fingerprint. Exit status is 0 only for `tests_passed`, 2 for completed rehearsals with blockers, and 1 for an operational failure. These results are compatibility evidence and never count as verified vulnerability discoveries. The agent reviews the handoff and patch before applying changes under the user's requested scope.

pnpm scanning/planning works in both the hosted dashboard and skill. pnpm rehearsal currently runs through the skill in the agent's sandbox. The dashboard points pnpm repositories to that flow instead of requesting an OpenRouter key for the npm-only hosted simulation image.

## Bounds and isolation

The API is registered before browser sessions and account authorization; it does not create cookies, access customer workspaces, or accept provider credentials. Cross-origin browser requests are rejected. Ingestion host routing still rejects it.

Requests are capped at 2 MB, 20 lockfiles, and 5,000 package entries. Anonymous access uses durable minute/hour quotas: 40 requests/minute and 100/hour per hashed client IP; 600/hour globally; two in-flight requests per app instance. Counter rows expire and are cleaned on subsequent requests. These counters survive instance restarts. Metadata analysis bounds upstream work to 90 fetches with a 90-second deadline and each existing provider request has a 20-second timeout. Streamed upstream responses are capped at 12 MB each and 24 MB total per request. Dependency path traversal is bounded. No model tokens or sandbox containers are billed by these endpoints.

Incomplete upstream checks return errors. Plans without a checked fix return blockers. The CLI preserves its scan report after a planning failure, marks omitted plans when its 30-plan limit is reached, and never represents those findings as fixed. Advisory metadata and passing repository tests alone do not establish exploitability or verified remediation.

Anonymous scans do not enter the authenticated workspace discovery metric. Counting untrusted client assertions as verified vulnerabilities would invalidate that metric. Account attribution and evidence-backed submission from external agents are future work; this release does not claim them.

## Development

`PURPLE_API_URL=http://127.0.0.1:3217 node public/skills/purple/scripts/purple.mjs scan /path/to/repo`

Use `--preview` to inspect metadata, `--plan-limit 0` for advisory-only checks, and `--output /path/to/report` to retain reports at a chosen location. No external dependencies are installed by the helper.

`npm run build` and `build:worker` regenerate the distributed helpers and release manifests before bundling the app. `npm run build:skill` runs that preparation alone. It bundles the shared updater for both skills and computes hashes after all generated files are complete. Bump the skill's version for every published change; a deployed version must never acquire different managed-file hashes. Keep known released hashes in `scripts/skill-release-history.json`; unknown historical/custom files are staged instead of overwritten.

To repeat the pnpm workspace integration checks with real OSV/npm requests:

```sh
docker build -t purple-skill-e2e:pnpm-10.32.1 test/fixtures/pnpm
node scripts/e2e-skill-pnpm.mjs
node scripts/e2e-skill-pnpm.mjs --baseline-failure
```

The test container receives curated fixture files and read-only helper/API bundles, with dropped capabilities, a read-only root filesystem and bounded resources. No provider keys or production secrets are passed. The first test checks a two-project workspace upgrade and patch; the second verifies a failing baseline produces a blocked result and exit code 2.

Skill format: https://agentskills.io/specification. Client project directories are client-specific; Codex uses `.agents/skills`, Claude Code `.claude/skills`, and Pi `.pi/skills`. An explicitly requested initial scan may run from the downloaded instructions; always finish installation by telling the user to start a new session in the same project before invoking the installed skill for their next task.

Use curl or Node fetch to download the skill package. Both were tested against production; Cloudflare browser integrity checking rejects the default Python urllib client with error 1010. The copied install prompt selects the tested download clients, and the scan helper itself uses Node fetch.

## Hosted source security scans

The optional [hosted scan workflow](hosted-scans.md) runs Opengrep, Trivy and Gitleaks against an explicit source upload. It uses workspace scan keys and durable jobs, separately from the anonymous metadata-only dependency endpoint. Download `scripts/hosted-scan.mjs` alongside the other skill resources. See the workflow guide for quotas, source retention, supported rules and verification.

## Hardened container bases (Purple 1.12)

The advanced package includes `scripts/hardened-image.mjs` and [the hardened-container reference](../public/skills/purple/references/hardened-containers.md). Requests such as “Use Purple to get a hardened container for this application” stay in the current coding workflow. The helper previews the selected Dockerfile locally, then an explicit `--pull` acquires a selected DHI, public Chainguard or Google Distroless base through the existing Docker CLI/context and registry authentication. No new Purple connection, source upload, credential-store access, registry login or hosted API is added.

Successful acquisition records the requested reference, matched registry digest, inspected platform and bounded configuration metadata. A local receipt and migration prompt retain compatibility blockers. A candidate Dockerfile is a proposal for the selected stage, not a tested migration. The coding agent separately verifies provider signatures/attestations and runs matching baseline/candidate builds and meaningful application checks before applying a migration. A hardened base does not establish that application dependencies are vulnerability-free.

The advanced install prompt includes both new resources, and the release manifest preserves the previous 1.11 hashes for safe updates. Customized installations still stage the complete update for review. After applying an update, start a new agent session in the same project before continuing.

Purple 1.12 is live at [the skill installer](https://app.purpleteam.sh/skill). Production verification covers exact download checksums, the downloaded helper's offline preview, desktop/phone copy behavior, and real pristine/customized 1.11-to-1.12 updates. See [deployment evidence](e2e/hardened-containers-production.json). App health confirmed the matching release; the existing agent/scanner deployment was preserved.
