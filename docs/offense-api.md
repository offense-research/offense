# Offense dependency security capability

Offense supplies security intelligence to the user's existing coding agent. The agent retains repository access, source review, patching and test execution. The initial capability is `audit_dependencies`; OSV supplies known-advisory evidence and the existing Purple planner checks npm release/parent/peer metadata. The interface does not expose a scanner-specific request shape. Additional providers and automatic provider selection are not implemented.

## Release status and installation

This capability is deployed at [app.purpleteam.sh/skill](https://app.purpleteam.sh/skill). The API, MCP endpoint, install page and Offense skill resources are live together. The production verification record is `docs/e2e/offense-capability-production.json`.

The `/skill` page has a primary **Copy prompt** action for Offense. Paste it into Codex, Claude Code, Cursor or another compatible coding environment. It installs a project-scoped skill and configures the remote MCP server using the client's supported mechanism, preserving other settings. It verifies initialization and tool discovery, or explains that a restart is required. An install-only request does not start a scan or edit application files. Clients without remote MCP can use the standalone HTTPS helper for the same capability. Configuration alone is not proof of a connected server.

The existing advanced Purple install prompt remains in a disclosure on that page for function reachability and deterministic upgrade rehearsals. Existing Purple `/api/skill/scan` and `/api/skill/plan` clients keep their wire format and share the new controller's work limits.

Install resources:

- `/skills/offense/SKILL.md`
- `/skills/offense/references/install.md`
- `/skills/offense/scripts/offense.mjs` — standalone Node 20+ helper, with its parser bundled.

The user can then ask: “Check my dependencies for security issues and fix anything critical.” The agent honors that scope, audits the current repository, inspects relevance, and carries out authorized changes. Preferred connections such as Composio, native connectors, MCP, authenticated CLIs or an existing checkout are reused. No Purple account, GitHub App installation, Cloudflare permission or model key is required.

## API and MCP

The deployed `0.6.0` release adds SDK/CLI downloads and lifecycle policy metadata to capability discovery. Repository automation is managed separately through the authenticated workspace dashboard. Before-deployment, after-deployment and agent-operation checks are invoked by the host, rather than scheduled by the anonymous audit API. See [automation settings](security-automation.md) and [agent integrations](agent-security.md). The [latest production app record](e2e/latest-app-production.json) verifies this release.

`POST https://app.purpleteam.sh/api/offense/audit` accepts the same arguments advertised by the MCP tool `offense.audit_dependencies` at `https://app.purpleteam.sh/mcp`:

```json
{
  "files": [{"path": "package-lock.json", "content": "sanitized lockfile JSON"}],
  "planLimit": 3
}
```

Prepare that argument object locally with the installed helper. The server accepts content; it cannot open the caller's local file paths. Never upload raw lockfiles or connector credentials. Unknown top-level fields are rejected.

```sh
node /installed/offense/scripts/offense.mjs metadata /path/to/repo
node /installed/offense/scripts/offense.mjs audit /path/to/repo
node /installed/offense/scripts/offense.mjs audit /path/to/repo --preview
```

The helper strips registry URLs, integrity data, package scripts, repository identity and unsupported credential-bearing constraints before sending. Dependency names, exact versions, supported ranges and relative paths can include private package information and are sent as metadata. Source files, `.npmrc` and connector credentials are not read for the upload. Preview makes no request. Symlinks, unsupported managers, directory/search limits and missing lockfile importers remain local coverage warnings. Manifest-only projects require a resolved lockfile for this initial capability.

`planLimit` defaults to 3, accepts 0–10 and prioritizes higher severity package/version pairs **per response**. Zero requests advisory scanning without planning. Every omitted, failed or constrained path remains explicit. Reports are saved outside the source checkout as `audit.json` and `remediation.md`; a failed request does not overwrite a saved report.

### Continue planning without repeating the full scan

The first full audit returns `remediation.planning` with fingerprint-scoped target identities, the attempted and remaining IDs, and `next`. Send `next` unchanged as the next request's `planning` field, with the same sanitized files and a positive `planLimit`:

```json
{
  "files": [{"path": "package-lock.json", "content": "the same sanitized lockfile JSON"}],
  "planLimit": 3,
  "planning": {
    "metadataFingerprint": "<64-character fingerprint from the original report>",
    "pendingTargetIds": ["<target IDs from remediation.planning.next>"]
  }
}
```

The continuation rechecks only the next selected installed packages against the advisory provider and plans those targets. It does not rerun the full dependency advisory scan or repeat already-attempted targets. IDs are bound to the exact normalized dependency fingerprint, package and version. Changed metadata, foreign IDs, duplicates, an empty cursor and a zero planning limit are rejected. A caller may explicitly select a known target for separate review, but this never establishes full-tree coverage.

Continuation responses have `remediation.planning.scope: "planning_continuation"` and `coverage.planningOnly: true`. **They must not replace the original full audit.** The standalone helper merges successful pages using `mergeAuditContinuation` from `shared/offense-planning.js`, retaining original findings, counts, scan time and coverage. It removes deferred-work blockers only for attempted targets, retains real failures, and checks shared-parent and root-declaration conflicts across all retained pages. Its combined remediation prompt contains every original advisory and the resulting paths and blockers. Changed provider evidence is recorded separately and requires a fresh full scan rather than receiving fix or discovery credit.

The helper bounds the total number of pages and elapsed time. If a later page fails or its bounds are reached, save prior successful progress and the remaining cursor as a partial result. Native MCP callers should follow the same merge rules; they can continue with the cursor through the same `offense.audit_dependencies` tool. A failed planning target is removed from automatic pending work while its concrete blocker remains; retry that target deliberately rather than creating an endless automatic retry loop. No server-side report, repository identity, cursor or source content is stored.

The standalone planning flags and resume behavior are described by the downloadable helper's `--help`. A continuation is not a final security rescan: after applying changes, run a fresh full audit against the final resolved tree.

`GET /api/offense/capabilities` publishes service version, continuation support and input/output JSON schemas. The code contract lives in `shared/offense-schema.js`. API and MCP responses expose server-generated `X-Offense-Request-Id` and `X-Offense-Version` diagnostics; incoming request ID headers are never trusted or echoed. Cloudflare may additionally supply its edge request ID. These identify a request and deployed service version, not a repository or user.

MCP uses the official SDK, stateless Streamable HTTP with JSON responses, current protocol negotiation and no session cookie. It exposes one read-only tool, not file access or a patch executor. GET/SSE and background tasks are not offered. It validates configured Host and Origin, MIME/version negotiation, input and result schemas. Tool errors use text content with `isError: true`, without a structured error object that would violate the advertised success schema and hide the diagnostic. The Worker forwards `/mcp` to the API; both APIs are registered before login and after the ingestion-host restriction. Vite development proxies `/mcp` and `/api` to the local API.

## Structured report and confidence

Responses use `schemaVersion: "offense.audit.v1"` and contain:

| Field | Meaning |
| --- | --- |
| `status` | Complete or partial for the requested analysis; never a security attestation. |
| `providers` | Evidence provider and capability provenance. |
| `metadataFingerprint` | SHA-256 of sorted normalized dependency files; not a source revision or Git commit. |
| `coverage` | Checked/skipped packages, supported managers, warnings and unassessed source reachability. |
| `findings` | Stable package/version/advisory identities, normalized/provider severity, source references, affected ranges and advisory-listed versions. |
| `summary` | Advisory counts and checked metadata paths; confirmed vulnerabilities remain zero. |
| `remediation` | Checked paths, parent/root/peer constraints, blockers, verification steps and a copied agent prompt. |

Every finding starts with `relevance.status: "needs_review"` and `verification.status: "advisory_match"`. A lockfile cannot establish vulnerable-function reachability, attacker control, deployed exposure or exploit reproduction. Development/transitive scope does not dismiss a finding. Unknown provider severity remains unknown; MODERATE normalizes to medium while retaining provider severity.

Findings also include an advisory-derived `impact` object (`schemaVersion: 1`): a plain-English consequence, possible business impacts, exposure prerequisites, suggested triage priority, next steps and source references. `impact.applicationExposure.status` remains `not_assessed`; this explanation does not increase the finding's verification status or change provider severity. Explicit advisory titles and provider CWE metadata select bounded explanations. Unclear evidence receives a generic review explanation instead of an invented attack scenario. The dashboard derives the same explanation for older saved findings, and remediation prompts recompute it from advisory metadata rather than accepting caller-supplied impact text. See [the explanation rules and limits](vulnerability-impact.md). This addition is included in the deployed 0.6.0 release.

Summary counting units are explicit: `advisoryMatches` counts package/version/advisory matches; `distinctAdvisoryIds` counts provider IDs (whose aliases can overlap); `distinctCves` counts CVE aliases actually present; `affectedPackageVersions`, `affectedLockfiles`, and `affectedPackageLockfileLocations` distinguish package versions from file locations. The last count is not a count of installed dependency instances. `summary.provenance` records metadata-only known-advisory evidence, with no source review, reproduced exploit, applied fix, new-vulnerability discovery or PR attribution. Merging planning pages never increments the original scan's advisory/discovery counts. Confirmed vulnerabilities remain zero for this capability, regardless of tests or plans reported by the caller.

`advisoryListedFixedVersions` are advisory-specific candidate versions, not safe recommendations. A `path_checked` plan has a rechecked target and no known unresolved metadata constraints; `compatibilityVerified` is still false. Conflicting targets for a shared installed parent, truncated paths, unknown constraints, missing parent upgrades or peer conflicts produce review blockers. A mitigation is proposed, not applied or verified. Separate installed versions may coexist; they are not automatically conflicts.

Every checked plan includes `targetSelection` explaining the selected target and earlier checked candidates that still had advisory matches or unresolved peer requirements. Blockers have a machine-readable `code`, `category`, `retryable` flag and actionable `nextAction`. Deferred `plan_limit` work, `graph_truncated`/`candidate_limit` evidence gaps, `provider_failure` operational problems, `dependency_constraints`/`peer_constraints`, and `no_checked_fix` require distinct handling. A truncated graph is not evidence of incompatibility; an unavailable registry is not proof that no maintained parent exists.

The fingerprint is embedded in the remediation prompt as `evidenceIdentity`, with an explicit notice that no Git commit or source was supplied. The helper validates that a response fingerprint matches the metadata it sent. Agents must confirm that metadata and checkout still match before acting, record passing normal checks before/after, inspect advisory prerequisites and rescan the final resolved tree. The prompt requires disclosure of runtime floors and behavior/test-fixture changes, independent checks for behavior replaced by mocks, and patch integrity plus a security regression for a claimed local mitigation. The capability runs no model or repository commands and never counts a match as a confirmed exploit fix.

## Bounds, errors and attribution

The legacy skill, REST and MCP share durable quotas: 40 work requests/minute and 100/hour per hashed IP, 600/hour globally, and two executing analyses per controller. REST/MCP route switching does not create additional execution slots. Anonymous reports are not stored in customer workspaces and do not enter the confirmed-discovery metric or leaderboard. Expiring hashed quota counters, short-lived privacy-safe diagnostics and separate count-only daily usage aggregates have different retention boundaries. [Operator skill usage](operations-metrics.md#anonymous-skill-and-mcp-usage) records audit outcomes and returned match occurrences without retaining reports, source or identities.

Requests accept at most 20 supported lockfiles, 5,000 entries and 2 MB of normalized metadata. One entire audit, including all planned packages, shares 90 upstream requests, a 90-second deadline, 12 MB per response and 24 MB aggregate provider bytes. Upstream hosts are restricted to HTTPS OSV/npm registry endpoints. Workers-compatible `redirect: manual` and explicit rejection of 3xx responses prevent redirects. No provider URL or API key can be selected in request arguments.

An advisory provider failure returns an error with no clean report. Successful scans survive subsequent planning errors as partial reports. HTTP uses structured `{error:{code,message}}` responses and 400/413/429/502/503 as appropriate; MCP returns protocol or tool errors. Coverage warnings keep the report partial even if there are zero returned matches. No vulnerabilities returned means no known matches in the checked scope at that time.

## Verification

```sh
npm run build:skill
node --test test/offense-api.test.js test/offense-mcp.test.js test/offense-install.test.js test/hosted-skill.test.js
node scripts/e2e-offense.mjs
node scripts/e2e-offense.mjs --live-providers
```

The default end-to-end test installs the downloadable helper into a temporary directory and exercises real HTTP/MCP handlers and parsing/planning with fixture provider responses. The live variant submits only a dedicated public semver 7.5.1 fixture to OSV/npm, finds CVE-2022-25883 and checks the 7.5.2 target. It never submits this repository's dependency tree or accesses production workspaces. Both leave the fixture unchanged and run no model or package scripts.

The deployed service passed the same public fixture through an official MCP SDK client, the HTTP API and a freshly downloaded standalone helper. All three returned matching metadata fingerprints and advisory identities, a checked 7.5.2 path, no blockers and zero confirmed vulnerabilities. Production desktop/phone checks verified installation copying, fallback selection, preserved advanced Purple resources and existing signed-in repositories.

MCP compatibility is also tested using an actual official SDK client. The Worker dry run verifies the Web Standard transport and Worker-compatible JSON-schema validator bundle without deploying. Browser acceptance verifies copying, complete resource availability, clipboard fallback, advanced Purple compatibility and phone layout.

Protocol references: [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools). Client-specific configuration references are maintained in the install resource.
