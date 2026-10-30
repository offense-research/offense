# Contributing a security tool

Use this guide to add or change a tool in Offense's catalog and public directory.
A listing describes supported behavior; it is not proof of working execution,
production availability or permission to run a scan.

The full-platform source release and supported self-hosting setup are still in
preparation. This guide does not change repository visibility or grant a new
license. Read [release preparation](release-preparation.md) for release boundaries.
Changes limited to the separate local engine follow
[`offense/CONTRIBUTING.md`](../offense/CONTRIBUTING.md); that package's license is
not a license for every component in this repository.

## Choose the smallest contribution

- **Correct an existing listing:** update its owning contract or reviewed display
  metadata. Verify against the implementation and upstream sources. Do not add a
  new tool ID, change prices or enable execution to fix descriptive text.
- **Add or expand an executable tool:** describe the contract below, then implement
  and verify it through the existing runner and shared API/CLI/MCP workflow.
  A directory-only entry is not an executable integration.
- **Add a local-only helper:** keep it out of the hosted inventory unless a hosted
  adapter also exists. Document installation, versions and actual data/network
  effects; do not infer local support from an upstream engine being installable.

For a new engine, network destination or coverage expansion, include the proposed
scope and license evidence for maintainer review before investing in a large
integration. There is no dynamic plugin loader or arbitrary-command registration.

## Describe the contract before the implementation

Include these facts in the proposal or pull request. They are review requirements,
not a new schema to paste wholesale into the static catalog.

| Fact | What to specify |
| --- | --- |
| Identity | Stable lowercase hyphenated ID, task-oriented name, upstream engine and version. Reuse an existing ID only if its contract remains compatible. |
| Coverage | Supported languages/formats/checks and explicit exclusions. Say whether results are findings, observations, provenance or advisory matches. |
| Input | Required fields, example synthetic input, byte/file/resource limits and rejected formats. State whether the tool must run alone. |
| Execution | Source/artifact, offline assessment, network assessment or mobile runtime; pinned engine, rules/templates and data revision. |
| Data and authority | What leaves the machine, retained output, credentials, network destinations, target ownership and any active-testing/live-verification consent. |
| Failure | Missing prerequisites, stale data, unsupported input, truncation, timeout and incomplete coverage behavior. None may silently become a clean scan. |
| Distribution | Upstream source and exact license/notice links for the engine, bundled dependencies, rules, templates and datasets separately. |
| Cost and operation | Execution budgets, proposed billing unit, refresh requirements and rollout prerequisites. A proposed price is not authorization to change the live rate card. |
| Evidence | Positive/safe fixtures, expected rule IDs or observations, normalized sample output, commands run and remaining unverified cases. |

Do not copy code under an assumed license. Preserve notices and identify any
source-distribution or network-use obligations for maintainer review. An engine's
license does not establish rights to its rules or hosted data; for example,
Scorecard engine licensing and published snapshot data licensing are distinct.
Never describe commercially restricted source as unrestricted Apache-2.0.

## Change the owning files, not generated copies

Read the closest existing integration first. Apply only the rows relevant to the
tool; a listing correction does not require an execution or billing rewrite.

| Responsibility | Source to inspect or extend |
| --- | --- |
| Hosted identity and coverage | [`shared/tool-catalog.js`](../shared/tool-catalog.js). Assessments belong in [`shared/assessment-tools.js`](../shared/assessment-tools.js), which the catalog already composes; do not duplicate their entries. |
| Input and job lifecycle | [`server/hosted-scans.js`](../server/hosted-scans.js), [`scan-input.js`](../server/scan-input.js), [`scan-artifacts.js`](../server/scan-artifacts.js), [`assessment-input.js`](../server/assessment-input.js) and [`workers/scan-container.js`](../workers/scan-container.js). Validate at the server/runtime boundary, not only in the CLI. |
| Source/artifact execution | [`agent/scan-runner.mjs`](../agent/scan-runner.mjs), the relevant adapter and [`agent/scan.Dockerfile`](../agent/scan.Dockerfile). Keep explicit supported-tool dispatch and fixed arguments. |
| Assessment execution | The private checkout uses `agent/assessment-offline.mjs`, `agent/assessment-network.mjs` and matching mobile/network/offline Dockerfiles. These runtimes/recipes are deferred from the minimal source export pending licensing review; see [release preparation](release-preparation.md). Generic egress remains in [`workers/assessment-egress.js`](../workers/assessment-egress.js). |
| Prices and enablement | [`config/scanner-prices.json`](../config/scanner-prices.json), [`server/scan-pricing.js`](../server/scan-pricing.js), [`server/scan-billing-config.js`](../server/scan-billing-config.js), [`server/assessment-config.js`](../server/assessment-config.js). Prepare reviewed source changes, not live secret/configuration edits. |
| Shared clients | [`server/offense-platform.js`](../server/offense-platform.js), [`server/offense-mcp.js`](../server/offense-mcp.js), [`scripts/offense-cli.mjs`](../scripts/offense-cli.mjs) and its imported helpers. Prefer the existing catalog/quote/call/result interfaces over a new MCP method per engine. |
| Directory descriptions | [`site/scripts/catalog.mjs`](../site/scripts/catalog.mjs) merges canonical names/coverage with [`site/src/catalog-descriptions.js`](../site/src/catalog-descriptions.js) and reviewed additions. Extend the applicable metadata location, not both. |
| Source/license and execution-mode copy | [`site/scripts/directory.mjs`](../site/scripts/directory.mjs): upstream mapping, data-boundary text and supported local helpers. New input families need explicit data/consent wording. |
| Client distribution | [`scripts/build-skill.mjs`](../scripts/build-skill.mjs) and [`scripts/build-offense-cli.mjs`](../scripts/build-offense-cli.mjs). Check which imported helpers are source versus generated output before editing. |

The free `dependency-audit` is composed separately by the landing catalog; do not
turn it into a paid scanner entry. Static directory pages must not hard-code live
prices or imply every deployment enables a tool. Category keys currently are
`dependencies`, `source`, `infrastructure`, `web` and `mobile`.

Do not hand-edit `site/dist`, `site/.cloudflare-build`, `cli/dist`, generated
downloads or the generated `site/dist/src/catalog.js`. The root build packages
clients once; the site copies those distributions and generates detail pages and
the sitemap. Update maintained documentation alongside changed contracts. Add
Offense source/contribution links to public pages only when their destination is
actually public, and local-run links only when that path is supported.

## Preserve the security and billing boundaries

- Treat submitted source/artifacts as data. Do not install their dependencies,
  execute their scripts or load user-controlled scanner configurations/plugins.
  Pin binaries and rules; verify release checksums where supplied and record
  database age separately from engine version.
- Keep offline jobs without egress. Network assessments use the controlled
  gateway, approved destinations, ownership checks and bounded budgets; never
  fall back to unrestricted networking. Do not accept caller-supplied executable
  paths, shell fragments or new credential destinations.
- Bound input, extraction, subprocess output, time, requests/connections and
  findings. Reject unsafe paths, symlinks and mismatched artifact identity before
  use. Preserve cleanup on failure as well as success.
- Normalize results with the existing contracts. Redact secret values and raw
  source from findings, errors and reports. Distinguish per-tool `complete` from
  job `completed`; retain explicit `partial`/`failed` results and coverage gaps.
  A finding is not a confirmed exploit, and a discovered endpoint is not a finding.
- Reuse authentication, quote caps, idempotency and reservations. Identical retries
  must return the same job without another charge; changed input with the same key
  must fail. Only completed jobs settle charges; partial/failed jobs release holds.
  Preserve tenant isolation and revoked-key rejection.

## Supply evidence that could reveal a wrong implementation

Reuse the existing tests and synthetic fixtures. Keep permanent tests focused on
observable contracts, not subprocess call order or private helper structure.

1. **Detection or observation:** run the pinned real engine against a known
   positive and a safe counterpart. Assert the expected rule/advisory identity or
   observation, not just a nonzero count. For provenance, include wrong signer,
   digest or tampered input rather than inventing a vulnerability expectation.
2. **Incomplete and hostile input:** cover relevant malformed/unsupported input,
   limits and missing/stale prerequisites. Show that timeouts and invalid reports
   cannot produce complete, zero-finding success. Exercise redaction on errors.
3. **Shared lifecycle:** use disposable local accounts/databases and fake job
   services for quote caps, same-key retries, failure release and tenant isolation.
   Check CLI/API/MCP report agreement when the integration changes those contracts.
4. **Discovery:** verify the ID and coverage in agent discovery and `/tools/<id>`.
   For visible changes, inspect desktop/narrow layouts, keyboard operation,
   search/category behavior and no-JavaScript navigation.

Useful starting tests are [`test/new-security-tools.test.js`](../test/new-security-tools.test.js)
for the shared lifecycle, [`test/scan-runner-tools.test.js`](../test/scan-runner-tools.test.js)
for runner behavior, and [`site/tests/build.test.mjs`](../site/tests/build.test.mjs)
for static discovery. The private checkout's `test/assessment-network.test.js`
is deferred alongside its network runtime. These do not replace real-engine evidence. Extend the
relevant family tests and fixtures rather than copying unrelated cases.

From the repository root, use Node.js 24+ and the locked dependencies:

```sh
npm ci
node --test test/new-security-tools.test.js test/scan-runner-tools.test.js
npm run build
npm test
npm --prefix site run test:browser
```

Add the changed adapter's focused tests to the commands above. The browser check
uses a local static server and blocks external/API traffic; set `PURPLE_BROWSER`
to an installed Chromium executable when the default path is unavailable.
Run `npm run build:worker` if runtime/Worker packaging changes. None of these
commands deploys the product. Default CI currently runs the root build and tests;
the browser and real-engine checks require separate execution.

For the original source-scanner family, `scripts/e2e-hosted-scans.mjs` is a local
API-to-Docker fixture using the prebuilt `purple-scan:local` image. It does not
cover every added tool or paid settlement. Inspect any E2E script before running
it: similarly named `*-live.mjs` scripts can use real accounts and hosted services.
Never use production credentials, customer inputs, paid scans or arbitrary public
targets as default tests. Any live acceptance requires separate approval of the
environment, account, target/credential scope, spend cap and cleanup.

## Pull request handoff and rollout

Use the [tool pull request template](../.github/PULL_REQUEST_TEMPLATE/tool.md)
for the contract, license review, verification evidence and rollout handoff.
Remove inapplicable sections or mark N/A with a reason; listing corrections do
not require new engine or billing runs. Record skipped checks explicitly.

After the template is merged into the repository's default branch, select it by
adding `template=tool.md` to the GitHub compare/new-PR URL query (`?template=tool.md`,
or `&template=tool.md` if a query already exists). Until then, copy the template
into the PR body. It is optional and does not replace the body for unrelated PRs.

Use the [G1–G6 acceptance contract](tool-acceptance-contract.md)
to report gaps honestly; historical counts and receipts are not current
availability guarantees. Do not attach tokens, customer code, private reports or
raw secret-bearing scanner output. Report sensitive vulnerabilities privately to
the maintainers rather than in a public issue or fixture.

Catalog changes alone do not make deployment safe. Source/artifact tools do not
share the assessment opt-in switch: coordinate their catalog, image and price-map
rollout. Assessments additionally require explicit `SCAN_ASSESSMENT_TOOLS_JSON`
enablement after their image and required egress path are verified. Follow the
[release boundaries](release-preparation.md) when preparing an operator-specific
deployment. The initial self-hosted profile does not enable assessment images.
Merging source is not authorization to deploy, change live prices, enable tools,
publish images/packages or remove the repository publication hold.
