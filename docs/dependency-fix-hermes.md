# Dependency fixes with Hermes

Purple's first Hermes workflow takes a clean npm/pnpm checkout and a pinned advisory scan through coordinated dependency updates, bounded application-code repair, independent verification, and a reviewable PR handoff. Hermes is the default coding engine for this new workflow. Existing Pi investigations remain available on their current production path while the new runtime is evaluated; no production runtime or customer repository has been migrated automatically.

## Commands

Requires Node 24, Docker, the existing repository dependencies, and access to the approved package/advisory/model endpoints. Build the dedicated image:

```
npm run build:hermes
```

Use an existing authorized provider connection to obtain a checkout if the repository is remote. Do not create a broader GitHub connection just to scan. Preserve uncommitted work: the fix command requires a clean committed repository root.

```
npm run dependencies:scan -- /absolute/path/to/repository
npm run dependencies:fix -- /absolute/path/to/repository --repository owner/repo
```

The repository argument identifies the intended future PR destination; it does not grant write permission or publish anything. `--scan /path/to/scan.json` reuses a fresh matching completed scan. The wrapper creates a clean Git snapshot without ignored/untracked files, then runs the actual fix in Docker. Your original checkout is not mounted into the container or changed. The output directory must be a new empty directory outside the source, including after resolving symlinked parents.

Supply `OPENROUTER_API_KEY` through an existing secret manager. For example, after Infisical has been connected:

```
npm run secrets:run -- dev node scripts/offense.mjs dependencies fix /path/to/repository --repository owner/repo
```

A model credential is needed only if application-code repair calls Hermes; deterministic successful upgrades and scans with no high/critical targets do not need a model call. The default model is `qwen/qwen3.7-flash`; choose `--model` or `PURPLE_FIX_MODEL` explicitly to change it. Attempts default to two (maximum three), with twelve model turns per attempt (maximum twenty), bounded model outputs and a twenty-minute outer execution limit. Unknown provider costs are not invented or charged to a Purple wallet.

The package also exposes `offense dependencies ...` when installed as a CLI; from this checkout, the npm commands or `node scripts/offense.mjs` need no global installation.

## What the workflow does

1. Bind the complete scan to the committed revision and dependency-file fingerprint. Stale scans, incomplete coverage, uncommitted source and missing executable checks block the fix.
2. Keep every advisory in the checklist. High/critical findings are targeted by default; other severities remain explicitly deferred. Deduplicate shared upgrades, coordinate checked parent/child changes, and keep missing/conflicting targets visible.
3. Reuse the existing rehearsal runner for baseline installs/checks and the initial dependency candidate. Preserve the chosen npm/pnpm manager, strict peer and engine requirements, and lifecycle-script restrictions.
4. If the candidate needs code changes, invoke Hermes with dependency evidence and actual failed checks. It may inspect code, patch code and add new regression files; existing tests, script entrypoints, package scripts and manager/engine policy remain protected. Attempts are bounded; model claims are never verification evidence.
5. Clear ignored artifacts, regenerate affected locks through the package manager, perform frozen installs, run the original checks independently, and rescan the entire supported resolved dependency tree. Clearing ignored files prevents an uncommitted generated helper from making an incomplete patch appear to work. Failed checks, remaining target findings, new advisories and unavailable/incomplete scans prevent a publishable result. Independent fixes and partial patches remain available when another finding is blocked.
6. Write `fix.json`, `fix.md`, `upgrade.patch`, `pr-body.md` and `pr-handoff.json`. Reports include the pinned commit, original/candidate source fingerprints, patch digest, all advisory outcomes, command results, runtime revision, repair attempts and verification limits.

A result is `ready_for_review`, `partial`, `blocked`, or `no_changes`. Ready means the recorded compatibility/advisory conditions passed, not that the application is vulnerability-free or that every advisory was exploitable. If a suitable new security regression contract is supplied, the separate existing observer runs the same regression against original/patched code and applies gate v2. Only qualified evidence changes the verification label to `security_regression_verified`; unsupported test frameworks or missing reproduction stay explicit.

Deprecated dependency or parent targets set `needsMaintainerReview` and carry the upstream warning in the checklist, report and draft PR. An advisory-free result does not make a deprecated release an upstream recommendation. Such handoffs require a draft PR and human review before merging.

## Independent verification and PR delivery

Re-run verification without any model call:

```
npm run dependencies:verify -- --report /path/to/job/fix.json
```

This rejects altered evidence and runs the same baseline/candidate checks plus a fresh rescan inside the container. New evidence is saved separately; the earlier report is preserved.

Re-verification establishes current compatibility and advisory evidence. Any earlier exploit regression result is retained as historical evidence, with its original timestamp; it is not relabeled as a newly executed security test.

Review the patch, checklist and PR body. To authorize publishing through an already authenticated `gh` connection:

```
npm run dependencies:publish -- --report /path/to/job/fix.json \
  --repository owner/repo --branch codex/dependency-fix --authorize-publish
```

Publishing is handled by the trusted host controller, after Hermes and repository commands exit. It verifies report/patch/body/checkout digests, evidence freshness and the unchanged GitHub base commit. It creates a branch, commit and **draft PR** through GitHub's API, reuses matching publication on retry, refuses conflicting branches, and never merges. Missing write access is an explicit blocker. The scan app stays read-only; GitHub write credentials are not passed to the coding or verification sandbox.

Check actual PR CI separately:

```
npm run dependencies:pr-status -- --report /path/to/job/fix.json
```

Pending, unavailable, incomplete or absent CI results are not a pass. Local checks and PR CI are separate evidence. Approval is required before merging.

## Runtime and isolation

- The image pins Hermes source commit `27c61463814f27ada4c2d5625a8839ed51f01f41`, frozen Python dependencies, Node 24, pnpm 10.34.5, and uv 0.13.4. Its preflight checks the supported embedding interface and pin. The user's installed/custom Hermes CLI and personal profile are not used.
- This Hermes revision includes the upstream Pillow 13.0.0 security fix and its explicit `uv.lock` override for browser-harness's older Pillow pin. Keep the frozen lock: do not repair that intentional metadata mismatch by downgrading Pillow or bypassing unrelated dependency conflicts. The image installs core dependencies only (`--no-dev --no-install-project`, no extras); optional packages in the upstream lock are not evidence that they are installed. Reassess dependencies before enabling additional Hermes features or extras.
- Python embeds `AIAgent` with exactly four Purple-owned tools: bounded list/read/write/exact patch. No terminal, browser, messaging, memory, plugins, skills, context-file autoloading, delegation or publishing tools are registered. Per-turn temporary Hermes state is removed after the call. A model may write only candidate files and its bounded plan output; it cannot alter the orchestrator's verdict.
- Model credentials arrive through the controller's stdin, never Docker command arguments, a mounted control file, or a repository subprocess environment. Repository installs/checks receive a curated environment without model, GitHub, Whop, Infisical or other platform credentials. The Python controller receives its model key explicitly; estimates are labeled unverified and excluded from billing.
- Each job has a separate container with a read-only root, no privilege escalation, resource/process/time limits and bounded output. The trusted controller uses only the capabilities required to switch repository commands to a separate user, manage checkout ownership and stop leftover processes. Repository installs/tests run as UID 1001 with no capabilities. Controller evidence, Git control files and model credentials stay outside that user's writable boundary. Ignored `.env` files and the user's home/credentials are not mounted.
- The job joins a dedicated Docker **internal network**. A separate trusted proxy, with no source or credentials mounted, provides HTTPS tunnels only to `registry.npmjs.org`, `app.purpleteam.sh`, `api.osv.dev`, and `openrouter.ai` on port 443. The proxy checks the CONNECT destination, public DNS address and visible TLS server name. Encrypted HTTP headers and payloads are not inspected; approved services remain intentional egress destinations. Cleanup removes the job, proxy and private network on completion, failure, timeout or interruption.
- Review checkouts and command outputs remain in the selected local output directory so independent verification and publishing can detect edits. Those artifacts contain repository source and may contain source snippets; remove the job directory after review when no longer needed. No platform credential is supplied to repository processes.

## Reproducible acceptance checks

After building the image, run:

```
npm run test:hermes
npm run test:dependency-fix
npm test
```

The first check exercises the pinned Hermes core against a synthetic loopback model with external networking disabled. The full acceptance check uses a committed vulnerable lodash fixture, real registry resolution/installs and OSV-backed rescans through the restricted gateway. The synthetic model repairs an API removed by the upgrade. Purple then reruns the original tests, writes the patch and PR handoff, and independently verifies the saved candidate without another model call. Artifacts remain in the printed temporary directory. Neither check uses a real model credential or publishes a PR.

## Rollout and current limits

This is a local CLI + pinned-container implementation. It does not replace the hosted web simulation button or production Pi image. A hosted rollout must reuse the same isolated tools, job-state boundaries, permission checks, limits and independent verification, and then pass staging fixtures before switching traffic.

No real model-provider inference, customer PR, customer scan, production deployment or automatic merge is required by the synthetic acceptance checks. The previously configured hosted OpenRouter credential was rejected; a valid credential must be supplied before a real model run can be validated. Runtime/transport tests use a loopback synthetic model and distinguish that from model quality or benchmark evidence.

The next validation milestone is the agreed ten-repository benchmark. Measure attempted/remaining advisories, upgrade/API-migration success, original/candidate checks, actual PR CI, model cost when provider-confirmed, time and human intervention. No benchmark success rate is claimed from fixture tests.
