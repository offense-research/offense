# Offense maintains Offense

This example uses the local Offense engine to audit this public repository and
prepare bounded dependency upgrades. It uses no Offense account, production
credentials, private registry, or paid Offense endpoint. The optional Hermes
repair step uses an operator-owned OpenRouter model credential.

## What runs

- **Offense dependency audit:** every PR, including forks. Installs a pinned
  scanner in a separate checkout, inventories all four npm lockfiles, compares
  base/head advisories and retains reports for seven days. Findings are advisory;
  missing coverage or provider errors fail. It does not install the target app.
  The orchestration is ordinary PR CI, so contributors can propose changes to it;
  it is not an unmodifiable security authority for its own workflow changes.
- **Offense dependency agent:** explicitly enabled on the default branch only,
  manually or daily at 09:23 UTC. Uses a separately pinned controller commit.
  No eligible high/critical patch/minor group means no repair/model/image build.
  Eligible runs attempt one coordinated group with up to two agent attempts and
  twelve turns each. Other findings remain in the report. Major, prerelease,
  downgrade and 0.x minor transitions need manual review.
- **Independent verification:** a second disposable container receives no model
  key and repeats the original baseline/candidate commands and local audit.
  The two containers run sequentially on one ephemeral read-only-permission
  Actions job; the model key exists only in the repair step's environment.
- **Publication:** a separate fresh job receives only a bounded JSON file bundle.
  It installs/runs no candidate code, verifies identity/policy/file hashes and
  freshness, rechecks the base, and creates a draft PR through GitHub's API.
  No merge, approval or deployment is automated.
- **Dependency runtime acceptance:** PRs affecting the runtime build the public
  image and exercise actual pinned Hermes with a synthetic loopback model and
  external networking disabled. A second acceptance scenario uses the real
  repository's four installs and six checks, a planted patch-upgrade compatibility
  failure, actual Hermes repair, a fresh credential-free verifier, bundle export,
  and the publisher with a GitHub API stub. Only advisory intelligence, model
  responses and GitHub transport are synthetic; npm artifacts and registry
  identity checks remain real. No provider key or model spending is required.

## CI gate and acceptance

`CI` owns the reusable audit, CLI and runtime workflows. Every PR (including
forks and docs-only PRs) gets `ci-gate`; it requires root/engine verification,
complete audit coverage and both platforms' CLI/Homebrew checks. Runtime changes
also require Docker acceptance. Runtime selection happens inside the workflow,
not in a workflow-level path filter, so an intentional skip cannot leave a
required check permanently pending. Missing, failed, cancelled or unexpectedly
skipped prerequisites fail the gate. Main pushes and manual CI runs always run
runtime acceptance. Feature-branch pushes do not duplicate PR CI, and new commits
cancel superseded PR checks. The paid agent still serializes without cancellation.

After this workflow is merged and its check is available, add **`ci-gate`** (GitHub
Actions) to the default branch ruleset's required status checks. Keep existing
review requirements. Adding a workflow job alone does not enable enforcement.

Run the same secret-free acceptance locally from a clean committed checkout:

```sh
docker build -f agent/hermes.Dockerfile -t offense-hermes:test .
node scripts/ci/dependency-acceptance.mjs --image offense-hermes:test --output /tmp/offense-acceptance-reports
```

The synthetic fixture exists only in a disposable clone. Its deliberate failure
must occur before repair; attempts to weaken its test or controller policy must
be denied. Both containers retain the production UID, capability, network and
resource limits, with a fresh restricted gateway for each phase. Only bounded
reports are retained. Invalid bundle controls must fail before any API request.
This does not validate paid-model quality or actual GitHub publication settings.

## Activate after merging

1. Merge the reviewed implementation and allow the normal CI, audit, and runtime
   acceptance workflows to pass. Do not enable paid runs to debug these checks.
2. Create an Actions environment named `offense-dependency-agent`. Restrict it to
   the repository's default branch. Add optional required reviewers for initial
   supervised runs. Store `OFFENSE_AGENT_MODEL_KEY` as an **environment secret**.
   Use a dedicated OpenRouter key with a provider-enforced spending limit. Never
   paste the value into a workflow, issue, PR, artifact, or chat.
3. Add these **repository Actions variables** (not secrets):

   | Variable | Value |
   | --- | --- |
   | `OFFENSE_AGENT_REPOSITORY` | `offense-research/offense` (forks use their own exact identity) |
   | `OFFENSE_CI_ENGINE_SHA` | Full reviewed implementation commit SHA on the default branch **after merge**, not the draft branch head |
   | `OFFENSE_AGENT_MODEL` | Explicit OpenRouter model ID approved by the operator |
   | `OFFENSE_AGENT_ENABLED` | `true` after setup |
   | `OFFENSE_AGENT_PUBLISH` | Leave unset initially; `true` enables scheduled draft PRs |

4. Run **Offense dependency agent** from the default branch with `publish=false`.
   Review the reports and bundle. A missing/invalid credential blocks a needed
   model call; deterministic successful upgrades need no model call.
5. For draft PRs, allow Actions to create PRs in repository/organization settings.
   Run again with `publish=true`, or enable `OFFENSE_AGENT_PUBLISH` for schedules.
   The publisher uses GitHub's ephemeral `GITHUB_TOKEN`; no PAT is needed.
   GitHub may require a maintainer to approve the resulting PR workflow runs.
   Local verification is not a substitute for those checks.
6. Review and merge the dependency PR yourself. Never give the bot a ruleset
   bypass. Update the controller SHA deliberately after reviewed improvements.

Forks inherit none of these values or credentials. The audit runs without a
model account. Repair remains disabled until the fork owner configures their own
repository identity, model, environment secret and controller pin. The workflow
will skip disabled/mismatched configurations. A valid runtime pin is mandatory;
there is no mutable `main` fallback for privileged repair or publication.

## Policy and verification

The trusted `.github/offense/dependency-policy.json` lists the four exact
lockfiles and full check matrix, including the nested engine. `cli/package.json`
and `sdk/package.json` are explicitly recorded as dependency-free distribution
manifests; adding dependencies to either blocks automation until coverage is
reviewed. Other missing inputs, symlinks and unexpected warnings stay failures.

Existing tests, CI, scripts, engine policy, registries and all files outside the
allowed manifests/locks and `src/`, `server/`, `shared/` remain protected. V1 does
not publish added regression tests automatically; a change needing those needs a
maintainer follow-up. All modified manifests preserve scripts and engines, and
registry lock entries require public npm HTTPS URLs and integrity digests.
The controller and publisher also compare each registry artifact with npm's
release metadata: the name, version, tarball URL and integrity must all match.
A lockfile cannot claim a patched version while downloading an older tarball.
Workspace links and unresolved registry entries require manual policy review.

The controller first installs without lifecycle scripts, then explicitly applies
the existing reviewed BugPatrol patch and generates Worker test sources. It runs
the same root build/tests and nested engine test/check commands on baseline and
candidate. The container loads its matrix from the pinned controller, not model
input. Re-verification and export reject missing/substituted installs or checks.
Integrity is checked after every command, before the next command can execute a
rewritten test. A broken baseline, stale input, edited tests, incomplete audit, new
advisory, changed base or failed check prevents publication. Runtime caps are not
a dollar spending guarantee; enforce the dollar budget at the provider.

The candidate uses the existing internal Docker network and restricted CONNECT
proxy. Controller/model processes and repository commands have separate users.
Nested checks retain the same restricted gateway. Executable test fixtures use
a private repository-user temporary directory in the job mount; the controller's
`/tmp` stays `noexec`, and no Docker socket is supplied to tests.
No Docker socket, host home, GitHub token or production credentials is mounted.
Only controller code receives the model credential over stdin. Reports and
candidate code are untrusted data. The model has scoped file tools; it does not
own commands, test results, permission policy or publishing.

## Artifacts, retries and failures

Only selected audit/review reports (seven days) and the successful bounded file
bundle (three days) are uploaded. Never upload the job directory, Git checkout,
model home, npm cache, or credential input. Public-repo artifacts are intended
for public review and contain public source changes. Do not adapt this recipe to
private inputs without reviewing retention/access and provider data policy.

Bundles bind repository, workflow run, controller SHA, policy hash, base SHA,
verification time and exact file bytes. Hashes detect changes; they are not a
signature or an independent security attestation. Publication accepts only the
artifact from this successful workflow run. It never uses `workflow_run` or
`pull_request_target` to promote a fork's artifacts into write access.

Concurrent repair runs serialize. A deterministic branch prevents overwriting
other runs or human edits; existing matching PRs are reported. If a network
response identifies an existing PR, it must still be an open draft targeting the
default branch with the exact verified file bytes, modes and parent commit.
Retargeted, edited, closed or ready-for-review PRs are not silently reused.
If a network failure occurs between branch creation and PR creation, the retry fails safely
on the existing branch: inspect it and create the draft PR manually, or remove
that unmerged bot branch before retrying. No force push is performed.

`ready_for_review` means compatibility checks and complete advisory rechecks
passed. It does not prove exploitability, application-wide security, or that a
paid model call occurred. The existing optional security-regression evidence
retains its distinct label. Review every deferred finding and maintenance warning.
