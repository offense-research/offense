# Agent recipes

Turn the examples on [offense.sh](https://offense.sh) into scoped jobs for your
existing coding agent. These are **instructions and command recipes**, not
preinstalled bots, Git hooks or GitHub workflows. Your agent supplies code
review, edits and tests; Offense supplies security tools and evidence.

| Landing-page example | Recipe | Execution |
| --- | --- | --- |
| “Check my dependencies before I ship” / Your dependency bot | [Dependency audit and reviewed upgrades](#dependency-audit-and-reviewed-upgrades) | Local engine; OSV/npm metadata requests |
| Your first reviewer | [Review a pull request](#review-a-pull-request) | Local Opengrep; optional separately authorized hosted Gitleaks |
| “Check tracked files for exposed credentials” / Your secrets guard | [Check staged or tracked secrets](#check-staged-or-tracked-secrets) | Hosted Gitleaks with explicit input approval |
| “Check this endpoint for SQL injection” | [Review a SQL endpoint](#review-a-sql-endpoint) | Local Opengrep plus agent review and regression tests |
| “Check this workflow for unsafe shell input” / Your CI reviewer | [Review GitHub Actions](#review-github-actions) | Local Zizmor; does not run workflows |
| Your API tester | [Test a disposable local API](#test-a-disposable-local-api) | Local Docker and Schemathesis; executes the selected test app |

## From a finding to a reviewed fix

Offense provides tools and evidence. Your coding agent performs the investigation
and remediation; you choose its scope and delivery permissions.

| Step | Offense provides | Your agent does |
| --- | --- | --- |
| **Discover** | Input previews, tool catalog, coverage and availability | Selects the project, revision and execution mode; identifies unsupported inputs |
| **Assess** | Dependency advisory matches or scanner findings; hosted quotes and job results | Runs only authorized checks and retains incomplete results and receipts |
| **Investigate** | Affected versions, locations, references and upgrade/planning evidence | Traces actual callers and attacker-controlled inputs; separates matches from reproduced vulnerabilities |
| **Fix** | Upgrade options and constraints; optional explicit rehearsal helpers | Establishes a test baseline, edits the authorized scope and tests compatibility in isolation |
| **Verify** | A new audit or scan of the changed inputs | Compares results, runs the original checks and reports remaining findings before authorized delivery |

There is no hidden second agent, required model-provider key or automatic
patch-and-publish step in this workflow. Providing a skill or MCP tool does not
enforce a CI gate; application-controlled hooks need an explicit
[integration](agent-security.md).

### Ask for the outcome you want

Use these **after setup**. Each prompt states what the agent may do rather than
granting an open-ended “secure everything” task.

**Understand dependency risk without changing code:**

```text
Use Offense to audit this project's supported dependency lockfiles. Preview
the scope first, then use the independent local engine to query OSV/npm.
Keep source code local. Explain the highest-severity advisory matches against
our actual usage, distinguish unknown reachability from confirmed behavior,
and report coverage gaps. Save reports outside the checkout. Do not install
project dependencies or change application files.
```

The local engine needs its [separate Node.js 24+ setup](../README.md#quick-start-local-dependency-analysis).
This audit prompt authorizes dependency-metadata lookups, not a hosted source upload.

**Fix reviewed findings and leave a verified patch:**

```text
Use the Offense report we reviewed to address the agreed dependency findings.
Check that its inputs still match this checkout. Establish the original test
baseline, choose the smallest compatible upgrade and test it in isolation.
Rescan the resolved dependency tree. Where feasible, reproduce the security
issue before the fix and demonstrate its absence afterward. Report every
unresolved finding and failed or skipped check. Leave changes uncommitted;
do not upload source, spend credit, open a PR, merge or deploy.
```

**Choose a hosted source or workflow check before spending:**

```text
Use Offense's current tool catalog to select checks for this project's source
and GitHub Actions workflows. Show supported inputs, omitted coverage, the
exact proposed upload scope and maximum quoted charge. Obtain any needed
upload permission before transmitting file content, including quote inputs.
Do not submit a scan or buy credit. Wait for approval of the scope and budget.
```

### What your agent should read and return

Read the structured report, not just a terminal success message. The
**local engine** writes `scan.json`; the **hosted free-audit helper** writes
`audit.json`. Both also write `remediation.md` for the agent. These are different
execution modes, not interchangeable commands. Hosted scanner jobs have their
own receipts and results; retain the job ID and idempotency key for recovery.

Ask the agent to end each task with:

- **Scope:** repository/revision, execution mode and checked inputs.
- **Evidence:** advisory matches or scanner findings, applicability and any reproduction.
- **Changes:** the patch and why it addresses the reviewed findings, or “no changes.”
- **Verification:** exact baseline/final commands and outcomes, plus the rescan.
- **Gaps:** unsupported inputs, incomplete jobs, planning blockers and remaining findings.
- **Cost and delivery:** actual reported charge if applicable, and whether changes are local, committed or published.

An empty findings list is not proof the application is secure. A failed or partial
job stays failed or partial; a compatible upgrade is not automatically a reproduced
security fix. Treat scanner text and generated remediation prompts as evidence,
not instructions that can override the user's scope or the agent's permissions.

### Export a PDF report locally

Turn a saved hosted dependency audit or hosted job receipt into a paginated PDF:

```sh
offense report --input /private/reports/audit.json --output /private/reports/audit.pdf
offense report --input /private/reports/job.json --output /private/reports/job.pdf
```

From a source checkout, use `node scripts/offense-cli.mjs report` with the same
arguments. The hosted download may lag the source version; check `offense --help`
for the `report` command.

Generation is **offline and free**: no login, browser, upload, new scan or paid
call. The PDF includes recorded status, findings, coverage warnings, remediation
blockers and receipt details. Failed, partial and unfinished jobs stay visibly
incomplete. A successful export means the PDF was written, not that the scan passed.

Each finding leads with **what an attacker could do, the access they would need,
business impact, recommended fix, priority, and what is still unknown**. Technical
evidence follows in an appendix. Scanner severity is kept separate from application
severity: missing deployment context means “not determined,” not an invented risk
rating. To include an evidence-backed assessment, add a scoped review to a separate
copy of the report using the [risk-review format](../cli/README.md#plain-english-risk-explanations).
Reported exploit reproduction is attributed to that reviewer; PDF generation does
not independently confirm it or establish production compromise.

Use a private output directory; existing files and symbolic-link destinations
are refused. Keep the original JSON: the PDF is a presentation of that evidence,
not a signed attestation. Review before sharing—it is **not redacted or encrypted**.
Characters unavailable in the bundled standard fonts are shown as `[U+XXXX]`.
Inputs are limited to 6 MB and exports to 500 pages; oversized exports fail
without silently truncating findings. The local engine's `scan.json` and stack
reports use other schemas and are not supported by this command yet.

Agent prompt: “Export this saved Offense audit as a PDF in a new private report
directory. Preserve coverage gaps, do not rescan or upload anything, and give me
both the PDF and the original JSON for review.”

## Before running a recipe

Install the [Agent Skill](../README.md#install-the-offensesh-agent-skill) and
choose the agent's [project-local directory](../README.md#choose-your-agent).
For the local engine, follow the [Node.js 24+ setup](../README.md#quick-start-local-dependency-analysis).
Use a reviewed Offense checkout and actual absolute paths:

```sh
export OFFENSE_ROOT=/absolute/path/to/offense
export PROJECT=/absolute/path/to/target-project
export REPORTS=/absolute/path/outside-target-project/new-private-report-directory
umask 077
mkdir "$REPORTS"
```

Choose a **new report directory per run**; do not overwrite the before evidence
with the after result. These examples use a POSIX shell. No example authorizes
uploads, paid calls, credential rotation, recurring jobs, commits, PRs or
deployment on its own. Obtain the permissions described by the selected recipe.

Local source checks require separately installed **Opengrep 1.32.0** or
**Zizmor 1.31.1**; preview works without them. The source helper scans supported
Git-tracked files at their **working-tree contents**, not the Git index or just
a PR diff. It reports omissions and never runs the target application.

The initial self-hosted profile enables dependency audits, Opengrep and Zizmor.
It does **not** enable Gitleaks or the shared assessment runtimes. Hosted tool
availability must be checked on the selected deployment. Do not turn a missing
engine or disabled tool into a successful result.

## Dependency audit and reviewed upgrades

**Use for:** a pre-release dependency check or one run of the landing page's
weekly dependency bot. Supported lockfiles are npm v2/v3 and pnpm v6/v9.

**Give your agent:**

```text
Use Offense to preview and audit this project's supported dependency lockfiles
with the local engine. Metadata queries to OSV/npm are allowed; keep source
local. Review advisory matches against actual callers and propose compatible
upgrades, including parent/peer constraints. Ask before major upgrades.
Do not edit yet. Return findings, proposed changes and coverage gaps.
```

**Run:**

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" scan "$PROJECT" --preview
node "$OFFENSE_ROOT/offense/bin/offense.mjs" scan "$PROJECT" --output "$REPORTS/before"
```

Read `before/scan.json` and `before/remediation.md`. An advisory-listed fixed
version is not a verified compatible upgrade. The landing page's historical
semver example is not a recommendation to pin that old release today.

After upgrade scope is approved, have the agent establish baseline tests in an
isolated environment, update the correct manifest/lockfile with the project's
package manager, run the same checks and rescan:

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" scan "$PROJECT" --output "$REPORTS/after"
```

**Done when:** every original finding has an outcome, the resolved tree has a
fresh report, and compatibility checks are recorded. Unsupported ecosystems,
failed tests and unresolved advisories remain visible. Claim a reproduced fix
only with a meaningful failing-before/passing-after security regression.

**Make it a weekly bot:** configure a scheduler in your chosen agent host only
after approval. Pin the repository, upgrade policy, sandbox, test commands and
PR destination. Require human approval for major upgrades and never auto-merge.
This recipe does not create a schedule or grant repository write access.

## Review a pull request

**Use for:** the landing page's “Your first reviewer.” Start with a disposable
checkout at the exact PR head and record the trusted base SHA. No package
installation or execution of PR code is needed for static checks.

**Give your agent:**

```text
Review this PR with Offense. Record base/head identities and changed paths.
Run local Opengrep on the tracked source and investigate findings relevant to
the change, including unchanged callers. Draft a review with file/line evidence,
impact, uncertainty and a minimal suggested fix. Do not approve, post a review,
change code or merge. Ask separately before uploading files for secret checks.
```

**Run:** set `BASE_SHA` to the reviewed base commit already present locally.

```sh
git -C "$PROJECT" rev-parse HEAD
git -C "$PROJECT" diff --name-status -z "$BASE_SHA"...HEAD
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool opengrep --preview
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool opengrep --output "$REPORTS/source"
```

The NUL-delimited status/path list is for machine consumption. The source scan covers
the supported tracked tree, **not only these paths**. Correlate findings with
the diff without discarding relevant unchanged sinks or callers. Record deleted,
renamed, unsupported and omitted files. Opengrep is not a secret scanner; use the
[secrets recipe](#check-staged-or-tracked-secrets) separately when authorized.

**Done when:** the draft distinguishes new findings, existing findings and gaps,
and cites `source/scan.json` / `source/scan.md`. Recheck if the head changes.
Publishing the review is a separate authorized step.

**Make it a PR bot:** supply the PR trigger in the agent host. Keep untrusted PR
code away from write tokens and secrets. Do not use a privileged
`pull_request_target` job to execute a fork's checkout. A dedicated review agent
still needs a scoped trigger, budget and permission policy; this recipe installs none.

## Check staged or tracked secrets

**Use for:** the tracked-file landing example, or a pre-commit check of what is
actually staged. These are different snapshots: choose one explicitly.

**Give your agent:**

```text
Prepare a credential check of this repository's staged file contents. Read
the Git index, not current working-tree files. Show only selected paths and
coverage gaps; never print suspected values. Stop before uploading and ask for
approval of the selected content and quoted maximum cost. After an authorized
Gitleaks scan, keep values redacted and explain removal and rotation options.
Do not commit, rotate/revoke credentials, test whether a key works or rewrite history.
```

**Collect the correct snapshot before quoting:**

1. For staged files, enumerate `git diff --cached --name-only --diff-filter=ACMR -z`
   from the target checkout. Read the stage-zero index blob for each selected
   path, not `readFile(path)` from the working tree. Stop on unresolved merge
   entries; handle paths as data, not shell fragments. Keep blob contents out of
   terminal logs. A partially staged file must be scanned at its staged version.
2. For tracked working-tree files instead, use `git ls-files -z` and read only
   reviewed regular files within the checkout. Do not follow symlinks. This mode
   may include unstaged changes; it is not proof about the next commit.
3. Prepare a private request file outside the checkout using the
   [text-tool contract](#hosted-text-tool-contract). Do not silently include
   untracked/ignored files or Git history. Record binary, oversized and unreadable
   inputs as gaps. Do not remove suspected values from scanner input and then
   claim the original content was checked; redaction applies to returned evidence.
4. Get explicit permission to send potentially sensitive file contents to the
   hosted service and approve the price ceiling. If upload is unacceptable, stop
   this hosted recipe and arrange a separately reviewed local Gitleaks workflow.

**Run:** after preparing `$REPORTS/gitleaks-input.json`, use `gitleaks` in the
quote/call commands below. The hosted service returns redacted findings; the
request file itself can still contain real credentials and must stay private.

**Done when:** report file/line/rule and the actual scanned snapshot without
values. If removal is authorized, move credentials to the project's secret
mechanism, restage deliberately, and scan the new index snapshot. Deleting a
value does not revoke it. Arrange provider-side revocation/rotation through an
authorized operator if it was exposed. Git history needs the separate
`gitleaks-history` tool and its own upload approval; never rewrite it implicitly.

**Make it a pre-commit guard:** a host-owned hook must capture the index on each
attempt, keep credentials out of logs, and pause on findings or incomplete checks.
Do not equate a working-tree scan with an index scan or a zero process exit code
with no findings. This recipe does not install a hook or spend credit on commits.

## Review a SQL endpoint

**Use for:** the landing page's request-input-to-SQL example. Requires local
Opengrep and a supported tracked JS/TS/Python endpoint. No live attack is needed.

**Give your agent:**

```text
Use local Offense source scanning to review this endpoint for SQL injection.
Trace request input through query construction and the actual database driver.
Treat a scanner match as a signal, not exploit proof. Propose bound parameters
and explain any identifiers that require allowlisting. Do not change code yet
or send requests to a deployed service. Keep source local.
```

**Run:**

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool opengrep --preview
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool opengrep --output "$REPORTS/before"
```

Inspect `before/scan.json` and the actual caller. The rules provide bounded
static/within-file analysis, not complete cross-file dataflow. No finding does
not establish that dynamic query construction is safe.

After patch approval, use the driver's parameter binding syntax—not string
escaping pasted into interpolation. Values and SQL identifiers are different;
binding a table name as a value does not make it a valid identifier. Test normal
searches, quote-containing inputs and a malicious predicate in a disposable
database. Assert which rows are returned, not only that no exception occurred.

Rescan with the same command into `$REPORTS/after`, run the original application
tests and retain the before/after security regression. A vanished static finding
alone is not proof the exploit was fixed.

## Review GitHub Actions

**Use for:** the CI reviewer and the PR-title-to-shell example. Requires local
Zizmor; no workflow is dispatched or executed.

**Give your agent:**

```text
Use Offense and Zizmor to review this project's changed Actions YAML, including
trigger permissions and untrusted expressions reaching shell steps. Read the
surrounding workflow and called actions. Draft a safer change, preserving the
job's purpose. Do not execute or dispatch workflows, approve a PR or merge.
```

**Run:**

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool zizmor --preview
node "$OFFENSE_ROOT/offense/bin/offense.mjs" source-scan "$PROJECT" --tool zizmor --output "$REPORTS/before"
```

The helper scans supported tracked workflows/action definitions, not a
changed-files-only set. Correlate its findings with the reviewed diff and retain
broader context. Offline checks do not fetch action histories or advisories.

For the landing example, this is the safer **illustrative step**, not a full
workflow or permission to run one:

```yaml
- name: Print pull request title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: printf '%s\n' "$PR_TITLE"
```

Moving data into an environment variable only helps if the shell expansion
stays quoted and is not passed into `eval`, `bash -c` or another interpreter.
Review event trust, token permissions, checkout behavior and downstream consumers
separately. After an approved edit, rerun Zizmor into `$REPORTS/after` and validate
the YAML. Test any shell behavior in an isolated local harness with synthetic PR
titles; never interpolate real attacker-controlled input into a command string.

**Done when:** explain the trust boundary and record before/after findings and
coverage. Workflow execution and merge remain separate approvals.

## Test a disposable local API

**Use for:** “Your API tester.” Requires Node.js 24+, Docker and a prepared
self-contained Node/Python app with an OpenAPI 3.0/3.1 schema and synthetic data.
This is active testing: unlike static source scans, it **executes the app**.

**Give your agent:**

```text
Prepare a disposable copy of this API with synthetic data and test-only
authentication. Review the OpenAPI schema and preview Offense's local API test.
Show the selected files, app command and request/time limits before execution.
Ask before building the test image or running the app. Never target production
or supply production credentials. After approval, investigate generated failures
and propose focused regression tests; do not call every 5xx a vulnerability.
```

Read the [local API testing contract](../offense/skills/purple/references/api-testing.md).
Prepare dependencies separately in isolation; the runner does not install them.
The app must listen on literal `127.0.0.1` using the provided `PORT`. External
services are unavailable; use local synthetic substitutes, not production access.

With explicit image-build approval, materialize and inspect the build context
in a fresh external directory, then build the pinned local image:

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" api-test --write-image-context "$REPORTS/image-context"
# Inspect the generated Dockerfile and runner before this build.
docker build -t purple-api-test:4.32.4 "$REPORTS/image-context"
```

Set `TEST_APP` to the prepared disposable snapshot containing `server.mjs` and
`openapi.json`. Adapt the explicit startup argv to the app; do not use a shell.

```sh
export TEST_APP=/absolute/path/to/disposable-test-app
node "$OFFENSE_ROOT/offense/bin/offense.mjs" api-test \
  --project "$TEST_APP" --schema "$TEST_APP/openapi.json" \
  --seed 1729 --examples 10 --seconds 20 --max-requests 200 \
  -- node server.mjs
```

That command is a **preview**. After execution approval, repeat it with `--run`
and an external output directory:

```sh
node "$OFFENSE_ROOT/offense/bin/offense.mjs" api-test \
  --project "$TEST_APP" --schema "$TEST_APP/openapi.json" \
  --run --output "$REPORTS/before" \
  --seed 1729 --examples 10 --seconds 20 --max-requests 200 \
  -- node server.mjs
```

**Done when:** read `before/api-test.json`, preserve the snapshot hash and seed,
map operation indices back to the schema locally, and investigate each candidate.
The report deliberately omits raw requests/responses and is not an exact exploit
replay. Write a focused reproduction when possible. After an approved fix, run
normal tests and rerun the same bounded check into `$REPORTS/after`.

The app and scanner run in separate containers sharing a network-disabled
loopback namespace. Unreachable authenticated operations, skipped inputs and
failed generation remain incomplete. Object-level authorization and cross-operation
stateful testing are not covered; a completed run is not API security clearance.

## Hosted text-tool contract

Use this for authorized Gitleaks scans, or a deliberate hosted alternative to
local Opengrep/Zizmor. Keep the selected account and service origin. Sign in using
the [existing CLI flow](offense-platform.md); never put a key in a recipe or chat.

Prepare a private UTF-8 JSON file outside the checkout with only selected inputs:

```json
{
  "files": [
    { "path": "src/example.js", "content": "REPLACE WITH THE EXACT REVIEWED FILE CONTENT" }
  ]
}
```

This is an **input shape**, not a meaningful scan fixture. Keep relative paths,
encode content as JSON, and inspect current catalog limits. The text contract
bounds file count/bytes; do not silently truncate oversized inputs. Do not include
credential stores or unrelated files merely because they are in the repository.

Set `TOOL` to the reviewed tool ID and `INPUT` to the prepared file. Discovery and
quoting do not submit a scan. This CLI's text quote sends byte/file dimensions,
not file content; other transports may differ. Scan submission uploads the files.

```sh
export OFFENSE_CLI="$OFFENSE_ROOT/public/skills/offense/scripts/cli.mjs"
export TOOL=gitleaks
export INPUT="$REPORTS/gitleaks-input.json"
node "$OFFENSE_CLI" tools show "$TOOL"
node "$OFFENSE_CLI" quote "$TOOL" --input "$INPUT"
```

Only after input-upload approval and a sufficient approved USD ceiling, set
`MAX_PRICE` to that ceiling and `REQUEST_KEY` to a unique 8–100-character key
(letters, digits, underscores or hyphens). Record both the key and exact input
identity **before** submitting, then keep them unchanged during recovery:

```sh
node "$OFFENSE_CLI" call "$TOOL" --input "$INPUT" \
  --max-price "${MAX_PRICE:?Set the approved USD ceiling}" \
  --idempotency-key "${REQUEST_KEY:?Set and retain one request key}" --wait
```

Save the returned receipt privately. If the result is queued, running or the
wait times out, read the existing job rather than submitting another:

```sh
node "$OFFENSE_CLI" job "${JOB_ID:?Use the saved job ID}"
```

If submission itself is uncertain, retry only with the original key and identical
input; do not mint another key. Completed, partial and failed statuses are
distinct. Read per-tool coverage and findings even when the process exits zero.
Never buy credit automatically, claim a quote is a settled charge, or publish
raw reports. The recipe does not establish that a hosted scan has run.
