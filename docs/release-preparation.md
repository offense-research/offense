# Source release scope and preparation record

**Source publication approved on 2026-10-30** by Imran Muthuvappa for
https://github.com/offense-research/offense. GitHub private vulnerability reporting
was enabled by the owner and verified through GitHub's API before publication.
Only the reviewed clean-history source export is approved. The original
repository remains private; packages, images and deployments are not approved.

`SOURCE-RELEASE.json` records this publication decision and final file hashes.
The export script still creates unapproved private candidates by default;
it never publishes or grants approval for a future snapshot automatically.

## README ownership

The maintained checkout's root `README.md` is its user entry point.
`docs/public-readme.md` is the active candidate template selected by
`config/source-release-files.json` and copied to the export's root `README.md`.
Its links are relative to that destination, and its private-candidate warning
applies to newly prepared snapshots. The earlier publication approval does not
authorize future candidates; preserve these restrictions when updating guidance.

## Source boundary

`config/source-release-files.json` is an exact-path allowlist, not an instruction
to publish the whole checkout. `scripts/prepare-source-release.mjs` copies only
those files to a new private directory, without Git history, hard links or
symlinks. It substitutes the public README and portable deployment examples,
replaces legacy deployment fallback hosts/IDs with example.invalid/zero placeholders
(including the matching synthetic test expectation), and emits hashes and a
dependency-license inventory. Unknown files are omitted. These legacy helpers
are reference source, not a configured deployment command; operators must supply
their own configuration and separately authorize deployment.
The export is a **review candidate**, not an automated legal/security approval.

Excluded: private Git history, operational receipts, customer/support evidence,
remediation reports, production account/routing configuration, local state,
credentials, dependency installations and prebuilt release tarballs. Generic
application, billing, orchestration, worker and source-scanner code stays in scope.
The optional assessment integrations listed below are deferred from this first
export; paid hosting is an operated service, not a source-code restriction.

The original repository remains private, including its operational documentation.
The owner requested removal of the uncleared Ryvn artwork and derived diagram
module from the checkout and Git history. That targeted removal is not a review
of the rest of the private history. Never publish it by toggling visibility.
Work from the verified clean-history snapshot after approval and retain required
attribution in the public history.

## First release: source only

The minimal export excludes `agent/mobsf-offline-policy.py` and
`agent/assessment-network-tls.py`. It also excludes their shared network/offline
assessment runners, mobile/network/offline Dockerfiles and Docker ignore files,
and five test files importing or inspecting those implementations. The exact
15 excluded paths appear in `SOURCE-RELEASE.json`. The exporter rejects their
reintroduction through the allowlist, including renamed destination mappings.

This closes `copyleft-compliance-review` **only for this narrowed source export**
by deferring the disputed integrations, not by clearing or relicensing them.
The private implementation remains unchanged, with its GPL/AGPL notices intact.
The export retains attribution and full license texts as context for that boundary.
Checkov and the other network adapters sharing those runners are deferred too;
splitting those runners into a separate public variant is outside this release.

Supported self-hosted execution remains dependency advisory analysis, Opengrep
and Zizmor. Other adapters and container recipes are **unsupported reference
source in this profile where included**, not enabled workflows. Catalog metadata,
project-owned rules/templates and generic lifecycle code remain available even
for deferred tools; a listing does not promise an included runtime. No hosted
behavior is changed. The source Dockerfile copies only its runner dependencies,
not the deferred assessment sources, even when built from the private checkout.
Do not publish scanner images, engine binaries, package archives or downloaded
datasets with the first release. Generated JavaScript helpers and site assets
remain allowlisted with their existing licensing/ownership boundaries; “source
only” does not mean every included byte is original Apache-licensed source.

For a new candidate, `SOURCE-RELEASE.json` initially records `releaseType: "source-only"`,
`publicationApproved: false`, `artifactPublicationApproved: false` and
`hostedComplianceVerified: false`. The exporter requires both copyleft license
texts and rejects common archive/binary filenames in addition to the exact-path
allowlist. This is an accidental-inclusion guard, not exhaustive file-type or
legal analysis; copied content under new source paths still requires review.
The initial `private-security-reporting` and `exact-snapshot-publication-approval`
holds were resolved for this published snapshot only. Images, binaries and existing hosted
deployments still require their separate compliance reviews.

The [licensing boundaries](../THIRD_PARTY_NOTICES.md#source-publication-is-not-hosted-or-image-compliance)
describe the separate source, image and hosted obligations. Before enabling or
certifying hosted SSLyze, obtain a qualified combined-work review, assemble a
deployment-matched corresponding-source package and verify the user-visible,
no-charge source-download route. Existing hosted versions must be checked
separately; this source release is neither that source offer nor a retroactive
compliance fix. Publishing or deploying the source offer needs separate approval.

## Reproduce preparation

```sh
node scripts/prepare-source-release.mjs /absolute/new/private-candidate
```

In that candidate, run `npm ci`, `npm run build`, `npm test`, then
`npm --prefix offense ci`, `npm --prefix offense test` and
`npm --prefix offense run check`. Build the source image and run
`node scripts/test-self-host.mjs`. Build outputs are validation products, not
automatically added to the source release. Record the final snapshot hashes.
Run a redacted secret scan of the exact export, review every finding and inspect
any changed file before approving it. Do not infer private-data safety solely
from a zero-secret result. The private history is excluded, not certified clean.

## Owner statements — 2026-10-29

Imran Muthuvappa identified **Offense Research, Inc.** as the code owner and
reported no employee/contractor/collaborator contributions yet. He identified
himself as the creator of the remaining logo, icons, illustrations and social
visuals. These are recorded owner statements, not an independent review of
assignments or third-party rights. Fonts retain their OFL notices.

On 2026-10-30, Imran authorized Apache-2.0 for his original artwork, closing
`artwork-license-approval`. The [asset inventory](../THIRD_PARTY_NOTICES.md#artwork-fonts-and-rule-provenance)
identifies this grant's scope. Third-party licenses and trademark reservations
remain unchanged. This is not approval to publish the repository or artifacts.

For the supplied Ryvn/Figma assets and derived diagram module, the owner chose
deletion rather than seeking a redistribution grant. The 27 SVGs under
`site/public/figma/` and `site/src/reference-diagrams.js` are removed from the
source candidate. They were not loaded by the current landing page.
History rewriting cannot remove other people's clones or GitHub's read-only
pull-request refs and cached views. Merged PR #1 references the affected tree;
complete erasure from GitHub cannot be claimed. GitHub's
[documented support policy](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
does not offer purging for non-sensitive data. Keep the original repository private and
publish only an approved clean-history export to a separate destination.
Existing clones must be replaced or carefully cleaned, never merged back into
the rewritten history.
No production redeployment is authorized by this source cleanup.

The owner's initial description of the scanners as hosted open-source tools
did not establish the checked-in rules' provenance. His subsequent authorship
confirmation is recorded below; it does not override the identified MobSF
source excerpt or SSLyze library integration.

## Scanner-rule provenance trace — 2026-10-29

**The history trace alone did not establish original authorship or upstream
adaptation. The subsequent owner confirmation below closes that hold.**
The following findings come from the complete
available Git history, introduction diffs, byte comparisons and the earlier
[Amp reconciliation thread](https://ampcode.com/threads/T-01a182fd-c8fc-73b0-af1d-325babbb7bbd).
Commit links use the rewritten history after the artwork removal.

| Rules/templates | First recorded in this repository | Evidence and limits |
| --- | --- | --- |
| Five original patterns in `agent/scan-rules.yml` | 2026-10-22, [Add isolated hosted scans](https://github.com/imranye/purple/commit/f94d124a30f76d79169467747eef161d6aa39c5d) | Added as a new 55-line file. Those original bytes remain unchanged at the start of the current file. No original authoring session or upstream attribution was identified. |
| Eight additional request-to-sink rules in `agent/scan-rules.yml` | 2026-10-27, [Reconcile Offense source](https://github.com/imranye/purple/commit/689f0e6dce49b6907de50750387edee87c37518a) | Appended 326 lines without changing the original five rules. The reconciliation record describes checkpointing previously uncommitted implementation, not the original rule-writing process. |
| Four Nuclei templates in `agent/assessment-network-templates/`: `actuator-env.yaml`, `directory-listing.yaml`, `dotenv.yaml`, `git-config.yaml` | Same 2026-10-27 reconciliation commit | All four remain byte-identical to their introduction versions. Their `author: purple` fields are labels, not evidence of independent creation. |
| Six patterns in `agent/semgrep-rules.yml` | 2026-10-28, [Ship Offense tools](https://github.com/imranye/purple/commit/006dfbea8410c9505cb9319ecac265fedeedf2bb) | Added as a new 35-line file; still byte-identical. The adapter loads this local profile rather than downloading registry rules, which does not establish how the YAML was originally authored. |

All three commits record author `ronny` with the `imranye` GitHub noreply
identity. That identifies the recorded committer/author account, not who or what
wrote each rule. None carries an Amp thread trailer or an upstream attribution.
The earlier Amp thread fast-forwarded pre-existing commits from
`codex/offense-reconciliation`; it did not witness rule creation. The branch
name does not establish Codex authorship. Its records point to an earlier local
checkout but identify no original rule-authoring transcript.

For matching older records, the reconciliation commit was originally
`89f8f44e1de6b85c754b2ca9f7ebdfac4fdc206a`, and the tools commit was originally
`36673cd048df714eb425d81af78a02ef32478154`, before the artwork history rewrite.
`offense/tools/internal/scan-rules.yml` was added in the reconciliation commit
and is byte-identical to `agent/scan-rules.yml`; its 13 rules share the same
provenance, rather than constituting another independently sourced set.

No inspected record establishes copying from a particular upstream ruleset;
absence of attribution is not proof of independent authorship either. This was
a repository/history trace, not an exhaustive external similarity or legal review.
Spectral's imported MIT-licensed OWASP ruleset is separately identified in
`THIRD_PARTY_NOTICES.md` and is not part of these 23 project-branded rules/templates.

### Owner confirmation — 2026-10-30

After reviewing the 23-rule inventory and the full Semgrep and Nuclei YAML,
Imran Muthuvappa stated:

> I wrote all 23 independently, with AI assistance; none were copied or adapted from another ruleset.

This confirmation covers the 13 rules in `agent/scan-rules.yml`, the six in
`agent/semgrep-rules.yml` and the four Nuclei templates listed above. It also
covers the identical 13-rule copy in `offense/tools/internal/scan-rules.yml`.
These project-owned rules are included under the existing Apache-2.0 license.
**The `project-rules-provenance` publication blocker is closed on the basis of
this author statement**, not an independent originality or legal determination.
The earlier history findings and their limitations remain recorded above.
This confirmation does not cover third-party engines/rulesets or GPL/AGPL
integrations, and does not authorize publication or deployment.

## Publication decisions and remaining compliance scope

1. GitHub private vulnerability reporting is enabled on `offense-research/offense`.
   Use the route in [SECURITY.md](../SECURITY.md).
2. The owner authorized publishing this reviewed minimal source snapshot to that
   destination. npm and image releases still require separate approval.

Separately, the private MobSF/SSLyze integrations still need a deployed-version
combined-work/source-offer review. Their omission resolves the source-export
hold, not existing obligations. Reintroducing them requires that review first.

These decisions authorize this source release, not a declaration that every
hosted integration or future distribution is compliant or production-ready.

## Minimal-export verification — 2026-10-30

The narrowed export passed 1,198 platform/site tests with seven explicit skips,
195 local-engine tests, the production build and the local package hygiene check.
Five dependent test files are excluded with the deferred assessment runtimes;
the private checkout separately passed all 1,246 platform/site tests.
Real self-hosted Opengrep/Zizmor checks passed positive/safe inputs, malformed
source handling, CLI/API/MCP execution, idempotency, zero charges, restart
persistence, cleanup and key revocation. All 15 deferred paths were absent.
The 24 Gitleaks findings were reviewed SHA-256 integrity-map entries, not credentials.
Public-launch edits update documentation and the release record, not runtime code.
GitHub CI in the original private repository could not start due to account billing;
local verification is not a claim that remote CI passed.

## Preparation evidence — 2026-10-29

- Fresh export installed and built with an empty process environment apart from
  PATH and a disposable HOME. No production credentials or original dependency
  installation were used. The source image was built from the exported recipe.
- `npm test`: 1,246 passing platform/site tests, seven explicit skips, zero
  failures. The original checkout passed the same suite. A clean-checkout failure
  caused by missing generated Worker source was fixed with credential-free generation.
- `npm --prefix offense test`: 195 passed. Its package hygiene check passed.
- `node scripts/test-self-host.mjs`: real Opengrep/Zizmor positive and safe
  controls, malformed-source partial coverage, CLI discovery, MCP execution,
  unauthenticated rejection, disabled-tool rejection, same-key idempotency,
  zero charges, completed-report restart persistence, source cleanup and key
  revocation passed. Browser OAuth and other scanner families were not certified.
- Offense local source helper: 15 changed JS/Python files, completed, zero
  findings, no source upload. This is bounded evidence, not a whole-tree audit.
- Pinned Gitleaks 8.30.1 on the pre-build source export returned 24 findings;
  every finding was a SHA-256 entry in the managed-skill release integrity maps.
  All were reviewed; no exclusions or suppressions were added. This is not
  a claim that arbitrary private/customer information can be detected automatically.

Any subsequent source change invalidates the corresponding execution evidence.
Re-export and record the resulting `SOURCE-RELEASE.json` hash before approval.
Execution evidence does not itself grant publication approval or settle legal obligations.
