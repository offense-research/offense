# Full-platform licensing boundaries

This is a source-release inventory, not an image SBOM or legal clearance.
The owner approved the minimal source-only release to `offense-research/offense`.
Its scope and remaining hosted/artifact obligations are recorded in
[release preparation](docs/release-preparation.md).

## Deferred copyleft integrations in the private checkout

The minimal source export excludes the following two files, their shared
assessment runners, build recipes and dependent tests. These notices document
the private checkout; they do not imply those implementations are in the export.
Full license texts remain available for reference. Exclusion is not clearance
of existing hosted or artifact-distribution obligations.

- `agent/mobsf-offline-policy.py` is distributed under **GPL-3.0-only**. Its
  `check_update` match text is copied from MobSF 4.5.3 `mobsf/MobSF/utils.py`,
  revision `d3869adc464b89db92a6a8a9e2dc13376f4a4c25`, by the
  [MobSF authors](https://github.com/MobSF/Mobile-Security-Framework-MobSF).
  Offense's modifications disable optional App Store and update lookups, retaining
  pinned-source checks. Dated modification notices are included in the policy
  script and both source replacements it produces. See [GPL-3.0](licenses/GPL-3.0.txt). Distribution of a
  modified MobSF image requires its complete corresponding source, not just this patch.
- `agent/assessment-network-tls.py` is distributed under **AGPL-3.0-only** as
  the Offense adapter importing [SSLyze 6.3.1](https://github.com/nabla-c0d3/sslyze/tree/3bd5094dec1dfbaac1a03957c35ba5e487f5b890).
  See [AGPL-3.0](licenses/AGPL-3.0.txt). Before operating or distributing the
  combined program, review its complete corresponding-source boundary and the
  network source-offer obligations. A link to this private repository is not a
  public source offer. No production compliance change is made by this release preparation.

## Included source and generated clients

- `server/braces-remediation.js` and its `offense/` copy include MIT braces 3.0.3
  patch context. Preserve [the upstream notice](offense/licenses/braces-3.0.3-LICENSE).
- Generated CLI and syntax bundles preserve embedded upstream license texts.
  `cli/THIRD_PARTY_LICENSES.txt` describes the actual CLI bundle. The YAML bundles
  retain ISC notices. Do not strip these when rebuilding or minifying.
- The local `offense/` package has its own [full notices](offense/THIRD_PARTY_NOTICES.md).

## Source publication is not hosted or image compliance

The first release target is **source only**, with Apache-2.0 for project-owned
code and the disputed GPL/AGPL integrations excluded. Publication
is not a blanket Apache license grant over third-party materials or completed
legal review. The private integrations retain their attribution, dated modification
notices and full license texts. Do not reintroduce them without a scope review.

[GPLv3 sections 4–5](https://www.gnu.org/licenses/gpl-3.0.en.html) permit compliant
distribution of source and modifications. Hosting alone is not conveying a copy.
Distributing a modified MobSF image instead invokes the corresponding-source
requirements for that artifact under section 6, including relevant build scripts
and separately licensed bundled components. This release does not approve that.

The SSLyze adapter imports AGPL code directly. Its file-level license does not
settle the combined-work boundary with the controller and service.
[AGPLv3 section 13](https://www.gnu.org/licenses/agpl-3.0.en.html) requires a
modified network-interactive covered work to offer its users no-charge access
to the corresponding source of that version. Before enabling or certifying this
hosted integration, review the boundary and assemble the exact deployed source,
modifications, required dependency sources, and build/install instructions.
Verify a prominent source-download route available to the affected users; a
private repository, an unrelated latest revision or only the adapter is not a
substitute. No deployment-matched source package or public route is supplied here.

In the deferred private network runner, TruffleHog is downloaded as an upstream executable and invoked as a subprocess;
the inspected recipe contains no modification step. That is not automatically a
license change for Offense, but subprocesses and containers do not establish
legal independence by themselves. Its binary redistribution obligations remain.
Opengrep and Semgrep binaries retain LGPL obligations on redistribution as well.

No scanner images, executable packages or downloaded datasets are released by
this candidate. Local image builds are not approved distribution artifacts:
`agent/source.Dockerfile` now copies only source-runner dependencies, excluding
MobSF/SSLyze integrations. It still downloads separately licensed engines and
dependencies, so do not claim that image is Apache-only. Existing hosted
operations need a separate deployed-version review; narrowing this release does
not resolve any obligations arising from earlier distribution or operation.

## Dependencies fetched by npm

Root runtime dependencies are MIT (`@cfworker/json-schema`, MCP SDK, Express,
jsonc-parser, React, React DOM, Zod), ISC (semver, yaml, Lucide), and BSD-3-Clause
(smol-toml). Lucide also retains Feather's MIT notice: preserve the complete
installed license, not just its SPDX label. The generated release inventory
records each lockfile entry, version, integrity and declared license.

Some optional/build dependencies contain LGPL libvips or CC-BY caniuse data.
Manifests alone do not redistribute these implementations. Distributing bundles
or native binaries requires the notices/source obligations for what they contain.
`reserved@0.1.2` in the Spectral lockfile uses legacy registry MIT license metadata.
Missing metadata must be reviewed, never silently interpreted as public domain.

## Scanner recipes are not binary redistribution approval

| Separately fetched component | Engine license |
| --- | --- |
| Opengrep, Semgrep OSS | LGPL-2.1 |
| Trivy, GuardDog, Spectral CLI, ZAP, Cosign, OSV Scanner, Pluto, Kubeconform, Prowler, Checkov | Apache-2.0 |
| Gitleaks, Zizmor, Nuclei, Katana, httpx, Schemathesis, Hermes, Pi coding agent | MIT |
| SSLyze, TruffleHog | AGPL-3.0 |
| MobSF | GPL-3.0 |

This inventory covers the private checkout as well as included source recipes;
the network/mobile/offline assessment recipes are deferred from the export.
Exact versions/checksums are in the applicable `agent/*Dockerfile` and dependency constraints.
Engine licenses do not cover every base-image package, Python dependency, plugin,
rule pack or dataset. Semgrep uses local rules and OSS mode, not Pro or registry
rules. Spectral's OWASP ruleset is MIT, separately from its Apache-2.0 CLI.
Kubernetes schemas, OSV advisories, Trivy data/checks, GuardDog rankings and
Sigstore trust data need their own provenance in any redistributed image.
Scorecard's published API data uses CDLA-Permissive-2.0; its engine is Apache-2.0.
Do not distribute prebuilt scanner images or databases under this source-release gate.

## Artwork, fonts and rule provenance

Archivo and IBM Plex Mono retain SIL OFL-1.1 notices under `site/public/fonts/`.
The grain generator and social-preview generator establish generation methods,
not ownership of every input. The supplied Ryvn/Figma assets and derived diagram
module have been removed at the owner's request; no redistribution rights are
claimed for them. Imran Muthuvappa identified himself as the creator of the
remaining Offense mark, icon sheet, security-core illustration and social visuals.
On 2026-10-30, he authorized **Apache-2.0** for his original artwork. Copyright
2026 Imran Muthuvappa. See [LICENSE](LICENSE). The identified assets are:

- `site/public/offense-mark.svg`, `site/public/icons.svg` and
  `site/public/visuals/security-core.svg`.
- `site/public/social/offense-logo.jpg`, `site/public/social/offense-logo.mp4`,
  `site/public/social/offense-preview.jpg` and `site/public/social/offense-preview.mp4`.
- `site/public/share/purple-preview-v1.png` and `site/public/share/purple-preview-v1.mp4`,
  including their identical copies under `public/share/`.
- `site/public/textures/grain.png`, generated by `site/scripts/generate-grain.mjs`.

This copyright grant does not relicense the OFL font files, Lucide/Feather icons
or other third-party materials, and grants no trademark rights beyond those in
the license and applicable law. It closes only the artwork-license approval;
it does not authorize repository, package or image publication.

Offense Research, Inc. is the owner identified for the code; no outside
contributors were reported. On 2026-10-30, Imran Muthuvappa confirmed that he
wrote all 23 project-branded scanner rules/templates independently with AI
assistance, without copying or adapting another ruleset. These project-owned
rules are included under Apache-2.0. This author statement is recorded in
`docs/release-preparation.md`; it is not an independent originality or legal review.
No automated license scanner can establish ownership rights.

The [scanner-rule provenance trace](docs/release-preparation.md#scanner-rule-provenance-trace--2026-10-29)
records the introduction commits for all 23 rules/templates and the identical
13-rule copy in `offense/tools/internal/scan-rules.yml`. Git records when they
entered the repository, not whether they were independently authored or adapted.
The subsequent author confirmation covers that copy and closes the
`project-rules-provenance` publication blocker. It does not relicense third-party
engines or rulesets, clear GPL/AGPL obligations, or authorize publication.
