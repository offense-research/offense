# Choose checks from project evidence

Read the generated [catalog](catalog.md) for exact coverage, then discover runtime
availability and current input contracts. This table supplies candidates, not an
instruction to run everything. Tell the builder what each selected check answers.
Use a primary check and add overlap only for a specific uncovered question.

| Evidence | Candidates | Selection and boundary |
| --- | --- | --- |
| JavaScript, TypeScript or Python source | `opengrep`, `semgrep` | Choose suitable reviewed rules; no cross-file or exploit-confirmation claim. |
| Dependency lockfiles | `trivy-vuln`, `osv-scanner` | Free sanitized npm/pnpm audit is also available; Python needs a supported scanner/input, not that free audit. OSV fixed versions are advisory evidence, not tested upgrades. |
| CycloneDX or SPDX JSON | `trivy-sbom` | Scan the supplied SBOM; retain its identity and age. |
| Working files with secret exposure concerns | `gitleaks` | Uploaded contents only; history remains unchecked. |
| Git history explicitly in scope | `gitleaks-history` | Requires a bounded Git bundle and distinct upload consent. |
| Need to verify whether credentials are live | `trufflehog-verified` | Separate explicit authorization for contacting credential providers; never inferred from static secret scanning. |
| Infrastructure files | `trivy-config`, `checkov` | Select policy coverage; no cloud account inspection is implied. |
| Rendered Kubernetes YAML/JSON | `k8s-deprecations`, `k8s-manifest-validate` | Need explicit target Kubernetes version; distinguish lifecycle checks from schema validation. Missing custom schemas remain partial. |
| Container release | `trivy-image`, `cosign-image` | Image archive for vulnerabilities; offline Cosign bundle plus expected signer and immutable digest for provenance. Neither substitutes for the other. |
| npm or PyPI package archive | `guarddog-npm`, `guarddog-pypi` | Suspicious package behavior signals in one archive, not confirmation of malicious intent. |
| Public GitHub upstream trust | `openssf-scorecard` | Published snapshot with date and assessed commit, not a fresh scan or private-repository check. |
| GitHub Actions workflow/action YAML | `zizmor` | Offline workflow trust and permission checks. |
| OpenAPI specification | `spectral-owasp` | Specification policy only; no live API testing. |
| Verified staging API and schema | `schemathesis`, `zap-api` | Explicit bounded active-test permission; distinguish generated request failures from security findings. |
| Deployed HTTPS service | `httpx`, `katana`, `nuclei`, `sslyze` | Ownership and authorization first. One-root observation, bounded discovery, four exposure checks and limited TLS checks respectively; not a general penetration test. |
| Captured HAR responses | `zap-passive-har` | Passive uploaded response checks; no live requests. Review selected capture for private content before upload. |
| Selected Cloudflare account | `prowler-cloudflare` | Explicit account and separately supplied read-only access; no account connection required for other checks. |
| APK/IPA release | `mobsf-static` | Static artifact analysis only, no emulator or runtime verification. |

Preserve unsupported file types, missing artifacts and disabled tools as coverage
gaps. A repo checkout is not an image, mobile build, production target or cloud
account grant. Request only inputs needed for a relevant selected check; continue
other independent authorized checks when these are absent.
