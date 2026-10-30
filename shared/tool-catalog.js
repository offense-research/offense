import { ASSESSMENT_TOOLS } from './assessment-tools.js';
import { KUBERNETES_VERSIONS } from './kubernetes-scan.js';

// Static hosted-tool contracts shared by discovery and execution. Importing the
// catalog does not load the server, authenticate, quote a price or start a job.
// Deployment availability and account pricing are added by hosted-scans.js.
export const TOOL_CATALOG = Object.freeze([
  { id: 'opengrep', name: 'Source code security', inputType: 'source-files', coverage: 'Operator-maintained JavaScript, TypeScript and Python patterns and within-file taint rules; no exploit confirmation' },
  { id: 'trivy-vuln', name: 'Dependency vulnerabilities', inputType: 'source-files', coverage: 'Supported dependency manifests and lockfiles' },
  { id: 'gitleaks', name: 'Exposed secrets', inputType: 'source-files', coverage: 'Uploaded file contents; Git history is excluded' },
  { id: 'trivy-config', name: 'Infrastructure configuration', inputType: 'source-files', coverage: 'Supported infrastructure-as-code files' },
  { id: 'trivy-sbom', name: 'SBOM vulnerabilities', inputType: 'sbom-json', coverage: 'One CycloneDX or SPDX JSON file' },
  { id: 'trivy-image', name: 'Container image vulnerabilities', inputType: 'image-tar', coverage: 'One uploaded, digest-checked Docker image archive, up to 80 MiB' },
  { id: 'gitleaks-history', name: 'Git history secrets', inputType: 'git-bundle', coverage: 'One bounded Git bundle; redacted findings from prior commits' },
  { id: 'guarddog-npm', name: 'npm package risk', inputType: 'package-archive', coverage: 'One uploaded npm package archive; suspicious package behavior signals' },
  { id: 'guarddog-pypi', name: 'PyPI package risk', inputType: 'package-archive', coverage: 'One uploaded PyPI package archive; suspicious package behavior signals' },
  { id: 'spectral-owasp', name: 'OpenAPI security policy', inputType: 'openapi-text', coverage: 'One uploaded OpenAPI JSON or YAML document; specification checks only' },
  { id: 'cosign-image', name: 'Container image provenance', inputType: 'cosign-save', coverage: 'One offline Cosign image bundle, expected signer and OCI digest' },
  { id: 'zap-passive-har', name: 'Passive web response checks', inputType: 'web-har', coverage: 'One uploaded HAR with at most 200 captured responses; no live crawl or active requests' },
  { id: 'zizmor', name: 'GitHub Actions security', inputType: 'source-files', coverage: 'Supplied workflow and action YAML; offline trust-boundary, injection and permission checks' },
  { id: 'osv-scanner', name: 'Dependency remediation intelligence', inputType: 'source-files', coverage: 'Offline OSV advisory matches and advisory-listed fixed versions for supported supplied lockfiles; no dependency installation, automatic fix or exploit confirmation' },
  { id: 'semgrep', name: 'Semgrep source code security', inputType: 'source-files', coverage: 'Additional operator-reviewed JavaScript, TypeScript and Python rules using Semgrep Community Edition; no remote registry rules, cross-file reachability or exploit confirmation' },
  { id: 'k8s-deprecations', name: 'Kubernetes API deprecations', inputType: 'source-files', requiredInput: ['files', 'kubernetesVersion'], kubernetesVersions: KUBERNETES_VERSIONS,
    coverage: 'Rendered YAML/JSON manifests against Pluto’s bundled Kubernetes API lifecycle data for the required kubernetesVersion; no cluster access or upgrade safety guarantee' },
  { id: 'k8s-manifest-validate', name: 'Kubernetes manifest validation', inputType: 'source-files', requiredInput: ['files', 'kubernetesVersion'], kubernetesVersions: KUBERNETES_VERSIONS,
    coverage: 'Strict offline validation of rendered YAML/JSON manifests against bundled schemas for the required kubernetesVersion; missing custom-resource schemas remain partial' },
  ...ASSESSMENT_TOOLS,
]);
