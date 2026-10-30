// Reviewed supporting copy for the original scanners. IDs, titles and coverage
// are checked and combined with the canonical catalog by scripts/catalog.mjs.
export const toolDetails = {
  'k8s-deprecations': {
    engine: 'Pluto', category: 'infrastructure', icon: 'layers', input: 'Rendered manifests + target version',
    points: [
      'Requires an explicit supported Kubernetes target version; no cluster credentials or live cluster access.',
      'Checks bundled API deprecation and removal rules. Render Helm or Kustomize locally before submitting manifests.',
      'Unlisted APIs, GPU drivers and safe upgrade sequencing are not assessed. Review coverage and migration requirements.'
    ]
  },
  'k8s-manifest-validate': {
    engine: 'Kubeconform', category: 'infrastructure', icon: 'layers', input: 'Rendered manifests + target version',
    points: [
      'Validates rendered YAML/JSON against strict, bundled schemas for an explicit supported Kubernetes target version.',
      'Runs offline. Missing schemas, including GPU Operator custom resources, remain partial results rather than clean checks.',
      'Does not prove cluster admission, workload health or a safe GPU upgrade. Review findings and coverage before planning changes.'
    ]
  },
  'osv-scanner': {
    provider: 'OFFENSE / OSV-SCANNER', engine: 'OSV-Scanner', category: 'dependencies', icon: 'dependency',
    status: 'IN OFFENSE', title: 'Dependency remediation intelligence',
    description: 'Review dependency advisory matches and the fixed versions represented in OSV data.',
    input: 'Dependency files',
    points: [
      'Checks supported dependency metadata against the scanner’s documented advisory data.',
      'Reported fixed versions are remediation evidence; compatibility and reachability require repository review.',
      'No automatic package installation, source execution, or verified exploit is implied by an advisory match.'
    ],
    url: 'https://offense.sh/app#tools', action: 'View tool and pricing'
  },
  'openssf-scorecard': {
    provider: 'OFFENSE / OPENSSF SCORECARD', engine: 'OpenSSF Scorecard', category: 'dependencies', icon: 'shield',
    status: 'IN OFFENSE', title: 'Supply-chain trust assessment',
    description: 'Review published OpenSSF Scorecard evidence for one public GitHub repository.',
    input: 'Public GitHub repository',
    points: [
      'Select one owner/repository explicitly; no connected GitHub credentials are forwarded.',
      'Reports the published snapshot’s assessment date, commit and individual checks when available.',
      'A score is a supply-chain signal, not a confirmed vulnerability or a fresh private-repository assessment.'
    ],
    url: 'https://offense.sh/app#tools', action: 'View tool and pricing'
  },
  katana: {
    provider: 'OFFENSE / KATANA', engine: 'Katana', category: 'web', icon: 'globe',
    status: 'IN OFFENSE', title: 'Web and API endpoint discovery',
    description: 'Discover endpoints within one verified HTTPS origin using a bounded crawl.',
    input: 'Verified deployment',
    points: [
      'Requires the existing target ownership verification before execution.',
      'Fixed request and time limits keep discovery within the selected origin; no arbitrary crawler flags.',
      'Discovered endpoints are observations for review and do not count as vulnerability findings.'
    ],
    url: 'https://offense.sh/app#tools', action: 'View tool and pricing'
  },
  httpx: {
    provider: 'OFFENSE / HTTPX', engine: 'httpx', category: 'web', icon: 'globe',
    status: 'IN OFFENSE', title: 'Live service reconnaissance',
    description: 'Observe the HTTP service at one verified HTTPS origin within fixed execution limits.',
    input: 'Verified deployment',
    points: [
      'Requires ownership verification for the explicitly selected origin.',
      'Returns bounded service metadata without response bodies, raw headers or credentials.',
      'Service observations describe exposure; they do not confirm that a vulnerability is exploitable.'
    ],
    url: 'https://offense.sh/app#tools', action: 'View tool and pricing'
  },
  semgrep: {
    provider: 'OFFENSE / SEMGREP', engine: 'Semgrep OSS', category: 'source', icon: 'code',
    status: 'IN OFFENSE', title: 'Additional SAST validation',
    description: 'Validate supplied source with Semgrep OSS and reviewed local rules.',
    input: 'Source files',
    points: [
      'Uses a fixed local ruleset without loading customer scan configuration or remote rules.',
      'Provides a separate Semgrep engine for supported source checks alongside Opengrep.',
      'Static matches require applicability review and tests; no cross-file reachability or exploit confirmation is implied.'
    ],
    url: 'https://offense.sh/app#tools', action: 'View tool and pricing'
  },
  "opengrep": {
    "provider": "OFFENSE / OPENGREP",
    "engine": "Opengrep",
    "category": "source",
    "icon": "code",
    "status": "IN OFFENSE",
    "title": "Source code security",
    "description": "JavaScript, TypeScript, and Python checks for risky patterns and within-file taint paths.",
    "input": "Source files",
    "points": [
      "Uses 13 operator-maintained rules, including eight within-file taint rules for modeled injection, path traversal, and SSRF paths.",
      "Available as a hosted Offense scanner or through the Offense skill for local checkout scanning without source uploads.",
      "Static findings need applicability review; they do not confirm exploitability or replace repository tests."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "trivy-vuln": {
    "provider": "OFFENSE / TRIVY",
    "engine": "Trivy",
    "category": "dependencies",
    "icon": "dependency",
    "status": "IN OFFENSE",
    "title": "Dependency vulnerabilities",
    "description": "Check supported manifests and lockfiles against known dependency advisories.",
    "input": "Lockfiles",
    "points": [
      "Coverage follows the supported dependency metadata supplied with the scan.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "gitleaks": {
    "provider": "OFFENSE / GITLEAKS",
    "engine": "Gitleaks",
    "category": "source",
    "icon": "key",
    "status": "IN OFFENSE",
    "title": "Exposed secrets",
    "description": "Find credential patterns in uploaded working files, with secret values removed from reports.",
    "input": "Source files",
    "points": [
      "Uploaded source is scanned; Git history is handled by the separate history tool.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "trivy-config": {
    "provider": "OFFENSE / TRIVY",
    "engine": "Trivy",
    "category": "infrastructure",
    "icon": "layers",
    "status": "IN OFFENSE",
    "title": "Infrastructure configuration",
    "description": "Check supported infrastructure files for configuration issues.",
    "input": "IaC files",
    "points": [
      "Reports identify supported configuration checks and any incomplete coverage.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "trivy-sbom": {
    "provider": "OFFENSE / TRIVY",
    "engine": "Trivy",
    "category": "dependencies",
    "icon": "document",
    "status": "IN OFFENSE",
    "title": "SBOM vulnerabilities",
    "description": "Check the components represented in a CycloneDX or SPDX software bill of materials.",
    "input": "SBOM",
    "points": [
      "Accepts one supported JSON SBOM and checks its represented components.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "trivy-image": {
    "provider": "OFFENSE / TRIVY",
    "engine": "Trivy",
    "category": "infrastructure",
    "icon": "package",
    "status": "IN OFFENSE",
    "title": "Container image vulnerabilities",
    "description": "Inspect an uploaded container image archive for known package vulnerabilities.",
    "input": "Image archive",
    "points": [
      "Uses a digest-checked Docker image archive through the separate artifact upload flow.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "gitleaks-history": {
    "provider": "OFFENSE / GITLEAKS",
    "engine": "Gitleaks",
    "category": "source",
    "icon": "history",
    "status": "IN OFFENSE",
    "title": "Git history secrets",
    "description": "Look for credential patterns in prior commits from a bounded Git bundle.",
    "input": "Git bundle",
    "points": [
      "Checks the supplied history bundle and returns redacted findings.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "guarddog-npm": {
    "provider": "OFFENSE / GUARDDOG",
    "engine": "GuardDog",
    "category": "dependencies",
    "icon": "shield",
    "status": "IN OFFENSE",
    "title": "npm package risk",
    "description": "Inspect an npm package archive for suspicious behavior and package risk signals.",
    "input": "npm archive",
    "points": [
      "Heuristic package signals need review; they do not independently establish malicious intent.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "guarddog-pypi": {
    "provider": "OFFENSE / GUARDDOG",
    "engine": "GuardDog",
    "category": "dependencies",
    "icon": "shield",
    "status": "IN OFFENSE",
    "title": "PyPI package risk",
    "description": "Inspect a Python package archive for suspicious behavior and package risk signals.",
    "input": "PyPI archive",
    "points": [
      "Heuristic package signals need review; they do not independently establish malicious intent.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "spectral-owasp": {
    "provider": "OFFENSE / SPECTRAL",
    "engine": "Spectral",
    "category": "source",
    "icon": "code",
    "status": "IN OFFENSE",
    "title": "OpenAPI security policy",
    "description": "Check an OpenAPI document against API security policy rules.",
    "input": "OpenAPI",
    "points": [
      "Inspects a supplied JSON or YAML specification rather than sending requests to the running API.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "cosign-image": {
    "provider": "OFFENSE / COSIGN",
    "engine": "Cosign",
    "category": "infrastructure",
    "icon": "target",
    "status": "IN OFFENSE",
    "title": "Container image provenance",
    "description": "Check an offline image signature bundle against an expected signer and image digest.",
    "input": "Signature bundle",
    "points": [
      "Uses a supplied Cosign bundle, signer identity, and OCI digest.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "zap-passive-har": {
    "provider": "OFFENSE / ZAP",
    "engine": "ZAP",
    "category": "web",
    "icon": "globe",
    "status": "IN OFFENSE",
    "title": "Passive web checks",
    "description": "Inspect captured web responses for passive security signals.",
    "input": "HAR capture",
    "points": [
      "Analyzes a supplied HAR without a live crawl or active requests.",
      "Included in Offense’s deployed scanner catalog, with recorded production verification.",
      "Review findings, confirm applicability, and verify any change with your own agent and repository checks."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  },
  "zizmor": {
    "provider": "OFFENSE / ZIZMOR",
    "engine": "Zizmor",
    "category": "source",
    "icon": "route",
    "status": "IN OFFENSE",
    "title": "GitHub Actions security",
    "description": "Offline checks for injection, permissions, and trust boundaries in supplied GitHub Actions workflows and actions.",
    "input": "Workflow YAML",
    "points": [
      "Checks supplied workflow and action YAML with Zizmor 1.31.1, without executing workflows.",
      "Offline coverage excludes online action history and advisory lookups; missing eligible input is reported as incomplete coverage.",
      "Static findings require review. The deployed scanner has synthetic production operator-canary evidence, not exploit confirmation."
    ],
    "url": "https://offense.sh/app#tools",
    "action": "View tool and pricing"
  }
};
