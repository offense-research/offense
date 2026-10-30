# Rehearse a dependency upgrade

The community rehearsal uses the current agent's isolated execution environment. `--sandboxed` is an acknowledgment of an existing boundary, not a sandbox provisioner or security attestation. A connector-only lockfile snapshot can be scanned, but cannot exercise application behavior.

The community runner does not load private hosted isolation adapters, Cloudflare certificate paths or implicit egress proxies. Explicit legacy isolation/proxy requests are rejected rather than silently weakened. Apply the intended execution and network policy in the calling agent's sandbox. Child commands receive fresh private HOME/npm-cache directories under that rehearsal's work root and no ambient provider credentials, proxies or host certificate overrides.

Prepare a clean committed checkout with the exact Node/package-manager version required by the project. Preserve user work elsewhere first. Read the repository's test/build scripts before authorizing execution. Use synthetic configuration and no production credentials. Existing npm/pnpm lifecycle hooks are disabled; ordinary declared test/typecheck/build commands still execute application-controlled code. Keep the package registry/network scope and filesystem restrictions appropriate to that project.

```sh
offense scan /isolated/project --output /tmp/project-scan
offense triage /isolated/project --scan /tmp/project-scan/scan.json --output /tmp/project-triage
offense rehearse /isolated/project --scan /tmp/project-scan/scan.json --sandboxed --output /tmp/project-rehearsal
```

Supported dependency metadata: npm v2/v3 lockfiles and pnpm v6/v9 lockfiles. Workspaces, aliases and peer contexts remain explicit. Unsupported ranges, unresolved workspace policy, conflicting targets and incomplete advisory coverage block automatic success claims.

The runner pins baseline and candidate to the same commit, performs frozen installs, chooses checked coordinated package changes, executes the same existing normal checks, and rescans the candidate through the included OSV/npm engine. Source and tests are fingerprinted before and after each command. A zero-exit command that rewrites tracked source or tests cannot produce a successful compatibility result. Command output, runtime and filesystem traversal are bounded. The original checkout remains untouched.

Review `rehearsal.json`, `rehearsal.md`, `upgrade.patch`, `candidate-scan/` and `handoff.md`. Failures, missing tests, truncated output, remaining advisories and newly introduced advisories remain visible. Successful compatibility checks do not establish that the original security issue was reachable, reproduced or fixed. The agent reviews source compatibility and, when authorized, adds issue-specific security regression evidence separately.

Choose a new report directory outside the checkout for each run. Existing directories and symlinked paths are rejected before execution; generated report updates preserve concurrent user edits.

If a provider refuses a requested regression, stop that operation and retain the verification gap. Do not reroute the refused task through another provider or remove safeguards. Independent permitted metadata checks can continue. PR publication, pushing branches and deployment require their own authorized scope.
