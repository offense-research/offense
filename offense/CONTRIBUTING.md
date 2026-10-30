# Contributing

Use Node.js 24 or newer. Install the locked dependencies with `npm ci --ignore-scripts`, then run
`npm test` and `npm run check`. Use synthetic fixtures and mock network providers
for default tests; make any registry, Docker or scanner integration explicit.

Keep dependency metadata, source relevance, compatibility and security
reproduction evidence separate. A failure to install or start an application
must not be reported as reproducing a vulnerability.

Preserve unrelated project instructions and working changes. Do not commit
secrets, private repositories, customer reports, runtime databases or local
agent configuration. Reports remain local and are not anonymous telemetry.

Add a focused regression when fixing a substantive defect. Document coverage
limits and update commands or examples when behavior changes. Contributions to
project-owned code are submitted under this project's Apache 2.0 license;
preserve third-party notices for copied or modified upstream code.

Use the security-reporting process in SECURITY.md for sensitive findings.

Offense is maintained by Offense Security. The 0.2.0 engine is published as source
in this repository. Keep the npm package marked private, and do not add publish or production
deployment automation without an explicit release instruction.
