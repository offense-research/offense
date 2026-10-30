<!--
Read docs/contributing-tools.md before filling this in.
Use synthetic inputs and sanitized evidence only. Never paste credentials,
customer source, private reports or raw secret-bearing scanner output.
Remove inapplicable sections or mark N/A with a reason. Check only verified items;
a listing correction does not require new engine or billing execution.
-->

## Tool and scope

- Tool ID(s):
- Contribution: listing correction / new integration / coverage change / local helper
- Problem and resulting behavior:
- Supported inputs, required fields and limits:
- Coverage exclusions and compatibility changes:
- Execution modes actually supported (local / hosted; offline / network / mobile):

## Upstream and licensing

- Upstream source and pinned engine version/checksum:
- Rules/templates/data revisions, provenance and freshness requirements:
- Engine, dependencies, rules and dataset licenses/notices (link separately):
- Distribution or network-use obligations and unresolved license questions:

## Data, authority and failure behavior

- Data leaving the machine, credentials, destinations and required consent/ownership:
- Isolation, resource budgets, redaction and cleanup:
- Invalid input, missing/stale prerequisites, timeouts and incomplete coverage:
- Result type and sanitized sample (findings / observations / provenance / advisories):

## Verification evidence

<!-- Link fixtures and give expected vs actual rule IDs/observations, not just counts.
Label each check: mocked adapter, real local engine, or authorized hosted run.
Include commands, engine/image/data revisions and fixture fingerprints as applicable.
-->

| Check | Fixture / command / evidence | Expected vs actual result | Execution level |
| --- | --- | --- | --- |
| Known positive and safe counterpart | | | |
| Malformed input, limits and engine failure | | | |
| Redaction, isolation and cleanup | | | |
| Quote cap, same-key retry and partial/failed hold release | | | |
| Tenant isolation and revoked keys | | | |
| CLI/API/MCP discovery and result agreement | | | |
| Directory page, search, keyboard, narrow layout and no-JS navigation | | | |

- Checks not run, reasons and remaining acceptance gaps:
- Screenshots/recording for visible or interaction changes:

## Pricing and rollout

- Proposed billing unit/price, or unchanged (not a live rate-card change):
- Image, data, configuration and enablement prerequisites:
- Rollout order, cleanup and rollback plan:
- Any separately authorized live checks: environment, target/account scope,
  approved spend cap, sanitized outcome and cleanup (never credential values):

## Contributor checks

- [ ] Canonical contracts, client behavior and directory claims agree; generated copies were not hand-edited.
- [ ] Findings, observations and confirmed vulnerabilities remain distinct; incomplete results are not reported as clean.
- [ ] Evidence and attachments contain no secrets or customer data; unverified claims and skipped checks are explicit.
- [ ] This PR does not itself authorize deployment, live pricing/enablement changes, image/package publication or repository publication.
