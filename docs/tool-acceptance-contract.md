# Tool acceptance contract

Use synthetic fixtures and report the actual execution level: mocked adapter,
real local engine or separately authorized hosted run. A catalog listing, a
successful process or zero findings alone does not establish detection quality.
Do not publish private operational receipts or customer data as evidence.

| Gate | Evidence required |
| --- | --- |
| G1 — discovery and input | Matching IDs/scope across directory, API, CLI and MCP; invalid/unsupported input rejected before retention or billing reservation. |
| G2 — engine correctness | Pinned real engine finds the expected rule/advisory on a positive fixture and accepts its safe counterpart. Malformed inputs, stale data and engine failures remain visibly incomplete. |
| G3 — client execution | Authorized CLI/API/MCP submission and result retrieval agree on input identity, scope, tool versions and normalized outcomes. Discovery alone is insufficient. |
| G4 — billing and retries | Exact quote/cap enforcement, same-key idempotency and failed/partial reservation release. For self-hosted execution, demonstrate zero charges without disabling authorization or isolation. |
| G5 — isolation and cleanup | Tenant/key boundaries, revocation, secret redaction, input/archive limits, target ownership, egress restrictions and cleanup under representative failures. |
| G6 — operations and coverage | Data freshness/provenance, bounded resources, restart/recovery, partial/error reasons and honest supported modes. Observations, advisory matches and confirmed vulnerabilities stay distinct. |

Include source/image/engine revisions, fixture fingerprints, expected versus
actual rule IDs or observations, command and result status. Record skipped gates
and limitations. Each advertised input/execution family needs its own real
acceptance evidence; a source scan cannot certify network or mobile execution.

Live checks require approval for the environment, account, targets, credentials,
maximum spend and cleanup. A pull request is not authorization to deploy or
publish an image, change pricing or enable a scanner.
