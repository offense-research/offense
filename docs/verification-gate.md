# Structured security verification (gate v2)

A fix qualifies only when all of the following hold:

1. The original repository normal suite runs actual tests and passes with no skips, todos, cancellations or infrastructure errors.
2. The same new security regression files run against the original code. Every declared security test fails with an `ERR_ASSERTION`, `testCodeFailure`, the declared strict/deep equality operator, the safe expected value, and the exact unsafe observed value. No unrelated failing test is accepted.
3. Those same test identities and bytes pass against the patched code, without skips or missing tests.
4. The identical original normal suite passes against the patched code.
5. Normal/regression test files and both checkouts remain unchanged by verification commands.

`agent/verification-gate.mjs` defines the evidence contract and final qualification predicate. The local Docker runner, Cloudflare runner, application result acceptance, workspace discovery ledger, operator aggregates and company dashboard all use it. A process exit code alone never qualifies.

The trusted observer uses structured `node:test` events from subprocesses, so repository stdout that resembles a successful report is not a verdict. Missing imports, syntax errors, crashes, hook failures, extra asynchronous errors, empty suites and timeouts are blockers. The baseline failure records the named assertion and actual/expected values. Only matching security assertions receive the UI label “security assertion reproduced.”

## Supported verification adapter

Automatic gate v2 currently supports Node.js `node:test` and equality assertions using `node:assert/strict`. The pinned root test script must be a supported `node --test` command, or `npm test` resolving to that command. No arbitrary shell commands, test-name filters, narrowed test suites or framework substitution are accepted. Declared normal paths must include detected existing test files. New regressions cannot overwrite old normal tests. Unsupported Jest/Vitest/custom test setup remains an explicit blocker requiring a structured adapter; it is never presented as a verified fix.

Pi receives the contract in `agent/verification-prompt.mjs`. The plan specifies named security tests, a concrete invariant and the unsafe observable result supported by source/incident evidence. These are still agent-authored tests: the gate verifies their execution and exact assertion evidence, not semantic proof that an arbitrary test models a real vulnerability. Patches, test source, positive controls and incident relevance remain reviewable evidence.

## Historical records

Earlier confirmations remain in `vulnerability_discoveries` with their evidence. They are excluded from current confirmed counts until re-verified under gate v2. Workspace metrics expose `legacyUnreviewed`; the UI offers re-verification of earlier runs. Upgrading an old ledger record preserves its earlier verification evidence and agent-run attribution. Current operator totals and confirmed-history charts apply the same qualification rule.

## Checks

- `node --test test/strict-verification.test.js`: real subprocess fixtures for security failures, imports/setup errors, crashes, skips/todos/empty suites, timeouts, changed normal tests, unrelated failures and broken patches.
- `node agent/verification-self-test.mjs`: bounded synthetic positive/negative suite without provider credentials or paid model calls.
- Operator-only `POST /diagnostics/verification` on the agent Worker runs the same synthetic suite inside its disposable container, then destroys it. It requires the existing shared agent secret and accepts no customer input.
