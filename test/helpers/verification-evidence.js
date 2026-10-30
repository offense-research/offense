import { contractFingerprint } from '../../agent/verification-gate.mjs';
export function verifiedEvidence() {
  const contract = { confirmed: true, summary: 'Tenant isolation fix', testPaths: ['test/security.test.mjs'], normal: ['npm', 'test'],
    securityTests: [{ file: 'test/security.test.mjs', name: 'cross-tenant read is forbidden', invariant: 'A tenant cannot read another tenant document.', operator: 'strictEqual', expected: 403, vulnerableActual: 200 }] };
  const normal = { protocolVersion: 2, complete: true, code: 0, passed: true, infrastructureErrors: [], summary: { passed: 1, failed: 0, skipped: 0, todo: 0, cancelled: 0 },
    tests: [{ file: 'test/normal.test.mjs', name: 'owner access works', line: 1, status: 'passed', skip: false, todo: false }] };
  const security = { ...structuredClone(normal), tests: [{ file: 'test/security.test.mjs', name: 'cross-tenant read is forbidden', line: 1, status: 'passed', skip: false, todo: false }] };
  const failed = structuredClone(security); failed.summary.passed = 0; failed.summary.failed = 1; failed.passed = false;
  failed.classification = 'security_assertion_failure'; failed.tests[0].status = 'failed';
  failed.tests[0].assertion = { code: 'ERR_ASSERTION', failureType: 'testCodeFailure', operator: 'strictEqual', actual: 200, expected: 403 };
  return { gateVersion: 2, verified: true, contract, contractFingerprint: contractFingerprint(contract), testFilesUnchanged: true,
    baselineNormal: normal, patchedNormal: structuredClone(normal), baselineReproduction: failed, patchedReproduction: security };
}
