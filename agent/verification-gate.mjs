import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';
const relative = value => typeof value === 'string' && value.length <= 250 && /^[A-Za-z0-9_./-]+$/.test(value) && !value.startsWith('/') && !value.split('/').some(part => !part || part === '.' || part === '..');
const jsonValue = value => {
  if (value === null || ['string', 'boolean'].includes(typeof value) || typeof value === 'number' && Number.isFinite(value)) return true;
  if (Array.isArray(value)) return value.length <= 100 && value.every(jsonValue);
  return value && typeof value === 'object' && Object.keys(value).length <= 100 && Object.values(value).every(jsonValue);
};
export function validateSecurityPlan(plan) {
  if (!plan || typeof plan.summary !== 'string' || plan.summary.length > 4000) throw new Error('Pi did not provide a valid investigation plan.');
  if (plan.confirmed === false) return { confirmed: false, summary: plan.summary };
  if (plan.confirmed !== true || !Array.isArray(plan.testPaths) || !plan.testPaths.length || plan.testPaths.length > 20 || plan.testPaths.some(file => !relative(file) || !/\.(?:test|spec)\.[cm]?js$/.test(file))) throw new Error('Invalid regression test paths; provide new Node test files.');
  if (!Array.isArray(plan.securityTests) || !plan.securityTests.length || plan.securityTests.length > 20 || plan.securityTests.some(item =>
    !plan.testPaths.includes(item.file) || typeof item.name !== 'string' || !item.name || item.name.length > 200 ||
    typeof item.invariant !== 'string' || item.invariant.length < 20 || item.invariant.length > 2000 ||
    !['strictEqual', 'deepStrictEqual'].includes(item.operator) || !Object.hasOwn(item, 'expected') || !Object.hasOwn(item, 'vulnerableActual') ||
    !jsonValue(item.expected) || !jsonValue(item.vulnerableActual) || isDeepStrictEqual(item.expected, item.vulnerableActual))) throw new Error('Declare named security assertions, their invariant, operator, safe expected value and observed vulnerable value.');
  if (new Set(plan.securityTests.map(item => `${item.file}:${item.name}`)).size !== plan.securityTests.length || plan.testPaths.some(file => !plan.securityTests.some(item => item.file === file))) throw new Error('Security test identities must be unique and cover every regression file.');
  const reproduction = ['node', '--test', ...plan.testPaths];
  if (plan.reproduction && !isDeepStrictEqual(plan.reproduction, reproduction)) throw new Error('Invalid reproduction command: only the declared Node regression files may run.');
  if (!Array.isArray(plan.normal) || !plan.normal.length || plan.normal.length > 30 || plan.normal.some(arg => typeof arg !== 'string' || !arg || arg.length > 300)) throw new Error('Invalid normal test command.');
  const result = { confirmed: true, summary: plan.summary, testPaths: [...new Set(plan.testPaths)], securityTests: plan.securityTests, reproduction, normal: plan.normal };
  if (JSON.stringify(result).length > 24000) throw new Error('Security assertion contract exceeds 24 KB.');
  return result;
}
export const contractFingerprint = plan => createHash('sha256').update(JSON.stringify(plan.securityTests)).digest('hex');
const clean = check => check?.protocolVersion === 2 && check.complete === true && !check.timedOut && !check.signal && !check.truncated && Array.isArray(check.tests) && check.tests.length > 0 &&
  check.summary && check.summary.skipped === 0 && check.summary.todo === 0 && check.summary.cancelled === 0 && !check.infrastructureErrors?.length &&
  new Set(check.tests.map(item => `${item.file}:${item.line}:${item.name}`)).size === check.tests.length && check.tests.every(item => !item.skip && !item.todo);
export function normalPassed(check) {
  return clean(check) && check.code === 0 && check.summary.failed === 0 && check.summary.passed > 0 && check.tests.every(item => item.status === 'passed');
}
export function securityFailure(check, assertions) {
  if (!clean(check) || check.code !== 0 || check.summary.failed !== assertions.length) return false;
  const failed = check.tests.filter(item => item.status === 'failed');
  if (failed.length !== assertions.length) return false;
  return assertions.every(expected => {
    const matches = failed.filter(item => item.file === expected.file && item.name === expected.name);
    const actual = matches[0]?.assertion;
    return matches.length === 1 && actual?.code === 'ERR_ASSERTION' && actual.failureType === 'testCodeFailure' && actual.operator === expected.operator &&
      isDeepStrictEqual(actual.expected, expected.expected) && isDeepStrictEqual(actual.actual, expected.vulnerableActual);
  });
}
export function securityPassed(check, baseline, assertions) {
  return normalPassed(check) && isDeepStrictEqual(check.tests.map(item => `${item.file}:${item.line}:${item.name}`).sort(), baseline.tests.map(item => `${item.file}:${item.line}:${item.name}`).sort()) &&
    assertions.every(expected => check.tests.filter(item => item.file === expected.file && item.name === expected.name && item.status === 'passed').length === 1);
}
export function verificationQualified(report) {
  if (report?.gateVersion !== 2 || report.verified !== true || !report.contract || !report.testFilesUnchanged || !normalPassed(report.baselineNormal) || !normalPassed(report.patchedNormal)) return false;
  try {
    const plan = validateSecurityPlan(report.contract);
    return report.contractFingerprint === contractFingerprint(plan) && securityFailure(report.baselineReproduction, plan.securityTests) &&
      securityPassed(report.patchedReproduction, report.baselineReproduction, plan.securityTests) &&
      isDeepStrictEqual(report.baselineNormal.tests.map(item => `${item.file}:${item.line}:${item.name}`).sort(), report.patchedNormal.tests.map(item => `${item.file}:${item.line}:${item.name}`).sort());
  } catch { return false; }
}
