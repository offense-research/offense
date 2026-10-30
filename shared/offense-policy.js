// Policy decisions are deterministic host-side checks, independent of an agent's
// choice of tools. Passing this policy is not a security attestation.
export const AUTOMATION_POLICY_SCHEMA = 'offense.automation.v1';
export const SECURITY_DECISION_SCHEMA = 'offense.decision.v1';
export const SECURITY_EVENTS = Object.freeze(['manual', 'dependency_change', 'scheduled', 'pre_deploy', 'post_deploy', 'agent_run']);

export function defaultAutomationPolicy() {
  return { schemaVersion: AUTOMATION_POLICY_SCHEMA, enabled: true, onChange: true, schedule: 'daily',
    preDeploy: false, postDeploy: false, agentRun: false,
    gate: { mode: 'report', minimumSeverity: 'high', onIncomplete: 'block' } };
}

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const invalid = () => Object.assign(new Error('Invalid automation policy. Use the supported settings and values.'), { status: 400, code: 'invalid_automation_policy' });

export function normalizeAutomationPolicy(input = {}) {
  const result = defaultAutomationPolicy();
  if (!record(input) || Object.keys(input).some(key => !Object.hasOwn(result, key))) throw invalid();
  if (input.schemaVersion !== undefined && input.schemaVersion !== AUTOMATION_POLICY_SCHEMA) throw invalid();
  for (const key of ['enabled', 'onChange', 'preDeploy', 'postDeploy', 'agentRun']) {
    if (input[key] === undefined) continue;
    if (typeof input[key] !== 'boolean') throw invalid();
    result[key] = input[key];
  }
  if (input.schedule !== undefined) {
    if (!['daily', 'weekly', 'off'].includes(input.schedule)) throw invalid();
    result.schedule = input.schedule;
  }
  if (input.gate !== undefined) {
    if (!record(input.gate) || Object.keys(input.gate).some(key => !Object.hasOwn(result.gate, key))) throw invalid();
    const allowed = { mode: ['report', 'block'], minimumSeverity: ['high', 'critical'], onIncomplete: ['block', 'report'] };
    for (const key of Object.keys(allowed)) {
      if (input.gate[key] === undefined) continue;
      if (!allowed[key].includes(input.gate[key])) throw invalid();
      result.gate[key] = input.gate[key];
    }
  }
  return result;
}

function eventEnabled(policy, event) {
  if (event === 'manual') return true;
  if (!policy.enabled) return false;
  return ({ dependency_change: policy.onChange, scheduled: policy.schedule !== 'off',
    pre_deploy: policy.preDeploy, post_deploy: policy.postDeploy, agent_run: policy.agentRun })[event];
}

export function evaluateSecurityPolicy(report, input = {}, event = 'manual', { now = Date.now() } = {}) {
  if (!SECURITY_EVENTS.includes(event)) throw Object.assign(new Error('Unsupported security lifecycle event.'), { code: 'invalid_security_event' });
  const policy = normalizeAutomationPolicy(input);
  const enabled = eventEnabled(policy, event);
  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, atOrAboveThreshold: 0,
    checkedPackages: 0, skippedPackages: 0 };
  const limitations = ['This decision uses known dependency advisory metadata, not verified application exploitability.',
    'A passing threshold check does not establish that an application or agent is secure.'];
  const base = { schemaVersion: SECURITY_DECISION_SCHEMA, event, enabled, counts, limitations };
  if (!enabled) return { ...base, action: 'skip', passed: null, reason: 'This automatic trigger is disabled. No security check is asserted.' };

  const coverage = record(report?.coverage) ? report.coverage : null;
  const findings = Array.isArray(report?.findings) && report.findings.length <= 100_000 ? report.findings : null;
  const valid = record(report) && report.schemaVersion === 'offense.audit.v1' && report.capability === 'audit_dependencies' &&
    ['complete', 'partial'].includes(report.status) && coverage && findings && record(report.summary);
  let incomplete = !valid;
  // A threshold decision over a saved report must not authorize an operation
  // using old evidence, even when a caller bypasses the HTTP client's checks.
  if (!Number.isFinite(now) || !Number.isFinite(report?.scannedAt) || report.scannedAt < now - 15 * 60_000 || report.scannedAt > now + 5 * 60_000) incomplete = true;
  if (coverage) {
    if (Number.isSafeInteger(coverage.checkedPackages) && coverage.checkedPackages >= 0) counts.checkedPackages = coverage.checkedPackages;
    else incomplete = true;
    if (Number.isSafeInteger(coverage.skippedPackages) && coverage.skippedPackages >= 0) counts.skippedPackages = coverage.skippedPackages;
    else incomplete = true;
    if (coverage.status !== 'complete' || counts.checkedPackages === 0 || counts.skippedPackages > 0 || coverage.planningOnly ||
        !Array.isArray(coverage.warnings) || coverage.warnings.length > 0) incomplete = true;
  }
  if (findings) {
    counts.total = findings.length;
    for (const finding of findings) {
      const level = typeof finding?.severity === 'string' ? finding.severity.toLowerCase() : 'unknown';
      const normalized = ['moderate', 'medium'].includes(level) ? 'medium' : ['critical', 'high', 'low'].includes(level) ? level : 'unknown';
      counts[normalized]++;
      if (!record(finding) || normalized === 'unknown') incomplete = true;
    }
  }
  counts.atOrAboveThreshold = counts.critical + (policy.gate.minimumSeverity === 'high' ? counts.high : 0);
  if (report?.status !== 'complete' || report?.summary?.advisoryMatches !== counts.total) incomplete = true;
  const canBlock = policy.gate.mode === 'block' && ['pre_deploy', 'agent_run'].includes(event);
  if (event === 'post_deploy') limitations.push('This check runs after deployment and cannot block or undo the deployment that already completed.');
  if (incomplete) {
    limitations.push('Missing, partial, unknown-severity or unavailable evidence must not be treated as a clean scan.');
    // Known high-risk matches still block even if incomplete checks are set to
    // report. That override only permits missing evidence, not known findings.
    const block = canBlock && (counts.atOrAboveThreshold > 0 || policy.gate.onIncomplete === 'block');
    return { ...base, action: block ? 'block' : 'report', passed: null,
      reason: counts.atOrAboveThreshold > 0
        ? 'Advisory matches meet the selected threshold, and scan evidence is incomplete. Review both before proceeding.'
        : 'A complete security result is unavailable. Coverage or provider evidence needs review.' };
  }
  const meetsThreshold = counts.atOrAboveThreshold > 0;
  return { ...base, action: canBlock ? meetsThreshold ? 'block' : 'allow' : 'report', passed: !meetsThreshold,
    reason: meetsThreshold ? 'Known advisory matches meet the selected severity threshold. Review their impact and remediation.'
      : 'No returned advisory matches meet the selected threshold in this complete checked scope.' };
}
