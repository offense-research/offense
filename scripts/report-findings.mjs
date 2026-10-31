import { explainVulnerabilityImpact } from '../shared/vulnerability-impact.js';

const text = value => typeof value === 'string' ? value.trim() : '';
const strings = value => Array.isArray(value) ? value.filter(item => text(item)).map(item => item.trim()) : [];
const severities = new Set(['critical', 'high', 'medium', 'low', 'unknown']);
// Interpret only our stable rule IDs, not arbitrary substrings in scanner text.
const ruleTypes = {
  'purple.js.dynamic-eval': 'Code injection',
  'purple.js.shell-exec': 'Command injection',
  'purple.python.shell-execution': 'Command injection',
  'purple.python.unsafe-deserialization': 'Unsafe deserialization',
  'purple.js.request-sql-injection': 'SQL injection',
  'purple.js.request-command-injection': 'Command injection',
  'purple.js.request-path-traversal': 'Arbitrary file read',
  'purple.js.request-ssrf': 'Server-side request forgery',
  'purple.python.request-sql-injection': 'SQL injection',
  'purple.python.request-command-injection': 'Command injection',
  'purple.python.request-path-traversal': 'Arbitrary file read',
  'purple.python.request-ssrf': 'Server-side request forgery',
  'offense.js.jwt-signature-disabled': 'Authentication bypass',
  'offense.python.jinja-autoescape-disabled': 'Cross-site scripting'
};

function reviewContext(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !['reviewer', 'scope', 'reviewedAt', 'severityReason', 'attackerOutcome', 'attackerAccess', 'businessImpact', 'recommendedFix'].every(key => text(value[key])) ||
      !Number.isFinite(Date.parse(value.reviewedAt)) || !Array.isArray(value.evidence) || !value.evidence.length || !value.evidence.every(item => text(item)) ||
      !Array.isArray(value.unknowns) || !value.unknowns.every(item => typeof item === 'string') ||
      !['reproduced', 'not_tested', 'not_applicable'].includes(value.exploitability) ||
      !severities.has(value.severity) || value.exploitability === 'not_applicable' && value.severity !== 'unknown') return null;
  return value;
}

/** Render-time interpretation only: never upgrades a scanner signal to proof. */
export function explainReportFinding(finding, report) {
  const scanner = report.schemaVersion !== 'offense.audit.v1' || typeof finding.tool === 'string';
  const ruleId = text(finding.ruleId);
  const knownRule = (finding.tool === 'opengrep' && ruleId.startsWith('purple.') ||
    finding.tool === 'semgrep' && ruleId.startsWith('offense.')) ? ruleTypes[ruleId] : null;
  // Recompute instead of trusting a saved/generated impact object.
  const impact = explainVulnerabilityImpact({ ...finding, summary: knownRule || finding.summary || finding.title });
  let attack = impact.whatCouldHappen, business = impact.businessImpact.join(' ');
  const conditions = [...impact.exposureConditions];
  if (scanner) {
    // These are pattern-specific consequences, conditional on the vulnerable
    // operation being deployed and accepting the required attacker input.
    const tls = finding.tool === 'opengrep' && finding.ruleId === 'purple.js.tls-verification-disabled' ||
      finding.tool === 'semgrep' && finding.ruleId === 'offense.python.requests-tls-verification-disabled';
    const credential = ['gitleaks', 'gitleaks-history'].includes(finding.tool);
    if (tls) {
      attack = 'An attacker able to intercept or redirect this connection could impersonate the remote service because its certificate is not checked.';
      business = 'Data sent over that connection could be read or changed. Customer data or credentials are at risk only if the application sends them on this connection.';
      conditions.splice(0, conditions.length, 'The flagged HTTP client must be used. The attacker needs a position on the connection path or a way to redirect it; internet access alone does not establish this.');
    } else if (credential) {
      attack = 'Someone who obtains this value could use it to access the associated service if it is a real, still-valid credential.';
      business = 'Unauthorized access or charges are possible within that credential’s permissions. A pattern match does not show that the credential is valid, publicly exposed or already used by an attacker.';
      conditions.splice(0, conditions.length, 'Determine who could read the file or repository history, which service accepts the value, whether it is active, and which permissions it grants. Do not test a credential against a live service without authorization.');
    } else if (finding.tool === 'semgrep' && ruleId === 'offense.js.cookie-httponly-disabled') {
      attack = 'If an attacker can already run script on this page, they could read this cookie. Disabling HttpOnly does not itself let an attacker inject script.';
      business = 'If this cookie authenticates a session, stealing it could allow account misuse. A non-sensitive preference cookie may have little business impact.';
      conditions.splice(0, conditions.length, 'Confirm what the cookie contains, whether it is deployed, and whether an attacker can run script in the same page context.');
    } else if (finding.tool === 'semgrep' && ruleId === 'offense.python.xml-external-entities-enabled') {
      attack = 'Crafted XML could cause the parser to read a local file or contact another service if external entities and the required access are allowed.';
      business = 'Files readable by the application could be exposed or internal services contacted, depending on parser permissions and whether results reach the attacker.';
      conditions.splice(0, conditions.length, 'An attacker must supply XML to this parser. Confirm whether it can access files or the network and whether parsed results are returned.');
    } else if (finding.tool === 'semgrep' && ruleId === 'offense.python.flask-debug-enabled') {
      attack = 'A reachable debug interface could reveal internal error details. Running code through a debugger requires additional access and configuration; the flag alone does not prove this is possible.';
      business = 'Internal paths or application details could leak; wider compromise depends on whether an interactive debugger is actually exposed and accessible.';
      conditions.splice(0, conditions.length, 'Confirm deployment mode, network exposure and debugger access protections. A local development setting is not proof of production exposure.');
    }
  }
  const review = reviewContext(finding.riskReview);
  const providerSeverity = text(finding.providerSeverity || finding.severity).toLowerCase() || 'unknown';
  let priority = impact.priority.label;
  let priorityReason = impact.priority.reason;
  let severity = `Application severity: not determined. Reported scanner/advisory severity: ${providerSeverity.toUpperCase()}. This is not a rating of your deployed application's risk.`;
  let confidence = scanner ? 'Potential risk: a scanner reported a pattern or condition. It has not demonstrated an attack against your application.' :
    'Potential risk: a dependency version matched an advisory. This does not show that the affected feature is used or reachable by an attacker.';
  const unknowns = [...impact.limitations.slice(2), 'Deployment exposure, attacker permissions, affected data and business scope have not been established by this export.'];
  if (!review && !impact.evidence.matchedSignals.includes('explicit_no_authentication') && !impact.evidence.matchedSignals.includes('explicit_authentication_required')) {
    conditions.push('Whether a login or a particular role is required is unknown unless the scoped review below establishes it.');
  }
  if (finding.verification?.confirmed === true) unknowns.push('The input claims confirmation. A confirmation flag alone is not exploit evidence.');
  if (finding.riskReview && !review) unknowns.push('The supplied risk review is incomplete or invalid and was not used to confirm exploitability, set severity or lower priority. See the original evidence.');
  if (review) {
    attack = `Reviewer-described outcome: ${review.attackerOutcome}`;
    business = `Reviewer-assessed business impact: ${review.businessImpact}`;
    conditions.unshift(`Reviewed scope: ${review.attackerAccess}`);
    severity = `Reviewer-assessed application severity: ${review.severity.toUpperCase()}. ${review.severityReason} Reported scanner/advisory severity remains ${providerSeverity.toUpperCase()}.`;
    confidence = review.exploitability === 'reproduced' ? 'Reviewer reports a reproduced exploit in the scope below. This exporter has not executed or independently verified that evidence; it is not proof of production compromise.' :
      review.exploitability === 'not_applicable' ? 'Reviewer reports this finding does not apply in the scope below. This is not a general safety claim or proof of a fix.' :
        'Potential risk: the reviewer has not reproduced an exploit. The context below is an assessment, not confirmation.';
    priority = review.exploitability === 'not_applicable' ? 'Monitor the reviewed scope' :
      ['critical', 'high'].includes(review.severity) ? 'Urgent review and containment planning' :
        review.severity === 'medium' ? 'Schedule remediation in the next maintenance cycle' :
          review.severity === 'low' ? 'Plan a routine fix' : 'Establish priority before accepting the risk';
    priorityReason = review.exploitability === 'not_applicable' ? 'Keep the scoped evidence and reassess when code, deployment or access changes. Do not mark the underlying issue fixed.' :
      `Based on the review's ${review.severity} severity assessment and ${review.exploitability.replaceAll('_', ' ')} exploit status. Agree an owner and deadline using the actual service exposure; no universal remediation deadline is inferred.`;
    unknowns.splice(0, unknowns.length, ...strings(review.unknowns), 'The exporter has not verified the review, its evidence, or whether its scope still matches the current deployment.');
  }
  const pkg = typeof finding.package === 'object' ? finding.package : { name: finding.package, installedVersion: finding.installedVersion };
  const plan = (Array.isArray(report.remediation?.plans) ? report.remediation.plans : []).find(item => item &&
    (finding.remediation?.planId && item.id === finding.remediation.planId ||
      pkg?.name && pkg.installedVersion && item.package === pkg.name && item.currentVersion === pkg.installedVersion));
  const fixes = review ? [review.recommendedFix] : typeof finding.remediation === 'string' ? [finding.remediation] : [...impact.nextSteps];
  const versions = strings(finding.advisoryListedFixedVersions);
  if (text(finding.fixedVersion)) versions.push(finding.fixedVersion);
  if (versions.length) fixes.push(`Provider-listed fixed version candidates: ${versions.join(', ')}. Verify the affected version range and compatibility; these are not automatically safe upgrade recommendations.`);
  if (text(plan?.proposedVersion)) fixes.push(`Matching upgrade plan proposes ${plan.proposedVersion}; recorded status: ${text(plan.status) || 'unknown'}. Compatibility and exploit remediation still require verification.`);
  if (text(finding.remediation?.blocker)) fixes.push(`Planning blocker: ${finding.remediation.blocker}`);
  fixes.push('After the change, test the attack path and normal behavior, then rescan the same scope. Passing normal tests alone does not prove the security issue is fixed.');
  const identity = [text(finding.advisoryId || finding.ruleId || finding.id), text(pkg?.name), text(pkg?.installedVersion),
    text(finding.file) && `${finding.file}${Number.isInteger(finding.line) ? `:${finding.line}` : ''}`].filter(Boolean).join(' / ');
  return { title: text(finding.summary || finding.title) || 'Finding requiring investigation', identity, priority, priorityReason, severity, confidence,
    attack, conditions, business, unknowns, fixes,
    review: review ? [`Reviewer: ${review.reviewer}; reviewed: ${review.reviewedAt}; scope: ${review.scope}`,
      ...review.evidence.map(item => `Evidence supplied by reviewer: ${item}`)] : [],
    basis: review ? 'Reviewer-supplied scoped assessment and source metadata; review evidence has not been independently verified by this exporter.' :
      scanner ? 'Conditional interpretation of scanner title, known rule identity or supplied weakness labels; not a reproduced attack.' :
      'Conditional interpretation of advisory title and weakness labels; not a source-code or deployment review.',
    references: scanner ? [] : impact.evidence.references };
}
