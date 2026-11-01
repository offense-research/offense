import { auditAgentPrompt, auditSummaryCounts } from './offense-planning.js';

const sameCursor = (a, b) => a?.metadataFingerprint === b?.metadataFingerprint && a?.packageOffset === b?.packageOffset &&
  a?.advisoryOffset === b?.advisoryOffset && a?.batchFingerprint === b?.batchFingerprint;

export function validateScanPage(page) {
  const scan = page.scanning;
  if (!scan || scan.schemaVersion !== 'offense.scanning.v1' || scan.metadataFingerprint !== page.metadataFingerprint ||
    !Number.isInteger(scan.totalPackages) || scan.totalPackages < 1 || scan.totalPackages > 5000 || page.coverage.planningOnly) {
    throw Error('Invalid advisory scan page. Retain the previous successful report.');
  }
  const validCursor = cursor => cursor && cursor.metadataFingerprint === page.metadataFingerprint &&
    Number.isInteger(cursor.packageOffset) && cursor.packageOffset >= 0 && cursor.packageOffset < scan.totalPackages && cursor.packageOffset % 100 === 0 &&
    Number.isInteger(cursor.advisoryOffset) && cursor.advisoryOffset >= 0 && cursor.advisoryOffset <= 100000 &&
    (cursor.batchFingerprint === null || /^[a-f0-9]{64}$/.test(cursor.batchFingerprint)) &&
    (cursor.advisoryOffset === 0 || !!cursor.batchFingerprint);
  const start = scan.start || { packageOffset: 0, advisoryOffset: 0 };
  if ((scan.start !== null && !validCursor(scan.start)) || (scan.next !== null && (!validCursor(scan.next) ||
    scan.next.packageOffset < start.packageOffset || (scan.next.packageOffset === start.packageOffset && scan.next.advisoryOffset <= start.advisoryOffset))) ||
    page.coverage.checkedPackages !== (scan.next?.packageOffset ?? scan.totalPackages) - start.packageOffset ||
    ((scan.start || scan.next) && (page.status !== 'partial' || page.coverage.status !== 'partial'))) {
    throw Error('Advisory scan page made no valid progress. Retain the previous successful report.');
  }
}

// Only a contiguous chain starting at the first page can establish full coverage.
// Keep the original metadata identity and merge evidence, never sliced lockfiles.
export function mergeAuditScanPage(base, page, planLimit = 0) {
  validateScanPage(page);
  if (!base.scanning?.next || base.scanning.start !== null || base.metadataFingerprint !== page.metadataFingerprint ||
    base.scanning.totalPackages !== page.scanning.totalPackages || !sameCursor(base.scanning.next, page.scanning.start) ||
    base.coverage.checkedPackages !== page.scanning.start.packageOffset) {
    throw Error('Advisory scan continuation does not match the saved scan.');
  }
  const result = structuredClone(base), findings = new Map(result.findings.map(finding => [finding.id, finding]));
  for (const finding of page.findings) {
    if (findings.has(finding.id)) throw Error('Advisory scan continuation repeated previously returned evidence.');
    findings.set(finding.id, structuredClone(finding));
  }
  result.findings = [...findings.values()];
  result.scanning.next = page.scanning.next;
  result.scanning.completedPages++;
  result.scanning.lastScannedAt = page.scannedAt;
  result.coverage.checkedPackages += page.coverage.checkedPackages;
  result.coverage.skippedPackages = Math.max(base.coverage.skippedPackages, page.coverage.skippedPackages);
  result.coverage.warnings = [...new Set([...base.coverage.warnings, ...page.coverage.warnings])];
  result.coverage.advisoryScope = result.scanning.next ? 'scan_page' : 'full_audit';
  result.coverage.status = result.scanning.next || result.coverage.warnings.length || result.coverage.skippedPackages ? 'partial' : 'complete';
  const rank = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  const targets = [...new Map([...result.findings].sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0))
    .map(finding => [finding.remediation.targetId, finding])).values()];
  const pending = targets.map(finding => finding.remediation.targetId);
  const canPlan = !result.scanning.next && planLimit > 0;
  result.summary = { ...auditSummaryCounts(result.findings, result.scanning.next ? 'scan_page' : 'full_audit'),
    critical: result.findings.filter(f => f.severity === 'critical').length, high: result.findings.filter(f => f.severity === 'high').length,
    affectedPackages: targets.length, checkedUpgradePaths: 0 };
  result.remediation.plans = [];
  result.remediation.blockers = targets.map(finding => ({ targetId: finding.remediation.targetId,
    package: finding.package.name, version: finding.package.installedVersion, status: 'not_planned',
    code: canPlan ? 'plan_limit' : 'not_requested', category: 'planning_deferred', retryable: true,
    reason: result.scanning.next ? 'Finish advisory scanning before upgrade planning.' : 'Upgrade planning has not run for this target.',
    nextAction: result.scanning.next ? 'Continue with scanning.next and retain all previous pages.' : 'Continue with remediation.planning.next using the complete original lockfiles.' }));
  result.remediation.planning = { ...result.remediation.planning, totalTargets: pending.length, attemptedTargetIds: [],
    remainingTargetIds: pending, hasMore: canPlan && pending.length > 0,
    next: canPlan && pending.length ? { metadataFingerprint: result.metadataFingerprint, pendingTargetIds: pending } : null,
    completedPages: 0 };
  result.remediation.status = canPlan && pending.length ? 'partial' : 'not_requested';
  result.status = result.coverage.status === 'partial' || result.remediation.planning.hasMore ? 'partial' : 'complete';
  result.remediation.agentPrompt = auditAgentPrompt(result);
  return result;
}
