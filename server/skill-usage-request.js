// Only capability handlers call this with their server-selected channel and
// operation. Counts come from the returned server report, never request fields.
const normalizeSeverity = value => ({ critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' })[String(value).toLowerCase()] || 'unknown';

export async function measureSkillAnalysis(store, { channel, operation }, action) {
  let attempt;
  try { attempt = store?.start({ channel, operation }); } catch { /* Usage cannot break an audit. */ }
  try {
    const report = await action();
    try {
      const findings = Array.isArray(report.findings) ? report.findings : report.vulnerabilityCheck?.findings || [];
      const severity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
      for (const finding of findings) severity[normalizeSeverity(finding.severity)]++;
      const partial = report.status === 'partial' || report.coverage?.status === 'partial' ||
        Boolean(report.vulnerabilityCheck && (report.warnings?.length || report.vulnerabilityCheck.skippedPackages > 0));
      attempt?.finish({ status: partial ? 'partial' : 'completed',
        checkedPackages: report.coverage?.checkedPackages ?? report.vulnerabilityCheck?.checkedPackages ?? report.packages?.length ?? 0,
        advisoryMatches: findings.length, severity });
    } catch { /* No response, source or error text is logged or stored. */ }
    return report;
  } catch (error) {
    try { attempt?.finish({ status: error.status >= 400 && error.status < 500 ? 'rejected' : 'failed' }); } catch {}
    throw error;
  }
}

export const skillOperation = input => input?.planning !== undefined ? 'planning' : 'audit';
