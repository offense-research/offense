import { createHash } from 'node:crypto';

const text = (value, max = 1000) => typeof value === 'string' ? value.slice(0, max) : '';
function location(value, root) {
  const name = text(value, 500).replaceAll('\\', '/');
  const relative = name.startsWith(`${root}/`) ? name.slice(root.length + 1) : name.replace(/^\.\//, '');
  if (!relative || relative.startsWith('/') || relative.split('/').some(part => part === '..')) return null;
  return relative;
}
const severity = value => ({ ERROR: 'HIGH', WARNING: 'MEDIUM', INFO: 'LOW', CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' }[String(value).toUpperCase()] || 'UNKNOWN');
export function normalizeFindings(tool, data, root = '/tmp/purple-scan/source', { inputPath } = {}) {
  const findings = [];
  function add(item) {
    const file = location(item.file, root);
    if (!file) return;
    const line = Number.isInteger(item.line) && item.line > 0 ? item.line : null;
    const result = { tool, ruleId: text(item.ruleId, 200), file, line, severity: severity(item.severity),
      title: text(item.title, 300), remediation: text(item.remediation, 1500),
      verification: 'scanner_finding', ...(item.package ? { package: text(item.package, 200), installedVersion: text(item.installedVersion, 100), fixedVersion: text(item.fixedVersion, 200) } : {}) };
    result.id = createHash('sha256').update(JSON.stringify([tool, result.ruleId, file, line, result.package, result.installedVersion])).digest('hex').slice(0, 32);
    findings.push(result);
  }
  if (tool === 'opengrep') for (const item of data.results || []) add({ file: item.path, line: item.start?.line,
    // Opengrep can prefix IDs with the operator config's temporary directory.
    // Retain stable rule identity without persisting that local path.
    ruleId: typeof item.check_id === 'string' ? item.check_id.match(/(?:^|\.)(purple\.(?:js|python)\.[a-z0-9-]+)$/)?.[1] || item.check_id : '',
    severity: item.extra?.severity, title: item.extra?.message,
    remediation: item.extra?.metadata?.remediation || 'Review the flagged operation and validate untrusted inputs before using this API.' });
  if (['trivy', 'trivy-vuln', 'trivy-sbom', 'trivy-image'].includes(tool)) for (const target of data.Results || []) for (const item of target.Vulnerabilities || []) add({
    file: inputPath || target.Target, line: item.PkgIdentifier?.LineNumber, ruleId: item.VulnerabilityID, severity: item.Severity,
    title: item.Title || item.VulnerabilityID, package: item.PkgName, installedVersion: item.InstalledVersion, fixedVersion: item.FixedVersion,
    remediation: item.FixedVersion ? `Upgrade ${text(item.PkgName, 200)} to a fixed version: ${text(item.FixedVersion, 200)}. Verify compatibility and re-scan.` : 'No fixed version reported. Assess exposure and apply a reviewed mitigation.' });
  if (tool === 'trivy-config') for (const target of data.Results || []) for (const item of target.Misconfigurations || []) {
    if (item.Status && String(item.Status).toUpperCase() !== 'FAIL') continue;
    add({
    file: target.Target, line: item.CauseMetadata?.StartLine || item.CauseMetadata?.Code?.Lines?.[0]?.Number,
    ruleId: item.ID || item.AVDID, severity: item.Severity, title: item.Title || item.ID,
    remediation: item.Resolution || 'Review this infrastructure setting against the rule and re-scan after changing it.' });
  }
  // Never copy Match, Secret, context, fingerprints or entropy from Gitleaks.
  if (tool === 'gitleaks') for (const item of data) add({ file: item.File, line: item.StartLine, ruleId: item.RuleID,
    severity: 'HIGH', title: `Potential exposed credential (${text(item.RuleID, 100)})`,
    remediation: 'Revoke and rotate this credential, remove it from source, and inspect its use. Removing the string alone does not revoke it.' });
  return [...new Map(findings.map(item => [item.id, item])).values()];
}

