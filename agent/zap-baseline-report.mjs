import { createHash } from 'node:crypto';
import { webScanOrigin, webScanUrlInScope } from '../server/web-scan-target.js';

const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const MAX_FINDINGS = 500;
const riskCode = { '0': 'LOW', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'CRITICAL' };

function safeTitle(value, ruleId) {
  // ZAP alert names are rule labels. Never expose evidence, parameters, request/response data or raw URLs.
  const title = typeof value === 'string' ? value.slice(0, 200).replace(/[\u0000-\u001f<>]/g, ' ').trim() : '';
  return title && !/https?:\/\/|[?=&]/i.test(title) ? title : `Passive web finding ${ruleId}`;
}

function sitesInReport(report) {
  if (Array.isArray(report.site)) return report.site;
  if (report.site && typeof report.site === 'object') return [report.site];
  throw new Error('ZAP did not return a valid site report.');
}

export function normalizeZapBaselineReport(report, target) {
  const origin = webScanOrigin(target);
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('ZAP did not return a valid report.');
  const sites = sitesInReport(report);
  const findings = new Map();
  let ignoredOffsite = 0, truncated = false;
  for (const site of sites) {
    if (!Array.isArray(site?.alerts)) throw new Error('ZAP did not return valid alerts.');
    for (const alert of site.alerts) {
      const id = String(alert?.pluginid ?? '');
      if (!/^\d{1,10}$/.test(id)) continue;
      const instances = Array.isArray(alert.instances) && alert.instances.length ? alert.instances : [{ uri: origin }];
      let inScope = false;
      for (const instance of instances) {
        if (webScanUrlInScope(instance?.uri, origin)) inScope = true;
        else ignoredOffsite++;
      }
      if (!inScope) continue;
      const fingerprint = createHash('sha256').update(`zap-baseline\n${origin}\n${id}`).digest('hex').slice(0, 32);
      if (findings.has(fingerprint)) continue;
      if (findings.size >= MAX_FINDINGS) { truncated = true; continue; }
      findings.set(fingerprint, { id: fingerprint, tool: 'zap-baseline', ruleId: id,
        file: origin, line: null, severity: riskCode[String(alert.riskcode)] || 'UNKNOWN',
        title: safeTitle(alert.alert, id),
        remediation: 'Review this passive web finding in the authorized application and verify the affected response before changing it.',
        verification: 'scanner_finding' });
    }
  }
  const warnings = [];
  if (ignoredOffsite) warnings.push('ZAP reported out-of-scope URLs; their details were discarded.');
  if (truncated) warnings.push('Report truncated to 500 rules. Narrow the target and repeat.');
  const status = warnings.length ? 'partial' : 'completed';
  return { status, tools: [{ name: 'zap-baseline', status: warnings.length ? 'partial' : 'complete', findings: findings.size }],
    findings: [...findings.values()], warnings, coverage: { origin, scope: 'Passive ZAP alerts from the verified HTTPS origin only; no active attack scan.' } };
}

export function parseZapBaselineReport(bytes, target) {
  const buffer = typeof bytes === 'string' ? Buffer.from(bytes) : bytes;
  if (!(buffer instanceof Uint8Array) || buffer.byteLength > MAX_REPORT_BYTES)
    throw new Error('ZAP report exceeds the 2 MiB limit.');
  let report;
  try { report = JSON.parse(Buffer.from(buffer).toString('utf8')); } catch { throw new Error('ZAP did not return valid JSON.'); }
  return normalizeZapBaselineReport(report, target);
}
