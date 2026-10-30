import { explainVulnerabilityImpact } from '../shared/vulnerability-impact.js';

const api = 'https://api.osv.dev/v1';
const exactNpmVersion = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

async function json(fetchImpl, url, options = {}) {
  const response = await fetchImpl(url, { ...options, signal: AbortSignal.any([AbortSignal.timeout(20000), options.signal].filter(Boolean)) });
  if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`);
  return response.json();
}

function severity(vulnerability, name) {
  const affected = (vulnerability.affected || []).find(item => item.package?.ecosystem === 'npm' && item.package.name === name);
  const value = affected?.ecosystem_specific?.severity || affected?.database_specific?.severity || vulnerability.database_specific?.severity;
  return typeof value === 'string' ? value.toUpperCase() : 'UNKNOWN';
}

function fixes(vulnerability, name) {
  return [...new Set((vulnerability.affected || [])
    .filter(item => item.package?.ecosystem === 'npm' && item.package.name === name)
    .flatMap(item => item.ranges || [])
    .flatMap(range => range.events || [])
    .map(event => event.fixed).filter(Boolean))];
}

function cwes(vulnerability, name) {
  const affected = (vulnerability.affected || []).filter(entry => entry.package?.ecosystem === 'npm' && entry.package.name === name);
  const sources = [vulnerability.database_specific?.cwe_ids,
    ...affected.flatMap(entry => [entry.ecosystem_specific?.cwe_ids, entry.database_specific?.cwe_ids])];
  return [...new Set(sources.flatMap(value => Array.isArray(value) ? value.slice(0, 100) : [value])
    .filter(value => typeof value === 'string' && /^CWE-[1-9]\d{0,5}$/i.test(value))
    .map(value => value.toUpperCase()))].slice(0, 20);
}

export async function checkVulnerabilities(packages, fetchImpl = fetch) {
  const deadline = AbortSignal.timeout(60_000);
  const request = (url, options = {}) => json(fetchImpl, url, { ...options, signal: deadline });
  const eligible = packages.filter(item => (item.resolved || ['declared_exact', 'declared_range'].includes(item.assessmentKind)) && exactNpmVersion.test(item.version));
  const skippedPackages = packages.length - eligible.length;
  const checkedAt = Date.now();
  if (!eligible.length) return { source: 'OSV', status: 'no_exact_versions', checkedAt, checkedPackages: 0, skippedPackages, findings: [] };
  const idsByPackage = new Map();
  for (let start = 0; start < eligible.length; start += 100) {
    let pending = eligible.slice(start, start + 100).map(item => ({ item, pageToken: '' }));
    for (let page = 0; pending.length; page++) {
      if (page >= 10) throw new Error('OSV returned too many advisory pages to check completely.');
      const result = await request(`${api}/querybatch`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: pending.map(({ item, pageToken }) => ({
          package: { ecosystem: 'npm', name: item.name }, version: item.version,
          ...(pageToken ? { page_token: pageToken } : {})
        })) })
      });
      if (!Array.isArray(result.results) || result.results.length !== pending.length) throw new Error('OSV returned an incomplete batch response.');
      const next = [];
      result.results.forEach((row, index) => {
        const item = pending[index].item;
        const key = `${item.name}\0${item.version}`;
        if (!idsByPackage.has(key)) idsByPackage.set(key, new Set());
        for (const vuln of row.vulns || []) if (typeof vuln.id === 'string') idsByPackage.get(key).add(vuln.id);
        if (row.next_page_token) next.push({ item, pageToken: row.next_page_token });
      });
      pending = next;
    }
  }
  const ids = [...new Set([...idsByPackage.values()].flatMap(set => [...set]))];
  if (ids.length > 500) throw new Error('This scan exceeds the 500-advisory limit. Continue in your coding agent and scan smaller projects.');
  const details = new Map();
  for (let start = 0; start < ids.length; start += 5) {
    await Promise.all(ids.slice(start, start + 5).map(async id => {
      if (!/^[A-Za-z0-9-]+$/.test(id)) throw new Error('OSV returned an invalid advisory ID.');
      details.set(id, await request(`${api}/vulns/${encodeURIComponent(id)}`));
    }));
  }
  const findings = [];
  for (const item of eligible) {
    for (const id of idsByPackage.get(`${item.name}\0${item.version}`) || []) {
      const vulnerability = details.get(id);
      if (!vulnerability || vulnerability.withdrawn) continue;
      const finding = { package: item.name, version: item.version, kind: item.kind, id,
        ...(!item.resolved ? { resolved: false, assessmentKind: item.assessmentKind, versionEvidence: item.assessmentKind, declaredRange: item.declaredRange, files: item.files || [] } : {}),
        cves: (vulnerability.aliases || []).filter(alias => /^CVE-\d{4}-\d+$/i.test(alias)),
        summary: vulnerability.summary || 'No summary provided', severity: severity(vulnerability, item.name),
        fixedVersions: fixes(vulnerability, item.name),
        advisory: {
          cwes: cwes(vulnerability, item.name),
          aliases: (vulnerability.aliases || []).filter(value => typeof value === 'string').slice(0, 100),
          modified: vulnerability.modified || null, published: vulnerability.published || null,
          details: String(vulnerability.details || '').slice(0, 24000),
          references: (vulnerability.references || []).filter(ref => typeof ref.url === 'string' && /^https:\/\//i.test(ref.url))
            .slice(0, 30).map(ref => ({ type: ref.type, url: ref.url })),
          affected: (vulnerability.affected || []).filter(entry => entry.package?.ecosystem === 'npm' && entry.package.name === item.name)
            .map(entry => ({ ranges: entry.ranges || [], versions: entry.versions || [], ecosystemSpecific: entry.ecosystem_specific || {} }))
        } };
      finding.impact = explainVulnerabilityImpact(finding, { manifestOnly: finding.resolved === false });
      findings.push(finding);
    }
  }
  return { source: 'OSV', status: 'complete', checkedAt, checkedPackages: eligible.length, skippedPackages, findings };
}
