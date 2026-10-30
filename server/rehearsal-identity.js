import { createHash } from 'node:crypto';

const unordered = new Set(['files', 'packages', 'nodes', 'requires', 'edges', 'warnings', 'inventoryWarnings',
  'findings', 'cves', 'cwes', 'fixedVersions', 'aliases', 'references', 'affected', 'ranges', 'versions',
  'missingLockfiles', 'omissions', 'expectedLockfiles']);

function canonical(value, field = '') {
  if (Array.isArray(value)) {
    const items = value.map(item => canonical(item));
    if (!unordered.has(field)) return items;
    return items.map(item => ({ item, key: JSON.stringify(item) })).sort((a, b) =>
      a.key < b.key ? -1 : a.key > b.key ? 1 : 0).map(entry => entry.item);
  }
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key], key)]));
}

export function scanEvidenceIdentity(snapshot) {
  const coverage = snapshot.coverage ? { ...snapshot.coverage } : null;
  if (coverage) delete coverage.assessmentCheckedAt;
  const vulnerabilityCheck = snapshot.vulnerabilityCheck ? { ...snapshot.vulnerabilityCheck } : null;
  if (vulnerabilityCheck) {
    delete vulnerabilityCheck.checkedAt;
    // Impact wording is derived presentation. It cannot invalidate a rehearsal
    // for unchanged provider evidence when an explanation template changes.
    if (Array.isArray(vulnerabilityCheck.findings)) vulnerabilityCheck.findings = vulnerabilityCheck.findings.map(finding => {
      if (!finding || typeof finding !== 'object' || Array.isArray(finding)) return finding;
      const providerEvidence = { ...finding };
      delete providerEvidence.impact;
      return providerEvidence;
    });
  }
  // The commit pins repository and lockfile bytes. Graph/package and advisory
  // content also participate, including advisory revisions, severity and fixes.
  // Upgrade-plan caches, job state and observation clocks never participate.
  const evidence = { schemaVersion: 1, repository: snapshot.repository, installationId: Number(snapshot.installationId),
    revision: snapshot.revision, files: snapshot.files || [], packages: snapshot.packages || [],
    graph: snapshot.graph || null, coverage, inventoryWarnings: snapshot.inventoryWarnings || [],
    warnings: snapshot.warnings || [], vulnerabilityCheck };
  return createHash('sha256').update(JSON.stringify(canonical(evidence))).digest('hex');
}

export function bindScanEvidence(snapshot) {
  return { ...snapshot, evidenceIdentity: scanEvidenceIdentity(snapshot) };
}
