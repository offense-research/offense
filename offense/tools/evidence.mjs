// Local evidence only: source text, paths, and assessment decisions never go to Purple.
import { readdir, readFile, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { analyzeReachability } from './reachability.mjs';
import { reserveExternalOutput } from './output.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const skip = new Set(['node_modules', 'vendor', 'dist', 'build', 'coverage']);
const sourceExtension = /\.(?:[cm]?[jt]sx?|vue|svelte|json|ya?ml|toml)$/;
export const findingKey = finding => `${finding.package}@${finding.version}:${finding.id}`;
export const advisoryFingerprint = finding => hash(JSON.stringify([finding.id, finding.severity, finding.cves || [], finding.summary, finding.fixedVersions, finding.advisory || null]));

// Textual references are navigation hints, never function-level reachability proof.
export async function inspectSources(directory, findings) {
  const root = await realpath(directory), files = [], warnings = [];
  const names = [...new Set(findings.map(item => item.package))];
  const references = Object.fromEntries(names.map(name => [name, []]));
  let entries = 0, bytes = 0;
  async function walk(folder, depth = 0) {
    if (depth > 12) { warnings.push('Source directory depth limit reached.'); return; }
    for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (++entries > 30000) throw new Error('Source evidence exceeds 30,000 entries; choose a narrower repository.');
      if (entry.name.startsWith('.') || skip.has(entry.name)) continue;
      const full = path.join(folder, entry.name), relative = path.relative(root, full).split(path.sep).join('/');
      if (entry.isSymbolicLink()) { warnings.push(`${relative}: symlink not inspected.`); continue; }
      if (entry.isDirectory()) { await walk(full, depth + 1); continue; }
      if (!entry.isFile() || !sourceExtension.test(entry.name) || /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml)$/.test(relative)) continue;
      const size = (await lstat(full)).size;
      if (size > 1_000_000 || bytes + size > 20_000_000) { warnings.push(`${relative}: source byte limit; not inspected.`); continue; }
      bytes += size;
      const content = await readFile(full, 'utf8');
      files.push({ path: relative, sha256: hash(content), lines: content.split('\n').length });
      for (const [index, line] of content.split('\n').entries()) for (const name of names) {
        // Deliberately includes comments/strings: never infer reachability or absence from this search.
        if (line.includes(`'${name}'`) || line.includes(`"${name}"`) || line.includes(`'${name}/`) || line.includes(`"${name}/`)) {
          if (references[name].length >= 30) { warnings.push(`${name}: reference limit reached; remaining matches omitted.`); continue; }
          references[name].push({ path: relative, line: index + 1, sha256: hash(content),
            category: entry.name === 'package.json' ? 'manifest_reference' : 'text_reference' });
        }
      }
    }
  }
  await walk(root);
  return { fingerprint: hash(JSON.stringify(files)), files, references, warnings: [...new Set(warnings)],
    coverage: 'Bounded source/configuration text search. Hidden files, dependencies, generated outputs and unsupported extensions excluded. Text references alone provide no call-graph or data-flow evidence; function analysis is reported separately when available.' };
}

export function reviewFindings(scan, source, decisions = [], now = Date.now()) {
  if (!Array.isArray(decisions) || decisions.length > 2000) throw new Error('Decisions must be an array of at most 2,000 assessments.');
  const keys = new Set((scan.vulnerabilityCheck?.findings || []).map(findingKey));
  const selected = new Map();
  for (const item of decisions) {
    if (!keys.has(item.key) || selected.has(item.key)) throw new Error('Assessment has an unknown or duplicate finding key.');
    selected.set(item.key, item);
  }
  return scan.vulnerabilityCheck.findings.map(finding => {
    const item = selected.get(findingKey(finding));
    let issue = null;
    if (item) {
      if (!['applicable', 'not_affected'].includes(item.status)) issue = 'Unsupported assessment status.';
      else if (!scan.repositoryRevision || item.repositoryRevision !== scan.repositoryRevision || item.metadataFingerprint !== scan.metadataFingerprint || item.sourceFingerprint !== source.fingerprint || item.advisoryFingerprint !== advisoryFingerprint(finding)) issue = 'Assessment evidence is stale or belongs to a different checkout, dependency set, or advisory.';
      else if (source.reachability && item.analysisFingerprint !== source.reachability.analysisFingerprint) issue = 'Reachability analysis or entry/target configuration changed. Review this assessment again.';
      else if (typeof item.assessedBy !== 'string' || !item.assessedBy.trim() || typeof item.reason !== 'string' || item.reason.trim().length < 20 || typeof item.prerequisites !== 'string' || item.prerequisites.trim().length < 20) issue = 'Assessment requires a reviewer, concrete rationale and advisory prerequisites.';
      else if (!Number.isFinite(item.reviewedAt) || item.reviewedAt > now || !Number.isFinite(item.expiresAt) || item.expiresAt <= now || item.expiresAt <= item.reviewedAt || item.expiresAt - item.reviewedAt > 30 * 86400000) issue = 'Assessment has expired or exceeds the 30-day review window.';
      else if (item.status === 'not_affected' && !finding.advisory?.details && !finding.advisory?.references?.length) issue = 'Advisory prerequisites were not available; fetch the advisory details before dismissing this finding.';
      else if (item.status === 'not_affected' && (scan.warnings?.length || source.warnings.length)) issue = 'Incomplete coverage prevents accepting a not-affected assessment.';
      else if (!Array.isArray(item.evidence) || !item.evidence.length || item.evidence.some(ref => !Number.isInteger(ref.line) || ref.line < 1 || !source.files.some(file => file.path === ref.path && file.sha256 === ref.sha256 && ref.line <= file.lines))) issue = 'Assessment requires references to inspected files with matching content hashes and positive line numbers.';
    }
    const status = item && !issue ? item.status : 'needs_review';
    return { key: findingKey(finding), package: finding.package, version: finding.version, id: finding.id, severity: finding.severity,
      advisoryFingerprint: advisoryFingerprint(finding), status, verification: status === 'needs_review' ? 'unassessed' : 'reviewer_assessment_only',
      ...(item ? { assessment: item, ...(issue ? { blocker: issue } : {}) } : {}),
      references: source.references[finding.package] || [],
      reachability: source.reachability?.findings.find(result => result.key === findingKey(finding))?.status || 'unknown',
      functionEvidence: source.reachability?.findings.find(result => result.key === findingKey(finding)) || null,
      nextStep: 'Trace the affected API through callers and attacker-controlled inputs; inspect advisory prerequisites. A package reference is not proof of a reachable vulnerable function. Missing references or runtime events do not establish safety.' };
  });
}

export async function triage(directory, { scanFile, decisionsFile, rehearsalFile, targetsFile, entries = [], output, now = Date.now() } = {}) {
  if (!scanFile) throw new Error('Triage requires --scan scan.json.');
  const { collectMetadata, checkoutRevision } = await import('./purple.mjs');
  const scan = JSON.parse(await readFile(scanFile, 'utf8'));
  if (scan.vulnerabilityCheck?.status !== 'complete') throw new Error('A completed scan is required.');
  const checkedAt = scan.vulnerabilityCheck.checkedAt;
  if (!Number.isFinite(checkedAt) || checkedAt > now || now - checkedAt > 86400000) throw new Error('Advisory evidence is missing or older than 24 hours. Rescan before triage.');
  const metadata = await collectMetadata(directory), revision = await checkoutRevision(directory);
  if (!scan.repositoryRevision || revision !== scan.repositoryRevision || metadata.fingerprint !== scan.metadataFingerprint) throw new Error('Scan is stale or not pinned to this executable checkout; rescan before triage.');
  const reportsOutput = await reserveExternalOutput(directory, output, 'purple-triage-');
  const destination = reportsOutput.directory;
  const source = await inspectSources(directory, scan.vulnerabilityCheck.findings);
  source.warnings = [...new Set([...source.warnings, ...metadata.warnings])];
  source.reachability = await analyzeReachability(directory, { source, metadata, findings: scan.vulnerabilityCheck.findings,
    targets: targetsFile ? JSON.parse(await readFile(targetsFile, 'utf8')) : [], entries });
  source.warnings = [...new Set([...source.warnings, ...source.reachability.issues.map(item => `${item.file}:${item.line}: ${item.reason}`)])];
  const decisions = decisionsFile ? JSON.parse(await readFile(decisionsFile, 'utf8')) : [];
  const rank = { static_path_found: 0, unknown: 1, no_path_observed: 2 };
  const findings = reviewFindings(scan, source, decisions, now).sort((a, b) => rank[a.reachability] - rank[b.reachability]);
  const reachabilityTotals = Object.fromEntries(Object.keys(rank).map(status => [status, findings.filter(item => item.reachability === status).length]));
  const report = { repositoryRevision: revision, metadataFingerprint: metadata.fingerprint, sourceFingerprint: source.fingerprint,
    analysisFingerprint: source.reachability.analysisFingerprint, generatedAt: now, verification: 'reviewer_assessments_only', sourceCoverage: source.coverage, reachabilityTotals, reachability: source.reachability, warnings: source.warnings, findings,
    totals: Object.fromEntries(['needs_review', 'applicable', 'not_affected'].map(status => [status, findings.filter(item => item.status === status).length])) };
  let simulation = 'No simulation evidence supplied. Existing-test compatibility does not establish exploitability or a verified security fix.';
  if (rehearsalFile) {
    const rehearsal = JSON.parse(await readFile(rehearsalFile, 'utf8'));
    if (rehearsal.revision !== revision || rehearsal.metadataFingerprint !== metadata.fingerprint || rehearsal.sourceFingerprint !== source.fingerprint) throw new Error('Rehearsal evidence is stale or missing its source fingerprint. Rerun against this checkout.');
    simulation = JSON.stringify({ status: rehearsal.status, verification: rehearsal.verification,
      baseline: rehearsal.result?.baseline, candidates: rehearsal.result?.scenarios,
      remainingAdvisories: rehearsal.remainingAdvisories, newAdvisories: rehearsal.newAdvisories }, null, 2);
    report.simulation = { status: rehearsal.status, verification: rehearsal.verification };
  }
  const template = findings.map(item => ({ key: item.key, status: 'needs_review', assessedBy: '', reason: '', prerequisites: '',
    repositoryRevision: revision, metadataFingerprint: metadata.fingerprint, sourceFingerprint: source.fingerprint,
    advisoryFingerprint: item.advisoryFingerprint, analysisFingerprint: source.reachability.analysisFingerprint, reviewedAt: now, expiresAt: now + 7 * 86400000,
    evidence: item.references.slice(0, 3) }));
  const targetTemplate = findings.filter(item => !item.functionEvidence?.mappings.length).map(item => ({ key: item.key, advisoryFingerprint: item.advisoryFingerprint, reviewedBy: '', symbols: [], reference: '', prerequisites: '' }));
  const markdown = ['# Dependency applicability review', '',
    `${findings.length} advisory matches retained. ${report.totals.needs_review} need review; ${report.totals.applicable} assessed applicable; ${report.totals.not_affected} assessed not affected.`,
    `Function paths: ${reachabilityTotals.static_path_found} found; ${reachabilityTotals.unknown} unknown; ${reachabilityTotals.no_path_observed} with no observed path.`,
    'Assessments are reviewer judgments, not reproduced vulnerabilities or verified fixes. No matches are hidden or removed.',
    `Commit: ${revision}`, `Source fingerprint: ${source.fingerprint}`, '', source.coverage,
    ...source.warnings.map(w => `- Coverage gap: ${w}`), '',
    ...findings.flatMap(item => [`## ${item.key}`, `Status: ${item.status}; function reachability: ${item.reachability}.`,
      ...(item.functionEvidence ? [item.functionEvidence.explanation,
        ...item.functionEvidence.mappings.map(mapping => `Affected APIs: ${mapping.symbols.join(', ')}. Source: ${mapping.reference}. Mapping: ${mapping.provenance}.`),
        ...item.functionEvidence.callPaths.map(chain => `- Call path: ${chain.map(frame => `${frame.file}:${frame.line} ${frame.function}`).join(' → ')}`),
        ...item.functionEvidence.prerequisites.map(value => `Prerequisites to verify: ${value}`)] : []),
      ...(item.blocker ? [`Blocker: ${item.blocker}`] : []),
      ...(item.assessment ? [`Rationale: ${item.assessment.reason}`, `Prerequisites: ${item.assessment.prerequisites}`] : []),
      ...(item.references.length ? item.references.map(ref => `- ${ref.path}:${ref.line} (${ref.category})`) : ['No package text references found; this does not prove the affected code is unused.']), item.nextStep, '']),
    '## Static analysis coverage', source.reachability.entryPolicy, ...source.reachability.limitations,
    'No-path results are candidates for further review; no advisory is automatically suppressed.',
    '## Upgrade simulation', simulation,
    '', '## Next agent actions',
    'Review the affected function, configuration prerequisites, dependency paths, production/build/test exposure, and attacker-controlled inputs. Keep unassessed findings visible. Do not suppress a finding because a model calls it unlikely, a package is dev-only, or normal tests pass.',
    'For suspected vulnerabilities, create a focused reproduction/regression in an isolated checkout; demonstrate the vulnerable baseline, patched behavior, and passing normal tests. Preserve all failures and remaining advisories. No automatic production execution or publishing.'
  ].join('\n');
  for (const [name, value] of [['triage.json', JSON.stringify(report, null, 2)], ['reachability.json', JSON.stringify(source.reachability, null, 2)], ['api-targets-template.json', JSON.stringify(targetTemplate, null, 2)], ['decisions-template.json', JSON.stringify(template, null, 2)], ['triage.md', markdown]]) await reportsOutput.write(name, value);
  const remediation = await readFile(path.join(path.dirname(path.resolve(scanFile)), 'remediation.md'), 'utf8');
  await reportsOutput.write('handoff.md', `${remediation}\n\n${markdown}`);
  return { ...report.totals, reachabilityTotals, staticPathsFound: findings.filter(item => item.reachability === 'static_path_found').length,
    reachability: path.join(destination, 'reachability.json'), apiTargetsTemplate: path.join(destination, 'api-targets-template.json'), report: path.join(destination, 'triage.md'), evidence: path.join(destination, 'triage.json'), decisionsTemplate: path.join(destination, 'decisions-template.json'), handoff: path.join(destination, 'handoff.md') };
}
