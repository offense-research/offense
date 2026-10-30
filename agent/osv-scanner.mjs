import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { adapterLocation, persistAdapterResult, stageAdapterFiles, validateAdapterOptions } from './scan-adapter-files.mjs';

export const OSV_SCANNER_VERSION = '2.7.0';
export const OSV_SCANNER_SHA256 = '160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b';
const MAX_OUTPUT = 8 * 1024 * 1024, DAY = 86400000;
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock',
  'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'uv.lock']);
const advisoryId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/.test(value);
const packageName = value => typeof value === 'string' && /^@?[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)?$/.test(value) && value.length <= 200;
const version = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+!-]{0,99}$/.test(value);
export const isOsvInput = value => LOCKFILES.has(path.posix.basename(value));

export async function freshOsvDatabase(cacheDir, now = Date.now()) {
  try {
    const metadataFile = path.join(cacheDir, 'metadata.json');
    const info = await lstat(metadataFile);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 16384) return null;
    const metadata = JSON.parse(await readFile(metadataFile, 'utf8'));
    const age = now - Date.parse(metadata.downloadedAt);
    if (metadata.schemaVersion !== 1 || !Number.isFinite(age) || age < -300000 || age >= 7 * DAY) return null;
    for (const ecosystem of ['npm', 'PyPI']) {
      const record = metadata.ecosystems?.[ecosystem];
      if (!record || !Number.isSafeInteger(record.size) || record.size < 1024 || record.size > 512 * 1024 * 1024 ||
          !/^[a-f0-9]{64}$/.test(record.sha256) || record.source !== `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip`) return null;
      const file = await lstat(path.join(cacheDir, 'osv-scalibr', ecosystem, 'all.zip'));
      if (!file.isFile() || file.isSymbolicLink() || file.size !== record.size) return null;
    }
    return metadata;
  } catch { return null; }
}

const rank = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
function severity(group, vulnerabilities) {
  const score = typeof group?.max_severity === 'string' && /^\d+(?:\.\d+)?$/.test(group.max_severity) ? Number(group.max_severity) : NaN;
  if (score >= 0 && score <= 10) return score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  return vulnerabilities.map(item => ({ MODERATE: 'MEDIUM', CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' })[item.database_specific?.severity] || 'UNKNOWN')
    .sort((a, b) => rank[b] - rank[a])[0] || 'UNKNOWN';
}

function normalizedPackages(raw, source, allowed) {
  const findings = []; let incomplete = false, packages = 0, unscannablePackages = 0;
  for (const item of raw.results) {
    const file = adapterLocation(item?.source?.path, source, allowed);
    if (!file || !Array.isArray(item.packages) || item.packages.length > 20000) { incomplete = true; continue; }
    for (const entry of item.packages) {
      if (++packages > 20000) return { findings, incomplete: true, packages, unscannablePackages };
      const pkg = entry?.package;
      if (!pkg || !packageName(pkg.name) || !version(pkg.version) || !['npm', 'PyPI'].includes(pkg.ecosystem) ||
          typeof pkg.purl === 'string' && /[?&]source=(?:LOCAL|UNKNOWN|PRIVATE_REGISTRY)(?:&|$)/.test(pkg.purl)) {
        incomplete = true; unscannablePackages++; continue;
      }
      const vulnerabilities = entry.vulnerabilities || [];
      if (!Array.isArray(vulnerabilities) || vulnerabilities.length > 5000 || vulnerabilities.some(vuln => !vuln || !advisoryId(vuln.id))) { incomplete = true; continue; }
      const groups = entry.groups || vulnerabilities.map(vuln => ({ ids: [vuln.id], aliases: vuln.aliases || [] }));
      if (!Array.isArray(groups) || groups.length > 5000) { incomplete = true; continue; }
      const represented = new Set();
      for (const group of groups) {
        if (!Array.isArray(group?.ids) || !group.ids.length || group.ids.length > 100 || group.ids.some(id => !advisoryId(id))) { incomplete = true; continue; }
        const related = vulnerabilities.filter(vuln => group.ids.includes(vuln.id) && !vuln.withdrawn);
        if (!related.length) { incomplete = true; continue; }
        related.forEach(vuln => represented.add(vuln.id));
        const ids = related.map(vuln => vuln.id).sort(), ruleId = ids[0];
        const aliases = [...new Set([...(Array.isArray(group.aliases) ? group.aliases : []), ...ids])].filter(advisoryId).sort().slice(0, 100);
        const fixedVersions = [...new Set(related.flatMap(vuln => (Array.isArray(vuln.affected) ? vuln.affected : [])
          .filter(affected => affected.package?.name === pkg.name && affected.package?.ecosystem === pkg.ecosystem)
          .flatMap(affected => (Array.isArray(affected.ranges) ? affected.ranges : []).filter(range => ['SEMVER', 'ECOSYSTEM'].includes(range.type)).flatMap(range =>
            (Array.isArray(range.events) ? range.events : []).map(event => event?.fixed).filter(version)))))].slice(0, 50);
        findings.push({ id: createHash('sha256').update(JSON.stringify(['osv-scanner', file, pkg.ecosystem, pkg.name, pkg.version, ids])).digest('hex').slice(0, 32),
          tool: 'osv-scanner', ruleId, aliases, file, line: null, severity: severity(group, related),
          title: `Dependency advisory for ${pkg.name} (${ruleId})`, package: pkg.name, ecosystem: pkg.ecosystem,
          installedVersion: pkg.version, fixedVersion: fixedVersions.join(', ').slice(0, 200), fixedVersions,
          advisoryUrl: `https://osv.dev/${encodeURIComponent(ruleId)}`, verification: 'scanner_finding',
          remediation: fixedVersions.length ? `Review the advisory fixed releases for ${pkg.name}: ${fixedVersions.join(', ')}. Select a compatible fixed version, update the lockfile, run normal tests and rescan. Fixed releases from separate version branches are alternatives, not an ordered upgrade path.`.slice(0, 1500)
            : 'No fixed release was reported. Assess applicability and choose a reviewed mitigation or alternative dependency. Test normal behavior and rescan.' });
      }
      if (vulnerabilities.some(vuln => !vuln.withdrawn && !represented.has(vuln.id))) incomplete = true;
    }
  }
  return { findings, incomplete, packages, unscannablePackages };
}

export async function runOsvScanner({ root, files, reportPath, execute = spawnSync, timeoutMs = 120000,
  executable = '/usr/local/bin/osv-scanner', cacheDir = '/opt/osv-cache', clock = Date.now } = {}) {
  validateAdapterOptions({ root, files, reportPath, timeoutMs });
  const selected = files.filter(isOsvInput), coverage = { eligibleFiles: selected.length, ecosystems: ['npm', 'PyPI'], offline: true,
    scope: 'Uploaded npm/pnpm/Yarn and Python lockfiles or pinned requirements, using bundled public OSV data. No package installation, transitive manifest resolution, automatic fixing, compatibility testing, reachability or exploit confirmation.' };
  const result = (status, findings, error) => persistAdapterResult(reportPath,
    { status, version: OSV_SCANNER_VERSION, findings, coverage, ...(error ? { error } : {}) });
  if (!selected.length) return result('partial', [], 'No supported npm, pnpm, Yarn or Python lockfile was supplied.');
  const database = await freshOsvDatabase(cacheDir, clock());
  if (!database) return result('failed', [], 'The bundled OSV npm/PyPI database is absent or older than seven days. Rebuild the scanner image.');
  coverage.databaseUpdatedAt = database.downloadedAt;
  let staged;
  try { staged = await stageAdapterFiles(root, selected); }
  catch { return result('failed', [], 'Dependency inputs must be regular bounded staged files.'); }
  try {
    const config = path.join(staged.directory, 'operator.toml'); await writeFile(config, '', { mode: 0o600 });
    let completed;
    try {
      completed = execute(executable, ['scan', 'source', '--offline', '--no-resolve', '--no-ignore', '--all-packages', '--all-vulns',
        '--config', config, '--local-db-path', cacheDir, '--format', 'json', '--verbosity', 'error',
        ...selected.flatMap(file => ['-L', path.join(staged.source, file)])], {
        cwd: staged.directory, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: staged.directory, TMPDIR: staged.directory,
          OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: cacheDir, NO_COLOR: '1' }, encoding: 'utf8', timeout: timeoutMs,
        killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT, stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { return result('failed', [], 'OSV Scanner failed or timed out.'); }
    if (!completed || completed.error || completed.signal || ![0, 1].includes(completed.status))
      return result('failed', [], 'OSV Scanner could not fully extract and match dependency data.');
    let raw;
    try {
      if (typeof completed.stdout !== 'string' || Buffer.byteLength(completed.stdout) > MAX_OUTPUT) throw new Error('Bounds');
      raw = JSON.parse(completed.stdout);
      if (!Array.isArray(raw.results) || raw.results.length > 500) throw new Error('Shape');
    } catch { return result('failed', [], 'OSV Scanner returned an invalid bounded report.'); }
    const checked = normalizedPackages(raw, staged.source, new Set(selected));
    coverage.packages = checked.packages; coverage.unscannablePackages = checked.unscannablePackages;
    const unique = [...new Map(checked.findings.map(item => [item.id, item])).values()];
    const incomplete = checked.incomplete || !checked.packages || unique.length > 500 || Boolean(completed.stderr?.trim()) ||
      selected.some(file => !raw.results.some(item => adapterLocation(item?.source?.path, staged.source, new Set(selected)) === file));
    return result(incomplete ? 'partial' : 'complete', unique.slice(0, 500), incomplete ? 'OSV dependency extraction or matching was incomplete. Local/private packages, unsupported inputs and unknown versions cannot be treated as clean.' : undefined);
  } finally { await staged.cleanup(); }
}
