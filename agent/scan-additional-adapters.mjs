import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';

const MAX_OUTPUT = 8 * 1024 * 1024;
const MAX_PACKAGE_ARCHIVE = 16 * 1024 * 1024;
const MAX_PACKAGE_UNPACKED = 64 * 1024 * 1024;
const TOOL_VERSIONS = Object.freeze({ 'spectral-owasp': '6.17.0 / ruleset 2.0.1', guarddog: '3.2.0' });
const bounded = (value, size) => typeof value === 'string' ? value.slice(0, size) : '';
const safeRule = value => bounded(value, 160).replace(/[^a-zA-Z0-9:._-]/g, '');
const validReportPath = value => value === undefined || (typeof value === 'string' && path.isAbsolute(value));

function finding(tool, { ruleId, file, line = null, severity = 'UNKNOWN', title, remediation, packageName, packageVersion }) {
  const result = {
    tool, ruleId: safeRule(ruleId), file: bounded(file, 500),
    line: Number.isInteger(line) && line > 0 ? line : null,
    severity, title: bounded(title, 300), remediation: bounded(remediation, 1500),
    verification: 'scanner_finding',
    ...(packageName ? { package: bounded(packageName, 200), installedVersion: bounded(packageVersion, 100), fixedVersion: '' } : {})
  };
  result.id = createHash('sha256').update(JSON.stringify([
    result.tool, result.ruleId, result.file, result.line, result.package, result.installedVersion, result.title
  ])).digest('hex').slice(0, 32);
  return result;
}

async function persist(reportPath, result) {
  if (reportPath) await writeFile(reportPath, JSON.stringify(result), { mode: 0o600 });
  return result;
}

function invalid(tool, error) { return { status: 'failed', version: TOOL_VERSIONS[tool], findings: [], error }; }

/** Lint one uploaded OpenAPI document with the pinned, operator-owned OWASP ruleset. */
export async function runSpectral({ filePath, displayPath = path.basename(filePath || ''), reportPath,
  execute = spawnSync, timeoutMs = 120000,
  executable = '/opt/purple/spectral/node_modules/.bin/spectral',
  rulesetPath = '/opt/purple/spectral/.spectral.yaml' } = {}) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) ||
      !/\.(?:json|ya?ml)$/i.test(filePath) || !validReportPath(reportPath))
    throw new Error('Spectral requires one staged OpenAPI JSON or YAML file and an absolute report path.');
  const tool = 'spectral-owasp';
  const result = execute(executable, ['lint', filePath, '--ruleset', rulesetPath, '--format', 'json', '--fail-severity', 'error'], {
    cwd: path.dirname(rulesetPath),
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', NO_COLOR: '1' },
    encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.error || ![0, 1].includes(result.status)) return persist(reportPath, invalid(tool, 'OpenAPI policy scanner failed or timed out.'));
  let diagnostics;
  try { diagnostics = JSON.parse(result.stdout); } catch { return persist(reportPath, invalid(tool, 'OpenAPI policy scanner returned an invalid report.')); }
  if (!Array.isArray(diagnostics) || diagnostics.length > 5000 || diagnostics.some(item => !item || typeof item !== 'object'))
    return persist(reportPath, invalid(tool, 'OpenAPI policy scanner returned an invalid report.'));
  const file = bounded(displayPath, 500);
  const findings = diagnostics.map(item => finding(tool, {
    ruleId: item.code,
    file,
    line: Number.isInteger(item.range?.start?.line) ? item.range.start.line + 1 : null,
    severity: ({ 0: 'HIGH', 1: 'MEDIUM', 2: 'LOW', 3: 'LOW' })[item.severity] || 'UNKNOWN',
    // Spectral messages can contain uploaded document values. Do not return them.
    title: `OpenAPI policy finding (${safeRule(item.code) || 'unknown-rule'})`,
    remediation: 'Review this OpenAPI rule against the specification and verify the actual API behavior.'
  }));
  const incomplete = diagnostics.some(item => /^(?:parser|resolver|unrecognized-format)/i.test(String(item.code || '')));
  return persist(reportPath, {
    status: incomplete ? 'partial' : 'complete', version: TOOL_VERSIONS[tool],
    findings: [...new Map(findings.map(item => [item.id, item])).values()],
    ...(incomplete ? { error: 'The OpenAPI document could not be fully parsed or resolved.' } : {})
  });
}

async function freshPopularityCache(ecosystem, cacheDir, now) {
  const filename = ({ npm: 'top_npm_packages.json', pypi: 'top_pypi_packages.json',
    rubygems: 'top_rubygems_packages.json' })[ecosystem];
  try {
    const cache = JSON.parse(await readFile(path.join(cacheDir, filename), 'utf8'));
    return Array.isArray(cache.packages) && cache.packages.length > 100 &&
      Number.isInteger(cache.downloaded_timestamp) &&
      now - cache.downloaded_timestamp * 1000 >= 0 &&
      now - cache.downloaded_timestamp * 1000 < 30 * 86400000;
  } catch { return false; }
}

export async function guardDogCachesFresh(cacheDir, now = Date.now()) {
  const fresh = await Promise.all(['npm', 'pypi', 'rubygems'].map(name => freshPopularityCache(name, cacheDir, now)));
  if (fresh.some(value => !value)) return false;
  try {
    const go = JSON.parse(await readFile(path.join(cacheDir, 'top_go_packages.json'), 'utf8'));
    return Array.isArray(go.packages) && go.packages.length > 100;
  } catch { return false; }
}

/** Read only the identity metadata from a bounded gzip tarball; never extract it. */
export async function verifyPackageArchive({ archivePath, ecosystem, packageName, version }) {
  try {
    const archiveStat = await stat(archivePath);
    if (!archiveStat.isFile() || archiveStat.size > MAX_PACKAGE_ARCHIVE) return false;
    const compressed = await readFile(archivePath);
    if (compressed.length < 2 || compressed.length > MAX_PACKAGE_ARCHIVE || compressed[0] !== 0x1f || compressed[1] !== 0x8b) return false;
    const tar = gunzipSync(compressed, { maxOutputLength: MAX_PACKAGE_UNPACKED });
    let identities = 0;
    for (let offset = 0; offset + 512 <= tar.length;) {
      const header = tar.subarray(offset, offset + 512);
      if (header.every(byte => byte === 0)) {
        if (tar.subarray(offset).some(byte => byte !== 0)) return false;
        break;
      }
      const checksumText = header.toString('ascii', 148, 156).replace(/\0.*$/, '').trim();
      const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
      if (!/^[0-7]+$/.test(checksumText) || checksum !== Number.parseInt(checksumText, 8)) return false;
      const name = header.toString('utf8', 0, 100).split('\0')[0];
      const prefix = header.toString('utf8', 345, 500).split('\0')[0];
      const entry = `${prefix ? `${prefix}/` : ''}${name}`.replace(/^\.\//, '');
      if (entry.startsWith('/') || entry.split('/').includes('..')) return false;
      const octal = header.toString('ascii', 124, 136).replace(/\0.*$/, '').trim();
      if (!/^[0-7]+$/.test(octal)) return false;
      const size = Number.parseInt(octal, 8), start = offset + 512;
      if (!Number.isSafeInteger(size) || size < 0 || start + size > tar.length) return false;
      const regular = header[156] === 0 || header[156] === 48;
      // Reject links and PAX/GNU path overrides so our identity check sees the same files GuardDog will extract.
      if (!regular && header[156] !== 53) return false;
      if (regular && size <= 1024 * 1024) {
        if (ecosystem === 'npm' && entry === 'package/package.json') {
          const metadata = JSON.parse(tar.toString('utf8', start, start + size));
          if (metadata?.name !== packageName || metadata?.version !== version) return false;
          identities++;
        }
        if (ecosystem === 'pypi' && /(?:^|\/)PKG-INFO$/.test(entry)) {
          const metadata = tar.toString('utf8', start, start + Math.min(size, 65536));
          const name = /^Name:\s*([^\r\n]+)/im.exec(metadata)?.[1]?.trim();
          const actualVersion = /^Version:\s*([^\r\n]+)/im.exec(metadata)?.[1]?.trim();
          const normalized = value => value?.toLowerCase().replace(/[-_.]+/g, '-');
          if (normalized(name) !== normalized(packageName) || actualVersion !== version) return false;
          identities++;
        }
      }
      offset = start + Math.ceil(size / 512) * 512;
    }
    return identities > 0 && (ecosystem !== 'npm' || identities === 1);
  } catch { /* Missing, malformed or oversized archives cannot prove the coordinate. */ }
  return false;
}

/** Scan one operator-fetched, exact-version npm/PyPI package archive; no package scripts execute. */
export async function runGuardDog({ archivePath, ecosystem, packageName, version, displayPath = path.basename(archivePath || ''),
  reportPath, execute = spawnSync, timeoutMs = 180000, clock = Date.now,
  executable = '/opt/purple/guarddog/bin/guarddog', cacheDir = '/opt/purple/guarddog-cache' } = {}) {
  if (typeof archivePath !== 'string' || !path.isAbsolute(archivePath) || !['npm', 'pypi'].includes(ecosystem) ||
      typeof packageName !== 'string' || !/^(?:@?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?)$/.test(packageName) ||
      typeof version !== 'string' || version.length > 100 || !/^[a-zA-Z0-9][a-zA-Z0-9._+!-]*$/.test(version) ||
      !validReportPath(reportPath)) throw new Error('GuardDog requires a staged exact-version npm or PyPI package archive.');
  const tool = 'guarddog';
  if (!(await verifyPackageArchive({ archivePath, ecosystem, packageName, version })))
    return persist(reportPath, { status: 'partial', version: TOOL_VERSIONS[tool], findings: [],
      error: 'Package archive identity could not be verified against the declared name and version.' });
  // GuardDog eagerly loads all four popularity lists even for one ecosystem.
  if (!(await guardDogCachesFresh(cacheDir, clock())))
    return persist(reportPath, { status: 'partial', version: TOOL_VERSIONS[tool], findings: [],
      error: 'GuardDog package-popularity data is absent or stale; rebuild its operator cache.' });
  const scan = (extraArgs, restrictPrivileges = false) => execute(restrictPrivileges ? '/usr/bin/setpriv' : executable,
    [...(restrictPrivileges ? ['--no-new-privs', '--', executable] : []),
      '--log-level', 'error', ecosystem, 'scan', archivePath, '--output-format=json', ...extraArgs], {
      cwd: path.dirname(archivePath),
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp', NO_COLOR: '1',
        GUARDDOG_TOP_PACKAGES_CACHE_LOCATION: cacheDir },
      encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  let result = scan([]);
  // Cloudflare's isolated, no-egress scanner VM can lack Landlock. GuardDog
  // then exits before reading the archive. Retry only that exact preflight
  // failure; all other sandbox and scan errors stay fail-closed.
  if (result.status === 1 && !result.error && !result.signal && !result.stdout &&
      result.stderr?.trim() === 'ERROR: Kernel-level sandbox is not available on this platform. Use --no-sandbox to scan without it.') {
    result = scan(['--no-sandbox'], true);
  }
  if (result.error || result.status !== 0) {
    const cause = result.error?.code && /^[A-Z0-9_]{1,30}$/.test(result.error.code) ? result.error.code :
      result.signal && /^[A-Z0-9_]{1,30}$/.test(result.signal) ? result.signal :
      Number.isInteger(result.status) ? `EXIT_${result.status}` : 'UNKNOWN';
    return persist(reportPath, invalid(tool, `Package risk scanner failed or timed out (${cause}).`));
  }
  let raw;
  try { raw = JSON.parse(result.stdout); } catch { return persist(reportPath, invalid(tool, 'Package risk scanner returned an invalid report.')); }
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.risks) ||
      typeof raw.risk_score !== 'object' || !Number.isFinite(raw.risk_score?.score) ||
      raw.risks.length > 5000 || raw.risks.some(item => !item || typeof item !== 'object'))
    return persist(reportPath, invalid(tool, 'Package risk scanner returned an invalid report.'));
  const findings = raw.risks.map(item => finding(tool, {
    ruleId: item.threat_rule || item.name,
    file: displayPath,
    severity: ({ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' })[String(item.severity).toLowerCase()] || 'UNKNOWN',
    // GuardDog raw JSON includes source snippets and matches. Never return those fields.
    title: `Potential malicious package behavior (${safeRule(item.name) || 'risk'})`,
    remediation: 'Review the package source and publisher history. Block or replace the exact version if the behavior is confirmed.',
    packageName,
    packageVersion: version
  }));
  const metadataErrors = raw.errors && typeof raw.errors === 'object' && Object.keys(raw.errors).length > 0;
  const cacheFetchFailed = /(?:Failed to download new cache data|Network error:)/i.test(result.stderr || '');
  const incomplete = metadataErrors || cacheFetchFailed;
  return persist(reportPath, {
    status: incomplete ? 'partial' : 'complete', version: TOOL_VERSIONS[tool],
    findings: [...new Map(findings.map(item => [item.id, item])).values()],
    ...(incomplete ? { error: 'Package metadata coverage was incomplete.' } : {})
  });
}
