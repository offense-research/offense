import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, rm, rename, stat } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sourceFiles } from '../server/scan-input.js';
import { runImageScan, verifyImageArchive } from './image-scan.mjs';
import { scanGitHistoryArtifact } from './gitleaks-history.mjs';
import { runSpectral, runGuardDog } from './scan-additional-adapters.mjs';
import { runCosignImage } from './cosign-image.mjs';
import { runZapPassiveHar } from './zap-passive-har.mjs';
import { runZizmor } from './zizmor.mjs';
import { runOsvScanner } from './osv-scanner.mjs';
import { runSemgrep } from './semgrep.mjs';
import { runKubernetesScan } from './kubernetes-scan.mjs';
import { KUBERNETES_SCAN_TOOLS, kubernetesScanVersion } from '../shared/kubernetes-scan.js';

import { normalizeFindings } from './scan-findings.mjs';
export { normalizeFindings } from './scan-findings.mjs';

const LEGACY_TOOLS = ['opengrep', 'trivy', 'gitleaks'];
const SCAN_TOOLS = new Set([...LEGACY_TOOLS, ...KUBERNETES_SCAN_TOOLS, 'trivy-vuln', 'trivy-config', 'trivy-sbom',
  'trivy-image', 'gitleaks-history', 'guarddog-npm', 'guarddog-pypi', 'spectral-owasp', 'cosign-image', 'zap-passive-har', 'zizmor', 'osv-scanner', 'semgrep']);
function selectedTools(input) {
  if (input.tools === undefined) return LEGACY_TOOLS;
  if (!Array.isArray(input.tools) || !input.tools.length || new Set(input.tools).size !== input.tools.length ||
      input.tools.some(tool => !SCAN_TOOLS.has(tool))) throw new Error('Select one or more supported scan tools.');
  return input.tools;
}
function sbomFile(files) {
  if (files.length !== 1 || !/\.json$/i.test(files[0].path)) throw new Error('Upload one CycloneDX or SPDX JSON SBOM.');
  let parsed;
  try { parsed = JSON.parse(files[0].content); } catch { throw new Error('SBOM must be valid JSON.'); }
  if (parsed?.bomFormat !== 'CycloneDX' && !/^SPDX-/i.test(parsed?.spdxVersion || ''))
    throw new Error('Upload a CycloneDX or SPDX JSON SBOM.');
  return files[0];
}

export async function runScan(input, { root = '/tmp/purple-scan', execute = spawnSync, clock = Date.now,
  databaseMetadataPath = '/opt/trivy-cache/db/metadata.json', osvCacheDir = '/opt/osv-cache' } = {}) {
  const startedAt = clock();
  const selected = selectedTools(input);
  const kubernetesVersion = kubernetesScanVersion({ ...input, tools: selected });
  if (input.artifact) return runArtifactScan(input, { root, execute, clock, databaseMetadataPath, selected, startedAt });
  const source = sourceFiles(input.files);
  const sbom = selected.includes('trivy-sbom') ? sbomFile(source.files) : null;
  if (sbom && selected.length !== 1) throw new Error('SBOM scanning requires its own job.');
  if (selected.some(name => ['trivy-image', 'gitleaks-history', 'guarddog-npm', 'guarddog-pypi', 'cosign-image', 'zap-passive-har'].includes(name)))
    throw new Error('This scan tool requires a bounded artifact upload.');
  if (selected.includes('spectral-owasp') && (selected.length !== 1 || source.files.length !== 1 ||
      !/\.(json|ya?ml)$/i.test(source.files[0].path))) throw new Error('OpenAPI scanning requires one JSON or YAML document.');
  const directory = path.join(root, 'source'), reports = path.join(root, 'reports');
  await mkdir(directory, { recursive: true, mode: 0o700 }); await mkdir(reports, { recursive: true, mode: 0o700 });
  try {
    for (const file of source.files) {
      const target = path.join(directory, file.path);
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, file.content, { mode: 0o600, flag: 'wx' });
    }
    let db;
    try { db = JSON.parse(await readFile(databaseMetadataPath, 'utf8')); } catch { /* trivy reports the unavailable database below */ }
    const dbUpdatedAt = db?.UpdatedAt || null;
    const fresh = dbUpdatedAt && clock() - Date.parse(dbUpdatedAt) < 7 * 86400000;
    // All selected tools must fit within the container's execution deadline.
    const toolTimeoutMs = Math.min(210000, Math.floor(600000 / selected.length));
    const trivyCommon = ['--config', '/opt/purple/trivy.yaml', '--ignorefile', '/opt/purple/empty.ignore', '--cache-dir', '/opt/trivy-cache', '--format', 'json', '--timeout', `${Math.floor(toolTimeoutMs / 1000) - 10}s`];
    const trivyVulnerabilities = ['--skip-db-update', '--skip-java-db-update', '--offline-scan', '--scanners', 'vuln'];
    const definitions = {
      opengrep: ['opengrep', ['scan', '--config', '/opt/purple/scan-rules.yml', '--taint-intrafile', '--json', '--output', `${reports}/opengrep.json`, '--disable-version-check', '--no-git-ignore', '--x-ignore-semgrepignore-files', '--disable-nosem', '--jobs', '2', '--timeout', '10', '--max-memory', '512', directory], '1.32.0'],
      'trivy': ['trivy', ['filesystem', ...trivyCommon, ...trivyVulnerabilities, '--output', `${reports}/trivy.json`, directory], '0.76.1'],
      'trivy-vuln': ['trivy', ['filesystem', ...trivyCommon, ...trivyVulnerabilities, '--output', `${reports}/trivy-vuln.json`, directory], '0.76.1'],
      'trivy-config': ['trivy', ['config', ...trivyCommon, '--skip-check-update', '--include-non-failures', '--output', `${reports}/trivy-config.json`, directory], '0.76.1'],
      'trivy-sbom': ['trivy', ['sbom', ...trivyCommon, ...trivyVulnerabilities, '--output', `${reports}/trivy-sbom.json`, path.join(directory, sbom?.path || '')], '0.76.1'],
      gitleaks: ['gitleaks', ['dir', directory, '--config', '/opt/purple/gitleaks.toml', '--gitleaks-ignore-path', '/opt/purple/empty.ignore', '--redact=100', '--ignore-gitleaks-allow', '--exit-code', '0', '--no-banner', '--report-format', 'json', '--report-path', `${reports}/gitleaks.json`], '8.30.1']
    };
    const tools = [], findings = [], warnings = [];
    for (const name of selected) {
      if (KUBERNETES_SCAN_TOOLS.includes(name)) {
        const begin = clock();
        const checked = await runKubernetesScan({ tool: name, root: directory,
          files: source.files.map(file => file.path), kubernetesVersion, execute, timeoutMs: toolTimeoutMs });
        findings.push(...checked.findings);
        tools.push({ name, version: checked.version, status: checked.status, durationMs: clock() - begin,
          findings: checked.findings.length, coverage: checked.coverage, ...(checked.error ? { error: checked.error } : {}) });
        continue;
      }
      if (name === 'osv-scanner' || name === 'semgrep') {
        const begin = clock(), run = name === 'osv-scanner' ? runOsvScanner : runSemgrep;
        const checked = await run({ root: directory, files: source.files.map(file => file.path),
          reportPath: `${reports}/${name}.json`, execute, timeoutMs: toolTimeoutMs,
          ...(name === 'osv-scanner' ? { cacheDir: osvCacheDir, clock } : {}) });
        const normalized = checked.findings || [];
        findings.push(...normalized);
        tools.push({ name, version: checked.version, status: checked.status, durationMs: clock() - begin,
          findings: normalized.length, coverage: checked.coverage, ...(checked.error ? { error: checked.error } : {}) });
        continue;
      }
      if (name === 'zizmor') {
        const begin = clock();
        const checked = await runZizmor({ root: directory, files: source.files.map(file => file.path),
          reportPath: `${reports}/zizmor.json`, execute, timeoutMs: Math.min(toolTimeoutMs, 120000) });
        const normalized = checked.findings || [];
        findings.push(...normalized);
        tools.push({ name, version: checked.version, status: checked.status, durationMs: clock() - begin,
          findings: normalized.length, coverage: checked.coverage, ...(checked.error ? { error: checked.error } : {}) });
        continue;
      }
      if (name === 'spectral-owasp') {
        const begin = clock();
        const checked = await runSpectral({ filePath: path.join(directory, source.files[0].path),
          displayPath: source.files[0].path, reportPath: `${reports}/spectral-owasp.json`, execute, timeoutMs: toolTimeoutMs });
        const normalized = checked.findings || [];
        findings.push(...normalized);
        tools.push({ name, version: checked.version, status: checked.status, durationMs: clock() - begin,
          findings: normalized.length, ...(checked.error ? { error: checked.error } : {}) });
        continue;
      }
      const [executable, args, version] = definitions[name];
      const begin = clock();
      if (name.startsWith('trivy') && name !== 'trivy-config' && !fresh) { tools.push({ name, version, status: 'failed', durationMs: 0, error: 'The bundled vulnerability database is absent or older than seven days. Rebuild the scanner image.' }); continue; }
      const result = execute(executable, args, { cwd: root, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: root, TMPDIR: root,
        SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', NO_COLOR: '1' }, timeout: toolTimeoutMs, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024, stdio: ['ignore', 'ignore', 'ignore'] });
      let report;
      try {
        const filename = `${reports}/${name}.json`;
        if ((await stat(filename)).size > 8 * 1024 * 1024) throw new Error('Report too large');
        report = JSON.parse(await readFile(filename, 'utf8'));
        if (name === 'gitleaks' && !Array.isArray(report)) throw new Error('Invalid report');
        if (name === 'opengrep' && !Array.isArray(report.results)) throw new Error('Invalid report');
        if (name.startsWith('trivy') && !Number.isInteger(report.SchemaVersion)) throw new Error('Invalid report');
      } catch { tools.push({ name, version, status: 'failed', durationMs: clock() - begin, error: 'Scanner did not return a valid bounded report.' }); continue; }
      const normalized = normalizeFindings(name, report, directory, { inputPath: sbom?.path });
      findings.push(...normalized);
      const noSource = name === 'opengrep' && !source.files.some(file => /\.(?:[cm]?jsx?|tsx?|py)$/i.test(file.path));
      const incomplete = result.status !== 0 || result.error || (name === 'opengrep' && report.errors?.length) || noSource ||
        (name === 'trivy-config' && !report.Results?.length);
      tools.push({ name, version, status: incomplete ? 'partial' : 'complete', durationMs: clock() - begin, findings: normalized.length,
        ...(name.startsWith('trivy') && name !== 'trivy-config' ? { databaseUpdatedAt: dbUpdatedAt } : {}),
        ...(incomplete ? { error: noSource ? 'No supported JavaScript, TypeScript or Python files were supplied.' : name === 'trivy-config' && !report.Results?.length ? 'No supported infrastructure configuration was detected.' : 'Scanner reported an execution, parsing or coverage error.' } : {}) });
    }
    const allowedPaths = new Set(source.files.map(file => file.path));
    const normalized = findings.filter(item => allowedPaths.has(item.file));
    if (normalized.length !== findings.length) warnings.push('Some scanner locations could not be matched to an uploaded file.');
    if (normalized.length > 500) warnings.push('Report truncated to 500 findings. Narrow the scan and repeat to inspect all results.');
    const complete = tools.every(tool => tool.status === 'complete') && !warnings.length;
    return { status: complete ? 'completed' : tools.every(tool => tool.status === 'failed') ? 'failed' : 'partial',
      tools, findings: normalized.slice(0, 500), warnings,
      coverage: { uploadedFiles: source.files.length, sourceBytes: source.bytes, fingerprint: source.fingerprint,
        scope: 'Uploaded text snapshot only; no Git history, container image, application execution or exploit verification. Opengrep uses reviewed JavaScript/TypeScript and Python pattern and within-file taint rules; it does not prove cross-file reachability or exploitability. Semgrep Community Edition uses six additional reviewed JavaScript/TypeScript/Python patterns, without remote registry rules or Pro analysis. OSV Scanner checks supported npm/pnpm/Yarn and Python dependency files offline against bundled advisory data and reports fixed releases, without testing compatibility. Zizmor checks supplied GitHub Actions workflows and actions offline. Trivy dependency checks use supported manifests and lockfiles; Trivy SBOM checks use the uploaded JSON document. Missing line numbers are null. Java archive dependencies require separate analysis.' },
      execution: { startedAt, finishedAt: clock(), durationMs: clock() - startedAt } };
  } finally { await rm(directory, { recursive: true, force: true }); await rm(reports, { recursive: true, force: true }); }
}

async function runArtifactScan(input, { root, execute, clock, databaseMetadataPath, selected, startedAt }) {
  const artifact = input.artifact;
  if (!artifact || typeof artifact !== 'object' || input.files?.length || selected.length !== 1 ||
      !['trivy-image', 'gitleaks-history', 'guarddog-npm', 'guarddog-pypi', 'cosign-image', 'zap-passive-har'].includes(selected[0]))
    throw new Error('Select one tool for the uploaded artifact.');
  const name = selected[0], expectedKind = name === 'trivy-image' ? 'image-tar' :
    name === 'gitleaks-history' ? 'git-bundle' : name === 'cosign-image' ? 'cosign-save' :
    name === 'zap-passive-har' ? 'web-har' : 'package-archive';
  if (artifact.kind !== expectedKind || !/^[a-f0-9]{64}$/.test(artifact.sha256 || '') ||
      !Number.isSafeInteger(artifact.size) || artifact.size < 1)
    throw new Error('Artifact kind does not match the selected scan tool.');
  const artifactPath = path.join(root, 'artifact');
  if (name === 'gitleaks-history') return scanGitHistoryArtifact({ artifactPath,
    expectedSha256: artifact.sha256, expectedBytes: artifact.size, root: path.join(root, 'history'), execute, now: clock });
  const reports = path.join(root, 'reports');
  await mkdir(reports, { recursive: true, mode: 0o700 });
  try {
    if (name === 'cosign-image') {
      await verifyImageArchive(artifactPath, { sha256: artifact.sha256, size: artifact.size });
      const checked = await runCosignImage({ archivePath: artifactPath, expectedDigest: artifact.expectedDigest,
        expectedIdentity: artifact.expectedIdentity, expectedIssuer: artifact.expectedIssuer,
        reportPath: path.join(reports, 'cosign-image.json'), execute, tempRoot: root });
      return { status: checked.status === 'complete' ? 'completed' : 'failed',
        tools: [{ name, version: checked.version, status: checked.status, durationMs: clock() - startedAt,
          findings: 0, ...(checked.error ? { error: checked.error } : {}) }], findings: [], warnings: [],
        ...(checked.verified ? { verified: checked.verified } : {}),
        coverage: { artifactBytes: artifact.size, artifactSha256: artifact.sha256,
          scope: 'One uploaded offline Cosign image bundle; exact OCI digest and signer identity were checked against the bundled trusted root.' },
        execution: { startedAt, finishedAt: clock(), durationMs: clock() - startedAt } };
    }
    if (name === 'zap-passive-har') {
      await verifyImageArchive(artifactPath, { sha256: artifact.sha256, size: artifact.size });
      const checked = await runZapPassiveHar(await readFile(artifactPath),
        { target: artifact.target, execute, tempRoot: root });
      return { ...checked,
        tools: checked.tools.map(tool => ({ ...tool, durationMs: clock() - startedAt })),
        coverage: { ...checked.coverage, artifactBytes: artifact.size, artifactSha256: artifact.sha256 },
        execution: { startedAt, finishedAt: clock(), durationMs: clock() - startedAt } };
    }
    if (name === 'trivy-image') {
      let db;
      try { db = JSON.parse(await readFile(databaseMetadataPath, 'utf8')); } catch { /* fail closed below */ }
      const dbUpdatedAt = db?.UpdatedAt || null;
      if (!dbUpdatedAt || clock() - Date.parse(dbUpdatedAt) >= 7 * 86400000)
        throw new Error('The bundled vulnerability database is absent or stale.');
      const { report, complete } = await runImageScan({ artifactPath, sha256: artifact.sha256, size: artifact.size,
        reportPath: path.join(reports, 'trivy-image.json'), execute });
      const findings = normalizeFindings('trivy-image', report, path.join(root, 'source'), { inputPath: 'image.tar' });
      const truncated = findings.length > 500;
      return { status: complete && !truncated ? 'completed' : 'partial',
        tools: [{ name, version: '0.76.1', status: complete && !truncated ? 'complete' : 'partial',
          durationMs: clock() - startedAt, findings: Math.min(findings.length, 500), databaseUpdatedAt: dbUpdatedAt }],
        findings: findings.slice(0, 500), warnings: truncated ? ['Image report truncated to 500 findings.'] : [],
        coverage: { artifactBytes: artifact.size, artifactSha256: artifact.sha256,
          scope: 'One uploaded Docker image archive; image layers were inspected without running the image.' },
        execution: { startedAt, finishedAt: clock(), durationMs: clock() - startedAt } };
    }
    await verifyImageArchive(artifactPath, { sha256: artifact.sha256, size: artifact.size });
    const ecosystem = name === 'guarddog-npm' ? 'npm' : 'pypi';
    const checked = await runGuardDog({ archivePath: artifactPath, ecosystem,
      packageName: artifact.packageName, version: artifact.packageVersion,
      displayPath: 'package-archive', reportPath: path.join(reports, `${name}.json`), execute, clock });
    const findings = (checked.findings || []).map(item => ({ ...item, tool: name,
      id: createHash('sha256').update(JSON.stringify([name, item.ruleId, item.file, item.line, item.package, item.installedVersion])).digest('hex').slice(0, 32) }));
    const truncated = findings.length > 500;
    const toolStatus = truncated && checked.status === 'complete' ? 'partial' : checked.status;
    return { status: toolStatus === 'complete' ? 'completed' : toolStatus,
      tools: [{ name, version: checked.version, status: toolStatus, durationMs: clock() - startedAt,
        findings: Math.min(findings.length, 500), ...(checked.error ? { error: checked.error } : {}) }],
      findings: findings.slice(0, 500), warnings: truncated ? ['Package report truncated to 500 findings.'] : [],
      coverage: { artifactBytes: artifact.size, artifactSha256: artifact.sha256,
        scope: `One uploaded ${ecosystem} package archive. Heuristic risk signals are not proof of malware.` },
      execution: { startedAt, finishedAt: clock(), durationMs: clock() - startedAt } };
  } finally { await rm(reports, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let buffer = ''; for await (const chunk of process.stdin) { buffer += chunk; if (buffer.length > 6 * 1024 * 1024) throw new Error('Input too large'); }
  let result;
  try { result = await runScan(JSON.parse(buffer)); }
  catch { result = { status: 'failed', tools: [], findings: [], error: 'Scanner execution failed.' }; }
  await writeFile('/tmp/purple-scan-result.json.tmp', JSON.stringify(result), { mode: 0o600 });
  await rename('/tmp/purple-scan-result.json.tmp', '/tmp/purple-scan-result.json');
}
