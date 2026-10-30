import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';

export const HISTORY_LIMITS = Object.freeze({
  artifactBytes: 32 * 1024 * 1024,
  commits: 1000,
  refs: 32,
  objects: 10000,
  objectBytes: 4 * 1024 * 1024,
  unpackedBytes: 128 * 1024 * 1024,
  findings: 500
});

const SHA = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DIGEST = /^[a-f0-9]{64}$/i;
const REPORT_LIMIT = 8 * 1024 * 1024;

function safePath(value) {
  if (typeof value !== 'string' || !value || value.length > 500 || value.includes('\\') || /[\x00-\x1f\x7f]/.test(value) ||
      value.startsWith('/') || value.split('/').some(part => !part || part === '.' || part === '..')) return null;
  return value;
}

export function normalizeGitHistoryFindings(raw) {
  if (!Array.isArray(raw)) throw new Error('Invalid Gitleaks report.');
  const findings = []; let omitted = 0;
  for (const item of raw) {
    const file = safePath(item?.File), commit = item?.Commit;
    if (!file || typeof commit !== 'string' || !SHA.test(commit)) { omitted++; continue; }
    const ruleId = String(item.RuleID || '').slice(0, 200);
    const line = Number.isInteger(item.StartLine) && item.StartLine > 0 ? item.StartLine : null;
    const finding = {
      tool: 'gitleaks-history', ruleId, file, line, commit: commit.toLowerCase(), severity: 'HIGH',
      title: `Potential exposed credential (${ruleId})`,
      remediation: 'Revoke and rotate this credential, inspect its use, and remove it from affected history where appropriate. Removing a string from the current files does not revoke it.',
      verification: 'scanner_finding'
    };
    finding.id = createHash('sha256').update(JSON.stringify([finding.tool, finding.ruleId, file, line, finding.commit])).digest('hex').slice(0, 32);
    findings.push(finding);
  }
  return { findings: [...new Map(findings.map(item => [item.id, item])).values()], omitted };
}

async function verifyArtifact(file, expectedSha256, expectedBytes, limit) {
  if (typeof expectedSha256 !== 'string' || !DIGEST.test(expectedSha256) ||
      !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > limit) {
    throw new Error('Invalid Git bundle metadata.');
  }
  const info = await lstat(file);
  if (!info.isFile() || info.size !== expectedBytes || info.size > limit) throw new Error('Git bundle size mismatch.');
  const digest = createHash('sha256'); let bytes = 0;
  for await (const chunk of createReadStream(file)) {
    bytes += chunk.length;
    if (bytes > limit) throw new Error('Git bundle exceeds the size limit.');
    digest.update(chunk);
  }
  if (bytes !== expectedBytes || digest.digest('hex') !== expectedSha256.toLowerCase()) throw new Error('Git bundle digest mismatch.');
}

function checked(execute, command, args, options) {
  const result = execute(command, args, {
    ...options, encoding: 'utf8', timeout: options.timeout ?? 45000,
    maxBuffer: options.maxBuffer ?? 2 * 1024 * 1024,
    stdio: options.stdio ?? ['ignore', 'pipe', 'pipe']
  });
  if (result.status !== 0 || result.error) throw new Error('Git bundle inspection failed.');
  return result.stdout || '';
}

function inspectedRepository(execute, repository, env, limits) {
  const options = { cwd: repository, env };
  const git = (args, extra = {}) => checked(execute, 'git', args, { ...options, ...extra });
  const commitCount = Number(git(['rev-list', '--all', '--count']).trim());
  if (!Number.isSafeInteger(commitCount) || commitCount < 1 || commitCount > limits.commits) throw new Error('Git bundle exceeds the commit limit.');
  const refs = git(['for-each-ref', '--format=%(refname)']).trim().split('\n').filter(Boolean);
  if (!refs.length || refs.length > limits.refs) throw new Error('Git bundle exceeds the reference limit.');
  const objectLines = git(['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objectsize)'],
    { maxBuffer: 1024 * 1024 }).trim().split('\n').filter(Boolean);
  if (!objectLines.length || objectLines.length > limits.objects) throw new Error('Git bundle exceeds the object limit.');
  const sizes = objectLines.map(line => {
    const [hash, value, extra] = line.split(' ');
    return !extra && SHA.test(hash) && /^\d+$/.test(value) ? Number(value) : NaN;
  });
  if (sizes.length !== objectLines.length || sizes.some(size => !Number.isSafeInteger(size) || size < 0 || size > limits.objectBytes) ||
      sizes.reduce((sum, size) => sum + size, 0) > limits.unpackedBytes) throw new Error('Git bundle exceeds the unpacked object limit.');
  return { commitCount, refCount: refs.length, objectCount: objectLines.length };
}

/** Scan a self-contained Git bundle supplied through Purple's authenticated artifact intake. */
export async function scanGitHistoryArtifact({
  artifactPath = '/tmp/purple-scan/artifact', expectedSha256, expectedBytes,
  root = '/tmp/purple-scan/history', execute = spawnSync, now = Date.now,
  gitleaksConfig = '/opt/purple/gitleaks.toml', ignoreFile = '/opt/purple/empty.ignore',
  limits = HISTORY_LIMITS
} = {}) {
  const startedAt = now();
  await verifyArtifact(artifactPath, expectedSha256, expectedBytes, limits.artifactBytes);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const verifyRepo = path.join(root, 'verify.git');
  const repository = path.join(root, 'repository.git');
  const reportPath = path.join(root, 'gitleaks-history.json');
  const env = {
    PATH: '/usr/local/bin:/usr/bin:/bin', HOME: root, TMPDIR: root,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
    GIT_OPTIONAL_LOCKS: '0', GIT_PROTOCOL_FROM_USER: '0', GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1', NO_COLOR: '1'
  };
  try {
    checked(execute, 'git', ['init', '--bare', '--quiet', verifyRepo], { cwd: root, env });
    checked(execute, 'git', ['bundle', 'verify', artifactPath], { cwd: verifyRepo, env });
    checked(execute, 'git', ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=always',
      'clone', '--mirror', '--quiet', '--', artifactPath, repository], { cwd: root, env, timeout: 60000 });
    const inventory = inspectedRepository(execute, repository, env, limits);
    const result = execute('gitleaks', ['git', repository, '--log-opts=--all', '--config', gitleaksConfig,
      '--gitleaks-ignore-path', ignoreFile, '--redact=100', '--ignore-gitleaks-allow', '--exit-code', '0',
      '--no-banner', '--report-format', 'json', '--report-path', reportPath], {
      cwd: root, env, timeout: 210000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'ignore', 'ignore']
    });
    if ((await stat(reportPath)).size > REPORT_LIMIT) throw new Error('Gitleaks history report exceeds the size limit.');
    const { findings, omitted } = normalizeGitHistoryFindings(JSON.parse(await readFile(reportPath, 'utf8')));
    const truncated = findings.length > limits.findings;
    const complete = result.status === 0 && !result.error && !omitted && !truncated;
    return {
      status: complete ? 'completed' : 'partial',
      tools: [{ name: 'gitleaks-history', version: '8.30.1', status: complete ? 'complete' : 'partial',
        durationMs: now() - startedAt, findings: Math.min(findings.length, limits.findings),
        ...(!complete ? { error: 'Scanner execution or result coverage was incomplete.' } : {}) }],
      findings: findings.slice(0, limits.findings),
      warnings: [...(omitted ? ['Some history findings had invalid file or commit locations.'] : []),
        ...(truncated ? ['Report truncated to 500 findings. Narrow the history range and repeat.'] : [])],
      coverage: { artifactBytes: expectedBytes, artifactSha256: expectedSha256.toLowerCase(), ...inventory,
        scope: 'All refs present in the uploaded self-contained Git bundle; current uncommitted files, omitted refs and remote-only history are outside this scan.' },
      execution: { startedAt, finishedAt: now(), durationMs: now() - startedAt }
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
