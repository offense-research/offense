import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, stat, symlink } from 'node:fs/promises';
import path from 'node:path';

const MAX_IMAGE_BYTES = 80 * 1024 * 1024;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;

export async function verifyImageArchive(file, { sha256, size }) {
  if (!/^[a-f0-9]{64}$/.test(sha256 || '') || !Number.isSafeInteger(size) || size < 1 || size > MAX_IMAGE_BYTES)
    throw new Error('Invalid image archive metadata.');
  const actual = await stat(file);
  if (!actual.isFile() || actual.size !== size) throw new Error('Image archive size differs from the upload.');
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(file)) digest.update(chunk);
  if (digest.digest('hex') !== sha256) throw new Error('Image archive checksum differs from the upload.');
}

export async function runImageScan({ artifactPath, sha256, size, reportPath, execute, timeoutMs = 210000,
  cacheDir = path.join(path.dirname(reportPath), 'trivy-cache'), databaseDir = '/opt/trivy-cache/db',
  configPath = '/opt/purple/trivy.yaml', ignorePath = '/opt/purple/empty.ignore' }) {
  await verifyImageArchive(artifactPath, { sha256, size });
  await mkdir(cacheDir, { recursive: true, mode: 0o700 });
  try { await symlink(databaseDir, `${cacheDir}/db`, 'dir'); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  const args = ['image', '--input', artifactPath, '--config', configPath, '--ignorefile', ignorePath,
    '--cache-dir', cacheDir, '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--scanners', 'vuln',
    '--format', 'json', '--timeout', `${Math.max(30, Math.floor(timeoutMs / 1000) - 10)}s`, '--output', reportPath];
  const result = execute('trivy', args, { timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp/purple-scan', TMPDIR: '/tmp/purple-scan', NO_COLOR: '1' },
    stdio: ['ignore', 'ignore', 'ignore'] });
  const info = await stat(reportPath);
  if (!info.isFile() || info.size > MAX_REPORT_BYTES) throw new Error('Trivy image report is missing or too large.');
  const report = JSON.parse(await readFile(reportPath, 'utf8'));
  // Trivy omits Results entirely for a valid image with no recognized packages.
  if (!Number.isInteger(report?.SchemaVersion) || report.ArtifactType !== 'container_image' ||
      (report.Results !== undefined && !Array.isArray(report.Results)))
    throw new Error('Trivy image report is invalid.');
  return { report, complete: result.status === 0 && !result.error };
}

export { MAX_IMAGE_BYTES };
