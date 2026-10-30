import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';

const VERSION = '3.1.4';
const MAX_COMPRESSED = 32 * 1024 * 1024;
const MAX_EXPANDED = 128 * 1024 * 1024;
const MAX_ENTRIES = 1024;
const MAX_OUTPUT = 2 * 1024 * 1024;
const digestPattern = /^sha256:[0-9a-f]{64}$/;

function exactPolicy(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 500 &&
    !/[\x00-\x1f\x7f*\[\]{}()|^$\\]/.test(value);
}

function tarName(header) {
  const name = header.toString('utf8', 0, 100).split('\0')[0];
  const prefix = header.toString('utf8', 345, 500).split('\0')[0];
  return `${prefix ? `${prefix}/` : ''}${name}`.replace(/^(?:\.\/)+/, '').replace(/\/$/, '');
}

function safeName(name) {
  if (!name || name === '.' || name.startsWith('/') || name.includes('\\') ||
      !/^[A-Za-z0-9._/-]+$/.test(name) || name.split('/').some(part => !part || part === '.' || part === '..')) return false;
  return path.posix.normalize(name) === name;
}

/** Expand only regular OCI layout files; reject links, devices and tar path tricks. */
export async function extractCosignSave({ archivePath, outputDir, expectedDigest }) {
  if (!path.isAbsolute(archivePath) || !path.isAbsolute(outputDir) || !digestPattern.test(expectedDigest))
    throw new Error('Invalid Cosign archive parameters.');
  const archiveStat = await stat(archivePath);
  if (!archiveStat.isFile() || archiveStat.size > MAX_COMPRESSED)
    throw new Error('Cosign save archive exceeds its size limit or is not a regular file.');
  const compressed = await readFile(archivePath);
  if (compressed.length < 2 || compressed.length > MAX_COMPRESSED || compressed[0] !== 0x1f || compressed[1] !== 0x8b)
    throw new Error('Cosign save archive exceeds its size limit or is not gzip.');
  const tar = gunzipSync(compressed, { maxOutputLength: MAX_EXPANDED });
  const seen = new Set(), blobs = new Set();
  let entries = 0;
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) {
      if (tar.subarray(offset).some(byte => byte !== 0)) throw new Error('Cosign save archive has trailing data.');
      break;
    }
    if (++entries > MAX_ENTRIES) throw new Error('Cosign save archive has too many entries.');
    const checksumText = header.toString('ascii', 148, 156).replace(/\0.*$/, '').trim();
    const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (!/^[0-7]+$/.test(checksumText) || checksum !== Number.parseInt(checksumText, 8))
      throw new Error('Cosign save archive has an invalid tar header.');
    const octal = header.toString('ascii', 124, 136).replace(/\0.*$/, '').trim();
    if (!/^[0-7]+$/.test(octal)) throw new Error('Cosign save archive has an invalid tar size.');
    const size = Number.parseInt(octal, 8), start = offset + 512;
    if (!Number.isSafeInteger(size) || size < 0 || start + size > tar.length)
      throw new Error('Cosign save archive entry exceeds its bounds.');
    const type = header[156];
    if (type === 120 || type === 103) { // PAX metadata is ignored; it cannot override the path used below.
      if (size > 65536) throw new Error('Cosign save archive has oversized metadata.');
      offset = start + Math.ceil(size / 512) * 512;
      continue;
    }
    const name = tarName(header);
    if (!name && type === 53 && size === 0) {
      offset = start;
      continue;
    }
    if (!safeName(name)) throw new Error('Cosign save archive contains an unsafe path.');
    if (seen.has(name)) throw new Error('Cosign save archive contains duplicate paths.');
    seen.add(name);
    const target = path.join(outputDir, ...name.split('/'));
    if (type === 53) {
      if (size !== 0) throw new Error('Cosign save archive has an invalid directory.');
      await mkdir(target, { recursive: true, mode: 0o700 });
    } else if (type === 0 || type === 48) {
      const content = tar.subarray(start, start + size);
      if (name.startsWith('blobs/sha256/')) {
        const hash = name.slice('blobs/sha256/'.length);
        if (!/^[0-9a-f]{64}$/.test(hash) || createHash('sha256').update(content).digest('hex') !== hash)
          throw new Error('Cosign save archive has a corrupt OCI blob.');
        blobs.add(`sha256:${hash}`);
      }
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, content, { flag: 'wx', mode: 0o600 });
    } else {
      throw new Error('Cosign save archive contains an unsupported tar entry.');
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!seen.has('index.json') || !seen.has('oci-layout') || !blobs.has(expectedDigest))
    throw new Error('Cosign save archive is missing the expected OCI image manifest.');
  const index = JSON.parse(await readFile(path.join(outputDir, 'index.json'), 'utf8'));
  const layout = JSON.parse(await readFile(path.join(outputDir, 'oci-layout'), 'utf8'));
  if (index?.schemaVersion !== 2 || !Array.isArray(index.manifests) || layout?.imageLayoutVersion !== '1.0.0')
    throw new Error('Cosign save archive is not a valid OCI layout.');
  return { blobs: blobs.size, entries };
}

function verifiedDigests(stdout) {
  let report;
  try { report = JSON.parse(stdout); } catch { return []; }
  const entries = Array.isArray(report) ? report : [report];
  return entries.map(item => {
    const critical = item?.critical || item?.Critical;
    const image = critical?.image || critical?.Image;
    const digest = image?.['docker-manifest-digest'] || image?.['Docker-manifest-digest'];
    return typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest) ? `sha256:${digest}` : digest;
  }).filter(value => typeof value === 'string' && digestPattern.test(value));
}

/** Verify a cosign-save OCI image against an exact signer policy without network access. */
export async function runCosignImage({ archivePath, expectedDigest, expectedIdentity, expectedIssuer,
  reportPath, execute = spawnSync, timeoutMs = 120000,
  executable = '/usr/local/bin/cosign', trustedRootPath = '/opt/purple/sigstore/trusted_root.json',
  tempRoot = os.tmpdir() } = {}) {
  if (typeof archivePath !== 'string' || !path.isAbsolute(archivePath) || !digestPattern.test(expectedDigest) ||
      !exactPolicy(expectedIdentity) || !exactPolicy(expectedIssuer) ||
      typeof trustedRootPath !== 'string' || !path.isAbsolute(trustedRootPath) ||
      (reportPath !== undefined && (typeof reportPath !== 'string' || !path.isAbsolute(reportPath))))
    throw new Error('Cosign needs a staged archive, digest and exact signer identity and issuer.');
  const persist = async result => {
    if (reportPath) await writeFile(reportPath, JSON.stringify(result), { mode: 0o600 });
    return result;
  };
  const failed = error => ({ status: 'failed', version: VERSION, findings: [], error });
  const layoutDir = await mkdtemp(path.join(tempRoot, 'purple-cosign-'));
  try {
    try { await extractCosignSave({ archivePath, outputDir: layoutDir, expectedDigest }); }
    catch { return persist(failed('The signed-image archive is invalid or does not contain the expected digest.')); }
    const args = ['verify', '--local-image', '--offline=true', '--check-claims=true', '--output=json',
      `--trusted-root=${trustedRootPath}`, `--certificate-identity=${expectedIdentity}`,
      `--certificate-oidc-issuer=${expectedIssuer}`, layoutDir];
    const result = execute(executable, args, {
      cwd: layoutDir,
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: layoutDir, TMPDIR: layoutDir, NO_COLOR: '1' },
      encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (result.error || result.status !== 0 || !verifiedDigests(result.stdout).includes(expectedDigest))
      return persist(failed('Image signature or expected signer could not be verified offline.'));
    return persist({ status: 'complete', version: VERSION, findings: [],
      verified: { digest: expectedDigest, identity: expectedIdentity, issuer: expectedIssuer } });
  } finally { await rm(layoutDir, { recursive: true, force: true }); }
}
