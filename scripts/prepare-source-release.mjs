import { lstat, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const denyPart = /^(?:\.git|\.amp|\.agents|\.bugpatrol|node_modules|data|reports|\.wrangler|\.worker-build|\.infisical\.(?:yaml|json)|credentials(?:\..*)?)$/i;
const denyFile = /\.(?:tgz|tar|gz|xz|bz2|zst|zip|7z|whl|deb|rpm|exe|dll|dylib|so(?:\.\d+)*|pem|key|p12|pfx|db|sqlite|jsonl)(?:-.*)?$/i;
// These optional runtimes share the unresolved MobSF/SSLyze boundary. Keep
// them private rather than publishing incomplete runners or implying clearance.
const deferredAssessmentPaths = new Set([
  'agent/mobsf-offline-policy.py', 'agent/assessment-network-tls.py',
  'agent/assessment-network.mjs', 'agent/assessment-offline.mjs',
  'agent/assessment-mobile.Dockerfile', 'agent/assessment-mobile.Dockerfile.dockerignore',
  'agent/assessment-network.Dockerfile', 'agent/assessment-network.Dockerfile.dockerignore',
  'agent/assessment-offline.Dockerfile', 'agent/assessment-offline.Dockerfile.dockerignore',
  'test/assessment-network.test.js', 'test/assessment-network-tls.test.js',
  'test/assessment-offline.test.js', 'test/mobsf-offline-policy.test.js', 'test/discovery-trust.test.js'
]);
function safeName(name) {
  if (typeof name !== 'string' || name.startsWith('/') || name.includes('\\') ||
      name.split('/').some(part => !part || part === '.' || part === '..' || denyPart.test(part)) ||
      name.split('/').some(part => part.startsWith('.env') && part !== '.env.example') || denyFile.test(name) ||
      deferredAssessmentPaths.has(name) || /^docs\/(?:e2e|support|remediation|ux)\//.test(name)) throw new Error('Forbidden source-release path.');
  return name;
}
async function sourceFile(name) {
  safeName(name);
  let current = root;
  for (const part of name.split('/')) {
    current = path.join(current, part);
    if ((await lstat(current)).isSymbolicLink()) throw new Error(`Release symlink: ${name}`);
  }
  const info = await lstat(current);
  if (!info.isFile() || info.nlink !== 1 || info.size > 20 * 1024 * 1024) throw new Error(`Invalid release file: ${name}`);
  return { bytes: await readFile(current), mode: info.mode & 0o111 ? 0o755 : 0o644 };
}

export async function prepareSourceRelease(destination) {
  const target = path.resolve(destination);
  const parent = await realpath(path.dirname(target));
  const actualTarget = path.join(parent, path.basename(target));
  const actualRoot = await realpath(root);
  if (actualTarget === actualRoot || actualTarget.startsWith(actualRoot + path.sep)) throw new Error('Export must be outside the checkout.');
  const allowed = JSON.parse(await readFile(new URL('../config/source-release-files.json', import.meta.url), 'utf8'));
  const seen = new Set(), files = [], inventory = [];
  // Validate the complete manifest before creating any output. Missing files,
  // symlinks, collisions or a removed publication guard fail closed.
  for (const entry of allowed) {
    const source = typeof entry === 'string' ? entry : entry.source;
    const name = safeName(typeof entry === 'string' ? entry : entry.destination);
    if (seen.has(name) || ['SOURCE-RELEASE.json', 'DEPENDENCY-LICENSES.json'].includes(name)) throw new Error('Duplicate or reserved release path.');
    seen.add(name);
    let { bytes, mode } = await sourceFile(source);
    // Retain generic release logic and its synthetic tests, not the private
    // operator's fallback destinations. Keep the original deployment untouched.
    if (['scripts/deployment-secrets.mjs', 'test/infisical.test.js'].includes(name)) {
      bytes = Buffer.from(bytes.toString('utf8').replace(/https:\/\/purple-agent(-staging)?\.[a-z0-9-]+\.workers\.dev/g,
        (_match, staging) => `https://agent${staging || ''}.example.invalid`));
    }
    if (name === 'scripts/deploy-agent-console-release.mjs') {
      const text = bytes.toString('utf8');
      const operator = /const account = '[a-f0-9]{32}', workerId = '[a-f0-9]{32}';/g;
      if ([...text.matchAll(operator)].length !== 1) throw new Error('Review the deployment identifier export boundary.');
      bytes = Buffer.from(text.replace(operator, `const account = '${'0'.repeat(32)}', workerId = '${'0'.repeat(32)}';`));
    }
    if (name.endsWith('package.json')) {
      const metadata = JSON.parse(bytes);
      if (!name.includes('fixtures/') && !name.includes('/node_modules/') && metadata.name && metadata.private !== true)
        throw new Error(`Publication guard missing: ${name}`);
      if (name === 'package.json') {
        // The public source candidate has no commands aimed at live operations.
        const safeScripts = ['dev', 'start', 'build', 'build:site', 'build:skill', 'build:agent-sdk', 'build:cli', 'postinstall', 'pretest', 'test', 'test:site'];
        metadata.scripts = Object.fromEntries(Object.entries(metadata.scripts).filter(([key]) => safeScripts.includes(key)));
        bytes = Buffer.from(JSON.stringify(metadata, null, 2) + '\n');
      }
    }
    if (name.endsWith('package-lock.json')) {
      const lock = JSON.parse(bytes);
      for (const [location, value] of Object.entries(lock.packages || {})) {
        if (!location) continue;
        if (value.resolved) {
          const url = new URL(value.resolved);
          if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.search || url.hash)
            throw new Error(`Nonpublic dependency resolution: ${name}`);
        }
        inventory.push({ lockfile: name, location, version: value.version,
          license: value.license || 'REVIEW_REQUIRED', integrity: value.integrity || null });
      }
    }
    // High-confidence patterns only. Never echo the matched material. This is
    // supplemental to a redacted scanner and human private-data review.
    const text = bytes.toString('utf8');
    if (/(?:gh[opsu]_|github_pat_|sk-or-v1-)[A-Za-z0-9_-]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text))
      throw new Error(`Potential credential requires review: ${name}`);
    files.push({ path: name, source, bytes, mode });
  }
  for (const required of ['LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md', 'THIRD_PARTY_NOTICES.md', 'package.json',
    'licenses/GPL-3.0.txt', 'licenses/AGPL-3.0.txt'])
    if (!seen.has(required)) throw new Error(`Missing release resource: ${required}`);
  await mkdir(actualTarget, { mode: 0o700 }); // never merge into/overwrite an export
  try {
    for (const file of files) {
      await mkdir(path.dirname(path.join(actualTarget, file.path)), { recursive: true, mode: 0o700 });
      await writeFile(path.join(actualTarget, file.path), file.bytes, { mode: file.mode, flag: 'wx' });
    }
    const dependencyBytes = Buffer.from(JSON.stringify(inventory, null, 2) + '\n');
    await writeFile(path.join(actualTarget, 'DEPENDENCY-LICENSES.json'), dependencyBytes, { flag: 'wx' });
    const manifest = { schemaVersion: 1, releaseType: 'source-only', publicationApproved: false, historyIncluded: false,
      artifactPublicationApproved: false, hostedComplianceVerified: false,
      excludedPaths: [...deferredAssessmentPaths],
      blockers: ['private-security-reporting', 'exact-snapshot-publication-approval'],
      dependencyInventorySha256: hash(dependencyBytes),
      files: files.map(file => ({ path: file.path, sha256: hash(file.bytes), bytes: file.bytes.length })) };
    await writeFile(path.join(actualTarget, 'SOURCE-RELEASE.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
    return { files: files.length, dependencies: inventory.length, publicationApproved: false,
      manifestSha256: hash(await readFile(path.join(actualTarget, 'SOURCE-RELEASE.json'))) };
  } catch (error) { await rm(actualTarget, { recursive: true, force: true }); throw error; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/prepare-source-release.mjs <new-private-directory-outside-checkout>');
  console.log(JSON.stringify(await prepareSourceRelease(process.argv[2])));
}
