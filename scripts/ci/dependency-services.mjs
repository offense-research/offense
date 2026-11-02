import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ciAnalyze, ciMetadata } from './dependency-analysis.mjs';
import { loadPolicy, allowedPath, minorUpgrade, validateManifest, validateLock } from './dependency-policy.mjs';
const exec = promisify(execFile);
export async function candidatePolicy(source, candidate, policy) {
  const { stdout } = await exec('git', ['-c', `safe.directory=${candidate}`, '-c', 'core.hooksPath=/dev/null', 'diff', '--name-only', '-z', 'HEAD'], { cwd: candidate, env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }, maxBuffer: 100000 });
  for (const file of stdout.split('\0').filter(Boolean)) {
    if (!allowedPath(file, policy)) throw Error(`Change requires manual review: ${file}`);
    if (file.endsWith('package.json')) validateManifest(JSON.parse(await readFile(path.join(source, file), 'utf8')), JSON.parse(await readFile(path.join(candidate, file), 'utf8')));
    if (file.endsWith('package-lock.json')) validateLock(JSON.parse(await readFile(path.join(candidate, file), 'utf8')));
  }
}
export async function ciServices() {
  const policy = await loadPolicy();
  return {
    analyze: ciAnalyze, collectMetadata: ciMetadata,
    allowedPath: file => allowedPath(file, policy),
    validateChanges(changes) { if (!changes.every(c => minorUpgrade(c.currentVersion, c.targetVersion))) throw Error('Major, prerelease, downgrade and 0.x minor upgrades require manual review.'); },
    validateCandidate: (source, candidate) => candidatePolicy(source, candidate, policy)
  };
}
