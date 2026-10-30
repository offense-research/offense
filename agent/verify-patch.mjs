import { readFile, writeFile, mkdir, lstat, copyFile, glob } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { npmProjects } from './npm-projects.mjs';
import { validateSecurityPlan, contractFingerprint, normalPassed, securityFailure, securityPassed, verificationQualified } from './verification-gate.mjs';
const exec = promisify(execFile);
const hash = value => createHash('sha256').update(value).digest('hex');
const ignored = file => file.split('/').some(part => ['node_modules', '.git', 'vendor', 'dist', 'build', 'coverage', 'fixtures', '__fixtures__'].includes(part));
async function regular(root, relative) {
  if (relative.startsWith('/') || relative.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe test path.');
  let current = root;
  for (const segment of relative.split('/')) { current = path.join(current, segment); if ((await lstat(current)).isSymbolicLink()) throw new Error('Symlinked test files are unsupported.'); }
  if (!(await lstat(current)).isFile()) throw new Error('Test must be a regular file.');
  return current;
}
async function git(root, args) {
  return (await exec('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', `safe.directory=${path.resolve(root)}`, ...args], { cwd: root, env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1' }, maxBuffer: 1500000, timeout: 10000 })).stdout;
}
async function snapshot(root) {
  return hash((await git(root, ['diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD'])) + '\n' + (await git(root, ['status', '--porcelain', '--untracked-files=all'])));
}
async function normalFiles(baseline, plan) {
  let argv = plan.normal;
  const manifest = await readFile(path.join(baseline, 'package.json'), 'utf8').then(JSON.parse).catch(error => error.code === 'ENOENT' ? null : Promise.reject(error));
  if (manifest?.scripts?.test) {
    const script = manifest.scripts.test;
    // A shell/delegating/framework command requires a future structured adapter.
    if (!/^node\s+--test(?:\s+[A-Za-z0-9_./*?{}-]+)*$/.test(script)) throw new Error('Normal test script needs a supported structured adapter; automatic verification currently supports Node --test.');
    const pinned = script.trim().split(/\s+/);
    if (JSON.stringify(argv) !== JSON.stringify(['npm', 'test']) && JSON.stringify(argv) !== JSON.stringify(pinned)) throw new Error('Normal command must run the original repository test script without narrowing it.');
    argv = pinned;
  }
  if (argv[0] !== 'node' || argv[1] !== '--test' || argv.slice(2).some(arg => arg.startsWith('-') || arg.startsWith('/') || arg.split('/').includes('..'))) throw new Error('Normal tests require Node --test paths; arbitrary commands and filters cannot establish verification.');
  const tracked = (await git(baseline, ['ls-files', '-z'])).split('\0').filter(Boolean);
  const detected = tracked.filter(file => !ignored(file) && /\.(?:test|spec)\.[cm]?js$/.test(file));
  const selected = new Set();
  if (!argv.slice(2).length) for (const file of detected) selected.add(file);
  for (const pattern of argv.slice(2)) {
    if (!/^[A-Za-z0-9_./*?{}-]+$/.test(pattern)) throw new Error('Unsupported normal test path.');
    let matches = 0;
    for await (const file of glob(pattern, { cwd: baseline })) {
      if (!ignored(file) && tracked.includes(file) && /\.[cm]?js$/.test(file)) { selected.add(file.split(path.sep).join('/')); matches++; }
      if (selected.size > 200) throw new Error('Normal suite exceeds 200 files.');
    }
    if (!matches) throw new Error('Normal test path matched no tracked test files.');
  }
  if (!selected.size || selected.size > 200 || detected.some(file => !selected.has(file))) throw new Error('Normal suite is empty, too large, or omits existing test files.');
  return [...selected].sort();
}
async function observed(command, directory, files, observer) {
  const process = await command(directory, ['node', observer, JSON.stringify(files)]);
  if (process.code !== 0 || process.timedOut || process.signal || process.truncated) return { ...process, classification: 'infrastructure_error', passed: false };
  try {
    const parsed = JSON.parse(process.stdout ?? process.output);
    if (parsed.protocolVersion !== 2) throw new Error('Missing observer protocol.');
    return { ...process, ...parsed, passed: parsed.complete && parsed.summary?.failed === 0 && parsed.summary?.passed > 0, output: JSON.stringify(parsed) };
  } catch { return { ...process, passed: false, classification: 'infrastructure_error', error: 'Missing or invalid structured test report.' }; }
}
export async function verifyPatch({ baseline, candidate, plan: input, command, observer = '/opt/purple/test-observer.mjs' }) {
  const report = { gateVersion: 2, verified: false, baselineNormal: null, baselineReproduction: null, patchedReproduction: null, patchedNormal: null, testFilesUnchanged: false };
  function block(reason) { report.blocker = reason; return report; }
  try {
    const plan = validateSecurityPlan(input); report.contract = plan; report.contractFingerprint = contractFingerprint(plan);
    const normal = await normalFiles(baseline, plan); report.normalTestFiles = normal;
    for (const file of normal) {
      const before = await readFile(await regular(baseline, file)), after = await readFile(await regular(candidate, file));
      if (!before.equals(after)) return block(`Existing normal test changed: ${file}`);
    }
    for (const file of plan.testPaths) {
      await regular(candidate, file);
      if (await lstat(path.join(baseline, file)).then(() => true, error => error.code === 'ENOENT' ? false : Promise.reject(error))) return block('Security regressions must be new files; preserve the original normal suite.');
    }
    report.setup = { projects: [] };
    for (const project of await npmProjects(baseline)) {
      const args = ['npm', 'ci', '--prefix', project, '--ignore-scripts', '--no-audit', '--no-fund'];
      const original = await command(baseline, args, 'setup'), patched = await command(candidate, args, 'setup');
      report.setup.projects.push({ directory: project, baseline: original, patched });
      if (!original.passed || !patched.passed) return block('Dependency setup did not pass on both checkouts.');
    }
    const baselineState = await snapshot(baseline), candidateState = await snapshot(candidate);
    report.baselineNormal = await observed(command, baseline, normal, observer);
    if (!normalPassed(report.baselineNormal)) return block('Original normal suite failed, skipped tests, ran no tests, or did not return complete structured evidence.');
    if (await snapshot(baseline) !== baselineState) return block('Original normal checks modified the checkout.');
    const expectedHashes = new Map();
    for (const file of plan.testPaths) {
      const source = await regular(candidate, file);
      let parent = baseline;
      for (const segment of file.split('/').slice(0, -1)) {
        parent = path.join(parent, segment);
        await mkdir(parent).catch(error => { if (error.code !== 'EEXIST') throw error; });
        if (!(await lstat(parent)).isDirectory() || (await lstat(parent)).isSymbolicLink()) throw new Error('Symlinked regression parent.');
      }
      await writeFile(path.join(baseline, file), '', { flag: 'wx' });
      await regular(baseline, file); await copyFile(source, path.join(baseline, file));
      expectedHashes.set(file, hash(await readFile(source)));
    }
    const baselineWithTests = await snapshot(baseline);
    report.baselineReproduction = await observed(command, baseline, plan.testPaths, observer);
    if (!securityFailure(report.baselineReproduction, plan.securityTests)) return block('Baseline did not fail only the declared security assertions with the expected unsafe values. Setup/runtime failures are not reproduction.');
    report.baselineReproduction.classification = 'security_assertion_failure';
    report.patchedReproduction = await observed(command, candidate, plan.testPaths, observer);
    if (!securityPassed(report.patchedReproduction, report.baselineReproduction, plan.securityTests)) return block('Patched security tests failed, changed identity, skipped, or did not run completely.');
    report.patchedNormal = await observed(command, candidate, normal, observer);
    if (!normalPassed(report.patchedNormal)) return block('Patched normal suite did not completely pass.');
    for (const file of [...normal, ...plan.testPaths]) {
      const original = hash(await readFile(await regular(baseline, file))), patched = hash(await readFile(await regular(candidate, file)));
      if (original !== patched || expectedHashes.has(file) && original !== expectedHashes.get(file)) return block('Test contents changed during verification.');
    }
    if (await snapshot(baseline) !== baselineWithTests || await snapshot(candidate) !== candidateState) return block('Verification commands modified the original or proposed checkout.');
    report.testFilesUnchanged = true; report.verified = true;
    if (!verificationQualified(report)) { report.verified = false; return block('Structured verification evidence did not meet the final gate.'); }
    return report;
  } catch (error) { return block(String(error.message || error).slice(0, 1000)); }
}
