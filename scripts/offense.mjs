#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, realpath, readdir, lstat } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from '../public/skills/purple/scripts/purple.mjs';

const HELP = `Usage:
  offense dependencies scan [directory] [--output directory]
  offense dependencies fix [directory] [--output directory] [--scan scan.json]
      [--repository owner/repo] [--model model] [--max-attempts 1..3] [--max-turns 1..20]
      [--image purple-hermes:local]
  offense dependencies verify --report fix.json [--output directory]
  offense dependencies pr-status --report fix.json
  offense dependencies publish --report fix.json --repository owner/repo
      --branch codex/dependency-fix --authorize-publish

Fix uses a disposable Docker container and a clean pinned checkout. It does not
modify your source checkout, publish a PR, merge, or deploy. Build the image with
npm run build:hermes first. OPENROUTER_API_KEY is required when Hermes is called.
Reports and review checkouts stay in the chosen local output directory. A PR
publish is a separate explicitly authorized command through your existing gh login.`;

export function parseArguments(args) {
  if (!args.length || args.includes('--help')) return { help: true };
  if (args.shift() !== 'dependencies') throw new Error('Expected dependencies. Use --help for commands.');
  const action = args.shift();
  if (!['scan', 'fix', 'publish', 'verify', 'pr-status'].includes(action)) throw new Error('Expected scan, fix, verify, publish or pr-status.');
  const result = { action, directory: '.', maxAttempts: 2, maxTurns: 12, image: 'purple-hermes:local' };
  if (args[0] && !args[0].startsWith('--')) result.directory = args.shift();
  const values = { '--output': 'output', '--scan': 'scanFile', '--repository': 'repository', '--model': 'model',
    '--max-attempts': 'maxAttempts', '--max-turns': 'maxTurns', '--image': 'image', '--report': 'reportFile', '--branch': 'branch', '--base': 'base' };
  while (args.length) {
    const key = args.shift();
    if (key === '--ci') { result.ci = true; continue; }
    if (key === '--authorize-publish') { result.authorizePublish = true; continue; }
    if (!values[key] || !args[0] || args[0].startsWith('--')) throw new Error(`Unknown or incomplete option: ${key}`);
    result[values[key]] = args.shift();
  }
  result.maxAttempts = Number(result.maxAttempts); result.maxTurns = Number(result.maxTurns);
  if (!Number.isInteger(result.maxAttempts) || result.maxAttempts < 1 || result.maxAttempts > 3 ||
    !Number.isInteger(result.maxTurns) || result.maxTurns < 1 || result.maxTurns > 20) throw new Error('Use 1–3 attempts and 1–20 model turns per attempt.');
  if (result.repository && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(result.repository)) throw new Error('Repository must be owner/repo.');
  if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}$/.test(result.image)) throw new Error('Invalid container image reference.');
  return result;
}
const cleanGitEnv = () => ({ PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });
export const MANAGED_JOB_FILE = '.purple-managed-job.json';
const within = (root, value) => value === root || value.startsWith(root + path.sep);
function narrowJobRoot(directory) {
  const home = path.resolve(homedir());
  if (directory === path.parse(directory).root || directory === path.resolve(tmpdir()) || within(directory, home)) throw new Error('A managed job cannot use a filesystem or home root.');
}
async function canonicalPath(value, { directory = false, mayCreate = false } = {}) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value !== path.resolve(value) || /[,\r\n\0]/.test(value)) throw new Error('Managed job paths must be canonical absolute paths.');
  let cursor = path.parse(value).root, missing = false;
  for (const part of path.relative(cursor, value).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    try {
      const stat = await lstat(cursor);
      if (stat.isSymbolicLink()) throw new Error('Symlinked managed job paths are unsupported.');
    } catch (error) {
      if (error.code !== 'ENOENT' || !mayCreate) throw error;
      missing = true;
    }
  }
  if (!missing) {
    const stat = await lstat(value);
    if (directory ? !stat.isDirectory() : !stat.isFile()) throw new Error('Managed job path has an unsupported file type.');
    if (await realpath(value) !== value) throw new Error('Managed job path changed during validation.');
  }
  return value;
}
async function execute(argv, { cwd, env = cleanGitEnv(), input, timeoutMs = 60000, maxBytes = 1000000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', overflow = false;
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(() => { kill(); }, timeoutMs);
    child.stdout.on('data', part => { if (Buffer.byteLength(stdout) + part.length > maxBytes) { overflow = true; kill(); } else stdout += part; });
    child.stderr.on('data', part => { stderr = (stderr + part).slice(-12000); });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer); kill();
      if (overflow || signal) reject(new Error('Command exceeded its time/output limit.'));
      else resolve({ code, stdout, stderr });
    });
    child.stdin.on('error', () => {}); child.stdin.end(input || '');
  });
}

export async function prepareSnapshot(directory, output) {
  const source = await realpath(directory), requested = path.resolve(output);
  // Resolve existing symlinked parents before creating or mounting anything.
  let ancestor = requested, suffix = [];
  for (;;) {
    try { ancestor = await realpath(ancestor); break; }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.dirname(ancestor);
      if (parent === ancestor) throw error;
      suffix.unshift(path.basename(ancestor)); ancestor = parent;
    }
  }
  const destination = path.join(ancestor, ...suffix);
  narrowJobRoot(destination);
  if (destination === source || destination.startsWith(source + path.sep)) throw new Error('Keep fix output outside the source checkout.');
  const git = async args => {
    const result = await execute(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', ...args], { cwd: source });
    if (result.code !== 0) throw new Error('Could not read the pinned source checkout.'); return result.stdout.trim();
  };
  const top = await git(['rev-parse', '--show-toplevel']);
  if (await realpath(top) !== source) throw new Error('Run dependency fixes from the repository root.');
  if (await git(['status', '--porcelain', '--untracked-files=all'])) throw new Error('Use a clean checkout before fixing dependencies; current work is preserved.');
  const revision = await git(['rev-parse', 'HEAD']);
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('A pinned Git commit is required.');
  await mkdir(destination, { recursive: true, mode: 0o700 });
  if ((await readdir(destination)).length) throw new Error('Choose a new empty output directory so existing files never enter the sandbox.');
  const snapshot = path.join(destination, 'input-repository');
  const clone = await execute(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', 'clone', '--quiet', '--no-hardlinks', '--no-local', '--', source, snapshot]);
  if (clone.code !== 0) throw new Error('Could not create the clean dependency snapshot.');
  const checkout = await execute(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', 'checkout', '--quiet', '--detach', revision], { cwd: snapshot });
  if (checkout.code !== 0) throw new Error('Could not pin the dependency snapshot.');
  // This host-created marker is mounted read-only over the writable artifact
  // volume. Repository programs cannot redefine the next verification mount.
  await writeFile(path.join(destination, MANAGED_JOB_FILE), JSON.stringify({ schemaVersion: 1, kind: 'purple-dependency-fix-job',
    jobId: randomBytes(12).toString('hex'), outputDirectory: destination, inputDirectory: snapshot, revision })+'\n', { mode: 0o600, flag: 'wx' });
  return { directory: snapshot, revision, originalDirectory: source, outputDirectory: destination };
}

export async function prepareVerification(reportFile, verificationOutput) {
  // Find the host's marker from the selected artifact, never from JSON paths.
  const selected = path.resolve(reportFile);
  if (path.basename(selected) !== 'fix.json') throw new Error('Select the managed fix.json report.');
  await canonicalPath(selected);
  let output = path.dirname(selected), marker;
  for (let depth = 0; depth < 12; depth++) {
    narrowJobRoot(output);
    try {
      const markerFile = await canonicalPath(path.join(output, MANAGED_JOB_FILE));
      if ((await lstat(markerFile)).size > 16000) throw new Error('Managed job marker exceeds its size limit.');
      marker = JSON.parse(await readFile(markerFile, 'utf8')); break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      output = path.dirname(output);
    }
  }
  if (!marker || marker.schemaVersion !== 1 || marker.kind !== 'purple-dependency-fix-job' || !/^[a-f0-9]{24}$/.test(marker.jobId || '') ||
    marker.outputDirectory !== output || marker.inputDirectory !== path.join(output, 'input-repository') || !/^[a-f0-9]{40}$/.test(marker.revision || '')) throw new Error('No valid host-managed job marker accompanies this report.');
  const reportParent = path.dirname(selected);
  if (reportParent !== output && !/^verification-[A-Za-z0-9_-]+$/.test(path.relative(output, reportParent))) throw new Error('Verification reports must be in the managed job or a direct verification directory.');
  await canonicalPath(output, { directory: true });
  const directory = await canonicalPath(marker.inputDirectory, { directory: true });
  const sourceDirectory = await canonicalPath(path.join(output, 'work', 'source'), { directory: true });
  const candidateDirectory = await canonicalPath(path.join(output, 'work', 'candidate-0'), { directory: true });
  if ((await lstat(selected)).size > 2 * 1024 * 1024) throw new Error('Fix report exceeds its size limit.');
  const report = JSON.parse(await readFile(selected, 'utf8'));
  if (report.sourceDirectory !== sourceDirectory || report.candidateDirectory !== candidateDirectory || report.revision !== marker.revision) throw new Error('Report paths or revision differ from the host-managed job.');
  const pinned = await execute(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', 'rev-parse', 'HEAD'], { cwd: directory });
  if (pinned.code !== 0 || pinned.stdout.trim() !== marker.revision) throw new Error('Managed input revision differs from the host snapshot.');
  let destination = path.join(output, `verification-${randomBytes(8).toString('hex')}`);
  if (verificationOutput) {
    destination = path.resolve(verificationOutput);
    if (!within(output, destination) || destination === output || path.dirname(destination) !== output || !/^verification-[A-Za-z0-9_-]+$/.test(path.basename(destination))) throw new Error('Use a new direct verification-* directory inside the managed job.');
    await canonicalPath(destination, { directory: true, mayCreate: true });
    try { if ((await readdir(destination)).length) throw new Error('Verification output must be empty.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return { output, pinned: { directory, revision: marker.revision }, input: { mode: 'verify', reportFile: selected, output, directory,
    verificationOutput: destination } };
}

export function dockerArguments({ directory, output, image, uid, gid, name }) {
  for (const value of [directory, output]) if (!path.isAbsolute(value) || /[,\r\n]/.test(value)) throw new Error('Container mount paths must be absolute and cannot contain commas or newlines.');
  if (!/^purple-fix-[a-f0-9]{24}$/.test(name || '')) throw new Error('A unique task container name is required.');
  return ['run', '--rm', '--name', name, '--stop-timeout=5', '--interactive', '--init', '--read-only', '--cap-drop=ALL',
    '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=CHOWN', '--cap-add=KILL', '--cap-add=FOWNER', '--cap-add=DAC_OVERRIDE', '--security-opt=no-new-privileges',
    '--network', `${name}-network`, '--env', 'PURPLE_FIX_EGRESS_PROXY=http://purple-egress:8080',
    '--env', 'HTTP_PROXY=http://purple-egress:8080', '--env', 'HTTPS_PROXY=http://purple-egress:8080',
    '--env', 'NO_PROXY=127.0.0.1,localhost', '--env', 'NODE_USE_ENV_PROXY=1', '--env', 'PURPLE_FIX_ISOLATE_COMMANDS=1',
    '--pids-limit=256', '--memory=3g', '--cpus=2', '--user', '0:0',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=2g',
    '--mount', `type=bind,source=${output},target=${output}`,
    '--mount', `type=bind,source=${directory},target=${directory},readonly`,
    '--mount', `type=bind,source=${path.join(output, MANAGED_JOB_FILE)},target=${path.join(output, MANAGED_JOB_FILE)},readonly`,
    '--workdir', '/tmp', '--entrypoint', 'node', image, '--disable-sigusr1', '/opt/purple/agent/dependency-fix-job.mjs'];
}

export async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) { console.log(HELP); return; }
  if (options.action === 'scan') { console.log(JSON.stringify(await analyze(path.resolve(options.directory), { output: options.output }), null, 2)); return; }
  if (options.action === 'pr-status') {
    if (!options.reportFile) throw new Error('Provide --report from the published dependency fix.');
    const publication = JSON.parse(await readFile(path.join(path.dirname(path.resolve(options.reportFile)), 'pr-published.json'), 'utf8'));
    const { dependencyPrChecks } = await import('../agent/pr-handoff.mjs');
    console.log(JSON.stringify(await dependencyPrChecks({ repository: publication.repository, headSha: publication.headSha }), null, 2)); return;
  }
  if (options.action === 'publish') {
    const { publishDependencyFix } = await import('../agent/pr-handoff.mjs');
    console.log(JSON.stringify(await publishDependencyFix(options), null, 2)); return;
  }
  const image = await execute(['docker', 'image', 'inspect', options.image], { timeoutMs: 15000 });
  if (image.code !== 0) throw new Error('The Hermes image is not available. Run npm run build:hermes first.');
  let output, pinned, input, apiKey;
  if (options.action === 'verify') {
    if (!options.reportFile) throw new Error('Provide --report with the dependency fix.json to verify.');
    ({ output, pinned, input } = await prepareVerification(options.reportFile, options.output));
  } else {
    output = options.output ? path.resolve(options.output) : await mkdtemp(path.join(tmpdir(), 'purple-dependency-fix-'));
    pinned = await prepareSnapshot(options.directory, output);
    output = pinned.outputDirectory;
    let scanFile;
    if (options.scanFile) {
      scanFile = path.join(output, 'initial-scan.json');
      await writeFile(scanFile, await readFile(path.resolve(options.scanFile)), { mode: 0o600 });
    } else scanFile = (await (options.ci ? (await import('./ci/dependency-analysis.mjs')).ciAnalyze : analyze)(pinned.directory, { output: path.join(output, 'scan'), planLimit: 30 })).json;
    apiKey = process.env.OPENROUTER_API_KEY;
    input = { directory: pinned.directory, scanFile, output, repository: options.repository,
      workDirectory: path.join(output, 'work'), maxAttempts: options.maxAttempts, maxTurns: options.maxTurns,
      model: options.model || process.env.PURPLE_FIX_MODEL || 'qwen/qwen3.7-flash', apiKey };
  }
  if (options.ci) {
    input.ci = true;
    if (options.action !== 'verify') {
      const { loadPolicy } = await import('./ci/dependency-policy.mjs');
      const { selectPlan } = await import('./ci/select-dependency-plan.mjs');
      const policy = await loadPolicy();
      const scan = JSON.parse(await readFile(input.scanFile, 'utf8'));
      const selected = selectPlan(scan);
      if (!selected) throw Error('No checked patch/minor high/critical upgrade group is available. Review the audit report.');
      input.selectedTargets = [`${selected.name}@${selected.currentVersion}`];
      input.checks = policy.checks;
      input.commandTimeoutMs = 180000;
      input.maxAttempts = policy.maxAttempts; input.maxTurns = policy.maxTurns;
    }
  }
  input.artifactUid = process.getuid(); input.artifactGid = process.getgid();
  console.error(`Running ${options.action === 'verify' ? 'independent verification' : 'Hermes'} against ${pinned.revision.slice(0,12)} in an isolated container…`);
  const name = `purple-fix-${randomBytes(12).toString('hex')}`;
  const removeContainer = () => {
    for (const argv of [['rm', '--force', name], ['rm', '--force', `${name}-proxy`], ['network', 'rm', `${name}-network`]]) {
      spawnSync('docker', argv, { env: cleanGitEnv(), stdio: 'ignore', timeout: 15000 });
    }
  };
  let interrupted = false, jobNeedsRecovery = false;
  const interrupt = () => { interrupted = true; process.exitCode = 130; removeContainer(); };
  process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
  try {
    const network = await execute(['docker', 'network', 'create', '--internal', `${name}-network`]);
    if (network.code !== 0) throw new Error('Could not create an isolated job network.');
    const proxy = await execute(['docker', 'run', '--rm', '--detach', '--name', `${name}-proxy`, '--init', '--read-only',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '--cpus=0.5',
      '--user', '1000:1000',
      '--entrypoint', 'node', options.image, '--disable-sigusr1', '/opt/purple/agent/fix-egress-proxy.mjs']);
    if (proxy.code !== 0) throw new Error('Could not start the restricted HTTPS gateway.');
    const attach = await execute(['docker', 'network', 'connect', '--alias', 'purple-egress', `${name}-network`, `${name}-proxy`]);
    if (attach.code !== 0) throw new Error('Could not attach the restricted HTTPS gateway.');
    jobNeedsRecovery = true;
    const run = await execute(['docker', ...dockerArguments({ directory: pinned.directory, output, image: options.image, uid: process.getuid(), gid: process.getgid(), name })],
      { input: JSON.stringify(input), timeoutMs: 20 * 60000, maxBytes: 256000 });
    jobNeedsRecovery = run.code !== 0;
    const clean = text => text.split(apiKey || '\0').join('[REDACTED]');
    if (run.stdout) process.stdout.write(clean(run.stdout));
    if (run.stderr) process.stderr.write(clean(run.stderr));
    process.exitCode = interrupted ? 130 : run.code === 0 ? 0 : 2;
  } finally {
    removeContainer(); process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
    const artifactRoot = await lstat(output);
    if (jobNeedsRecovery || artifactRoot.uid !== process.getuid() || (artifactRoot.mode & 0o777) !== 0o700) {
      // A timed-out/killed controller may leave root-owned artifacts. Recover
      // only this previously validated job mount in a credential-free container.
      const recovery = await execute(['docker', 'run', '--rm', '--interactive', '--init', '--read-only', '--network', 'none',
        '--cap-drop=ALL', '--cap-add=CHOWN', '--security-opt=no-new-privileges', '--user', '0:0',
        '--pids-limit=32', '--memory=128m', '--cpus=0.5', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m',
        '--mount', `type=bind,source=${output},target=${output}`, '--entrypoint', 'node', options.image, '--disable-sigusr1', '/opt/purple/agent/dependency-fix-job.mjs'],
      { input: JSON.stringify({ mode: 'restore_ownership', output, artifactUid: process.getuid(), artifactGid: process.getgid() }), timeoutMs: 60000, maxBytes: 2000 });
      if (recovery.code !== 0) throw new Error('Job artifacts remain owned by the isolated controller; ownership recovery did not complete.');
    }
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Offense: ${error.message}`); if (process.exitCode !== 130) process.exitCode = 1; });
}
