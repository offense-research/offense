import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, lstat, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { validateSecurityPlan } from './verification-gate.mjs';
import { verifyPatch } from './verify-patch.mjs';
import { verificationInstructions } from './verification-prompt.mjs';

const MAX_OUTPUT = 256 * 1024;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

async function command(argv, { cwd, env = {}, timeout = 180000, allowFailure = false, maxOutput = MAX_OUTPUT } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd, detached: true, env: { PATH: process.env.PATH, HOME: process.env.HOME, GIT_TERMINAL_PROMPT: '0',
        GIT_SSL_CAINFO: '/etc/cloudflare/certs/cloudflare-containers-ca.crt',
        NODE_EXTRA_CA_CERTS: '/etc/cloudflare/certs/cloudflare-containers-ca.crt',
        PI_OFFLINE: '1', PI_TELEMETRY: '0', ...env },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '', stderr = '', exceeded = false;
    let timedOut = false;
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeout);
    child.stdout.on('data', chunk => {
      if (stdout.length < maxOutput) stdout += chunk.toString().slice(0, maxOutput - stdout.length);
      else exceeded = true;
    });
    child.stderr.on('data', chunk => { if (stderr.length < 3000) stderr += chunk.toString().slice(0, 3000 - stderr.length); });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer); kill();
      if (exceeded) return reject(new Error(`${argv[0]} produced too much output.`));
      if (code !== 0 && !allowFailure) return reject(new Error(timedOut ? `${argv[0]} timed out after ${Math.round(timeout / 1000)} seconds.` : `${argv[0]} failed (${signal || code}): ${stderr.slice(-500)}`));
      resolve({ code, signal, timedOut, truncated: exceeded, passed: code === 0 && !timedOut && !signal, stdout: stdout.trim(), stderr: stderr.trim(), output: `${stdout.trim()}\n${stderr.trim()}`.trim() });
    });
  });
}

async function run(input) {
  if (!REPOSITORY.test(input.repository) || !/^[A-Za-z0-9/_.-]{1,100}$/.test(input.model) ||
      !Array.isArray(input.logs) || input.logs.length > 100 || !input.githubToken || !input.openrouterKey ||
      !input.incident || typeof input.incident !== 'object') throw new Error('Invalid investigation input.');
  const root = await mkdtemp(path.join(tmpdir(), 'purple-agent-'));
  const repo = path.join(root, 'repo'), baseline = path.join(root, 'baseline');
  const context = path.join(root, 'context'), output = path.join(root, 'output');
  await mkdir(context); await mkdir(output);
  const gitHeader = `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${input.githubToken}`).toString('base64')}`;
  await command(['git', '-c', `http.https://github.com/.extraheader=${gitHeader}`, 'clone', '--depth', '1',
    '--single-branch', `https://github.com/${input.repository}.git`, repo], { timeout: 120000 });
  const sha = (await command(['git', 'rev-parse', 'HEAD'], { cwd: repo })).stdout;
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error('Invalid repository commit.');
  await command(['git', 'clone', '--quiet', '--no-hardlinks', repo, baseline]);
  await writeFile(path.join(context, 'incident.json'), JSON.stringify({ ...input.incident, repository: input.repository, commitSha: sha }, null, 2));
  await writeFile(path.join(context, 'events.json'), JSON.stringify(input.logs, null, 2));
  const prompt = `Read ${context}/incident.json and ${context}/events.json, investigate the suspected issue in ${repo}, and write ${output}/plan.json. ${verificationInstructions}`;
  await command(['pi', '-p', '--no-session', '--no-context-files', '--no-skills', '--no-extensions', '--no-mcp',
    '--no-approve', '--provider', 'openrouter', '--model', input.model, '--tools', 'read,grep,find,ls,edit,write', prompt],
  { cwd: repo, env: { OPENROUTER_API_KEY: input.openrouterKey, PI_CODING_AGENT_DIR: path.join(root, 'pi') }, timeout: 600000 });
  if (!(await lstat(path.join(output, 'plan.json'))).isFile()) throw new Error('Pi did not write a regular plan file.');
  const plan = validateSecurityPlan(JSON.parse(await readFile(path.join(output, 'plan.json'), 'utf8')));
  if (!plan.confirmed) {
    if ((await command(['git', 'status', '--porcelain'], { cwd: repo })).stdout) throw new Error('Pi changed the repository without a finding.');
    return { status: 'completed', commitSha: sha, summary: plan.summary };
  }
  await command(['git', 'add', '-N', '--all'], { cwd: repo });
  const patch = (await command(['git', 'diff', '--binary', '--no-ext-diff', 'HEAD'], { cwd: repo, maxOutput: MAX_OUTPUT })).stdout;
  if (!patch || patch.length > MAX_OUTPUT) throw new Error('Pi did not produce a reviewable patch.');
  const changed = (await command(['git', 'diff', '--name-only', 'HEAD'], { cwd: repo })).stdout.split('\n');
  if (!plan.testPaths.every(name => changed.includes(name)) || changed.every(name => plan.testPaths.includes(name))) {
    throw new Error('Pi must change source code and regression tests.');
  }
  const verification = await verifyPatch({ candidate: repo, baseline, plan, command: (directory, argv) => command(argv, { cwd: directory, allowFailure: true, maxOutput: 128000 }) });
  return { status: verification.verified ? 'verified' : 'verification_failed', commitSha: sha,
    summary: plan.summary, patch, verification };
}

let inputText = '';
for await (const chunk of process.stdin) {
  inputText += chunk.toString();
  if (inputText.length > 200000) throw new Error('Investigation input too large.');
}
let result;
try {
  result = await run(JSON.parse(inputText));
} catch (error) {
  result = { status: 'failed', error: String(error.message || error).slice(0, 1000) };
}
const output = JSON.stringify(result);
if (process.env.PURPLE_RESULT_PATH) await writeFile(process.env.PURPLE_RESULT_PATH, output, { mode: 0o600 });
else process.stdout.write(output);
