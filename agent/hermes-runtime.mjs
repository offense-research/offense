import { spawn } from 'node:child_process';
import { mkdtemp, realpath, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERMES_REVISION = '27c61463814f27ada4c2d5625a8839ed51f01f41';
const script = fileURLToPath(new URL('./hermes-task.py', import.meta.url));
const inside = (parent, child) => child === parent || child.startsWith(parent + path.sep);
const maxJson = 512 * 1024;

function trustedProxyEnvironment() {
  const env = {};
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY']) {
    if (!process.env[name]) continue;
    const url = new URL(process.env[name]);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new Error('The Hermes controller proxy must use an HTTP URL without credentials.');
    }
    env[name] = url.href;
  }
  if (process.env.NO_PROXY) env.NO_PROXY = process.env.NO_PROXY.slice(0, 2000);
  return env;
}

function redact(value, secret) {
  if (typeof value === 'string') return value.replaceAll(secret, '[REDACTED]');
  if (Array.isArray(value)) return value.map(item => redact(item, secret));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key.replaceAll(secret, '[REDACTED]'), redact(item, secret)]));
  return value;
}

function validateEndpoint(endpoint) {
  const url = new URL(endpoint || 'https://openrouter.ai/api/v1');
  if (url.username || url.password || url.search || url.hash || (url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)))) {
    throw new Error('Hermes model endpoint requires HTTPS (HTTP is allowed only for a local test endpoint).');
  }
  return url.href.replace(/\/$/, '');
}

async function invoke(payload, { python, hermesPath, timeoutMs = 600_000, signal, spawnImpl = spawn, allowUnpinnedForTest = false } = {}) {
  hermesPath ||= process.env.PURPLE_HERMES_PATH || '/opt/hermes';
  python ||= process.env.PURPLE_HERMES_PYTHON || path.join(hermesPath, '.venv/bin/python');
  if (!existsSync(path.join(hermesPath, 'run_agent.py')) && spawnImpl === spawn) throw new Error('Hermes is not installed in the configured runtime. Build the dedicated Hermes image first.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 900_000) throw new Error('Hermes timeout must be between 100 and 900000 ms.');
  if (signal?.aborted) throw new Error('Hermes task was canceled.');
  const home = await mkdtemp(path.join(tmpdir(), 'purple-hermes-home-'));
  try {
    const input = JSON.stringify({ protocolVersion: 1, ...payload, hermesPath, revision: HERMES_REVISION, allowUnpinnedForTest });
    if (Buffer.byteLength(input) > maxJson) throw new Error('Hermes task input exceeds 512 KiB.');
    const result = await new Promise((resolve, reject) => {
      // No app, GitHub, Infisical, shell-preload or personal Hermes credentials
      // are inherited. The model credential is sent over stdin, never argv.
      const env = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, HERMES_HOME: home,
        PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1', NO_COLOR: '1',
        HERMES_TELEMETRY_DISABLED: '1', HF_HUB_DISABLE_TELEMETRY: '1', ...trustedProxyEnvironment() };
      const child = spawnImpl(python, ['-I', '-B', script], { cwd: home, env, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      let output = '', bytes = 0, stderrBytes = 0, stopped = false;
      const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill?.('SIGKILL'); } };
      const stop = message => { if (stopped) return; stopped = true; kill(); reject(new Error(message)); };
      const timer = setTimeout(() => stop('Hermes task exceeded its time budget.'), timeoutMs);
      const cancel = () => stop('Hermes task was canceled.');
      signal?.addEventListener('abort', cancel, { once: true });
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', cancel); };
      child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > maxJson) stop('Hermes returned excessive output.'); else output += chunk.toString(); });
      child.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes > 128 * 1024) stop('Hermes emitted excessive diagnostic output.'); });
      child.on('error', () => { cleanup(); stop('Hermes Python runtime could not be started.'); });
      child.on('close', code => {
        cleanup(); kill(); if (stopped) return;
        if (code !== 0) return reject(new Error('Hermes runtime failed. No untrusted diagnostic text was included.'));
        try {
          const value = JSON.parse(output);
          if (value.protocolVersion !== 1 || value.runtime?.name !== 'hermes' || !['completed', 'blocked', 'ready'].includes(value.status)) throw new Error();
          resolve(payload.apiKey ? redact(value, payload.apiKey) : value);
        } catch { reject(new Error('Hermes returned an invalid runtime result.')); }
      });
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    });
    return result;
  } finally { await rm(home, { recursive: true, force: true }); }
}

export async function preflightHermes(options = {}) {
  return invoke({ preflight: true }, { ...options, timeoutMs: options.timeoutMs || 60_000 });
}

export async function runHermesTask({ candidateDirectory, outputDirectory, task, feedback = null, model, apiKey,
  endpoint, maxTurns = 12, timeoutMs = 600_000, signal } = {}, options = {}) {
  const candidate = await realpath(candidateDirectory), output = await realpath(outputDirectory);
  if (!(await stat(candidate)).isDirectory() || !(await stat(output)).isDirectory() || inside(candidate, output) || inside(output, candidate)) {
    throw new Error('Hermes requires separate candidate and output directories.');
  }
  if (typeof task !== 'object' || !task || Array.isArray(task)) throw new Error('Hermes requires structured dependency-fix evidence.');
  if (!/^[A-Za-z0-9/_.:-]{1,150}$/.test(model || '')) throw new Error('Configure an explicit Hermes model.');
  if (typeof apiKey !== 'string' || apiKey.length < 8 || apiKey.length > 1000) throw new Error('Configure a model key for Hermes.');
  if (!Number.isInteger(maxTurns) || maxTurns < 1 || maxTurns > 24) throw new Error('Hermes turn budget must be between 1 and 24.');
  return invoke({ candidateDirectory: candidate, outputDirectory: output, task, feedback, model, apiKey,
    endpoint: validateEndpoint(endpoint), maxTurns }, { ...options, timeoutMs, signal });
}
