#!/usr/bin/env node
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { parse as parseToml } from 'smol-toml';
import { parse as parseJsonc, modify, applyEdits } from 'jsonc-parser';
import { collectDependencyMetadata } from './hosted-metadata.mjs';

export const OFFENSE_CLI_VERSION = '0.2.0';
export const OFFENSE_ENDPOINT = 'https://offense.sh';
const MAX_RESPONSE = 8_000_000, MAX_INPUT = 6_000_000;
const terminal = new Set(['completed', 'partial', 'failed']);
const jobStatuses = new Set(['queued', 'starting', 'running', ...terminal]);
const keyPattern = /^(?:offense_sk_[A-Za-z0-9_-]{32,128}|purple_scan_[a-f0-9]{64})$/;
const idPattern = /^[A-Za-z0-9_-]{8,100}$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const safeInteger = value => Number.isSafeInteger(value) && value >= 0;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const validJob = (value, id) => object(value) && /^[a-f0-9]{32}$/.test(value.id || '') &&
  (id === undefined || value.id === id) && jobStatuses.has(value.status);
class CliError extends Error {
  constructor(message, { code = 'cli_error', status, details } = {}) { super(message); this.code = code; this.status = status; this.details = details; }
}

export function serviceEndpoint(value) {
  let url;
  try { url = new URL(value); } catch { throw new CliError('Choose a valid HTTPS Offense endpoint.'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
    throw new CliError('The endpoint must be an HTTPS origin, or an explicit HTTP loopback origin.');
  }
  return url.origin;
}

export function dollarsToMicros(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,6})(?:\.\d{1,6})?$/.test(value)) throw new CliError('Use a nonnegative USD amount with at most six decimal places.');
  const [whole, fraction = ''] = value.split('.');
  const micros = Number(whole) * 1_000_000 + Number(fraction.padEnd(6, '0'));
  if (!Number.isSafeInteger(micros)) throw new CliError('The USD amount is too large.');
  return micros;
}

async function noSymlinks(destination) {
  const absolute = path.resolve(destination), parsed = path.parse(absolute);
  let current = parsed.root;
  for (const segment of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try { if ((await lstat(current)).isSymbolicLink()) throw new CliError('Refusing a symbolic link in the configuration path.'); }
    catch (error) { if (error.code === 'ENOENT') break; throw error; }
  }
}

function owned(info) { return typeof process.getuid !== 'function' || info.uid === process.getuid(); }
async function configDirectory(directory, { create = false, privateDirectory = true } = {}) {
  await noSymlinks(directory);
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 });
  let info;
  try { info = await lstat(directory); } catch (error) { if (error.code === 'ENOENT' && !create) return false; throw error; }
  // Project MCP files contain a command, never a credential. Shared project
  // groups remain supported; secret storage still requires owner-only access.
  if (!info.isDirectory() || !owned(info) || (info.mode & (privateDirectory ? 0o077 : 0o002))) {
    throw new CliError('Offense configuration must use an owned directory with private permissions.');
  }
  return true;
}

async function secureRead(filename, { privateFile = true } = {}) {
  await noSymlinks(filename);
  let handle;
  try {
    handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const info = await handle.stat();
    if (!info.isFile() || !owned(info) || (privateFile && (info.mode & 0o077)) || info.size > 2_000_000) {
      throw new CliError('Configuration must be an owned, bounded regular file with private permissions.');
    }
    return await handle.readFile('utf8');
  } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  finally { await handle?.close(); }
}

async function atomicWrite(filename, content, { privateDirectory = true, expected } = {}) {
  await configDirectory(path.dirname(filename), { create: true, privateDirectory });
  await noSymlinks(filename);
  if (expected !== undefined) {
    const actual = await secureRead(filename, { privateFile: privateDirectory });
    if (actual !== expected) throw new CliError('Configuration changed during setup; review it before retrying.');
  }
  const temporary = path.join(path.dirname(filename), `.offense-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    await handle.writeFile(content, 'utf8'); await handle.sync(); await handle.close(); handle = null;
    await noSymlinks(filename);
    await rename(temporary, filename);
  } finally { await handle?.close(); await rm(temporary, { force: true }); }
}

async function boundedJson(response) {
  if (Number(response.headers.get('content-length')) > MAX_RESPONSE) { await response.body?.cancel(); throw new CliError('Offense response exceeded the client limit.'); }
  const reader = response.body?.getReader();
  if (!reader) throw new CliError('Offense returned an empty response.');
  const chunks = []; let size = 0;
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength;
      if (size > MAX_RESPONSE) throw new CliError('Offense response exceeded the client limit.'); chunks.push(value); }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new CliError('Offense returned an invalid JSON response.'); }
}

function firstPartyUrl(value, endpoint, comparisonCode) {
  let url; try { url = new URL(value); } catch { throw new CliError('Offense returned an invalid sign-in address.'); }
  const comparisonFragment = url.pathname === '/device' && !url.search && /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(comparisonCode || '') && url.hash === '#code=' + comparisonCode;
  if (url.origin !== endpoint || url.username || url.password || (url.hash && !comparisonFragment) ||
      [...url.searchParams.keys()].some(key => /token|device_code|api.?key|secret/i.test(key))) throw new CliError('Offense returned an unsafe sign-in address.');
  return url.href;
}
function paymentUrl(value) {
  let url; try { url = new URL(value); } catch { throw new CliError('Offense returned an invalid payment address.'); }
  if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com', 'checkout.whop.com'].includes(url.hostname) || url.username || url.password) {
    throw new CliError('Only a secure Whop checkout address may be opened.');
  }
  return url.href;
}
async function defaultBrowser(url) {
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'rundll32.exe' : 'xdg-open';
  const args = process.platform === 'win32' ? ['url.dll,FileProtocolHandler', url] : [url];
  await new Promise(resolve => {
    try { const child = spawn(command, args, { detached: true, stdio: 'ignore', shell: false }); child.once('error', resolve); child.once('spawn', () => { child.unref(); resolve(); }); }
    catch { resolve(); }
  });
}

function argumentsFor(argv) {
  const positionals = [], flags = {};
  const boolean = new Set(['no-browser', 'wait', 'json', 'help', 'version', 'replace-offense']);
  const values = new Set(['endpoint', 'input', 'max-price', 'idempotency-key', 'client', 'project', 'output', 'plan-limit']);
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i];
    if (!word.startsWith('--')) { positionals.push(word); continue; }
    const name = word.slice(2);
    if (own(flags, name)) throw new CliError(`Duplicate option --${name}.`);
    if (boolean.has(name)) flags[name] = true;
    else if (values.has(name) && argv[i + 1] && !argv[i + 1].startsWith('--')) flags[name] = argv[++i];
    else throw new CliError('Unknown or incomplete CLI option. Run offense-hosted --help.');
  }
  return { positionals, flags };
}

export async function installProjectMcp({ client, project, endpoint = OFFENSE_ENDPOINT, cliPath = fileURLToPath(import.meta.url), nodePath = process.execPath, replaceOffense = false, configRoot }) {
  if (!['codex', 'claude', 'cursor'].includes(client)) throw new CliError('Choose --client codex, claude or cursor.');
  if (!project) throw new CliError('Choose an explicit --project directory.');
  if (configRoot !== undefined && (typeof configRoot !== 'string' || !path.isAbsolute(configRoot) || configRoot.includes('\0'))) {
    throw new CliError('Choose an absolute Offense credential directory.');
  }
  const root = await realpath(project), base = serviceEndpoint(endpoint);
  const command = nodePath, args = [path.resolve(cliPath), ...(base === OFFENSE_ENDPOINT ? [] : ['--endpoint', base]), 'mcp'];
  const credentialDirectory = configRoot === undefined ? undefined : path.resolve(configRoot);
  const childEnv = credentialDirectory === undefined ? undefined : { OFFENSE_CONFIG_DIR: credentialDirectory };
  const defaultDirectory = path.join(homedir(), '.config', 'offense');
  const equivalent = entry => {
    if (!object(entry) || entry.command !== command || JSON.stringify(entry.args) !== JSON.stringify(args) ||
        Object.keys(entry).some(key => !['command', 'args', 'env', 'type'].includes(key)) ||
        own(entry, 'type') && entry.type !== 'stdio') return false;
    if (entry.env === undefined || object(entry.env) && Object.keys(entry.env).length === 0) {
      return credentialDirectory === undefined || credentialDirectory === defaultDirectory;
    }
    return credentialDirectory !== undefined && object(entry.env) && Object.keys(entry.env).length === 1 &&
      entry.env.OFFENSE_CONFIG_DIR === credentialDirectory;
  };
  const filename = path.join(root, client === 'codex' ? '.codex/config.toml' : client === 'claude' ? '.mcp.json' : '.cursor/mcp.json');
  const before = await secureRead(filename, { privateFile: false });
  let next;
  if (client === 'codex') {
    let document; try { document = before ? parseToml(before) : {}; } catch { throw new CliError('Existing Codex configuration could not be parsed; it was preserved.'); }
    if (document.mcp_servers !== undefined && !object(document.mcp_servers)) throw new CliError('Existing Codex MCP configuration is customized; it was preserved.');
    const current = document.mcp_servers?.offense;
    if (current !== undefined && (!replaceOffense || equivalent(current))) return { changed: false, preserved: true, equivalent: equivalent(current), path: filename,
      next: equivalent(current) ? 'Reusing the existing Offense connection.' : 'Existing Offense configuration was preserved. Review it; use --replace-offense only to authorize replacing this entry with the authenticated CLI proxy.' };
    const section = '[mcp_servers.offense]\ncommand = ' + JSON.stringify(command) + '\nargs = ' + JSON.stringify(args) + '\n' +
      (childEnv ? '[mcp_servers.offense.env]\nOFFENSE_CONFIG_DIR = ' + JSON.stringify(credentialDirectory) + '\n' : '');
    if (current !== undefined) {
      const headers = [...before.matchAll(/^\s*\[([^\]\r\n]+)\][^\S\r\n]*(?:#[^\r\n]*)?$/gm)];
      const start = headers.findIndex(header => header[1] === 'mcp_servers.offense');
      if (start < 0) throw new CliError('The customized inline Offense table was preserved. Review it and migrate that entry manually.');
      const end = headers.slice(start + 1).find(header => !header[1].startsWith('mcp_servers.offense.'))?.index ?? before.length;
      next = before.slice(0, headers[start].index) + section + '\n' + before.slice(end);
    } else next = (before || '') + (before?.endsWith('\n') || !before ? '' : '\n') + '\n' + section;
  } else {
    const errors = [], document = before ? parseJsonc(before, errors, { allowTrailingComma: true }) : {};
    if (errors.length || !object(document) || document.mcpServers !== undefined && !object(document.mcpServers)) throw new CliError('Existing MCP configuration could not be parsed; it was preserved.');
    const current = document.mcpServers?.offense;
    if (current !== undefined && (!replaceOffense || equivalent(current))) return { changed: false, preserved: true, equivalent: equivalent(current), path: filename,
      next: equivalent(current) ? 'Reusing the existing Offense connection.' : 'Existing Offense configuration was preserved. Review it; use --replace-offense only to authorize replacing this entry with the authenticated CLI proxy.' };
    const text = before || '{}\n';
    next = applyEdits(text, modify(text, ['mcpServers', 'offense'], { command, args, ...(childEnv ? { env: childEnv } : {}) }, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
  }
  await atomicWrite(filename, next, { privateDirectory: false, expected: before });
  return { changed: true, scope: 'project', client, path: filename, restartRequired: true,
    next: 'Start a new agent session to load the Offense MCP tools. Existing sessions cannot load this configuration automatically.' };
}

export function createOffenseCli({ env = process.env, fetchImpl = fetch, output = value => process.stdout.write(value),
  diagnostic = value => process.stderr.write(value), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  now = Date.now, openBrowser = defaultBrowser, uuid = randomUUID, stdin = process.stdin,
  cliPath = fileURLToPath(import.meta.url), mcpProxy = runMcpProxy } = {}) {
  const knownSecrets = new Set();
  const configRoot = path.resolve(env.OFFENSE_CONFIG_DIR || path.join(env.XDG_CONFIG_HOME || path.join(homedir(), '.config'), 'offense'));
  const configFile = path.join(configRoot, 'config.json');
  const scrub = text => {
    let safe = String(text).replace(/(?:offense_sk_[A-Za-z0-9_-]{32,128}|purple_scan_[a-f0-9]{64})/g, '[REDACTED]');
    for (const secret of knownSecrets) if (secret) safe = safe.split(secret).join('[REDACTED]');
    return safe;
  };
  const print = value => output(scrub(JSON.stringify(value, null, 2)) + '\n');
  async function configuration() {
    if (!await configDirectory(configRoot)) return {};
    const contents = await secureRead(configFile);
    if (contents === null) return {};
    try { const cfg = JSON.parse(contents); if (!object(cfg)) throw Error(); return cfg; }
    catch { throw new CliError('Offense configuration is invalid; it was not replaced.'); }
  }
  async function credentials(endpoint, cfg) {
    const token = env.OFFENSE_API_KEY || env.PURPLE_SCAN_KEY || cfg.apiKey;
    if (!keyPattern.test(token || '')) throw new CliError('Sign in with offense-hosted login, or provide OFFENSE_API_KEY.', { code: 'login_required' });
    if (env.OFFENSE_API_KEY || env.PURPLE_SCAN_KEY) {
      const bound = serviceEndpoint(env.OFFENSE_API_URL || OFFENSE_ENDPOINT);
      const official = new Set([OFFENSE_ENDPOINT, 'https://app.purpleteam.sh']);
      if (endpoint !== bound && !(official.has(endpoint) && official.has(bound))) throw new CliError('The environment credential is bound to OFFENSE_API_URL. Configure that origin explicitly before using a self-hosted endpoint.', { code: 'endpoint_mismatch' });
    }
    if (!env.OFFENSE_API_KEY && !env.PURPLE_SCAN_KEY && (!cfg.endpoint || serviceEndpoint(cfg.endpoint) !== endpoint)) {
      throw new CliError('The saved credential belongs to another endpoint. Sign in to the selected endpoint first.', { code: 'endpoint_mismatch' });
    }
    knownSecrets.add(token); return token;
  }
  async function request(endpoint, route, { token, body, idempotencyKey, allowError = false } = {}) {
    if (token) knownSecrets.add(token);
    let response;
    try { response = await fetchImpl(new URL(route, endpoint).href, { method: body === undefined ? 'GET' : 'POST',
      headers: { accept: 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual', credentials: 'omit', signal: AbortSignal.timeout(60000) }); }
    catch { throw new CliError('Could not reach Offense. The request outcome is unknown; reuse the same idempotency key for a paid retry.', { code: 'network_error' }); }
    if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw new CliError('Offense redirects are not followed with credentials.', { code: 'redirect_refused' }); }
    const value = await boundedJson(response);
    if (!response.ok && !allowError) {
      const code = typeof value?.error === 'string' && /^[a-z_]{1,60}$/.test(value.error) ? value.error :
        typeof value?.error?.code === 'string' && /^[a-z_]{1,60}$/.test(value.error.code) ? value.error.code : 'request_failed';
      throw new CliError(`Offense returned HTTP ${response.status} (${code}).`, { status: response.status, code });
    }
    return { value, status: response.status, ok: response.ok };
  }
  async function inputFile(filename) {
    if (!filename) throw new CliError('Provide --input with an explicit JSON file, or - for stdin.');
    let content;
    if (filename === '-') {
      const parts = []; let size = 0;
      for await (const part of stdin) { const bytes = Buffer.from(part); size += bytes.length; if (size > MAX_INPUT) throw new CliError('Input exceeds the client limit.'); parts.push(bytes); }
      content = Buffer.concat(parts).toString('utf8');
    } else {
      const info = await lstat(filename); if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_INPUT) throw new CliError('Input must be an explicit bounded regular JSON file.');
      content = await readFile(filename, 'utf8');
    }
    let input; try { input = JSON.parse(content); } catch { throw new CliError('Input is not valid JSON.'); }
    if (!object(input) || own(input, 'maxChargeMicros')) throw new CliError('Input must be a JSON object without maxChargeMicros; authorize spending with --max-price.');
    if ([...knownSecrets].some(secret => content.includes(secret))) throw new CliError('Input contains the Offense credential; it was not uploaded.');
    return input;
  }
  function dimensions(input) {
    if (Array.isArray(input.files)) {
      if (!input.files.length || input.files.some(file => !object(file) || typeof file.path !== 'string' || typeof file.content !== 'string')) throw new CliError('Provide explicit file paths and text contents.');
      return { inputBytes: input.files.reduce((sum, file) => sum + Buffer.byteLength(file.content), 0), fileCount: input.files.length };
    }
    if (!safeInteger(input.inputBytes) || !Number.isSafeInteger(input.fileCount) || input.fileCount < 1) throw new CliError('Artifact or assessment requests require inputBytes and fileCount for the quote.');
    return { inputBytes: input.inputBytes, fileCount: input.fileCount };
  }
  async function login(endpoint, flags, cfg) {
    const environmentCredential = Boolean(env.OFFENSE_API_KEY || env.PURPLE_SCAN_KEY);
    if (environmentCredential || cfg.apiKey && cfg.endpoint && serviceEndpoint(cfg.endpoint) === endpoint) {
      const token = await credentials(endpoint, cfg);
      try {
        const { value: account } = await request(endpoint, '/v1/account', { token });
        if (!object(account) || !object(account.workspace) || typeof account.workspace.id !== 'string' || !account.workspace.id ||
            !object(account.key) || typeof account.key.id !== 'string' || !account.key.id) throw new CliError('Offense returned invalid account information; the existing credential was preserved.', { code: 'invalid_account_response' });
        print({ signedIn: true, endpoint, keyId: account.key.id, workspace: account.workspace,
          credentialSaved: !environmentCredential, credentialReused: true,
          next: 'Use offense-hosted tools, offense-hosted balance, or install MCP into this project.' });
        return;
      } catch (error) {
        if (environmentCredential && error instanceof CliError && error.status === 401) throw new CliError('The environment credential was rejected. Update or unset OFFENSE_API_KEY or PURPLE_SCAN_KEY before signing in.', { code: 'invalid_api_key', status: 401 });
        if (!(error instanceof CliError) || error.status !== 401) throw error;
      }
    }
    const { value: device } = await request(endpoint, '/v1/auth/device', { body: {} });
    if (!object(device) || typeof device.device_code !== 'string' || device.device_code.length < 32 ||
        typeof device.user_code !== 'string' || !/^[A-Z0-9-]{4,20}$/.test(device.user_code) ||
        !Number.isSafeInteger(device.expires_in) || device.expires_in < 1 || device.expires_in > 1800 ||
        !Number.isSafeInteger(device.interval) || device.interval < 1 || device.interval > 60) throw new CliError('Offense returned an invalid device sign-in response.');
    knownSecrets.add(device.device_code);
    const url = firstPartyUrl(device.verification_uri_complete || device.verification_uri, endpoint, device.user_code);
    diagnostic(`Sign in at ${url}\nConfirm this code: ${device.user_code}\n`);
    if (!flags['no-browser']) await openBrowser(url);
    const deadline = now() + device.expires_in * 1000;
    let interval = device.interval * 1000;
    while (now() < deadline) {
      await sleep(Math.min(interval, Math.max(0, deadline - now())));
      if (now() >= deadline) break;
      const result = await request(endpoint, '/v1/auth/device/token', { body: { device_code: device.device_code }, allowError: true });
      const token = result.value?.access_token;
      if (result.ok && keyPattern.test(token || '')) {
        knownSecrets.add(token);
        const saved = { ...cfg, endpoint, apiKey: token, keyId: result.value.key_id || null, workspace: result.value.workspace || null };
        await atomicWrite(configFile, JSON.stringify(saved, null, 2) + '\n');
        print({ signedIn: true, endpoint, keyId: saved.keyId, workspace: saved.workspace, credentialSaved: true,
          next: 'Use offense-hosted tools, offense-hosted balance, or install MCP into this project.' });
        return;
      }
      const code = typeof result.value?.error === 'string' ? result.value.error : result.value?.error?.code;
      if (code === 'authorization_pending') continue;
      if (code === 'slow_down') { interval = Math.min(interval + 5000, 60000); continue; }
      if (['expired_token', 'access_denied'].includes(code)) throw new CliError(code === 'access_denied' ? 'Sign-in was declined.' : 'Sign-in expired. Run offense-hosted login again.', { code });
      throw new CliError('Device sign-in did not return a valid credential.', { code: 'invalid_device_response' });
    }
    throw new CliError('Sign-in expired. Run offense-hosted login again.', { code: 'expired_token' });
  }
  async function run(argv = []) {
    try {
      const { positionals, flags } = argumentsFor(argv);
      if (flags.version) { print({ name: 'Offense', company: 'Offense Security', version: OFFENSE_CLI_VERSION }); return 0; }
      if (flags.help || positionals[0] === 'help') {
        print({ name: 'Offense', company: 'Offense Security', commands: ['audit [directory] [--output directory] [--plan-limit 0..10]', 'login [--no-browser]', 'logout', 'status', 'whoami', 'tools [list|show <tool>]', 'balance', 'topup', 'quote <tool> --input input.json', 'call <tool> --input input.json --max-price USD [--idempotency-key KEY] [--wait]', 'job <id>', 'mcp', 'mcp install --client codex|claude|cursor --project .'],
          options: ['--endpoint HTTPS_OR_LOOPBACK_ORIGIN', '--json'], credentials: 'OFFENSE_API_KEY or a private credential saved by offense-hosted login.' });
        return 0;
      }
      const cfg = await configuration(), endpoint = serviceEndpoint(flags.endpoint || env.OFFENSE_API_URL || cfg.endpoint || OFFENSE_ENDPOINT);
      const action = positionals[0] || 'status';
      if (action === 'audit') {
        if (positionals.length > 2 || flags['plan-limit'] !== undefined && !/^(?:[0-9]|10)$/.test(flags['plan-limit'])) throw new CliError('Use offense-hosted audit [directory] with --plan-limit from 0 to 10.');
        const planLimit = flags['plan-limit'] === undefined ? 3 : Number(flags['plan-limit']);
        const root = await realpath(positionals[1] || process.cwd());
        const metadata = await collectDependencyMetadata(root);
        const payload = { files: metadata.files, planLimit };
        const serialized = JSON.stringify(payload);
        for (const secret of [env.OFFENSE_API_KEY, env.PURPLE_SCAN_KEY, cfg.apiKey].filter(Boolean)) {
          knownSecrets.add(secret);
          if (serialized.includes(secret)) throw new CliError('Dependency metadata contains an Offense credential; it was not uploaded.');
        }
        const metadataFingerprint = createHash('sha256').update(JSON.stringify(metadata.files.slice().sort((a, b) => a.path.localeCompare(b.path)))).digest('hex');
        const { value: report } = await request(endpoint, '/api/offense/audit', { body: payload });
        if (!object(report) || report.schemaVersion !== 'offense.audit.v1' || report.capability !== 'audit_dependencies' ||
            !['complete', 'partial'].includes(report.status) || !object(report.coverage) || !safeInteger(report.coverage.checkedPackages) ||
            !Array.isArray(report.findings) || !object(report.summary) || report.summary.advisoryMatches !== report.findings.length ||
            report.summary.confirmedVulnerabilities !== 0 || !object(report.remediation) || !Array.isArray(report.remediation.plans) ||
            !Array.isArray(report.remediation.blockers) || report.coverage.planningOnly ||
            report.remediation.planning && report.remediation.planning.scope !== 'full_audit') {
          throw new CliError('Offense returned an incomplete audit report. No clean result was established.', { code: 'invalid_audit_report' });
        }
        if (report.metadataFingerprint !== metadataFingerprint) throw new CliError('The audit report does not match the dependency metadata sent. It was not saved.', { code: 'audit_fingerprint_mismatch' });
        let target = flags.output ? path.resolve(flags.output) : await mkdtemp(path.join(tmpdir(), 'offense-audit-'));
        if (target === root || target.startsWith(root + path.sep)) throw new CliError('Choose an audit report directory outside the source checkout.');
        await configDirectory(target, { create: true }); target = await realpath(target);
        if (target === root || target.startsWith(root + path.sep)) throw new CliError('Audit report output resolves inside the source checkout.');
        const partial = metadata.warnings.length > 0 || report.status === 'partial' || Boolean(report.remediation.planning?.hasMore);
        const saved = { ...report, status: partial ? 'partial' : 'complete', serverStatus: report.status,
          clientCoverage: { metadataFingerprint, inspectedLockfiles: metadata.inspectedLockfiles, warnings: metadata.warnings } };
        const jsonPath = path.join(target, 'audit.json'), promptPath = path.join(target, 'remediation.md');
        const notices = metadata.warnings.length ? '\n\nLocal coverage warnings:\n' + metadata.warnings.map(warning => '- ' + warning).join('\n') : '';
        const planning = report.remediation.planning?.hasMore ? '\n\nUpgrade planning remains incomplete. Retain this full audit and the recorded remediation.planning.next cursor when requesting continuation pages.' : '';
        await atomicWrite(jsonPath, JSON.stringify(saved, null, 2) + '\n');
        await atomicWrite(promptPath, String(report.remediation.agentPrompt || 'Review audit.json and its coverage, advisory matches and remediation blockers.') + notices + planning + '\n');
        print({ status: saved.status, serverStatus: report.status, advisoryMatches: report.findings.length,
          checkedPackages: report.coverage.checkedPackages, confirmedVulnerabilities: 0, localCoverageWarnings: metadata.warnings,
          upgradePlans: report.remediation.plans.length, blockers: report.remediation.blockers.length,
          json: jsonPath, prompt: promptPath, note: 'Known advisory matches are not confirmed vulnerabilities. No repository files were changed.' });
        return partial ? 2 : 0;
      }
      if (action === 'login') { await login(endpoint, flags, cfg); return 0; }
      if (action === 'logout') {
        await noSymlinks(configFile);
        if (await configDirectory(configRoot)) {
          const before = await secureRead(configFile);
          if (before !== null) { const { apiKey, keyId, workspace, ...rest } = cfg; await atomicWrite(configFile, JSON.stringify(rest, null, 2) + '\n', { expected: before }); }
        }
        print({ signedIn: false, localCredentialRemoved: true, environmentCredentialStillSet: Boolean(env.OFFENSE_API_KEY || env.PURPLE_SCAN_KEY),
          next: 'Server keys remain valid until revoked from your account. Environment credentials must be removed from their source.' }); return 0;
      }
      if (action === 'mcp' && positionals[1] === 'install') {
        const token = await credentials(endpoint, cfg);
        if ((env.OFFENSE_API_KEY || env.PURPLE_SCAN_KEY) &&
            (cfg.apiKey !== token || !cfg.endpoint || serviceEndpoint(cfg.endpoint) !== endpoint)) {
          throw new CliError('Project MCP setup needs the same credential saved by offense-hosted login. The active environment key would not survive a new client. Manage that key in your client environment intentionally, or unset the environment override and run offense-hosted login before installing MCP. No settings were changed.', { code: 'mcp_persistent_login_required' });
        }
        const installed = await installProjectMcp({ client: flags.client, project: flags.project, endpoint, cliPath, replaceOffense: flags['replace-offense'] === true, configRoot });
        print(installed); return installed.equivalent === false ? 2 : 0;
      }
      if (action === 'status' && !env.OFFENSE_API_KEY && !env.PURPLE_SCAN_KEY && !cfg.apiKey) {
        print({ product: 'Offense', company: 'Offense Security', endpoint, signedIn: false, next: 'Run offense-hosted login to connect this agent.' }); return 0;
      }
      const token = await credentials(endpoint, cfg);
      const api = async (route, options) => (await request(endpoint, route, { token, ...options })).value;
      if (action === 'status' || action === 'whoami') {
        const account = await api('/v1/account');
        print({ endpoint, signedIn: true, keyFingerprint: createHash('sha256').update(token).digest('hex').slice(0, 12), account }); return 0;
      }
      if (action === 'tools') {
        const tools = await api('/v1/tools');
        if (positionals[1] === 'show') {
          const selected = tools.tools?.find(tool => tool.id === positionals[2]);
          if (!selected) throw new CliError('Tool not found. Run offense-hosted tools.'); print(selected);
        } else if (!positionals[1] || positionals[1] === 'list') print(tools);
        else throw new CliError('Use offense-hosted tools list or offense-hosted tools show <tool>.');
        return 0;
      }
      if (action === 'balance') { print(await api('/v1/usage')); return 0; }
      if (action === 'topup') {
        const checkout = await api('/v1/billing/topups', { body: {} });
        const url = paymentUrl(checkout.url);
        print({ ...checkout, url, paymentRequired: true, next: 'Complete payment on Whop. The balance changes only after verified payment confirmation.' });
        if (!flags['no-browser']) await openBrowser(url); return 0;
      }
      if (action === 'job') {
        if (!/^[a-f0-9]{32}$/.test(positionals[1] || '')) throw new CliError('Provide a valid Offense job ID.');
        const job = await api(`/v1/scans/${positionals[1]}`);
        if (!validJob(job, positionals[1])) throw new CliError('Offense returned an invalid job response.', { code: 'invalid_receipt' });
        print(job); return job.status === 'failed' || job.status === 'partial' ? 2 : 0;
      }
      if (action === 'quote' || action === 'call') {
        const tool = positionals[1];
        if (!/^[a-z][a-z0-9-]{0,60}$/.test(tool || '')) throw new CliError('Choose a tool ID from offense-hosted tools.');
        const input = await inputFile(flags.input);
        if (input.tools !== undefined && (!Array.isArray(input.tools) || input.tools.length !== 1 || input.tools[0] !== tool)) throw new CliError('The input must match the one selected tool.');
        const sizes = dimensions(input);
        const quote = await api('/v1/quotes', { body: { tools: [tool], ...sizes } });
        if (!object(quote) || typeof quote.billable !== 'boolean' || quote.currency !== 'usd' || !safeInteger(quote.maximumMicros) ||
            quote.inputBytes !== sizes.inputBytes || quote.fileCount !== sizes.fileCount ||
            !Array.isArray(quote.toolIds) || quote.toolIds.length !== 1 || quote.toolIds[0] !== tool || !quote.billable && quote.maximumMicros !== 0) {
          throw new CliError('Offense returned an invalid price quote. No paid call was submitted.');
        }
        if (action === 'quote') { print(quote); return 0; }
        if (quote.billable && flags['max-price'] === undefined) throw new CliError('Paid calls require --max-price USD. Obtain the price with offense-hosted quote.', { code: 'budget_required' });
        const maximum = flags['max-price'] === undefined ? 0 : dollarsToMicros(flags['max-price']);
        if (quote.maximumMicros > maximum) throw new CliError('The quote exceeds --max-price. No paid call was submitted.', { code: 'budget_exceeded' });
        const idempotencyKey = flags['idempotency-key'] || uuid();
        if (!idPattern.test(idempotencyKey)) throw new CliError('Use an idempotency key with 8–100 letters, digits, underscores or hyphens.');
        diagnostic(scrub(JSON.stringify({ quote, idempotencyKey, note: 'Reuse this idempotency key and exact input if the submission outcome is uncertain.' })) + '\n');
        const { inputBytes, fileCount, ...body } = input;
        let job = await api('/v1/scans', { body: { ...body, tools: [tool], maxChargeMicros: quote.maximumMicros }, idempotencyKey });
        if (!validJob(job)) throw new CliError('Offense returned an invalid submission receipt; preserve its idempotency key.', { code: 'invalid_receipt' });
        const deadline = now() + 15 * 60_000;
        while (flags.wait && !terminal.has(job.status) && now() < deadline) {
          await sleep(Math.min(5000, Math.max(0, deadline - now())));
          if (now() >= deadline) break;
          const next = await api(`/v1/scans/${job.id}`);
          if (!validJob(next, job.id)) throw new CliError('Offense returned an invalid job response.', { code: 'invalid_receipt' }); job = next;
        }
        const waitTimedOut = flags.wait === true && !terminal.has(job.status);
        print({ ...job, idempotencyKey, quoteMaximumMicros: quote.maximumMicros,
          ...(waitTimedOut ? { waitTimedOut: true } : {}),
          ...(!terminal.has(job.status) ? { next: `offense-hosted job ${job.id}` } : {}) });
        return waitTimedOut || job.status === 'failed' || job.status === 'partial' ? 2 : 0;
      }
      if (action === 'mcp' && !positionals[1]) { await mcpProxy({ endpoint, token, scrub, diagnostic }); return 0; }
      throw new CliError('Unknown Offense command. Run offense-hosted --help.');
    } catch (error) {
      diagnostic(scrub(JSON.stringify({ error: { code: error instanceof CliError ? error.code : 'cli_error',
        message: error instanceof CliError ? error.message : 'The command could not complete; configuration and credentials were not printed.',
        ...(error instanceof CliError && error.status ? { status: error.status } : {}) } })) + '\n');
      return 1;
    }
  }
  return { run };
}

export async function runMcpProxy({ endpoint, token, scrub = text => text, diagnostic = text => process.stderr.write(text) }) {
  const [{ Client }, { StreamableHTTPClientTransport }, { Server }, { StdioServerTransport }, { ListToolsRequestSchema, CallToolRequestSchema }] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'), import('@modelcontextprotocol/sdk/client/streamableHttp.js'),
    import('@modelcontextprotocol/sdk/server/index.js'), import('@modelcontextprotocol/sdk/server/stdio.js'), import('@modelcontextprotocol/sdk/types.js')
  ]);
  const upstream = new Client({ name: 'offense-cli', version: OFFENSE_CLI_VERSION });
  const transport = new StreamableHTTPClientTransport(new URL('/mcp', serviceEndpoint(endpoint)), {
    requestInit: { headers: { authorization: `Bearer ${token}` } }, fetch: (input, options) => fetch(input, { ...options, redirect: 'manual' })
  });
  await upstream.connect(transport);
  const local = new Server({ name: 'offense', version: OFFENSE_CLI_VERSION }, { capabilities: { tools: {} } });
  const safeResult = value => JSON.parse(scrub(JSON.stringify(value)).split(token).join('[REDACTED]'));
  const relay = async action => {
    try { return safeResult(await action()); }
    catch (error) { throw new Error(scrub(String(error?.message || 'Offense MCP request could not complete.')).split(token).join('[REDACTED]')); }
  };
  local.setRequestHandler(ListToolsRequestSchema, request => relay(() => upstream.listTools(request.params)));
  local.setRequestHandler(CallToolRequestSchema, request => relay(() => upstream.callTool(request.params)));
  let closing = false;
  const close = async () => { if (closing) return; closing = true; await Promise.allSettled([local.close(), upstream.close()]); };
  local.onerror = () => diagnostic(scrub('Offense MCP transport error.\n'));
  local.onclose = () => { void close(); };
  await local.connect(new StdioServerTransport());
  process.once('SIGINT', close); process.once('SIGTERM', close);
}

