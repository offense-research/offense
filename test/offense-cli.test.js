import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, mkdir, chmod, lstat, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { parse as parseToml } from 'smol-toml';
import { parse as parseJsonc } from 'jsonc-parser';
import { createOffenseCli, dollarsToMicros, installProjectMcp, serviceEndpoint } from '../scripts/offense-cli.mjs';

const TOKEN = 'offense_sk_' + 'a'.repeat(64), OLD_TOKEN = 'purple_scan_' + 'b'.repeat(64);
const DEVICE = 'd'.repeat(64), JOB = 'c'.repeat(32);
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
async function fixture(t, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-cli-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = path.join(directory, 'config.json'), stdout = [], stderr = [], calls = [], opened = [];
  let clock = 0;
  const handler = options.handler || (() => json({}));
  const cli = createOffenseCli({ env: { OFFENSE_CONFIG_DIR: directory, ...options.env },
    fetchImpl: async (url, request) => { calls.push({ url, ...request }); return handler(new URL(url), request, calls.length); },
    output: text => stdout.push(text), diagnostic: text => stderr.push(text), openBrowser: async url => opened.push(url),
    sleep: async ms => { clock += ms; }, now: () => clock,
    uuid: () => 'test-request-0001', cliPath: '/installed/offense-cli.mjs', ...options.overrides });
  const save = async (value = {}) => writeFile(config, JSON.stringify({ endpoint: 'https://offense.sh', apiKey: TOKEN, ...value }), { mode: 0o600 });
  return { directory, config, cli, stdout, stderr, calls, opened, save, out: () => JSON.parse(stdout.at(-1)), err: () => JSON.parse(stderr.at(-1)) };
}

test('canonical endpoints and USD ceilings reject credentials, remote plaintext and ambiguous amounts', () => {
  assert.equal(serviceEndpoint('https://offense.sh/'), 'https://offense.sh');
  assert.equal(serviceEndpoint('http://127.0.0.1:4211'), 'http://127.0.0.1:4211');
  for (const value of ['http://offense.sh', 'https://u:p@offense.sh', 'https://offense.sh/path', 'https://offense.sh?token=secret', 'https://offense.sh/#x']) assert.throws(() => serviceEndpoint(value));
  assert.equal(dollarsToMicros('0.000001'), 1); assert.equal(dollarsToMicros('10.25'), 10_250_000);
  for (const value of ['1e3', '-1', '0.0000001', 'NaN', '01', '', '.1']) assert.throws(() => dollarsToMicros(value));
});

test('fresh CLI home is useful to agents without fetching or creating credentials', async t => {
  const f = await fixture(t);
  assert.equal(await f.cli.run([]), 0);
  assert.equal(f.out().product, 'Offense'); assert.equal(f.out().signedIn, false);
  assert.equal(f.calls.length, 0);
  assert.equal(await f.cli.run(['--version']), 0); assert.equal(f.out().company, 'Offense Security');
});

test('device login honors pending and slowdown, privately saves once, and never prints secrets', async t => {
  let polls = 0;
  const f = await fixture(t, { handler: (url, request) => {
    if (url.pathname === '/v1/account') return json({ error: { code: 'invalid_api_key' } }, 401);
    if (url.pathname === '/v1/auth/device') return json({ device_code: DEVICE, user_code: 'ABCD-EFGH',
      verification_uri_complete: 'https://offense.sh/device#code=ABCD-EFGH', expires_in: 300, interval: 1 });
    assert.equal(url.pathname, '/v1/auth/device/token'); assert.deepEqual(JSON.parse(request.body), { device_code: DEVICE });
    assert.equal(request.headers.authorization, undefined);
    if (++polls === 1) return json({ error: 'authorization_pending' }, 400);
    if (polls === 2) return json({ error: 'slow_down' }, 400);
    return json({ access_token: TOKEN, key_id: 'key-1', workspace: { id: 'workspace-1', name: 'Personal' } });
  } });
  await f.save({ theme: 'custom', apiKey: OLD_TOKEN });
  assert.equal(await f.cli.run(['login', '--no-browser']), 0);
  assert.equal(polls, 3); assert.equal(f.opened.length, 0);
  const saved = JSON.parse(await readFile(f.config, 'utf8'));
  assert.equal(saved.apiKey, TOKEN); assert.equal(saved.theme, 'custom'); assert.equal(saved.endpoint, 'https://offense.sh');
  assert.equal((await lstat(f.directory)).mode & 0o077, 0); assert.equal((await lstat(f.config)).mode & 0o077, 0);
  assert.equal(f.out().signedIn, true); assert.equal(f.out().keyId, 'key-1');
  assert.ok(f.stderr.join('').includes('ABCD-EFGH'));
  for (const secret of [DEVICE, TOKEN, OLD_TOKEN]) assert.ok(!(f.stdout.join('') + f.stderr.join('')).includes(secret));
});

test('declined or expired device login preserves existing credential', async t => {
  for (const errorCode of ['access_denied', 'expired_token']) {
    const f = await fixture(t, { handler: url => {
      if (url.pathname === '/v1/account') return json({ error: { code: 'invalid_api_key' } }, 401);
      return url.pathname === '/v1/auth/device' ? json({ device_code: DEVICE, user_code: 'ABCD',
        verification_uri: 'https://offense.sh/device', expires_in: 20, interval: 1 }) : json({ error: errorCode }, 400);
    } });
    await f.save();
    assert.equal(await f.cli.run(['login', '--no-browser']), 1); assert.equal(f.err().error.code, errorCode);
    assert.equal(JSON.parse(await readFile(f.config, 'utf8')).apiKey, TOKEN);
  }
});

test('login reuses a valid saved credential and workspace without issuing another key or rewriting settings', async t => {
  const account = { workspace: { id: 'existing-workspace', name: 'Existing account' }, key: { id: 'existing-key' } };
  const f = await fixture(t, { handler: (url, request) => {
    assert.equal(url.pathname, '/v1/account'); assert.equal(request.method, 'GET');
    assert.equal(request.headers.authorization, `Bearer ${TOKEN}`); return json(account);
  } });
  await f.save({ theme: 'custom', workspace: account.workspace }); const before = await readFile(f.config, 'utf8');
  for (let i = 0; i < 2; i++) {
    assert.equal(await f.cli.run(['login']), 0); assert.equal(f.out().credentialReused, true);
    assert.equal(f.out().credentialSaved, true); assert.deepEqual(f.out().workspace, account.workspace);
    assert.equal(f.out().keyId, account.key.id);
  }
  assert.equal(f.calls.length, 2); assert.equal(f.opened.length, 0);
  assert.equal(await readFile(f.config, 'utf8'), before); assert.ok(!f.stdout.join('').includes(TOKEN));
});

test('login validates environment credentials without persisting them or creating an unusable device grant', async t => {
  for (const valid of [true, false]) {
    const f = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN }, handler: (url, request) => {
      assert.equal(url.pathname, '/v1/account'); assert.equal(request.headers.authorization, `Bearer ${TOKEN}`);
      return valid ? json({ workspace: { id: 'env-workspace' }, key: { id: 'env-key' } }) : json({ error: { code: 'invalid_api_key' } }, 401);
    } });
    await f.save({ apiKey: OLD_TOKEN }); const before = await readFile(f.config, 'utf8');
    assert.equal(await f.cli.run(['login']), valid ? 0 : 1);
    if (valid) { assert.equal(f.out().credentialReused, true); assert.equal(f.out().credentialSaved, false); }
    else { assert.equal(f.err().error.code, 'invalid_api_key'); assert.match(f.err().error.message, /Update or unset/); }
    assert.equal(f.calls.length, 1); assert.equal(f.opened.length, 0); assert.equal(await readFile(f.config, 'utf8'), before);
  }
});

test('login account check failures preserve the saved credential without starting device authorization', async t => {
  for (const response of ['network', 'server', 'invalid']) {
    const f = await fixture(t, { handler: url => {
      assert.equal(url.pathname, '/v1/account');
      if (response === 'network') throw Error('network failed');
      return response === 'server' ? json({ error: { code: 'account_unavailable' } }, 503) : json({});
    } });
    await f.save(); const before = await readFile(f.config, 'utf8');
    assert.equal(await f.cli.run(['login']), 1); assert.equal(f.calls.length, 1); assert.equal(f.opened.length, 0);
    assert.equal(await readFile(f.config, 'utf8'), before);
  }
});

test('login to another explicit endpoint never forwards the old credential and preserves it until approved', async t => {
  const endpoint = 'https://selfhost.example';
  const f = await fixture(t, { handler: (url, request) => {
    assert.equal(url.origin, endpoint); assert.equal(request.headers.authorization, undefined);
    if (url.pathname === '/v1/auth/device') return json({ device_code: DEVICE, user_code: 'ABCD',
      verification_uri: `${endpoint}/device`, expires_in: 20, interval: 1 });
    assert.equal(url.pathname, '/v1/auth/device/token'); return json({ error: 'access_denied' }, 400);
  } });
  await f.save(); const before = await readFile(f.config, 'utf8');
  assert.equal(await f.cli.run(['login', '--endpoint', endpoint, '--no-browser']), 1);
  assert.equal(f.err().error.code, 'access_denied'); assert.equal(f.calls.length, 2);
  assert.equal(await readFile(f.config, 'utf8'), before);
});

test('device sign-in rejects foreign approval pages and credentials carried in URLs', async t => {
  for (const url of ['https://elsewhere.test/device', 'https://offense.sh/device?device_code='+DEVICE, 'https://offense.sh/device#token='+TOKEN, 'https://offense.sh/device#code=ABCD-EFGH']) {
    const f = await fixture(t, { handler: () => json({ device_code: DEVICE, user_code: 'ABCD',
      verification_uri_complete: url, expires_in: 20, interval: 1 }) });
    assert.equal(await f.cli.run(['login']), 1); assert.equal(f.opened.length, 0); assert.equal(f.calls.length, 1);
    assert.ok(!f.stderr.join('').includes(DEVICE));
  }
});

test('saved credentials are endpoint-bound and environment keys are never persisted or printed', async t => {
  const f = await fixture(t); await f.save();
  assert.equal(await f.cli.run(['--endpoint', 'https://different.test', 'whoami']), 1);
  assert.equal(f.calls.length, 0); assert.equal(f.err().error.code, 'endpoint_mismatch');
  const g = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN }, handler: (_url, request) => {
    assert.equal(request.headers.authorization, `Bearer ${TOKEN}`); return json({ user: { login: 'example' }, accidentallyEchoed: TOKEN });
  } });
  assert.equal(await g.cli.run(['whoami']), 0); assert.equal(g.out().signedIn, true);
  assert.ok(!g.stdout.join('').includes(TOKEN));
  await assert.rejects(readFile(g.config), { code: 'ENOENT' });
});

test('legacy Purple scanner keys remain accepted without changing the saved secret', async t => {
  const f = await fixture(t, { handler: () => json({ balanceMicros: 100 }) });
  await f.save({ apiKey: OLD_TOKEN }); assert.equal(await f.cli.run(['balance']), 0);
  assert.equal(f.calls[0].headers.authorization, `Bearer ${OLD_TOKEN}`);
  assert.equal(JSON.parse(await readFile(f.config, 'utf8')).apiKey, OLD_TOKEN);
});

test('insecure directories, credential symlinks and symlinked configuration parents are refused', async t => {
  const f = await fixture(t); await f.save(); await chmod(f.config, 0o644);
  assert.equal(await f.cli.run(['whoami']), 1); assert.equal(f.calls.length, 0);
  await chmod(f.config, 0o600); await chmod(f.directory, 0o755);
  assert.equal(await f.cli.run(['whoami']), 1); assert.equal(f.calls.length, 0);
  await chmod(f.directory, 0o700); await rm(f.config); const target = path.join(f.directory, 'private.json');
  await writeFile(target, JSON.stringify({ apiKey: TOKEN }), { mode: 0o600 }); await symlink(target, f.config);
  assert.equal(await f.cli.run(['whoami']), 1); assert.equal(f.calls.length, 0);
  const alias = f.directory + '-link'; await symlink(f.directory, alias); t.after(() => rm(alias, { force: true }));
  const g = createOffenseCli({ env: { OFFENSE_CONFIG_DIR: alias }, output() {}, diagnostic() {}, fetchImpl: () => { throw Error('must not fetch'); } });
  assert.equal(await g.run(['status']), 1);
});

test('logout removes only local credentials and explains server revocation separately', async t => {
  const f = await fixture(t); await f.save({ preference: 'keep' });
  assert.equal(await f.cli.run(['logout']), 0);
  const cfg = JSON.parse(await readFile(f.config, 'utf8')); assert.equal(cfg.apiKey, undefined); assert.equal(cfg.preference, 'keep');
  assert.equal(cfg.endpoint, 'https://offense.sh'); assert.equal(f.calls.length, 0);
  assert.equal(f.out().localCredentialRemoved, true); assert.match(f.out().next, /remain valid until revoked/);
});

test('Whop top-up creates a checkout only, never credits funds or automatically charges', async t => {
  const f = await fixture(t, { handler: (url, request) => { assert.equal(url.pathname, '/v1/billing/topups');
    assert.deepEqual(JSON.parse(request.body), {}); return json({ url: 'https://whop.com/checkout/test', orderId: 'order-1' }); } });
  await f.save(); assert.equal(await f.cli.run(['topup', '--no-browser']), 0);
  assert.equal(f.out().paymentRequired, true); assert.equal(f.opened.length, 0); assert.equal(f.calls.length, 1);
  const g = await fixture(t, { handler: () => json({ url: 'https://evil.test/pay' }) });
  await g.save(); assert.equal(await g.cli.run(['topup']), 1); assert.equal(g.opened.length, 0);
});

async function scanFixture(t, { price = 10_000, handler, jobStatus = 'queued', overrides } = {}) {
  const f = await fixture(t, { handler: (url, request) => {
    if (url.pathname === '/v1/quotes') return json({ billable: true, currency: 'usd', maximumMicros: price, toolIds: ['gitleaks'], inputBytes: 5, fileCount: 1 });
    return handler ? handler(url, request) : json({ id: JOB, status: jobStatus });
  }, overrides });
  await f.save(); const input = path.join(f.directory, 'scan-input.json');
  await writeFile(input, JSON.stringify({ files: [{ path: 'app.js', content: 'hello' }] }));
  return { ...f, input };
}

test('paid calls require an explicit ceiling and never submit a quote over budget', async t => {
  const f = await scanFixture(t);
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input]), 1);
  assert.equal(f.err().error.code, 'budget_required'); assert.equal(f.calls.length, 1);
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.009']), 1);
  assert.equal(f.err().error.code, 'budget_exceeded'); assert.equal(f.calls.length, 2);
  assert.equal(f.calls.filter(call => new URL(call.url).pathname === '/v1/scans').length, 0);
});

test('paid call uses the quoted exact charge and stable receipt key without mutation retries', async t => {
  const f = await scanFixture(t);
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.02', '--idempotency-key', 'stable-call-001']), 0);
  const quote = JSON.parse(f.calls[0].body), submit = f.calls[1];
  assert.deepEqual(quote, { tools: ['gitleaks'], inputBytes: 5, fileCount: 1 });
  assert.equal(JSON.parse(submit.body).maxChargeMicros, 10_000); assert.equal(submit.headers['idempotency-key'], 'stable-call-001');
  assert.equal(submit.redirect, 'manual'); assert.equal(f.out().idempotencyKey, 'stable-call-001');
  assert.equal(f.calls.length, 2); assert.equal(f.out().id, JOB);
  assert.ok(!f.stderr.join('').includes(TOKEN));
});

test('uncertain paid submission preserves the idempotency recovery key and does not retry', async t => {
  const f = await scanFixture(t, { handler: () => { throw Error('network response lost'); } });
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.02']), 1);
  assert.equal(f.calls.length, 2); assert.equal(f.err().error.code, 'network_error');
  assert.ok(f.stderr.join('').includes('test-request-0001')); assert.ok(f.stderr.join('').includes('reuse the same idempotency key'));
});

test('waiting polls only the returned job and preserves partial/failure evidence in exit status', async t => {
  let polls = 0;
  const f = await scanFixture(t, { handler: (url, request) => {
    if (url.pathname === '/v1/scans') return json({ id: JOB, status: 'queued' });
    assert.equal(request.method, 'GET'); assert.equal(url.pathname, `/v1/scans/${JOB}`);
    return json({ id: JOB, status: ++polls === 1 ? 'running' : 'partial', findings: [] });
  } });
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.02', '--wait']), 2);
  assert.equal(polls, 2); assert.equal(f.out().status, 'partial');
  assert.equal(f.calls.filter(c => c.method === 'POST' && new URL(c.url).pathname === '/v1/scans').length, 1);
});

test('wait deadline returns an explicit incomplete receipt and never submits the job again', async t => {
  let clock = 0, polls = 0;
  const f = await scanFixture(t, { overrides: { now: () => clock, sleep: async ms => { clock += ms; } },
    handler: (url, request) => {
      if (url.pathname === '/v1/scans') return json({ id: JOB, status: 'queued' });
      assert.equal(request.method, 'GET'); assert.equal(url.pathname, `/v1/scans/${JOB}`);
      assert.ok(clock < 15 * 60_000); polls++;
      return json({ id: JOB, status: 'running' });
    } });
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.02', '--idempotency-key', 'stable-wait-001', '--wait']), 2);
  assert.equal(clock, 15 * 60_000); assert.equal(polls, 179);
  assert.equal(f.out().status, 'running'); assert.equal(f.out().waitTimedOut, true);
  assert.equal(f.out().id, JOB); assert.equal(f.out().idempotencyKey, 'stable-wait-001');
  assert.equal(f.out().next, `offense job ${JOB}`);
  assert.equal(f.calls.filter(call => call.method === 'POST' && new URL(call.url).pathname === '/v1/scans').length, 1);
});

test('job receipts preserve terminal evidence and use unsuccessful exit codes for failed or partial scans', async t => {
  for (const status of ['queued', 'starting', 'running', 'completed', 'partial', 'failed']) {
    const receipt = { id: JOB, status, findings: [{ ruleId: 'fixture-rule' }],
      metering: { state: status === 'failed' ? 'released' : 'settled', chargeMicros: status === 'failed' ? 0 : 10_000, currency: 'usd' } };
    const f = await fixture(t, { handler: (url, request) => {
      assert.equal(url.pathname, `/v1/scans/${JOB}`); assert.equal(request.method, 'GET'); return json(receipt);
    } });
    await f.save();
    assert.equal(await f.cli.run(['job', JOB]), ['partial', 'failed'].includes(status) ? 2 : 0);
    assert.deepEqual(f.out(), receipt); assert.equal(f.calls.length, 1);
  }
});

test('unrecognized or mismatched job receipts cannot report success', async t => {
  const f = await scanFixture(t, { jobStatus: 'complete' });
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '0.02']), 1);
  assert.equal(f.err().error.code, 'invalid_receipt'); assert.equal(f.stdout.length, 0);
  assert.equal(f.calls.length, 2); assert.ok(f.stderr.join('').includes('test-request-0001'));
  for (const receipt of [{ id: JOB, status: 'complete' }, { id: 'a'.repeat(32), status: 'completed' }]) {
    const g = await fixture(t, { handler: () => json(receipt) }); await g.save();
    assert.equal(await g.cli.run(['job', JOB]), 1); assert.equal(g.err().error.code, 'invalid_receipt');
    assert.equal(g.stdout.length, 0); assert.equal(g.calls.length, 1);
  }
});

test('input containing the API credential is rejected before quote or upload', async t => {
  const f = await scanFixture(t);
  await writeFile(f.input, JSON.stringify({ files: [{ path: 'app.js', content: TOKEN }] }));
  assert.equal(await f.cli.run(['call', 'gitleaks', '--input', f.input, '--max-price', '1']), 1);
  assert.equal(f.calls.length, 0); assert.ok(!f.stderr.join('').includes(TOKEN));
});

test('foreign redirects and raw provider error bodies never leak credentials', async t => {
  const f = await fixture(t, { handler: () => new Response(TOKEN, { status: 302, headers: { location: 'https://evil.test/' } }) });
  await f.save(); assert.equal(await f.cli.run(['whoami']), 1); assert.equal(f.err().error.code, 'redirect_refused');
  assert.equal(f.calls.length, 1); assert.ok(!f.stderr.join('').includes(TOKEN));
  const g = await fixture(t, { handler: () => json({ error: { code: 'insufficient_balance', message: TOKEN, nested: DEVICE } }, 402) });
  await g.save(); assert.equal(await g.cli.run(['balance']), 1); assert.equal(g.err().error.status, 402);
  assert.ok(!g.stderr.join('').includes(TOKEN)); assert.ok(!g.stderr.join('').includes(DEVICE));
});

test('project MCP setup preserves TOML comments and unrelated servers without writing a token', async t => {
  const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(path.join(project, '.codex'), { recursive: true, mode: 0o700 });
  const filename = path.join(project, '.codex', 'config.toml');
  const before = '# custom instructions must survive\n[mcp_servers.other]\ncommand = "other-server"\n';
  await writeFile(filename, before);
  const result = await installProjectMcp({ client: 'codex', project, cliPath: '/installed/offense-cli.mjs' });
  assert.equal(result.changed, true); assert.equal(result.scope, 'project'); assert.equal(result.restartRequired, true);
  assert.match(result.next, /new agent session/);
  const after = await readFile(filename, 'utf8'); assert.ok(after.startsWith(before)); assert.match(after, /\[mcp_servers\.offense\]/);
  assert.ok(!after.includes(TOKEN)); assert.ok(!after.includes('Authorization')); assert.ok(!after.includes('apiKey'));
  const again = await installProjectMcp({ client: 'codex', project, cliPath: '/installed/offense-cli.mjs' });
  assert.equal(again.changed, false); assert.equal(again.equivalent, true); assert.equal(await readFile(filename, 'utf8'), after);
});

test('Claude and Cursor project JSONC preserve unrelated entries and customized Offense entries', async t => {
  for (const client of ['claude', 'cursor']) {
    const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(project);
    const filename = path.join(project, client === 'claude' ? '.mcp.json' : '.cursor/mcp.json');
    if (client === 'cursor') await mkdir(path.dirname(filename));
    const before = '{\n // keep this comment\n "mcpServers": {"other": {"command": "other-server"}}\n}\n';
    await writeFile(filename, before);
    const result = await installProjectMcp({ client, project, cliPath: '/installed/offense-cli.mjs' });
    assert.equal(result.changed, true); const after = await readFile(filename, 'utf8');
    assert.ok(after.includes('// keep this comment')); assert.ok(after.includes('other-server')); assert.ok(after.includes('offense-cli.mjs'));
    const customized = '{"mcpServers":{"offense":{"command":"my-custom-offense"},"other":{"command":"other"}}}';
    await writeFile(filename, customized);
    const preserved = await installProjectMcp({ client, project, cliPath: '/installed/offense-cli.mjs' });
    assert.equal(preserved.changed, false); assert.equal(preserved.equivalent, false);
    assert.equal(await readFile(filename, 'utf8'), customized);
  }
});

test('CLI project MCP setup pins its selected credential directory without storing a key', async t => {
  for (const client of ['codex', 'claude', 'cursor']) {
    const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(project);
    await f.save();
    assert.equal(await f.cli.run(['mcp', 'install', '--client', client, '--project', project]), 0);
    const filename = f.out().path, after = await readFile(filename, 'utf8');
    const document = client === 'codex' ? parseToml(after) : parseJsonc(after);
    const entry = (document.mcp_servers || document.mcpServers).offense;
    assert.deepEqual({ ...entry.env }, { OFFENSE_CONFIG_DIR: f.directory });
    assert.ok(!after.includes(TOKEN)); assert.ok(!after.includes('OFFENSE_API_KEY'));
    assert.equal(f.calls.length, 0);
    assert.equal(await f.cli.run(['mcp', 'install', '--client', client, '--project', project]), 0);
    assert.equal(f.out().equivalent, true); assert.equal(await readFile(filename, 'utf8'), after);
    for (const env of [{ OFFENSE_CONFIG_DIR: path.join(f.directory, 'another-account') },
      { OFFENSE_CONFIG_DIR: f.directory, OFFENSE_API_KEY: TOKEN }, { OFFENSE_API_URL: 'https://another.example' }]) {
      const custom = { ...entry, env };
      const text = client === 'codex'
        ? `[mcp_servers.offense]\ncommand = ${JSON.stringify(custom.command)}\nargs = ${JSON.stringify(custom.args)}\n[mcp_servers.offense.env]\n` +
          Object.entries(env).map(([key, value]) => `${key} = ${JSON.stringify(value)}\n`).join('')
        : JSON.stringify({ mcpServers: { offense: custom } });
      await writeFile(filename, text);
      assert.equal(await f.cli.run(['mcp', 'install', '--client', client, '--project', project]), 2);
      assert.equal(f.out().equivalent, false); assert.equal(await readFile(filename, 'utf8'), text);
    }
  }
});

test('legacy default MCP entries are reused only when they select the same default account directory', async t => {
  const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(project);
  const setup = { client: 'claude', project, cliPath: '/installed/offense-cli.mjs' };
  const created = await installProjectMcp(setup), before = await readFile(created.path, 'utf8');
  const existing = await installProjectMcp({ ...setup, configRoot: path.join(os.homedir(), '.config', 'offense') });
  assert.equal(existing.changed, false); assert.equal(existing.equivalent, true);
  const custom = await installProjectMcp({ ...setup, configRoot: f.directory });
  assert.equal(custom.changed, false); assert.equal(custom.equivalent, false);
  assert.equal(await readFile(created.path, 'utf8'), before);
});

test('project MCP setup refuses an environment-only or overriding account without persisting its key', async t => {
  for (const saved of [null, { apiKey: OLD_TOKEN }, { endpoint: 'https://another.example' }]) {
    const f = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN } });
    if (saved) await f.save(saved);
    const configBefore = saved ? await readFile(f.config, 'utf8') : null;
    const project = path.join(f.directory, 'project'); await mkdir(project);
    const filename = path.join(project, '.mcp.json');
    const before = '{\n // preserve this existing client setup\n "mcpServers":{"other":{"command":"keep-me"}}\n}\n';
    await writeFile(filename, before);
    assert.equal(await f.cli.run(['--endpoint', 'https://offense.sh', 'mcp', 'install', '--client', 'claude', '--project', project]), 1);
    assert.equal(f.err().error.code, 'mcp_persistent_login_required');
    assert.match(f.err().error.message, /unset the environment override and run offense login/);
    assert.equal(await readFile(filename, 'utf8'), before); assert.equal(f.calls.length, 0);
    if (saved) assert.equal(await readFile(f.config, 'utf8'), configBefore);
    else await assert.rejects(readFile(f.config), { code: 'ENOENT' });
    assert.ok(!(f.stdout.join('') + f.stderr.join('')).includes(TOKEN));
  }
  const f = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN } }), project = path.join(f.directory, 'project'); await mkdir(project);
  await f.save();
  assert.equal(await f.cli.run(['mcp', 'install', '--client', 'claude', '--project', project]), 0);
  const entry = parseJsonc(await readFile(f.out().path, 'utf8')).mcpServers.offense;
  assert.deepEqual({ ...entry.env }, { OFFENSE_CONFIG_DIR: f.directory });
  assert.ok(!JSON.stringify(entry).includes(TOKEN));
});

test('malformed project configuration and symlink destinations remain unchanged', async t => {
  const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(path.join(project, '.codex'), { recursive: true });
  const filename = path.join(project, '.codex/config.toml'); await writeFile(filename, 'mcp_servers = "custom"\n');
  await assert.rejects(installProjectMcp({ client: 'codex', project }), /preserved/);
  assert.equal(await readFile(filename, 'utf8'), 'mcp_servers = "custom"\n');
  const outside = path.join(f.directory, 'outside.json'); await writeFile(outside, '{}');
  await symlink(outside, path.join(project, '.mcp.json'));
  await assert.rejects(installProjectMcp({ client: 'claude', project }), /symbolic link/);
  assert.equal(await readFile(outside, 'utf8'), '{}');
});

test('MCP proxy startup receives key privately and never writes protocol chatter through CLI output', async t => {
  let received;
  const f = await fixture(t, { overrides: { mcpProxy: async options => { received = options; } } });
  await f.save(); assert.equal(await f.cli.run(['mcp']), 0);
  assert.equal(received.endpoint, 'https://offense.sh'); assert.equal(received.token, TOKEN);
  assert.deepEqual(f.stdout, []); assert.deepEqual(f.stderr, []);
});

test('generated project MCP config preserves the account when a fresh client starts without the parent credential environment', async t => {
  const [{ default: express }, { once }, { Client }, { StdioClientTransport }, { Server }, { WebStandardStreamableHTTPServerTransport }, { ListToolsRequestSchema, CallToolRequestSchema }] = await Promise.all([
    import('express'), import('node:events'), import('@modelcontextprotocol/sdk/client/index.js'),
    import('@modelcontextprotocol/sdk/client/stdio.js'), import('@modelcontextprotocol/sdk/server/index.js'),
    import('@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'), import('@modelcontextprotocol/sdk/types.js')
  ]);
  const f = await fixture(t, { overrides: { cliPath: path.resolve('scripts/offense-cli.mjs') } }), app = express(); let authenticatedRequests = 0;
  app.use(express.json());
  app.post('/mcp', async (req, res) => {
    if (req.get('authorization') !== `Bearer ${TOKEN}`) return res.sendStatus(401);
    authenticatedRequests++;
    const upstream = new Server({ name: 'synthetic-cli-proxy-check', version: '1' }, { capabilities: { tools: {} } });
    upstream.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'cli_ping', description: 'Fixed synthetic diagnostic.', inputSchema: { type: 'object', properties: {} } }] }));
    upstream.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: 'text', text: 'synthetic proxy roundtrip ' + TOKEN }] }));
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    try {
      await upstream.connect(transport);
      const response = await transport.handleRequest(new Request('http://127.0.0.1/mcp', {
        method: 'POST', headers: req.headers
      }), { parsedBody: req.body });
      for (const [key, value] of response.headers) res.set(key, value);
      res.status(response.status).send(await response.text());
    } finally { await upstream.close(); }
  });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  await f.save({ endpoint });
  const project = path.join(f.directory, 'project'); await mkdir(project);
  assert.equal(await f.cli.run(['mcp', 'install', '--client', 'codex', '--project', project]), 0);
  const entry = parseToml(await readFile(f.out().path, 'utf8')).mcp_servers.offense;
  assert.deepEqual({ ...entry.env }, { OFFENSE_CONFIG_DIR: f.directory });
  assert.ok(!JSON.stringify(entry).includes(TOKEN));
  const client = new Client({ name: 'cli-proxy-test', version: '1' });
  const stdio = new StdioClientTransport({ command: entry.command, args: entry.args,
    env: { PATH: process.env.PATH, ...entry.env }, stderr: 'pipe' });
  const errors = []; stdio.stderr?.on('data', bytes => errors.push(bytes.toString()));
  t.after(() => client.close());
  await client.connect(stdio);
  const tools = await client.listTools(); assert.equal(tools.tools[0].name, 'cli_ping');
  const result = await client.callTool({ name: 'cli_ping', arguments: {} });
  assert.equal(result.content[0].text, 'synthetic proxy roundtrip [REDACTED]');
  assert.ok(authenticatedRequests >= 3); assert.ok(!errors.join('').includes(TOKEN));
  await client.close();
});

const auditResponse = (body, extra = {}) => ({ schemaVersion: 'offense.audit.v1', capability: 'audit_dependencies', status: 'complete',
  metadataFingerprint: createHash('sha256').update(JSON.stringify(body.files.slice().sort((a, b) => a.path.localeCompare(b.path)))).digest('hex'),
  coverage: { status: 'complete', checkedPackages: 1, planningOnly: false }, findings: [],
  summary: { advisoryMatches: 0, confirmedVulnerabilities: 0 },
  remediation: { plans: [], blockers: [], agentPrompt: 'Review the submitted dependency evidence.', planning: { scope: 'full_audit', hasMore: false } }, ...extra });
async function auditProject(directory) {
  const project = path.join(directory, 'source'); await mkdir(project);
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ name: 'PRIVATE_PROJECT_NAME', scripts: { postinstall: 'DO_NOT_EXECUTE_SECRET' } }));
  await writeFile(path.join(project, 'package-lock.json'), JSON.stringify({ name: 'PRIVATE_PROJECT_NAME', lockfileVersion: 3, packages: {
    '': { name: 'PRIVATE_PROJECT_NAME', dependencies: { semver: '^7.5.1' }, scripts: { postinstall: 'DO_NOT_EXECUTE_SECRET' } },
    'node_modules/semver': { version: '7.5.1', resolved: 'https://user:REGISTRY_SECRET@private.registry/semver.tgz', integrity: 'PRIVATE_INTEGRITY' }
  } }));
  await writeFile(path.join(project, 'index.js'), 'PRIVATE_SOURCE_CODE_MUST_NOT_UPLOAD');
  return project;
}

test('free audit sends only sanitized metadata without a key, source code, registry URLs or package scripts', async t => {
  const f = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN }, handler: (url, request) => {
    assert.equal(url.origin, 'https://offense.sh'); assert.equal(url.pathname, '/api/offense/audit');
    assert.equal(request.headers.authorization, undefined);
    const body = JSON.parse(request.body); assert.equal(body.planLimit, 0);
    for (const privateValue of [TOKEN, 'PRIVATE_SOURCE_CODE_MUST_NOT_UPLOAD', 'REGISTRY_SECRET', 'private.registry', 'DO_NOT_EXECUTE_SECRET', 'PRIVATE_PROJECT_NAME', 'PRIVATE_INTEGRITY'])
      assert.ok(!request.body.includes(privateValue));
    assert.deepEqual(Object.keys(body).sort(), ['files', 'planLimit']);
    return json(auditResponse(body));
  } });
  const project = await auditProject(f.directory), output = path.join(f.directory, 'audit-reports');
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '0', '--output', output]), 0);
  assert.equal(f.calls.length, 1); assert.equal(f.out().advisoryMatches, 0); assert.equal(f.out().checkedPackages, 1);
  assert.equal(f.out().confirmedVulnerabilities, 0);
  assert.equal((await lstat(path.join(output, 'audit.json'))).mode & 0o077, 0);
  assert.equal((await lstat(path.join(output, 'remediation.md'))).mode & 0o077, 0);
  assert.match(await readFile(path.join(project, 'index.js'), 'utf8'), /PRIVATE_SOURCE_CODE/);
});

test('free audit retains uncovered manifests as partial local coverage without inventing a failed server scan', async t => {
  const f = await fixture(t, { handler: (_url, request) => json(auditResponse(JSON.parse(request.body))) });
  const project = await auditProject(f.directory), uncovered = path.join(project, 'sdk'); await mkdir(uncovered);
  await writeFile(path.join(uncovered, 'package.json'), '{"name":"sdk-without-lockfile"}');
  const output = path.join(f.directory, 'reports');
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '0', '--output', output]), 2);
  assert.equal(f.out().status, 'partial'); assert.equal(f.out().serverStatus, 'complete');
  assert.ok(f.out().localCoverageWarnings.some(warning => warning.includes('sdk/package.json')));
  const saved = JSON.parse(await readFile(path.join(output, 'audit.json'), 'utf8'));
  assert.equal(saved.status, 'partial'); assert.equal(saved.serverStatus, 'complete');
  assert.match(await readFile(path.join(output, 'remediation.md'), 'utf8'), /sdk\/package.json/);
});

test('free audit rejects mismatched fingerprints and invalid planning limits before saving a report', async t => {
  const f = await fixture(t, { handler: (_url, request) => json(auditResponse(JSON.parse(request.body), { metadataFingerprint: '0'.repeat(64) })) });
  const project = await auditProject(f.directory), output = path.join(f.directory, 'reports');
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '11', '--output', output]), 1);
  assert.equal(f.calls.length, 0);
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '0', '--output', output]), 1);
  assert.equal(f.err().error.code, 'audit_fingerprint_mismatch');
  await assert.rejects(readFile(path.join(output, 'audit.json')), { code: 'ENOENT' });
});

test('free audit keeps reports outside the source checkout and retains incomplete planning', async t => {
  const f = await fixture(t, { handler: (_url, request) => {
    const report = auditResponse(JSON.parse(request.body)); report.remediation.planning.hasMore = true;
    return json(report);
  } });
  const project = await auditProject(f.directory);
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '1', '--output', path.join(project, 'reports')]), 1);
  const output = path.join(f.directory, 'reports');
  assert.equal(await f.cli.run(['audit', project, '--plan-limit', '1', '--output', output]), 2);
  assert.equal(f.out().status, 'partial');
  assert.match(await readFile(path.join(output, 'remediation.md'), 'utf8'), /planning remains incomplete/);
});


test('environment credentials are bound to an explicit service origin before any request', async t => {
  const f = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN } });
  assert.equal(await f.cli.run(['--endpoint', 'https://untrusted.example', 'whoami']), 1);
  assert.equal(f.calls.length, 0); assert.equal(f.err().error.code, 'endpoint_mismatch');
  const g = await fixture(t, { env: { OFFENSE_API_KEY: TOKEN, OFFENSE_API_URL: 'https://selfhost.example' } });
  assert.equal(await g.cli.run(['whoami']), 0);
  assert.equal(new URL(g.calls[0].url).origin, 'https://selfhost.example');
});

test('an anonymous HTTP MCP entry is preserved without claiming paid access is configured', async t => {
  const f = await fixture(t), project = path.join(f.directory, 'project'); await mkdir(project);
  const filename = path.join(project, '.mcp.json');
  const text = JSON.stringify({mcpServers:{offense:{type:'http',url:'https://offense.sh/mcp'}}});
  await writeFile(filename,text);
  const result = await installProjectMcp({client:'claude',project,cliPath:'/installed/offense-cli.mjs'});
  assert.equal(result.changed,false);assert.equal(result.equivalent,false);
  assert.equal(await readFile(filename,'utf8'),text);
});

test('explicit migration replaces only the reviewed Offense entry and preserves other project settings', async t => {
  for(const client of ['codex','claude']) {
    const f=await fixture(t), project=path.join(f.directory,'project');await mkdir(project);
    const filename=path.join(project,client==='codex'?'.codex/config.toml':'.mcp.json');await mkdir(path.dirname(filename),{recursive:true});
    const before=client==='codex'?'# keep\n[mcp_servers.offense]\nurl = "https://offense.sh/mcp"\n[mcp_servers.other]\ncommand = "keep-me"\n':'{\n// keep\n"mcpServers":{"offense":{"url":"https://offense.sh/mcp"},"other":{"command":"keep-me"}}\n}';
    await writeFile(filename,before);
    const result=await installProjectMcp({client,project,cliPath:'/installed/offense-cli.mjs',replaceOffense:true});
    assert.equal(result.changed,true);assert.equal(result.restartRequired,true);
    const after=await readFile(filename,'utf8');assert.ok(after.includes('keep-me'));assert.ok(after.includes('keep'));assert.ok(after.includes('offense-cli.mjs'));assert.ok(!after.includes('url = "https://offense.sh/mcp"'));
  }
});
