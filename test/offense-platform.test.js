import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createAccounts } from '../server/accounts.js';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createScanWhopBilling, SCAN_PRODUCT } from '../server/scan-whop-billing.js';
import { createToolGateway, registerOffensePlatform, SECURITY_MCP_TOOLS } from '../server/offense-platform.js';
import { registerOffenseMcp, OFFENSE_MCP_TOOL } from '../server/offense-mcp.js';
import { publicOrigins, requestPublicOrigin, productOrigin, LOGIN_RETURN_PATHS } from '../server/public-origins.js';
import { createWorkerApp } from '../workers/app-api.js';

const PRIVATE = 'PRIVATE_OFFENSE_PROVIDER_SECRET';
const webhookSecret = 'ws_offense_platform_fixture';
const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
const source = { files: [{ path: 'src/example.js', content: 'console.log("fixture only");' }] };
const dimensions = { tools: ['opengrep'], inputBytes: Buffer.byteLength(source.files[0].content), fileCount: 1 };
const rpcHeaders = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25' };

async function fixture(t) {
  const db = new DatabaseSync(':memory:'), accounts = createAccounts(db);
  const user = accounts.upsertUser(1234, 'first-user'), other = accounts.upsertUser(5678, 'second-user');
  accounts.createWorkspace(user.id, 'first-account', { company: 'First account', cloudflare: { accessToken: PRIVATE }, openrouter: { secret: PRIVATE } });
  accounts.createWorkspace(other.id, 'second-account', { company: 'Second account' });
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  let payment = null, checkoutCalls = 0, starts = 0, dispatchRequests = 0, checkoutFailure = false;
  const provider = {
    async checkout(orderId) { checkoutCalls++; if (checkoutFailure) throw Error(PRIVATE);
      return { id: `ch_${orderId}`, account_id: 'biz_platformfixture', purchase_url: `https://whop.com/checkout/${orderId}`,
        plan: { currency: 'usd', initial_price: 10, plan_type: 'one_time' } }; },
    async payment() { return payment; }
  };
  const billing = createScanWhopBilling(db, { meter, provider, apiKey: PRIVATE, webhookSecret,
    enabled: true, publicUrl: 'https://offense.sh' });
  let selected = [];
  const sandbox = {
    async start(input) { starts++; selected = input.tools; return { status: 'running' }; },
    async get() { return { status: 'completed', tools: selected.map(name => ({ name, status: 'complete', durationMs: 10 })), findings: [] }; },
    async destroy() { return {}; }
  };
  const scans = createHostedScans(db, { sandbox, metering: meter,
    encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString() });
  const key = scans.issueKey('first-account', user.id), otherKey = scans.issueKey('second-account', other.id);
  const dispatch = () => { dispatchRequests++; };
  const gateway = createToolGateway({ scans, billing, accounts, dispatch, baseUrl: 'https://offense.sh' });
  const app = express();
  registerOffensePlatform(app, { scans, billing, gateway, baseUrl: 'https://offense.sh' });
  registerScanApi(app, { scans, dispatch });
  registerOffenseMcp(app, { publicUrl: 'http://127.0.0.1', gateway, audit: async () => { throw Error('The free audit is not executed by this fixture.'); } });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const request = (path, { method = 'GET', body, token = key.token, headers = {} } = {}) => fetch(url + path, {
    method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  return { db, accounts, user, other, meter, billing, scans, key, otherKey, gateway, app, request, url,
    get starts() { return starts; }, get checkoutCalls() { return checkoutCalls; }, get dispatchRequests() { return dispatchRequests; },
    get payment() { return payment; },
    set payment(value) { payment = value; },
    set checkoutFailure(value) { checkoutFailure = value; },
    fund(amount = 1_000_000) { meter.recordVerifiedPurchase({ workspaceId: 'first-account', paymentId: 'pay_preverified_fixture', amountMicros: amount }); } };
}
async function client(t, f, token) {
  const value = new Client({ name: 'offense-platform-fixture', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(f.url + '/mcp'), token ? { requestInit: { headers: { authorization: `Bearer ${token}` } } } : undefined);
  await value.connect(transport); t.after(() => value.close()); return value;
}
const content = result => result.structuredContent || JSON.parse(result.content.find(item => item.type === 'text').text);
const jobCount = db => db.prepare('SELECT COUNT(*) AS n FROM scan_jobs').get().n;

test('one Offense API key reads catalog, account, quotes and usage without exposing account/provider secrets', async t => {
  const f = await fixture(t); f.fund();
  assert.match(f.key.token, /^offense_sk_[a-f0-9]{64}$/);
  const publicCatalog = await f.request('/v1/catalog', { token: null });
  assert.equal(publicCatalog.status, 200); assert.equal(publicCatalog.headers.get('cache-control'), 'no-store');
  const catalog = await publicCatalog.json();
  assert.equal(catalog.company, 'Offense Security'); assert.equal(catalog.product, 'Offense');
  assert.equal(catalog.tools.find(tool => tool.id === 'dependency-audit').priceMicros, 0);
  const accountResponse = await f.request('/v1/account'); assert.equal(accountResponse.status, 200);
  const account = await accountResponse.json();
  assert.equal(account.workspace.id, 'first-account'); assert.equal(account.billing.balanceMicros, 1_000_000);
  const listed = await f.request('/v1/tools'); assert.equal(listed.status, 200);
  assert.ok((await listed.json()).tools.some(tool => tool.id === 'opengrep'));
  const quoteResponse = await f.request('/v1/quotes', { method: 'POST', body: dimensions }); assert.equal(quoteResponse.status, 200);
  const quote = await quoteResponse.json(); assert.ok(quote.maximumMicros > 0);
  const usageResponse = await f.request('/v1/usage'); assert.equal(usageResponse.status, 200);
  const usage = await usageResponse.json(); assert.equal(usage.balanceMicros, 1_000_000);
  for (const secret of [f.key.token, f.otherKey.token, PRIVATE]) assert.ok(!JSON.stringify({ catalog, account, quote, usage }).includes(secret));
  assert.equal(jobCount(f.db), 0); assert.equal(f.meter.status('first-account').balanceMicros, 1_000_000);
  assert.equal((await f.request('/v1/account', { token: 'offense_sk_' + 'f'.repeat(64) })).status, 401);
  assert.equal((await f.request('/v1/account', { headers: { origin: 'https://untrusted.test' } })).status, 403);
});

test('new single-tool calls enforce the reviewed price, charge one completed job and retry idempotently', async t => {
  const f = await fixture(t); f.fund();
  const quote = await (await f.request('/v1/quotes', { method: 'POST', body: dimensions })).json();
  assert.equal((await f.request('/v1/call/opengrep', { method: 'POST', body: source, headers: { 'idempotency-key': 'platform-call-001' } })).status, 400);
  assert.equal((await f.request('/v1/call/opengrep', { method: 'POST', body: { ...source, maxChargeMicros: quote.maximumMicros - 1 }, headers: { 'idempotency-key': 'platform-call-001' } })).status, 409);
  assert.equal(jobCount(f.db), 0);
  const body = { ...source, maxChargeMicros: quote.maximumMicros };
  const first = await f.request('/v1/call/opengrep', { method: 'POST', body, headers: { 'idempotency-key': 'platform-call-001' } });
  assert.equal(first.status, 202); const job = await first.json();
  const second = await f.request('/v1/call/opengrep', { method: 'POST', body, headers: { 'idempotency-key': 'platform-call-001' } });
  assert.equal(second.status, 202); assert.equal((await second.json()).id, job.id); assert.equal(jobCount(f.db), 1);
  assert.equal(f.meter.status('first-account').reservedMicros, quote.maximumMicros);
  await f.scans.dispatch(); await f.scans.dispatch();
  assert.equal(f.starts, 1); assert.equal(f.scans.get(job.id, 'first-account').status, 'completed');
  assert.equal(f.meter.status('first-account').balanceMicros, 1_000_000 - quote.maximumMicros);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 1);
  const retried = await f.request('/v1/call/opengrep', { method: 'POST', body, headers: { 'idempotency-key': 'platform-call-001' } });
  assert.equal((await retried.json()).id, job.id);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 1);
  assert.equal((await f.request(`/v1/scans/${job.id}`, { token: f.otherKey.token })).status, 404);
});

test('insufficient balance returns funding guidance without creating a job or charging the account', async t => {
  const f = await fixture(t), quote = f.scans.quote(dimensions, 'first-account');
  const response = await f.request('/v1/call/opengrep', { method: 'POST', body: { ...source, maxChargeMicros: quote.maximumMicros }, headers: { 'idempotency-key': 'platform-unfunded' } });
  assert.equal(response.status, 402); const body = await response.json();
  assert.equal(body.error.code, 'insufficient_balance'); assert.equal(body.topupUrl, 'https://offense.sh/account#billing');
  assert.equal(jobCount(f.db), 0); assert.equal(f.meter.status('first-account').reservedMicros, 0);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 0);
});

test('legacy scan keys remain usable and removed account membership invalidates old and new API surfaces', async t => {
  const f = await fixture(t); f.fund();
  const legacy = 'purple_scan_' + 'c'.repeat(64);
  f.db.prepare('INSERT INTO scan_keys VALUES (?,?,?,?,?,NULL)').run('legacy-key', 'first-account', f.user.id,
    createHash('sha256').update(legacy).digest('hex'), Date.now());
  assert.equal((await f.request('/v1/account', { token: legacy })).status, 200);
  assert.equal((await f.request('/v1/tools', { token: legacy })).status, 200);
  f.db.prepare('DELETE FROM memberships WHERE user_id=? AND workspace_id=?').run(f.user.id, 'first-account');
  for (const token of [legacy, f.key.token]) {
    for (const path of ['/v1/account', '/v1/tools', '/v1/usage']) assert.equal((await f.request(path, { token })).status, 401, path);
    assert.equal((await f.request('/v1/quotes', { token, method: 'POST', body: dimensions })).status, 401);
    assert.equal((await f.request('/v1/billing/topups', { token, method: 'POST', body: {} })).status, 401);
    assert.equal((await f.request('/v1/call/opengrep', { token, method: 'POST', body: { ...source, maxChargeMicros: 50000 }, headers: { 'idempotency-key': 'removed-membership' } })).status, 401);
  }
  assert.equal(jobCount(f.db), 0); assert.equal(f.checkoutCalls, 0);
});

test('API-key top-up links do not credit balances until signed payment and provider readback succeed', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/v1/billing/topups', { method: 'POST', body: { amount: 100, workspaceId: 'second-account' } })).status, 400);
  const response = await f.request('/v1/billing/topups', { method: 'POST', body: {} }); assert.equal(response.status, 200);
  const checkout = await response.json(); assert.ok(checkout.url.startsWith('https://whop.com/checkout/'));
  assert.equal(f.meter.status('first-account').balanceMicros, 0);
  const repeated = await f.request('/v1/billing/topups', { method: 'POST', body: {} });
  assert.deepEqual(await repeated.json(), checkout); assert.equal(f.checkoutCalls, 1);
  f.payment = { id: 'pay_platformfixture', account_id: 'biz_platformfixture', checkout_configuration_id: `ch_${checkout.orderId}`,
    status: 'paid', currency: 'usd', total: { amount: '10.00', currency: 'usd' }, refunded_amount: { amount: '0.00', currency: 'usd' },
    metadata: { purple_order_id: checkout.orderId, purple_product: SCAN_PRODUCT } };
  const raw = Buffer.from(JSON.stringify({ type: 'payment.succeeded', data: { id: 'pay_platformfixture', metadata: f.payment.metadata } }));
  const id = 'platform-event-1', timestamp = String(Math.floor(Date.now() / 1000));
  const headers = { 'webhook-id': id, 'webhook-timestamp': timestamp,
    'webhook-signature': 'v1,' + createHmac('sha256', webhookSecret).update(`${id}.${timestamp}.`).update(raw).digest('base64') };
  f.billing.webhook(raw, headers); assert.equal(f.meter.status('first-account').balanceMicros, 0);
  await f.billing.dispatch(); assert.equal(f.meter.status('first-account').balanceMicros, 10_000_000);
  f.billing.webhook(raw, headers); await f.billing.dispatch();
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='purchase'").get().n, 1);
  assert.equal(f.meter.status('second-account').balanceMicros, 0);
});

test('MCP lists only the free audit anonymously and exposes paid tools through the same authenticated key', async t => {
  const f = await fixture(t), anonymous = await client(t, f);
  assert.deepEqual((await anonymous.listTools()).tools.map(tool => tool.name), [OFFENSE_MCP_TOOL]);
  const denied = await anonymous.callTool({ name: 'offense.account', arguments: {} });
  assert.equal(denied.isError, true); assert.equal(denied.structuredContent, undefined); assert.equal(content(denied).error.code, 'invalid_api_key');
  const signedIn = await client(t, f, f.key.token);
  const listed = await signedIn.listTools();
  assert.deepEqual(new Set(listed.tools.map(tool => tool.name)), new Set([OFFENSE_MCP_TOOL, ...SECURITY_MCP_TOOLS.map(tool => tool.name)]));
  const account = await signedIn.callTool({ name: 'offense.account', arguments: {} });
  assert.equal(account.isError, false); assert.equal(content(account).workspace.id, 'first-account');
  const catalog = await signedIn.callTool({ name: 'offense.security_tools', arguments: {} });
  assert.equal(catalog.isError, false); assert.ok(content(catalog).tools.some(tool => tool.id === 'opengrep'));
  const quote = await signedIn.callTool({ name: 'offense.security_quote', arguments: { tool: 'opengrep', inputBytes: dimensions.inputBytes, fileCount: 1 } });
  assert.equal(quote.isError, false); assert.ok(content(quote).maximumMicros > 0);
  const malformed = await signedIn.callTool({ name: 'offense.security_quote', arguments: { tool: 'opengrep', inputBytes: -1, fileCount: 1 } });
  assert.equal(malformed.isError, true); assert.equal(malformed.structuredContent, undefined); assert.equal(content(malformed).error.code, 'invalid_input');
  const unfunded = await signedIn.callTool({ name: 'offense.security_call', arguments: { tool: 'opengrep', input: source, maxChargeMicros: content(quote).maximumMicros, idempotencyKey: 'mcp-unfunded-1' } });
  assert.equal(unfunded.isError, true); assert.equal(content(unfunded).error.code, 'insufficient_balance'); assert.equal(jobCount(f.db), 0);
  const topup = await signedIn.callTool({ name: 'offense.topup', arguments: {} });
  assert.equal(topup.isError, false); assert.ok(content(topup).url.startsWith('https://whop.com/checkout/'));
  assert.equal(f.meter.status('first-account').balanceMicros, 0);
  f.fund();
  const paidArgs = { tool: 'opengrep', input: source, maxChargeMicros: content(quote).maximumMicros, idempotencyKey: 'mcp-funded-001' };
  const submitted = await signedIn.callTool({ name: 'offense.security_call', arguments: paidArgs });
  assert.equal(submitted.isError, false); const job = content(submitted); assert.equal(job.status, 'queued');
  const retry = await signedIn.callTool({ name: 'offense.security_call', arguments: paidArgs });
  assert.equal(content(retry).id, job.id); assert.equal(jobCount(f.db), 1);
  await f.scans.dispatch(); await f.scans.dispatch();
  const result = await signedIn.callTool({ name: 'offense.security_result', arguments: { id: job.id } });
  assert.equal(result.isError, false); assert.equal(content(result).status, 'completed');
  assert.equal(content(result).metering.chargeMicros, content(quote).maximumMicros);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='usage'").get().n, 1);
  for (const secret of [f.key.token, f.otherKey.token, PRIVATE]) assert.ok(!JSON.stringify({ listed, account, catalog, quote, malformed, unfunded, topup, submitted, retry, result }).includes(secret));
  for (const tool of ['k8s-deprecations', 'k8s-manifest-validate']) {
    const contract = content(catalog).tools.find(entry => entry.id === tool);
    assert.deepEqual(contract.requiredInput, ['files', 'kubernetesVersion']);
    assert.ok(contract.kubernetesVersions.includes('1.34.0'));
    const quoted = content(await signedIn.callTool({ name: 'offense.security_quote', arguments: { tool, inputBytes: 100, fileCount: 1 } }));
    const args = { tool, input: { kubernetesVersion: '1.34.0', files: [{ path: 'pod.yaml', content: 'apiVersion: v1\nkind: Pod\n' }] },
      maxChargeMicros: quoted.maximumMicros, idempotencyKey: `mcp-${tool}` };
    const created = await signedIn.callTool({ name: 'offense.security_call', arguments: args });
    assert.equal(created.isError, false);
    assert.equal(content(created).kubernetesVersion, '1.34.0');
    assert.equal(content(await signedIn.callTool({ name: 'offense.security_call', arguments: args })).id, content(created).id);
    await f.scans.dispatch(); await f.scans.dispatch();
    const completed = content(await signedIn.callTool({ name: 'offense.security_result', arguments: { id: content(created).id } }));
    assert.equal(completed.status, 'completed');
    assert.equal(completed.metering.chargeMicros, quoted.maximumMicros);
  }
  f.db.prepare('UPDATE scan_keys SET revoked_at=? WHERE id=?').run(Date.now(), f.key.id);
  assert.deepEqual((await signedIn.listTools()).tools.map(tool => tool.name), [OFFENSE_MCP_TOOL]);
  assert.equal((await signedIn.callTool({ name: 'offense.account', arguments: {} })).isError, true);
});

test('canonical Offense and legacy aliases are exact origins and foreign hosts cannot use MCP', async t => {
  assert.deepEqual([...publicOrigins('https://app.purpleteam.sh')], ['https://app.purpleteam.sh', 'https://offense.sh']);
  assert.equal(productOrigin('https://app.purpleteam.sh'), 'https://offense.sh');
  assert.equal(productOrigin('http://localhost:3217'), 'http://localhost:3217');
  assert.equal(requestPublicOrigin({ get: () => 'offense.sh' }, 'https://app.purpleteam.sh'), 'https://offense.sh');
  assert.equal(requestPublicOrigin({ get: () => 'offense.sh.attacker.test' }, 'https://app.purpleteam.sh'), 'https://app.purpleteam.sh');
  assert.ok(LOGIN_RETURN_PATHS.includes('/device'));
  const app = express(); registerOffenseMcp(app, { publicUrl: 'https://app.purpleteam.sh', allowedOrigins: [...publicOrigins('https://app.purpleteam.sh')], audit: async () => ({}) });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const post = (host, origin) => new Promise((resolve, reject) => {
    const req = httpRequest(`http://127.0.0.1:${server.address().port}/mcp`, { method: 'POST', headers: { ...rpcHeaders, Host: host, ...(origin ? { Origin: origin } : {}) } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    }); req.on('error', reject); req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }));
  });
  assert.equal(await post('offense.sh'), 200);
  assert.equal(await post('app.purpleteam.sh', 'https://offense.sh'), 200);
  assert.equal(await post('offense.sh.attacker.test'), 403);
  assert.equal(await post('offense.sh', 'https://offense.sh.attacker.test'), 403);
});

test('unexpected payment-provider errors stay actionable without exposing private details through HTTP or MCP', async t => {
  const f = await fixture(t); f.checkoutFailure = true;
  const http = await f.request('/v1/billing/topups', { method: 'POST', body: {} });
  assert.equal(http.status, 503);
  const httpBody = await http.json();
  assert.ok(!JSON.stringify(httpBody).includes(PRIVATE)); assert.ok(httpBody.error.message);
  const signedIn = await client(t, f, f.key.token);
  const result = await signedIn.callTool({ name: 'offense.topup', arguments: {} });
  assert.equal(result.isError, true); assert.equal(result.structuredContent, undefined);
  assert.ok(!JSON.stringify(result).includes(PRIVATE), 'Unexpected provider errors must not reveal private internal details.');
  assert.equal(jobCount(f.db), 0); assert.equal(f.meter.status('first-account').balanceMicros, 0);
});

test('GitHub login preserves device return and the callback origin for both canonical and legacy hosts', async t => {
  const db = new DatabaseSync(':memory:'), originalFetch = globalThis.fetch, redirects = [];
  const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://app.purpleteam.sh', ENCRYPTION_KEY: 'a'.repeat(64),
    GITHUB_APP_SLUG: 'offense', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret' }, schedule() {} });
  globalThis.fetch = async (url, options) => {
    if (String(url).includes('github.com/login/oauth/access_token')) { redirects.push(JSON.parse(options.body).redirect_uri); return Response.json({ access_token: 'fixture-provider-token' }); }
    if (String(url) === 'https://api.github.com/user') return Response.json({ id: 918273, login: 'fixture-owner' });
    if (String(url).startsWith('https://api.github.com/user/installations')) return Response.json({ installations: [] });
    return originalFetch(url, options);
  };
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { globalThis.fetch = originalFetch; server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  const get = (route, host, cookie) => new Promise((resolve, reject) => {
    const req = httpRequest(`http://127.0.0.1:${server.address().port}${route}`, { headers: { Host: host, ...(cookie ? { cookie } : {}) } }, res => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location, cookie: res.headers['set-cookie']?.[0]?.split(';')[0] }));
    }); req.on('error', reject); req.end();
  });
  for (const host of ['offense.sh', 'app.purpleteam.sh']) {
    const start = await get('/api/auth/github/start?returnTo=%2Fdevice', host); assert.equal(start.status, 302);
    const authorize = new URL(start.location); assert.equal(authorize.searchParams.get('redirect_uri'), `https://${host}/api/github/callback`);
    const end = await get(`/api/github/callback?state=${encodeURIComponent(authorize.searchParams.get('state'))}&code=fixture`, host, start.cookie);
    assert.equal(end.status, 302); assert.equal(end.location, '/device');
    assert.equal(redirects.at(-1), `https://${host}/api/github/callback`);
  }
});
