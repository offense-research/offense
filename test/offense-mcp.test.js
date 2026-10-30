import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { request as httpRequest } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { registerOffenseMcp, OFFENSE_MCP_TOOL } from '../server/offense-mcp.js';
import { AUDIT_SCHEMA_VERSION, OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';

const args = { files: [{ path: 'package-lock.json', content: { lockfileVersion: 3, packages: { 'node_modules/example': { version: '1.0.0' } } } }], planLimit: 0 };
const report = () => ({ schemaVersion: AUDIT_SCHEMA_VERSION, capability: 'audit_dependencies', status: 'complete',
  findings: [{ id: 'OSV-EXAMPLE', package: 'example', version: '1.0.0', verification: 'advisory_match' }],
  coverage: { complete: true }, remediation: { plans: [], blockers: [] }, summary: { advisoryMatches: 1 }, providers: [{ id: 'osv' }] });
const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25' };
const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } } };
const call = (overrides = {}) => ({ jsonrpc: '2.0', id: 'call-1', method: 'tools/call', params: { name: OFFENSE_MCP_TOOL, arguments: structuredClone(args) }, ...overrides });

async function fixture(t, overrides = {}) {
  const calls = [], admissions = [];
  const app = express();
  registerOffenseMcp(app, { publicUrl: 'http://127.0.0.1', audit: async (input, req) => { calls.push({ input, method: req.method }); return report(); },
    admit: req => { admissions.push(req.path); return null; }, ...overrides });
  app.use((req, res) => res.status(401).json({ error: 'protected app' }));
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return { url: `http://127.0.0.1:${server.address().port}`, calls, admissions };
}
const post = (url, message, extra = {}) => fetch(`${url}/mcp`, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(message) });

test('official MCP SDK client initializes, discovers and calls the stateless capability without authentication', async t => {
  const { url, calls, admissions } = await fixture(t);
  const client = new Client({ name: 'independent-sdk-client', version: '1' });
  const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`));
  t.after(() => client.close());
  await client.connect(transport);
  assert.equal(transport.sessionId, undefined);
  assert.equal(client.getServerVersion().name, 'offense');
  await client.ping();
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name), [OFFENSE_MCP_TOOL]);
  assert.equal(listed.tools[0].annotations.readOnlyHint, true);
  assert.equal(listed.tools[0].outputSchema.properties.schemaVersion.const, AUDIT_SCHEMA_VERSION);
  const result = await client.callTool({ name: OFFENSE_MCP_TOOL, arguments: args });
  assert.deepEqual(result.structuredContent, report());
  assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
  assert.equal(result.isError, false); assert.equal(calls.length, 1); assert.equal(admissions.length, 1);
  assert.deepEqual(calls[0].input, args);
  assert.equal((await fetch(`${url}/protected`)).status, 401);
});

test('initialization negotiates a supported version and never issues account or MCP session cookies', async t => {
  const { url, admissions } = await fixture(t);
  const response = await post(url, { ...initialize, params: { ...initialize.params, protocolVersion: 'future-version' } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('set-cookie'), null); assert.equal(response.headers.get('mcp-session-id'), null);
  const body = await response.json(); assert.equal(body.id, 1); assert.equal(body.result.protocolVersion, '2025-11-25');
  assert.deepEqual(body.result.capabilities, { tools: {} });
  assert.equal(response.headers.get('cache-control'), 'no-store'); assert.deepEqual(admissions, []);
});

test('official SDK clients receive actionable upstream errors without validating them as successful audit reports', async t => {
  const { url } = await fixture(t, { audit: async () => { throw Object.assign(new Error('OSV unavailable; no advisory result was established.'), { code: 'provider_unavailable' }); } });
  const client = new Client({ name: 'sdk-error-client', version: '1' });
  t.after(() => client.close());
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`)));
  await client.listTools();
  const result = await client.callTool({ name: OFFENSE_MCP_TOOL, arguments: args });
  assert.equal(result.isError, true);
  assert.equal(result.structuredContent, undefined);
  const failure = JSON.parse(result.content[0].text);
  assert.equal(failure.status, 'error');
  assert.equal(failure.error.code, 'provider_unavailable');
  assert.equal(failure.error.message, 'OSV unavailable; no advisory result was established.');
});

test('notifications and client responses get 202 without execution or JSON-RPC response bodies', async t => {
  const { url, calls, admissions } = await fixture(t);
  for (const message of [{ jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } },
    { jsonrpc: '2.0', id: 'client-response', result: {} }, { jsonrpc: '2.0', method: 'tools/call', params: { name: OFFENSE_MCP_TOOL, arguments: args } }]) {
    const response = await post(url, message); assert.equal(response.status, 202); assert.equal(await response.text(), '');
  }
  assert.deepEqual(calls, []); assert.deepEqual(admissions, []);
});

test('malformed messages, ids, batches, JSON and oversized bodies are rejected before analysis', async t => {
  const { url, calls } = await fixture(t);
  for (const message of [[initialize], [], null, 1, {}, { ...initialize, jsonrpc: '1.0' }, { ...initialize, id: null }, { ...initialize, id: 1.2 },
    { ...initialize, id: {} }, { ...initialize, method: null }, { ...initialize, params: [] }]) {
    const response = await post(url, message); assert.equal(response.status, 400, JSON.stringify(message)); assert.ok((await response.json()).error);
  }
  const invalid = await fetch(`${url}/mcp`, { method: 'POST', headers, body: '{broken' });
  assert.equal(invalid.status, 400); assert.equal((await invalid.json()).error.code, -32700);
  const large = await post(url, { ...call(), padding: 'x'.repeat(2_100_000) }); assert.equal(large.status, 413);
  assert.deepEqual(calls, []);
});

test('transport requires compatible MIME/version headers, validates every Origin/Host, and declines SSE/session routes', async t => {
  const { url, calls } = await fixture(t);
  assert.equal((await post(url, initialize, { Accept: 'application/json' })).status, 406);
  assert.equal((await post(url, initialize, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await post(url, { jsonrpc: '2.0', id: 2, method: 'ping' }, { 'MCP-Protocol-Version': '2099-01-01' })).status, 400);
  for (const method of ['GET', 'DELETE', 'PUT']) assert.equal((await fetch(`${url}/mcp`, { method })).status, 405);
  assert.equal((await fetch(`${url}/mcp/nested`, { headers })).status, 404);
  for (const method of ['GET', 'POST', 'DELETE']) {
    const response = await fetch(`${url}/mcp`, { method, headers: { ...headers, Origin: 'https://attacker.test' }, ...(method === 'POST' ? { body: JSON.stringify(initialize) } : {}) });
    assert.equal(response.status, 403);
  }
  const rebindingStatus = await new Promise((resolve, reject) => {
    const req = httpRequest(`${url}/mcp`, { method: 'POST', headers: { ...headers, Host: 'attacker.test' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.end(JSON.stringify(initialize));
  });
  assert.equal(rebindingStatus, 403); assert.deepEqual(calls, []);
});

test('unknown methods/tools and unsupported task requests return protocol errors without invoking the audit', async t => {
  const { url, calls } = await fixture(t);
  for (const message of [{ jsonrpc: '2.0', id: 1, method: 'roots/list' }, call({ params: { name: 'offense.execute', arguments: args } }),
    call({ params: { name: OFFENSE_MCP_TOOL, arguments: args, task: { ttl: 1000 } } }), call({ params: { name: OFFENSE_MCP_TOOL, arguments: [] } })]) {
    const response = await post(url, message); const body = await response.json();
    assert.equal(response.status, 200); assert.equal(body.id, message.id); assert.ok(body.error, JSON.stringify(body));
  }
  assert.deepEqual(calls, []);
});

test('tool input validation errors are actionable tool failures, not empty or successful scans', async t => {
  const { url, calls } = await fixture(t);
  for (const input of [{}, { files: [] }, { ...args, planLimit: 11 }, { ...args, apiKey: 'never-accepted' }, { ...args, files: [{ ...args.files[0], repository: 'not-accepted' }] }]) {
    const response = await post(url, call({ params: { name: OFFENSE_MCP_TOOL, arguments: input } }));
    const body = await response.json(); assert.equal(response.status, 200); assert.equal(body.result.isError, true);
    const failure = JSON.parse(body.result.content[0].text);
    assert.equal(body.result.structuredContent, undefined); assert.equal(failure.error.code, 'invalid_input'); assert.equal(failure.findings, undefined);
  }
  assert.deepEqual(calls, []);
});

test('shared admission returns HTTP quota/backpressure errors and never invokes the audit', async t => {
  let runs = 0;
  for (const denied of [{ status: 429, retryAfter: 60, error: 'Quota reached' }, { status: 503, retryAfter: 10, error: 'Concurrency full' }]) {
    const { url } = await fixture(t, { audit: async () => { runs++; return report(); }, admit: () => denied });
    const response = await post(url, call()); const body = await response.json();
    assert.equal(response.status, denied.status); assert.equal(response.headers.get('retry-after'), String(denied.retryAfter));
    assert.equal(body.error.message, denied.error); assert.equal(body.id, 'call-1'); assert.equal(body.result, undefined);
  }
  assert.equal(runs, 0);
});

test('upstream failures and malformed output cannot be mistaken for a clean vulnerability result', async t => {
  for (const audit of [async () => { throw Object.assign(new Error('OSV unavailable'), { code: 'provider_unavailable' }); }, async () => ({ findings: [] })]) {
    const { url } = await fixture(t, { audit }); const response = await post(url, call()); const body = await response.json();
    const failure = JSON.parse(body.result.content[0].text);
    assert.equal(response.status, 200); assert.equal(body.result.isError, true); assert.equal(failure.status, 'error');
    assert.equal(body.result.structuredContent, undefined); assert.equal(failure.findings, undefined);
  }
});

test('MCP exposes Offense naming, continuation arguments and safe release/request diagnostics', async t => {
  const { url, calls } = await fixture(t);
  const init = await post(url, initialize, { 'X-Offense-Request-Id': 'caller-controlled' });
  assert.equal(init.status, 200); assert.equal(init.headers.get('x-offense-version'), OFFENSE_SERVICE_VERSION);
  assert.match(init.headers.get('x-offense-request-id'), /^[a-f0-9-]{36}$/);
  assert.notEqual(init.headers.get('x-offense-request-id'), 'caller-controlled');
  const initialized = await init.json();
  assert.equal(initialized.result.serverInfo.title, 'Offense Security');
  assert.equal(initialized.result.serverInfo.version, OFFENSE_SERVICE_VERSION);
  const listing = await (await post(url, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })).json();
  assert.match(listing.result.tools[0].description, /Use Purple/);
  assert.ok(listing.result.tools[0].inputSchema.properties.planning);
  const input = { ...args, planLimit: 1, planning: { metadataFingerprint: 'a'.repeat(64), pendingTargetIds: ['b'.repeat(64)] } };
  const response = await post(url, call({ params: { name: OFFENSE_MCP_TOOL, arguments: input } }));
  assert.equal(response.status, 200); assert.equal((await response.json()).result.isError, false);
  assert.deepEqual(calls[0].input, input);
});
