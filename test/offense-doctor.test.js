import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { doctor } from '../scripts/offense-audit-client.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'offense-doctor-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const installation = path.join(root, '.agents/skills/offense');
  await mkdir(path.join(installation, 'scripts'), { recursive: true });
  await writeFile(path.join(installation, 'SKILL.md'), '---\nname: offense\nmetadata:\n  version: "0.4.0"\n---\n');
  await writeFile(path.join(installation, 'scripts/offense.mjs'), '// inspected local helper');
  return { root, scriptUrl: pathToFileURL(path.join(installation, 'scripts/offense.mjs')).href };
}

function protocolFetch(requests, { sse = false } = {}) {
  return async (url, options) => {
    const input = JSON.parse(options.body);
    requests.push({ url: String(url), input, options });
    assert.equal(String(url), 'https://app.purpleteam.sh/mcp');
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.headers.authorization, undefined);
    assert.match(options.headers['user-agent'], /Purple-Offense-CLI/);
    let body;
    if (input.method === 'initialize') body = { jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} } } };
    else if (input.method === 'notifications/initialized') return new Response(null, { status: 202 });
    else if (input.method === 'tools/list') body = { jsonrpc: '2.0', id: 2, result: { tools: [{ name: 'offense.audit_dependencies' }] } };
    else assert.fail('Doctor attempted an audit or unsupported operation');
    const headers = { 'mcp-session-id': 'public-protocol-session', 'x-offense-request-id': 'fixture-request' };
    if (input.method !== 'initialize') assert.equal(options.headers['Mcp-Session-Id'], 'public-protocol-session');
    return sse ? new Response(`event: message\ndata: ${JSON.stringify(body)}\n\n`, { headers: { ...headers, 'content-type': 'text/event-stream' } }) : Response.json(body, { headers });
  };
}

test('doctor verifies the endpoint while keeping saved configuration and active-session readiness separate', async t => {
  const { root, scriptUrl } = await fixture(t), requests = [];
  await mkdir(path.join(root, '.codex'));
  await writeFile(path.join(root, '.codex/config.toml'), '[mcp_servers.offense]\nurl = "https://app.purpleteam.sh/mcp"\n[unrelated]\ntoken="DO-NOT-PRINT-OR-UPLOAD"');
  const result = await doctor(root, { scriptUrl, fetchImpl: protocolFetch(requests) });
  assert.equal(result.installation.status, 'files_present');
  assert.equal(result.installation.version, '0.4.0');
  assert.equal(result.projectConfiguration.status, 'requires_client_verification');
  assert.equal(result.projectConfiguration.files[0].endpointMentioned, true);
  assert.equal(result.endpoint.status, 'verified');
  assert.equal(result.endpoint.toolAdvertised, true);
  assert.equal(result.activeSession.status, 'not_observable_from_helper');
  assert.match(result.newSessionInstruction, /new coding-agent session in this same project/);
  assert.deepEqual(requests.map(item => item.input.method), ['initialize', 'notifications/initialized', 'tools/list']);
  assert.ok(!JSON.stringify([result, requests]).includes('DO-NOT-PRINT-OR-UPLOAD'));
});

test('doctor accepts bounded MCP event streams without claiming the host session loaded tools', async t => {
  const { root, scriptUrl } = await fixture(t), requests = [];
  const result = await doctor(root, { scriptUrl, fetchImpl: protocolFetch(requests, { sse: true }) });
  assert.equal(result.endpoint.status, 'verified');
  assert.equal(result.activeSession.status, 'not_observable_from_helper');
  assert.equal(result.projectConfiguration.status, 'not_observed');
});

test('doctor reports blocked clients with safe edge/request diagnostics instead of asking for credentials', async t => {
  const { root, scriptUrl } = await fixture(t);
  const result = await doctor(root, { scriptUrl, fetchImpl: async () => new Response('<html>PRIVATE-EDGE-DETAILS</html>', {
    status: 403, headers: { 'content-type': 'text/html', 'cf-ray': 'edge-fixture', 'x-request-id': 'request-fixture' }
  }) });
  assert.equal(result.endpoint.status, 'failed');
  assert.equal(result.endpoint.diagnostics.httpStatus, 403);
  assert.equal(result.endpoint.diagnostics.edgeRequestId, 'edge-fixture');
  assert.equal(result.endpoint.diagnostics.requestId, 'request-fixture');
  assert.match(result.endpoint.message, /does not require credentials/);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-EDGE-DETAILS'));
});

test('doctor rejects unsupported response identities, oversized responses and credential-bearing endpoints', async t => {
  const { root, scriptUrl } = await fixture(t);
  const wrongIdentity = await doctor(root, { scriptUrl, fetchImpl: async () => Response.json({ jsonrpc: '2.0', id: 999, result: { protocolVersion: '2025-03-26' } }) });
  assert.equal(wrongIdentity.endpoint.status, 'failed');
  assert.match(wrongIdentity.endpoint.message, /invalid result/);
  const oversized = await doctor(root, { scriptUrl, fetchImpl: async () => new Response('x'.repeat(256_001)) });
  assert.equal(oversized.endpoint.status, 'failed');
  assert.match(oversized.endpoint.message, /byte limit/);
  await assert.rejects(doctor(root, { scriptUrl, endpoint: 'https://secret:token@example.test', fetchImpl: () => assert.fail('Credential endpoint was requested') }), /without credentials/);
});

test('doctor does not follow project-settings links into another account scope', async t => {
  const { root, scriptUrl } = await fixture(t), outside = await mkdtemp(path.join(os.tmpdir(), 'offense-doctor-other-scope-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  await writeFile(path.join(outside, 'config.toml'), '[mcp_servers.offense]\nurl="https://app.purpleteam.sh/mcp"\ntoken="DO-NOT-READ-OUTSIDE"');
  await symlink(outside, path.join(root, '.codex'));
  const result = await doctor(root, { scriptUrl, fetchImpl: protocolFetch([]) });
  assert.equal(result.projectConfiguration.files[0].status, 'not_read');
  assert.match(result.projectConfiguration.files[0].reason, /outside this project/);
  assert.equal(result.projectConfiguration.files[0].endpointMentioned, undefined);
  assert.ok(!JSON.stringify(result).includes('DO-NOT-READ-OUTSIDE'));
});

test('doctor preview remains offline and paginated discovery can find the tool beyond the first page', async t => {
  const { root, scriptUrl } = await fixture(t);
  const offline = await doctor(root, { scriptUrl, preview: true, fetchImpl: () => assert.fail('Doctor preview made a request') });
  assert.equal(offline.endpoint.status, 'not_checked');
  const requests = [], standard = protocolFetch(requests);
  const result = await doctor(root, { scriptUrl, fetchImpl: async (url, options) => {
    const input = JSON.parse(options.body);
    if (input.method === 'tools/list' && !input.params.cursor) return Response.json({ jsonrpc: '2.0', id: input.id,
      result: { tools: [{ name: 'unrelated.tool' }], nextCursor: 'next-tool-page' } });
    if (input.method === 'tools/list') {
      assert.equal(input.params.cursor, 'next-tool-page');
      return Response.json({ jsonrpc: '2.0', id: input.id, result: { tools: [{ name: 'offense.audit_dependencies' }] } });
    }
    return standard(url, options);
  } });
  assert.equal(result.endpoint.status, 'verified');
  assert.equal(result.endpoint.discoveryPages, 2);
});
