// Opt-in real Docker acceptance check. Disposable local state; no hosted keys,
// billing, uploads, account login or production services are used.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const run = promisify(execFile), wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const directory = await mkdtemp(path.join(tmpdir(), 'offense-self-host-test-'));
const state = path.join(directory, 'state');
const lease = createServer().listen(0, '127.0.0.1'); await once(lease, 'listening');
const port = lease.address().port; await new Promise(resolve => lease.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const env = { PATH: process.env.PATH, HOME: directory, PORT: String(port), PUBLIC_URL: origin };
let server, client;
const jobs = [];
async function start() {
  server = spawn(process.execPath, [`--env-file=${state}/server.env`, 'server/index.js'], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  server.stderr.resume();
  for (let n = 0; n < 100; n++) {
    if (server.exitCode !== null) throw new Error('Self-hosted server exited before readiness.');
    try { if ((await fetch(`${origin}/v1/catalog`)).ok) return; } catch {}
    await wait(100);
  }
  throw new Error('Self-hosted server readiness deadline exceeded.');
}
async function stop() {
  if (server && server.exitCode === null) { const exited = once(server, 'exit'); server.kill('SIGTERM'); await exited; }
}
try {
  await assert.rejects(run(process.execPath, ['scripts/init-self-host.mjs', '.self-host-test-state'], { env }), /outside the source checkout/);
  await run(process.execPath, ['scripts/init-self-host.mjs', state], { env });
  await assert.rejects(run(process.execPath, ['scripts/init-self-host.mjs', state], { env }));
  const { key, keyId } = JSON.parse(await readFile(`${state}/api-key.json`, 'utf8'));
  const auth = { authorization: `Bearer ${key}`, 'content-type': 'application/json' };
  await start();
  const request = async (route, body, id) => {
    const response = await fetch(origin + route, { headers: { ...auth, ...(id ? { 'idempotency-key': id } : {}) },
      ...(body ? { method: 'POST', body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
  };
  const catalog = (await request('/v1/catalog')).body;
  assert.deepEqual(catalog.tools.filter(tool => tool.availability === 'available').map(tool => tool.id).sort(), ['dependency-audit', 'opengrep', 'zizmor']);
  assert.equal(catalog.billing.enabled, false);
  assert.equal((await fetch(`${origin}/v1/account`)).status, 401);
  assert.equal((await request('/v1/call/trivy-vuln', { files: [{ path: 'x.js', content: '1' }], maxChargeMicros: 0 }, 'disabled-tool')).status, 503);
  const cli = await run(process.execPath, ['scripts/offense-cli.mjs', 'tools', '--json'],
    { env: { ...env, OFFENSE_API_KEY: key, OFFENSE_API_URL: origin } });
  assert.ok(cli.stdout.includes('opengrep'));
  assert.ok(!cli.stdout.includes(key));
  client = new Client({ name: 'self-host-acceptance', version: '1' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: auth } }));
  const mcp = async (name, args) => {
    const result = await client.callTool({ name: `offense.${name}`, arguments: args });
    assert.notEqual(result.isError, true);
    return result.structuredContent || JSON.parse(result.content[0].text);
  };
  assert.ok((await client.listTools()).tools.some(tool => tool.name === 'offense.security_call'));
  const cases = [
    { id: 'positive-source', tool: 'opengrep', file: 'app.js', content: 'export function run(req) { return eval(req.query.code); }', positive: true },
    { id: 'safe-source', tool: 'opengrep', file: 'app.js', content: 'export function run(req) { return String(req.query.code); }', positive: false },
    { id: 'positive-workflow', tool: 'zizmor', file: '.github/workflows/ci.yml', content: 'name: Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n', positive: true },
    { id: 'safe-workflow', tool: 'zizmor', file: '.github/workflows/ci.yml', content: 'name: Test\non: push\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          persist-credentials: false\n', positive: false },
    { id: 'invalid-source', tool: 'opengrep', file: 'app.js', content: 'function broken( {', positive: false, status: 'partial' }
  ];
  for (const item of cases) {
    const quote = await mcp('security_quote', { tool: item.tool, inputBytes: Buffer.byteLength(item.content), fileCount: 1 });
    assert.equal(quote.maximumMicros, 0);
    const args = { tool: item.tool, input: { files: [{ path: item.file, content: item.content }] }, maxChargeMicros: 0, idempotencyKey: item.id };
    const job = await mcp('security_call', args); jobs.push(job.id);
    assert.equal((await mcp('security_call', args)).id, job.id);
    let result;
    for (let n = 0; n < 100; n++) {
      result = (await request(`/v1/scans/${job.id}`)).body;
      if (['completed', 'partial', 'failed'].includes(result.status)) break;
      await wait(300);
    }
    assert.equal(result.status, item.status || 'completed', JSON.stringify(result.tools));
    assert.equal(result.metering.chargeMicros, 0);
    assert.equal(result.findings.some(finding => finding.tool === item.tool), item.positive);
    if (item.tool === 'opengrep' && item.positive) assert.ok(result.findings.some(finding => /dynamic-eval/.test(finding.ruleId)));
    if (item.tool === 'zizmor' && item.positive) assert.ok(result.findings.some(finding => /unpinned-uses/.test(finding.ruleId)));
    assert.equal((await mcp('security_result', { id: job.id })).status, item.status || 'completed');
  }
  await client.close(); client = null;
  await stop(); await start();
  assert.equal((await request(`/v1/scans/${jobs[0]}`)).body.status, 'completed');
  await stop();
  const db = new DatabaseSync(`${state}/purple.sqlite`);
  try {
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_cleanup').get().n, 0);
    db.prepare('UPDATE scan_keys SET revoked_at = 1 WHERE id = ?').run(keyId);
  } finally { db.close(); }
  await start();
  assert.equal((await request('/v1/account')).status, 401);
  console.log(JSON.stringify({ passed: true, realEngines: ['opengrep', 'zizmor'],
    sourcePositiveAndSafe: true, workflowPositiveAndSafe: true, invalidSourcePartial: true, cliDiscovery: true, mcpExecution: true,
    unauthenticatedRejected: true, unsupportedDisabled: true, idempotent: true,
    zeroCharges: true, persistedAcrossRestart: true, sourceDeleted: true, revokedKeyRejected: true }));
} finally {
  await client?.close(); await stop();
  for (const id of jobs) await run('docker', ['rm', '--force', `offense-source-${id}`]).catch(() => {});
  await rm(directory, { recursive: true, force: true });
}
