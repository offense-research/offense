import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';
import { createOffenseClient, createAuditTool, createHostedScanClient, defaultAutomationPolicy,
  dependencyMetadataFingerprint, evaluateSecurityPolicy, assertSecurityDecision, SecurityGateError,
  claudeMcpOptions, opencodeMcpConfig, OFFENSE_API_URL, OFFENSE_SDK_VERSION } from '../sdk/index.mjs';
import { collectDependencyMetadata, checkRepository } from '../sdk/node.mjs';
import { automationMain } from '../scripts/offense-automation.mjs';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';

const execute = promisify(execFile);
const lock = () => ({ lockfileVersion: 3, name: 'PRIVATE-REPO', packages: {
  '': { dependencies: { semver: '^7.5.1' }, scripts: { postinstall: 'DO-NOT-RUN' } },
  'node_modules/semver': { version: '7.5.1', resolved: 'https://user:SECRET@private.invalid/package.tgz', integrity: 'PRIVATE-INTEGRITY' }
} });
const files = () => [{ path: 'package-lock.json', content: lock() }];
const blocking = () => ({ ...defaultAutomationPolicy(), preDeploy: true, agentRun: true,
  gate: { mode: 'block', minimumSeverity: 'high', onIncomplete: 'block' } });
const normalizedFinding = severity => ({ id: 'a'.repeat(64), advisoryId: 'SYNTHETIC-SDK-1', severity,
  package: { name: 'semver', installedVersion: '7.5.1', lockfiles: ['package-lock.json'] }, verification: { status: 'advisory_match', confirmed: false } });
async function reportFor(dependencyFiles = files(), { severity, partial = false } = {}) {
  const findings = severity ? [normalizedFinding(severity)] : [];
  return { schemaVersion: 'offense.audit.v1', capability: 'audit_dependencies', status: partial ? 'partial' : 'complete', scannedAt: Date.now(),
    metadataFingerprint: await dependencyMetadataFingerprint(dependencyFiles), findings,
    coverage: { status: partial ? 'partial' : 'complete', checkedPackages: 1, skippedPackages: 0, warnings: [] },
    summary: { advisoryMatches: findings.length, confirmedVulnerabilities: 0 }, remediation: { plans: [], blockers: [] }, providers: [{ id: 'osv' }] };
}
async function temporary(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-agent-security-'));
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function repository(t) {
  const directory = await temporary(t);
  await writeFile(path.join(directory, 'package-lock.json'), JSON.stringify(lock()));
  await writeFile(path.join(directory, 'package.json'), JSON.stringify({ private: true, scripts: { postinstall: 'DO-NOT-RUN' } }));
  await writeFile(path.join(directory, '.npmrc'), 'NPM_TOKEN=SECRET-NPMRC');
  await writeFile(path.join(directory, '.env'), 'SECRET_ENV=DO-NOT-READ');
  await writeFile(path.join(directory, 'source.js'), 'SOURCE-DO-NOT-UPLOAD');
  return directory;
}
async function server(t, configure) {
  const app = express(); await configure(app);
  const instance = app.listen(0, '127.0.0.1'); await new Promise(resolve => instance.once('listening', resolve));
  t.after(async () => { instance.closeAllConnections(); await new Promise(resolve => instance.close(resolve)); });
  return `http://127.0.0.1:${instance.address().port}`;
}

test('portable SDK audits through actual shared HTTP handlers with matching metadata and original confidence', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let checkedPackages, uploaded;
  const baseUrl = await server(t, app => {
    app.use(express.json({ limit: '2mb' }));
    app.use((req, res, next) => { uploaded = req.body; next(); });
    const intelligence = createDependencyIntelligence({ db, traceEnabled: false,
      check: async packages => { checkedPackages = packages; return { status: 'complete', checkedAt: Date.now(), checkedPackages: packages.length, skippedPackages: 0,
        findings: [{ id: 'SYNTHETIC-SDK-1', package: 'semver', version: '7.5.1', severity: 'HIGH', summary: 'Synthetic input processing issue', fixedVersions: ['7.5.2'] }] }; } });
    registerOffenseApi(app, { intelligence, publicUrl: 'http://127.0.0.1' });
  });
  const telemetry = [], client = createOffenseClient({ baseUrl, onEvent: value => telemetry.push(value) });
  const result = await client.check({ files: files(), event: 'pre_deploy', policy: blocking() });
  assert.equal(result.decision.action, 'block'); assert.equal(result.decision.passed, false);
  assert.equal(result.report.summary.confirmedVulnerabilities, 0);
  assert.equal(result.report.findings[0].verification.confirmed, false);
  assert.equal(result.report.findings[0].impact.applicationExposure.status, 'not_assessed');
  assert.equal(checkedPackages[0].name, 'semver'); assert.equal(uploaded.planLimit, 0);
  for (const secret of ['SECRET', 'PRIVATE-REPO', 'DO-NOT-RUN', 'private.invalid', 'PRIVATE-INTEGRITY']) assert.ok(!JSON.stringify(uploaded).includes(secret));
  assert.equal(telemetry.length, 2); assert.equal(telemetry[1].advisoryMatches, 1);
  assert.doesNotMatch(JSON.stringify(telemetry), /semver|SYNTHETIC|PRIVATE|SECRET|source/);
});

test('disabled lifecycle checks skip before collecting or transmitting dependency data', async () => {
  let calls = 0;
  const client = createOffenseClient({ fetchImpl: async () => { calls++; throw Error('Should not be called'); } });
  const result = await checkRepository({ directory: '/path/that/does/not/exist', event: 'pre_deploy', client });
  assert.equal(result.decision.action, 'skip'); assert.equal(result.decision.passed, null);
  assert.equal(result.localCoverage.status, 'not_checked'); assert.equal(calls, 0);
  assert.throws(() => assertSecurityDecision(result.decision, { requirePassed: true }), SecurityGateError);
});

test('provider failures, malformed output, unknown severity and stale evidence cannot pass a configured gate', async () => {
  const cases = [
    async () => { throw Error('Network canary SECRET'); },
    async () => Response.json({ status: 'complete', findings: [] }),
    async () => new Response('<html>not JSON</html>'),
    async () => Response.json(await reportFor(files(), { severity: 'unknown' })),
    async () => Response.json({ ...await reportFor(), scannedAt: 1 }),
    async () => new Response('SECRET ERROR BODY', { status: 503 })
  ];
  for (const fetchImpl of cases) {
    const result = await createOffenseClient({ fetchImpl }).check({ files: files(), policy: blocking(), event: 'pre_deploy' });
    assert.equal(result.decision.action, 'block'); assert.equal(result.decision.passed, null);
    assert.doesNotMatch(JSON.stringify(result), /SECRET|Network canary|ERROR BODY/);
  }
});

test('report fingerprints bind exact submitted versions rather than a previous clean report', async () => {
  const report = await reportFor();
  const changed = files(); changed[0].content.packages['node_modules/semver'].version = '8.0.0';
  const result = await createOffenseClient({ fetchImpl: async () => Response.json(report) }).check({ files: changed, policy: blocking(), event: 'pre_deploy' });
  assert.equal(result.error.code, 'metadata_mismatch'); assert.equal(result.decision.action, 'block'); assert.equal(result.decision.passed, null);
});

test('response size bounds are enforced before parsing and telemetry errors cannot change a result', async () => {
  const oversized = await createOffenseClient({ maximumResponseBytes: 1024,
    fetchImpl: async () => new Response('x'.repeat(1025)) }).check({ files: files(), policy: blocking(), event: 'pre_deploy' });
  assert.equal(oversized.error.code, 'response_limit'); assert.equal(oversized.decision.action, 'block');
  const clean = await createOffenseClient({ fetchImpl: async () => Response.json(await reportFor()), onEvent: () => { throw Error('Telemetry offline'); } })
    .check({ files: files(), policy: blocking(), event: 'pre_deploy' });
  assert.equal(clean.decision.action, 'allow'); assert.equal(clean.decision.passed, true);
});

test('SDK rejects unsafe endpoints and never follows redirects or includes browser credentials', async () => {
  for (const baseUrl of ['http://public.invalid', 'https://user:secret@example.com', 'https://example.com/path', 'https://example.com/?secret=value'])
    assert.throws(() => createOffenseClient({ baseUrl }));
  let request;
  const client = createOffenseClient({ fetchImpl: async (url, options) => { request = { url, options }; return Response.json(await reportFor()); } });
  await client.audit({ files: files() });
  assert.equal(request.url, 'https://offense.sh/api/offense/audit');
  assert.equal(request.options.redirect, 'manual'); assert.equal(request.options.credentials, 'omit');
  assert.equal(request.options.headers.authorization, undefined);
});

test('real redirects are rejected before any dependency payload or scanner credential reaches another origin', async t => {
  let destinationCalls = 0;
  const destination = await server(t, app => app.use((req, res) => { destinationCalls++; res.json({}); }));
  const source = await server(t, app => app.use((req, res) => res.redirect(307, `${destination}/unexpected`)));
  const result = await createOffenseClient({ baseUrl: source }).check({ files: files(), policy: blocking(), event: 'pre_deploy' });
  assert.equal(result.decision.action, 'block'); assert.equal(result.error.code, 'http_error'); assert.equal(result.error.status, 307);
  const scans = createHostedScanClient({ baseUrl: source, apiKey: `purple_scan_${'c'.repeat(64)}` });
  await assert.rejects(() => scans.tools(), error => error.code === 'http_error' && error.status === 307);
  assert.equal(destinationCalls, 0);
});

test('repository collection uploads only sanitized lockfile metadata and does not run scripts', async t => {
  const directory = await repository(t), metadata = await collectDependencyMetadata(directory);
  assert.equal(metadata.inspectedLockfiles, 1); assert.deepEqual(metadata.warnings, []);
  const text = JSON.stringify(metadata);
  for (const secret of ['SECRET', 'DO-NOT-RUN', 'SOURCE-DO-NOT-UPLOAD', 'private.invalid', '.npmrc', 'SECRET_ENV']) assert.ok(!text.includes(secret));
  assert.ok(text.includes('semver')); assert.ok(text.includes('7.5.1'));
});

test('uncovered projects, unsupported managers and symlinks retain incomplete local coverage', async t => {
  const directory = await repository(t), external = await temporary(t);
  await mkdir(path.join(directory, 'nested'));
  await writeFile(path.join(directory, 'nested/package.json'), '{}');
  await writeFile(path.join(directory, 'yarn.lock'), '# unsupported');
  await writeFile(path.join(external, 'package-lock.json'), JSON.stringify(lock()));
  await symlink(external, path.join(directory, 'linked'));
  const client = createOffenseClient({ fetchImpl: async (url, options) => Response.json(await reportFor(JSON.parse(options.body).files)) });
  const result = await checkRepository({ directory, policy: blocking(), event: 'pre_deploy', client });
  assert.equal(result.decision.action, 'block'); assert.equal(result.decision.passed, null);
  assert.equal(result.localCoverage.status, 'incomplete');
  assert.ok(result.localCoverage.warnings.some(value => value.includes('nested/package.json')));
  assert.ok(result.localCoverage.warnings.some(value => value.includes('yarn.lock')));
  assert.ok(result.localCoverage.warnings.some(value => value.includes('symlink')));
  assert.equal(result.report.coverage.status, 'partial');
});

test('sanitizer omissions stay partial even when a provider fixture claims complete coverage', async () => {
  const input = files(); input[0].content.packages['node_modules/unsupported'] = { version: 'git+https://SECRET@private.invalid' };
  const client = createOffenseClient({ fetchImpl: async (url, options) => Response.json(await reportFor(JSON.parse(options.body).files)) });
  const result = await client.check({ files: input, policy: blocking(), event: 'pre_deploy' });
  assert.equal(result.report.status, 'partial'); assert.equal(result.decision.action, 'block'); assert.equal(result.decision.passed, null);
});

test('custom tool policy and lifecycle are host-controlled and cannot be overridden by model arguments', async () => {
  let checked;
  const tool = createAuditTool({ policy: blocking(), event: 'agent_run', client: { check: async input => { checked = input; return { decision: 'fixture' }; } } });
  assert.equal(tool.name, 'offense_audit_dependencies');
  assert.throws(() => tool.execute({ files: files(), policy: { enabled: false } }));
  assert.throws(() => tool.execute({ files: files(), event: 'manual' }));
  await tool.execute({ files: files() });
  assert.equal(checked.event, 'agent_run'); assert.equal(checked.policy.gate.mode, 'block');
});

test('CLI policy controls gating, explicit missing-evidence override and disabled trigger exit codes', async t => {
  const directory = await repository(t), policyFile = path.join(directory, 'offense.config.json');
  const run = async (policy, fetchImpl, event = 'pre_deploy') => {
    await writeFile(policyFile, JSON.stringify(policy)); const output = [], errors = [];
    const code = await automationMain(['--event', event, '--policy', policyFile, directory], { stdout: value => output.push(value), stderr: value => errors.push(value), fetchImpl });
    return { code, output: output[0] && JSON.parse(output[0]), errors };
  };
  const risk = async (url, options) => Response.json(await reportFor(JSON.parse(options.body).files, { severity: 'high' }));
  const blocked = await run(blocking(), risk); assert.equal(blocked.code, 1); assert.equal(blocked.output.decision.action, 'block');
  const unavailable = async () => { throw Error('Network unavailable'); };
  const failClosed = await run(blocking(), unavailable); assert.equal(failClosed.code, 1); assert.equal(failClosed.output.decision.passed, null);
  const override = { ...blocking(), gate: { ...blocking().gate, onIncomplete: 'report' } };
  const permittedUnknown = await run(override, unavailable); assert.equal(permittedUnknown.code, 0); assert.equal(permittedUnknown.output.decision.passed, null);
  assert.match(permittedUnknown.errors.join(' '), /not a passing security check/);
  const stillBlocked = await run(override, risk); assert.equal(stillBlocked.code, 1);
  const paused = await run(defaultAutomationPolicy(), unavailable); assert.equal(paused.code, 3); assert.equal(paused.output.decision.action, 'skip');
  const post = await run({ ...blocking(), postDeploy: true }, risk, 'post_deploy'); assert.equal(post.code, 0); assert.equal(post.output.decision.action, 'report'); assert.equal(post.output.decision.passed, false);
});

test('invalid or overlarge CLI configuration never invokes a provider or prints policy contents', async t => {
  const directory = await repository(t), policyFile = path.join(directory, 'policy.json');
  let calls = 0; const output = [], errors = [];
  await writeFile(policyFile, JSON.stringify({ SECRET_POLICY: 'SHOULD-NOT-PRINT' }));
  const code = await automationMain(['--policy', policyFile, directory], { stdout: value => output.push(value), stderr: value => errors.push(value), fetchImpl: async () => { calls++; } });
  assert.equal(code, 2); assert.equal(calls, 0); assert.deepEqual(output, []); assert.doesNotMatch(errors.join(' '), /SHOULD-NOT-PRINT|SECRET_POLICY/);
});

test('MCP helpers configure official SDK transport shapes without claiming enforced lifecycle checks', () => {
  assert.equal(OFFENSE_API_URL, 'https://offense.sh');
  assert.deepEqual(claudeMcpOptions(), { mcpServers: { offense: { type: 'http', url: 'https://offense.sh/mcp' } }, allowedTools: ['mcp__offense__*'] });
  assert.deepEqual(opencodeMcpConfig(), { mcp: { offense: { type: 'remote', url: 'https://offense.sh/mcp', enabled: true, oauth: false, timeout: 120000 } } });
  assert.equal(claudeMcpOptions({ baseUrl: 'https://app.purpleteam.sh' }).mcpServers.offense.url, 'https://app.purpleteam.sh/mcp');
  assert.equal(opencodeMcpConfig({ baseUrl: 'https://self-hosted.example' }).mcp.offense.url, 'https://self-hosted.example/mcp');
});

test('SDK uses the canonical hosted origin while preserving explicit legacy integrations', async () => {
  const apiKey = `offense_sk_${'a'.repeat(64)}`;
  for (const baseUrl of [undefined, 'https://app.purpleteam.sh']) {
    let called;
    const scans = createHostedScanClient({ apiKey, ...(baseUrl ? { baseUrl } : {}), fetchImpl: async (url, options) => {
      called = url; assert.equal(options.headers.authorization, `Bearer ${apiKey}`);
      return Response.json({ tools: [{ id: 'opengrep' }] });
    } });
    await scans.tools();
    assert.equal(called, `${baseUrl || 'https://offense.sh'}/v1/tools`);
  }
});

test('SDK rejects malformed, unknown and mismatched job receipts without retrying a paid submission', async () => {
  const apiKey = `offense_sk_${'b'.repeat(64)}`, scanId = 'a'.repeat(32), wrongId = 'b'.repeat(32);
  for (const receipt of [{ id: scanId, status: 'success' }, { id: 'invalid', status: 'completed' }, { id: scanId }]) {
    let submissions = 0;
    const client = createHostedScanClient({ apiKey, fetchImpl: async (url, options) => {
      if (url.endsWith('/v1/quotes')) { const input = JSON.parse(options.body); return Response.json({ ...input,
        currency: 'usd', billable: true, toolIds: input.tools, maximumMicros: 100_000 }); }
      submissions++; return Response.json(receipt);
    } });
    const quote = await client.quote({ tools: ['opengrep'], inputBytes: 3, fileCount: 1 });
    await assert.rejects(client.submit({ input: { tools: ['opengrep'], files: [{ path: 'app.js', content: 'abc' }] }, quote,
      maxChargeMicros: 100_000, idempotencyKey: 'stable-sdk-job' }), { code: 'invalid_response' });
    assert.equal(submissions, 1);
  }
  for (const receipt of [{ id: wrongId, status: 'completed' }, { id: scanId, status: 'succeeded' }]) {
    const client = createHostedScanClient({ apiKey, fetchImpl: async () => Response.json(receipt) });
    await assert.rejects(client.get(scanId), { code: 'invalid_response' });
  }
  for (const status of ['queued', 'starting', 'running', 'completed', 'partial', 'failed']) {
    const client = createHostedScanClient({ apiKey, fetchImpl: async () => Response.json({ id: scanId, status }) });
    assert.equal((await client.get(scanId)).status, status);
  }
});

test('metered SDK requires a known quote, explicit spending cap and idempotency before source upload', async t => {
  const apiKey = `purple_scan_${'f'.repeat(64)}`, requests = [], scanId = 'a'.repeat(32);
  const baseUrl = await server(t, app => {
    app.use(express.json()); app.use((req, res, next) => { requests.push({ method: req.method, path: req.path, headers: req.headers, body: req.body }); next(); });
    app.get('/v1/tools', (req, res) => res.json({ tools: [{ id: 'opengrep' }] }));
    app.post('/v1/quotes', (req, res) => res.json({ currency: 'usd', billable: true, toolIds: req.body.tools,
      inputBytes: req.body.inputBytes, fileCount: req.body.fileCount, maximumMicros: 100_000 }));
    app.post('/v1/scans', (req, res) => res.status(202).json({ id: scanId, status: 'queued' }));
    app.get(`/v1/scans/${scanId}`, (req, res) => res.json({ id: scanId, status: 'completed', findings: [], coverage: {} }));
  });
  const scans = createHostedScanClient({ apiKey, baseUrl });
  assert.equal((await scans.tools()).tools[0].id, 'opengrep');
  const input = { tools: ['opengrep'], files: [{ path: 'example.js', content: 'abc' }] };
  const quote = await scans.quote({ tools: input.tools, inputBytes: 3, fileCount: 1 });
  await assert.rejects(() => scans.submit({ input, quote, maxChargeMicros: 99_999, idempotencyKey: 'stable-host-job' }));
  await assert.rejects(() => scans.submit({ input, quote: { ...quote }, maxChargeMicros: 100_000, idempotencyKey: 'stable-host-job' }));
  await assert.rejects(() => scans.submit({ input: { ...input, files: [{ path: 'example.js', content: 'longer' }] }, quote, maxChargeMicros: 100_000, idempotencyKey: 'stable-host-job' }));
  assert.equal(requests.filter(value => value.path === '/v1/scans').length, 0);
  const job = await scans.submit({ input, quote, maxChargeMicros: 200_000, idempotencyKey: 'stable-host-job' });
  assert.equal(job.status, 'queued');
  const submission = requests.find(value => value.path === '/v1/scans');
  assert.equal(submission.body.maxChargeMicros, 100_000, 'The actual accepted quote is the server-side charge ceiling.');
  assert.equal(submission.headers['idempotency-key'], 'stable-host-job');
  assert.equal(submission.headers.authorization, `Bearer ${apiKey}`);
  assert.equal((await scans.get(scanId)).status, 'completed');
  assert.equal(JSON.stringify(scans).includes(apiKey), false);
});

test('metered SDK uses actual key-scoped scanner routes, ledger settlement and durable usage attribution', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const prices = JSON.parse(await readFile('config/scanner-prices.json', 'utf8'));
  const metering = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  metering.recordVerifiedPurchase({ workspaceId: 'sdk-workspace', paymentId: 'sdk-payment-fixture', amountMicros: 1_000_000 });
  let result = { status: 'running' }, executions = 0;
  const scans = createHostedScans(db, { metering,
    encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString(),
    sandbox: { start: async () => { executions++; return { status: 'running' }; }, get: async () => result, destroy: async () => {} } });
  const key = scans.issueKey('sdk-workspace', 'sdk-user'), other = scans.issueKey('other-workspace', 'other-user');
  assert.match(key.token, /^offense_sk_[a-f0-9]{64}$/, 'The SDK must accept the key format issued by the current server.');
  const baseUrl = await server(t, app => registerScanApi(app, { scans, dispatch: () => {} }));
  const client = createHostedScanClient({ baseUrl, apiKey: key.token });
  assert.ok((await client.tools()).tools.some(tool => tool.id === 'opengrep'));
  const quote = await client.quote({ tools: ['opengrep'], inputBytes: 3, fileCount: 1 });
  const input = { tools: ['opengrep'], files: [{ path: 'example.js', content: 'abc' }] };
  const job = await client.submit({ input, quote, maxChargeMicros: quote.maximumMicros, idempotencyKey: 'sdk-real-route-fixture' });
  assert.equal((await client.submit({ input, quote, maxChargeMicros: quote.maximumMicros, idempotencyKey: 'sdk-real-route-fixture' })).id, job.id);
  assert.equal((await client.usage()).availableMicros, 1_000_000 - quote.maximumMicros);
  await scans.dispatch(); assert.equal(executions, 1);
  result = { status: 'completed', tools: [{ name: 'opengrep', status: 'complete', durationMs: 100 }], findings: [] };
  await scans.dispatch();
  const completed = await client.get(job.id);
  assert.equal(completed.status, 'completed'); assert.equal(completed.metering.chargeMicros, quote.maximumMicros);
  const usage = await client.usage(); assert.equal(usage.jobs[0].id, job.id); assert.ok(usage.analytics);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_usage_jobs WHERE workspace_id = ?').get('sdk-workspace').n, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_usage_jobs WHERE workspace_id = ?').get('other-workspace').n, 0);
  await assert.rejects(() => createHostedScanClient({ baseUrl, apiKey: other.token }).get(job.id), error => error.status === 404);
});

test('metered SDK refuses source containing its key and does not retry an uncertain paid submission', async () => {
  const apiKey = `purple_scan_${'e'.repeat(64)}`; let submits = 0;
  const scans = createHostedScanClient({ apiKey, fetchImpl: async (url, options) => {
    if (url.endsWith('/v1/quotes')) { const input = JSON.parse(options.body); return Response.json({ currency: 'usd', billable: true,
      toolIds: input.tools, inputBytes: input.inputBytes, fileCount: input.fileCount, maximumMicros: 100_000 }); }
    submits++; throw Error(`SECRET ${apiKey}`);
  } });
  const quote = await scans.quote({ tools: ['opengrep'], inputBytes: apiKey.length, fileCount: 1 });
  await assert.rejects(() => scans.submit({ input: { tools: ['opengrep'], files: [{ path: 'example.js', content: apiKey }] }, quote,
    maxChargeMicros: 100_000, idempotencyKey: 'stable-host-job' }), error => !error.message.includes(apiKey));
  assert.equal(submits, 0);
  const safeQuote = await scans.quote({ tools: ['opengrep'], inputBytes: 3, fileCount: 1 });
  await assert.rejects(() => scans.submit({ input: { tools: ['opengrep'], files: [{ path: 'example.js', content: 'abc' }] }, quote: safeQuote,
    maxChargeMicros: 100_000, idempotencyKey: 'stable-host-job' }), error => !error.message.includes(apiKey));
  assert.equal(submits, 1, 'An uncertain billable submission is not automatically retried.');
});

function archiveFiles(archive) {
  const files = new Map();
  for (let offset = 0; offset + 512 <= archive.length;) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) break;
    const name = header.subarray(0, 100).toString().replace(/\0.*$/, ''), size = Number.parseInt(header.subarray(124, 136).toString().replace(/\0.*$/, ''), 8);
    assert.match(name, /^package\/[a-zA-Z0-9./-]+$/); assert.ok(!name.split('/').includes('..'));
    assert.equal(Number.parseInt(header.subarray(136, 148).toString(), 8), 0, 'Archive mtime is fixed.');
    files.set(name, archive.subarray(offset + 512, offset + 512 + size)); offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

test('downloaded SDK archive is standalone and its deployment wrapper enforces a gate before calling deploy', async t => {
  const destination = await temporary(t), archive = archiveFiles(gunzipSync(await readFile('public/downloads/offense-sdk.tgz')));
  for (const [name, bytes] of archive) { const filename = path.join(destination, name); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes); }
  const pkg = JSON.parse(archive.get('package/package.json')); assert.equal(pkg.name, '@purpleteam/offense'); assert.equal(pkg.private, true); assert.equal(pkg.dependencies, undefined);
  assert.ok(archive.has('package/index.d.ts')); assert.ok(archive.has('package/node.d.ts'));
  const sdk = await import(pathToFileURL(path.join(destination, 'package/dist/index.mjs')).href);
  assert.equal(pkg.version, OFFENSE_SDK_VERSION);
  assert.equal(sdk.OFFENSE_SDK_VERSION, OFFENSE_SDK_VERSION);
  assert.equal(sdk.OFFENSE_API_URL, OFFENSE_API_URL);
  const { deployWithSecurity } = await import(pathToFileURL(path.join(destination, 'package/examples/deploy.mjs')).href);
  const directory = await repository(t); let deploys = 0;
  const risk = await reportFor(files(), { severity: 'high' }), clean = await reportFor();
  const clientFor = report => ({ check: async input => ({ report, decision: evaluateSecurityPolicy(report, input.policy, input.event), durationMs: 1 }) });
  await assert.rejects(() => deployWithSecurity({ directory, trustedPolicy: blocking(), deploy: async () => { deploys++; }, client: clientFor(risk) }), error => error.name === 'SecurityGateError');
  assert.equal(deploys, 0);
  const result = await deployWithSecurity({ directory, trustedPolicy: { ...blocking(), postDeploy: true }, deploy: async () => { deploys++; return { id: 'deployment-1' }; }, client: clientFor(clean) });
  assert.equal(deploys, 1); assert.equal(result.before.decision.action, 'allow'); assert.equal(result.after.decision.action, 'report');
});

test('Claude and OpenCode examples gate runs without invoking a real provider and preserve other MCP configuration', async t => {
  const destination = await temporary(t), archive = archiveFiles(gunzipSync(await readFile('public/downloads/offense-sdk.tgz')));
  for (const [name, bytes] of archive) { const filename = path.join(destination, name); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes); }
  const { runClaudeWithSecurity } = await import(pathToFileURL(path.join(destination, 'package/examples/claude-agent.mjs')).href);
  const { runOpenCodeWithSecurity } = await import(pathToFileURL(path.join(destination, 'package/examples/opencode-agent.mjs')).href);
  const directory = await repository(t), risk = await reportFor(files(), { severity: 'high' }), clean = await reportFor();
  const clientFor = report => ({ check: async input => ({ report, decision: evaluateSecurityPolicy(report, input.policy, input.event), durationMs: 1 }) });
  let calls = 0, options;
  const query = async function* (input) { calls++; options = input.options; yield { type: 'result', subtype: 'success' }; };
  await assert.rejects(async () => { for await (const item of runClaudeWithSecurity({ query, directory, trustedPolicy: blocking(), prompt: 'fixture', client: clientFor(risk) })) void item; });
  assert.equal(calls, 0);
  const messages = [];
  for await (const item of runClaudeWithSecurity({ query, directory, trustedPolicy: blocking(), prompt: 'fixture', client: clientFor(clean),
    options: { mcpServers: { existing: { type: 'http', url: 'https://example.org/mcp' } }, allowedTools: ['existing-tool'] } })) messages.push(item);
  assert.equal(calls, 1); assert.equal(messages[0].type, 'security_decision'); assert.ok(options.mcpServers.existing); assert.ok(options.mcpServers.offense); assert.ok(options.allowedTools.includes('existing-tool'));
  let created = 0, closed = 0, configuration;
  const createOpencode = async input => { created++; configuration = input.config; return { server: { close: () => { closed++; } },
    client: { session: { create: async () => ({ data: { id: 'fixture-session' } }), prompt: async input => ({ data: input }) } } }; };
  await assert.rejects(() => runOpenCodeWithSecurity({ createOpencode, directory, trustedPolicy: blocking(), prompt: 'fixture', client: clientFor(risk) }));
  assert.equal(created, 0);
  await runOpenCodeWithSecurity({ createOpencode, directory, trustedPolicy: blocking(), prompt: 'fixture', client: clientFor(clean),
    config: { mcp: { existing: { type: 'remote', url: 'https://example.org/mcp' } } } });
  assert.equal(created, 1); assert.equal(closed, 1); assert.ok(configuration.mcp.existing); assert.ok(configuration.mcp.offense);
});

test('standalone downloaded lifecycle helper runs outside the repository without npm dependencies', async t => {
  const destination = await temporary(t), directory = await repository(t), helper = path.join(destination, 'offense-automation.mjs');
  await writeFile(helper, await readFile('public/downloads/offense-automation.mjs'));
  const defaults = await execute(process.execPath, [helper, '--print-default-policy'], { cwd: destination });
  assert.equal(JSON.parse(defaults.stdout).preDeploy, false);
  const baseUrl = await server(t, app => { app.use(express.json()); app.post('/api/offense/audit', async (req, res) => res.json(await reportFor(req.body.files))); });
  const policyFile = path.join(destination, 'policy.json'); await writeFile(policyFile, JSON.stringify(blocking()));
  const executed = await execute(process.execPath, [helper, '--event', 'pre_deploy', '--policy', policyFile, '--endpoint', baseUrl, directory], { cwd: destination });
  const result = JSON.parse(executed.stdout); assert.equal(result.decision.action, 'allow'); assert.equal(result.decision.passed, true);
});
