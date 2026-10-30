import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile, writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { builtinModules } from 'node:module';
import { request as httpRequest } from 'node:http';
import { createHash, webcrypto } from 'node:crypto';
import { gzipSync, deflateSync } from 'node:zlib';
import { OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';

const artifact = process.argv[2] || '/tmp/purple-offense-release.js';
const reportPath = process.argv[3] || '/tmp/purple-offense-artifact-validation.json';
const report = { artifact, checkedAt: new Date().toISOString(), checks: [], outbound: [], evalDisabled: true, providerCallsOnlyFixtures: true };
const source = await readFile(artifact, 'utf8');
const releaseProof = JSON.parse(await readFile(artifact.replace(/\.js$/, '') + '-proof.json', 'utf8'));
const factoryBinding = releaseProof.validationFactoryName || 'createWorkerApp';
report.artifactSha256 = createHash('sha256').update(source).digest('hex');
const advisory = { id: 'GHSA-fixture-semver', aliases: ['CVE-2022-25883'], summary: 'Fixture advisory', details: 'Synthetic advisory evidence.',
  modified: '2026-10-20T00:00:00Z', affected: [{ package: { name: 'semver', ecosystem: 'npm' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '7.5.2' }] }], database_specific: { severity: 'HIGH' } }],
  references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/GHSA-fixture-semver' }] };
const extraPackages = ['fixture-alpha', 'fixture-beta', 'fixture-gamma', 'fixture-delta'];
const extraAdvisories = new Map(extraPackages.map(name => [name, { ...advisory, id: `GHSA-${name}`, aliases: [],
  affected: [{ package: { name, ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }], database_specific: { severity: 'HIGH' } }] }]));
const fixtures = async (input, options = {}) => {
  const url = new URL(typeof input === 'string' ? input : input.url);
  report.outbound.push({ host: url.host, pathname: url.pathname, method: options.method || 'GET' });
  assert.ok(['api.osv.dev', 'registry.npmjs.org'].includes(url.host), 'Unexpected remote provider: ' + url.host);
  if (options.body) for (const marker of ['SECRET-CREDENTIAL-MARKER', 'DO-NOT-EXECUTE-MARKER', 'PRIVATE-REPOSITORY-MARKER']) assert.ok(!String(options.body).includes(marker), 'Unsanitized metadata forwarded');
  if (url.host === 'api.osv.dev' && url.pathname === '/v1/querybatch') {
    const body = JSON.parse(options.body);
    return Response.json({ results: body.queries.map(query => query.package.name === 'semver' && query.version === '7.5.1' ? { vulns: [{ id: advisory.id }] } :
      extraAdvisories.has(query.package.name) && query.version === '1.0.0' ? { vulns: [{ id: extraAdvisories.get(query.package.name).id }] } : {}) });
  }
  if (url.host === 'api.osv.dev' && url.pathname === '/v1/vulns/' + advisory.id) return Response.json(advisory);
  if (url.host === 'api.osv.dev') for (const value of extraAdvisories.values()) if (url.pathname === '/v1/vulns/' + value.id) return Response.json(value);
  if (url.host === 'registry.npmjs.org' && url.pathname === '/semver') return Response.json({ name: 'semver', versions: { '7.5.1': { version: '7.5.1' }, '7.5.2': { version: '7.5.2' } } });
  if (url.host === 'registry.npmjs.org' && extraPackages.includes(url.pathname.slice(1))) return Response.json({ name: url.pathname.slice(1), versions: { '1.0.0': { version: '1.0.0' }, '1.0.1': { version: '1.0.1' } } });
  throw Error('Unexpected provider path: ' + url.pathname);
};
const safeProcess = new Proxy(process, { get(target, property) { if (property === 'env') return { NODE_ENV: 'test' }; const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value; } });
const context = vm.createContext({ console, Buffer, process: safeProcess, fetch: fixtures, Request, Response, Headers,
  URL, URLSearchParams, AbortController, AbortSignal, TextEncoder, TextDecoder, TextEncoderStream, TextDecoderStream,
  TransformStream, ReadableStream, WritableStream, DecompressionStream, Blob, File, FormData, crypto: webcrypto, performance,
  setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate, queueMicrotask,
  atob, btoa, structuredClone }, { name: 'offense-actual-release-validation', codeGeneration: { strings: false, wasm: false } });
const cache = new Map();
const builtins = new Set(builtinModules.flatMap(name => [name, name.replace(/^node:/, '')]));
async function linkedModule(specifier) {
  if (cache.has(specifier)) return cache.get(specifier);
  let namespace;
  if (specifier === 'cloudflare:workers') namespace = { DurableObject: class { constructor(ctx, env) { this.ctx = ctx; this.env = env; } } };
  else if (specifier === 'cloudflare:node') namespace = { httpServerHandler() { throw Error('Cloudflare bridge must not be needed by isolated app validation'); } };
  else {
    assert.ok(specifier.startsWith('node:') || builtins.has(specifier), 'Non-builtin external import cannot be shipped in the Worker: ' + specifier);
    namespace = await import(specifier);
  }
  const names = Object.keys(namespace);
  const module = new vm.SyntheticModule(names, function() { for (const name of names) this.setExport(name, namespace[name]); }, { context, identifier: specifier });
  cache.set(specifier, module); return module;
}
const module = new vm.SourceTextModule(source + `\nexport { ${factoryBinding} as __artifactCreateWorkerApp };\n`, { context, identifier: artifact,
  initializeImportMeta(meta) { meta.url = 'file://' + artifact; }, importModuleDynamically() { throw Error('Unexpected dynamic import in Worker release'); } });
let db, server;
try {
  await module.link(linkedModule); await module.evaluate({ timeout: 15_000 });
  report.checks.push('Actual release module loads with dynamic code generation disabled and no external package imports');
  db = new DatabaseSync(':memory:');
  const app = module.namespace.__artifactCreateWorkerApp({ db, env: { PUBLIC_URL: 'http://127.0.0.1', PURPLE_INGEST_URL: 'https://ingest.example.test', PURPLE_RELEASE: 'artifact-fixture' }, schedule() { throw Error('Unexpected background dispatch'); } }).app;
  server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const files = [{ path: 'package-lock.json', content: { lockfileVersion: 3, name: 'PRIVATE-REPOSITORY-MARKER', packages: {
    '': { dependencies: { semver: '^7.5.1' }, scripts: { postinstall: 'DO-NOT-EXECUTE-MARKER' } },
    'node_modules/semver': { version: '7.5.1', resolved: 'https://user:SECRET-CREDENTIAL-MARKER@private.example/package.tgz' }
  } } }];
  const post = (pathname, body, headers = {}) => fetch(base + pathname, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const publicResponses = [];
  const capability = await fetch(base + '/api/offense/capabilities'); assert.equal(capability.status, 200); publicResponses.push(capability);
  const discovery = await capability.json(); assert.equal(discovery.capabilities[0].mcpTool, 'offense.audit_dependencies');
  const auditResponse = await post('/api/offense/audit', { files, planLimit: 1 }); assert.equal(auditResponse.status, 200); publicResponses.push(auditResponse);
  const audit = await auditResponse.json(); assert.equal(audit.schemaVersion, 'offense.audit.v1'); assert.equal(audit.status, 'complete'); assert.equal(audit.findings.length, 1);
  assert.equal(audit.findings[0].verification.confirmed, false); assert.equal(audit.findings[0].relevance.status, 'needs_review'); assert.equal(audit.summary.checkedUpgradePaths, 1);
  assert.equal(audit.remediation.plans[0].proposedVersion, '7.5.2');
  for (const marker of ['SECRET-CREDENTIAL-MARKER', 'DO-NOT-EXECUTE-MARKER', 'PRIVATE-REPOSITORY-MARKER']) assert.ok(!JSON.stringify(audit).includes(marker));
  report.checks.push('Actual artifact REST capability scans, normalizes, plans checked target and sanitizes metadata without account credentials');
  const { mergeAuditContinuation } = await import('../shared/offense-planning.js');
  const pagedFiles = [{ path: 'package-lock.json', content: { lockfileVersion: 3, packages: {
    '': { dependencies: Object.fromEntries(extraPackages.map(name => [name, '^1.0.0'])) },
    ...Object.fromEntries(extraPackages.map(name => [`node_modules/${name}`, { version: '1.0.0' }]))
  } } }];
  const firstPage = await post('/api/offense/audit', { files: pagedFiles, planLimit: 1 }); assert.equal(firstPage.status, 200);
  let combined = await firstPage.json(), pages = 1;
  const originalFindings = JSON.stringify(combined.findings.map(finding => finding.id));
  assert.equal(combined.findings.length, extraPackages.length);
  assert.equal(combined.remediation.planning.hasMore, true);
  while (combined.remediation.planning.hasMore && pages < 5) {
    const response = await post('/api/offense/audit', { files: pagedFiles, planLimit: 1, planning: combined.remediation.planning.next });
    assert.equal(response.status, 200);
    const page = await response.json(); assert.equal(page.coverage.planningOnly, true);
    combined = mergeAuditContinuation(combined, page); pages++;
  }
  assert.equal(pages, extraPackages.length); assert.equal(combined.remediation.planning.hasMore, false);
  assert.equal(combined.remediation.plans.length, extraPackages.length);
  assert.equal(combined.summary.advisoryMatches, extraPackages.length); assert.equal(combined.summary.confirmedVulnerabilities, 0);
  assert.equal(JSON.stringify(combined.findings.map(finding => finding.id)), originalFindings);
  assert.ok(combined.remediation.plans.every(plan => plan.compatibilityVerified === false));
  report.checks.push('Actual compiled artifact continues four planning pages, preserves original findings/counts, and never claims executable verification');
  for (const encoding of ['gzip', 'deflate']) for (const trailing of [false, true]) {
    const frame = (encoding === 'gzip' ? gzipSync : deflateSync)(Buffer.from(JSON.stringify({ files, planLimit: 0 })));
    const body = trailing ? Buffer.concat([frame, Buffer.of(0), Buffer.alloc(100 * 1024, 0x58)]) : frame;
    const response = await new Promise((resolve, reject) => {
      const request = httpRequest(base + '/api/offense/audit', { method: 'POST', agent: false,
        headers: { 'Content-Type': 'application/json', 'Content-Encoding': encoding, 'Content-Length': body.length } }, response => {
        const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
        response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      request.on('error', reject); request.setTimeout(5000, () => request.destroy(Error('Compressed artifact request timed out.'))); request.end(body);
    });
    assert.equal(response.status, 200); assert.equal(JSON.parse(response.body).findings.length, 1);
    await new Promise(resolve => setTimeout(resolve, 150));
    assert.equal((await fetch(base + '/health')).status, 200);
  }
  report.checks.push('Exact production artifact parses normal gzip/deflate and remains alive after the decoder trailing-data security regression');
  const legacyScan = await post('/api/skill/scan', { files }); publicResponses.push(legacyScan); assert.equal(legacyScan.status, 200); assert.equal((await legacyScan.json()).protocolVersion, 1);
  const legacyPlan = await post('/api/skill/plan', { files, name: 'semver', version: '7.5.1' }); publicResponses.push(legacyPlan); assert.equal(legacyPlan.status, 200); const oldPlan = await legacyPlan.json(); assert.equal(oldPlan.protocolVersion, 1); assert.equal(oldPlan.plan.targetVersion, '7.5.2');
  report.checks.push('Legacy skill scan and plan wire formats remain usable in the same app');
  const mcpHeaders = { Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25' };
  const initialize = await post('/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'actual-artifact-validator', version: '1' } } }, mcpHeaders);
  publicResponses.push(initialize); assert.equal(initialize.status, 200); assert.equal((await initialize.json()).result.serverInfo.name, 'offense');
  const listed = await post('/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' }, mcpHeaders); publicResponses.push(listed); assert.equal(listed.status, 200); assert.equal((await listed.json()).result.tools[0].name, 'offense.audit_dependencies');
  const called = await post('/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'offense.audit_dependencies', arguments: { files, planLimit: 0 } } }, mcpHeaders); publicResponses.push(called); assert.equal(called.status, 200);
  const result = (await called.json()).result; assert.equal(result.isError, false); assert.equal(result.structuredContent.findings.length, 1); assert.equal(result.structuredContent.summary.confirmedVulnerabilities, 0);
  const invalid = await post('/mcp', { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'offense.audit_dependencies', arguments: { files: [] } } }, mcpHeaders); publicResponses.push(invalid); assert.equal((await invalid.json()).result.isError, true);
  report.checks.push('Actual artifact MCP initializes, discovers, invokes and rejects invalid tool input with eval disabled');
  assert.ok(publicResponses.every(response => !response.headers.get('set-cookie') && !response.headers.get('mcp-session-id')));
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0);
  report.checks.push('Public capabilities, MCP and legacy calls create no browser or MCP sessions');
  const traceRows = db.prepare('SELECT event FROM offense_trace_events').all();
  assert.ok(traceRows.length > 0);
  const traceJson = JSON.stringify(traceRows);
  for (const marker of ['SECRET-CREDENTIAL-MARKER', 'DO-NOT-EXECUTE-MARKER', 'PRIVATE-REPOSITORY-MARKER',
    'package-lock.json', 'semver', audit.metadataFingerprint]) assert.ok(!traceJson.includes(marker), 'Private audit content entered a diagnostic record.');
  for (const row of traceRows) {
    const event = JSON.parse(row.event);
    assert.equal(event.schemaVersion, 'offense.trace.v1'); assert.equal(event.origin, 'server');
    assert.equal(event.timestampMs % 60_000, 0);
    assert.match(event.requestId, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  }
  assert.equal((await fetch(base + '/api/offense/traces')).status, 404);
  report.checks.push('Compiled API/MCP/legacy diagnostic records exclude source, dependency names/paths, fingerprints and credentials; no public trace-read route exists');
  const deniedOrigin = await post('/api/offense/audit', { files }, { Origin: 'https://attacker.example' }); assert.equal(deniedOrigin.status, 403);
  for (const pathname of ['/mcp', '/api/offense/audit', '/api/skill/scan']) {
    const status = await new Promise((resolve, reject) => { const req = httpRequest(base + pathname, { method: 'POST', headers: { Host: 'ingest.example.test', 'content-type': 'application/json', Accept: 'application/json, text/event-stream' } }, res => { res.resume(); resolve(res.statusCode); }); req.on('error', reject); req.end('{}'); });
    assert.equal(status, 404, 'Ingest host exposed public analysis: ' + pathname);
  }
  assert.equal((await fetch(base + '/api/agent/repositories')).status, 401);
  report.checks.push('Existing auth boundary, request-origin policy and ingest-host isolation remain intact');
  const manifestResponse = await module.namespace.default.fetch(new Request('https://app.example/skills/offense/manifest.json'), {}, {});
  assert.equal(manifestResponse.status, 200); assert.match(manifestResponse.headers.get('content-type'), /^application\/json/);
  assert.equal(manifestResponse.headers.get('cache-control'), 'no-store');
  const skillManifest = await manifestResponse.json(); assert.equal(skillManifest.version, OFFENSE_SERVICE_VERSION);
  assert.ok(skillManifest.files.some(file => file.path === 'references/verification.md'));
  for (const skill of ['offense', 'purple']) {
    const response = await module.namespace.default.fetch(new Request(`https://app.example/skills/${skill}/manifest.json`), {}, {});
    const manifest = await response.json();
    for (const file of manifest.files) {
      const resource = await module.namespace.default.fetch(new Request(`https://app.example/skills/${skill}/${file.path}`), {}, {});
      const bytes = Buffer.from(await resource.arrayBuffer());
      assert.equal(bytes.length, file.bytes); assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
    }
  }
  report.checks.push('Actual Worker serves both complete managed skill packages with verified hashes and JSON/no-store release manifests');
  const maintenance = [];
  db.prepare('UPDATE offense_trace_events SET expires_at = 0').run();
  const maintenanceContext = { pruneTraces() { app.purplePruneTraces(); maintenance.push('pruned'); }, async flushClickHouse() { maintenance.push('flushed'); },
    async dispatchAgents() { maintenance.push('dispatched'); }, ctx: { storage: { async setAlarm() { maintenance.push('scheduled'); } } } };
  await module.namespace.PurpleState.prototype.alarm.call(maintenanceContext);
  assert.deepEqual(maintenance, ['pruned', 'flushed', 'dispatched', 'scheduled']);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM offense_trace_events').get().count, 0);
  maintenance.length = 0;
  maintenanceContext.flushClickHouse = async () => { maintenance.push('flush_failed'); throw Error('Synthetic maintenance failure'); };
  await assert.rejects(module.namespace.PurpleState.prototype.alarm.call(maintenanceContext), /Synthetic maintenance failure/);
  assert.deepEqual(maintenance, ['pruned', 'flush_failed', 'scheduled']);
  report.checks.push('Actual exported Durable Object alarm prunes trace records and reschedules even when other maintenance fails');
  let forwarded = 0;
  const ctx = { exports: { PurpleState: { getByName() { return { fetch() { forwarded++; return new Response('forwarded'); } }; } } } };
  assert.equal((await module.namespace.default.fetch(new Request('https://app.example/mcp', { method: 'POST' }), {}, ctx)).status, 200);
  assert.equal(forwarded, 1);
  assert.equal((await module.namespace.default.fetch(new Request('https://app.example/mcp/extra', { method: 'POST' }), {}, ctx)).status, 404);
  assert.equal(forwarded, 1);
  report.checks.push('Actual Worker entrypoint forwards exactly /mcp to Durable Object API');
  report.passed = true;
} catch (error) { report.passed = false; report.error = error.stack || error.message; }
finally {
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  db?.close();
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
}
console.log(JSON.stringify(report));
if (!report.passed) process.exitCode = 1;
