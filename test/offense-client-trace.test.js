import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, lstat, symlink, stat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { auditDependencies, prepareAudit } from '../scripts/offense-audit-client.mjs';

const privatePackage = '@private-customer/internal-widget', privateVersion = '7.6.5';
const privateValues = ['alice-private@example.test', 'CANARY-API-CREDENTIAL-123', 'PRIVATE-ORG-CUSTOMER',
  'https://private-customer.test/private-repository', 'PRIVATE-SOURCE-CODE', 'PRIVATE-PROVIDER-MESSAGE',
  'PRIVATE-RAW-HEADER', 'PRIVATE-ADVISORY-IDENTITY', privatePackage, privateVersion];

async function fixture(t, { unsupported = false } = {}) {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'offense-private-customer-')), root = path.join(outer, 'PRIVATE-ORG-CUSTOMER');
  await mkdir(root);
  t.after(() => rm(outer, { recursive: true, force: true }));
  const lock = { name: 'PRIVATE-ORG-CUSTOMER', lockfileVersion: 3, packages: {
    '': { dependencies: { [privatePackage]: privateVersion } },
    [`node_modules/${privatePackage}`]: { version: privateVersion, resolved: 'https://alice-private:CANARY-API-CREDENTIAL-123@registry.test/package' }
  } };
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify(lock));
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'PRIVATE-ORG-CUSTOMER', author: 'alice-private@example.test' }));
  await writeFile(path.join(root, 'index.js'), 'PRIVATE-SOURCE-CODE');
  if (unsupported) await writeFile(path.join(root, 'requirements.txt'), 'Pillow==1.2.3\n--extra-index-url https://alice-private:CANARY-API-CREDENTIAL-123@registry.test/private\n');
  const prepared = await prepareAudit(root), metadataFingerprint = prepared.local.metadataFingerprint;
  const response = () => ({ schemaVersion: 'offense.audit.v1', capability: 'audit_dependencies', status: 'complete', metadataFingerprint,
    findings: [{ id: 'PRIVATE-ADVISORY-IDENTITY', advisoryId: 'PRIVATE-ADVISORY-IDENTITY',
      package: { ecosystem: 'npm', name: privatePackage, installedVersion: privateVersion, lockfiles: ['package-lock.json'] },
      summary: privateValues.join(' '), verification: { status: 'advisory_match', confirmed: false } }],
    coverage: { status: 'complete', checkedPackages: 1 },
    remediation: { plans: [], blockers: [], agentPrompt: `PRIVATE-PROVIDER-MESSAGE ${privateValues.join(' ')}` } });
  return { root, outer, output: path.join(outer, 'report'), response, metadataFingerprint };
}

async function readTrace(filename, extraForbidden = []) {
  const raw = await readFile(filename, 'utf8'), trace = JSON.parse(raw);
  for (const value of [...privateValues, ...extraForbidden]) assert.ok(!raw.includes(value), `Trace leaked ${value}`);
  assert.equal(trace.schemaVersion, 'offense.trace.v1');
  assert.equal(trace.origin, 'helper'); assert.equal(trace.transport, 'https_helper');
  assert.match(trace.runId, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.ok(trace.events.length > 0);
  return trace;
}

test('local trace records observed stages and counters without copying private inputs, reports or response headers', async t => {
  const { root, output, response, metadataFingerprint } = await fixture(t, { unsupported: true });
  const sent = [];
  const result = await auditDependencies(root, { output, fetchImpl: async (url, options) => {
    sent.push({ url: String(url), body: options.body });
    return Response.json(response(), { headers: { 'x-offense-request-id': 'alice-private@example.test', 'cf-ray': 'PRIVATE-RAW-HEADER' } });
  } });
  assert.equal(result.traceStatus, 'saved');
  assert.equal(result.trace, path.join(output, 'trace.json'));
  assert.equal(result.status, 'partial'); assert.equal(result.advisoryMatches, 1);
  const trace = await readTrace(result.trace, [root, output, metadataFingerprint]);
  assert.ok(trace.events.some(event => event.stage === 'discovery' && event.outcome === 'completed' && event.counts.lockfiles === 1));
  assert.ok(trace.events.some(event => event.stage === 'local_coverage' && event.outcome === 'partial' && event.counts.unsupportedFiles === 1));
  assert.ok(trace.events.some(event => event.stage === 'advisory_scan' && event.outcome === 'completed' && event.counts.advisoryMatches === 1));
  assert.equal(trace.events.at(-1).stage, 'response'); assert.equal(trace.events.at(-1).outcome, 'partial');
  assert.ok(trace.events.some(event => typeof event.durationMs === 'number' && event.durationMs >= 0));
  assert.equal((await stat(result.trace)).mode & 0o777, 0o600);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, 'https://app.purpleteam.sh/api/offense/audit');
  assert.deepEqual(Object.keys(JSON.parse(sent[0].body)).sort(), ['files', 'planLimit']);
  assert.ok(!sent[0].body.includes(trace.runId), 'Local trace was uploaded with audit metadata');
  assert.match(await readFile(result.json, 'utf8'), /PRIVATE-PROVIDER-MESSAGE/);
});

test('provider error strings remain outside the trace while HTTP failure gets a fixed category', async t => {
  const { root, output, metadataFingerprint } = await fixture(t);
  let observed;
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ error: {
    code: 'alice-private@example.test', message: privateValues.join(' ')
  } }, { status: 502, headers: { 'x-request-id': 'PRIVATE-RAW-HEADER' } }) }), error => {
    observed = error;
    return error.status === 502 && error.traceFile === path.join(output, 'trace.json');
  });
  assert.match(observed.message, /PRIVATE-PROVIDER-MESSAGE/);
  const trace = await readTrace(observed.traceFile, [root, metadataFingerprint]);
  assert.ok(trace.events.some(event => event.stage === 'advisory_scan' && event.outcome === 'failed' && event.errorCode === 'provider_failure'));
  assert.equal(trace.events.at(-1).outcome, 'failed');
  await assert.rejects(lstat(path.join(output, 'audit.json')), { code: 'ENOENT' });
});

test('failed network and invalid response diagnostics cannot export exception text or dependency fingerprints', async t => {
  const { root, outer, output, response, metadataFingerprint } = await fixture(t);
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => { throw Error(privateValues.join(' ')); } }), /could not reach/);
  const trace = await readTrace(path.join(output, 'trace.json'), [metadataFingerprint]);
  assert.ok(trace.events.some(event => event.errorCode === 'network_failure'));
  const invalidOutput = path.join(outer, 'invalid-response');
  await assert.rejects(auditDependencies(root, { output: invalidOutput, fetchImpl: async () => Response.json({ ...response(), metadataFingerprint: 'PRIVATE-ORG-CUSTOMER' }) }), /does not match/);
  const invalidTrace = await readTrace(path.join(invalidOutput, 'trace.json'), [metadataFingerprint]);
  assert.ok(invalidTrace.events.some(event => event.stage === 'validation' && event.errorCode === 'metadata_changed'));
  assert.notEqual(trace.runId, invalidTrace.runId);
});

test('a later continuation failure preserves the full audit and the minimized failure trace', async t => {
  const { root, output, response, metadataFingerprint } = await fixture(t);
  let calls = 0;
  const result = await auditDependencies(root, { output, fetchImpl: async () => {
    if (++calls > 1) return Response.json({ error: { code: 'PRIVATE-PROVIDER-MESSAGE', message: privateValues.join(' ') } }, { status: 429 });
    const report = response(), pendingId = 'a'.repeat(64);
    report.status = 'partial';
    report.remediation.planning = { scope: 'full_audit', metadataFingerprint, hasMore: true,
      remainingTargetIds: [pendingId], next: { metadataFingerprint, pendingTargetIds: [pendingId] } };
    return Response.json(report);
  } });
  assert.equal(result.advisoryMatches, 1); assert.equal(result.status, 'partial');
  const trace = await readTrace(result.trace, [metadataFingerprint, 'a'.repeat(64)]);
  assert.ok(trace.events.some(event => event.stage === 'continuation' && event.outcome === 'failed' && event.errorCode === 'quota_exceeded'));
  assert.equal(JSON.parse(await readFile(result.json, 'utf8')).findings.length, 1);
});

test('disabled tracing and blocked trace destinations never change a successful audit or follow trace symlinks', async t => {
  const { root, outer, output, response } = await fixture(t);
  const disabled = await auditDependencies(root, { output, trace: false, fetchImpl: async () => Response.json(response()) });
  assert.equal(disabled.status, 'complete'); assert.equal(disabled.trace, null); assert.equal(disabled.traceStatus, 'disabled');
  await assert.rejects(lstat(path.join(output, 'trace.json')), { code: 'ENOENT' });
  await writeFile(path.join(output, 'trace.json'), 'OLDER-LOCAL-TRACE-RETAINED');
  const reused = await auditDependencies(root, { output, trace: false, fetchImpl: async () => Response.json(response()) });
  assert.equal(reused.traceStatus, 'disabled'); assert.equal(reused.trace, null);
  assert.equal(await readFile(path.join(output, 'trace.json'), 'utf8'), 'OLDER-LOCAL-TRACE-RETAINED');
  const blocked = path.join(outer, 'blocked-trace'); await mkdir(blocked);
  const source = path.join(root, 'index.js'), original = await readFile(source, 'utf8');
  await symlink(source, path.join(blocked, 'trace.json'));
  const result = await auditDependencies(root, { output: blocked, fetchImpl: async () => Response.json(response()) });
  assert.equal(result.status, 'complete'); assert.equal(result.advisoryMatches, 1);
  assert.equal(result.trace, null); assert.equal(result.traceStatus, 'unavailable');
  assert.equal(await readFile(source, 'utf8'), original);
});

test('known provider failure categories are retained without copying the provider message', async t => {
  const { root, output } = await fixture(t);
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ error: {
    code: 'planning_budget_exhausted', message: privateValues.join(' ')
  } }, { status: 502 }) }), /HTTP 502/);
  const trace = await readTrace(path.join(output, 'trace.json'));
  assert.ok(trace.events.some(event => event.outcome === 'failed' && event.errorCode === 'planning_budget_exhausted'));
});

test('a real signal timeout during response-body reading produces a fixed timeout event', async t => {
  const { root, output } = await fixture(t), originalTimeout = AbortSignal.timeout;
  t.mock.method(AbortSignal, 'timeout', milliseconds => originalTimeout(Math.min(milliseconds, 10)));
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async (url, options) => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(`{"private":"${privateValues.join(' ')}"`));
      if (options.signal.aborted) controller.error(options.signal.reason);
      else options.signal.addEventListener('abort', () => controller.error(options.signal.reason), { once: true });
    }
  }), { headers: { 'content-type': 'application/json' } }) }), /response timed out/);
  const trace = await readTrace(path.join(output, 'trace.json'));
  assert.ok(trace.events.some(event => event.stage === 'advisory_scan' && event.outcome === 'failed' && event.errorCode === 'timeout'));
});

test('invalid explicit evidence is reported as a reviewed-artifact verification failure without leaking its path', async t => {
  const { root, output, outer, response } = await fixture(t), evidence = path.join(outer, 'alice-private@example.test.json');
  await writeFile(evidence, privateValues.join(' '));
  await assert.rejects(auditDependencies(root, { output, evidence, fetchImpl: async () => Response.json(response()) }));
  const trace = await readTrace(path.join(output, 'trace.json'), [evidence]);
  assert.ok(trace.events.some(event => event.stage === 'local_verification' && event.outcome === 'failed' && event.evidenceSource === 'reviewed_artifact'));
});

test('preview writes no diagnostic files and local collection failure can still produce a safe failure trace', async t => {
  const { root, output } = await fixture(t);
  const preview = await auditDependencies(root, { output, preview: true, fetchImpl: () => assert.fail('Preview made a request') });
  assert.equal(preview.request.files.length, 1);
  await assert.rejects(lstat(output), { code: 'ENOENT' });
  await rm(path.join(root, 'package-lock.json'));
  await assert.rejects(auditDependencies(root, { output, fetchImpl: () => assert.fail('Invalid metadata was sent') }), /Exact dependency versions are unknown/);
  const trace = await readTrace(path.join(output, 'trace.json'), [root]);
  assert.equal(trace.events[0].stage, 'discovery');
  assert.equal(trace.events.at(-1).outcome, 'failed');
});
