import test from 'node:test';
import assert from 'node:assert/strict';
import { createOffenseTrace, classifyTraceError, serializeTraceEvent, serializeOffenseTrace, readStoredTraceEvent,
  OFFENSE_TRACE_SCHEMA, OFFENSE_TRACE_VERSIONS, MAX_TRACE_EVENTS, MAX_TRACE_BYTES } from '../shared/offense-trace.js';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const pii = 'TRACE_CANARY_person@example.invalid_203.0.113.48';
const run = () => createOffenseTrace({ origin: 'helper', transport: 'https_helper' });
const ownEvent = () => run().record('request', 'completed', { durationMs: 1234, counts: { advisoryMatches: 19 } });

test('trace identifiers and trusted version/time originate inside the constructor', () => {
  const before = Math.floor(Date.now() / 60_000) * 60_000;
  const trace = createOffenseTrace({ origin: 'helper', transport: 'https_helper', runId: pii, requestId: pii, timestampMs: 1,
    componentVersion: pii, userId: pii, metadataFingerprint: 'a'.repeat(64) });
  const event = trace.record('advisory_scan', 'completed', { eventId: pii, runId: pii, requestId: pii, timestampMs: 1,
    componentVersion: pii, durationMs: 1234, counts: { checkedPackages: 1544, advisoryMatches: 19, critical: 1 } });
  const after = Math.floor(Date.now() / 60_000) * 60_000;
  assert.equal(event.schemaVersion, OFFENSE_TRACE_SCHEMA); assert.equal(event.componentVersion, OFFENSE_TRACE_VERSIONS.helper);
  assert.match(event.runId, uuid); assert.match(event.requestId, uuid); assert.match(event.eventId, uuid);
  assert.equal(event.runId, trace.runId); assert.equal(event.requestId, trace.requestId);
  assert.ok(event.timestampMs >= before && event.timestampMs <= after); assert.equal(event.timestampMs % 60_000, 0);
  assert.equal(event.durationMs, 1200); assert.equal(event.errorCode, 'none'); assert.equal(event.evidenceSource, 'observed');
  assert.doesNotMatch(serializeOffenseTrace(trace), /TRACE_CANARY|metadataFingerprint|userId/);
});

test('nested project data, URLs, credentials, identity hashes, source and terminal text are never serialized', () => {
  const fields = { email: pii, name: pii, ip: pii, userAgent: pii, url: `https://private.invalid/${pii}?token=${pii}`,
    headers: { authorization: pii, 'x-forwarded-for': pii }, repository: pii, package: pii, files: [{ path: pii, source: pii }],
    lockfiles: { [pii]: pii }, prompt: pii, stdout: pii, stderr: pii, message: pii, stack: pii, metadataFingerprint: 'a'.repeat(64),
    userId: pii, projectId: pii, counts: { checkedPackages: 42, repository: pii, arbitrary: { email: pii } } };
  const trace = run(), event = trace.record('request', 'failed', fields), text = serializeTraceEvent(event);
  assert.equal(event.counts.checkedPackages, 42); assert.deepEqual(Object.keys(event.counts), ['checkedPackages']);
  assert.doesNotMatch(text, /TRACE_CANARY|private\.invalid|authorization|source|prompt|stdout|stderr|Fingerprint|userId|projectId/);
  assert.deepEqual(Object.keys(event).sort(), ['schemaVersion', 'runId', 'requestId', 'origin', 'transport', 'componentVersion',
    'eventId', 'timestampMs', 'event', 'stage', 'outcome', 'errorCode', 'evidenceSource', 'counts'].sort());
});

test('only fixed enum choices survive and invalid evidence source remains unknown', () => {
  const trace = createOffenseTrace({ origin: 'server', transport: pii });
  const event = trace.record(pii, pii, { event: pii, errorCode: pii, evidenceSource: pii });
  assert.equal(event.transport, 'unknown'); assert.equal(event.stage, 'unknown'); assert.equal(event.outcome, 'unknown');
  assert.equal(event.event, 'stage'); assert.equal(event.errorCode, 'unknown'); assert.equal(event.evidenceSource, 'unknown');
  assert.equal(event.componentVersion, OFFENSE_TRACE_VERSIONS.server); assert.doesNotMatch(serializeTraceEvent(event), /TRACE_CANARY/);
  assert.throws(() => createOffenseTrace({ origin: pii }), error => !error.message.includes(pii));
});

test('observed, reviewed-artifact and agent-reported evidence are distinguished explicitly', () => {
  const trace = run();
  const observed = trace.record('advisory_scan', 'completed', { counts: { advisoryMatches: 19 } });
  const reviewed = trace.record('local_verification', 'partial', { evidenceSource: 'reviewed_artifact', counts: { mitigationsVerified: 1 } });
  const reported = trace.record('local_verification', 'unknown', { evidenceSource: 'agent_reported', counts: { securityRegressionsVerified: 1 } });
  assert.equal(observed.evidenceSource, 'observed'); assert.equal(reviewed.evidenceSource, 'reviewed_artifact'); assert.equal(reported.evidenceSource, 'agent_reported');
  assert.ok(!Object.hasOwn(trace.snapshot(), 'confirmedVulnerabilities'));
});

test('numeric measurements are bounded typed values, never coerced from strings or objects', () => {
  let coerced = 0;
  const malicious = { valueOf() { coerced++; return 10; }, toString() { coerced++; return pii; } };
  const event = run().record('report', 'completed', { durationMs: malicious,
    counts: { checkedPackages: '1544', advisoryMatches: malicious, critical: NaN, high: Infinity, low: -1, files: 30_001,
      lockfiles: 21, patches: 0.5, planningPages: 1, coverageWarnings: 0, bytes: 2_000_001 } });
  assert.equal(coerced, 0); assert.equal(Object.hasOwn(event, 'durationMs'), false);
  assert.deepEqual(Object.keys(event.counts).sort(), ['planningPages', 'coverageWarnings'].sort());
  for (const duration of [pii, -1, NaN, Infinity, 3_600_001, malicious]) assert.equal(Object.hasOwn(run().record('report', 'failed', { durationMs: duration }), 'durationMs'), false);
});

test('getters, inherited fields, user toJSON hooks and hostile prototypes are never invoked', () => {
  let invoked = 0;
  const counts = Object.create({ checkedPackages: 99, email: pii });
  Object.defineProperty(counts, 'advisoryMatches', { get() { invoked++; return pii; }, enumerable: true }); counts.high = 2;
  const fields = Object.create({ errorCode: 'provider_failure', message: pii }); fields.counts = counts;
  Object.defineProperty(fields, 'errorCode', { get() { invoked++; return pii; }, enumerable: true });
  fields.toJSON = () => { invoked++; return { email: pii }; };
  const event = run().record('request', 'partial', fields);
  assert.equal(invoked, 0); assert.equal(event.errorCode, 'none'); assert.equal(event.counts.high, 2); assert.equal(Object.keys(event.counts).length, 1);
  assert.doesNotMatch(serializeTraceEvent(event), /TRACE_CANARY/); assert.equal(invoked, 0);
  assert.equal(classifyTraceError(Object.create({ code: 'provider_failure', status: 403 })), 'unknown');
});

test('global prototype toJSON pollution cannot append identity to a constructed export', () => {
  const originalObject = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
  const originalArray = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');
  let invoked = 0, serialized;
  try {
    Object.defineProperty(Object.prototype, 'toJSON', { configurable: true, value() { invoked++; return { email: pii }; } });
    Object.defineProperty(Array.prototype, 'toJSON', { configurable: true, value() { invoked++; return [pii]; } });
    const trace = run(); trace.record('request', 'completed', { counts: { checkedPackages: 1 } });
    serialized = serializeOffenseTrace(trace);
  } finally {
    if (originalObject) Object.defineProperty(Object.prototype, 'toJSON', originalObject); else delete Object.prototype.toJSON;
    if (originalArray) Object.defineProperty(Array.prototype, 'toJSON', originalArray); else delete Array.prototype.toJSON;
  }
  assert.equal(invoked, 0); assert.doesNotMatch(serialized, /TRACE_CANARY/); assert.equal(JSON.parse(serialized).events.length, 1);
});

test('raw errors are bucketed without inspecting message, stack, cause or an arbitrary string code', () => {
  let touched = 0;
  const error = { code: pii, status: '403', cause: { code: 'provider_failure', message: pii } };
  for (const key of ['message', 'stack', 'response', 'headers']) Object.defineProperty(error, key, { get() { touched++; throw Error(pii); } });
  assert.equal(classifyTraceError(error), 'unknown'); assert.equal(classifyTraceError(pii), 'unknown');
  assert.equal(classifyTraceError({ code: 'provider_unavailable', message: pii }), 'provider_failure');
  assert.equal(classifyTraceError({ code: 'stale_planning_cursor' }), 'stale_planning_cursor');
  assert.equal(classifyTraceError({ code: 'ETIMEDOUT' }), 'timeout'); assert.equal(classifyTraceError({ status: 403 }), 'access_denied');
  assert.equal(classifyTraceError({ status: 429 }), 'quota_exceeded'); assert.equal(classifyTraceError({ name: 'AbortError' }), 'timeout');
  assert.equal(classifyTraceError({ code: { toString() { touched++; return pii; } } }), 'unknown'); assert.equal(touched, 0);
});

test('a throwing proxy cannot cause a raw diagnostic exception or copy its fields', () => {
  const proxy = new Proxy({}, { getOwnPropertyDescriptor() { throw Error(pii); } });
  assert.equal(classifyTraceError(proxy), 'unknown');
  const event = run().record('request', 'failed', proxy);
  assert.equal(event.errorCode, 'none'); assert.equal(Object.keys(event.counts).length, 0); assert.doesNotMatch(serializeTraceEvent(event), /TRACE_CANARY/);
});

test('module ownership prevents arbitrary event/run objects from crossing writer serialization', () => {
  const trace = run(), event = trace.record('request', 'completed');
  assert.throws(() => serializeTraceEvent({ ...event, email: pii }), /Only constructed/);
  assert.throws(() => serializeTraceEvent(JSON.parse(serializeTraceEvent(event))), /Only constructed/);
  assert.throws(() => serializeOffenseTrace({ ...trace, email: pii }), /Only constructed/);
  assert.throws(() => serializeOffenseTrace(trace.snapshot()), /Only constructed/);
  assert.equal(JSON.parse(serializeTraceEvent(event)).eventId, event.eventId);
});

test('snapshots and nested records are immutable and independent runs use fresh identifiers', () => {
  const a = run(), b = run(), eventA = a.record('request', 'started', { counts: { requests: 1 } }), eventB = b.record('request', 'started');
  assert.notEqual(a.runId, b.runId); assert.notEqual(a.requestId, b.requestId); assert.notEqual(eventA.eventId, eventB.eventId);
  assert.throws(() => eventA.counts.requests = 99, TypeError); assert.throws(() => eventA.email = pii, TypeError);
  const snapshot = a.snapshot(); assert.throws(() => snapshot.events.push({ email: pii }), TypeError);
  a.record('response', 'completed'); assert.equal(snapshot.events.length, 1); assert.equal(a.snapshot().events.length, 2);
});

test('event count and serialized size are bounded and excess events are discarded safely', () => {
  const trace = run(); let accepted = 0;
  for (let i = 0; i < MAX_TRACE_EVENTS + 100; i++) {
    if (trace.record('continuation', 'completed', { counts: { checkedPackages: 100000, advisoryMatches: 100000, upgradePlans: 100000,
      blockers: 100000, coverageWarnings: 30000, files: 30000, bytes: 2000000, planningPages: 1000 } })) accepted++;
  }
  const serialized = serializeOffenseTrace(trace);
  assert.ok(accepted > 0 && accepted <= MAX_TRACE_EVENTS); assert.equal(trace.snapshot().events.length, accepted);
  assert.ok(Buffer.byteLength(serialized) <= MAX_TRACE_BYTES); assert.equal(trace.record('response', 'completed'), null);
});

test('trusted-storage readback revalidates exact schema and refuses unknown keys at every level', () => {
  const original = ownEvent(), encoded = serializeTraceEvent(original), restored = readStoredTraceEvent(encoded);
  assert.equal(restored.eventId, original.eventId); assert.equal(restored.counts.advisoryMatches, 19); assert.equal(Object.getPrototypeOf(restored), null);
  assert.throws(() => serializeTraceEvent(restored), /Only constructed/);
  for (const mutation of [value => value.email = pii, value => value.message = pii, value => value.counts.email = pii,
    value => value.counts.arbitrary = { email: pii }, value => value.requestId = pii, value => value.stage = pii,
    value => value.errorCode = pii, value => value.evidenceSource = pii, value => value.componentVersion = pii,
    value => value.timestampMs += 1, value => value.durationMs = 1234, value => value.counts.advisoryMatches = '19',
    value => delete value.origin, value => value.runId = { toString: pii }]) {
    const candidate = JSON.parse(encoded); mutation(candidate); assert.equal(readStoredTraceEvent(JSON.stringify(candidate)), null, mutation.toString());
  }
  assert.equal(readStoredTraceEvent(pii), null); assert.equal(readStoredTraceEvent({ email: pii }), null); assert.equal(readStoredTraceEvent('x'.repeat(4001)), null);
});

test('all intended HTTP/helper stages and error buckets preserve the same minimal event schema', () => {
  const trace = createOffenseTrace({ origin: 'server', transport: 'mcp' });
  for (const stage of ['request', 'validation', 'advisory_scan', 'upgrade_planning', 'response', 'discovery', 'local_coverage',
    'local_verification', 'report', 'continuation', 'activation', 'update']) {
    const event = trace.record(stage, 'rejected', { errorCode: 'invalid_origin' }); assert.equal(event.stage, stage);
    assert.equal(readStoredTraceEvent(serializeTraceEvent(event)).errorCode, 'invalid_origin');
  }
});
