// Privacy boundary: construct diagnostics from a fixed vocabulary, never redact free text.
// This module performs no I/O. Local exports and optional server persistence use these same records.
export const OFFENSE_TRACE_SCHEMA = 'offense.trace.v1';
export const OFFENSE_TRACE_VERSIONS = Object.freeze({ helper: '0.6.0', server: '0.6.0' });
export const MAX_TRACE_EVENTS = 256;
export const MAX_TRACE_BYTES = 64_000;

const origins = new Set(['helper', 'server']);
const transports = new Set(['https', 'https_helper', 'mcp', 'local', 'unknown']);
const events = new Set(['stage', 'audit', 'continuation', 'connection', 'verification', 'update', 'export']);
const stages = new Set(['request', 'validation', 'advisory_scan', 'upgrade_planning', 'response', 'discovery',
  'local_coverage', 'local_verification', 'report', 'continuation', 'activation', 'update', 'unknown']);
const outcomes = new Set(['started', 'completed', 'partial', 'rejected', 'failed', 'skipped', 'unknown']);
const evidenceSources = new Set(['observed', 'agent_reported', 'reviewed_artifact', 'unknown']);
const errorCodes = new Set(['none', 'unknown', 'invalid_request', 'invalid_origin', 'invalid_host', 'unsupported_method',
  'unsupported_media_type', 'quota_exceeded', 'busy', 'provider_failure', 'planning_budget_exhausted', 'graph_truncated',
  'dependency_constraints', 'analysis_incomplete', 'not_found', 'access_denied', 'timeout', 'network_failure',
  'local_io_failure', 'response_invalid', 'metadata_changed', 'stale_planning_cursor', 'verification_incomplete', 'update_required', 'update_failed', 'trace_unavailable']);
const countLimits = Object.freeze({
  lockfiles: 20, files: 30_000, packages: 100_000, checkedPackages: 100_000,
  matches: 100_000, advisoryMatches: 100_000, critical: 100_000, high: 100_000, moderate: 100_000, low: 100_000,
  affectedPackages: 100_000, planningTargets: 100_000, plans: 100_000, upgradePlans: 100_000, blockers: 100_000,
  pending: 100_000, remainingPlanningTargets: 100_000, requests: 10_000, bytes: 2_000_000, pages: 1_000, planningPages: 1_000,
  coverageWarnings: 30_000, uncoveredManifests: 30_000, unsupportedFiles: 30_000, patches: 30_000,
  compatibilityVerified: 100_000, mitigationsVerified: 100_000, securityRegressionsVerified: 100_000,
});
const uuidV4 = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const ownedEvents = new WeakSet();
const ownedTraces = new WeakMap();
const recordObject = value => Object.assign(Object.create(null), value);
function recordArray(values) {
  const array = [...values];
  // JSON.stringify otherwise invokes a polluted Array.prototype.toJSON.
  Object.defineProperty(array, 'toJSON', { value: undefined });
  return array;
}

// Data descriptors only: getters, inherited values, toJSON and object coercion are never invoked.
function own(value, key) {
  if (!value || typeof value !== 'object') return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch { return undefined; }
}
const enumValue = (value, allowed, fallback) => typeof value === 'string' && allowed.has(value) ? value : fallback;
const safeInteger = (value, maximum) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const generatedId = () => {
  const value = globalThis.crypto.randomUUID();
  if (!uuidV4.test(value)) throw Error('Diagnostic identifier generation failed.');
  return value;
};
function countsFrom(input) {
  const result = Object.create(null);
  for (const [key, limit] of Object.entries(countLimits)) {
    const value = own(input, key);
    if (safeInteger(value, limit)) result[key] = value;
  }
  return Object.freeze(result);
}
function safeDuration(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 3_600_000 ? Math.round(value / 100) * 100 : undefined;
}

/** Bucket an observed failure without copying its message, stack, arbitrary code or response. */
export function classifyTraceError(error) {
  const code = own(error, 'code');
  if (typeof code === 'string' && errorCodes.has(code) && code !== 'none') return code;
  if (code === 'provider_unavailable') return 'provider_failure';
  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return 'timeout';
  if (code === 'ENOTFOUND' || code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'EAI_AGAIN') return 'network_failure';
  if (code === 'ENOENT') return 'not_found';
  if (code === 'EACCES' || code === 'EPERM' || code === 'ENOSPC' || code === 'EROFS') return 'local_io_failure';
  const name = own(error, 'name');
  if (name === 'AbortError' || name === 'TimeoutError') return 'timeout';
  const status = own(error, 'status');
  if (status === 429) return 'quota_exceeded';
  if (status === 401 || status === 403) return 'access_denied';
  if (status === 404) return 'not_found';
  if (status === 400 || status === 413 || status === 422) return 'invalid_request';
  if (status === 405) return 'unsupported_method';
  if (status === 415) return 'unsupported_media_type';
  if (status === 408 || status === 504) return 'timeout';
  if (status === 502) return 'provider_failure';
  if (status === 503) return 'busy';
  return 'unknown';
}

/**
 * Create one ephemeral diagnostic run. IDs/version/time are generated here, never accepted
 * from a request or project. The recorder is an opaque capability, not a telemetry endpoint.
 */
export function createOffenseTrace(options = {}) {
  const origin = own(options, 'origin');
  if (!origins.has(origin)) throw Error('Diagnostics require a supported component origin.');
  const base = Object.freeze(recordObject({ schemaVersion: OFFENSE_TRACE_SCHEMA, runId: generatedId(), requestId: generatedId(),
    origin, transport: enumValue(own(options, 'transport'), transports, 'unknown'), componentVersion: OFFENSE_TRACE_VERSIONS[origin] }));
  const state = { base, events: recordArray([]) };
  const recorder = Object.freeze({ runId: base.runId, requestId: base.requestId,
    record(stage, outcome, fields = {}) {
      if (state.events.length >= MAX_TRACE_EVENTS) return null;
      const durationMs = safeDuration(own(fields, 'durationMs'));
      const requestedErrorCode = own(fields, 'errorCode'), requestedEvidenceSource = own(fields, 'evidenceSource');
      const event = Object.freeze(recordObject({ ...base, eventId: generatedId(), timestampMs: Math.floor(Date.now() / 60_000) * 60_000,
        event: enumValue(own(fields, 'event'), events, 'stage'), stage: enumValue(stage, stages, 'unknown'),
        outcome: enumValue(outcome, outcomes, 'unknown'), errorCode: requestedErrorCode === undefined ? 'none' : enumValue(requestedErrorCode, errorCodes, 'unknown'),
        evidenceSource: requestedEvidenceSource === undefined ? 'observed' : enumValue(requestedEvidenceSource, evidenceSources, 'unknown'),
        ...(durationMs !== undefined ? { durationMs } : {}), counts: countsFrom(own(fields, 'counts')) }));
      const snapshot = recordObject({ ...base, events: recordArray([...state.events, event]) });
      if (JSON.stringify(snapshot).length > MAX_TRACE_BYTES) return null;
      ownedEvents.add(event); state.events.push(event); return event;
    },
    snapshot() { return Object.freeze(recordObject({ ...base, events: Object.freeze(recordArray(state.events)) })); },
  });
  ownedTraces.set(recorder, state);
  return recorder;
}

/** Only constructor-owned events may cross a server writer boundary. */
export function serializeTraceEvent(event) {
  if (!event || typeof event !== 'object' || !ownedEvents.has(event)) throw Error('Only constructed diagnostic events can be serialized.');
  return JSON.stringify(event);
}

/** Serialize a local report; passing an arbitrary object does not create a valid trace. */
export function serializeOffenseTrace(recorder) {
  const state = recorder && typeof recorder === 'object' ? ownedTraces.get(recorder) : null;
  if (!state) throw Error('Only constructed diagnostic runs can be serialized.');
  return JSON.stringify(recordObject({ ...state.base, events: state.events }));
}

/**
 * Readback for a trusted table containing previously constructed events, never public input.
 * Revalidate every field, including IDs and nested counts, before export; reject unknown keys.
 * Returned values are not registered for writes through serializeTraceEvent.
 */
export function readStoredTraceEvent(serialized) {
  if (typeof serialized !== 'string' || serialized.length > 4_000) return null;
  let value;
  try { value = JSON.parse(serialized); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const keys = new Set(['schemaVersion', 'runId', 'requestId', 'origin', 'transport', 'componentVersion', 'eventId', 'timestampMs',
    'event', 'stage', 'outcome', 'errorCode', 'evidenceSource', 'durationMs', 'counts']);
  if (Object.keys(value).some(key => !keys.has(key))) return null;
  if ([...keys].filter(key => key !== 'durationMs').some(key => !Object.hasOwn(value, key))) return null;
  if (value.schemaVersion !== OFFENSE_TRACE_SCHEMA || !origins.has(value.origin) || !transports.has(value.transport) ||
    value.componentVersion !== OFFENSE_TRACE_VERSIONS[value.origin] || !['runId', 'requestId', 'eventId'].every(key => typeof value[key] === 'string' && uuidV4.test(value[key])) ||
    !events.has(value.event) || !stages.has(value.stage) || !outcomes.has(value.outcome) || !errorCodes.has(value.errorCode) || !evidenceSources.has(value.evidenceSource) ||
    !safeInteger(value.timestampMs, 8_640_000_000_000_000) || value.timestampMs % 60_000 !== 0 || value.timestampMs > Date.now() + 60_000) return null;
  if (Object.hasOwn(value, 'durationMs') && (safeDuration(value.durationMs) !== value.durationMs || !safeInteger(value.durationMs, 3_600_000))) return null;
  if (!value.counts || typeof value.counts !== 'object' || Array.isArray(value.counts) ||
    Object.entries(value.counts).some(([key, count]) => !Object.hasOwn(countLimits, key) || !safeInteger(count, countLimits[key]))) return null;
  const counts = countsFrom(value.counts);
  return Object.freeze(recordObject({ schemaVersion: OFFENSE_TRACE_SCHEMA, runId: value.runId, requestId: value.requestId, origin: value.origin,
    transport: value.transport, componentVersion: value.componentVersion, eventId: value.eventId, timestampMs: value.timestampMs,
    event: value.event, stage: value.stage, outcome: value.outcome, errorCode: value.errorCode, evidenceSource: value.evidenceSource,
    ...(Object.hasOwn(value, 'durationMs') ? { durationMs: value.durationMs } : {}), counts }));
}
