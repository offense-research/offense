import { createOffenseTrace, serializeTraceEvent, readStoredTraceEvent } from '../shared/offense-trace.js';
import { transactionSync } from './db-transaction.js';

export const OFFENSE_TRACE_LIMITS = Object.freeze({ rows: 10_000, bytes: 4_000_000, eventBytes: 1024, eventsPerRequest: 32, retentionMs: 7 * 24 * 60 * 60 * 1000 });
const contexts = new WeakMap();
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const bounded = (value, fallback, maximum) => Number.isSafeInteger(value) && value > 0 ? Math.min(value, maximum) : fallback;
const timestamp = value => Number.isSafeInteger(value) && value >= 0 ? value : Date.now();
const ownValue = (value, key) => {
  try { const descriptor = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, key) : null;
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch { return undefined; }
};

// Turning collection off must not extend the lifetime of records already
// present. This path creates no table and writes no diagnostic events.
export function pruneOffenseTraceEvents(db, time = Date.now()) {
  try {
    if (!db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'offense_trace_events'").get()) return { status: 'disabled', removed: 0 };
    const current = timestamp(time);
    const removed = db.prepare('DELETE FROM offense_trace_events WHERE expires_at <= ? OR created_at <= ?')
      .run(current, current - OFFENSE_TRACE_LIMITS.retentionMs).changes;
    return { status: 'ok', removed };
  } catch { return { status: 'unavailable', removed: 0 }; }
}

// This store receives only events constructed and allowlisted by the shared
// recorder. It has no request-body, identity, header, error or source interface.
export function createOffenseTraceStore({ db, now = Date.now, limits = {} } = {}) {
  const bounds = Object.freeze(Object.fromEntries(Object.entries(OFFENSE_TRACE_LIMITS).map(([key, maximum]) => [key, bounded(limits[key], maximum, maximum)])));
  let enabled = true;
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS offense_trace_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      bytes INTEGER NOT NULL, event TEXT NOT NULL
    )`);
    db.exec('CREATE INDEX IF NOT EXISTS offense_trace_expiry ON offense_trace_events(expires_at)');
    db.exec('CREATE INDEX IF NOT EXISTS offense_trace_request ON offense_trace_events(request_id, id)');
  } catch { enabled = false; }

  function pruneInside(time) {
    let removed = db.prepare('DELETE FROM offense_trace_events WHERE expires_at <= ? OR created_at <= ?').run(time, time - bounds.retentionMs).changes;
    let totals = db.prepare('SELECT COUNT(*) AS count, COALESCE(SUM(bytes), 0) AS bytes FROM offense_trace_events').get();
    if (totals.count > bounds.rows) {
      removed += db.prepare('DELETE FROM offense_trace_events WHERE id IN (SELECT id FROM offense_trace_events ORDER BY id ASC LIMIT ?)').run(totals.count - bounds.rows).changes;
      totals = db.prepare('SELECT COUNT(*) AS count, COALESCE(SUM(bytes), 0) AS bytes FROM offense_trace_events').get();
    }
    // Usually one old event makes room for a new one. Read only a small chunk
    // during eviction instead of materializing the entire retained trace set.
    let bytes = totals.bytes;
    while (bytes > bounds.bytes) {
      const rows = db.prepare('SELECT id, bytes FROM offense_trace_events ORDER BY id ASC LIMIT 256').all();
      if (!rows.length) break;
      let cutoff = null;
      for (const row of rows) {
        bytes -= row.bytes; cutoff = row.id;
        if (bytes <= bounds.bytes) break;
      }
      removed += db.prepare('DELETE FROM offense_trace_events WHERE id <= ?').run(cutoff).changes;
    }
    return { removed };
  }

  function prune(time = now()) {
    if (!enabled) return { status: 'unavailable', removed: 0 };
    try { return { status: 'ok', ...transactionSync(db, () => pruneInside(timestamp(time))) }; }
    catch { return { status: 'unavailable', removed: 0 }; }
  }

  function persist(event) {
    if (!enabled || !event) return false;
    try {
      // Serialization is also a provenance check: arbitrary object literals,
      // client-provided IDs, payloads and unknown fields cannot reach SQL.
      const serialized = serializeTraceEvent(event);
      const bytes = new TextEncoder().encode(serialized).byteLength;
      if (bytes > bounds.eventBytes || !uuid.test(event.requestId)) return false;
      return transactionSync(db, () => {
        pruneInside(timestamp(now()));
        if ((db.prepare('SELECT COUNT(*) AS count FROM offense_trace_events WHERE request_id = ?').get(event.requestId)?.count || 0) >= bounds.eventsPerRequest) return false;
        db.prepare('INSERT INTO offense_trace_events (request_id, created_at, expires_at, bytes, event) VALUES (?, ?, ?, ?, ?)')
          .run(event.requestId, event.timestampMs, event.timestampMs + bounds.retentionMs, bytes, serialized);
        pruneInside(timestamp(now()));
        return true;
      });
    } catch { return false; }
  }

  function start(transport = 'https') {
    const recorder = createOffenseTrace({ origin: 'server', transport });
    let emitted = 0;
    return Object.freeze({ requestId: recorder.requestId,
      record(stage, outcome, details = {}) {
        try {
          // Reserve space for the terminal response event when the request is
          // unusually large. The recorder independently bounds local memory.
          if (emitted >= bounds.eventsPerRequest || (stage !== 'response' && emitted >= bounds.eventsPerRequest - 1)) return null;
          const event = recorder.record(stage, outcome, { errorCode: ownValue(details, 'errorCode'), durationMs: ownValue(details, 'durationMs'),
            counts: ownValue(details, 'counts'), evidenceSource: 'observed' });
          if (!event) return null;
          emitted++; persist(event); return event;
        } catch { return null; }
      }
    });
  }

  function read({ requestId, limit = 100 } = {}) {
    if (!enabled) return [];
    try {
      const time = timestamp(now());
      const result = prune(time);
      if (result.status !== 'ok') return [];
      if (requestId !== undefined && (typeof requestId !== 'string' || !uuid.test(requestId))) return [];
      const count = bounded(limit, 100, Math.min(bounds.rows, 1000));
      const rows = requestId === undefined ?
        db.prepare('SELECT event FROM offense_trace_events WHERE expires_at > ? ORDER BY id DESC LIMIT ?').all(time, count) :
        db.prepare('SELECT event FROM offense_trace_events WHERE expires_at > ? AND request_id = ? ORDER BY id DESC LIMIT ?').all(time, requestId, count);
      return rows.map(row => readStoredTraceEvent(row.event)).filter(Boolean);
    } catch { return []; }
  }

  prune();
  return Object.freeze({ start, prune, read, limits: bounds });
}

export function offenseRequestTrace(requestOrResponse) {
  return requestOrResponse && typeof requestOrResponse === 'object' ? contexts.get(requestOrResponse) || null : null;
}

// Only route code calls this with a fixed transport. The response UUID is
// always generated here, even if persistence is disabled or unavailable.
export function beginOffenseRequest(req, res, { store, transport = 'https', now = Date.now } = {}) {
  const existing = offenseRequestTrace(req);
  if (existing) return existing;
  let request = null;
  try { request = store?.start(transport); } catch {}
  if (!request) {
    const recorder = createOffenseTrace({ origin: 'server', transport });
    request = { requestId: recorder.requestId, record: () => null };
  }
  let finalOutcome = null, finalCode = 'none', finished = false;
  const started = timestamp(now());
  const context = Object.freeze({ requestId: request.requestId,
    record: (stage, outcome, details) => { try { return request.record(stage, outcome, details); } catch { return null; } },
    outcome(outcome, errorCode = 'none') { finalOutcome = outcome; finalCode = errorCode; },
    reject(errorCode = 'invalid_request') { finalOutcome = 'rejected'; finalCode = errorCode; context.record('validation', 'rejected', { errorCode }); },
    finish(status) {
      if (finished) return; finished = true;
      const outcome = finalOutcome || (status >= 500 ? 'failed' : status >= 400 ? 'rejected' : 'completed');
      context.record('response', outcome, { errorCode: finalCode, durationMs: Math.max(0, timestamp(now()) - started) });
    }
  });
  contexts.set(req, context); contexts.set(res, context);
  res.set('X-Offense-Request-Id', context.requestId);
  context.record('request', 'started');
  if (typeof res.once === 'function') {
    res.once('finish', () => context.finish(res.statusCode));
    res.once('close', () => context.finish(res.statusCode >= 400 ? res.statusCode : 500));
  }
  return context;
}
