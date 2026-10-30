import { transactionSync } from './db-transaction.js';

const FIVE_MINUTES = 5 * 60_000;
const THIRTY_MINUTES = 30 * 60_000;

export const RULES = {
  suspicious_request: { title: 'Suspicious request pattern', severity: 'high', description: 'A Worker logged a recognized attack or WAF signal.' },
  repeated_auth_failure: { title: 'Repeated authentication failures', severity: 'medium', description: 'At least five authentication failures reached this Worker within five minutes.' },
  worker_exception: { title: 'Worker exception', severity: 'medium', description: 'The Worker reported an unhandled exception.' },
  resource_limit: { title: 'Worker resource limit', severity: 'high', description: 'The Worker exceeded a CPU or memory limit.' },
  server_error_burst: { title: 'Burst of server errors', severity: 'medium', description: 'At least eight HTTP 5xx responses came from this Worker within five minutes.' }
};

const suspiciousPattern = /\b(?:sql injection|sqli|path traversal|command injection|cross.site scripting|xss attempt|exploit attempt|malicious request|waf (?:block|challenge)|blocked by waf|prototype pollution)\b/i;
const authPattern = /\b(?:login|sign.?in|authentication|password|credential|token)\b.{0,40}\b(?:fail(?:ed|ure)?|denied|invalid|rejected)\b/i;

export function classifyEvent(event) {
  const messages = (event.logs || []).map(log => String(log.message || '')).join('\n');
  const signals = [];
  if (suspiciousPattern.test(messages)) signals.push('suspicious_request');
  if (event.responseStatus === 401 || authPattern.test(messages)) signals.push('auth_failure');
  if (event.outcome === 'exception' || (event.exceptionNames || []).length > 0) signals.push('worker_exception');
  if (event.outcome === 'exceededCpu' || event.outcome === 'exceededMemory') signals.push('resource_limit');
  if (event.responseStatus >= 500 && event.responseStatus <= 599 && !signals.includes('worker_exception')) signals.push('server_error');
  return signals;
}

function groupKey(event, ruleId) {
  if (ruleId === 'worker_exception') return String(event.exceptionNames?.[0] || 'Unknown exception').slice(0, 64);
  if (ruleId === 'resource_limit') return event.outcome;
  if (ruleId === 'suspicious_request') {
    const messages = (event.logs || []).map(log => String(log.message || '')).join('\n');
    if (/\b(?:sql injection|sqli)\b/i.test(messages)) return 'sql_injection';
    if (/\bpath traversal\b/i.test(messages)) return 'path_traversal';
    if (/\bcommand injection\b/i.test(messages)) return 'command_injection';
    if (/\b(?:cross.site scripting|xss attempt)\b/i.test(messages)) return 'xss';
    if (/\bprototype pollution\b/i.test(messages)) return 'prototype_pollution';
    if (/\bwaf\b/i.test(messages)) return 'waf';
    return 'other';
  }
  return '';
}

export function createDetection(db) {
  const columns = new Set(db.prepare('PRAGMA table_info(events)').all().map(column => column.name));
  if (!columns.has('detected_at')) db.exec('ALTER TABLE events ADD COLUMN detected_at INTEGER');
  db.exec(`CREATE TABLE IF NOT EXISTS detection_signals (
    event_id INTEGER NOT NULL, session_id TEXT NOT NULL, source_worker TEXT NOT NULL,
    kind TEXT NOT NULL, received_at INTEGER NOT NULL, request_id TEXT,
    PRIMARY KEY (event_id, kind)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, rule_id TEXT NOT NULL, group_key TEXT NOT NULL DEFAULT '',
    source_worker TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
    severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  )`);
  const investigationColumns = new Set(db.prepare('PRAGMA table_info(investigations)').all().map(column => column.name));
  if (!investigationColumns.has('group_key')) db.exec("ALTER TABLE investigations ADD COLUMN group_key TEXT NOT NULL DEFAULT ''");
  db.exec(`CREATE TABLE IF NOT EXISTS investigation_events (
    investigation_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
    received_at INTEGER NOT NULL, request_id TEXT, reason TEXT NOT NULL,
    PRIMARY KEY (investigation_id, event_id)
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS signals_window ON detection_signals(session_id, source_worker, kind, received_at)');
  db.exec('CREATE INDEX IF NOT EXISTS signals_retention ON detection_signals(received_at)');
  db.exec('CREATE INDEX IF NOT EXISTS investigations_workspace ON investigations(session_id, status, last_seen DESC)');
  db.exec('CREATE INDEX IF NOT EXISTS investigations_group_key ON investigations(session_id, source_worker, rule_id, group_key, last_seen DESC)');
  db.exec('CREATE INDEX IF NOT EXISTS investigation_events_recent ON investigation_events(investigation_id, received_at DESC)');

  const insertSignal = db.prepare('INSERT OR IGNORE INTO detection_signals (event_id, session_id, source_worker, kind, received_at, request_id) VALUES (?, ?, ?, ?, ?, ?)');
  const recentSignals = db.prepare('SELECT event_id AS eventId, received_at AS receivedAt, request_id AS requestId FROM detection_signals WHERE session_id = ? AND source_worker = ? AND kind = ? AND received_at BETWEEN ? AND ? ORDER BY received_at, event_id');
  const currentInvestigation = db.prepare("SELECT id FROM investigations WHERE session_id = ? AND source_worker = ? AND rule_id = ? AND group_key = ? AND status = 'open' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1");
  const createInvestigation = db.prepare('INSERT INTO investigations (session_id, rule_id, group_key, source_worker, title, description, severity, first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const attachEvidence = db.prepare('INSERT OR IGNORE INTO investigation_events (investigation_id, event_id, received_at, request_id, reason) VALUES (?, ?, ?, ?, ?)');
  const updateInvestigation = db.prepare('UPDATE investigations SET first_seen = min(first_seen, ?), last_seen = max(last_seen, ?), event_count = event_count + ?, updated_at = ? WHERE id = ?');
  const pruneEvidence = db.prepare('DELETE FROM investigation_events WHERE investigation_id = ? AND event_id NOT IN (SELECT event_id FROM investigation_events WHERE investigation_id = ? ORDER BY received_at DESC, event_id DESC LIMIT 100)');
  const pruneSignals = db.prepare('DELETE FROM detection_signals WHERE received_at < ?');
  const markDetected = db.prepare('UPDATE events SET detected_at = ? WHERE id = ?');

  function attach(sessionId, worker, ruleId, key, evidence, event, receivedAt) {
    const rule = RULES[ruleId];
    let investigation = currentInvestigation.get(sessionId, worker, ruleId, key, receivedAt - THIRTY_MINUTES);
    if (!investigation) {
      const firstSeen = evidence[0].receivedAt;
      investigation = { id: Number(createInvestigation.run(sessionId, ruleId, key, worker, rule.title, rule.description, rule.severity, firstSeen, receivedAt, Date.now(), Date.now()).lastInsertRowid) };
    }
    let added = 0;
    for (const item of evidence) {
      const reason = item.eventId === event.id ? event.reason : `Part of the ${rule.title.toLowerCase()} pattern`;
      added += Number(attachEvidence.run(investigation.id, item.eventId, item.receivedAt, item.requestId || null, reason).changes);
    }
    if (added) {
      updateInvestigation.run(evidence[0].receivedAt, receivedAt, added, Date.now(), investigation.id);
      pruneEvidence.run(investigation.id, investigation.id);
    }
  }

  function processEvent(sessionId, eventId, event, receivedAt) {
    const worker = event.sourceWorker;
    const signals = classifyEvent(event);
    const current = { id: eventId, requestId: event.requestId || event.queueMessageId || null,
      reason: event.outcome === 'exception' ? 'Unhandled Worker exception' : event.outcome === 'exceededCpu' || event.outcome === 'exceededMemory' ? event.outcome :
        event.responseStatus ? `HTTP ${event.responseStatus}` : 'Matched a redacted log signal' };
    for (const signal of signals) insertSignal.run(eventId, sessionId, worker, signal, receivedAt, current.requestId);
    for (const signal of signals) {
      if (signal === 'auth_failure' || signal === 'server_error') {
        const evidence = recentSignals.all(sessionId, worker, signal, receivedAt - FIVE_MINUTES, receivedAt);
        const threshold = signal === 'auth_failure' ? 5 : 8;
        if (evidence.length >= threshold) attach(sessionId, worker, signal === 'auth_failure' ? 'repeated_auth_failure' : 'server_error_burst', '', evidence, current, receivedAt);
      } else attach(sessionId, worker, signal, groupKey(event, signal), [{ eventId, receivedAt, requestId: current.requestId }], current, receivedAt);
    }
    markDetected.run(Date.now(), eventId);
  }

  function backfill() {
    const rows = db.prepare('SELECT id, session_id AS sessionId, received_at AS receivedAt, payload FROM events WHERE detected_at IS NULL ORDER BY received_at, id').all();
    if (!rows.length) return 0;
    transactionSync(db, () => {
      for (const row of rows) processEvent(row.sessionId, row.id, JSON.parse(row.payload), row.receivedAt);
    });
    return rows.length;
  }

  function list(sessionId, limit = 20) {
    return db.prepare('SELECT id, rule_id AS ruleId, group_key AS groupKey, source_worker AS sourceWorker, title, description, severity, status, first_seen AS firstSeen, last_seen AS lastSeen, event_count AS eventCount FROM investigations WHERE session_id = ? ORDER BY (status = \'open\') DESC, last_seen DESC LIMIT ?').all(sessionId, limit);
  }

  function evidence(sessionId, id) {
    const investigation = db.prepare('SELECT id, rule_id AS ruleId, group_key AS groupKey, source_worker AS sourceWorker, title, description, severity, status, first_seen AS firstSeen, last_seen AS lastSeen, event_count AS eventCount FROM investigations WHERE session_id = ? AND id = ?').get(sessionId, id);
    if (!investigation) return null;
    return { ...investigation, events: db.prepare('SELECT event_id AS eventId, received_at AS receivedAt, request_id AS requestId, reason FROM investigation_events WHERE investigation_id = ? ORDER BY received_at DESC, event_id DESC LIMIT 20').all(id) };
  }

  function setStatus(sessionId, id, status) {
    const result = db.prepare('UPDATE investigations SET status = ?, updated_at = ? WHERE session_id = ? AND id = ?').run(status, Date.now(), sessionId, id);
    return Boolean(result.changes);
  }

  return { processEvent, backfill, list, evidence, setStatus,
    pruneOldSignals: now => pruneSignals.run(now - 24 * 60 * 60_000) };
}
