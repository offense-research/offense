import { createDetection } from './detection.js';
import { transactionSync } from './db-transaction.js';

export function createEventStore(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL, payload TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS ingest_batches (
    id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL,
    message_count INTEGER NOT NULL, accepted_count INTEGER NOT NULL DEFAULT 0,
    duplicate_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending'
  )`);
  const columns = new Set(db.prepare('PRAGMA table_info(events)').all().map(column => column.name));
  if (!columns.has('queue_message_id')) db.exec('ALTER TABLE events ADD COLUMN queue_message_id TEXT');
  if (!columns.has('batch_id')) db.exec('ALTER TABLE events ADD COLUMN batch_id INTEGER');
  if (!columns.has('analysis_status')) db.exec("ALTER TABLE events ADD COLUMN analysis_status TEXT NOT NULL DEFAULT 'pending'");
  if (!columns.has('exported_at')) db.exec('ALTER TABLE events ADD COLUMN exported_at INTEGER');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS events_queue_message ON events(session_id, queue_message_id) WHERE queue_message_id IS NOT NULL');
  db.exec('CREATE INDEX IF NOT EXISTS events_pending ON events(session_id, analysis_status, id)');
  db.exec('CREATE INDEX IF NOT EXISTS batches_workspace ON ingest_batches(session_id, id DESC)');
  db.exec('CREATE INDEX IF NOT EXISTS events_export_pending ON events(id) WHERE exported_at IS NULL');
  const detection = createDetection(db);
  detection.backfill();

  const addBatch = db.prepare('INSERT INTO ingest_batches (session_id, received_at, message_count) VALUES (?, ?, ?)');
  const addEvent = db.prepare('INSERT OR IGNORE INTO events (session_id, received_at, payload, queue_message_id, batch_id) VALUES (?, ?, ?, ?, ?)');
  const finishBatch = db.prepare('UPDATE ingest_batches SET accepted_count = ?, duplicate_count = ?, status = ? WHERE id = ?');

  function receiveBatch(sessionId, events) {
    const receivedAt = Date.now();
    return transactionSync(db, () => {
      const batchId = Number(addBatch.run(sessionId, receivedAt, events.length).lastInsertRowid);
      let accepted = 0;
      for (const event of events) {
        const safe = {
          schema: 'purple.tail.v1', sourceWorker: event.sourceWorker.slice(0, 128),
          timestamp: String(event.timestamp || '').slice(0, 40), eventType: String(event.eventType || '').slice(0, 20),
          outcome: String(event.outcome || '').slice(0, 64), requestMethod: event.requestMethod ? String(event.requestMethod).slice(0, 16) : null,
          responseStatus: Number.isInteger(event.responseStatus) ? event.responseStatus : null,
          requestId: typeof event.requestId === 'string' && /^[a-f0-9]{16,32}(?:-[A-Z]{3})?$/i.test(event.requestId) ? event.requestId : null,
          queueMessageId: event.queueMessageId || null,
          logLevels: Array.isArray(event.logLevels) ? event.logLevels.slice(0, 100).map(level => String(level).slice(0, 16)) : [],
          logs: Array.isArray(event.logs) ? event.logs.slice(0, 20).map(log => ({
            level: ['debug', 'info', 'log', 'warn', 'error'].includes(log?.level) ? log.level : 'log',
            message: String(log?.message || '').slice(0, 500)
          })) : [],
          exceptionNames: Array.isArray(event.exceptionNames) ? event.exceptionNames.slice(0, 20).map(name => String(name).slice(0, 64)) : []
        };
        const inserted = addEvent.run(sessionId, receivedAt, JSON.stringify(safe), event.queueMessageId || null, batchId);
        if (inserted.changes) detection.processEvent(sessionId, Number(inserted.lastInsertRowid), safe, receivedAt);
        accepted += Number(inserted.changes);
      }
      const duplicates = events.length - accepted;
      detection.pruneOldSignals(receivedAt);
      finishBatch.run(accepted, duplicates, accepted ? 'pending' : 'duplicate', batchId);
      db.exec('DELETE FROM events WHERE exported_at IS NOT NULL AND id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000)');
      db.exec('DELETE FROM ingest_batches WHERE id NOT IN (SELECT id FROM ingest_batches ORDER BY id DESC LIMIT 10000)');
      return { batchId, accepted, duplicates };
    });
  }

  function recentBatches(sessionId) {
    return db.prepare('SELECT id, received_at AS receivedAt, message_count AS messageCount, accepted_count AS acceptedCount, duplicate_count AS duplicateCount, status FROM ingest_batches WHERE session_id = ? ORDER BY id DESC LIMIT 20').all(sessionId);
  }

  function pendingExport(limit = 100) {
    return db.prepare('SELECT id, session_id AS workspaceId, received_at AS receivedAt, payload FROM events WHERE exported_at IS NULL ORDER BY id LIMIT ?').all(limit);
  }

  function markExported(rows) {
    const mark = db.prepare('UPDATE events SET exported_at = ? WHERE id = ? AND exported_at IS NULL');
    transactionSync(db, () => {
      const now = Date.now();
      for (const row of rows) mark.run(now, row.id);
    });
  }

  return { receiveBatch, recentBatches, pendingExport, markExported,
    investigations: detection.list, investigation: detection.evidence, setInvestigationStatus: detection.setStatus };
}
