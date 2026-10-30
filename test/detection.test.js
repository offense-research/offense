import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createEventStore } from '../server/event-store.js';
import { classifyEvent } from '../server/detection.js';

function setup() {
  const db = new DatabaseSync(':memory:');
  return { db, store: createEventStore(db) };
}

function event(queueMessageId, extras = {}) {
  return { schema: 'purple.tail.v1', sourceWorker: 'api', timestamp: new Date().toISOString(), queueMessageId, ...extras };
}

test('five authentication failures become one workspace-scoped investigation and retries add nothing', () => {
  const { db, store } = setup();
  for (let i = 1; i <= 4; i++) store.receiveBatch('customer-a', [event(`auth-${i}`, { responseStatus: 401 })]);
  assert.equal(store.investigations('customer-a').length, 0);
  store.receiveBatch('customer-b', [event('other-customer', { responseStatus: 401 })]);
  store.receiveBatch('customer-a', [event('auth-5', { responseStatus: 401, requestId: '57d55f210d7b95f3' })]);
  let investigations = store.investigations('customer-a');
  assert.equal(investigations.length, 1);
  assert.equal(investigations[0].ruleId, 'repeated_auth_failure');
  assert.equal(investigations[0].eventCount, 5);
  assert.equal(store.investigation('customer-b', investigations[0].id), null);
  assert.equal(store.investigation('customer-a', investigations[0].id).events.length, 5);
  store.receiveBatch('customer-a', [event('auth-5', { responseStatus: 401 })]);
  assert.equal(store.investigations('customer-a')[0].eventCount, 5);
  store.receiveBatch('customer-a', [event('auth-6', { responseStatus: 401 })]);
  assert.equal(store.investigations('customer-a')[0].eventCount, 6);
  db.close();
});

test('exceptions and resource limits group separately without duplicating 5xx investigations', () => {
  const { db, store } = setup();
  store.receiveBatch('customer-a', [event('exception-1', { outcome: 'exception', responseStatus: 500, exceptionNames: ['TypeError'] })]);
  store.receiveBatch('customer-a', [event('exception-2', { outcome: 'exception', responseStatus: 500, exceptionNames: ['TypeError'] })]);
  store.receiveBatch('customer-a', [event('exception-3', { outcome: 'exception', exceptionNames: ['RangeError'] })]);
  store.receiveBatch('customer-a', [event('cpu-1', { outcome: 'exceededCpu' })]);
  const investigations = store.investigations('customer-a');
  assert.equal(investigations.length, 3);
  assert.equal(investigations.find(item => item.ruleId === 'worker_exception' && item.groupKey === 'TypeError').eventCount, 2);
  assert.equal(investigations.find(item => item.ruleId === 'resource_limit').severity, 'high');
  const exception = investigations.find(item => item.ruleId === 'worker_exception' && item.groupKey === 'TypeError');
  assert.equal(store.setInvestigationStatus('customer-a', exception.id, 'resolved'), true);
  store.receiveBatch('customer-a', [event('exception-4', { outcome: 'exception', exceptionNames: ['TypeError'] })]);
  assert.equal(store.investigations('customer-a').filter(item => item.ruleId === 'worker_exception').length, 3);
  db.close();
});

test('suspicious log patterns and server-error bursts require meaningful signals', () => {
  const { db, store } = setup();
  assert.deepEqual(classifyEvent(event('ordinary', { responseStatus: 403, logs: [{ message: 'Normal forbidden response' }] })), []);
  store.receiveBatch('customer-a', [event('attack-1', { responseStatus: 403, logs: [{ level: 'warn', message: 'WAF blocked SQL injection attempt' }] })]);
  for (let i = 1; i <= 8; i++) store.receiveBatch('customer-a', [event(`server-${i}`, { responseStatus: 502 })]);
  const investigations = store.investigations('customer-a');
  assert.equal(investigations.find(item => item.ruleId === 'suspicious_request').severity, 'high');
  assert.equal(investigations.find(item => item.ruleId === 'server_error_burst').eventCount, 8);
  db.close();
});

test('stored events receive detections during schema migration', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL, payload TEXT NOT NULL)');
  db.prepare('INSERT INTO events (session_id, received_at, payload) VALUES (?, ?, ?)').run('customer-a', Date.now(), JSON.stringify(event('historic', { outcome: 'exception' })));
  const store = createEventStore(db);
  assert.equal(store.investigations('customer-a')[0].ruleId, 'worker_exception');
  assert.ok(db.prepare('SELECT detected_at FROM events').get().detected_at);
  db.close();
});
