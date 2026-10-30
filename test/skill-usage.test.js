import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSkillUsageStore, skillUsageMetrics } from '../server/skill-usage.js';

const DAY = 86_400_000, NOW = Date.UTC(2026, 9, 26, 12);
function database(t) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close()); return db;
}

test('audit outcomes, route channels and planning stay separate, including unfinished requests', t => {
  const db = database(t); let now = NOW;
  const store = createSkillUsageStore({ db, now: () => now });
  const a = store.start({ channel: 'mcp', operation: 'audit' }); now += 100;
  assert.equal(a.finish({ status: 'completed', checkedPackages: 8, advisoryMatches: 2, severity: { critical: 1, high: 1 } }), true);
  const b = store.start({ channel: 'https', operation: 'audit' }); now += 200;
  assert.equal(b.finish({ status: 'partial', checkedPackages: 4, advisoryMatches: 3, severity: { medium: 2, unknown: 1 } }), true);
  const c = store.start({ channel: 'legacy', operation: 'audit' }); now += 50; c.finish({ status: 'failed' });
  const d = store.start({ channel: 'mcp', operation: 'audit' }); now += 10; d.finish({ status: 'rejected' });
  store.start({ channel: 'https', operation: 'audit' });
  const planning = store.start({ channel: 'mcp', operation: 'planning' }); now += 100;
  planning.finish({ status: 'completed', checkedPackages: 1, advisoryMatches: 7 });
  const metrics = store.read({ days: 7 });
  assert.equal(metrics.coverage.available, true); assert.equal(metrics.timezone, 'UTC');
  assert.equal(metrics.coverage.trackingStartedAt, NOW); assert.equal(metrics.coverage.historyComplete, false);
  assert.deepEqual(metrics.totals, { started: 5, completed: 1, partial: 1, failed: 1, rejected: 1,
    checkedPackages: 12, advisoryMatches: 5, durationMs: 360, durationSamples: 4, unfinished: 1,
    severity: { critical: 1, high: 1, medium: 2, low: 0, unknown: 1 } });
  assert.deepEqual(metrics.lifetime, metrics.totals);
  assert.deepEqual(metrics.channels.map(row => [row.channel, row.started, row.advisoryMatches]), [['mcp', 2, 2], ['https', 2, 3], ['legacy', 1, 0]]);
  assert.equal(metrics.operations.find(row => row.operation === 'planning').advisoryMatches, 7);
  assert.equal(metrics.operations.find(row => row.operation === 'audit').advisoryMatches, 5);
  assert.equal(metrics.series.at(-1).started, 5);
  assert.equal(metrics.series.at(-2).started, null, 'pre-collection days are unknown');
  assert.equal(metrics.series.at(-2).tracked, false);
  assert.match(metrics.definitions.advisoryMatches, /Repeat audits count again/);
  assert.equal('confirmedVulnerabilities' in metrics.totals, false);
});

test('counts survive connection restart and trace removal; period and lifetime have distinct windows', t => {
  const folder = mkdtempSync(join(tmpdir(), 'purple-skill-usage-')); t.after(() => rmSync(folder, { recursive: true, force: true }));
  const file = join(folder, 'usage.sqlite'); let db = new DatabaseSync(file), now = NOW - 40 * DAY;
  let store = createSkillUsageStore({ db, now: () => now });
  store.start({ channel: 'legacy', operation: 'audit' }).finish({ status: 'completed', checkedPackages: 1, advisoryMatches: 3 });
  db.exec('CREATE TABLE offense_trace_events(event TEXT); INSERT INTO offense_trace_events VALUES (\'temporary\'); DROP TABLE offense_trace_events;');
  db.close(); db = new DatabaseSync(file); t.after(() => db.close()); now = NOW;
  store = createSkillUsageStore({ db, now: () => now });
  store.start({ channel: 'https', operation: 'audit' }).finish({ status: 'completed', checkedPackages: 5, advisoryMatches: 2 });
  const seven = store.read({ days: 7 });
  assert.equal(seven.totals.started, 1); assert.equal(seven.totals.advisoryMatches, 2);
  assert.equal(seven.lifetime.started, 2); assert.equal(seven.lifetime.advisoryMatches, 5);
  assert.equal(seven.coverage.trackingStartedAt, NOW - 40 * DAY, 'restart preserves first collection time');
  assert.equal(seven.series[0].started, 0, 'known idle days after collection began are zero');
  assert.equal(store.read({ days: 90 }).totals.started, 2);
});

test('a request crossing UTC midnight settles its start-day cohort exactly once', t => {
  const db = database(t); let now = Date.UTC(2026, 9, 26, 23, 59, 59, 900);
  const store = createSkillUsageStore({ db, now: () => now });
  const request = store.start({ channel: 'mcp', operation: 'audit' }); now += 200;
  assert.equal(request.finish({ status: 'partial', checkedPackages: 2, advisoryMatches: 1 }), true);
  assert.equal(request.finish({ status: 'completed', checkedPackages: 100, advisoryMatches: 50 }), false);
  const result = store.read({ days: 7 }), previous = result.series.at(-2), current = result.series.at(-1);
  assert.equal(previous.date, '2026-10-26'); assert.equal(previous.started, 1); assert.equal(previous.partial, 1); assert.equal(previous.unfinished, 0);
  assert.equal(previous.durationMs, 200); assert.equal(current.date, '2026-10-27'); assert.equal(current.started, 0);
  assert.equal(result.totals.partial, 1); assert.equal(result.totals.completed, 0); assert.equal(result.totals.advisoryMatches, 1);
});

test('independent in-flight handles update the same durable bucket without lost increments', t => {
  const db = database(t), store = createSkillUsageStore({ db, now: () => NOW });
  const requests = Array.from({ length: 50 }, () => store.start({ channel: 'https', operation: 'audit' }));
  assert.equal(store.read().totals.unfinished, 50);
  for (const request of requests.reverse()) {
    request.finish({ status: 'completed', checkedPackages: 3, advisoryMatches: 1 });
    request.finish({ status: 'failed' });
  }
  assert.equal(store.read().totals.completed, 50); assert.equal(store.read().totals.checkedPackages, 150);
  assert.equal(store.read().totals.advisoryMatches, 50); assert.equal(store.read().totals.unfinished, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM skill_usage_days').get().count, 1);
});

test('only bounded numeric facts and fixed channel/operation labels reach database bindings', t => {
  const db = database(t), bindings = [], privateValue = 'PRIVATE_customer_token_source_and_repo_98391'; let getters = 0;
  const observedDb = { exec: sql => db.exec(sql), prepare(sql) {
    const statement = db.prepare(sql);
    return { get: (...values) => statement.get(...values), all: (...values) => statement.all(...values), run(...values) {
      bindings.push(values); return statement.run(...values);
    } };
  } };
  const store = createSkillUsageStore({ db: observedDb, now: () => NOW });
  const requestInput = { channel: 'mcp', operation: 'audit', ip: privateValue, repository: privateValue, requestId: privateValue, [privateValue]: privateValue };
  Object.defineProperty(requestInput, 'extra', { get() { getters++; throw Error(privateValue); } });
  const resultInput = { status: 'completed', checkedPackages: 2, advisoryMatches: 1, severity: { high: 1, secret: privateValue },
    source: privateValue, package: privateValue, advisoryId: privateValue, headers: { Authorization: privateValue } };
  Object.defineProperty(resultInput, 'extra', { get() { getters++; throw Error(privateValue); } });
  store.start(requestInput).finish(resultInput);
  const dump = { bindings, days: db.prepare('SELECT * FROM skill_usage_days').all(), meta: db.prepare('SELECT * FROM skill_usage_meta').all(), output: store.read() };
  assert.equal(getters, 0); assert.ok(!JSON.stringify(dump).includes(privateValue));
  assert.equal(store.read().totals.advisoryMatches, 1);
  assert.deepEqual(Object.keys(dump.days[0]), ['day', 'channel', 'operation', 'started', 'completed', 'partial', 'failed', 'rejected',
    'checked_packages', 'advisory_matches', 'critical', 'high', 'medium', 'low', 'unknown', 'duration_ms', 'duration_samples']);
});

test('invalid enums, count values and severity totals are rejected without terminal writes or property getters', t => {
  const db = database(t), store = createSkillUsageStore({ db, now: () => NOW }); let getters = 0;
  for (const input of [{ channel: 'private-identity', operation: 'audit' }, { channel: 'mcp', operation: 'discovery' }, null, []])
    assert.equal(store.start(input).finish({ status: 'completed' }), false);
  const poisoned = { operation: 'audit' }; Object.defineProperty(poisoned, 'channel', { get() { getters++; throw Error('private'); } });
  assert.equal(store.start(poisoned).finish({ status: 'completed' }), false); assert.equal(getters, 0);
  const request = store.start({ channel: 'mcp', operation: 'audit' });
  for (const value of [null, -1, NaN, Infinity, 0.5, 10_000_001, '12'])
    assert.equal(request.finish({ status: 'completed', advisoryMatches: value }), false, String(value));
  for (const input of [{ status: 'private-identity' }, { status: 'completed', advisoryMatches: 1, severity: { high: 2 } },
    { status: 'completed', advisoryMatches: 0, severity: null }, { status: 'completed', severity: { high: null } },
    { status: 'failed', checkedPackages: 1 }, { status: 'rejected', advisoryMatches: 1 }]) assert.equal(request.finish(input), false);
  assert.equal(store.read().totals.unfinished, 1); assert.equal(store.read().totals.completed, 0);
  assert.equal(request.finish({ status: 'completed' }), true, 'invalid attempts do not consume the terminal handle');
  assert.equal(store.read().totals.completed, 1); assert.equal(store.read().totals.unfinished, 0);
});

test('absent collection is unknown and the metrics reader never initializes or writes tables', t => {
  const db = database(t), before = db.prepare('SELECT total_changes() AS count').get().count;
  const result = skillUsageMetrics(db, { days: 7, now: () => NOW });
  assert.equal(result.coverage.available, false); assert.equal(result.coverage.trackingStartedAt, null);
  assert.equal(result.totals.started, null); assert.equal(result.lifetime.advisoryMatches, null);
  assert.equal(result.channels.length, 3); assert.ok(result.channels.every(channel => channel.started === null));
  assert.equal(result.operations.length, 2); assert.ok(result.series.every(day => day.started === null));
  assert.equal(db.prepare('SELECT total_changes() AS count').get().count, before);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table'").get().count, 0);
  assert.throws(() => skillUsageMetrics(db, { days: 31, now: NOW }), error => error.status === 400);
  assert.throws(() => skillUsageMetrics(db, { days: 7, now: NaN }), error => error.status === 400);
});

test('schema migration initializes empty collection tables and respects SQL enum boundaries', t => {
  const db = database(t);
  db.exec(readFileSync(new URL('../migrations/0008_skill_usage.sql', import.meta.url), 'utf8'));
  assert.equal(skillUsageMetrics(db, { now: NOW }).coverage.available, false, 'migration alone does not invent a collection start');
  const store = createSkillUsageStore({ db, now: () => NOW });
  assert.equal(store.read().coverage.available, true); assert.equal(store.read().totals.started, 0);
  assert.throws(() => db.prepare('INSERT INTO skill_usage_days(day,channel,operation) VALUES(?,?,?)').run('2026-10-26', 'arbitrary-client-name', 'audit'), /CHECK/);
});

test('recording storage failures never throw into audits and cannot masquerade as zero usage', t => {
  const db = database(t); let failFinish = false;
  const observedDb = { exec: sql => db.exec(sql), prepare(sql) {
    const statement = db.prepare(sql);
    return { get: (...values) => statement.get(...values), all: (...values) => statement.all(...values), run(...values) {
      if (failFinish && sql.startsWith('UPDATE skill_usage_days')) throw Error('PRIVATE_database_error');
      return statement.run(...values);
    } };
  } };
  const store = createSkillUsageStore({ db: observedDb, now: () => NOW });
  const request = store.start({ channel: 'https', operation: 'audit' }); failFinish = true;
  assert.equal(request.finish({ status: 'completed', advisoryMatches: 1 }), false);
  assert.equal(store.read().coverage.available, false); assert.equal(store.read().totals.started, null);
  assert.equal(skillUsageMetrics(observedDb, { now: NOW }).totals.advisoryMatches, null);
  assert.ok(!JSON.stringify(store.read()).includes('PRIVATE_database_error'));
  assert.equal(request.finish({ status: 'failed' }), false);
  const secondDb = database(t), startFailingDb = { exec: sql => secondDb.exec(sql), prepare(sql) {
    const statement = secondDb.prepare(sql);
    return { get: (...values) => statement.get(...values), all: (...values) => statement.all(...values), run(...values) {
      if (sql.startsWith('INSERT INTO skill_usage_days')) throw Error('unavailable'); return statement.run(...values);
    } };
  } };
  const second = createSkillUsageStore({ db: startFailingDb, now: () => NOW });
  assert.equal(second.start({ channel: 'legacy', operation: 'audit' }).finish({ status: 'completed' }), false);
  assert.equal(second.read().coverage.available, false); assert.equal(second.read().totals.started, null);
  const failedInitialization = createSkillUsageStore({ db: { exec() { throw Error('unavailable'); } }, now: () => NOW });
  assert.equal(failedInitialization.start({ channel: 'mcp', operation: 'audit' }).finish({ status: 'completed' }), false);
  assert.equal(failedInitialization.read().coverage.available, false);
});

test('lost cohorts and invalid aggregate data report unavailable instead of invented clean totals', t => {
  const db = database(t), store = createSkillUsageStore({ db, now: () => NOW });
  const request = store.start({ channel: 'mcp', operation: 'audit' });
  db.exec('DELETE FROM skill_usage_days');
  assert.equal(request.finish({ status: 'completed' }), false); assert.equal(store.read().coverage.available, false);
  const corruptDb = database(t), other = createSkillUsageStore({ db: corruptDb, now: () => NOW });
  other.start({ channel: 'mcp', operation: 'audit' });
  corruptDb.exec('UPDATE skill_usage_days SET completed = 4');
  const result = other.read(); assert.equal(result.coverage.available, false); assert.equal(result.totals.completed, null);
});
