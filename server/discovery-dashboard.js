import { verificationQualified } from '../agent/verification-gate.mjs';
import { createHash } from 'node:crypto';
const TIME_ZONE = 'America/New_York';
const comparableCoverage = (current, previous) => Boolean(current && previous && ((!current.failedScans && !previous.failedScans) || (current.failedCoverage && current.failedCoverage === previous.failedCoverage)));
const fixture = repository => String(repository).toLowerCase() === 'imranye/purple-e2e-fixture';
const formatter = new Intl.DateTimeFormat('en-US', { timeZone: TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit' });
export function discoveryDay(time) {
  const parts = Object.fromEntries(formatter.formatToParts(new Date(time)).map(part => [part.type, part.value]));
  return `${parts.year}-${parts.month}-${parts.day}`;
}
function shiftDay(day, offset) {
  const date = new Date(`${day}T12:00:00Z`); date.setUTCDate(date.getUTCDate() + offset);
  return date.toISOString().slice(0, 10);
}
export function discoveryGrowth(current, previous) {
  if (previous === null) return { change: null, percent: null };
  const change = current - previous;
  return { change, percent: previous === 0 ? change === 0 ? 0 : null : change / previous * 100 };
}
export function isMetricsOperator(user, ids = '') {
  return Boolean(user?.githubId && String(ids).split(',').map(id => id.trim()).filter(id => /^\d+$/.test(id)).includes(String(user.githubId)));
}

export function createDiscoveryDashboard(db, { now = Date.now } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS discovery_metric_days (
    day TEXT PRIMARY KEY, first_observed_at INTEGER NOT NULL, observed_at INTEGER NOT NULL, data TEXT NOT NULL
  )`);
  function capture() {
    const timestamp = now(), day = discoveryDay(timestamp);
    const saved = db.prepare('SELECT observed_at FROM discovery_metric_days WHERE day = ?').get(day);
    if (saved && timestamp - saved.observed_at < 60_000) return;
    const counts = { customer: 0, test: 0, completedScans: 0, failedScans: 0, uncheckedScans: 0, latestScanAt: null };
    const failedSources = [];
    for (const row of db.prepare('SELECT session_id, repository, installation_id, data FROM dependency_snapshots').all()) {
      const check = JSON.parse(row.data).vulnerabilityCheck;
      if (check?.status !== 'complete') {
        if (check?.status === 'failed') {
          counts.failedScans++; failedSources.push(JSON.stringify([row.session_id, row.repository, row.installation_id]));
        } else counts.uncheckedScans++;
        continue;
      }
      counts.completedScans++;
      counts[fixture(row.repository) ? 'test' : 'customer'] += (check.findings || []).length;
      if (check.checkedAt) counts.latestScanAt = Math.max(counts.latestScanAt || 0, check.checkedAt);
    }
    counts.failedCoverage = createHash('sha256').update(JSON.stringify(failedSources.sort())).digest('hex');
    db.prepare(`INSERT INTO discovery_metric_days (day, first_observed_at, observed_at, data) VALUES (?, ?, ?, ?)
      ON CONFLICT(day) DO UPDATE SET observed_at = excluded.observed_at, data = excluded.data`)
      .run(day, timestamp, timestamp, JSON.stringify(counts));
  }
  function read({ days = 30, includeTests = false } = {}) {
    if (![7, 30, 90].includes(days)) throw Object.assign(new Error('Choose 7, 30 or 90 days.'), { status: 400 });
    capture();
    const timestamp = now(), today = discoveryDay(timestamp), start = shiftDay(today, 1 - days), yesterday = shiftDay(today, -1);
    const observations = new Map(db.prepare('SELECT * FROM discovery_metric_days WHERE day >= ? AND day <= ? ORDER BY day').all(shiftDay(start, -1), today)
      .map(row => [row.day, { ...JSON.parse(row.data), observedAt: row.observed_at }]));
    const additions = new Map(); let prior = 0, fixtureTotal = 0;
    for (const row of db.prepare('SELECT discovered_at, is_test, verification FROM vulnerability_discoveries WHERE discovered_at <= ?').all(timestamp)) {
      let evidence; try { evidence = JSON.parse(row.verification); } catch {}
      if (!verificationQualified(evidence)) continue;
      if (row.is_test) fixtureTotal++;
      if (row.is_test && !includeTests) continue;
      const day = discoveryDay(row.discovered_at);
      if (day < start) prior++; else additions.set(day, (additions.get(day) || 0) + 1);
    }
    const matches = observation => observation ? observation.customer + (includeTests ? observation.test : 0) : null;
    let cumulative = prior;
    const series = Array.from({ length: days }, (_, index) => {
      const date = shiftDay(start, index), confirmedNew = additions.get(date) || 0;
      cumulative += confirmedNew;
      const observation = observations.get(date), previous = observations.get(shiftDay(date, -1));
      const advisoryMatches = matches(observation);
      const comparable = comparableCoverage(observation, previous);
      return { date, confirmedNew, confirmedTotal: cumulative, advisoryMatches,
        advisoryChange: comparable ? advisoryMatches - matches(previous) : null,
        advisoryComplete: observation ? !observation.failedScans : null, observedAt: observation?.observedAt || null };
    });
    const current = observations.get(today), previous = observations.get(yesterday);
    const history = db.prepare('SELECT MIN(first_observed_at) AS startedAt FROM discovery_metric_days').get();
    const todayNew = additions.get(today) || 0;
    const comparable = comparableCoverage(current, previous);
    return { generatedAt: timestamp, timezone: TIME_ZONE, days, includeTests, historyStartedAt: history.startedAt,
      summary: {
        confirmed: { total: cumulative, todayNew, yesterdayNew: additions.get(yesterday) || 0,
          ...discoveryGrowth(cumulative, cumulative - todayNew), excludedFixtures: includeTests ? 0 : fixtureTotal },
        advisories: { total: matches(current), ...discoveryGrowth(matches(current), comparable ? matches(previous) : null),
          observedAt: current?.observedAt || null, completedScans: current?.completedScans || 0,
          failedScans: current?.failedScans || 0, uncheckedScans: current?.uncheckedScans || 0,
          latestScanAt: current?.latestScanAt || null, excludedFixtures: includeTests ? 0 : current?.test || 0 }
      }, series };
  }
  return { capture, read };
}

export function registerDiscoveryDashboard(app, { dashboard, operatorIds }) {
  app.get('/api/operator/discoveries', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser) return res.status(401).json({ error: 'Sign in with GitHub to view company metrics.' });
    if (!isMetricsOperator(req.authUser, operatorIds)) return res.status(403).json({ error: 'Company metrics are restricted to Purple operators.' });
    const days = req.query.days === undefined ? 30 : Number(req.query.days);
    if (req.query.includeTests !== undefined && !['0', '1'].includes(req.query.includeTests)) return res.status(400).json({ error: 'Invalid test fixture selection.' });
    res.json(dashboard.read({ days, includeTests: req.query.includeTests === '1' }));
  });
}
