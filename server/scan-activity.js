import { usageMetrics } from './usage-metrics.js';
import { hostedScanTools } from './hosted-scans.js';

const DAY = 86_400_000;
const PERIODS = new Set([7, 30, 90]);
const fail = message => Object.assign(new Error(message), { status: 400 });
const exists = (db, table) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
const columns = (db, table) => exists(db, table) ? new Set(db.prepare(`PRAGMA table_info(${table})`).all().map(row => row.name)) : new Set();
const numeric = value => typeof value === 'number' && Number.isFinite(value);
const safeOpaque = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value) ? value : null;

function summary(usage) {
  return { spendMicros: usage.billing.netUsageMicros, jobs: usage.totals.jobs,
    completed: usage.totals.completed, successRate: usage.totals.successRate,
    findings: usage.totals.jobs === 0 && usage.coverage.complete ? 0 : usage.totals.findings,
    findingsSamples: usage.totals.findingsSamples };
}

function coverage(usage) {
  return { ...usage.coverage,
    windowComplete: usage.coverage.complete && Number.isSafeInteger(usage.coverage.firstRecordedAt) &&
      usage.coverage.firstRecordedAt <= usage.period.startAt,
    findingsComplete: Number.isSafeInteger(usage.totals.jobs) && usage.coverage.complete &&
      usage.totals.findingsSamples === usage.totals.jobs };
}

function change(current, previous, comparable) {
  const known = comparable && numeric(current) && numeric(previous);
  return { absolute: known ? current - previous : null,
    percent: known && previous > 0 && current >= 0 ? (current - previous) / previous * 100 : null,
    comparable: !!known };
}

function activitySeries(usage) {
  const trackingStartedAt = usage.coverage.firstRecordedAt;
  return usage.series.map(row => {
    const dayStart = Date.parse(`${row.date}T00:00:00Z`);
    if (row.jobs !== 0 || Number.isSafeInteger(trackingStartedAt) && dayStart >= trackingStartedAt) return row;
    // An empty retained fact set cannot prove zero for an unobserved day.
    // Preserve measured backfilled jobs and exact posted wallet amounts.
    return { ...row, jobs: null, completed: null, partial: null, failed: null,
      active: null, inputBytes: null, findings: null };
  });
}

function keyBreakdown(db, workspaceId, period, spendMicros) {
  const jobColumns = columns(db, 'scan_jobs'), keyColumns = columns(db, 'scan_keys');
  const jobsAvailable = ['id', 'workspace_id', 'key_id', 'created_at'].every(name => jobColumns.has(name));
  const keysAvailable = ['id', 'workspace_id', 'revoked_at'].every(name => keyColumns.has(name));
  const walletAvailable = exists(db, 'scan_wallet_entries');
  if (!jobsAvailable || !keysAvailable) return { topKeys: [], complete: false,
    unattributedSpendMicros: spendMicros, jobsAvailable, keysAvailable };
  // The actual ledger posting date governs spend. A refund can therefore
  // attribute credit to a key whose last submission predates this window.
  const money = walletAvailable ? `SELECT k.id, SUM(-w.amount_micros) AS netUsageMicros
    FROM scan_wallet_entries w
    JOIN scan_jobs j ON j.workspace_id = w.workspace_id AND j.id = CASE
      WHEN w.kind = 'usage' THEN substr(w.id, 7) WHEN w.kind = 'refund' THEN substr(w.id, 8) END
    JOIN scan_keys k ON k.id = j.key_id AND k.workspace_id = j.workspace_id
      AND length(k.id) = 32 AND k.id NOT GLOB '*[^a-f0-9]*'
    WHERE w.workspace_id = ? AND w.created_at >= ? AND w.created_at <= ?
      AND w.kind IN ('usage','refund') GROUP BY k.id` : null;
  const monetary = money ? db.prepare(money).all(workspaceId, period.startAt, period.endAt) : [];
  const spendByKey = new Map(monetary.map(row => [row.id, row.netUsageMicros]));
  const rows = db.prepare(`SELECT k.id, k.revoked_at,
    COUNT(j.id) AS hostedJobs, MAX(j.created_at) AS lastUsedAt
    FROM scan_keys k LEFT JOIN scan_jobs j ON j.key_id = k.id AND j.workspace_id = k.workspace_id
      AND j.created_at >= ? AND j.created_at <= ?
    WHERE k.workspace_id = ? GROUP BY k.id`)
    .all(period.startAt, period.endAt, workspaceId);
  const totalAttributed = monetary.reduce((sum, row) => sum + row.netUsageMicros, 0);
  const unmatched = walletAvailable ? db.prepare(`SELECT COUNT(*) AS n FROM scan_wallet_entries w
    LEFT JOIN scan_jobs j ON j.workspace_id = w.workspace_id AND j.id = CASE
      WHEN w.kind = 'usage' THEN substr(w.id, 7) WHEN w.kind = 'refund' THEN substr(w.id, 8) END
    LEFT JOIN scan_keys k ON k.id = j.key_id AND k.workspace_id = j.workspace_id
    WHERE w.workspace_id = ? AND w.created_at >= ? AND w.created_at <= ?
      AND w.kind IN ('usage','refund') AND (k.id IS NULL OR length(k.id) != 32 OR k.id GLOB '*[^a-f0-9]*')`)
    .get(workspaceId, period.startAt, period.endAt).n : null;
  const topKeys = rows.filter(row => safeOpaque(row.id) && (row.hostedJobs > 0 || (spendByKey.get(row.id) ?? 0) !== 0))
    .map(row => ({ id: row.id, revoked: row.revoked_at !== null, hostedJobs: row.hostedJobs,
      netUsageMicros: walletAvailable ? spendByKey.get(row.id) ?? 0 : null, lastUsedAt: row.lastUsedAt }))
    .sort((a, b) => b.hostedJobs - a.hostedJobs || (b.netUsageMicros ?? 0) - (a.netUsageMicros ?? 0) || a.id.localeCompare(b.id))
    .slice(0, 10);
  return { topKeys, complete: walletAvailable && unmatched === 0,
    unattributedSpendMicros: numeric(spendMicros) ? spendMicros - totalAttributed : null,
    jobsAvailable, keysAvailable };
}

function recentJobs(db, workspaceId, period) {
  if (!exists(db, 'scan_usage_jobs')) return [];
  const keys = columns(db, 'scan_keys'), jobs = columns(db, 'scan_jobs');
  const canKey = ['id', 'workspace_id', 'key_id'].every(name => jobs.has(name)) &&
    ['id', 'workspace_id'].every(name => keys.has(name));
  const walletAvailable = exists(db, 'scan_wallet_entries');
  const meterAvailable = exists(db, 'scan_meter_jobs');
  const names = new Map(hostedScanTools().tools.map(tool => [tool.id, tool.name]));
  const rows = db.prepare(`SELECT u.job_id, u.status, u.created_at, u.findings_count${canKey ? ', k.id AS key_id' : ''}
    FROM scan_usage_jobs u ${canKey ? `LEFT JOIN scan_jobs j ON j.id = u.job_id AND j.workspace_id = u.workspace_id
      LEFT JOIN scan_keys k ON k.id = j.key_id AND k.workspace_id = u.workspace_id` : ''}
    WHERE u.workspace_id = ? AND u.created_at >= ? AND u.created_at <= ?
    ORDER BY u.created_at DESC, u.job_id DESC LIMIT 25`).all(workspaceId, period.startAt, period.endAt);
  return rows.filter(row => safeOpaque(row.job_id)).map(row => {
    const tools = exists(db, 'scan_usage_tools') ? db.prepare('SELECT tool_id FROM scan_usage_tools WHERE job_id = ? ORDER BY tool_id')
      .all(row.job_id).filter(tool => names.has(tool.tool_id)).map(tool => ({ id: tool.tool_id, name: names.get(tool.tool_id) })) : [];
    const posted = walletAvailable ? db.prepare(`SELECT COUNT(*) AS n, SUM(-amount_micros) AS spend
      FROM scan_wallet_entries WHERE workspace_id = ? AND
      ((kind = 'usage' AND id = ?) OR (kind = 'refund' AND id = ?)) AND created_at <= ?`)
      .get(workspaceId, `usage:${row.job_id}`, `refund:${row.job_id}`, period.endAt) : null;
    const meter = meterAvailable ? db.prepare('SELECT state, charge_micros FROM scan_meter_jobs WHERE workspace_id = ? AND job_id = ?')
      .get(workspaceId, row.job_id) : null;
    return { id: row.job_id, keyId: safeOpaque(row.key_id), status: row.status, submittedAt: row.created_at,
      tools, findings: row.findings_count,
      netUsageMicros: posted?.n > 0 ? posted.spend : walletAvailable && meter &&
        (['released', 'unbilled'].includes(meter.state) || meter.state === 'settled' && meter.charge_micros === 0) ? 0 : null };
  });
}

/** Bounded, read-only account analytics. No source, raw reports or key hashes. */
export function scanActivity(db, { workspaceId, days = 30, now = Date.now } = {}) {
  if (typeof workspaceId !== 'string' || !workspaceId || workspaceId.length > 200) throw fail('Invalid workspace activity scope.');
  if (!PERIODS.has(days)) throw fail('Choose 7, 30 or 90 days.');
  const generatedAt = typeof now === 'function' ? now() : now;
  if (!Number.isSafeInteger(generatedAt) || generatedAt < days * 2 * DAY) throw fail('Invalid activity time.');
  const current = usageMetrics(db, { workspaceId, days, now: generatedAt });
  const prior = usageMetrics(db, { workspaceId, days, now: current.period.startAt - 1 });
  const currentSummary = summary(current), previous = summary(prior);
  const currentCoverage = coverage(current), previousCoverage = coverage(prior);
  const comparisonAvailable = currentCoverage.windowComplete && previousCoverage.windowComplete;
  const keyStats = keyBreakdown(db, workspaceId, current.period, currentSummary.spendMicros);
  return { schemaVersion: 1, scope: 'workspace', days, timezone: 'UTC', generatedAt,
    period: current.period, previousPeriod: prior.period, summary: currentSummary, previous,
    comparison: {
      spendMicros: change(currentSummary.spendMicros, previous.spendMicros, true),
      jobs: change(currentSummary.jobs, previous.jobs, comparisonAvailable),
      completed: change(currentSummary.completed, previous.completed, comparisonAvailable),
      successRate: change(currentSummary.successRate, previous.successRate, comparisonAvailable),
      findings: change(currentSummary.findings, previous.findings, comparisonAvailable && currentCoverage.findingsComplete && previousCoverage.findingsComplete)
    },
    coverage: { current: currentCoverage, previous: previousCoverage, comparisonAvailable,
      keyAttributionComplete: keyStats.complete, unattributedKeySpendMicros: keyStats.unattributedSpendMicros,
      keyMetadataAvailable: keyStats.keysAvailable && keyStats.jobsAvailable },
    series: activitySeries(current), tools: current.tools, topKeys: keyStats.topKeys,
    recentJobs: recentJobs(db, workspaceId, current.period),
    definitions: {
      period: 'The selected UTC calendar days, including today so far, compared with the preceding complete UTC calendar period.',
      jobs: 'Hosted jobs by submission date. Anonymous free dependency audits cannot be attributed to this account.',
      spend: 'Net usage debits minus usage refunds by ledger posting date. Purchases and welcome grants are excluded.',
      findings: 'Recorded scanner finding candidates, not confirmed vulnerabilities.',
      keys: 'Known workspace API keys, including revoked keys, ranked by submissions in the period. Key IDs are identifiers, not token prefixes.',
      recentJobs: 'At most 25 most recent recorded jobs in the period. Job spend is lifetime net posted usage through the current window end; it is not a period aggregate.',
      comparison: 'Historical comparisons require complete tracking coverage. No percentage is computed from a zero or negative baseline.'
    } };
}

export function registerScanActivity(app, { db }) {
  app.get('/api/scanner-activity', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser || typeof req.workspaceId !== 'string' || !req.workspaceId)
      return res.status(401).json({ error: 'Sign in to view account activity.' });
    try {
      if (Object.keys(req.query || {}).some(key => key !== 'days') || req.query.days !== undefined &&
          (typeof req.query.days !== 'string' || !/^(7|30|90)$/.test(req.query.days))) throw fail('Choose only a days parameter of 7, 30 or 90.');
      res.json(scanActivity(db, { workspaceId: req.workspaceId, days: req.query.days === undefined ? 30 : Number(req.query.days) }));
    } catch (error) {
      res.status(error.status === 400 ? 400 : 500).json({ error: error.status === 400 ? error.message : 'Account activity is temporarily unavailable.' });
    }
  });
}
