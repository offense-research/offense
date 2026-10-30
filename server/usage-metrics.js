import { hostedScanTools } from './hosted-scans.js';
import { isMetricsOperator } from './discovery-dashboard.js';
import { registerSkillUsageMetrics } from './skill-usage-routes.js';

const DAY = 86_400_000;
const PERIODS = new Set([7, 30, 90]);
const fail = message => Object.assign(new Error(message), { status: 400 });
const exists = (db, name) => !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
const dayName = at => new Date(at).toISOString().slice(0, 10);
const nullableSum = rows => rows.some(value => value !== null) ? rows.reduce((sum, value) => sum + (value ?? 0), 0) : null;

function percentiles(db, from, params, field) {
  const where = `${from} AND ${field} IS NOT NULL AND ${field} >= 0`;
  const samples = db.prepare(`SELECT COUNT(*) AS count ${where}`).get(...params).count;
  if (!samples) return { samples: 0, p50Ms: null, p95Ms: null };
  const value = percentile => db.prepare(`SELECT ${field} AS value ${where} ORDER BY ${field} LIMIT 1 OFFSET ?`)
    .get(...params, Math.max(0, Math.ceil(samples * percentile) - 1)).value;
  return { samples, p50Ms: value(0.5), p95Ms: value(0.95) };
}

function walletMetrics(db, { startAt, endAt, workspaceId }) {
  const present = exists(db, 'scan_wallet_entries'), meters = exists(db, 'scan_meter_jobs');
  const where = workspaceId === undefined ? '' : ' AND workspace_id = ?';
  const scoped = workspaceId === undefined ? [] : [workspaceId];
  const result = { currency: 'usd', chargesMicros: null, refundsMicros: null, netUsageMicros: null,
    topUpsMicros: null, reservedMicros: null, balanceMicros: null, availableMicros: null,
    attributedUsageMicros: null, unattributedUsageMicros: null, allocationComplete: false };
  if (!present) return { result, byDay: new Map(), byTool: new Map() };
  const sums = db.prepare(`SELECT
    COALESCE(SUM(CASE WHEN kind = 'usage' THEN -amount_micros ELSE 0 END), 0) AS chargesMicros,
    COALESCE(SUM(CASE WHEN kind = 'refund' THEN amount_micros ELSE 0 END), 0) AS refundsMicros,
    COALESCE(SUM(CASE WHEN kind = 'purchase' THEN amount_micros ELSE 0 END), 0) AS topUpsMicros
    FROM scan_wallet_entries WHERE created_at >= ? AND created_at <= ?${where}`).get(startAt, endAt, ...scoped);
  Object.assign(result, sums, { netUsageMicros: sums.chargesMicros - sums.refundsMicros });
  result.balanceMicros = db.prepare(`SELECT COALESCE(SUM(amount_micros), 0) AS value FROM scan_wallet_entries WHERE 1 = 1${where}`).get(...scoped).value;
  if (meters) {
    result.reservedMicros = db.prepare(`SELECT COALESCE(SUM(reserve_micros), 0) AS value
      FROM scan_meter_jobs WHERE state = 'reserved'${where}`).get(...scoped).value;
    // Sum spendable balances per workspace. Do not offset one workspace's
    // negative/review balance against another workspace's available credit.
    result.availableMicros = db.prepare(`SELECT COALESCE(SUM(MAX(0, b.balance - COALESCE(h.held, 0))), 0) AS value
      FROM (SELECT workspace_id, SUM(amount_micros) AS balance FROM scan_wallet_entries WHERE 1 = 1${where} GROUP BY workspace_id) b
      LEFT JOIN (SELECT workspace_id, SUM(reserve_micros) AS held FROM scan_meter_jobs WHERE state = 'reserved' GROUP BY workspace_id) h
      ON b.workspace_id = h.workspace_id`).get(...scoped).value;
  }
  const byDay = new Map(db.prepare(`SELECT strftime('%Y-%m-%d', created_at / 1000.0, 'unixepoch') AS date,
    SUM(CASE WHEN kind IN ('usage', 'refund') THEN -amount_micros ELSE 0 END) AS netUsageMicros,
    SUM(CASE WHEN kind = 'purchase' THEN amount_micros ELSE 0 END) AS topUpsMicros
    FROM scan_wallet_entries WHERE created_at >= ? AND created_at <= ?${where} GROUP BY date`).all(startAt, endAt, ...scoped)
    .map(row => [row.date, row]));
  const byTool = new Map();
  if (meters) {
    // Attribute actual posted debits/refunds by the immutable per-tool quote.
    // Financial totals above remain authoritative even if a legacy entry has
    // no surviving quote; its allocation stays explicitly unattributed.
    const rows = db.prepare(`SELECT json_extract(p.value, '$.tool') AS id,
      SUM(-w.amount_micros * json_extract(p.value, '$.maximumMicros') /
        NULLIF(json_extract(m.quote_json, '$.maximumMicros'), 0)) AS netUsageMicros
      FROM scan_wallet_entries w JOIN scan_meter_jobs m ON m.workspace_id = w.workspace_id
        AND m.job_id = CASE WHEN w.kind = 'usage' THEN substr(w.id, 7) WHEN w.kind = 'refund' THEN substr(w.id, 8) END
      JOIN json_each(m.quote_json, '$.prices') p
      WHERE w.created_at >= ? AND w.created_at <= ? AND w.kind IN ('usage', 'refund')${workspaceId === undefined ? '' : ' AND w.workspace_id = ?'}
      GROUP BY json_extract(p.value, '$.tool')`).all(startAt, endAt, ...scoped);
    for (const row of rows) if (typeof row.id === 'string') byTool.set(row.id, row.netUsageMicros);
    result.attributedUsageMicros = nullableSum([...byTool.values()]) ?? 0;
    result.unattributedUsageMicros = result.netUsageMicros - result.attributedUsageMicros;
    const unmatched = db.prepare(`SELECT COUNT(*) AS count FROM scan_wallet_entries w
      LEFT JOIN scan_meter_jobs m ON m.workspace_id = w.workspace_id
        AND m.job_id = CASE WHEN w.kind = 'usage' THEN substr(w.id, 7) WHEN w.kind = 'refund' THEN substr(w.id, 8) END
      WHERE w.created_at >= ? AND w.created_at <= ? AND w.kind IN ('usage', 'refund')${workspaceId === undefined ? '' : ' AND w.workspace_id = ?'}
        AND (m.job_id IS NULL OR json_extract(m.quote_json, '$.maximumMicros') IS NULL OR
          json_extract(m.quote_json, '$.maximumMicros') <= 0 OR json_array_length(m.quote_json, '$.prices') IS NULL OR
          json_array_length(m.quote_json, '$.prices') = 0)`).get(startAt, endAt, ...scoped).count;
    result.allocationComplete = unmatched === 0 && result.unattributedUsageMicros === 0;
  } else {
    result.allocationComplete = result.chargesMicros === 0 && result.refundsMicros === 0;
  }
  return { result, byDay, byTool };
}

/** Read-only, bounded-window aggregates. Never select raw scanner reports. */
export function usageMetrics(db, { days = 30, workspaceId, now = Date.now } = {}) {
  if (!PERIODS.has(days)) throw fail('Choose 7, 30 or 90 days.');
  if (workspaceId !== undefined && (typeof workspaceId !== 'string' || !workspaceId || workspaceId.length > 200))
    throw fail('Invalid workspace metrics scope.');
  const generatedAt = typeof now === 'function' ? now() : now;
  if (!Number.isSafeInteger(generatedAt) || generatedAt < 0) throw fail('Invalid metrics time.');
  const today = Math.floor(generatedAt / DAY) * DAY, startAt = today - (days - 1) * DAY;
  const params = workspaceId === undefined ? [startAt, generatedAt] : [startAt, generatedAt, workspaceId];
  const scope = workspaceId === undefined ? '' : ' AND j.workspace_id = ?';
  const from = `FROM scan_usage_jobs j WHERE j.created_at >= ? AND j.created_at <= ?${scope}`;
  const available = exists(db, 'scan_usage_jobs') && exists(db, 'scan_usage_tools');
  const activityAvailable = exists(db, 'scan_usage_activity');
  let trackingStartedAt = null;
  if (exists(db, 'scan_usage_meta')) {
    const row = db.prepare("SELECT value FROM scan_usage_meta WHERE key = 'tracking_started_at'").get();
    if (row && Number.isSafeInteger(Number(row.value))) trackingStartedAt = Number(row.value);
  }
  const firstJobAt = available ? db.prepare(`SELECT MIN(created_at) AS value FROM scan_usage_jobs${workspaceId === undefined ? '' : ' WHERE workspace_id = ?'}`)
    .get(...(workspaceId === undefined ? [] : [workspaceId])).value : null;
  const legacyJobsMissing = available && exists(db, 'scan_jobs') ? db.prepare(`SELECT COUNT(*) AS value FROM scan_jobs j
    LEFT JOIN scan_usage_jobs u ON u.job_id = j.id WHERE u.job_id IS NULL AND j.created_at >= ? AND j.created_at <= ?${scope}`)
    .get(...params).value : null;
  const counts = available ? db.prepare(`SELECT COUNT(*) AS jobs,
    COALESCE(SUM(status = 'completed'), 0) AS completed, COALESCE(SUM(status = 'partial'), 0) AS partial,
    COALESCE(SUM(status = 'failed'), 0) AS failed,
    COALESCE(SUM(status IN ('queued', 'starting', 'running')), 0) AS active,
    COALESCE(SUM(input_bytes), 0) AS inputBytes, COALESCE(SUM(file_count), 0) AS fileCount,
    COALESCE(SUM(tool_count), 0) AS selectedToolRuns,
    SUM(findings_count) AS findings, COUNT(findings_count) AS findingsSamples,
    SUM(outbound_connections) AS outboundConnections, COUNT(outbound_connections) AS networkConnectionSamples,
    SUM(network_failures) AS networkFailures, COUNT(network_failures) AS networkFailureSamples,
    SUM(container_ms) AS containerDurationMs, COUNT(container_ms) AS containerDurationSamples,
    COUNT(DISTINCT workspace_id) AS activeWorkspaces ${from}`).get(...params) : null;
  const totals = counts ? { ...counts, confirmedVulnerabilities: 0,
    successRate: counts.completed + counts.partial + counts.failed ? counts.completed / (counts.completed + counts.partial + counts.failed) : null }
    : { jobs: null, completed: null, partial: null, failed: null, active: null, inputBytes: null, fileCount: null,
      selectedToolRuns: null, findings: null, findingsSamples: 0, confirmedVulnerabilities: 0,
      outboundConnections: null, networkConnectionSamples: 0, networkFailures: null, networkFailureSamples: 0,
      containerDurationMs: null, containerDurationSamples: 0, successRate: null };
  if (workspaceId !== undefined) delete totals.activeWorkspaces;
  if (counts?.jobs === 0 && legacyJobsMissing > 0) for (const key of ['jobs', 'completed', 'partial', 'failed', 'active', 'inputBytes', 'fileCount', 'selectedToolRuns']) totals[key] = null;
  const latency = available ? { queue: percentiles(db, from, params, 'j.queue_ms'), execution: percentiles(db, from, params, 'j.execution_ms') }
    : { queue: { samples: 0, p50Ms: null, p95Ms: null }, execution: { samples: 0, p50Ms: null, p95Ms: null } };
  const wallet = walletMetrics(db, { startAt, endAt: generatedAt, workspaceId });
  const toolFrom = `FROM scan_usage_tools t JOIN scan_usage_jobs j ON j.job_id = t.job_id WHERE j.created_at >= ? AND j.created_at <= ?${scope}`;
  const toolRows = available ? db.prepare(`SELECT t.tool_id AS id, COUNT(*) AS jobs,
    SUM(t.status = 'complete') AS complete, SUM(t.status = 'partial') AS partial,
    SUM(t.status = 'failed') AS failed, SUM(t.status = 'missing') AS missing,
    SUM(t.status IN ('queued', 'starting', 'running')) AS active,
    SUM(t.findings_count) AS findings, COUNT(t.findings_count) AS findingsSamples,
    SUM(t.critical) AS critical, SUM(t.high) AS high, SUM(t.medium) AS medium,
    SUM(t.low) AS low, SUM(t.unknown) AS unknown,
    SUM(t.duration_ms) AS durationMs, COUNT(t.duration_ms) AS durationSamples ${toolFrom} GROUP BY t.tool_id`).all(...params) : [];
  const names = new Map(hostedScanTools().tools.map(tool => [tool.id, tool.name]));
  const tools = toolRows.filter(row => names.has(row.id)).map(row => {
    const { critical, high, medium, low, unknown, ...rest } = row;
    return { ...rest, name: names.get(row.id), severity: { critical, high, medium, low, unknown },
      latency: percentiles(db, `${toolFrom} AND t.tool_id = ?`, [...params, row.id], 't.duration_ms'),
      netUsageMicros: wallet.result.allocationComplete ? wallet.byTool.get(row.id) ?? 0 : null };
  });
  for (const [id, netUsageMicros] of wallet.byTool) if (names.has(id) && !tools.some(tool => tool.id === id)) {
    tools.push({ id, name: names.get(id), jobs: 0, complete: 0, partial: 0, failed: 0, missing: 0, active: 0,
      findings: null, findingsSamples: 0, severity: { critical: null, high: null, medium: null, low: null, unknown: null },
      durationMs: null, durationSamples: 0, latency: { samples: 0, p50Ms: null, p95Ms: null },
      netUsageMicros: wallet.result.allocationComplete ? netUsageMicros : null });
  }
  tools.sort((a, b) => b.jobs - a.jobs || a.id.localeCompare(b.id));
  const toolDuration = available ? db.prepare(`SELECT SUM(t.duration_ms) AS value, COUNT(t.duration_ms) AS samples ${toolFrom}`).get(...params) : { value: null, samples: 0 };
  totals.toolDurationMs = toolDuration.value; totals.toolDurationSamples = toolDuration.samples;
  const jobsByDay = new Map(available ? db.prepare(`SELECT strftime('%Y-%m-%d', j.created_at / 1000.0, 'unixepoch') AS date,
    COUNT(*) AS jobs, SUM(status = 'completed') AS completed, SUM(status = 'partial') AS partial,
    SUM(status = 'failed') AS failed, SUM(status IN ('queued', 'starting', 'running')) AS active,
    SUM(input_bytes) AS inputBytes, SUM(findings_count) AS findings ${from} GROUP BY date`).all(...params).map(row => [row.date, row]) : []);
  const missingByDay = new Map(available && exists(db, 'scan_jobs') ? db.prepare(`SELECT strftime('%Y-%m-%d', j.created_at / 1000.0, 'unixepoch') AS date,
    COUNT(*) AS count FROM scan_jobs j LEFT JOIN scan_usage_jobs u ON u.job_id = j.id
    WHERE u.job_id IS NULL AND j.created_at >= ? AND j.created_at <= ?${scope} GROUP BY date`).all(...params).map(row => [row.date, row.count]) : []);
  const activityRows = activityAvailable ? db.prepare(`SELECT day, kind, SUM(count) AS count FROM scan_usage_activity
    WHERE day >= ? AND day <= ?${workspaceId === undefined ? '' : ' AND workspace_id = ?'} GROUP BY day, kind`)
    .all(dayName(startAt), dayName(generatedAt), ...(workspaceId === undefined ? [] : [workspaceId])) : [];
  const activity = { quotesIssued: activityAvailable ? 0 : null, quotesDenied: activityAvailable ? 0 : null, submissionsDenied: activityAvailable ? 0 : null };
  const activityByDay = new Map(), activityKinds = { quote_issued: 'quotesIssued', quote_denied: 'quotesDenied', submission_denied: 'submissionsDenied' };
  for (const row of activityRows) {
    const field = activityKinds[row.kind]; if (!field) continue;
    if (!activityByDay.has(row.day)) activityByDay.set(row.day, { quotesIssued: 0, quotesDenied: 0, submissionsDenied: 0 });
    activityByDay.get(row.day)[field] += row.count; activity[field] += row.count;
  }
  const series = Array.from({ length: days }, (_, index) => {
    const at = startAt + index * DAY, date = dayName(at), row = jobsByDay.get(date), money = wallet.byDay.get(date);
    const known = available && !(missingByDay.get(date) > 0 && !row);
    return { date, jobs: row?.jobs ?? (known ? 0 : null), completed: row?.completed ?? (known ? 0 : null),
      partial: row?.partial ?? (known ? 0 : null), failed: row?.failed ?? (known ? 0 : null), active: row?.active ?? (known ? 0 : null),
      inputBytes: row?.inputBytes ?? (known ? 0 : null), findings: row ? row.findings : known ? 0 : null,
      netUsageMicros: wallet.result.netUsageMicros === null ? null : money?.netUsageMicros ?? 0,
      topUpsMicros: wallet.result.topUpsMicros === null ? null : money?.topUpsMicros ?? 0,
      activity: activityByDay.has(date) || activityAvailable && trackingStartedAt !== null && at + DAY > trackingStartedAt
        ? activityByDay.get(date) || { quotesIssued: 0, quotesDenied: 0, submissionsDenied: 0 }
        : { quotesIssued: null, quotesDenied: null, submissionsDenied: null } };
  });
  return { schemaVersion: 1, generatedAt, days, timezone: 'UTC', scope: workspaceId === undefined ? 'operator' : 'workspace',
    period: { startAt, endAt: generatedAt }, coverage: { available, firstRecordedAt: trackingStartedAt,
      firstJobAt, legacyJobsMissing, activityAvailable, activityStartedAt: trackingStartedAt,
      complete: available && legacyJobsMissing === 0 }, totals, billing: wallet.result, latency, activity, tools, series,
    definitions: { jobs: 'Jobs created in this UTC calendar window; status reflects the latest recorded outcome.',
      money: 'Actual wallet entries posted in this window. Purchased credit is distinct from consumed credit. Balances and reservations are current.',
      latency: 'Nearest-rank percentiles of known measurements only. Missing measurements remain null.',
      findings: 'Scanner candidates in retained usage facts; no exploit or verified-fix claim.',
      activity: 'Authenticated quote and rejected submission requests. Repeated requests count as requests, not as additional billed jobs.' } };
}

function queryDays(req) {
  if (Object.keys(req.query || {}).some(key => key !== 'days') || req.query.days !== undefined &&
      (typeof req.query.days !== 'string' || !/^(7|30|90)$/.test(req.query.days))) throw fail('Choose only a days parameter of 7, 30 or 90.');
  return req.query.days === undefined ? 30 : Number(req.query.days);
}

export function registerUsageMetrics(app, { db, operatorIds }) {
  registerSkillUsageMetrics(app, { db, operatorIds });
  app.get('/api/scanner-usage', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser || typeof req.workspaceId !== 'string' || !req.workspaceId)
      return res.status(401).json({ error: 'Sign in to view workspace usage.' });
    try { res.json(usageMetrics(db, { days: queryDays(req), workspaceId: req.workspaceId })); }
    catch (error) { res.status(error.status === 400 ? 400 : 500).json({ error: error.status === 400 ? error.message : 'Usage metrics are temporarily unavailable.' }); }
  });
  app.get('/api/operator/usage', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser) return res.status(401).json({ error: 'Sign in to view company usage.' });
    if (!isMetricsOperator(req.authUser, operatorIds)) return res.status(403).json({ error: 'Company usage is restricted to Purple operators.' });
    try { res.json(usageMetrics(db, { days: queryDays(req) })); }
    catch (error) { res.status(error.status === 400 ? 400 : 500).json({ error: error.status === 400 ? error.message : 'Usage metrics are temporarily unavailable.' }); }
  });
}
