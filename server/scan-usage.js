// Durable, numeric usage facts. This store never accepts source, names, URLs,
// credentials, request bodies, scanner snippets, or arbitrary metric labels.
export const SCAN_USAGE_SCHEMA = `
CREATE TABLE IF NOT EXISTS scan_usage_jobs (
  job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  started_at INTEGER, finished_at INTEGER, status TEXT NOT NULL,
  input_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, tool_count INTEGER NOT NULL,
  queue_ms INTEGER, execution_ms INTEGER, container_ms INTEGER, findings_count INTEGER,
  outbound_connections INTEGER, network_failures INTEGER
);
CREATE INDEX IF NOT EXISTS scan_usage_created ON scan_usage_jobs(created_at, job_id);
CREATE INDEX IF NOT EXISTS scan_usage_workspace ON scan_usage_jobs(workspace_id, created_at, job_id);
CREATE TABLE IF NOT EXISTS scan_usage_tools (
  job_id TEXT NOT NULL, tool_id TEXT NOT NULL, status TEXT NOT NULL, duration_ms INTEGER,
  findings_count INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, unknown INTEGER,
  PRIMARY KEY(job_id, tool_id)
);
CREATE INDEX IF NOT EXISTS scan_usage_tool_id ON scan_usage_tools(tool_id, job_id);
CREATE TABLE IF NOT EXISTS scan_usage_activity (
  day TEXT NOT NULL, workspace_id TEXT NOT NULL, tool_id TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY(day, workspace_id, tool_id, kind)
);
CREATE INDEX IF NOT EXISTS scan_usage_activity_day ON scan_usage_activity(day, workspace_id);
CREATE TABLE IF NOT EXISTS scan_usage_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);`;

const JOB_STATES = new Set(['queued', 'starting', 'running', 'completed', 'partial', 'failed']);
const TOOL_STATES = new Set(['queued', 'starting', 'running', 'complete', 'partial', 'failed', 'missing']);
const ACTIVITY = new Set(['quote_issued', 'quote_denied', 'submission_denied']);
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000 ? value : null;
const time = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const duration = (start, end) => time(start) !== null && time(end) !== null && end >= start ? count(end - start) : null;

export function createScanUsage(db, { toolIds = [], now = Date.now } = {}) {
  const knownTools = new Set(toolIds);
  db.exec(SCAN_USAGE_SCHEMA);
  db.prepare("INSERT OR IGNORE INTO scan_usage_meta VALUES ('tracking_started_at', ?)").run(now());

  function capture(jobId) {
    const row = db.prepare(`SELECT id,workspace_id,created_at,started_at,finished_at,status,
      input_bytes,file_count,selected_tools,result FROM scan_jobs WHERE id = ?`).get(jobId);
    if (!row || !JOB_STATES.has(row.status)) return false;
    let selected = [], report;
    try { selected = JSON.parse(row.selected_tools); } catch { /* old invalid metadata remains uncovered */ }
    selected = Array.isArray(selected) ? [...new Set(selected.filter(id => typeof id === 'string' && knownTools.has(id)))] : [];
    try { if (row.result) report = JSON.parse(row.result); } catch { /* no fabricated counts */ }
    const findings = Array.isArray(report?.findings) && report.findings.length <= 10000 ? report.findings : null;
    let observations = Array.isArray(report?.tools) ? report.tools.slice(0, 100) : [];
    const terminal = ['completed', 'partial', 'failed'].includes(row.status);
    if (!observations.length && terminal && db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_meter_jobs'").get()) {
      // Settlement retains only allowlisted names, statuses and durations even
      // after the detailed report expires. Recover those known observations.
      const meter = db.prepare('SELECT reported_tools_json FROM scan_meter_jobs WHERE job_id=?').get(jobId);
      try {
        const saved = JSON.parse(meter?.reported_tools_json || 'null');
        if (Array.isArray(saved)) observations = saved.slice(0, 100);
      } catch { /* missing/corrupt measurements stay unknown */ }
    }
    const network = report?.coverage;
    const containerMs = report?.execution?.observer === 'container_controller' ? count(report.execution.containerDurationMs) : null;
    db.prepare(`INSERT INTO scan_usage_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(job_id) DO UPDATE SET started_at=excluded.started_at, finished_at=excluded.finished_at,
      status=excluded.status, queue_ms=excluded.queue_ms, execution_ms=excluded.execution_ms,
      container_ms=COALESCE(excluded.container_ms, scan_usage_jobs.container_ms),
      findings_count=COALESCE(excluded.findings_count, scan_usage_jobs.findings_count),
      outbound_connections=COALESCE(excluded.outbound_connections, scan_usage_jobs.outbound_connections),
      network_failures=COALESCE(excluded.network_failures, scan_usage_jobs.network_failures)`)
      .run(row.id, row.workspace_id, row.created_at, row.started_at, row.finished_at, row.status,
        count(row.input_bytes) || 0, count(row.file_count) || 0, selected.length,
        duration(row.created_at, row.started_at), duration(row.started_at, row.finished_at), containerMs,
        findings?.length ?? null, count(network?.outboundConnections), count(network?.networkFailures));
    for (const id of selected) {
      const observed = observations.find(tool => tool?.name === id);
      const status = observed && TOOL_STATES.has(observed.status) ? observed.status : terminal ? 'missing' : row.status;
      const matches = findings?.filter(finding => finding?.tool === id);
      const severity = matches ? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } : null;
      for (const finding of matches || []) {
        const label = typeof finding.severity === 'string' ? finding.severity.toLowerCase() : 'unknown';
        severity[Object.hasOwn(severity, label) ? label : 'unknown']++;
      }
      db.prepare(`INSERT INTO scan_usage_tools VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id,tool_id) DO UPDATE SET
        status=CASE WHEN excluded.status='missing' AND scan_usage_tools.status IN ('complete','partial','failed')
          THEN scan_usage_tools.status ELSE excluded.status END,
        duration_ms=COALESCE(excluded.duration_ms, scan_usage_tools.duration_ms),
        findings_count=COALESCE(excluded.findings_count, scan_usage_tools.findings_count),
        critical=COALESCE(excluded.critical, scan_usage_tools.critical), high=COALESCE(excluded.high, scan_usage_tools.high),
        medium=COALESCE(excluded.medium, scan_usage_tools.medium), low=COALESCE(excluded.low, scan_usage_tools.low),
        unknown=COALESCE(excluded.unknown, scan_usage_tools.unknown)`)
        .run(row.id, id, status, count(observed?.durationMs), matches?.length ?? null,
          severity?.critical ?? null, severity?.high ?? null, severity?.medium ?? null, severity?.low ?? null, severity?.unknown ?? null);
    }
    return true;
  }

  function containerDuration(jobId, measurement) {
    const value = measurement?.observer === 'container_controller' ? count(measurement.containerDurationMs) : null;
    if (value === null) return false;
    db.prepare('UPDATE scan_usage_jobs SET container_ms = ? WHERE job_id = ?').run(value, jobId);
    return true;
  }

  function activity(workspaceId, kind, tools = []) {
    if (typeof workspaceId !== 'string' || !workspaceId || !ACTIVITY.has(kind)) return;
    // A quote is one event, regardless of how many tools were selected. Tool
    // adoption comes from the job/tool fact table, not duplicated quote events.
    const tool = tools.length === 1 && knownTools.has(tools[0]) ? tools[0] : 'unknown';
    const day = new Date(now()).toISOString().slice(0, 10);
    db.prepare(`INSERT INTO scan_usage_activity VALUES (?, ?, ?, ?, 1)
      ON CONFLICT(day,workspace_id,tool_id,kind) DO UPDATE SET count=count+1`)
      .run(day, workspaceId, tool, kind);
  }

  function backfill(limit = 100) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Invalid usage backfill limit.');
    // No source or credentials are read. Expired reports leave measurements
    // null; job timestamps and outcomes can still be recovered accurately.
    const rows = db.prepare(`SELECT j.id FROM scan_jobs j LEFT JOIN scan_usage_jobs u ON u.job_id=j.id
      WHERE u.job_id IS NULL ORDER BY (j.result IS NULL), j.created_at, j.id LIMIT ?`).all(limit);
    for (const row of rows) capture(row.id);
    return rows.length;
  }
  return { capture, containerDuration, activity, backfill };
}
