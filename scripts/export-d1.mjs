import { DatabaseSync, backup } from 'node:sqlite';
import { chmodSync, closeSync, mkdirSync, openSync, rmSync, writeSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Keep the order stable so parent rows exist before memberships are imported.
export const TABLES = [
  'users', 'user_contacts', 'workspaces', 'memberships', 'sessions', 'ingest_tokens',
  'ingest_batches', 'events', 'detection_signals', 'investigations',
  'investigation_events', 'worker_repositories', 'dependency_snapshots', 'dependency_monitor', 'dependency_automation_policies', 'dependency_automation_runs', 'agent_runs', 'vulnerability_discoveries', 'workspace_revisions', 'account_connections', 'upgrade_rehearsals', 'rehearsal_trials', 'discovery_metric_days', 'scan_keys', 'scan_jobs', 'scan_sources', 'scan_cleanup',
  'wallet_orders', 'wallet_entries', 'wallet_runs', 'billing_events',
  'scan_wallet_entries', 'scan_meter_jobs', 'scan_wallet_blocks', 'scan_wallet_orders', 'scan_billing_events',
  'scan_auto_topup_orders', 'scan_auto_topup_events',
  'scan_usage_jobs', 'scan_usage_tools', 'scan_usage_activity', 'scan_usage_meta', 'skill_usage_days', 'skill_usage_meta', 'tool_call_days', 'tool_call_meta', 'cli_auth_devices', 'cli_auth_limits',
  // Restore consent last, after all associated order/payment identities.
  'wallet_preferences', 'scan_auto_topup_preferences'
];

export const FINANCIAL_TABLES = Object.freeze([
  'wallet_orders', 'wallet_entries', 'wallet_runs', 'billing_events', 'wallet_preferences',
  'scan_wallet_entries', 'scan_meter_jobs', 'scan_wallet_blocks', 'scan_wallet_orders', 'scan_billing_events',
  'scan_auto_topup_orders', 'scan_auto_topup_events', 'scan_auto_topup_preferences'
]);
export const OPTIONAL_TABLES = Object.freeze([
  'user_contacts', 'dependency_monitor', 'dependency_automation_policies', 'dependency_automation_runs',
  'vulnerability_discoveries', 'workspace_revisions', 'account_connections', 'upgrade_rehearsals', 'rehearsal_trials',
  'discovery_metric_days', 'scan_keys', 'scan_jobs', 'scan_sources', 'scan_cleanup', ...FINANCIAL_TABLES,
  'scan_usage_jobs', 'scan_usage_tools', 'scan_usage_activity', 'scan_usage_meta', 'skill_usage_days', 'skill_usage_meta', 'tool_call_days', 'tool_call_meta',
  'cli_auth_devices', 'cli_auth_limits'
]);

function sqlValue(value) {
  if (value === null) return 'NULL';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'string') return `'${value.replaceAll("'", "''")}'`;
  throw new Error(`Unsupported SQLite value type: ${typeof value}`);
}

export function writeDataSql(db, destination) {
  const fd = openSync(destination, 'wx', 0o600);
  const counts = {};
  try {
    writeSync(fd, '-- Purple D1 data import. Contains encrypted secrets and active sessions. Keep private.\n');
    for (const table of TABLES) {
      const columns = db.prepare(`PRAGMA table_info("${table}")`).all().map(row => row.name);
      if (!columns.length && OPTIONAL_TABLES.includes(table)) { counts[table] = 0; continue; }
      if (!columns.length) throw new Error(`Missing table: ${table}`);
      const names = columns.map(name => `"${name}"`).join(', ');
      let count = 0;
      let batch = [];
      for (const row of db.prepare(`SELECT ${names} FROM "${table}"`).iterate()) {
        batch.push(`(${columns.map(name => sqlValue(row[name])).join(', ')})`);
        count++;
        if (batch.length === 50) {
          writeSync(fd, `INSERT INTO "${table}" (${names}) VALUES ${batch.join(', ')};\n`);
          batch = [];
        }
      }
      if (batch.length) writeSync(fd, `INSERT INTO "${table}" (${names}) VALUES ${batch.join(', ')};\n`);
      counts[table] = count;
    }
    return counts;
  } finally { closeSync(fd); }
}

export async function exportD1(sourcePath, outputDir) {
  mkdirSync(outputDir, { mode: 0o700 });
  const snapshot = path.join(outputDir, 'purple-snapshot.sqlite');
  const dataSql = path.join(outputDir, 'purple-d1-data.sql');
  const source = new DatabaseSync(sourcePath, { readOnly: true });
  try { await backup(source, snapshot); }
  finally { source.close(); }
  chmodSync(snapshot, 0o600);
  const frozen = new DatabaseSync(snapshot, { readOnly: true });
  try { return { snapshot, dataSql, counts: writeDataSql(frozen, dataSql) }; }
  catch (error) { rmSync(dataSql, { force: true }); throw error; }
  finally { frozen.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [sourcePath, outputDir] = process.argv.slice(2);
  if (!sourcePath || !outputDir) {
    console.error('Usage: node scripts/export-d1.mjs <sqlite-file> <new-private-output-directory>');
    process.exitCode = 2;
  } else {
    try {
      const result = await exportD1(sourcePath, outputDir);
      console.log(JSON.stringify({ directory: outputDir, counts: result.counts }, null, 2));
    } catch (error) {
      console.error(`Export failed: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
