import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { FINANCIAL_TABLES, OPTIONAL_TABLES, TABLES } from './export-d1.mjs';

const MAX_BATCH_BYTES = 180_000;
const payloadBytes = value => Buffer.byteLength(JSON.stringify(value));

// Inspect the complete frozen source before issuing a reset or importing any
// row. An older backup can be merged, but cannot erase unrepresented wallets.
export function prepareWorkerImport(db, { reset = false } = {}) {
  const present = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map(row => row.name));
  const missing = TABLES.filter(table => !present.has(table));
  const required = missing.filter(table => !OPTIONAL_TABLES.includes(table));
  if (required.length) throw new Error(`Backup is missing required tables: ${required.join(', ')}.`);
  if (reset) {
    const absentFinancial = FINANCIAL_TABLES.filter(table => !present.has(table));
    if (absentFinancial.length) throw new Error(`Reset requires a complete financial backup; missing: ${absentFinancial.join(', ')}. Nothing was sent.`);
  }
  const tables = TABLES.filter(table => present.has(table));
  for (const table of tables) {
    const columns = db.prepare(`PRAGMA table_info("${table}")`).all();
    if (columns.some(column => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(column.name))) throw new Error(`Unsupported column name in ${table}.`);
    for (const row of db.prepare(`SELECT * FROM "${table}"`).iterate()) {
      if (Object.values(row).some(value => value !== null && typeof value !== 'string' &&
          !(typeof value === 'number' && Number.isFinite(value)))) throw new Error(`Unsupported row value in ${table}.`);
      if (payloadBytes({ table, rows: [row] }) > MAX_BATCH_BYTES) throw new Error(`${table} has a row too large to import safely. Nothing was sent.`);
    }
  }
  return { tables, skipped: missing };
}

export async function importWorkerState({ databasePath, destination, key, reset = false,
  fetchImpl = fetch, log = text => process.stdout.write(text + '\n'),
  sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)) }) {
  let target;
  try { target = new URL(destination); } catch { throw new Error('Choose an HTTPS Worker origin.'); }
  if (target.protocol !== 'https:' || target.username || target.password || target.search || target.hash || target.pathname !== '/')
    throw new Error('Choose an HTTPS Worker origin without credentials or a path.');
  if (typeof key !== 'string' || key.length < 32 || key.length > 1024 || /\s/.test(key)) throw new Error('Migration key is invalid.');
  const db = new DatabaseSync(databasePath, { readOnly: true });
  const endpoint = new URL('/api/internal/import', target);
  let transaction = false;
  try {
    db.exec('BEGIN'); transaction = true;
    const plan = prepareWorkerImport(db, { reset });
    async function send(payload) {
      const body = JSON.stringify(payload);
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const response = await fetchImpl(endpoint, { method: 'POST',
            headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
            body, signal: AbortSignal.timeout(30000), redirect: 'error' });
          const result = await response.json().catch(() => ({}));
          if (!response.ok) throw Object.assign(new Error(`Import returned HTTP ${response.status}.`), {
            retryable: response.status >= 500 || response.status === 429
          });
          return result;
        } catch (error) {
          if (attempt === 2 || error.retryable === false) throw error;
          await sleep(500 * (attempt + 1));
        }
      }
    }
    if (reset) await send({ reset: true });
    const counts = {};
    for (const table of plan.skipped) log(`${table}: unavailable in this older backup`);
    for (const table of plan.tables) {
      let batch = [], count = 0;
      for (const row of db.prepare(`SELECT * FROM "${table}"`).iterate()) {
        if (batch.length && (batch.length >= 100 || payloadBytes({ table, rows: [...batch, row] }) > MAX_BATCH_BYTES)) {
          await send({ table, rows: batch }); count += batch.length; batch = [];
        }
        batch.push(row);
      }
      if (batch.length) { await send({ table, rows: batch }); count += batch.length; }
      counts[table] = count; log(`${table}: ${count} rows`);
    }
    return { counts, skipped: plan.skipped };
  } finally {
    if (transaction) db.exec('ROLLBACK');
    db.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [databasePath, destination, keyPath, option, ...extra] = process.argv.slice(2);
  if (!databasePath || !destination || !keyPath || extra.length || option !== undefined && option !== '--reset') {
    console.error('Usage: node scripts/import-worker-state.mjs <sqlite-file> <https-worker-origin> <migration-key-file> [--reset]');
    process.exitCode = 2;
  } else {
    try { await importWorkerState({ databasePath, destination, key: readFileSync(keyPath, 'utf8').trim(), reset: option === '--reset' }); }
    catch (error) { console.error(`Import failed: ${error.message}`); process.exitCode = 1; }
  }
}
