// Scanner usage has its own ledger. The existing Whop balance was sold for
// hosted model usage and must not be debited for scans without new terms.
import { ARTIFACT_LIMITS, ARTIFACT_TOOLS } from './scan-artifacts.js';
import { SCAN_LIMITS } from './scan-input.js';
import { SCAN_PRICE_TOOLS, validScanPriceMap } from './scan-pricing.js';
import { assessmentTool } from '../shared/assessment-tools.js';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const MIB = 1024 * 1024;
const TOOL_IDS = new Set(SCAN_PRICE_TOOLS.map(tool => tool.id));
const ARTIFACT_TOOL_IDS = new Set(Object.values(ARTIFACT_TOOLS).flat());

function validMoney(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000;
}

export function createScanMetering(db, { enabled = false, priceByToolMicros = {}, now = Date.now } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS scan_wallet_entries (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, amount_micros INTEGER NOT NULL,
    kind TEXT NOT NULL, created_at INTEGER NOT NULL
  ); CREATE INDEX IF NOT EXISTS scan_wallet_workspace ON scan_wallet_entries(workspace_id, created_at);
  CREATE TABLE IF NOT EXISTS scan_wallet_blocks (
    workspace_id TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scan_meter_jobs (
    job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, state TEXT NOT NULL,
    quote_json TEXT NOT NULL, reserve_micros INTEGER NOT NULL, charge_micros INTEGER NOT NULL DEFAULT 0,
    reported_tools_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  ); CREATE INDEX IF NOT EXISTS scan_meter_workspace ON scan_meter_jobs(workspace_id, created_at);`);

  if (enabled && !validScanPriceMap(priceByToolMicros))
    throw fail('Scanner billing requires an explicit valid price for every tool.', 503);

  function quote({ tools, inputBytes, fileCount }) {
    if (!Array.isArray(tools) || !tools.length || new Set(tools).size !== tools.length ||
      tools.some(id => !TOOL_IDS.has(id))) throw fail('Select distinct supported scanner tools.');
    const artifactJob = tools.length === 1 && ARTIFACT_TOOL_IDS.has(tools[0]);
    const artifactKind = artifactJob ? Object.entries(ARTIFACT_TOOLS).find(([, ids]) => ids.includes(tools[0]))?.[0] : null;
    const maxBytes = artifactKind ? ARTIFACT_LIMITS[artifactKind] : SCAN_LIMITS.totalBytes;
    if (!Number.isSafeInteger(inputBytes) || inputBytes < (artifactJob ? 1 : 0) || inputBytes > maxBytes ||
      !Number.isSafeInteger(fileCount) || fileCount < 1 || fileCount > (artifactJob ? 1 : SCAN_LIMITS.files))
      throw fail('Invalid scanner usage dimensions.');
    const inputMiB = Math.max(1, Math.ceil(inputBytes / MIB));
    const prices = tools.map(id => {
      if (enabled && !priceByToolMicros[id]) throw fail('This tool does not have a configured scanner price.', 503);
      const basePriceMicros = enabled ? priceByToolMicros[id].baseMicros : 0;
      const additionalMiBPriceMicros = enabled ? priceByToolMicros[id].additionalMiBMicros : 0;
      const bounded = !!assessmentTool(id);
      return { tool: id, unit: bounded ? 'bounded_assessment' : 'first_mib_plus_additional_started_mib', inputMiB,
        additionalMiBUnits: bounded ? 0 : inputMiB - 1, basePriceMicros, additionalMiBPriceMicros,
        maximumMicros: basePriceMicros + (bounded ? 0 : inputMiB - 1) * additionalMiBPriceMicros };
    });
    const maximumMicros = prices.reduce((sum, price) => sum + price.maximumMicros, 0);
    if (!Number.isSafeInteger(maximumMicros)) throw fail('Scanner price exceeds the supported limit.', 503);
    return { currency: 'usd', billable: !!enabled, toolIds: [...tools], inputBytes, fileCount,
      inputMiB, prices, maximumMicros };
  }

  function balance(workspaceId) {
    return db.prepare('SELECT COALESCE(SUM(amount_micros), 0) AS balance FROM scan_wallet_entries WHERE workspace_id = ?').get(workspaceId).balance;
  }
  function held(workspaceId) {
    return db.prepare("SELECT COALESCE(SUM(reserve_micros), 0) AS held FROM scan_meter_jobs WHERE workspace_id = ? AND state = 'reserved'").get(workspaceId).held;
  }
  function status(workspaceId) {
    const balanceMicros = balance(workspaceId), reservedMicros = held(workspaceId);
    const welcomeCreditMicros = db.prepare("SELECT COALESCE(SUM(amount_micros), 0) AS value FROM scan_wallet_entries WHERE workspace_id = ? AND kind = 'welcome'").get(workspaceId).value;
    const blocked = !!db.prepare('SELECT workspace_id FROM scan_wallet_blocks WHERE workspace_id = ?').get(workspaceId);
    return { enabled: !!enabled, currency: 'usd', balanceMicros, reservedMicros, welcomeCreditMicros,
      availableMicros: Math.max(0, balanceMicros - reservedMicros), blocked };
  }

  // The caller creates the scan job and reserves inside the same DB transaction.
  function reserve({ jobId, workspaceId, quote: offered }) {
    if (typeof jobId !== 'string' || !/^[a-f0-9]{32}$/.test(jobId) ||
      typeof workspaceId !== 'string' || !workspaceId) throw fail('Invalid scan billing identity.');
    const priced = quote({ tools: offered?.toolIds, inputBytes: offered?.inputBytes, fileCount: offered?.fileCount });
    if (offered?.maximumMicros !== priced.maximumMicros) throw fail('Scanner price changed; request a fresh quote.', 409);
    const old = db.prepare('SELECT workspace_id, quote_json FROM scan_meter_jobs WHERE job_id = ?').get(jobId);
    if (old) {
      if (old.workspace_id !== workspaceId || old.quote_json !== JSON.stringify(priced)) throw fail('Scan billing identity was reused with different input.', 409);
      return usage(jobId);
    }
    const wallet = status(workspaceId);
    if (wallet.blocked) throw fail('Scanner balance is under payment review.', 409);
    if (enabled && wallet.availableMicros < priced.maximumMicros) throw fail('Add scanner credit before running this scan.', 402);
    const timestamp = now();
    db.prepare('INSERT INTO scan_meter_jobs(job_id,workspace_id,state,quote_json,reserve_micros,charge_micros,created_at,updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)')
      .run(jobId, workspaceId, enabled ? 'reserved' : 'unbilled', JSON.stringify(priced), priced.maximumMicros, timestamp, timestamp);
    return usage(jobId);
  }

  // A partial or failed report does not consume scanner credit. Per-tool time
  // is still recorded for cost analysis, with no source or raw scanner output.
  function settle({ jobId, status: scanStatus, tools }) {
    const row = db.prepare('SELECT * FROM scan_meter_jobs WHERE job_id = ?').get(jobId);
    if (!row) return null;
    if (row.state === 'settled' || row.state === 'released') return usage(jobId);
    const reported = Array.isArray(tools) ? tools.map(tool => ({
      name: typeof tool?.name === 'string' ? tool.name.slice(0, 80) : '',
      status: typeof tool?.status === 'string' ? tool.status.slice(0, 40) : 'unknown',
      durationMs: Number.isSafeInteger(tool?.durationMs) && tool.durationMs >= 0 ? tool.durationMs : null
    })) : [];
    const selected = JSON.parse(row.quote_json).toolIds;
    const complete = scanStatus === 'completed' && selected.every(id =>
      reported.some(tool => tool.name === id && tool.status === 'complete'));
    const charge = enabled && complete ? JSON.parse(row.quote_json).maximumMicros : 0;
    if (charge) db.prepare("INSERT OR IGNORE INTO scan_wallet_entries(id,workspace_id,amount_micros,kind,created_at) VALUES (?, ?, ?, 'usage', ?)")
      .run(`usage:${jobId}`, row.workspace_id, -charge, now());
    db.prepare('UPDATE scan_meter_jobs SET state = ?, charge_micros = ?, reported_tools_json = ?, updated_at = ? WHERE job_id = ?')
      .run(complete && enabled ? 'settled' : 'released', charge, JSON.stringify(reported), now(), jobId);
    return usage(jobId);
  }

  function release(jobId) {
    const row = db.prepare('SELECT * FROM scan_meter_jobs WHERE job_id = ?').get(jobId);
    if (!row || row.state === 'released') return usage(jobId);
    if (row.state === 'settled' && row.charge_micros > 0) db.prepare("INSERT OR IGNORE INTO scan_wallet_entries(id,workspace_id,amount_micros,kind,created_at) VALUES (?, ?, ?, 'refund', ?)")
      .run(`refund:${jobId}`, row.workspace_id, row.charge_micros, now());
    db.prepare("UPDATE scan_meter_jobs SET state = 'released', updated_at = ? WHERE job_id = ?").run(now(), jobId);
    return usage(jobId);
  }

  function usage(jobId) {
    const row = db.prepare('SELECT * FROM scan_meter_jobs WHERE job_id = ?').get(jobId);
    if (!row) return null;
    return { state: row.state, quote: JSON.parse(row.quote_json), chargeMicros: row.charge_micros,
      currency: 'usd', reportedTools: row.reported_tools_json ? JSON.parse(row.reported_tools_json) : null };
  }

  // Only a payment handler that has independently verified a paid, unrefunded
  // scanner-credit purchase should call this. It is intentionally not an API route.
  function recordVerifiedPurchase({ workspaceId, paymentId, amountMicros }) {
    if (typeof workspaceId !== 'string' || !workspaceId || typeof paymentId !== 'string' || !/^[A-Za-z0-9_-]{8,120}$/.test(paymentId) ||
      !validMoney(amountMicros) || amountMicros === 0) throw fail('Invalid verified scanner purchase.');
    db.prepare("INSERT OR IGNORE INTO scan_wallet_entries(id,workspace_id,amount_micros,kind,created_at) VALUES (?, ?, ?, 'purchase', ?)")
      .run(`purchase:${paymentId}`, workspaceId, amountMicros, now());
    const row = db.prepare('SELECT workspace_id, amount_micros FROM scan_wallet_entries WHERE id = ?').get(`purchase:${paymentId}`);
    if (row.workspace_id !== workspaceId || row.amount_micros !== amountMicros) throw fail('Scanner purchase identity was reused.', 409);
    return status(workspaceId);
  }

  function block(workspaceId, reason = 'payment_review') {
    if (typeof workspaceId !== 'string' || !workspaceId) throw fail('Invalid scanner workspace.');
    db.prepare('INSERT OR IGNORE INTO scan_wallet_blocks(workspace_id,reason,created_at) VALUES (?, ?, ?)')
      .run(workspaceId, String(reason).slice(0, 80), now());
    return status(workspaceId);
  }

  return { quote, reserve, settle, release, usage, status, recordVerifiedPurchase, block };
}
