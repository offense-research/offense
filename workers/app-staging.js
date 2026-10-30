import { DurableObject } from 'cloudflare:workers';
import { createServer } from 'node:http';
import { httpServerHandler } from 'cloudflare:node';
import { createWorkerApp } from './app-api.js';
import { DurableSqlite } from './sqlite-adapter.js';
import { assets } from './asset-manifest.generated.js';
import { staticAssetResponse } from './static-assets.js';
import { timingSafeEqual } from 'node:crypto';
import { uploadScanArtifact } from './artifact-upload.js';
import { createToolCallBridge, withArtifactCallMetrics } from './tool-call-bridge.js';
import { isClientAsset, legacyClientAsset } from './client-assets.js';

const importTables = new Set([
  'users', 'user_contacts', 'workspaces', 'memberships', 'sessions', 'ingest_tokens', 'ingest_batches',
  'events', 'detection_signals', 'investigations', 'investigation_events',
  'worker_repositories', 'dependency_monitor', 'dependency_snapshots', 'dependency_automation_policies', 'dependency_automation_runs', 'agent_runs', 'vulnerability_discoveries', 'workspace_revisions', 'account_connections', 'upgrade_rehearsals', 'rehearsal_trials', 'wallet_orders', 'wallet_preferences', 'wallet_entries', 'wallet_runs', 'billing_events', 'discovery_metric_days', 'scan_keys', 'scan_jobs', 'scan_sources', 'scan_cleanup', 'scan_wallet_entries', 'scan_meter_jobs', 'scan_wallet_blocks', 'scan_wallet_orders', 'scan_billing_events', 'scan_auto_topup_orders', 'scan_auto_topup_events', 'scan_auto_topup_preferences', 'scan_usage_jobs', 'scan_usage_tools', 'scan_usage_activity', 'scan_usage_meta', 'skill_usage_days', 'skill_usage_meta', 'tool_call_days', 'tool_call_meta', 'cli_auth_devices', 'cli_auth_limits'
]);

export class PurpleState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const db = new DurableSqlite(ctx.storage);
    this.db = db;
    const { app, flushClickHouse, dispatchAgents, pruneTraces, hostedScans, toolCallMetrics } = createWorkerApp({
      db, env, schedule: promise => ctx.waitUntil(promise)
    });
    this.hostedScans = hostedScans;
    this.toolCallBridge = createToolCallBridge(toolCallMetrics);
    this.flushClickHouse = flushClickHouse;
    this.dispatchAgents = dispatchAgents;
    this.pruneTraces = pruneTraces;
    this.handler = httpServerHandler(createServer(app));
  }

  async fetch(request) {
    if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + 15_000);
    return this.handler.fetch(request, this.env, this.ctx);
  }

  async beginArtifactUpload(token, metadata) {
    const reservation = this.hostedScans.beginArtifactUpload(token, metadata);
    try {
      if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + 15_000);
      return reservation;
    } catch (error) {
      this.hostedScans.abandonArtifactUpload(token, reservation.id);
      throw error;
    }
  }
  finishArtifactUpload(token, id, size) { return this.hostedScans.finishArtifactUpload(token, id, size); }
  abandonArtifactUpload(token, id) { return this.hostedScans.abandonArtifactUpload(token, id); }
  beginArtifactCallMetrics() { return this.toolCallBridge.begin(); }
  finishArtifactCallMetrics(id, status) { return this.toolCallBridge.finish(id, status); }

  importRows(table, rows) {
    if (!importTables.has(table) || !Array.isArray(rows) || rows.length > 100 ||
        rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))) {
      throw new Error('Invalid import batch.');
    }
    const columns = new Set(this.db.prepare(`PRAGMA table_info(${table})`).all().map(column => column.name));
    return this.ctx.storage.transactionSync(() => {
      for (const row of rows) {
        const names = Object.keys(row);
        if (!names.length || names.some(name => !columns.has(name))) throw new Error('Invalid import columns.');
        const conflict = table === 'workspaces' ? ' ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at' : '';
        this.db.prepare(`INSERT ${conflict ? '' : 'OR REPLACE '}INTO ${table} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})${conflict}`)
          .run(...names.map(name => row[name]));
      }
      return { table, imported: rows.length };
    });
  }

  resetImport() {
    const tables = [...importTables].reverse();
    this.ctx.storage.transactionSync(() => {
      for (const table of tables) this.db.exec(`DELETE FROM ${table}`);
    });
    return { reset: true };
  }

  async alarm() {
    try {
      this.pruneTraces();
      await this.flushClickHouse();
      await this.dispatchAgents();
    } finally { await this.ctx.storage.setAlarm(Date.now() + 60_000); }
  }
}

async function boundedText(request, maxBytes) {
  const length = Number(request.headers.get('content-length'));
  if (Number.isFinite(length) && length > maxBytes) throw new Error('Import batch too large');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('Import batch is empty');
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error('Import batch too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/v1/artifacts' && request.method === 'POST') {
      const state = ctx.exports.PurpleState.getByName(env.PURPLE_STATE_NAME || 'staging');
      return withArtifactCallMetrics(state, () => uploadScanArtifact(request, env, state));
    }
    if (url.pathname === '/api/internal/import' && request.method === 'POST') {
      const supplied = request.headers.get('authorization')?.replace(/^Bearer /, '') || '';
      const expected = env.MIGRATION_KEY || '';
      const a = Buffer.from(supplied), b = Buffer.from(expected);
      if (!expected || a.length !== b.length || !timingSafeEqual(a, b)) return new Response('Unauthorized', { status: 401 });
      try {
        const text = await boundedText(request, 250000);
        const payload = JSON.parse(text);
        const state = ctx.exports.PurpleState.getByName(env.PURPLE_STATE_NAME || 'staging');
        return Response.json(payload.reset === true ? await state.resetImport() :
          await state.importRows(payload.table, payload.rows));
      } catch (error) {
        return Response.json({ error: error.message }, { status: error.message === 'Import batch too large' ? 413 : 400 });
      }
    }
    if (url.pathname === '/health' || url.pathname === '/mcp' || url.pathname.startsWith('/api/') || url.pathname.startsWith('/v1/') || url.pathname.startsWith('/admin/')) {
      return ctx.exports.PurpleState.getByName(env.PURPLE_STATE_NAME || 'staging').fetch(request);
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Not found', { status: 404 });
    if (isClientAsset(url.pathname)) return legacyClientAsset(request);
    if ((url.pathname.startsWith('/assets/') || url.pathname.startsWith('/skills/')) && !assets[url.pathname]) return new Response('Not found', { status: 404 });
    return staticAssetResponse(assets, url.pathname, request);
  }
};
