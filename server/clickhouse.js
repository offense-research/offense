import { createHash } from 'node:crypto';

function identifier(value, name) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error(`Invalid ClickHouse ${name}.`);
  return value;
}

function clickhouseTime(value) {
  const date = new Date(value);
  return (Number.isNaN(date.getTime()) ? new Date() : date).toISOString().replace('T', ' ').replace('Z', '');
}

export function createClickHouse(config, fetchImpl = fetch) {
  if (!config.url || !config.password) return null;
  const endpoint = new URL(config.url);
  if (endpoint.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(endpoint.hostname)) throw new Error('ClickHouse requires an HTTPS endpoint.');
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.pathname !== '/') throw new Error('Use a ClickHouse endpoint without credentials or a path.');
  const database = identifier(config.database || 'default', 'database');
  const table = identifier(config.table || 'purple_events', 'table');
  const name = `${database}.${table}`;
  const authorization = `Basic ${Buffer.from(`${config.user || 'default'}:${config.password}`).toString('base64')}`;
  let schemaPromise;

  async function execute(query, { params = {}, body, settings = {} } = {}) {
    const url = new URL(endpoint);
    url.searchParams.set('database', database);
    for (const [key, value] of Object.entries({ ...params, ...settings })) url.searchParams.set(key, String(value));
    if (body !== undefined) url.searchParams.set('query', query);
    const response = await fetchImpl(url, {
      method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'text/plain; charset=utf-8' },
      body: body === undefined ? query : body, signal: AbortSignal.timeout(15000)
    });
    const result = await response.text();
    if (!response.ok) throw new Error(`ClickHouse returned HTTP ${response.status}: ${result.slice(0, 300)}`);
    return result;
  }

  function ensureSchema() {
    if (!schemaPromise) schemaPromise = execute(`CREATE TABLE IF NOT EXISTS ${name} (
      workspace_id String,
      event_id UInt64,
      occurred_at DateTime64(3, 'UTC'),
      received_at DateTime64(3, 'UTC'),
      source_worker LowCardinality(String),
      request_id String,
      event_type LowCardinality(String),
      outcome LowCardinality(String),
      request_method LowCardinality(String),
      response_status UInt16,
      log_text String,
      payload String,
      INDEX request_id_index request_id TYPE bloom_filter(0.01) GRANULARITY 1
    ) ENGINE = MergeTree
    PARTITION BY toYYYYMM(occurred_at)
    ORDER BY (workspace_id, source_worker, occurred_at, event_id)`)
      .catch(error => { schemaPromise = null; throw error; });
    return schemaPromise;
  }

  async function insert(rows) {
    if (!rows.length) return;
    await ensureSchema();
    const records = rows.map(row => {
      const event = JSON.parse(row.payload);
      return {
        workspace_id: row.workspaceId, event_id: row.id,
        occurred_at: clickhouseTime(event.timestamp || row.receivedAt), received_at: clickhouseTime(row.receivedAt),
        source_worker: event.sourceWorker, request_id: event.requestId || event.queueMessageId || '',
        event_type: event.eventType || '', outcome: event.outcome || '', request_method: event.requestMethod || '',
        response_status: event.responseStatus || 0,
        log_text: (event.logs || []).map(log => log.message).join('\n'), payload: row.payload
      };
    });
    const body = records.map(record => JSON.stringify(record)).join('\n') + '\n';
    await execute(`INSERT INTO ${name} FORMAT JSONEachRow`, {
      body,
      settings: {
        async_insert: 1, wait_for_async_insert: 1, async_insert_deduplicate: 1,
        insert_deduplication_token: createHash('sha256').update(body).digest('hex')
      }
    });
  }

  async function search(workspaceId, filters = {}) {
    await ensureSchema();
    const conditions = ['workspace_id = {workspace:String}'];
    const params = { param_workspace: workspaceId };
    if (filters.worker) { conditions.push('source_worker = {worker:String}'); params.param_worker = filters.worker; }
    if (filters.requestId) { conditions.push('request_id = {request_id:String}'); params.param_request_id = filters.requestId; }
    if (filters.from) { conditions.push('occurred_at >= fromUnixTimestamp64Milli({from:Int64})'); params.param_from = filters.from; }
    if (filters.to) { conditions.push('occurred_at < fromUnixTimestamp64Milli({to:Int64})'); params.param_to = filters.to; }
    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 100);
    const result = await execute(`SELECT event_id, toUnixTimestamp64Milli(received_at) AS received_at_ms, payload
      FROM ${name} WHERE ${conditions.join(' AND ')}
      ORDER BY occurred_at DESC, event_id DESC LIMIT ${limit} FORMAT JSONEachRow`, { params });
    return result.trim() ? result.trim().split('\n').map(line => {
      const row = JSON.parse(line);
      return { id: row.event_id, receivedAt: Number(row.received_at_ms), ...JSON.parse(row.payload) };
    }) : [];
  }

  return { ensureSchema, insert, search };
}

