import { randomBytes } from 'node:crypto';

// Only aggregate counts reach SQLite. Short-lived completion handles contain
// no request data and remain in memory; interrupted uploads stay unfinished.
export function createToolCallBridge(store, { now = Date.now, maximum = 2048, ttl = 30 * 60_000 } = {}) {
  const pending = new Map();
  function begin() {
    const at = now();
    for (const [id, ticket] of pending) if (at - ticket.at >= ttl) pending.delete(id);
    let counter;
    try { counter = store.start({ kind: 'request', channel: 'http', operation: 'artifact_upload', endpoint: 'POST /v1/artifacts' }); }
    catch { return null; }
    if (pending.size >= maximum) return null;
    const id = randomBytes(16).toString('hex');
    pending.set(id, { at, counter });
    return id;
  }
  function finish(id, statusCode) {
    const ticket = typeof id === 'string' ? pending.get(id) : null;
    if (!ticket || !Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) return false;
    pending.delete(id);
    try { return ticket.counter.finish({ status: statusCode >= 500 ? 'failed' : statusCode >= 400 ? 'rejected' : 'completed' }); }
    catch { return false; }
  }
  return { begin, finish };
}

export async function withArtifactCallMetrics(state, upload) {
  let ticket;
  try { ticket = await state.beginArtifactCallMetrics(); } catch { /* Telemetry never prevents uploads. */ }
  try {
    const response = await upload();
    if (ticket) try { await state.finishArtifactCallMetrics(ticket, response.status); } catch { /* The recorded attempt remains unfinished. */ }
    return response;
  } catch (error) {
    if (ticket) try { await state.finishArtifactCallMetrics(ticket, 500); } catch { /* No retry can duplicate a terminal counter. */ }
    throw error;
  }
}
