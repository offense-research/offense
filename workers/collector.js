// Uploaded as a Tail Worker. Keep this file self-contained for Cloudflare's module API.
const sensitiveKey = /pass(word|phrase)?|secret|token|api[_-]?key|auth(orization)?|cookie|session|credential|private[_-]?key|email|phone/i;
const allowedLevels = new Set(['debug', 'info', 'log', 'warn', 'error']);

function redactText(value) {
  return String(value)
    .replace(/https?:\/\/[^\s"'<>]+/gi, '[REDACTED_URL]')
    .replace(/\bBearer\s+[^\s,;"']+/gi, 'Bearer [REDACTED]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g, '[REDACTED]')
    .replace(/\b([\w.-]+@[\w.-]+\.[A-Za-z]{2,})\b/g, '[REDACTED_EMAIL]')
    .replace(/\b(password|passphrase|secret|token|api[_-]?key|authorization|cookie|session|credential|private[_-]?key|email|phone)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1=[REDACTED]')
    .slice(0, 500);
}

function redactValue(value, depth = 0) {
  if (depth > 4) return '[TRUNCATED]';
  if (typeof value === 'string') {
    if (value.length <= 4000 && /^[\[{]/.test(value.trim())) {
      try { return redactValue(JSON.parse(value), depth + 1); } catch { /* Treat ordinary text as text. */ }
    }
    return redactText(value);
  }
  if (Array.isArray(value)) return value.slice(0, 20).map(item => redactValue(item, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).slice(0, 30).map(([key, item]) =>
      [redactText(key).slice(0, 64), sensitiveKey.test(key) ? '[REDACTED]' : redactValue(item, depth + 1)]));
  }
  return value == null || typeof value === 'boolean' || typeof value === 'number' ? value : '[UNSUPPORTED]';
}

function redactLog(log) {
  const level = allowedLevels.has(log?.level) ? log.level : 'log';
  const parts = Array.isArray(log?.message) ? log.message : [log?.message];
  const rendered = parts.slice(0, 10).map(part => {
    const safe = redactValue(part);
    return typeof safe === 'string' ? safe : JSON.stringify(safe);
  });
  const label = /^(?:password|passphrase|secret|token|api[_-]?key|authorization|cookie|session|credential|private[_-]?key|email|phone)\s*[:=]?\s*$/i;
  for (let index = 1; index < rendered.length; index++) {
    if (label.test(rendered[index - 1].trim())) rendered[index] = '[REDACTED]';
  }
  return { level, message: redactText(rendered.join(' ')) };
}

function normalize(item) {
  const fetchEvent = item.event?.request ? item.event : null;
  const timestamp = Number(item.eventTimestamp);
  const eventDate = new Date(timestamp);
  const method = String(fetchEvent?.request?.method || '').toUpperCase();
  const ray = fetchEvent?.request?.headers?.['cf-ray'];
  const outcome = String(item.outcome || 'unknown');
  const names = new Set(['Error', 'TypeError', 'ReferenceError', 'RangeError', 'SyntaxError', 'URIError', 'EvalError', 'AggregateError']);
  const logs = Array.isArray(item.logs) ? item.logs.slice(0, 20).map(redactLog) : [];
  return {
    schema: 'purple.tail.v1',
    sourceWorker: String(item.scriptName || 'unknown').slice(0, 128),
    timestamp: Number.isFinite(timestamp) && !Number.isNaN(eventDate.getTime()) ? eventDate.toISOString() : new Date().toISOString(),
    eventType: fetchEvent ? 'fetch' : 'other',
    outcome: ['unknown', 'ok', 'exception', 'exceededCpu', 'exceededMemory', 'scriptNotFound', 'canceled', 'responseStreamDisconnected'].includes(outcome) ? outcome : 'unknown',
    requestMethod: fetchEvent && ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) ? method : null,
    requestId: typeof ray === 'string' && /^[a-f0-9]{16,32}(?:-[A-Z]{3})?$/i.test(ray) ? ray : null,
    responseStatus: Number.isInteger(fetchEvent?.response?.status) ? fetchEvent.response.status : null,
    logLevels: logs.map(log => log.level),
    logs,
    exceptionNames: Array.isArray(item.exceptions) ? item.exceptions.slice(0, 20).map(error => names.has(error.name) ? error.name : 'Error') : []
  };
}

export default {
  async tail(events, env) {
    if (!Array.isArray(events) || !events.length) return;
    // The app Worker also serves ingestion. Tailing those requests would make
    // each forwarded batch produce another batch indefinitely.
    const sourceEvents = events.filter(item => {
      try {
        const url = new URL(item.event?.request?.url || '');
        return !(url.hostname === 'ingest.purpleteam.sh' && url.pathname === '/api/ingest');
      } catch { return true; }
    });
    if (!sourceEvents.length) return;
    // Enqueue only allowlisted metadata and redacted, bounded log messages.
    await env.PURPLE_EVENTS.sendBatch(sourceEvents.map(item => ({ body: normalize(item) })));
  }
};
