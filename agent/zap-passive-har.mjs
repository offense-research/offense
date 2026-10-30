import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { normalizeZapBaselineReport } from './zap-baseline-report.mjs';
import { webScanOrigin, webScanUrlInScope } from '../server/web-scan-target.js';

const MAX_HAR_BYTES = 2 * 1024 * 1024;
const MAX_ENTRIES = 200;
const MAX_SANITIZED_HAR_BYTES = 2 * 1024 * 1024;
const MAX_RUNTIME_MS = 3 * 60_000;
const allowedHeaders = new Set(['content-type', 'content-security-policy', 'strict-transport-security',
  'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cache-control',
  'access-control-allow-origin', 'access-control-allow-credentials']);

function headerValue(value) {
  return typeof value === 'string' ? value.replace(/[\r\n\u0000-\u001f]/g, ' ').slice(0, 256) : '';
}

function responseHeaders(headers) {
  if (!Array.isArray(headers) || headers.length > 200) throw new Error('HAR response headers exceed the limit.');
  const result = [];
  for (const header of headers) {
    if (result.length >= 24) break;
    const name = String(header?.name || '').toLowerCase();
    if (name === 'set-cookie') {
      // Preserve only cookie flags so ZAP can inspect them without seeing credential values.
      const flags = String(header?.value || '').split(';').slice(1).map(item => item.trim())
        .filter(item => /^(?:secure|httponly|samesite=(?:strict|lax|none))$/i.test(item));
      result.push({ name: 'Set-Cookie', value: `purple_redacted=redacted${flags.length ? `; ${flags.join('; ')}` : ''}` });
    } else if (allowedHeaders.has(name)) result.push({ name, value: headerValue(header?.value) });
  }
  return result;
}

export function sanitizeHarForPassiveScan(input, target) {
  const origin = webScanOrigin(target);
  const bytes = typeof input === 'string' ? Buffer.byteLength(input) : input?.byteLength;
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_HAR_BYTES) throw new Error('HAR exceeds the 2 MiB limit.');
  let document;
  try { document = JSON.parse(Buffer.from(input).toString('utf8')); } catch { throw new Error('HAR must be valid JSON.'); }
  const entries = document?.log?.entries;
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_ENTRIES)
    throw new Error('HAR must contain 1 to 200 captured responses.');
  const cleaned = entries.map((entry, index) => {
    const req = entry?.request, res = entry?.response;
    if (!req || !res || !['GET', 'HEAD'].includes(req.method) || !webScanUrlInScope(req.url, origin) ||
        !Number.isInteger(res.status) || res.status < 100 || res.status > 599)
      throw new Error('HAR contains an invalid or out-of-scope response.');
    const pathname = new URL(req.url).pathname;
    const pathHash = createHash('sha256').update(pathname).digest('hex').slice(0, 16);
    return { startedDateTime: '2026-01-01T00:00:00.000Z', time: 0,
      request: { method: req.method, url: `${origin}/purple-har/${pathHash}-${index}`, httpVersion: 'HTTP/1.1',
        cookies: [], headers: [], queryString: [], headersSize: -1, bodySize: 0 },
      response: { status: res.status, statusText: '', httpVersion: 'HTTP/1.1',
        cookies: [], headers: responseHeaders(res.headers || []), content: { size: 0, mimeType: 'text/plain', text: '' },
        redirectURL: '', headersSize: -1, bodySize: 0 }, cache: {}, timings: { send: 0, wait: 0, receive: 0 } };
  });
  const sanitized = { log: { version: '1.2', creator: { name: 'Purple sanitized HAR', version: '1' }, entries: cleaned } };
  if (Buffer.byteLength(JSON.stringify(sanitized)) > MAX_SANITIZED_HAR_BYTES)
    throw new Error('Sanitized HAR exceeds the 2 MiB limit.');
  return sanitized;
}

export function zapPassiveHarPlan(harPath, reportDirectory, target) {
  const origin = webScanOrigin(target);
  // ZAP 2.17.0's bundled HAR import job only imports recorded responses; it has no replay option.
  return `env:\n  contexts:\n    - name: purple-captured-responses\n      urls:\n        - ${JSON.stringify(`${origin}/`)}\n  parameters:\n    failOnError: true\n    failOnWarning: false\n    progressToStdout: false\njobs:\n  - type: import\n    parameters:\n      type: har\n      fileName: ${JSON.stringify(harPath)}\n  - type: passiveScan-wait\n    parameters:\n      maxDuration: 2\n  - type: report\n    parameters:\n      template: traditional-json\n      reportDir: ${JSON.stringify(reportDirectory)}\n      reportFile: report.json\n      displayReport: false\n`;
}

export async function runZapPassiveHar(input, { target, execute = spawnSync, binary = '/zap/zap.sh',
  tempRoot = os.tmpdir() } = {}) {
  const origin = webScanOrigin(target);
  const sanitized = sanitizeHarForPassiveScan(input, origin);
  const directory = await mkdtemp(path.join(tempRoot, 'purple-zap-har-'));
  const harPath = path.join(directory, 'input.har'), planPath = path.join(directory, 'plan.yaml');
  const reportPath = path.join(directory, 'report.json');
  try {
    await writeFile(harPath, JSON.stringify(sanitized), { mode: 0o600 });
    await writeFile(planPath, zapPassiveHarPlan(harPath, directory, origin), { mode: 0o600 });
    const result = execute(binary, ['-cmd', '-autorun', planPath, '-Xmx768m'], {
      cwd: directory, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: directory, TMPDIR: directory,
        JAVA_TOOL_OPTIONS: '-Djava.awt.headless=true' }, timeout: MAX_RUNTIME_MS, killSignal: 'SIGKILL',
      maxBuffer: 1024 * 1024, stdio: ['ignore', 'ignore', 'ignore'] });
    if (result.error || ![0, 2].includes(result.status)) throw new Error('ZAP passive HAR processing failed.');
    if ((await stat(reportPath)).size > 2 * 1024 * 1024) throw new Error('ZAP report exceeds the 2 MiB limit.');
    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    const normalized = normalizeZapBaselineReport(report, origin);
    normalized.tools[0].name = 'zap-passive-har';
    normalized.tools[0].version = '2.17.0';
    for (const finding of normalized.findings) finding.tool = 'zap-passive-har';
    if (result.status === 2) {
      normalized.status = 'partial';
      normalized.tools[0].status = 'partial';
      normalized.warnings.push('ZAP reported a warning; the passive scan may be incomplete.');
    }
    normalized.coverage.scope = `${sanitized.log.entries.length} sanitized captured responses; no live crawl or active requests.`;
    return normalized;
  } finally { await rm(directory, { recursive: true, force: true }); }
}
