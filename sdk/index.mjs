import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { defaultAutomationPolicy, normalizeAutomationPolicy, evaluateSecurityPolicy } from '../shared/offense-policy.js';

export { defaultAutomationPolicy, normalizeAutomationPolicy, evaluateSecurityPolicy };
export const OFFENSE_SDK_VERSION = '0.1.1';
export const OFFENSE_API_URL = 'https://offense.sh';
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const jobStatuses = new Set(['queued', 'starting', 'running', 'completed', 'partial', 'failed']);
const validJob = (value, id) => object(value) && /^[a-f0-9]{32}$/.test(value.id || '') &&
  (id === undefined || value.id === id) && jobStatuses.has(value.status);
const events = new Set(['manual', 'pre_deploy', 'post_deploy', 'agent_run', 'dependency_change', 'scheduled']);
const severities = new Set(['critical', 'high', 'medium', 'low', 'unknown']);
const fail = code => Object.assign(new Error({ invalid_response: 'The security service returned an unsupported or incomplete report.',
  request_failed: 'The security request did not complete.', response_limit: 'The security response exceeded the byte limit.',
  timeout: 'The security request timed out.', http_error: 'The security service did not accept or complete this request.',
  stale_response: 'The security report is stale or has an invalid scan time.', metadata_mismatch: 'The security report does not match the supplied dependency metadata.' }[code] || 'Security check failed.'), { code });

function serviceBase(value) {
  let url; try { url = new URL(value); } catch { throw Error('Provide an HTTPS Offense base URL.'); }
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if ((!local && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw Error('Provide an HTTPS origin without credentials, path, query or fragment. HTTP is supported only on loopback for development.');
  return url;
}

async function responseJson(response, maximum) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum) { await response.body?.cancel(); throw fail('response_limit'); }
  if (!response.body) throw fail('invalid_response');
  const reader = response.body.getReader(), chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw fail('response_limit');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); } catch { throw fail('invalid_response'); }
}

export async function dependencyMetadataFingerprint(files) {
  const normalized = sanitizeLockfiles(files).files.sort((a, b) => a.path.localeCompare(b.path));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(normalized)));
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

function validateReport(report) {
  const validFinding = finding => object(finding) && typeof finding.id === 'string' && finding.id.length > 0 &&
    typeof finding.advisoryId === 'string' && finding.advisoryId.length > 0 && severities.has(finding.severity) &&
    object(finding.package) && typeof finding.package.name === 'string' && finding.package.name.length > 0 &&
    typeof finding.package.installedVersion === 'string' && finding.package.installedVersion.length > 0 && Array.isArray(finding.package.lockfiles) &&
    finding.verification?.status === 'advisory_match' && finding.verification.confirmed === false;
  if (!object(report) || report.schemaVersion !== 'offense.audit.v1' || report.capability !== 'audit_dependencies' ||
      !['complete', 'partial'].includes(report.status) || !Array.isArray(report.findings) || !report.findings.every(validFinding) ||
      !object(report.coverage) || !['complete', 'partial'].includes(report.coverage.status) ||
      !Number.isInteger(report.coverage.checkedPackages) || report.coverage.checkedPackages < 0 ||
      !Number.isInteger(report.coverage.skippedPackages) || report.coverage.skippedPackages < 0 || !Array.isArray(report.coverage.warnings) ||
      !object(report.summary) || report.summary.advisoryMatches !== report.findings.length || report.summary.confirmedVulnerabilities !== 0 ||
      !object(report.remediation) || !Array.isArray(report.remediation.plans) || !Array.isArray(report.remediation.blockers) ||
      !Array.isArray(report.providers) || !report.providers.length || !/^[a-f0-9]{64}$/.test(report.metadataFingerprint || '')) throw fail('invalid_response');
  if (!Number.isFinite(report.scannedAt) || report.scannedAt < Date.now() - 15 * 60_000 || report.scannedAt > Date.now() + 5 * 60_000) throw fail('stale_response');
  return report;
}

export function createOffenseClient({ baseUrl = OFFENSE_API_URL, fetchImpl = globalThis.fetch,
  timeoutMs = 100_000, maximumResponseBytes = 8_000_000, onEvent } = {}) {
  const base = serviceBase(baseUrl);
  if (typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000 ||
      !Number.isInteger(maximumResponseBytes) || maximumResponseBytes < 1024 || maximumResponseBytes > 16_000_000) throw Error('Invalid bounded security client configuration.');
  const emit = event => { try { onEvent?.(Object.freeze(event)); } catch { /* Telemetry cannot change a security decision. */ } };
  async function audit({ files, signal } = {}) {
    const clean = sanitizeLockfiles(files);
    const timeout = AbortSignal.timeout(timeoutMs);
    const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response;
    try {
      response = await fetchImpl(new URL('/api/offense/audit', base).href, { method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': `Purple-Offense-SDK/${OFFENSE_SDK_VERSION}` },
        body: JSON.stringify({ files: clean.files, planLimit: 0 }), redirect: 'manual', credentials: 'omit', signal: requestSignal });
    } catch { throw fail(requestSignal.aborted ? 'timeout' : 'request_failed'); }
    if (!response.ok) { await response.body?.cancel(); const error = fail('http_error'); error.status = response.status; throw error; }
    let report;
    try { report = validateReport(await responseJson(response, maximumResponseBytes)); }
    catch (error) { if (requestSignal.aborted) throw fail('timeout'); throw error; }
    if (report.metadataFingerprint !== await dependencyMetadataFingerprint(clean.files)) throw fail('metadata_mismatch');
    if (clean.warnings.length) report = { ...report, status: 'partial', coverage: { ...report.coverage, status: 'partial',
      warnings: [...new Set([...report.coverage.warnings, ...clean.warnings])] } };
    return report;
  }
  async function check({ files, event = 'manual', policy = defaultAutomationPolicy(), signal } = {}) {
    if (!events.has(event)) throw Error('Unknown security lifecycle event.');
    const configuration = normalizeAutomationPolicy(policy);
    const initial = evaluateSecurityPolicy(null, configuration, event);
    if (initial.action === 'skip') return { report: null, decision: initial, durationMs: 0 };
    const started = performance.now(); emit({ event, stage: 'audit', outcome: 'started' });
    try {
      const report = await audit({ files, signal });
      const decision = evaluateSecurityPolicy(report, configuration, event);
      const durationMs = Math.round(performance.now() - started);
      emit({ event, stage: 'audit', outcome: decision.action, durationMs, advisoryMatches: report.findings.length });
      return { report, decision, durationMs };
    } catch (error) {
      const durationMs = Math.round(performance.now() - started), decision = evaluateSecurityPolicy(null, configuration, event);
      const code = ['invalid_response', 'request_failed', 'response_limit', 'timeout', 'http_error', 'stale_response', 'metadata_mismatch'].includes(error.code) ? error.code : 'input_invalid';
      emit({ event, stage: 'audit', outcome: 'incomplete', durationMs, errorCode: code });
      return { report: null, decision, durationMs, error: { code, ...(Number.isInteger(error.status) ? { status: error.status } : {}) } };
    }
  }
  return Object.freeze({ audit, check });
}

export class SecurityGateError extends Error {
  constructor(decision) { super('The security policy did not permit this operation. Review the security decision before proceeding.'); this.name = 'SecurityGateError'; this.decision = decision; }
}

export function assertSecurityDecision(decision, { requirePassed = false } = {}) {
  if (!object(decision) || decision.schemaVersion !== 'offense.decision.v1' ||
      !['allow', 'block', 'report', 'skip'].includes(decision.action) ||
      typeof decision.enabled !== 'boolean' || ![true, false, null].includes(decision.passed) ||
      decision.action === 'allow' && decision.passed !== true || decision.action === 'skip' && decision.passed !== null ||
      decision.action === 'block' || requirePassed && decision.passed !== true) throw new SecurityGateError(decision);
  return decision;
}

export function createAuditTool({ client = createOffenseClient(), policy = defaultAutomationPolicy(), event = 'manual' } = {}) {
  const configuration = normalizeAutomationPolicy(policy);
  if (!events.has(event)) throw Error('Unknown security lifecycle event.');
  return Object.freeze({ name: 'offense_audit_dependencies',
    description: 'Check sanitized npm or pnpm dependency metadata for known advisory matches and return a security policy decision. Advisory matches are unconfirmed application exposure.',
    inputSchema: { type: 'object', additionalProperties: false, required: ['files'], properties: {
      files: { type: 'array', minItems: 1, maxItems: 20, items: { type: 'object', additionalProperties: false, required: ['path', 'content'],
        properties: { path: { type: 'string', maxLength: 240 }, content: { anyOf: [{ type: 'string', maxLength: 2_000_000 }, { type: 'object' }] } } } }
    } },
    execute(input) {
      if (!object(input) || Object.keys(input).some(key => key !== 'files')) throw Error('This security tool accepts dependency files only. The host controls policy and lifecycle event.');
      return client.check({ files: input.files, event, policy: configuration });
    }
  });
}

export function claudeMcpOptions({ baseUrl = OFFENSE_API_URL } = {}) {
  const url = new URL('/mcp', serviceBase(baseUrl)).href;
  return { mcpServers: { offense: { type: 'http', url } }, allowedTools: ['mcp__offense__*'] };
}

export function opencodeMcpConfig({ baseUrl = OFFENSE_API_URL } = {}) {
  const url = new URL('/mcp', serviceBase(baseUrl)).href;
  return { mcp: { offense: { type: 'remote', url, enabled: true, oauth: false, timeout: 120_000 } } };
}

// Paid jobs are a separate, explicit interface. Dependency checks never receive
// this key, upload source, or silently switch to a billable scanner.
export function createHostedScanClient({ apiKey, baseUrl = OFFENSE_API_URL, fetchImpl = globalThis.fetch,
  timeoutMs = 60_000 } = {}) {
  const base = serviceBase(baseUrl), quotes = new WeakMap();
  if (typeof apiKey !== 'string' || !/^(?:offense_sk_|purple_scan_)[a-f0-9]{64}$/.test(apiKey) || typeof fetchImpl !== 'function' ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw Error('Provide a workspace scanner key and valid bounded client options.');
  const safeInteger = value => Number.isSafeInteger(value) && value >= 0;
  async function request(route, { body, idempotencyKey, signal } = {}) {
    const timeout = AbortSignal.timeout(timeoutMs), combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response;
    try {
      response = await fetchImpl(new URL(route, base).href, { method: body === undefined ? 'GET' : 'POST',
        headers: { authorization: `Bearer ${apiKey}`, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'manual', credentials: 'omit', signal: combined });
      if (!response.ok) { await response.body?.cancel(); const error = fail('http_error'); error.status = response.status; throw error; }
      return await responseJson(response, 8_000_000);
    } catch (error) {
      if (combined.aborted) throw fail('timeout');
      if (['http_error', 'response_limit', 'invalid_response'].includes(error.code)) throw error;
      throw fail('request_failed');
    }
  }
  async function tools({ signal } = {}) {
    const result = await request('/v1/tools', { signal });
    if (!object(result) || !Array.isArray(result.tools) || !result.tools.every(tool => typeof tool.id === 'string')) throw fail('invalid_response');
    return result;
  }
  async function usage({ signal } = {}) { return request('/v1/usage', { signal }); }
  async function quote({ tools: ids, inputBytes, fileCount, signal } = {}) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 32 || ids.some(id => typeof id !== 'string' || !/^[a-z][a-z0-9-]{0,60}$/.test(id)) ||
        new Set(ids).size !== ids.length || !safeInteger(inputBytes) || !safeInteger(fileCount) || fileCount < 1) throw Error('Provide selected tools and bounded input dimensions.');
    const result = await request('/v1/quotes', { body: { tools: ids, inputBytes, fileCount }, signal });
    if (!object(result) || typeof result.billable !== 'boolean' || result.currency !== 'usd' || !safeInteger(result.maximumMicros) ||
        result.inputBytes !== inputBytes || result.fileCount !== fileCount || !Array.isArray(result.toolIds) ||
        result.toolIds.length !== ids.length || new Set(result.toolIds).size !== result.toolIds.length ||
        result.toolIds.some(id => !ids.includes(id)) || !result.billable && result.maximumMicros !== 0) throw fail('invalid_response');
    const exposed = Object.freeze({ ...result, toolIds: Object.freeze([...result.toolIds]) });
    quotes.set(exposed, { maximumMicros: result.maximumMicros, tools: [...result.toolIds], inputBytes, fileCount });
    return exposed;
  }
  async function submit({ input, quote: acceptedQuote, maxChargeMicros, idempotencyKey, signal } = {}) {
    const price = quotes.get(acceptedQuote);
    if (!price || !safeInteger(maxChargeMicros) || price.maximumMicros > maxChargeMicros) throw Error('Obtain a quote with this client and explicitly approve a maximum charge that covers it before submitting.');
    if (!object(input) || Object.hasOwn(input, 'maxChargeMicros') || !Array.isArray(input.tools) || input.tools.length !== price.tools.length ||
        input.tools.some(id => !price.tools.includes(id)) || new Set(input.tools).size !== input.tools.length ||
        typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/.test(idempotencyKey)) throw Error('Use the quoted tools and an explicit stable idempotency key for this job.');
    const serialized = JSON.stringify(input);
    if (serialized.includes(apiKey) || new TextEncoder().encode(serialized).byteLength > 6_000_000) throw Error('Scan input is oversized or contains the scanner key. It was not uploaded.');
    if (Array.isArray(input.files)) {
      if (!input.files.every(file => object(file) && typeof file.path === 'string' && typeof file.content === 'string')) throw Error('Provide explicit text file contents for this scan.');
      const bytes = input.files.reduce((sum, file) => sum + new TextEncoder().encode(file.content).byteLength, 0);
      if (bytes !== price.inputBytes || input.files.length !== price.fileCount) throw Error('The supplied files do not match the accepted quote dimensions. Request a fresh quote.');
    }
    const result = await request('/v1/scans', { body: { ...input, maxChargeMicros: price.maximumMicros }, idempotencyKey, signal });
    if (!validJob(result)) throw fail('invalid_response');
    return result;
  }
  async function get(scanId, { signal } = {}) {
    if (typeof scanId !== 'string' || !/^[a-f0-9]{32}$/.test(scanId)) throw Error('Provide a valid scan ID.');
    const result = await request(`/v1/scans/${scanId}`, { signal });
    if (!validJob(result, scanId)) throw fail('invalid_response');
    return result;
  }
  return Object.freeze({ tools, usage, quote, submit, get });
}
