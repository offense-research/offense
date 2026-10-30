#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { updateBeforeRun } from './update.mjs';
import { prepareGitHistoryBundle } from './git-history-bundle.mjs';
import { quoteHostedScan, scannerPriceMessage } from './hosted-scan.mjs';

const TOOL_KINDS = Object.freeze({
  'trivy-image': 'image-tar',
  'gitleaks-history': 'git-bundle',
  'guarddog-npm': 'package-archive',
  'guarddog-pypi': 'package-archive',
  'cosign-image': 'cosign-save',
  'zap-passive-har': 'web-har'
});
const LIMITS = Object.freeze({ 'image-tar': 80 * 1024 * 1024, 'git-bundle': 32 * 1024 * 1024,
  'package-archive': 16 * 1024 * 1024, 'cosign-save': 32 * 1024 * 1024,
  'web-har': 2 * 1024 * 1024 });
const PACKAGE_NAME = /^(?:@?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?)$/;
const PACKAGE_VERSION = /^[a-zA-Z0-9][a-zA-Z0-9._+!-]{0,99}$/;
const BLOCKED_WEB_SUFFIXES = ['.localhost', '.local', '.internal', '.test', '.invalid', '.onion', '.arpa', '.lan', '.home', '.corp'];
const PASSIVE_HEADERS = new Set(['content-type', 'content-security-policy', 'strict-transport-security',
  'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cache-control',
  'access-control-allow-origin', 'access-control-allow-credentials']);

function publicWebOrigin(value) {
  if (typeof value !== 'string' || value.length < 12 || value.length > 2048) throw new Error('Use a public HTTPS origin.');
  let url;
  try { url = new URL(value); } catch { throw new Error('Use a public HTTPS origin.'); }
  const hostname = url.hostname.toLowerCase(), labels = hostname.split('.');
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' ||
      url.search || url.hash || value.includes('@') || hostname.endsWith('.') ||
      isIP(hostname.replace(/^\[|\]$/g, '')) || labels.length < 2 || !/^[a-z]{2,63}$/.test(labels.at(-1)) ||
      labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label)) ||
      BLOCKED_WEB_SUFFIXES.some(suffix => hostname.endsWith(suffix))) throw new Error('Use a public HTTPS origin.');
  return url.origin;
}

async function sanitizedPassiveHar(file, origin) {
  const info = await lstat(file);
  if (!info.isFile() || info.size < 1 || info.size > LIMITS['web-har'])
    throw new Error('HAR must be a regular file of at most 2 MiB.');
  let document;
  try { document = JSON.parse(await readFile(file, 'utf8')); } catch { throw new Error('HAR must be valid JSON.'); }
  const entries = document?.log?.entries;
  if (!Array.isArray(entries) || !entries.length || entries.length > 200)
    throw new Error('HAR must contain 1 to 200 captured responses.');
  const cleaned = entries.map((entry, index) => {
    const request = entry?.request, response = entry?.response;
    let url;
    try { url = new URL(request?.url); } catch { throw new Error('HAR contains an invalid or out-of-scope response.'); }
    if (!['GET', 'HEAD'].includes(request?.method) || url.protocol !== 'https:' || url.username || url.password ||
        url.origin !== origin || !Number.isInteger(response?.status) || response.status < 100 || response.status > 599 ||
        !Array.isArray(response.headers) || response.headers.length > 200)
      throw new Error('HAR contains an invalid or out-of-scope response.');
    const headers = [];
    for (const header of response.headers) {
      if (headers.length >= 24) break;
      const name = String(header?.name || '').toLowerCase();
      if (name === 'set-cookie') {
        const flags = String(header?.value || '').split(';').slice(1).map(value => value.trim())
          .filter(value => /^(?:secure|httponly|samesite=(?:strict|lax|none))$/i.test(value));
        headers.push({ name: 'Set-Cookie', value: `purple_redacted=redacted${flags.length ? `; ${flags.join('; ')}` : ''}` });
      } else if (PASSIVE_HEADERS.has(name)) {
        headers.push({ name, value: typeof header?.value === 'string' ?
          header.value.replace(/[\r\n\u0000-\u001f]/g, ' ').slice(0, 256) : '' });
      }
    }
    const pathHash = createHash('sha256').update(url.pathname).digest('hex').slice(0, 16);
    return { startedDateTime: '2026-01-01T00:00:00.000Z', time: 0,
      request: { method: request.method, url: `${origin}/purple-har/${pathHash}-${index}`, httpVersion: 'HTTP/1.1',
        cookies: [], headers: [], queryString: [], headersSize: -1, bodySize: 0 },
      response: { status: response.status, statusText: '', httpVersion: 'HTTP/1.1', cookies: [], headers,
        content: { size: 0, mimeType: 'text/plain', text: '' }, redirectURL: '', headersSize: -1, bodySize: 0 },
      cache: {}, timings: { send: 0, wait: 0, receive: 0 } };
  });
  const bytes = Buffer.from(JSON.stringify({ log: { version: '1.2', creator: { name: 'Purple sanitized HAR', version: '1' }, entries: cleaned } }));
  if (bytes.length > LIMITS['web-har']) throw new Error('Sanitized HAR exceeds the 2 MiB limit.');
  return bytes;
}

function safeJob(job, key) {
  const text = (value, max = 1500) => typeof value === 'string' ?
    value.slice(0, max).replaceAll(key || '\u0000', '[redacted]') : '';
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const fields = ['id', 'status', 'createdAt', 'startedAt', 'finishedAt', 'fingerprint', 'reportExpired'];
  const safe = Object.fromEntries(fields.filter(field => Object.hasOwn(job, field)).map(field => [field, job[field]]));
  safe.selectedTools = Array.isArray(job.selectedTools) ? job.selectedTools.slice(0, 20).map(value => text(value, 80)) : [];
  safe.usage = job.usage ? { inputBytes: count(job.usage.inputBytes), files: count(job.usage.files),
    durationMs: count(job.usage.durationMs) } : null;
  safe.metering = job.metering ? { state: text(job.metering.state, 30),
    chargeMicros: count(job.metering.chargeMicros), currency: text(job.metering.currency, 10) } : null;
  safe.coverage = job.coverage ? { scope: text(job.coverage.scope),
    artifactBytes: count(job.coverage.artifactBytes), uploadedFiles: count(job.coverage.uploadedFiles),
    sourceBytes: count(job.coverage.sourceBytes), commitCount: count(job.coverage.commitCount),
    refCount: count(job.coverage.refCount), objectCount: count(job.coverage.objectCount),
    ...(typeof job.coverage.artifactSha256 === 'string' && /^[a-f0-9]{64}$/i.test(job.coverage.artifactSha256) ?
      { artifactSha256: job.coverage.artifactSha256.toLowerCase() } : {}) } : null;
  safe.verified = job.verified && /^sha256:[a-f0-9]{64}$/.test(job.verified.digest || '') ? {
    digest: job.verified.digest, identity: text(job.verified.identity, 240), issuer: text(job.verified.issuer, 300)
  } : undefined;
  safe.execution = job.execution ? { startedAt: count(job.execution.startedAt),
    finishedAt: count(job.execution.finishedAt), durationMs: count(job.execution.durationMs) } : null;
  safe.error = job.error ? text(job.error) : undefined;
  safe.warnings = Array.isArray(job.warnings) ? job.warnings.map(value => text(value, 500)).slice(0, 50) : [];
  safe.tools = Array.isArray(job.tools) ? job.tools.slice(0, 20).map(tool => ({
    name: text(tool.name, 80), version: text(tool.version, 80), status: text(tool.status, 40),
    durationMs: Number.isSafeInteger(tool.durationMs) ? tool.durationMs : null,
    findings: Number.isSafeInteger(tool.findings) ? tool.findings : null,
    ...(tool.error ? { error: text(tool.error, 500) } : {})
  })) : [];
  safe.findings = Array.isArray(job.findings) ? job.findings.slice(0, 500).map(item => ({
    id: text(item.id, 64), tool: text(item.tool, 80), ruleId: text(item.ruleId, 200),
    file: text(item.file, 500), line: Number.isSafeInteger(item.line) && item.line > 0 ? item.line : null,
    severity: text(item.severity, 20), title: text(item.title, 300), remediation: text(item.remediation),
    ...(typeof item.commit === 'string' && /^[a-f0-9]{40,64}$/i.test(item.commit) ? { commit: item.commit } : {}),
    ...(item.package ? { package: text(item.package, 200), installedVersion: text(item.installedVersion, 100),
      fixedVersion: text(item.fixedVersion, 200) } : {})
  })) : [];
  return safe;
}

async function digestFile(file, limit) {
  const info = await lstat(file);
  if (!info.isFile() || info.size < 1 || info.size > limit) throw new Error(`Artifact must be a regular file of 1–${limit} bytes.`);
  let bytes = 0; const digest = createHash('sha256');
  for await (const chunk of createReadStream(file)) {
    bytes += chunk.byteLength;
    if (bytes > limit) throw new Error('Artifact grew beyond its upload limit.');
    digest.update(chunk);
  }
  if (bytes !== info.size) throw new Error('Artifact changed while it was being read.');
  return { size: bytes, sha256: digest.digest('hex') };
}

export async function hostedArtifactScan(file, { api = process.env.PURPLE_API_URL || 'https://app.purpleteam.sh',
  key = process.env.PURPLE_SCAN_KEY, tool, packageName, packageVersion, target: webTarget,
  expectedDigest, expectedIdentity, expectedIssuer, preview = false,
  scanId, output, idempotencyKey = randomUUID(), onJobCreated, onQuote, onSubmissionPrepared,
  timeoutMs = 14 * 60000, pollMs = 5000, fetchImpl = fetch } = {}) {
  const base = new URL(api);
  if (base.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(base.hostname)) throw new Error('Hosted scans require HTTPS.');
  if (base.username || base.password || base.search || base.hash) throw new Error('Use a plain API origin.');
  if (!scanId && !Object.hasOwn(TOOL_KINDS, tool)) throw new Error('Select one supported artifact tool.');
  const kind = scanId ? null : TOOL_KINDS[tool];
  const webOrigin = kind === 'web-har' ? publicWebOrigin(webTarget) : null;
  if (!scanId && kind === 'package-archive' && (!PACKAGE_NAME.test(packageName || '') || !PACKAGE_VERSION.test(packageVersion || '')))
    throw new Error('Package scans require an exact package name and version.');
  if (!scanId && kind === 'cosign-save') {
    let issuer;
    try { issuer = new URL(expectedIssuer); } catch { throw new Error('Cosign scans require a canonical HTTPS signer issuer.'); }
    if (!/^sha256:[a-f0-9]{64}$/.test(expectedDigest || '') ||
        typeof expectedIdentity !== 'string' || expectedIdentity.length < 1 || expectedIdentity.length > 240 ||
        !/^[\x21-\x7e]+$/.test(expectedIdentity) || /[\*?\[\]{}()|+^$\\]/.test(expectedIdentity) ||
        issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash || issuer.origin !== expectedIssuer)
      throw new Error('Cosign scans require an exact image digest, signer identity and canonical HTTPS issuer.');
  }
  if (preview && scanId) throw new Error('Preview requires a local artifact.');
  if (scanId && !/^[a-f0-9]{32}$/.test(scanId)) throw new Error('Scan ID is invalid.');
  if (!scanId && !/^[A-Za-z0-9_-]{8,100}$/.test(idempotencyKey)) throw new Error('Idempotency key is invalid.');
  const har = kind === 'web-har' ? await sanitizedPassiveHar(path.resolve(file), webOrigin) : null;
  const source = scanId ? null : har ? { size: har.length, sha256: createHash('sha256').update(har).digest('hex') } :
    await digestFile(path.resolve(file), LIMITS[kind]);
  if (preview) return { destination: base.origin, tool, kind, bytes: source.size, sha256: source.sha256,
    ...(kind === 'package-archive' ? { packageName, packageVersion } : {}),
    ...(kind === 'cosign-save' ? { expectedDigest, expectedIdentity, expectedIssuer } : {}),
    ...(kind === 'web-har' ? { target: webOrigin, capturedResponses: JSON.parse(har).log.entries.length } : {}) };
  if (!key) throw new Error('Set PURPLE_SCAN_KEY to a workspace scan key from Purple’s dashboard.');
  const quote = scanId ? null : await quoteHostedScan({ base, key, tools: [tool],
    inputBytes: source.size, fileCount: 1, fetchImpl, onQuote });
  const target = output ? path.resolve(output) : await mkdtemp(path.join(os.tmpdir(), 'purple-hosted-artifact-'));
  await mkdir(target, { recursive: true, mode: 0o700 });
  const headers = { authorization: `Bearer ${key}` };
  async function read(response, label) {
    if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}; no clean result is implied.`);
    return response.json();
  }
  let job;
  if (!scanId) {
    const uploaded = await read(await fetchImpl(new URL('/v1/artifacts', base), {
      method: 'POST', headers: { ...headers, 'content-type': 'application/octet-stream',
        'content-length': String(source.size), 'x-purple-artifact-kind': kind, 'x-content-sha256': source.sha256 },
      body: har ? Readable.from([har]) : createReadStream(path.resolve(file)), duplex: 'half',
      redirect: 'error', signal: AbortSignal.timeout(5 * 60000)
    }), 'Artifact upload');
    if (typeof uploaded.id !== 'string' || !/^[a-f0-9]{32}$/.test(uploaded.id)) throw new Error('Artifact upload returned an invalid ID.');
    const submission = { artifactId: uploaded.id, tools: [tool], maxChargeMicros: quote.maximumMicros,
      ...(kind === 'package-archive' ? { packageName, packageVersion } : {}),
      ...(kind === 'cosign-save' ? { expectedDigest, expectedIdentity, expectedIssuer } : {}),
      ...(kind === 'web-har' ? { target: webOrigin } : {}) };
    if (onSubmissionPrepared) await onSubmissionPrepared({ input: submission, inputBytes: source.size, fileCount: 1, idempotencyKey });
    job = await read(await fetchImpl(new URL('/v1/scans', base), {
      method: 'POST', headers: { ...headers, 'content-type': 'application/json', 'idempotency-key': idempotencyKey },
      body: JSON.stringify(submission),
      redirect: 'error', signal: AbortSignal.timeout(60000)
    }), 'Scan creation');
  } else {
    job = await read(await fetchImpl(new URL(`/v1/scans/${encodeURIComponent(scanId)}`, base), {
      headers, redirect: 'error', signal: AbortSignal.timeout(60000)
    }), 'Scan retrieval');
  }
  const validate = expectedId => {
    if (typeof job.id !== 'string' || !/^[a-f0-9]{32}$/.test(job.id) || expectedId && job.id !== expectedId ||
        !['queued', 'starting', 'running', 'completed', 'partial', 'failed'].includes(job.status) ||
        !scanId && Array.isArray(job.selectedTools) && JSON.stringify(job.selectedTools) !== JSON.stringify([tool]))
      throw new Error('Scan returned invalid job metadata.');
  };
  validate(scanId);
  const jobId = job.id;
  if (!scanId && onJobCreated) await onJobCreated({ id: job.id, status: job.status });
  const save = async () => writeFile(path.join(target, 'scan.json'), JSON.stringify({ ...safeJob(job, key),
    clientCoverage: source ? { kind, bytes: source.size, sha256: source.sha256,
      scope: 'One local artifact at upload time; destination received its bytes after SHA-256 verification.' } :
      { scope: 'Resumed job; inspect the original upload report for local artifact details.' } }, null, 2), { mode: 0o600 });
  await save();
  const deadline = Date.now() + timeoutMs;
  while (['queued', 'starting', 'running'].includes(job.status)) {
    if (Date.now() >= deadline) throw new Error(`Polling deadline reached. Resume with --scan-id ${job.id}. Job metadata is saved in ${target}.`);
    await new Promise(resolve => setTimeout(resolve, pollMs));
    job = await read(await fetchImpl(new URL(`/v1/scans/${jobId}`, base), {
      headers, redirect: 'error', signal: AbortSignal.timeout(60000)
    }), 'Scan polling');
    validate(jobId);
    await save();
  }
  if (job.reportExpired) throw new Error('This scan report expired. Start a new scan; usage metadata is not a security result.');
  const clean = safeJob(job, key);
  const findings = clean.findings.map(item => `- **${item.severity}** ${item.title} — ${item.file}${item.line ? `:${item.line}` : ''}${item.commit ? ` @ ${item.commit}` : ''} (${item.tool}, ${item.ruleId})\n  ${item.remediation}`).join('\n');
  await writeFile(path.join(target, 'scan.md'), `# Purple hosted artifact scan\n\nStatus: ${clean.status}\nScan: ${clean.id}\nSelected tool: ${(clean.selectedTools || [tool || 'unknown']).join(', ')}\n\n${findings || 'No findings returned. Check completion and coverage before drawing conclusions.'}\n\n## Coverage\n\n${clean.coverage?.scope || clean.error || 'Scanner coverage unavailable.'}\n\n${clean.tools.map(item => `${item.name} ${item.version || ''}: ${item.status}${item.error ? ` — ${item.error}` : ''}`).join('\n\n')}\n\nScanner findings require review and do not establish exploitability.\n`, { mode: 0o600 });
  return { id: job.id, status: job.status, findings: clean.findings.length,
    report: path.join(target, 'scan.md'), json: path.join(target, 'scan.json') };
}

async function main() {
  if (process.argv.includes('--help')) {
    console.log('Usage: node hosted-artifact-scan.mjs ARTIFACT --tool trivy-image|gitleaks-history|guarddog-npm|guarddog-pypi|cosign-image|zap-passive-har [--target PUBLIC_HTTPS_ORIGIN for a HAR] [--from-repo for a local Git repository] [--package-name NAME --package-version VERSION] [--expected-digest sha256:HEX --expected-identity ID --expected-issuer HTTPS_ORIGIN] [--preview] [--scan-id ID] [--output DIRECTORY] [--api URL]. Set PURPLE_SCAN_KEY for uploads.');
    return;
  }
  const args = process.argv.slice(2), file = args[0] && !args[0].startsWith('--') ? args.shift() : null;
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tool') options.tool = args[++i];
    else if (args[i] === '--package-name') options.packageName = args[++i];
    else if (args[i] === '--package-version') options.packageVersion = args[++i];
    else if (args[i] === '--expected-digest') options.expectedDigest = args[++i];
    else if (args[i] === '--expected-identity') options.expectedIdentity = args[++i];
    else if (args[i] === '--expected-issuer') options.expectedIssuer = args[++i];
    else if (args[i] === '--target') options.target = args[++i];
    else if (args[i] === '--from-repo') options.fromRepo = true;
    else if (args[i] === '--preview') options.preview = true;
    else if (args[i] === '--scan-id') options.scanId = args[++i];
    else if (args[i] === '--output') options.output = args[++i];
    else if (args[i] === '--api') options.api = args[++i];
    else throw new Error(`Unknown option ${args[i]}`);
  }
  if (!options.scanId && !file) throw new Error('Provide a local artifact file.');
  if (options.fromRepo && options.tool !== 'gitleaks-history') throw new Error('--from-repo requires --tool gitleaks-history.');
  if (options.fromRepo && options.scanId) throw new Error('--from-repo starts a new scan; omit --scan-id.');
  const update = await updateBeforeRun('purple', import.meta.url, { preview: options.preview });
  if (update.stop) return;
  const prepared = options.fromRepo ? await prepareGitHistoryBundle(file) : null;
  let result;
  try { result = await hostedArtifactScan(prepared?.artifactPath || file,
    { ...options, onQuote: quote => console.log(scannerPriceMessage(quote)) }); }
  finally { await prepared?.cleanup(); }
  console.log(JSON.stringify(result, null, 2));
  if (!options.preview && result.status !== 'completed') process.exitCode = 2;
}

if (typeof OFFENSE_CLI_EMBEDDED === 'undefined' && process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
