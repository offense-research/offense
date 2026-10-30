#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectSource, scannerPriceMessage } from './hosted-scan.mjs';
import { updateBeforeRun } from './update.mjs';

const IDS = new Set(['nuclei', 'prowler-cloudflare', 'schemathesis', 'zap-api', 'sslyze', 'checkov', 'trufflehog-verified', 'mobsf-static',
  'openssf-scorecard', 'katana', 'httpx']);
const TARGET_TOOLS = new Set(['nuclei', 'schemathesis', 'zap-api', 'sslyze', 'katana', 'httpx']);
const API_TOOLS = new Set(['schemathesis', 'zap-api']);
const JOB_ID = /^[a-f0-9]{32}$/;
const STATES = new Set(['queued', 'starting', 'running', 'completed', 'partial', 'failed']);
const MOBILE_LIMIT = 80 * 1024 * 1024;
const SOURCE_LIMIT = 4 * 1024 * 1024;

function apiOrigin(value) {
  const url = new URL(value);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) ||
      url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Use a plain HTTPS API origin.');
  return url;
}

function targetOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Use one public HTTPS origin without a path.'); }
  const host = url.hostname.toLowerCase(), labels = host.split('.');
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash ||
      isIP(host.replace(/^\[|\]$/g, '')) || host.endsWith('.') || labels.length < 2 || !/^[a-z]{2,63}$/.test(labels.at(-1)) ||
      labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label)) ||
      ['.localhost', '.local', '.internal', '.test', '.invalid', '.onion', '.arpa', '.lan', '.home', '.corp'].some(suffix => host.endsWith(suffix)))
    throw new Error('Use one public HTTPS origin without a path.');
  return url.origin;
}

function publicRepository(value) {
  if (typeof value !== 'string' || value.length > 140 || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9_.-]{1,100}$/.test(value) ||
      ['.', '..'].includes(value.split('/')[1])) throw new Error('Supply --repository owner/repo for one public GitHub repository.');
  return value;
}

async function regularFile(file, limit) {
  const absolute = path.resolve(file);
  let ancestor = path.parse(absolute).root;
  for (const part of absolute.slice(ancestor.length).split(path.sep)) {
    ancestor = path.join(ancestor, part);
    if ((await lstat(ancestor)).isSymbolicLink()) throw new Error('Select a regular local file without symlink ancestors.');
  }
  const stat = await lstat(absolute);
  if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw new Error(`Selected file must contain between 1 and ${limit} bytes.`);
  return { file: absolute, size: stat.size };
}

async function readSchema(file) {
  const source = await regularFile(file, 256 * 1024);
  const content = new TextDecoder('utf-8', { fatal: true }).decode(await readFile(source.file));
  let schema;
  try { schema = JSON.parse(content); } catch { throw new Error('API assessments require OpenAPI JSON.'); }
  if (!/^3\.[01]\./.test(schema?.openapi || '') || !schema.paths || typeof schema.paths !== 'object' || Array.isArray(schema.paths))
    throw new Error('API assessments require an OpenAPI 3.0 or 3.1 JSON document.');
  let operations = 0;
  const walk = value => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if ((key === '$ref' && (typeof child !== 'string' || !child.startsWith('#/'))) ||
          ['callbacks', 'webhooks', 'externalValue', 'externalDocs'].includes(key))
        throw new Error('Remote references, callbacks, webhooks and external examples are unsupported.');
      walk(child);
    }
  };
  walk(schema);
  for (const [route, item] of Object.entries(schema.paths)) {
    if (!route.startsWith('/') || route.startsWith('//') || route.includes('\\') || /[\r\n?#]/.test(route)) throw new Error('Invalid API path.');
    for (const method of Object.keys(item || {})) if (/^(get|put|post|delete|patch|options|head|trace)$/.test(method)) operations++;
  }
  if (operations < 1 || operations > 25) throw new Error('API assessments support 1 to 25 operations.');
  return { files: [{ path: 'openapi.json', content }], operations, bytes: Buffer.byteLength(content), omitted: [] };
}

async function readJson(response, label, limit = 1_500_000) {
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}; no clean result is implied.`);
  if (!response.body) throw new Error(`${label} returned no JSON.`);
  const reader = response.body.getReader(), parts = []; let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      if ((bytes += value.byteLength) > limit) { await reader.cancel(); throw new Error(`${label} response exceeds the limit.`); }
      parts.push(value);
    }
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
  } catch (error) {
    if (error.message.includes('exceeds the limit')) throw error;
    throw new Error(`${label} returned invalid JSON.`);
  } finally { reader.releaseLock(); }
}

function safeReport(job, secrets) {
  const text = (value, limit = 1500) => {
    let result = typeof value === 'string' ? value.slice(0, limit) : '';
    for (const secret of secrets.filter(Boolean)) result = result.replaceAll(secret, '[redacted]');
    return result;
  };
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const safeUrl = value => {
    try {
      const url = new URL(value);
      targetOrigin(url.origin);
      if (url.username || url.password || url.href.length > 2048) return null;
      return text(url.origin + url.pathname, 2048);
    } catch { return null; }
  };
  const observations = Array.isArray(job.observations) ? job.observations.slice(0, 200).flatMap(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return [];
    if ((item.kind === 'endpoint' && item.tool === 'katana') || (item.kind === 'service' && item.tool === 'httpx')) {
      const url = safeUrl(item.url);
      if (!url || item.method !== 'GET') return [];
      return [{ kind: item.kind, tool: item.tool, url, method: 'GET',
        statusCode: Number.isInteger(item.statusCode) && item.statusCode >= 100 && item.statusCode <= 599 ? item.statusCode : null,
        ...(item.kind === 'service' ? { contentType: typeof item.contentType === 'string' ? text(item.contentType, 120) : null,
          contentLength: count(item.contentLength), technologies: Array.isArray(item.technologies) ? item.technologies
            .filter(value => typeof value === 'string').slice(0, 20).map(value => text(value, 80)) : [] } : {}) }];
    }
    if (item.kind === 'supply-chain-score' && item.tool === 'openssf-scorecard' && item.source === 'published-scorecard') {
      let repository;
      try { repository = publicRepository(item.repository); } catch { return []; }
      if (!Number.isFinite(item.score) || item.score < 0 || item.score > 10 ||
          typeof item.assessedAt !== 'string' || item.assessedAt.length > 40 || !Number.isFinite(Date.parse(item.assessedAt)) ||
          !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(item.commit || '') || !Array.isArray(item.checks)) return [];
      return [{ kind: item.kind, tool: item.tool, repository, score: item.score, assessedAt: new Date(item.assessedAt).toISOString(),
        commit: item.commit, source: 'published-scorecard', checks: item.checks.slice(0, 50)
          .filter(check => check && typeof check.name === 'string' && Number.isFinite(check.score) && check.score >= -1 && check.score <= 10)
          .map(check => ({ name: text(check.name, 100), score: check.score })) }];
    }
    return [];
  }) : [];
  return {
    id: job.id, status: job.status, confirmedVulnerabilities: 0,
    selectedTools: Array.isArray(job.selectedTools) ? job.selectedTools.filter(value => IDS.has(value)) : [],
    error: text(job.error), reportExpired: job.reportExpired === true, observations,
    coverage: { scope: text(job.coverage?.scope), confirmedVulnerabilities: 0 },
    metering: job.metering ? { state: text(job.metering.state, 40), chargeMicros: count(job.metering.chargeMicros), currency: 'usd' } : null,
    tools: Array.isArray(job.tools) ? job.tools.slice(0, 8).map(tool => ({ name: text(tool.name, 80), version: text(tool.version, 80),
      status: text(tool.status, 30), durationMs: count(tool.durationMs), error: text(tool.error) })) : [],
    findings: Array.isArray(job.findings) ? job.findings.slice(0, 1000).map(item => ({ id: text(item.id, 120), tool: text(item.tool, 80),
      ruleId: text(item.ruleId, 150), severity: text(item.severity, 20), file: text(item.file, 240),
      line: count(item.line), title: text(item.title, 500), remediation: text(item.remediation) })) : []
  };
}

async function privateDirectory(output) {
  const directory = output ? path.resolve(output) : await mkdtemp(path.join(os.tmpdir(), 'purple-assessment-'));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077))
    throw new Error('Use a private output directory with mode 0700.');
  return directory;
}

/** Preview by default. Only run:true may submit source, artifacts or credentials. */
export async function hostedAssessment({ tool, project = process.cwd(), schema, artifact, format, target, repository, accountId, tokenEnv,
  preview = false, run = false, challenge = false, verifyTarget, scanId, output,
  confirmActiveTesting = false, confirmLiveVerification = false,
  api = process.env.PURPLE_API_URL || 'https://app.purpleteam.sh', key = process.env.PURPLE_SCAN_KEY, env = process.env,
  fetchImpl = fetch, collectSourceImpl = collectSource, onQuote, pollMs = 5000, timeoutMs = 14 * 60000,
  idempotencyKey = randomUUID(), onSubmissionPrepared } = {}) {
  const base = apiOrigin(api);
  if (challenge && verifyTarget || scanId && (challenge || verifyTarget) || preview && run) throw new Error('Choose one assessment, challenge, verification, or resume mode.');
  if (scanId && !JOB_ID.test(scanId)) throw new Error('Invalid scan ID.');
  if (!scanId && !challenge && !verifyTarget && !IDS.has(tool)) throw new Error('Select one supported assessment tool.');
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(idempotencyKey)) throw new Error('Invalid idempotency key.');
  const offline = preview || (!run && !challenge && !verifyTarget && !scanId);
  const headers = { authorization: `Bearer ${key}`, 'content-type': 'application/json' };
  const request = async (route, body, label = 'Assessment request') => readJson(await fetchImpl(new URL(route, base), {
    method: body ? 'POST' : 'GET', headers, ...(body ? { body: JSON.stringify(body) } : {}),
    redirect: 'error', signal: AbortSignal.timeout(60000)
  }), label);

  if (challenge || verifyTarget) {
    let proof;
    if (verifyTarget) {
      const file = await regularFile(verifyTarget, 8192);
      try { proof = JSON.parse(await readFile(file.file, 'utf8')); } catch { throw new Error('Supply the saved target-challenge.json file.'); }
      target = targetOrigin(proof.origin);
    } else target = targetOrigin(target);
    if (preview) return { mode: challenge ? 'challenge-preview' : 'verification-preview', destination: base.origin, target, networkRequests: 0 };
    if (!key) throw new Error('Set PURPLE_SCAN_KEY from the Billing & scan keys page.');
    const result = await request(challenge ? '/v1/targets/challenge' : '/v1/targets/verify', challenge ? { target } : { challenge: proof }, 'Target ownership');
    if (targetOrigin(result.origin) !== target || !Number.isSafeInteger(result.expiresAt)) throw new Error('Target ownership returned an invalid response.');
    if (!challenge) return { origin: target, verifiedAt: result.verifiedAt, expiresAt: result.expiresAt };
    if (result.recordName !== `_purple-scan.${new URL(target).hostname}` || !/^purple-scan-verification=[A-Za-z0-9_-]{32}$/.test(result.recordValue || '') ||
        !/^[a-f0-9]{64}$/.test(result.signature || '') || !/^[A-Za-z0-9_-]{32}$/.test(result.token || ''))
      throw new Error('Target ownership returned an invalid challenge.');
    const directory = await privateDirectory(output), file = path.join(directory, 'target-challenge.json');
    await writeFile(file, JSON.stringify({ origin: target, recordName: result.recordName, recordValue: result.recordValue,
      token: result.token, signature: result.signature, expiresAt: result.expiresAt }, null, 2), { mode: 0o600 });
    return { origin: target, recordName: result.recordName, recordValue: result.recordValue, expiresAt: result.expiresAt, challengeFile: file };
  }

  let source = null, mobile = null, apiToken;
  const body = { tools: [tool] };
  if (!scanId) {
    if (TARGET_TOOLS.has(tool)) body.target = targetOrigin(target);
    if (tool === 'openssf-scorecard') body.repository = publicRepository(repository);
    if (API_TOOLS.has(tool)) {
      if (!offline && confirmActiveTesting !== true) throw new Error('Use --confirm-active-testing for a staging API you authorize testing.');
      source = await readSchema(schema);
      body.files = source.files; body.confirmActiveTesting = true;
    } else if (tool === 'checkov' || tool === 'trufflehog-verified') {
      if (tool === 'trufflehog-verified' && !offline && confirmLiveVerification !== true)
        throw new Error('Use --confirm-live-verification to permit live checks of credentials in the selected files.');
      source = await collectSourceImpl(path.resolve(project));
      body.files = source.files;
      if (tool === 'trufflehog-verified') body.confirmLiveVerification = true;
    } else if (tool === 'prowler-cloudflare') {
      if (!/^[a-f0-9]{32}$/.test(accountId || '') || !/^[A-Za-z_][A-Za-z0-9_]{0,100}$/.test(tokenEnv || '') || tokenEnv === 'PURPLE_SCAN_KEY')
        throw new Error('Supply --account-id HEX and --token-env NAME for a separate read-only Cloudflare token.');
      body.accountId = accountId;
      if (!offline) {
        apiToken = env[tokenEnv];
        if (typeof apiToken !== 'string' || !/^[A-Za-z0-9_-]{20,200}$/.test(apiToken) || apiToken === key) throw new Error('The selected token environment variable must contain a separate Cloudflare API token.');
      }
    } else if (tool === 'mobsf-static') {
      if (!['apk', 'ipa'].includes(format)) throw new Error('Supply --format apk or ipa.');
      mobile = await regularFile(artifact, MOBILE_LIMIT);
      const hash = createHash('sha256');
      for await (const chunk of createReadStream(mobile.file)) hash.update(chunk);
      mobile.sha256 = hash.digest('hex'); body.format = format;
    }
    if (source && (source.files.length > 500 || source.bytes > SOURCE_LIMIT || source.files.some(file => Buffer.byteLength(file.content) > 256 * 1024)))
      throw new Error('Assessment source exceeds the file or byte limit.');
  }
  if (key && body.repository?.includes(key)) throw new Error('The scan key appears in the selected repository; no request was sent.');
  if (offline) return { mode: 'preview', destination: base.origin, tool,
    ...(body.target ? { target: body.target, ownershipRequired: true } : {}),
    ...(body.repository ? { repository: body.repository, source: 'published-scorecard', publicRepositoryOnly: true } : {}),
    ...(source ? { upload: source.files.map(file => ({ path: file.path, bytes: Buffer.byteLength(file.content) })), omitted: source.omitted, bytes: source.bytes, ...(source.operations ? { operations: source.operations } : {}) } : {}),
    ...(mobile ? { format, bytes: mobile.size, sha256: mobile.sha256 } : {}),
    ...(accountId ? { accountId, tokenEnvironmentVariable: tokenEnv, tokenValueIncluded: false } : {}),
    budgetSeconds: tool === 'mobsf-static' ? 480 : 120, maxConnections: 200, networkRequests: 0,
    requiredConfirmation: API_TOOLS.has(tool) ? '--confirm-active-testing' : tool === 'trufflehog-verified' ? '--confirm-live-verification' : null };
  if (!key) throw new Error('Set PURPLE_SCAN_KEY from the Billing & scan keys page.');
  if (source?.files.some(file => file.content.includes(key))) throw new Error('The scan key appears in selected source; no files were uploaded.');
  const directory = await privateDirectory(output);
  let quote;
  if (!scanId) {
    const catalog = await request('/v1/tools', null, 'Assessment catalog');
    if (!Array.isArray(catalog.tools) || !catalog.tools.some(item => item.id === tool && item.billingUnit === 'bounded_assessment' && !['unavailable', 'disabled'].includes(item.availability)))
      throw new Error('The service does not advertise this bounded assessment; no input was uploaded.');
    const inputBytes = mobile ? mobile.size : Math.min(SOURCE_LIMIT, Math.max(1, Buffer.byteLength(JSON.stringify(body)) + 1024));
    quote = await request('/v1/quotes', { tools: [tool], inputBytes, fileCount: 1 }, 'Assessment quote');
    const usage = await request('/v1/usage', null, 'Scanner credit');
    if (quote.currency !== 'usd' || typeof quote.billable !== 'boolean' || quote.billable !== usage.enabled ||
        !Number.isSafeInteger(quote.maximumMicros) || quote.maximumMicros < 0 ||
        JSON.stringify(quote.toolIds) !== JSON.stringify([tool]) || !Array.isArray(quote.prices) || quote.prices.length !== 1 ||
        quote.prices[0].tool !== tool || quote.prices[0].unit !== 'bounded_assessment' || quote.prices[0].maximumMicros !== quote.maximumMicros ||
        (quote.billable ? quote.maximumMicros === 0 : quote.maximumMicros !== 0) ||
        !Number.isSafeInteger(usage.availableMicros) || usage.availableMicros < 0)
      throw new Error('Assessment quote or credit did not match the request; no input was uploaded.');
    const price = { billable: quote.billable, maximumMicros: quote.maximumMicros, availableMicros: usage.availableMicros, prices: quote.prices };
    if (onQuote) await onQuote(price);
    if (usage.blocked || usage.availableMicros < quote.maximumMicros) throw new Error('Add scanner credit or resolve the payment review before uploading.');
    if (apiToken) body.apiToken = apiToken;
    if (mobile) {
      const upload = await readJson(await fetchImpl(new URL('/v1/artifacts', base), { method: 'POST', headers: {
        authorization: `Bearer ${key}`, 'content-type': 'application/octet-stream', 'content-length': String(mobile.size),
        'x-purple-artifact-kind': 'mobile-app', 'x-content-sha256': mobile.sha256
      }, body: createReadStream(mobile.file), duplex: 'half', redirect: 'error', signal: AbortSignal.timeout(5 * 60000) }), 'Artifact upload');
      if (!JOB_ID.test(upload.id || '')) throw new Error('Artifact upload returned an invalid ID.');
      body.artifactId = upload.id;
    }
    body.maxChargeMicros = quote.maximumMicros;
    if (onSubmissionPrepared) await onSubmissionPrepared({ input: body, inputBytes, fileCount: 1, idempotencyKey });
  }
  let job = scanId ? await request(`/v1/scans/${scanId}`, null, 'Assessment retrieval') :
    await readJson(await fetchImpl(new URL('/v1/scans', base), { method: 'POST', headers: { ...headers, 'idempotency-key': idempotencyKey },
      body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(60000) }), 'Assessment creation');
  const validate = () => {
    if (!JOB_ID.test(job.id || '') || !STATES.has(job.status) || scanId && job.id !== scanId ||
        !scanId && Array.isArray(job.selectedTools) && JSON.stringify(job.selectedTools) !== JSON.stringify([tool]))
      throw new Error('Assessment returned invalid job metadata.');
  };
  validate();
  const id = job.id, secrets = [key, apiToken];
  const json = path.join(directory, 'assessment.json'), report = path.join(directory, 'assessment.md');
  const save = async () => writeFile(json, JSON.stringify({ ...safeReport(job, secrets), clientCoverage: {
    omitted: source?.omitted ?? null, scope: scanId ? 'Resumed job. Original local upload coverage is unknown.' :
      mobile ? 'One selected mobile artifact; static analysis only.' : source ? 'Selected tracked source or one OpenAPI JSON document; no Git history.' :
        body.repository ? 'Published Scorecard snapshot for one selected public GitHub repository; no fresh or private-repository scan.' : 'One selected verified target or cloud account.',
    ...(mobile ? { artifactBytes: mobile.size, artifactSha256: mobile.sha256 } : {})
  } }, null, 2), { mode: 0o600 });
  await save();
  const deadline = Date.now() + timeoutMs;
  while (['queued', 'starting', 'running'].includes(job.status)) {
    if (Date.now() >= deadline) throw new Error(`Polling deadline reached. Resume with --scan-id ${id}. Metadata is saved in ${directory}.`);
    await new Promise(resolve => setTimeout(resolve, pollMs));
    job = await request(`/v1/scans/${id}`, null, 'Assessment polling');
    if (job.id !== id) throw new Error('Assessment polling returned a different job.');
    validate(); await save();
  }
  if (job.reportExpired) throw new Error('Assessment report expired; usage metadata is not a security result.');
  const clean = safeReport(job, secrets);
  const findings = clean.findings.map(item => `- **${item.severity}** ${item.title} (${item.tool}, ${item.ruleId})\n  ${item.remediation}`).join('\n');
  const observations = clean.observations.map(item => item.kind === 'supply-chain-score'
    ? `- Published Scorecard: ${item.repository}, ${item.score}/10, assessed ${item.assessedAt}, commit ${item.commit}.`
    : `- ${item.kind === 'endpoint' ? 'Endpoint' : 'Service'}: ${item.method} ${item.url}${item.statusCode ? ` (HTTP ${item.statusCode})` : ''}`).join('\n');
  await writeFile(report, `# Purple hosted assessment\n\nStatus: ${clean.status}\nJob: ${id}\n\n${findings || 'No vulnerability findings returned. Check completion and coverage before drawing conclusions.'}\n\n${observations ? `Observations (not vulnerability findings):\n${observations}\n\n` : ''}${clean.coverage.scope || clean.error || 'Coverage details unavailable.'}\n\nFindings are candidates for review, not confirmed vulnerabilities. Discovery and supply-chain observations are not vulnerability findings. This report claims no reproduced exploit or verified fix. See assessment.json for client omissions.\n`, { mode: 0o600 });
  return { id, status: clean.status, findings: clean.findings.length, observations: clean.observations.length, report, json };
}

async function main() {
  if (process.argv.includes('--help')) {
    console.log('Usage: node hosted-assessment.mjs --tool ID [--project DIR | --schema FILE | --artifact FILE --format apk|ipa | --repository OWNER/REPO | --account-id HEX --token-env NAME] [--target HTTPS_ORIGIN] [--preview | --run] [--confirm-active-testing | --confirm-live-verification] [--output PRIVATE_DIR] [--api HTTPS_ORIGIN]\nTarget ownership: --target HTTPS_ORIGIN --challenge; publish the returned DNS TXT record, then --verify-target CHALLENGE_FILE. Resume: --scan-id HEX. Set PURPLE_SCAN_KEY in the environment. No --run means offline preview. IDs: ' + [...IDS].join(', '));
    return;
  }
  const args = process.argv.slice(2), options = {};
  const values = { '--tool': 'tool', '--project': 'project', '--schema': 'schema', '--artifact': 'artifact', '--format': 'format',
    '--target': 'target', '--repository': 'repository', '--account-id': 'accountId', '--token-env': 'tokenEnv', '--verify-target': 'verifyTarget', '--scan-id': 'scanId', '--output': 'output', '--api': 'api' };
  const flags = { '--preview': 'preview', '--run': 'run', '--challenge': 'challenge', '--confirm-active-testing': 'confirmActiveTesting', '--confirm-live-verification': 'confirmLiveVerification' };
  for (let i = 0; i < args.length; i++) {
    if (Object.hasOwn(values, args[i])) {
      const key = values[args[i]], value = args[++i];
      if (!value || value.startsWith('--') || Object.hasOwn(options, key)) throw new Error('Provide each option once with its required value.');
      options[key] = value;
    } else if (Object.hasOwn(flags, args[i])) options[flags[args[i]]] = true;
    else throw new Error('Unknown assessment option; use --help.');
  }
  const offline = options.preview || (!options.run && !options.challenge && !options.verifyTarget && !options.scanId);
  const update = await updateBeforeRun('purple', import.meta.url, { preview: offline });
  if (update.stop) return;
  const result = await hostedAssessment({ ...options, onQuote: price => console.log(scannerPriceMessage(price)) });
  console.log(JSON.stringify(result, null, 2));
  if (result.status && result.status !== 'completed') process.exitCode = 2;
}

if (typeof OFFENSE_CLI_EMBEDDED === 'undefined' && process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
