#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { lstat, readFile, mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { updateBeforeRun } from './update.mjs';

const DEFAULT_TOOLS = ['opengrep', 'trivy-vuln', 'gitleaks'];

export function scannerPriceMessage({ maximumMicros, availableMicros, billable }) {
  const dollars = micros => `$${(micros / 1_000_000).toFixed(2)}`;
  return billable ? `Maximum scanner charge: ${dollars(maximumMicros)}. Available scanner credit: ${dollars(availableMicros)}.` :
    'Maximum scanner charge: $0.00 (free pilot).';
}

export async function quoteHostedScan({ base, key, tools, inputBytes, fileCount, fetchImpl = fetch, onQuote }) {
  const headers = { authorization: `Bearer ${key}`, 'content-type': 'application/json' };
  const request = async (route, init, label) => {
    const response = await fetchImpl(new URL(route, base), { ...init, headers, redirect: 'error', signal: AbortSignal.timeout(60000) });
    if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}; no source was uploaded.`);
    return response.json();
  };
  const [quote, usage] = await Promise.all([
    request('/v1/quotes', { method: 'POST', body: JSON.stringify({ tools, inputBytes, fileCount }) }, 'Scanner quote'),
    request('/v1/usage', { method: 'GET' }, 'Scanner balance')
  ]);
  if (typeof quote?.billable !== 'boolean' || !Number.isSafeInteger(quote.maximumMicros) || quote.maximumMicros < 0 ||
      typeof usage?.enabled !== 'boolean' || quote.billable !== usage.enabled ||
      (quote.billable && (quote.maximumMicros === 0 || !Number.isSafeInteger(usage.availableMicros) || usage.availableMicros < 0)) ||
      (!quote.billable && quote.maximumMicros !== 0))
    throw new Error('Scanner quote or balance was invalid; no source was uploaded.');
  const price = { billable: quote.billable, maximumMicros: quote.maximumMicros,
    availableMicros: Number.isSafeInteger(usage.availableMicros) && usage.availableMicros >= 0 ? usage.availableMicros : 0,
    prices: Array.isArray(quote.prices) ? quote.prices : [] };
  if (onQuote) await onQuote(price);
  if (price.billable && price.availableMicros < price.maximumMicros)
    throw new Error(`Add scanner credit in Purple before uploading. ${scannerPriceMessage(price)}`);
  return price;
}

export async function collectSource(directory) {
  const names = execFileSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', 'ls-files', '--cached', '-z'],
    { cwd: directory, maxBuffer: 4 * 1024 * 1024, timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_OPTIONAL_LOCKS: '0' } }).toString('utf8').split('\0').filter(Boolean);
  const files = [], omitted = []; let bytes = 0;
  for (const name of [...new Set(names)]) {
    if (name.split('/').some(part => ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.agents', '.claude', '.pi'].includes(part))) { omitted.push({ path: name, reason: 'Generated output, dependency directory or agent configuration' }); continue; }
    const target = path.resolve(directory, name);
    if (!target.startsWith(`${path.resolve(directory)}${path.sep}`)) throw new Error('Tracked path escapes the scan directory.');
    // Check every ancestor: a tracked directory replaced by a symlink must not expose outside files.
    let current = path.resolve(directory);
    for (const part of name.split('/')) {
      current = path.join(current, part);
      const info = await lstat(current).catch(() => null);
      if (!info || info.isSymbolicLink()) { current = null; break; }
    }
    if (!current || !(await lstat(target)).isFile()) { omitted.push({ path: name, reason: 'Missing, symlink or non-file' }); continue; }
    const info = await lstat(target);
    if (info.size > 256 * 1024) throw new Error(`${name} exceeds 256 KB. Narrow the scan directory; it was not uploaded.`);
    const buffer = await readFile(target);
    if (buffer.includes(0)) { omitted.push({ path: name, reason: 'Binary file' }); continue; }
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(buffer); }
    catch { omitted.push({ path: name, reason: 'Non-UTF-8 file' }); continue; }
    bytes += buffer.byteLength;
    if (bytes > 4 * 1024 * 1024 || files.length >= 500) throw new Error('Scan exceeds 500 text files or 4 MB. Narrow the scan directory; no source was uploaded.');
    files.push({ path: name, content });
  }
  if (!files.length) throw new Error('No tracked UTF-8 text files were found. Commit or stage the intended files first.');
  return { files, omitted, bytes };
}

export async function hostedScan(directory, { api = process.env.PURPLE_API_URL || 'https://app.purpleteam.sh', key = process.env.PURPLE_SCAN_KEY,
  preview = false, scanId, output, tools, onQuote,
  timeoutMs = 14 * 60000, fetchImpl = fetch, pollMs = 5000, collectSourceImpl = collectSource } = {}) {
  const base = new URL(api);
  if (base.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(base.hostname)) throw new Error('Hosted scans require HTTPS.');
  if (tools !== undefined && (!Array.isArray(tools) || !tools.length || tools.some(tool => typeof tool !== 'string' || !/^[a-z][a-z0-9-]*$/.test(tool)) || new Set(tools).size !== tools.length)) {
    throw new Error('Select one or more unique tool IDs with --tool.');
  }
  const source = scanId ? null : await collectSourceImpl(path.resolve(directory));
  if (preview) return { upload: source.files.map(file => ({ path: file.path, bytes: Buffer.byteLength(file.content) })), bytes: source.bytes, omitted: source.omitted, destination: base.origin, tools: tools || DEFAULT_TOOLS };
  if (!key) throw new Error('Set PURPLE_SCAN_KEY to a workspace scan key from Purple’s dashboard.');
  if (source?.files.some(file => file.content.includes(key))) throw new Error('Your scan key appears in tracked source. Remove it from the upload before scanning.');
  const quote = scanId ? null : await quoteHostedScan({ base, key, tools: tools || DEFAULT_TOOLS,
    inputBytes: source.bytes, fileCount: source.files.length, fetchImpl, onQuote });
  const target = output ? path.resolve(output) : await mkdtemp(path.join(os.tmpdir(), 'purple-hosted-scan-'));
  await mkdir(target, { recursive: true, mode: 0o700 });
  async function request(route, body, idempotency) {
    const response = await fetchImpl(new URL(`/v1/scans${route}`, base), { method: body ? 'POST' : 'GET',
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', ...(idempotency ? { 'idempotency-key': idempotency } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(60000), redirect: 'error' });
    if (!response.ok) throw new Error(`Hosted scan returned HTTP ${response.status}. Check the key, quotas and service availability; no clean result is implied.`);
    return response.json();
  }
  let job = scanId ? await request(`/${scanId}`) : await request('', { files: source.files,
    ...(tools ? { tools } : {}), maxChargeMicros: quote.maximumMicros }, randomUUID());
  const save = async () => writeFile(path.join(target, 'scan.json'), JSON.stringify({ ...job, clientCoverage: { omitted: source?.omitted ?? null,
    source: source ? 'Tracked files at upload time, including current working changes; no Git history or untracked files.' : 'Resumed job. Consult the original upload report for client omissions; they are unknown in this resumed report.' } }, null, 2), { mode: 0o600 });
  await save();
  const deadline = Date.now() + timeoutMs;
  while (['queued', 'starting', 'running'].includes(job.status)) {
    if (Date.now() >= deadline) throw new Error(`Polling deadline reached. Resume with --scan-id ${job.id}. Job metadata is saved in ${target}.`);
    await new Promise(resolve => setTimeout(resolve, pollMs));
    job = await request(`/${job.id}`); await save();
  }
  if (job.reportExpired) throw new Error('This scan report has expired. Run a new scan; usage metadata alone is not a security result.');
  const findings = (job.findings || []).map(item => `- **${item.severity}** ${item.title} — ${item.file}${item.line ? `:${item.line}` : ''} (${item.tool}, ${item.ruleId})\n  ${item.remediation}`).join('\n');
  await writeFile(path.join(target, 'scan.md'), `# Purple hosted security scan\n\nStatus: ${job.status}\nScan: ${job.id}\nSelected tools: ${(job.selectedTools || tools || ['opengrep', 'trivy-vuln', 'gitleaks']).join(', ')}\n\n${findings || 'No findings returned. Check completion and coverage before drawing conclusions.'}\n\n## Coverage\n\n${job.coverage?.scope || job.error || 'Scanner coverage unavailable.'}\n\n${(job.tools || []).map(tool => `${tool.name} ${tool.version || ''}: ${tool.status}${tool.error ? ` — ${tool.error}` : ''}`).join('\n\n')}\n\nClient omitted files: ${source ? source.omitted.length : 'unknown for resumed job'}. See scan.json. Findings require review and do not establish exploitability.\n`, { mode: 0o600 });
  return { id: job.id, status: job.status, findings: job.findings?.length || 0, report: path.join(target, 'scan.md'), json: path.join(target, 'scan.json') };
}

async function main() {
  if (process.argv.includes('--help')) {
    console.log('Usage: node hosted-scan.mjs [directory] [--tool ID ...] [--preview] [--scan-id ID] [--output directory]\nTool IDs: opengrep, semgrep, osv-scanner, zizmor, trivy-vuln, gitleaks, trivy-config, trivy-sbom, spectral-owasp. Default: opengrep, trivy-vuln, gitleaks. Use source-scan.mjs for local Opengrep/Zizmor without source upload, api-test.mjs for sandbox API tests, and hosted-artifact-scan.mjs for binary artifacts. Normal runs check installed skill updates first. Help and previews stay offline.');
    return;
  }
  const args = process.argv.slice(2), directory = args[0] && !args[0].startsWith('--') ? args.shift() : process.cwd();
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--preview') options.preview = true;
    else if (args[i] === '--scan-id') options.scanId = args[++i];
    else if (args[i] === '--output') options.output = args[++i];
    else if (args[i] === '--tool') (options.tools ||= []).push(args[++i]);
    else throw new Error(`Unknown option ${args[i]}`);
  }
  const update = await updateBeforeRun('purple', import.meta.url, { preview: options.preview });
  if (update.stop) return;
  const result = await hostedScan(directory, { ...options, onQuote: quote => console.log(scannerPriceMessage(quote)) });
  console.log(JSON.stringify(result, null, 2));
  if (!options.preview && result.status !== 'completed') process.exitCode = 2;
}

if (typeof OFFENSE_CLI_EMBEDDED === 'undefined' && process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
