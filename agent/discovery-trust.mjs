import { webScanOrigin, webScanUrlInScope } from '../server/web-scan-target.js';

const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const MAX_OBSERVATIONS = 500;
const SCORECARD_MAX_AGE = 7 * 86400000;
const SCORECARD_CHECKS = new Set(['Binary-Artifacts', 'Branch-Protection', 'CI-Tests', 'CII-Best-Practices',
  'Code-Review', 'Contributors', 'Dangerous-Workflow', 'Dependency-Update-Tool', 'Fuzzing', 'License',
  'Maintained', 'Packaging', 'Pinned-Dependencies', 'SAST', 'Security-Policy', 'Signed-Releases',
  'Token-Permissions', 'Vulnerabilities', 'Webhooks']);
export const SCORECARD_API_ORIGIN = 'https://api.scorecard.dev';

export function publicScorecardRepository(value) {
  if (typeof value !== 'string' || value.length > 140 ||
      !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,38})\/[a-zA-Z0-9_.-]{1,100}$/.test(value) ||
      ['.', '..'].includes(value.split('/')[1]) || value.endsWith('.git'))
    throw new Error('Supply a public GitHub repository as owner/repository.');
  return value;
}

function rows(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_REPORT_BYTES) throw new Error('Discovery report exceeds its bounds.');
  const lines = text.split('\n').filter(line => line.trim());
  if (!lines.length || lines.length > 5000) throw new Error('Discovery returned no bounded observations.');
  return lines.map(line => JSON.parse(line));
}

function observedUrl(value, target) {
  if (typeof value !== 'string' || value.length > 2048 || !webScanUrlInScope(value, target))
    throw new Error('Discovery returned an out-of-scope observation.');
  const url = new URL(value);
  // Queries and fragments can carry user identifiers, access codes or tokens.
  url.search = ''; url.hash = '';
  return url.href;
}

function statusCode(value) {
  if (!Number.isInteger(value) || value < 100 || value > 599) throw new Error('Discovery returned an invalid response status.');
  return value;
}

export function normalizeKatanaReport(text, target, { maxRequests = 50 } = {}) {
  webScanOrigin(target);
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 50) throw new Error('Invalid crawl budget.');
  const observations = new Map(); let visited = 0, errors = 0;
  for (const row of rows(text)) {
    const request = row?.request, response = row?.response;
    if (!request || request.method !== 'GET') throw new Error('Discovery returned an unsupported request method.');
    const url = observedUrl(request.endpoint, target);
    let code = null;
    if (response?.status_code !== undefined) { code = statusCode(response.status_code); visited++; }
    if (row.error && !/^max(?:imum)? depth(?: reached| exceeded)?$/i.test(row.error)) errors++;
    const existing = observations.get(url);
    if (!existing || existing.statusCode === null && code !== null)
      observations.set(url, { kind: 'endpoint', tool: 'katana', url, method: 'GET', statusCode: code });
  }
  if (!visited || visited > maxRequests) throw new Error('Crawl did not establish bounded response coverage.');
  return { findings: [], observations: [...observations.values()].slice(0, MAX_OBSERVATIONS),
    partial: errors > 0 || observations.size > MAX_OBSERVATIONS || visited >= maxRequests,
    coverage: { visitedPages: visited, discoveredEndpoints: observations.size, maxRequests, maxDepth: 2,
      budgetReached: visited >= maxRequests, queryValuesRetained: false,
      scope: 'GET-only HTML and JavaScript endpoint discovery on one verified HTTPS origin, at most 50 pages and two link levels. Queries, fragments, raw headers and bodies are omitted. No browser, form submission, authentication, complete inventory or vulnerability confirmation.' } };
}

export function normalizeHttpxReport(text, target) {
  const parsed = rows(text);
  if (parsed.length !== 1) throw new Error('Service inspection returned an unexpected number of responses.');
  const row = parsed[0];
  if (!row || row.failed === true || row.error || row.method !== undefined && row.method !== 'GET')
    throw new Error('Service inspection did not obtain a valid response.');
  const url = observedUrl(row.url, target);
  if (url !== new URL(webScanOrigin(target)).href) throw new Error('Service inspection returned a non-root response.');
  const contentType = typeof row.content_type === 'string' ? row.content_type.split(';')[0].trim().toLowerCase() : null;
  if (contentType !== null && !/^[a-z0-9!#$&^_.+-]{1,50}\/[a-z0-9!#$&^_.+-]{1,50}$/.test(contentType))
    throw new Error('Service inspection returned an invalid content type.');
  if (row.content_length !== undefined && (!Number.isSafeInteger(row.content_length) || row.content_length < 0 || row.content_length > 1e12))
    throw new Error('Service inspection returned an invalid content length.');
  const technologies = row.tech ?? [];
  if (!Array.isArray(technologies) || technologies.length > 30 ||
      technologies.some(value => typeof value !== 'string' || !/^[a-zA-Z0-9 .()+#/_:-]{1,80}$/.test(value)))
    throw new Error('Service inspection returned invalid technology observations.');
  return { findings: [], observations: [{ kind: 'service', tool: 'httpx', url, method: 'GET',
    statusCode: statusCode(row.status_code), contentType, contentLength: row.content_length ?? null,
    technologies: [...new Set(technologies)].sort() }], partial: false,
  coverage: { visitedPages: 1, maxRequests: 1, queryValuesRetained: false,
    scope: 'One unauthenticated GET response from the verified HTTPS origin root. Redirects and HTTP fallback are disabled. No port scan, browser, sensitive headers, page title, response body or vulnerability confirmation.' } };
}

export function normalizeScorecardReport(raw, repository, { now = Date.now } = {}) {
  repository = publicScorecardRepository(repository);
  const assessed = typeof raw?.date === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(raw.date) ? Date.parse(raw.date) : NaN;
  const checkedAt = now();
  if (!raw || raw.repo?.name?.toLowerCase() !== `github.com/${repository}`.toLowerCase() ||
      typeof raw.repo.commit !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(raw.repo.commit) ||
      !Number.isFinite(assessed) || assessed > checkedAt + 5 * 60_000 ||
      !Number.isFinite(raw.score) || raw.score < 0 || raw.score > 10 ||
      !Array.isArray(raw.checks) || raw.checks.length < 1 || raw.checks.length > 40)
    throw new Error('Published Scorecard did not return a valid repository assessment.');
  const checks = [], seen = new Set();
  for (const check of raw.checks) {
    if (!SCORECARD_CHECKS.has(check?.name) || seen.has(check.name) || !Number.isInteger(check.score) || check.score < -1 || check.score > 10)
      throw new Error('Published Scorecard returned an unsupported check.');
    seen.add(check.name); checks.push({ name: check.name, score: check.score });
  }
  const stale = checkedAt - assessed > SCORECARD_MAX_AGE;
  const incompleteChecks = checks.filter(check => check.score === -1).length;
  return { findings: [], observations: [{ kind: 'supply-chain-score', tool: 'openssf-scorecard', repository,
    source: 'published-scorecard', score: raw.score, assessedAt: new Date(assessed).toISOString(),
    commit: raw.repo.commit, checks }], partial: stale || incompleteChecks > 0,
  coverage: { source: 'published-scorecard', publicRepositoryOnly: true, freshScan: false,
    assessedAt: new Date(assessed).toISOString(), assessedCommit: raw.repo.commit,
    stale, freshnessLimitDays: 7, assessedChecks: checks.length, incompleteChecks,
    scope: 'Published OpenSSF Scorecard snapshot for one public GitHub repository, with its recorded commit, date and check scores. This does not run a fresh scan or access private repositories. Low scores are trust signals, not confirmed vulnerabilities; missing or stale results cannot establish current repository security.' } };
}
