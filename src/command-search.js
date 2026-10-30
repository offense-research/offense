const TOOL_ID = /^[a-z0-9-]{1,80}$/;
const MAX_TOOLS = 256;
const MAX_QUERY = 160;

const pages = [
  { id: 'start', title: 'Get started', subtitle: 'Connect your coding agent', href: '/app#start', keywords: 'connect setup install coding agent codex claude cursor mcp' },
  { id: 'tools', title: 'Tools', subtitle: 'Browse security tools and pricing', href: '/app#tools', keywords: 'catalog security checks scanners capabilities' },
  { id: 'keys', title: 'API keys', subtitle: 'Manage your agent connections', href: '/account#keys', keywords: 'api key apikey credentials access token authentication' },
  { id: 'activity', title: 'Activity', subtitle: 'Your hosted tool calls and results', href: '/activity', keywords: 'usage logs runs calls requests history results spend' },
  { id: 'billing', title: 'Billing', subtitle: 'Credit and automatic top-up', href: '/billing', keywords: 'credits credit balance money payment payments topup top up refill automatic auto' },
  { id: 'settings', title: 'Settings', subtitle: 'Account and email preferences', href: '/account#settings', keywords: 'profile account preferences email notifications' },
  { id: 'setup', title: 'Agent setup', subtitle: 'Install the Offense skill', href: '/skill', keywords: 'skill installation instructions documentation docs agents mcp' },
  { id: 'metrics', title: 'Company metrics', subtitle: 'Company-wide Offense call volume', href: '/metrics', keywords: 'company calls stats statistics metrics endpoint volume all workspaces', operator: true },
  { id: 'legacy', title: 'V1 workspace', subtitle: 'Existing repositories and connections', href: '/legacy', keywords: 'legacy repositories repository repo repos github organization cloudflare workers projects connections' }
];

const aliases = {
  'dependency-audit': 'dependencies dependency advisories cve vulnerabilities npm pnpm packages lockfiles upgrades remediation',
  'osv-scanner': 'dependencies dependency osv advisories cve npm pnpm packages lockfiles fixed versions remediation',
  'openssf-scorecard': 'supply chain trust assessment openssf scorecard public github repository security checks score',
  opengrep: 'source code sast static analysis javascript typescript python taint patterns',
  semgrep: 'source code sast static analysis rules validation javascript typescript python',
  gitleaks: 'secrets secret credentials tokens exposed',
  'gitleaks-history': 'secrets secret git history credentials tokens',
  'trivy-vuln': 'dependencies dependency cve vulnerabilities npm pnpm packages manifests',
  'trivy-sbom': 'dependencies dependency cve vulnerabilities sbom cyclonedx spdx',
  'trivy-image': 'container containers image docker cve vulnerabilities',
  'cosign-image': 'container containers image provenance signatures supply chain',
  'trivy-config': 'infrastructure configuration terraform cloud misconfigurations',
  checkov: 'infrastructure configuration terraform cloud misconfigurations',
  zizmor: 'github actions workflows ci pipeline code',
  'guarddog-npm': 'npm package packages malicious malware supply chain dependencies',
  'guarddog-pypi': 'python pypi package packages malicious malware supply chain dependencies',
  'spectral-owasp': 'openapi api schema specification owasp web',
  'zap-passive-har': 'web api http responses passive har browser',
  nuclei: 'web deployment exposure templates security',
  katana: 'web api endpoint endpoints discovery crawl crawler routes verified deployment',
  httpx: 'web api live service discovery reconnaissance http https response technology verified deployment',
  schemathesis: 'web api openapi schema testing staging',
  'zap-api': 'web api openapi staging testing',
  sslyze: 'https tls ssl certificates encryption hostname',
  'prowler-cloudflare': 'cloudflare cf infrastructure cloud account configuration',
  'trufflehog-verified': 'secrets secret credentials live verification',
  'mobsf-static': 'mobile android ios apk ipa application'
};

const normalize = value => typeof value === 'string'
  ? value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim().replace(/\s+/g, ' ')
  : '';

/** Select only public catalog fields. Server-provided links are never used. */
export function validateCatalogTools(catalog) {
  if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog) || !Array.isArray(catalog.tools) || catalog.tools.length > MAX_TOOLS)
    throw new Error('The tool catalog returned an incomplete response.');
  const seen = new Set();
  return catalog.tools.map(tool => {
    if (!tool || typeof tool !== 'object' || Array.isArray(tool) || typeof tool.id !== 'string' || !TOOL_ID.test(tool.id) || seen.has(tool.id) ||
        typeof tool.name !== 'string' || !tool.name.trim() || tool.name.length > 200 ||
        tool.coverage !== undefined && (typeof tool.coverage !== 'string' || tool.coverage.length > 4096) ||
        tool.inputType !== undefined && (typeof tool.inputType !== 'string' || tool.inputType.length > 100))
      throw new Error('The tool catalog returned an incomplete response.');
    seen.add(tool.id);
    return { id: tool.id, name: tool.name.trim(),
      ...(tool.coverage === undefined ? {} : { coverage: tool.coverage.trim() }),
      ...(tool.inputType === undefined ? {} : { inputType: tool.inputType.trim() }) };
  });
}

export function buildCommandEntries({ tools = [], isOperator = false } = {}) {
  const cleanTools = validateCatalogTools({ tools });
  return [
    ...pages.filter(page => !page.operator || isOperator === true).map(({ operator: _operator, ...page }) => ({ ...page, id: `page:${page.id}`, type: 'page', group: 'Pages' })),
    ...cleanTools.map(tool => ({ id: `tool:${tool.id}`, type: 'tool', group: 'Tools', title: tool.name,
      subtitle: tool.id, href: `/app?tool=${encodeURIComponent(tool.id)}#tools`,
      keywords: [aliases[tool.id] || '', tool.coverage || '', tool.inputType || ''].join(' ') }))
  ];
}

/** Recognize one insertion, deletion, substitution, or adjacent transposition. */
function nearWord(query, word) {
  if (query.length < 4 || Math.abs(query.length - word.length) > 1) return false;
  let i = 0, j = 0, edits = 0;
  while (i < query.length && j < word.length) {
    if (query[i] === word[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (query.length === word.length && query[i] === word[j + 1] && query[i + 1] === word[j]) { i += 2; j += 2; }
    else if (query.length > word.length) i++;
    else if (query.length < word.length) j++;
    else { i++; j++; }
  }
  return edits + (i < query.length || j < word.length ? 1 : 0) <= 1;
}

function subsequence(query, word) {
  if (query.length < 3 || query[0] !== word[0] || query.length / word.length < .55 || word.length > query.length + 6) return false;
  let index = 0;
  for (const character of word) if (character === query[index] && ++index === query.length) return true;
  return false;
}

function tokenScore(query, words, weight) {
  if (words.includes(query)) return weight;
  if (words.some(word => word.startsWith(query))) return weight * .8;
  if (words.some(word => word.includes(query))) return weight * .55;
  if (words.some(word => nearWord(query, word))) return weight * .3;
  if (words.some(word => subsequence(query, word))) return weight * .14;
  return 0;
}

/** Searches stay local and bounded; no queries or result history are stored. */
export function searchCommands(entries, query = '', { limit = 16 } = {}) {
  const maximum = Number.isInteger(limit) ? Math.max(0, Math.min(20, limit)) : 16;
  if (!Array.isArray(entries) || typeof query !== 'string' || query.length > MAX_QUERY || !maximum) return [];
  const term = normalize(query), tokens = term.split(' ').filter(Boolean);
  if (tokens.length > 12) return [];
  const candidates = entries.slice(0, MAX_TOOLS + pages.length).filter(entry => entry &&
    ['page', 'tool'].includes(entry.type) && typeof entry.id === 'string' && typeof entry.title === 'string' &&
    isSafeCommandHref(entry.href, { isOperator: true }));
  if (!term) return candidates.slice(0, maximum);
  return candidates.map((entry, order) => {
    const title = normalize(entry.title), id = normalize(entry.type === 'tool' ? entry.subtitle : ''), keywords = normalize(entry.keywords), subtitle = normalize(entry.subtitle);
    const fields = [title.split(' '), id.split(' '), keywords.split(' '), subtitle.split(' ')];
    const scores = tokens.map(token => Math.max(tokenScore(token, fields[0], 1200), tokenScore(token, fields[1], 1100),
      tokenScore(token, fields[2], 650), tokenScore(token, fields[3], 400)));
    if (scores.some(score => score === 0)) return null;
    const phrase = title === term ? 16000 : id === term ? 15000 : title.startsWith(term) ? 11000 :
      id.startsWith(term) ? 10000 : title.includes(term) ? 7000 : id.includes(term) ? 6000 : 0;
    return { entry, order, score: phrase + scores.reduce((sum, value) => sum + value, 0) };
  }).filter(Boolean).sort((a, b) => b.score - a.score || a.order - b.order).slice(0, maximum).map(result => result.entry);
}

/** Closed navigation destinations prevent search results from becoming actions. */
export function isSafeCommandHref(href, { isOperator = false } = {}) {
  if (typeof href !== 'string' || href.length > 256) return false;
  if (pages.some(page => page.href === href && (!page.operator || isOperator === true))) return true;
  return /^\/app\?tool=[a-z0-9-]{1,80}#tools$/.test(href);
}

export function navigateSearchResult(href, { isOperator = false, windowObject = globalThis.window } = {}) {
  if (!isSafeCommandHref(href, { isOperator }) || !windowObject?.history || !windowObject?.location) return false;
  const destination = new URL(href, windowObject.location.origin);
  if (destination.origin !== windowObject.location.origin) return false;
  const next = destination.pathname + destination.search + destination.hash;
  const current = windowObject.location.pathname + windowObject.location.search + windowObject.location.hash;
  if (next !== current) windowObject.history.pushState(null, '', next);
  windowObject.dispatchEvent(new windowObject.PopStateEvent('popstate'));
  return true;
}
