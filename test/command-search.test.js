import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCommandEntries, searchCommands, validateCatalogTools, isSafeCommandHref, navigateSearchResult } from '../src/command-search.js';

const tools = [
  { id: 'dependency-audit', name: 'Dependency advisory intelligence', coverage: 'Known npm and pnpm advisories and coordinated upgrade plans.', inputType: 'sanitized-lockfiles' },
  { id: 'opengrep', name: 'Source code security', coverage: 'JavaScript, TypeScript and Python patterns and within-file taint checks.', inputType: 'source-files' },
  { id: 'gitleaks', name: 'Exposed secrets', coverage: 'Checks selected source files for credentials.', inputType: 'source-files' },
  { id: 'trivy-image', name: 'Container vulnerabilities', coverage: 'An uploaded Docker image archive.', inputType: 'image-tar' },
  { id: 'future-engine', name: 'Café package review', coverage: 'Future public package metadata checks.', inputType: 'package-archive' }
];
const entries = () => buildCommandEntries({ tools });

test('entries contain only useful navigation destinations and public tool metadata', () => {
  const dirty = structuredClone(tools);
  dirty[0].href = 'https://untrusted.example/execute'; dirty[0].token = 'synthetic-secret-token';
  const built = buildCommandEntries({ tools: dirty });
  assert.equal(built.find(row => row.id === 'tool:opengrep').href, '/app?tool=opengrep#tools');
  assert.equal(built.find(row => row.id === 'page:keys').href, '/account#keys');
  assert.ok(built.every(row => isSafeCommandHref(row.href)));
  assert.equal(JSON.stringify(built).includes('synthetic-secret-token'), false);
  assert.equal(JSON.stringify(built).includes('untrusted.example'), false);
  assert.equal(built.find(row => row.id === 'tool:future-engine').title, 'Café package review');
  assert.equal(tools[0].href, undefined, 'Caller data was not mutated.');
});

test('company metrics only enter the index after explicit operator confirmation', () => {
  for (const isOperator of [undefined, false, 1, 'true']) {
    const built = buildCommandEntries({ tools, isOperator });
    assert.equal(built.some(row => row.href === '/metrics'), false);
    assert.equal(searchCommands(built, 'company stats').length, 0);
  }
  const built = buildCommandEntries({ tools, isOperator: true });
  assert.equal(searchCommands(built, 'company calls')[0].href, '/metrics');
  assert.equal(isSafeCommandHref('/metrics'), false);
  assert.equal(isSafeCommandHref('/metrics', { isOperator: true }), true);
});

test('exact titles and tool IDs beat incidental coverage or alias matches', () => {
  const built = entries();
  assert.equal(searchCommands(built, 'API KEYS')[0].id, 'page:keys');
  assert.equal(searchCommands(built, 'Opengrep')[0].id, 'tool:opengrep');
  assert.equal(searchCommands(built, 'dependency')[0].id, 'tool:dependency-audit');
  assert.equal(searchCommands(built, 'dependencies')[0].id, 'tool:dependency-audit');
  assert.equal(searchCommands(built, 'container')[0].id, 'tool:trivy-image');
});

test('multiword, semantic aliases, punctuation and diacritics match the relevant page or tool', () => {
  const built = entries();
  for (const query of ['credits', 'top-up', 'auto refill']) assert.equal(searchCommands(built, query)[0].id, 'page:billing');
  for (const query of ['usage', 'logs', 'runs']) assert.equal(searchCommands(built, query)[0].id, 'page:activity');
  assert.equal(searchCommands(built, 'python taint')[0].id, 'tool:opengrep');
  assert.equal(searchCommands(built, 'CVE npm')[0].id, 'tool:dependency-audit');
  assert.equal(searchCommands(built, 'cafe')[0].id, 'tool:future-engine');
  assert.equal(searchCommands(built, 'package archive')[0].id, 'tool:future-engine');
  assert.equal(searchCommands(built, 'repository')[0].id, 'page:legacy');
});

test('added dependency, trust, discovery and SAST tools are discoverable by intent without adding execution actions', () => {
  const built = buildCommandEntries({ tools: [
    { id: 'osv-scanner', name: 'Dependency remediation intelligence' },
    { id: 'openssf-scorecard', name: 'Supply-chain trust assessment' },
    { id: 'katana', name: 'Web and API endpoint discovery' },
    { id: 'httpx', name: 'Live service reconnaissance' },
    { id: 'semgrep', name: 'Additional SAST validation' }
  ] });
  for (const [query, id] of [['fixed versions', 'osv-scanner'], ['supply chain score', 'openssf-scorecard'],
    ['endpoint crawler', 'katana'], ['service reconnaissance', 'httpx'], ['sast validation', 'semgrep']]) {
    const result = searchCommands(built, query)[0];
    assert.equal(result.id, `tool:${id}`); assert.equal(result.href, `/app?tool=${id}#tools`);
    assert.ok(isSafeCommandHref(result.href));
  }
});

test('common one-edit typos and useful subsequences work without matching every short query', () => {
  const built = entries();
  assert.equal(searchCommands(built, 'billng')[0].id, 'page:billing');
  assert.equal(searchCommands(built, 'bililng')[0].id, 'page:billing');
  assert.equal(searchCommands(built, 'gitlek')[0].id, 'tool:gitleaks');
  assert.equal(searchCommands(built, 'qz').length, 0);
  assert.equal(searchCommands(built, 'unrelated fictional value').length, 0);
});

test('empty and extreme searches remain deterministic, bounded and side-effect free', () => {
  const many = buildCommandEntries({ tools: Array.from({ length: 100 }, (_, index) => ({ id: `future-${index}`, name: `Future tool ${index}` })) });
  const before = JSON.stringify(many);
  assert.equal(searchCommands(many, '').length, 16);
  assert.equal(searchCommands(many, '   ')[0].id, 'page:start');
  assert.equal(searchCommands(many, 'future', { limit: 999 }).length, 20);
  assert.equal(searchCommands(many, 'future', { limit: 3 }).length, 3);
  assert.equal(searchCommands(many, 'future', { limit: 0 }).length, 0);
  assert.equal(searchCommands(many, 'x'.repeat(161)).length, 0);
  assert.equal(searchCommands(many, Array(14).fill('future').join(' ')).length, 0);
  assert.equal(searchCommands(many, {}).length, 0);
  assert.equal(JSON.stringify(many), before);
});

test('invalid or duplicate catalogs fail as a whole, while unknown future tools stay searchable', () => {
  for (const catalog of [null, [], {}, { tools: null }, { tools: [null] }, { tools: [{ id: 42, name: 'Numeric ID' }] },
    { tools: [{ id: 'valid', name: '' }] }, { tools: [{ id: 'bad/id', name: 'Unsafe' }] },
    { tools: [{ id: 'safe', name: 'One' }, { id: 'safe', name: 'Two' }] },
    { tools: [{ id: 'safe', name: 'Safe', coverage: null }] }, { tools: [{ id: 'safe', name: 'Safe', inputType: {} }] },
    { tools: Array.from({ length: 257 }, (_, index) => ({ id: `tool-${index}`, name: 'Too many' })) }]) {
    assert.throws(() => validateCatalogTools(catalog), /incomplete response/);
  }
  assert.deepEqual(validateCatalogTools({ tools: [] }), []);
  const clean = validateCatalogTools({ tools: [{ id: 'future', name: ' Future engine ', coverage: ' Coverage ', inputType: 'source-files', privateValue: 'ignored' }] });
  assert.deepEqual(clean, [{ id: 'future', name: 'Future engine', coverage: 'Coverage', inputType: 'source-files' }]);
});

test('result destinations cannot authorize actions, external redirects or arbitrary private paths', () => {
  for (const href of ['https://offense.sh/app#tools', 'https://evil.example/', '//evil.example/app', '/api/auth/logout', '/api/scanner-billing/checkout',
    '/app?tool=opengrep&run=1#tools', '/app?tool=opengrep#billing', '/app?tool=opengrep%0A#tools', '/app?tool=../../private#tools',
    '/app?tool=evil%2Ftool#tools', '/app#unknown', '/account?key=secret#keys', '/metrics?scope=private', '/app/../api/auth/logout',
    '/app#tools\n', 'javascript:alert(1)', null]) assert.equal(isSafeCommandHref(href), false, String(href));
  assert.equal(isSafeCommandHref('/app?tool=known-tool-2#tools'), true);
  assert.equal(searchCommands([{ id: 'unsafe', type: 'page', title: 'Unsafe', href: 'https://evil.example/' }], 'Unsafe').length, 0);
});

test('navigation preserves same-origin scope and emits the SPA event only for an allowed destination', () => {
  const events = [], pushes = [], fake = { location: { origin: 'https://offense.sh', pathname: '/app', search: '', hash: '#tools' },
    history: { pushState(...args) { pushes.push(args); } }, PopStateEvent: class { constructor(type) { this.type = type; } },
    dispatchEvent(event) { events.push(event.type); } };
  assert.equal(navigateSearchResult('/activity', { windowObject: fake }), true);
  assert.deepEqual(pushes[0], [null, '', '/activity']); assert.deepEqual(events, ['popstate']);
  assert.equal(navigateSearchResult('/app#tools', { windowObject: fake }), true);
  assert.equal(pushes.length, 1, 'The current destination does not add another history entry.');
  assert.equal(navigateSearchResult('/metrics', { windowObject: fake }), false);
  assert.equal(navigateSearchResult('/api/auth/logout', { windowObject: fake }), false);
  assert.equal(navigateSearchResult('https://evil.example/', { windowObject: fake }), false);
  assert.equal(events.length, 2);
  assert.equal(navigateSearchResult('/app#tools', { windowObject: null }), false);
});
