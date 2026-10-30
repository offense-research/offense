import test from 'node:test';
import assert from 'node:assert/strict';
import { checkVulnerabilities } from '../server/osv.js';

test('OSV matches pinned npm versions and shows CVE aliases and fixes', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (url.endsWith('/querybatch')) {
      const body = JSON.parse(options.body);
      assert.deepEqual(body.queries, [{ package: { ecosystem: 'npm', name: 'lodash' }, version: '4.17.20' }]);
      return { ok: true, json: async () => ({ results: [{ vulns: [{ id: 'GHSA-test-1234-5678' }] }] }) };
    }
    assert.match(url, /\/vulns\/GHSA-test-1234-5678$/);
    return { ok: true, json: async () => ({ id: 'GHSA-test-1234-5678', summary: 'Unsafe input handling',
      aliases: ['CVE-2021-23337'], database_specific: { severity: 'HIGH' }, affected: [{
        package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }]
      }] }) };
  };
  const result = await checkVulnerabilities([
    { name: 'lodash', version: '4.17.20', kind: 'runtime', resolved: true },
    { name: 'express', version: '^5.1.0', kind: 'runtime', resolved: false }
  ], fetchImpl);
  assert.equal(requests.length, 2);
  assert.equal(result.status, 'complete');
  assert.equal(result.checkedPackages, 1);
  assert.equal(result.skippedPackages, 1);
  const [{ impact, ...originalFinding }] = result.findings;
  assert.deepEqual([originalFinding], [{ package: 'lodash', version: '4.17.20', kind: 'runtime',
    id: 'GHSA-test-1234-5678', cves: ['CVE-2021-23337'], summary: 'Unsafe input handling', severity: 'HIGH', fixedVersions: ['4.17.21'], advisory: { cwes: [], aliases: ['CVE-2021-23337'], modified: null, published: null, details: '', references: [],
      affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }], versions: [], ecosystemSpecific: {} }] } }]);
  assert.equal(impact.schemaVersion, 1);
  assert.equal(impact.category, 'unknown');
  assert.equal(impact.applicationExposure.status, 'not_assessed');
});

test('OSV paginated batch results are collected before reporting completion', async () => {
  let calls = 0;
  const fetchImpl = async (url, options) => {
    if (url.endsWith('/querybatch')) {
      calls++;
      const pageToken = JSON.parse(options.body).queries[0].page_token;
      return { ok: true, json: async () => ({ results: [{ vulns: [{ id: pageToken ? 'GHSA-second' : 'GHSA-first' }],
        ...(pageToken ? {} : { next_page_token: 'next' }) }] }) };
    }
    return { ok: true, json: async () => ({ summary: 'Advisory' }) };
  };
  const result = await checkVulnerabilities([{ name: 'example', version: '1.0.0', kind: 'transitive', resolved: true }], fetchImpl);
  assert.equal(calls, 2);
  assert.deepEqual(result.findings.map(item => item.id), ['GHSA-first', 'GHSA-second']);
});

test('a repository with more than 200 distinct advisories completes without dropping matches', async () => {
  const ids = Array.from({ length: 205 }, (_, index) => `GHSA-large-${index}`);
  let details = 0;
  const result = await checkVulnerabilities([{ name: 'example', version: '1.0.0', kind: 'runtime', resolved: true }], async (url, options) => {
    assert.ok(options.signal instanceof AbortSignal);
    if (url.endsWith('/querybatch')) return { ok: true, json: async () => ({ results: [{ vulns: ids.map(id => ({ id })) }] }) };
    details++;
    return { ok: true, json: async () => ({ summary: 'Fixture advisory', database_specific: { severity: 'HIGH' } }) };
  });
  assert.equal(result.status, 'complete'); assert.equal(details, 205);
  assert.deepEqual(result.findings.map(item => item.id), ids);
});

test('advisory workloads above the bounded limit fail explicitly before hydrating details', async () => {
  let details = 0;
  await assert.rejects(checkVulnerabilities([{ name: 'example', version: '1.0.0', resolved: true }], async url => {
    if (url.endsWith('/querybatch')) return { ok: true, json: async () => ({ results: [{ vulns: Array.from({ length: 501 }, (_, index) => ({ id: `GHSA-large-${index}` })) }] }) };
    details++; return { ok: true, json: async () => ({}) };
  }), /500-advisory limit/);
  assert.equal(details, 0);
});
