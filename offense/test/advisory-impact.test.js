import test from 'node:test';
import assert from 'node:assert/strict';
import { checkVulnerabilities } from '../server/osv.js';
import { auditMetadata } from '../lib/audit.mjs';

const dependency = { name: 'synthetic-impact-package', version: '1.0.0', resolved: true, kind: 'runtime' };
const advisory = {
  id: 'SYNTHETIC-IMPACT-PIPELINE', summary: 'Input handling issue',
  aliases: ['CVE-2099-12345'], database_specific: { severity: 'HIGH', cwe_ids: ['cwe-79', 'CWE-79', 'not-a-cwe'] },
  affected: [
    { package: { ecosystem: 'npm', name: dependency.name }, ecosystem_specific: { cwe_ids: ['CWE-79'] }, ranges: [] },
    { package: { ecosystem: 'npm', name: 'unrelated-package' }, ecosystem_specific: { cwe_ids: ['CWE-94'] } }
  ]
};
function provider() {
  const requests = [];
  return { requests, fetchImpl: async (url, options) => {
    const parsed = new URL(url); requests.push(parsed.hostname);
    assert.equal(parsed.origin, 'https://api.osv.dev');
    if (parsed.pathname === '/v1/querybatch') {
      assert.equal(JSON.parse(options.body).queries[0].package.name, dependency.name);
      return new Response(JSON.stringify({ results: [{ vulns: [{ id: advisory.id }] }] }));
    }
    assert.equal(parsed.pathname, '/v1/vulns/' + advisory.id);
    return new Response(JSON.stringify(advisory));
  } };
}

test('OSV carries validated package-scoped CWE evidence into a conditional impact explanation', async () => {
  const p = provider();
  const report = await checkVulnerabilities([dependency], p.fetchImpl);
  assert.equal(report.status, 'complete');
  assert.deepEqual(report.findings[0].advisory.cwes, ['CWE-79']);
  assert.equal(report.findings[0].impact.category, 'cross_site_scripting');
  assert.equal(report.findings[0].impact.applicationExposure.status, 'not_assessed');
  assert.deepEqual(p.requests, ['api.osv.dev', 'api.osv.dev']);
});

test('local audit and remediation prompt preserve impact prerequisites without claiming a confirmed vulnerability', async () => {
  const p = provider();
  const lock = { lockfileVersion: 3, packages: {
    '': { dependencies: { [dependency.name]: dependency.version } },
    ['node_modules/' + dependency.name]: { version: dependency.version }
  } };
  const report = await auditMetadata({ files: [{ path: 'package-lock.json', content: lock }], planLimit: 0 }, { fetchImpl: p.fetchImpl });
  assert.equal(report.status, 'complete');
  assert.deepEqual(report.findings[0].source.cwes, ['CWE-79']);
  assert.equal(report.findings[0].impact.category, 'cross_site_scripting');
  assert.equal(report.findings[0].impact.applicationExposure.status, 'not_assessed');
  assert.equal(report.findings[0].verification.confirmed, false);
  assert.equal(report.summary.confirmedVulnerabilities, 0);
  assert.match(report.remediation.agentPrompt, /potential consequence and business impact/);
  assert.match(report.remediation.agentPrompt, /"impact"/);
  assert.match(report.remediation.agentPrompt, /verify application exposure separately/);
  assert.equal(p.requests.length, 2);
});
