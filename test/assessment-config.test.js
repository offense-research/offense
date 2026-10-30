import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { configuredAssessmentTools } from '../server/assessment-config.js';
import { createHostedScans } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { scanBillingConfig } from '../server/scan-billing-config.js';
import { assessmentTool } from '../shared/assessment-tools.js';

const allPrices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const oldPrices = Object.fromEntries(Object.entries(allPrices).filter(([id]) => !assessmentTool(id)));

test('assessment rollout defaults disabled and accepts only an explicit known allowlist', () => {
  assert.deepEqual(configuredAssessmentTools(), []);
  assert.deepEqual(configuredAssessmentTools({ SCAN_ASSESSMENT_TOOLS_JSON: '["checkov","mobsf-static"]' }), ['checkov', 'mobsf-static']);
  for (const value of ['true', '{}', 'null', '["unknown"]', '["checkov","checkov"]', 'invalid'])
    assert.throws(() => configuredAssessmentTools({ SCAN_ASSESSMENT_TOOLS_JSON: value }));
});

test('existing prepaid deployments accept the prior exact rate card while new prices remain explicit', t => {
  const credentials = { SCAN_BILLING_ENABLED: 'true', WHOP_API_KEY: 'fixture', SCAN_WHOP_WEBHOOK_SECRET: 'fixture',
    SCAN_TOOL_PRICES_JSON: JSON.stringify(oldPrices) };
  assert.equal(scanBillingConfig(credentials).enabled, true);
  assert.throws(() => scanBillingConfig({ ...credentials, SCAN_ASSESSMENT_TOOLS_JSON: '["checkov"]' }), /explicit scanner price/);
  assert.throws(() => scanBillingConfig({ ...credentials, SCAN_TOOL_PRICES_JSON: JSON.stringify({ ...oldPrices, checkov: allPrices.checkov }) }), /every catalog tool/);
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const meter = createScanMetering(db, scanBillingConfig(credentials));
  assert.equal(meter.quote({ tools: ['opengrep'], inputBytes: 1, fileCount: 1 }).maximumMicros, 25000);
  assert.throws(() => meter.quote({ tools: ['checkov'], inputBytes: 1, fileCount: 1 }), /configured scanner price/);
});

test('unprovisioned tools are disabled before quote, upload, or source retention', t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: oldPrices });
  const scans = createHostedScans(db, { metering: meter, sandbox: {}, artifacts: {}, encrypt: value => value, decrypt: value => value });
  const key = scans.issueKey('workspace-a', 'user-a'), principal = scans.authenticate(key.token);
  const catalog = scans.tools('workspace-a');
  assert.equal(catalog.tools.find(tool => tool.id === 'checkov').availability, 'disabled');
  assert.equal(catalog.tools.find(tool => tool.id === 'opengrep').availability, 'available');
  assert.throws(() => scans.quote({ tools: ['checkov'], inputBytes: 1, fileCount: 1 }), error => error.status === 503);
  assert.throws(() => scans.create(principal, { tools: ['checkov'], files: [{ path: 'main.tf', content: 'private' }] }, 'disabled-tool-001'), error => error.status === 503);
  assert.throws(() => scans.beginArtifactUpload(key.token, { kind: 'mobile-app', size: 10, sha256: 'a'.repeat(64) }), error => error.status === 503);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_jobs').get().n, 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_artifacts').get().n, 0);
});
