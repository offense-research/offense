import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { hostedScan } from '../public/skills/purple/scripts/hosted-scan.mjs';

test('hosted scan client sends selected tools and records them in its report', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'purple-scan-client-'));
  try {
    const content = 'resource "aws_s3_bucket" "example" {}\n';
    await writeFile(path.join(directory, 'main.tf'), content);
    const collectSourceImpl = async () => ({ files: [{ path: 'main.tf', content }], omitted: [], bytes: Buffer.byteLength(content) });
    const requests = []; let shownQuote;
    const fetchImpl = async (url, options) => {
      requests.push({ url: String(url), ...options });
      if (url.pathname === '/v1/quotes') {
        assert.deepEqual(JSON.parse(options.body), { tools: ['trivy-config'], inputBytes: Buffer.byteLength(content), fileCount: 1 });
        return Response.json({ billable: true, maximumMicros: 50_000, prices: [] });
      }
      if (url.pathname === '/v1/usage') return Response.json({ enabled: true, availableMicros: 100_000 });
      if (options.method === 'POST') return Response.json({ id: 'scan-1', status: 'queued', selectedTools: ['trivy-config'] });
      return Response.json({ id: 'scan-1', status: 'completed', selectedTools: ['trivy-config'], findings: [],
        tools: [{ name: 'trivy-config', status: 'complete', version: 'test' }], coverage: { scope: 'Uploaded IaC only.' } });
    };
    const output = path.join(directory, 'report');
    const result = await hostedScan(directory, { api: 'http://localhost:3217', key: 'test-key', tools: ['trivy-config'],
      fetchImpl, collectSourceImpl, pollMs: 1, output, onQuote: quote => { shownQuote = quote; } });
    assert.equal(result.status, 'completed');
    assert.equal(shownQuote.maximumMicros, 50_000);
    assert.equal(shownQuote.availableMicros, 100_000);
    assert.deepEqual(JSON.parse(requests[2].body), { files: [{ path: 'main.tf', content }],
      tools: ['trivy-config'], maxChargeMicros: 50_000 });
    assert.match(await readFile(result.report, 'utf8'), /Selected tools: trivy-config/);
    assert.deepEqual(JSON.parse(await readFile(result.json, 'utf8')).selectedTools, ['trivy-config']);
    await assert.rejects(hostedScan(directory, { preview: true, tools: ['trivy-config', 'trivy-config'], collectSourceImpl }), /unique tool IDs/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('hosted scan refuses insufficient credit before sending source', async () => {
  const requests = [];
  const source = { files: [{ path: 'a.js', content: 'const a = 1;\n' }], omitted: [], bytes: 13 };
  let shownQuote;
  await assert.rejects(hostedScan('/tmp', { api: 'https://api.example.test', key: 'test-key',
    collectSourceImpl: async () => source, onQuote: quote => { shownQuote = quote; },
    fetchImpl: async (url) => {
      requests.push(url.pathname);
      if (url.pathname === '/v1/quotes') return Response.json({ billable: true, maximumMicros: 50_000, prices: [] });
      if (url.pathname === '/v1/usage') return Response.json({ enabled: true, availableMicros: 20_000 });
      throw new Error('Source must not be uploaded with insufficient credit.');
    } }), /Add scanner credit/);
  assert.deepEqual(requests, ['/v1/quotes', '/v1/usage']);
  assert.equal(shownQuote.maximumMicros, 50_000);
});
