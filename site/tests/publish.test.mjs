import assert from 'node:assert/strict';
import test from 'node:test';
import publishStaticSite from '../deploy/publish-static-site.mjs';

async function publishFixture(services) {
  const calls = [];
  const cloudflare = {
    async request(request) {
      calls.push(request);
      return request.method === 'PUT'
        ? { success: true, result: { deployment_id: 'deployment-fixture', etag: 'etag-fixture' }, errors: [] }
        : { success: true, errors: [] };
    },
  };
  const site = {
    name: 'offense-landing',
    compatibilityDate: '2026-10-26',
    observability: { enabled: true },
    assetConfig: { html_handling: 'auto-trailing-slash', not_found_handling: 'none', _headers: '/*\n  X-Content-Type-Options: nosniff\n' },
    workerSource: 'export default { fetch() { return new Response("fixture"); } };',
    services,
  };
  const result = await publishStaticSite(cloudflare, 'account-fixture', site, 'asset-completion-fixture');
  const upload = calls[0];
  assert.equal(upload.method, 'PUT');
  assert.equal(upload.path, '/accounts/account-fixture/workers/scripts/offense-landing');
  assert.equal(upload.rawBody, true);
  const form = await new Response(upload.body, { headers: { 'Content-Type': upload.contentType } }).formData();
  const metadata = JSON.parse(form.get('metadata'));
  assert.deepEqual(metadata.assets, { jwt: 'asset-completion-fixture', config: site.assetConfig });
  assert.equal(metadata.main_module, 'fallback.js');
  assert.equal(await form.get('fallback.js').text(), site.workerSource);
  assert.deepEqual(calls[1], {
    method: 'POST',
    path: '/accounts/account-fixture/workers/scripts/offense-landing/subdomain',
    body: { enabled: true, previews_enabled: false },
  });
  assert.equal(calls.length, 2);
  assert.equal(result.success, true);
  return metadata;
}

test('publishing retains application service bindings alongside static assets', async () => {
  const metadata = await publishFixture([
    { binding: 'OFFENSE_APP', service: 'purple-app' },
    { binding: 'PREVIEW_APP', service: 'purple-app', environment: 'preview' },
  ]);
  assert.deepEqual(metadata.bindings, [
    { type: 'service', name: 'OFFENSE_APP', service: 'purple-app' },
    { type: 'service', name: 'PREVIEW_APP', service: 'purple-app', environment: 'preview' },
  ]);
});

test('publishing a site without configured services keeps assets and an empty binding list', async t => {
  for (const [name, services] of [['omitted', undefined], ['empty', []]]) {
    await t.test(name, async () => {
      const metadata = await publishFixture(services);
      assert.deepEqual(metadata.bindings, []);
    });
  }
});
