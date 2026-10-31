import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { landingCatalog } from '../scripts/catalog.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
test('site build publishes canonical coverage and byte-identical root client artifacts', async () => {
  await promisify(execFile)(process.execPath, ['site/scripts/build.mjs'], { cwd: root });
  for (const removed of ['figma', 'src/reference-diagrams.js']) {
    await assert.rejects(stat(path.join(root, 'site/dist', removed)), { code: 'ENOENT' });
  }
  for (const file of ['install.html', 'templates/offense.yml', 'src/repository-install.js', 'src/repository-install.css']) {
    const source = file.startsWith('src/') ? file : `public/${file}`;
    assert.deepEqual(await readFile(path.join(root, 'site/dist', file)), await readFile(path.join(root, 'site', source)), file);
  }
  const html = await readFile(path.join(root, 'site/dist/index.html'), 'utf8');
  const browserCatalog = await readFile(path.join(root, 'site/dist/src/catalog.js'), 'utf8');
  const tools = landingCatalog();
  assert.equal((html.match(/class="tool-row"/g) || []).length, Object.keys(tools).length);
  assert.match(html, /data-scanner-count>29/);
  assert.match(html, /data-filter="mobile"/);
  assert.doesNotMatch(html, /data-engine-count|Offense scanners|13 tools/);
  for (const id of Object.keys(tools)) {
    assert.ok(html.includes(`data-tool="${id}"`), id);
    assert.ok(browserCatalog.includes(JSON.stringify(id)), id);
  }
  assert.doesNotMatch(browserCatalog, /import |node:|\.\.\/server/);
  const directory = await readFile(path.join(root, 'site/dist/tools.html'), 'utf8');
  const sitemap = await readFile(path.join(root, 'site/dist/sitemap.xml'), 'utf8');
  assert.match(html, /href="\/tools"/);
  assert.match(sitemap, /<loc>https:\/\/offense.sh\/tools<\/loc>/);
  assert.equal((directory.match(/data-directory-tool=/g) || []).length, Object.keys(tools).length);
  for (const [id, tool] of Object.entries(tools)) {
    const detail = await readFile(path.join(root, `site/dist/tools/${id}.html`), 'utf8');
    assert.ok(directory.includes(`href="/tools/${id}"`));
    assert.ok(sitemap.includes(`<loc>https://offense.sh/tools/${id}</loc>`));
    assert.ok(detail.includes(`<h1>${tool.title}</h1>`));
    assert.ok(detail.includes(`rel="canonical" href="https://offense.sh/tools/${id}"`));
    assert.match(detail, /What leaves your machine/);
    assert.doesNotMatch(detail, /github.com\/imranye\/|\$\d|100% open source/);
    if (id === 'dependency-audit') {
      assert.match(detail, /offense audit \. --plan-limit 0/);
      assert.match(detail, /Free · no account/);
      assert.match(detail, /sends sanitized dependency metadata/);
    } else {
      assert.ok(detail.includes(`offense tools show ${id}`));
      assert.match(detail, /Engine license only/);
      assert.match(detail, /href="https:\/\/github.com\/[^" ]+\/blob\/[^" ]+"/);
      assert.match(detail, /Prepaid · quote required/);
    }
  }
  const network = await readFile(path.join(root, 'site/dist/tools/zap-api.html'), 'utf8');
  assert.match(network, /Explicit active-testing consent is required/);
  const scorecard = await readFile(path.join(root, 'site/dist/tools/openssf-scorecard.html'), 'utf8');
  assert.match(scorecard, /does not receive repository credentials or perform a fresh scan/);
  assert.match(scorecard, /Data licensing is separate from the engine license/);
  const kubernetes = await readFile(path.join(root, 'site/dist/tools/k8s-manifest-validate.html'), 'utf8');
  assert.match(kubernetes, /Required <code>kubernetesVersion<\/code>/);
  assert.match(kubernetes, /1\.32\.0/);
  const local = await readFile(path.join(root, 'site/dist/tools/opengrep.html'), 'utf8');
  assert.match(local, /Local helper setup/);
  assert.match(local, /separately installed, pinned scanner/);
  for (const directory of ['downloads', 'skills']) {
    await assert.rejects(stat(path.join(root, 'site/public', directory)), { code: 'ENOENT' });
    let checked = 0;
    async function compare(relative = '') {
      for (const entry of await readdir(path.join(root, 'public', directory, relative), { withFileTypes: true })) {
        const file = path.join(relative, entry.name);
        if (entry.isDirectory()) await compare(file);
        else if (entry.isFile()) {
          assert.deepEqual(await readFile(path.join(root, 'site/dist', directory, file)), await readFile(path.join(root, 'public', directory, file)), file);
          checked++;
        } else assert.fail(`Unsupported client asset: ${file}`);
      }
    }
    await compare();
    assert.ok(checked > 0);
  }
});
