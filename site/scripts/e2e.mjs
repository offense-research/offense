// Static local browser checks only. No account, scan, provider or payment calls.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { landingCatalog } from './catalog.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = path.join(root, 'test-results');
const base = 'http://127.0.0.1:4238';
const server = spawn(process.execPath, ['scripts/serve.mjs', '--directory', 'dist', '--port', '4238'], { cwd: root, stdio: 'ignore' });
let browser;
const errors = [], blockedRequests = [], checks = [];
try {
  for (let attempt = 0; ; attempt++) {
    try { const response = await fetch(base); if (response.ok) break; } catch { /* Wait for this local process only. */ }
    if (attempt >= 40 || server.exitCode !== null) throw new Error('Local site server did not start.');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  browser = await chromium.launch({ executablePath: process.env.PURPLE_BROWSER || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ reducedMotion: 'reduce', viewport: { width: 1440, height: 1000 } });
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base || !['GET', 'HEAD'].includes(request.method()) || /^\/(api|v1)\//.test(url.pathname)) {
      blockedRequests.push({ origin: url.origin, pathname: url.pathname, method: request.method() });
      return route.abort();
    }
    return route.continue();
  });
  await context.addInitScript(() => {
    window.__copies = []; window.__rejectCopy = false;
    Object.defineProperty(navigator, 'clipboard', { value: { async writeText(value) {
      if (window.__rejectCopy) throw new Error('Synthetic clipboard failure');
      window.__copies.push(value);
    } } });
  });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(base);
  await page.getByRole('button', { name: 'Copy setup prompt', exact: true }).click();
  const prompt = 'Set up Offense from https://offense.sh/llms.txt';
  assert.equal(await page.evaluate(() => window.__copies.at(-1)), prompt);
  assert.equal(await page.getByRole('link', { name: 'get an API key', exact: true }).getAttribute('href'), 'https://offense.sh/account#keys');
  await page.evaluate(() => { window.__rejectCopy = true; });
  await page.locator('[data-copy="install-command"]').click();
  assert.equal(await page.evaluate(() => window.getSelection().toString()), prompt);
  checks.push('Canonical setup prompt, API key link and clipboard fallback');

  await page.locator('#all-tools > summary').click();
  const tools = landingCatalog();
  const toolCount = Object.keys(tools).length;
  assert.equal(await page.locator('#all-tools .tool-row').count(), toolCount);
  for (const id of Object.keys(tools)) {
    await page.locator(`#all-tools button[data-details="${id}"]`).click();
    await page.getByRole('dialog').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#dialog-title').textContent(), tools[id].title);
    assert.equal(await page.locator('#dialog-description').textContent(), tools[id].description);
    assert.equal(await page.locator('#dialog-link').getAttribute('href'), 'https://offense.sh/app#tools');
    await page.keyboard.press('Escape');
  }
  checks.push(`All ${toolCount} supported tool dialogs and canonical coverage`);
  for (const category of ['source', 'dependencies', 'infrastructure', 'web', 'mobile', 'all']) {
    await page.locator(`[data-filter="${category}"]`).click();
    const count = category === 'all' ? toolCount : Object.values(tools).filter(tool => tool.category === category).length;
    assert.equal(await page.locator('#all-tools .tool-row:visible').count(), count);
    assert.equal(await page.locator(`[data-filter="${category}"]`).getAttribute('aria-pressed'), 'true');
  }
  assert.equal(await page.locator('.featured-tools .tool-card:visible').count(), 3);
  checks.push('Every catalog category, mobile coverage and independent featured cards');

  await mkdir(output, { recursive: true });
  const sizes = [320, 375, 390, 768, 1024, 1440];
  for (const width of sizes) {
    await page.setViewportSize({ width, height: 900 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `Horizontal page overflow at ${width}px`);
    await page.getByRole('button', { name: 'Copy setup prompt', exact: true }).scrollIntoViewIfNeeded();
  }
  await page.screenshot({ path: path.join(output, 'landing-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 375, height: 812 });
  await page.screenshot({ path: path.join(output, 'landing-mobile.png'), fullPage: true });
  checks.push('Six responsive widths without page overflow');

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(base);
  await page.getByRole('link', { name: 'Tools', exact: true }).click();
  assert.equal(new URL(page.url()).pathname, '/tools');
  const visibleTools = () => page.locator('[data-directory-tool]:visible').evaluateAll(cards => cards.map(card => card.dataset.directoryTool));
  assert.equal((await visibleTools()).length, toolCount);
  const search = page.getByRole('searchbox', { name: 'Find a security tool' });
  await search.fill('  TrIvY container  ');
  assert.deepEqual(await visibleTools(), ['trivy-image']);
  assert.equal(await page.locator('#directory-count').textContent(), '1 tool of 29');
  const sourceFilter = page.getByRole('button', { name: 'Source & secrets', exact: true });
  await sourceFilter.focus(); await page.keyboard.press('Space');
  assert.deepEqual(await visibleTools(), []);
  assert.equal(await sourceFilter.getAttribute('aria-pressed'), 'true');
  assert.ok(await page.getByRole('heading', { name: 'No tools found.' }).isVisible());
  await page.getByRole('button', { name: 'Show all tools' }).click();
  assert.equal((await visibleTools()).length, toolCount);
  assert.equal(await search.inputValue(), '');
  assert.equal(new URL(page.url()).search, '');
  assert.equal(await search.evaluate(element => document.activeElement === element), true);
  for (const [label, ids] of [
    ['Mobile', ['mobsf-static']],
    ['Web & API', ['zap-passive-har', 'nuclei', 'schemathesis', 'zap-api', 'sslyze', 'katana', 'httpx']],
  ]) {
    await page.getByRole('button', { name: label, exact: true }).click();
    assert.deepEqual(await visibleTools(), ids);
  }
  await page.goto(`${base}/tools?category=infrastructure&q=kubernetes`);
  assert.deepEqual(await visibleTools(), ['k8s-deprecations', 'k8s-manifest-validate']);
  await page.getByRole('link', { name: 'Kubernetes API deprecations', exact: true }).click();
  assert.equal(await page.locator('h1').textContent(), 'Kubernetes API deprecations');
  await page.goBack();
  assert.deepEqual(await visibleTools(), ['k8s-deprecations', 'k8s-manifest-validate']);
  await page.getByRole('button', { name: 'Reset', exact: true }).click();
  assert.equal((await visibleTools()).length, toolCount);
  checks.push('Public directory: combined search/category, keyboard filtering, empty-state recovery, shareable URLs and back navigation');

  for (const [id, tool] of Object.entries(tools)) {
    const response = await page.goto(`${base}/tools/${id}`);
    assert.equal(response.status(), 200, id);
    assert.equal(await page.locator('h1').textContent(), tool.title);
    assert.equal(await page.locator('.directory-detail-hero .directory-intro').textContent(), tool.description);
    assert.ok(await page.getByRole('heading', { name: 'What leaves your machine.' }).isVisible());
    assert.equal(await page.locator('link[rel="canonical"]').getAttribute('href'), `https://offense.sh/tools/${id}`);
  }
  await page.goto(`${base}/tools/opengrep`);
  await page.getByRole('button', { name: 'Copy command' }).click();
  assert.equal(await page.evaluate(() => window.__copies.at(-1)), 'offense login\noffense tools show opengrep');
  await page.evaluate(() => { window.__rejectCopy = true; });
  await page.getByRole('button', { name: 'Copy command' }).click();
  assert.equal(await page.evaluate(() => window.getSelection().toString()), 'offense login\noffense tools show opengrep');
  assert.match(await page.locator('.directory-copy-status').textContent(), /Copy the selected command/);
  for (const route of ['/tools', '/tools/opengrep', '/tools/dependency-audit', '/tools/k8s-manifest-validate']) {
    await page.goto(base + route);
    for (const width of sizes) {
      await page.setViewportSize({ width, height: 900 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${route} overflows at ${width}px`);
    }
  }
  assert.equal((await page.goto(`${base}/tools/not-a-tool`)).status(), 404);
  const redirect = await context.request.get(`${base}/tools/opengrep/?q=keep`, { maxRedirects: 0 });
  assert.equal(redirect.status(), 308);
  assert.equal(redirect.headers().location, '/tools/opengrep?q=keep');
  checks.push('Every detail URL, canonical title/scope, clipboard fallback, responsive directory/detail layouts, redirects and genuine 404s');

  const noScript = await browser.newContext({ javaScriptEnabled: false });
  await noScript.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());
  const staticPage = await noScript.newPage();
  await staticPage.goto(`${base}/tools`);
  assert.equal(await staticPage.locator('[data-directory-tool]:visible').count(), toolCount);
  assert.equal(await staticPage.getByRole('searchbox').isVisible(), false);
  await staticPage.getByRole('link', { name: 'Source code security', exact: true }).click();
  assert.equal(await staticPage.locator('h1').textContent(), 'Source code security');
  assert.match(await staticPage.locator('#tool-command').textContent(), /offense tools show opengrep/);
  assert.equal(await staticPage.getByRole('button', { name: 'Copy command' }).isVisible(), false);
  await noScript.close();
  checks.push('Directory and linked detail pages remain readable and navigable without JavaScript');
  assert.deepEqual(errors, []); assert.deepEqual(blockedRequests, []);
  const report = { passed: true, checkedAt: new Date().toISOString(), checks, responsiveWidths: sizes,
    pageErrors: errors, blockedRequests, scope: 'Local static build only; no authentication, customer, provider, scan or payment calls.' };
  await writeFile(path.join(output, 'browser.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  await browser?.close();
  server.kill('SIGTERM');
}
