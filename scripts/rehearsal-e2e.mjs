import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { parseArgs } from 'node:util';
import path from 'node:path';

const { values } = parseArgs({ options: { 'session-file': { type: 'string' }, 'playwright-module': { type: 'string', default: 'playwright' },
  'output-dir': { type: 'string', default: '/tmp/purple-rehearsal-e2e' } } });
if (!values['session-file']) throw new Error('Provide a private test session file.');
const session = readFileSync(values['session-file'], 'utf8').trim();
if (!/^[a-f0-9]{64}$/.test(session)) throw new Error('Invalid test session.');
const out = path.resolve(values['output-dir']); mkdirSync(out, { recursive: true, mode: 0o700 });
const { chromium } = await import(values['playwright-module']);
const browser = await chromium.launch({ executablePath: '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
await context.addCookies([{ name: 'purple_session', value: session, domain: 'app.purpleteam.sh', path: '/', secure: true, httpOnly: true }]);
const page = await context.newPage();
const report = { startedAt: new Date().toISOString(), errors: [], checks: [] };
page.on('pageerror', error => report.errors.push(error.message));
try {
  await page.goto('https://app.purpleteam.sh/#dependencies');
  await page.getByRole('combobox', { name: 'Repository', exact: true }).selectOption({ label: 'imranye/purple-e2e-fixture' });
  const accepted = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/dependencies/rehearsal');
  await page.getByRole('button', { name: 'Run simulation', exact: true }).click({ timeout: 180000 });
  const response = await accepted;
  assert.equal(response.status(), 202);
  const startedJob = (await response.json()).rehearsal;
  report.checks.push('Started rehearsal through the browser');
  let job;
  const deadline = Date.now() + 18 * 60_000;
  while (Date.now() < deadline) {
    const response = await context.request.get('https://app.purpleteam.sh/api/dependencies?cached=1');
    assert.equal(response.status(), 200);
    const snapshot = (await response.json()).snapshots.find(item => item.repository === 'imranye/purple-e2e-fixture');
    job = snapshot?.rehearsal;
    if (job?.id !== startedJob.id) { await new Promise(resolve => setTimeout(resolve, 1000)); continue; }
    if (job?.status === 'failed') throw new Error(job.error);
    if (job?.status === 'completed') break;
    console.log(`Rehearsal ${job?.status || 'starting'}…`);
    await new Promise(resolve => setTimeout(resolve, 10000));
  }
  assert.equal(job?.status, 'completed'); assert.equal(job.stale, false);
  assert.equal(job.model, 'qwen/qwen3.7-flash');
  assert.ok(job.result.baseline.checks.length > 0 && job.result.baseline.checks.every(check => check.passed));
  assert.ok(job.result.scenarios.some(scenario => scenario.status === 'tests_passed' && scenario.remainingAdvisories === 0));
  report.checks.push('Cheap-model proposal, pinned sandbox checkout, baseline and upgraded tests, final OSV check');
  report.rehearsal = job;
  // The UI must receive the completed job through its background refresh.
  await page.getByText('Simulation results · checks passed', { exact: true }).waitFor({ timeout: 45000 });
  await page.getByText('Simulation results · checks passed', { exact: true }).click();
  await page.screenshot({ path: path.join(out, 'rehearsal-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: 'Copy repo prompt', exact: true }).click();
  await page.getByText('Prompt copied.', { exact: true }).waitFor({ timeout: 180000 });
  const prompt = await page.evaluate(() => navigator.clipboard.readText());
  const start = prompt.indexOf('\n{') + 1, end = prompt.indexOf('\n\nUpdate path and remediation steps:');
  const evidence = JSON.parse(prompt.slice(start, end));
  writeFileSync(path.join(out, 'one-shot-prompt.txt'), prompt, { mode: 0o600 });
  report.promptRehearsal = evidence.upgradeRehearsal;
  assert.equal(evidence.repository, 'imranye/purple-e2e-fixture');
  assert.equal(evidence.upgradeRehearsal.id, job.id); assert.equal(evidence.upgradeRehearsal.usable, true);
  assert.ok(evidence.tasks.every(task => task.updatePath.targetVersion === '7.5.2'));
  report.checks.push('Copied repository prompt contains the completed current rehearsal and upgrade path');
  writeFileSync(path.join(out, 'one-shot-prompt.txt'), prompt, { mode: 0o600 });
  await page.setViewportSize({ width: 393, height: 852 });
  await page.locator('.sidebar').evaluate(async element => {
    getComputedStyle(element).transform;
    await Promise.allSettled(element.getAnimations().map(animation => animation.finished));
  });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.screenshot({ path: path.join(out, 'rehearsal-mobile.png'), fullPage: true });
  report.checks.push('Mobile layout has no horizontal overflow');
  assert.deepEqual(report.errors, []);
  report.status = 'passed'; console.log(JSON.stringify({ status: report.status, checks: report.checks, usage: job.prediction.usage }, null, 2));
} catch (error) { report.status = 'failed'; report.error = error.message; console.error(error.message); process.exitCode = 1; }
finally { report.finishedAt = new Date().toISOString(); writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 }); await browser.close(); }
