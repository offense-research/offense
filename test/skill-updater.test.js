import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink, access } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';
import { checkSkillUpdates, INSTALL_RECORD, updateBeforeRun } from '../scripts/skill-updater.mjs';
import { SKILL_FILES } from '../scripts/skill-manifests.mjs';

const execute = promisify(execFile), digest = value => createHash('sha256').update(value).digest('hex');
const skillText = version => `---\nname: offense\nmetadata:\n  version: "${version}"\n---\n\n# Offense ${version}\n`;
const files = version => ({ 'SKILL.md': skillText(version), 'references/install.md': 'Setup ' + version,
  'scripts/offense.mjs': `export const version = '${version}';\n`, 'scripts/update.mjs': `export const version = '${version}';\n` });
const release = (version, content, previous = []) => ({ schemaVersion: 1, skill: 'offense', version, minimumNodeMajor: 20,
  files: Object.entries(content).map(([file, value]) => ({ path: file, bytes: Buffer.byteLength(value), sha256: digest(value) })),
  previousReleases: previous.map(([oldVersion, oldFiles]) => ({ version: oldVersion, files: Object.fromEntries(Object.entries(oldFiles).map(([file, value]) => [file, digest(value)])) })) });

async function fixture(t, content = files('1.0.0'), skill = 'offense') {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'purple-updater-test-')), root = path.join(outer, skill);
  await mkdir(root);
  for (const [file, value] of Object.entries(content)) {
    await mkdir(path.dirname(path.join(root, file)), { recursive: true }); await writeFile(path.join(root, file), value);
  }
  t.after(() => rm(outer, { recursive: true, force: true }));
  const server = { manifest: { ...release('1.0.0', content), skill }, content, requests: [] };
  const fetchImpl = async (url, options) => {
    server.requests.push({ url: String(url), options });
    assert.equal(options.method, 'GET'); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    assert.equal(options.cache, 'no-store'); assert.equal(options.headers['cache-control'], 'no-cache');
    assert.equal(options.body, undefined); assert.equal(options.headers.authorization, undefined);
    const prefix = 'https://app.purpleteam.sh/skills/' + skill + '/';
    assert.ok(String(url).startsWith(prefix));
    const file = String(url).slice(prefix.length);
    if (file === 'manifest.json') return Response.json(server.manifest);
    assert.ok(Object.hasOwn(server.content, file), 'unexpected resource ' + file);
    return new Response(server.content[file]);
  };
  const run = options => checkSkillUpdates({ skill, root, fetchImpl, ...options });
  const newer = (version, content, prior = [['1.0.0', files('1.0.0')]]) => { server.manifest = { ...release(version, content, prior), skill }; server.content = content; };
  return { outer, root, server, run, newer, fetchImpl };
}

test('first run records verified installed hashes; every later run rechecks the public manifest', async t => {
  const f = await fixture(t);
  assert.equal((await f.run()).status, 'initialized');
  const receipt = JSON.parse(await readFile(path.join(f.root, INSTALL_RECORD), 'utf8'));
  assert.equal(receipt.releaseVersion, '1.0.0'); assert.equal(receipt.files['SKILL.md'].upstreamSha256, digest(skillText('1.0.0')));
  assert.equal((await f.run()).status, 'current');
  assert.deepEqual(f.server.requests.map(request => request.url), Array(2).fill('https://app.purpleteam.sh/skills/offense/manifest.json'));
});

test('Codex-managed skills never fetch, stage, accept or mutate hosted updates', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.root, '.offense-distribution.json'), JSON.stringify({ schemaVersion: 1, manager: 'codex-plugin' }));
  for (const mode of ['auto', 'check', 'accept-local']) {
    const outcome = await f.run({ mode });
    assert.equal(outcome.status, 'plugin_managed');
    assert.match(outcome.message, /Codex/);
  }
  assert.equal((await updateBeforeRun('offense', new URL('file://' + path.join(f.root, 'scripts/offense.mjs')), { fetchImpl: f.fetchImpl, log() {} })).status, 'plugin_managed');
  assert.equal(f.server.requests.length, 0);
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0'));
  await assert.rejects(access(path.join(f.root, INSTALL_RECORD)), { code: 'ENOENT' });
  await assert.rejects(access(path.join(f.root, '.skill-updates')), { code: 'ENOENT' });
});

test('a newer release replaces only unchanged managed files and requires a new session', async t => {
  const f = await fixture(t); await f.run();
  await writeFile(path.join(f.root, 'AGENTS.md'), 'Keep these custom project instructions');
  const next = { ...files('1.1.0'), 'references/new.md': 'New reference' }; f.newer('1.1.0', next);
  const outcome = await f.run();
  assert.equal(outcome.status, 'updated'); assert.equal(outcome.sessionReloadRequired, true); assert.equal(outcome.stop, true);
  assert.match(outcome.message, /Start a new coding-agent session in this same project/);
  for (const [file, value] of Object.entries(next)) assert.equal(await readFile(path.join(f.root, file), 'utf8'), value);
  assert.equal(await readFile(path.join(f.root, 'AGENTS.md'), 'utf8'), 'Keep these custom project instructions');
  assert.equal((await f.run()).status, 'current');
});

test('known legacy release hashes allow a safe upgrade without an old installation receipt', async t => {
  const f = await fixture(t); f.newer('1.1.0', files('1.1.0'));
  assert.equal((await f.run()).status, 'updated');
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.1.0'));
});

test('customized files stage the whole release without mixing active helper versions', async t => {
  const f = await fixture(t); await f.run();
  const custom = skillText('1.0.0') + '\nKeep my organization policy.\n';
  await writeFile(path.join(f.root, 'SKILL.md'), custom); f.newer('1.1.0', files('1.1.0'));
  const outcome = await f.run();
  assert.equal(outcome.status, 'review_required'); assert.deepEqual(outcome.conflicts, ['SKILL.md']); assert.equal(outcome.sessionReloadRequired, false);
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), custom);
  assert.equal(await readFile(path.join(f.root, 'scripts/offense.mjs'), 'utf8'), files('1.0.0')['scripts/offense.mjs']);
  assert.equal(await readFile(path.join(outcome.stagedDirectory, 'files/SKILL.md'), 'utf8'), skillText('1.1.0'));
  assert.ok(!JSON.stringify(f.server.requests).includes('organization policy'));
});

test('reviewed local merges remain customized during later releases', async t => {
  const f = await fixture(t); await f.run();
  await writeFile(path.join(f.root, 'SKILL.md'), skillText('1.0.0') + '\nCustom instructions');
  f.newer('1.1.0', files('1.1.0')); await f.run();
  const merged = skillText('1.1.0') + '\nCustom instructions';
  for (const [file, value] of Object.entries(files('1.1.0'))) await writeFile(path.join(f.root, file), file === 'SKILL.md' ? merged : value);
  const accepted = await f.run({ mode: 'accept-local' });
  assert.equal(accepted.status, 'customizations_accepted'); assert.equal(accepted.sessionReloadRequired, true);
  assert.equal((await f.run()).status, 'current_customized');
  f.newer('1.2.0', files('1.2.0'), [['1.1.0', files('1.1.0')]]);
  assert.equal((await f.run()).status, 'review_required');
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), merged);
});

test('unknown legacy customizations are never adopted as unmodified upstream files', async t => {
  const f = await fixture(t, { ...files('1.0.0'), 'SKILL.md': skillText('1.0.0') + '\nLocal policy' });
  f.newer('1.1.0', files('1.1.0'));
  const result = await f.run(); assert.equal(result.status, 'review_required');
  await assert.rejects(access(path.join(f.root, INSTALL_RECORD)), { code: 'ENOENT' });
});

test('retiring a customized managed helper requires review and never deletes it', async t => {
  const original = { ...files('1.0.0'), 'scripts/retired.mjs': 'Old helper' }, f = await fixture(t, original); await f.run();
  await writeFile(path.join(f.root, 'scripts/retired.mjs'), 'Customized old helper');
  f.newer('1.1.0', files('1.1.0'), [['1.0.0', original]]);
  const result = await f.run(); assert.equal(result.status, 'review_required'); assert.ok(result.conflicts.includes('scripts/retired.mjs'));
  assert.equal(await readFile(path.join(f.root, 'scripts/retired.mjs'), 'utf8'), 'Customized old helper');
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0'));
});

test('checksum failures preserve every active file and the installation receipt', async t => {
  const f = await fixture(t); await f.run(); const original = await readFile(path.join(f.root, INSTALL_RECORD));
  f.newer('1.1.0', files('1.1.0')); f.server.content['scripts/offense.mjs'] += '\ncorruption';
  const result = await f.run(); assert.equal(result.status, 'check_failed'); assert.match(result.message, /size limit|checksum/);
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0'));
  assert.ok((await readFile(path.join(f.root, INSTALL_RECORD))).equals(original));
});

test('write failures roll back already replaced files instead of leaving a mixed release', async t => {
  const f = await fixture(t); await f.run(); f.newer('1.1.0', files('1.1.0'));
  const result = await f.run({ beforeReplace: file => { if (file === 'references/install.md') throw Error('simulated disk failure'); } });
  assert.equal(result.status, 'check_failed'); assert.match(result.message, /simulated disk failure/);
  for (const [file, value] of Object.entries(files('1.0.0'))) assert.equal(await readFile(path.join(f.root, file), 'utf8'), value);
  assert.equal(JSON.parse(await readFile(path.join(f.root, INSTALL_RECORD), 'utf8')).releaseVersion, '1.0.0');
  await assert.rejects(access(path.join(f.root, '.skill-update-transaction.json')), { code: 'ENOENT' });
});

test('an interrupted transaction recovers before making its next network request', async t => {
  const f = await fixture(t); await f.run(); const receipt = await readFile(path.join(f.root, INSTALL_RECORD));
  await writeFile(path.join(f.root, 'SKILL.md'), skillText('1.1.0'));
  await writeFile(path.join(f.root, '.skill-update.lock'), JSON.stringify({ pid: 999999999 }));
  await writeFile(path.join(f.root, '.skill-update-transaction.json'), JSON.stringify({ schemaVersion: 1, skill: 'offense',
    oldReceipt: receipt.toString('base64'), newReceiptSha256: 'a'.repeat(64), files: [{ path: 'SKILL.md',
      previous: Buffer.from(skillText('1.0.0')).toString('base64'), previousSha256: digest(skillText('1.0.0')),
      nextSha256: digest(skillText('1.1.0')), mode: 0o644 }] }));
  const result = await f.run({ fetchImpl: async () => {
    assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0')); throw Error('offline after recovery');
  } });
  assert.equal(result.status, 'check_failed'); assert.ok((await readFile(path.join(f.root, INSTALL_RECORD))).equals(receipt));
  await assert.rejects(access(path.join(f.root, '.skill-update-transaction.json')), { code: 'ENOENT' });
});

test('recovery never overwrites a concurrent edit and can finish after an explicit reviewed merge', async t => {
  const f = await fixture(t); await f.run(); f.newer('1.1.0', files('1.1.0'));
  const custom = skillText('1.1.0') + '\nMy concurrent customization';
  const outcome = await f.run({ beforeReplace: async file => {
    if (file === 'references/install.md') { await writeFile(path.join(f.root, 'SKILL.md'), custom); throw Error('interrupted'); }
  } });
  assert.equal(outcome.status, 'recovery_required'); assert.equal(outcome.stop, true);
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), custom);
  for (const [file, value] of Object.entries(files('1.1.0'))) await writeFile(path.join(f.root, file), file === 'SKILL.md' ? custom : value);
  assert.equal((await f.run({ mode: 'accept-local' })).status, 'customizations_accepted');
  assert.equal((await f.run()).status, 'current_customized');
});

test('edits during downloads are preserved and prevent automatic promotion', async t => {
  const f = await fixture(t); await f.run(); f.newer('1.1.0', files('1.1.0'));
  let edited = false;
  const result = await f.run({ fetchImpl: async (url, options) => {
    if (!edited && String(url).endsWith('/scripts/offense.mjs')) {
      edited = true; await writeFile(path.join(f.root, 'SKILL.md'), 'Concurrent user edit');
    }
    return f.fetchImpl(url, options);
  } });
  assert.equal(result.status, 'review_required');
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), 'Concurrent user edit');
  assert.equal(await readFile(path.join(f.root, 'scripts/offense.mjs'), 'utf8'), files('1.0.0')['scripts/offense.mjs']);
});

test('concurrent checks cannot run against a skill while another updater holds its lock', async t => {
  const f = await fixture(t); let releaseFetch, entered;
  const gate = new Promise(resolve => { releaseFetch = resolve; }), start = new Promise(resolve => { entered = resolve; });
  const first = f.run({ fetchImpl: async (...args) => { entered(); await gate; return f.fetchImpl(...args); } });
  await start; const second = await f.run(); assert.equal(second.status, 'busy'); assert.equal(second.stop, true);
  releaseFetch(); assert.equal((await first).status, 'initialized');
});

test('a partially written lock stops the command before any release or scan work', async t => {
  const f = await fixture(t); await writeFile(path.join(f.root, '.skill-update.lock'), '');
  const result = await f.run(); assert.equal(result.status, 'busy'); assert.equal(result.stop, true); assert.equal(f.server.requests.length, 0);
});

test('check-only mode and offline previews make no installation changes', async t => {
  const f = await fixture(t); await f.run(); f.newer('1.1.0', files('1.1.0'));
  assert.equal((await f.run({ mode: 'check' })).status, 'update_available');
  await assert.rejects(access(path.join(f.root, '.skill-updates')), { code: 'ENOENT' });
  const result = await updateBeforeRun('offense', new URL('../scripts/offense.mjs', import.meta.url), { preview: true, fetchImpl: () => assert.fail('Preview contacted update server') });
  assert.equal(result.status, 'offline_preview');
});

test('an unavailable update endpoint reports failure without changing installed files', async t => {
  const f = await fixture(t);
  const result = await f.run({ fetchImpl: async () => { throw Error('network unavailable'); } });
  assert.equal(result.status, 'check_failed'); assert.equal(result.stop, false); assert.match(result.message, /network unavailable/);
  assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0'));
});

test('published source artifacts in a repository never self-update or acquire installation receipts', async t => {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'purple-updater-source-')); t.after(() => rm(outer, { recursive: true, force: true }));
  const root = path.join(outer, 'public/skills/offense'); await mkdir(root, { recursive: true }); await mkdir(path.join(outer, '.git'));
  await writeFile(path.join(root, 'SKILL.md'), skillText('1.0.0'));
  const result = await checkSkillUpdates({ skill: 'offense', root, automatic: true, fetchImpl: () => assert.fail('Source artifact checked for client updates') });
  assert.equal(result.status, 'not_installed'); await assert.rejects(access(path.join(root, INSTALL_RECORD)), { code: 'ENOENT' });
});

test('version rollback and reused release numbers do not silently replace a skill', async t => {
  const f = await fixture(t); await f.run();
  f.newer('0.9.0', files('0.9.0')); assert.equal((await f.run()).status, 'server_older');
  f.newer('1.0.0', { ...files('1.0.0'), 'references/install.md': 'Different bytes without a version bump' });
  const collision = await f.run(); assert.equal(collision.status, 'check_failed'); assert.match(collision.message, /without a version bump/);
});

for (const unsafe of ['../AGENTS.md', '/tmp/escape.mjs', 'scripts/../../.codex/config.toml', 'scripts/hidden\\file.mjs', '.env', 'references/.hidden.md']) {
  test(`manifest cannot write an unrelated or escaping path: ${unsafe}`, async t => {
    const f = await fixture(t); f.newer('1.1.0', files('1.1.0'));
    f.server.manifest.files.push({ path: unsafe, bytes: 1, sha256: digest('x') });
    assert.equal((await f.run()).status, 'check_failed'); assert.equal(f.server.requests.length, 1);
    assert.equal(await readFile(path.join(f.root, 'SKILL.md'), 'utf8'), skillText('1.0.0'));
  });
}

for (const target of ['SKILL.md', 'references', '.skill-install.json', '.skill-updates']) {
  test(`symlinked managed file or update directory is refused: ${target}`, async t => {
    const f = await fixture(t); await f.run(); f.newer('1.1.0', files('1.1.0'));
    const outside = path.join(f.outer, 'outside'); await mkdir(outside); await writeFile(path.join(outside, 'sentinel'), 'unchanged');
    await rm(path.join(f.root, target), { recursive: true, force: true });
    await symlink(target === 'SKILL.md' || target === '.skill-install.json' ? path.join(outside, 'sentinel') : outside, path.join(f.root, target));
    assert.equal((await f.run()).status, 'check_failed');
    assert.equal(await readFile(path.join(outside, 'sentinel'), 'utf8'), 'unchanged');
  });
}

test('a CLI update stops before metadata collection and never executes downloaded helper code', async t => {
  const compiled = await readFile('public/skills/offense/scripts/offense.mjs', 'utf8');
  const f = await fixture(t, { ...files('1.0.0'), 'scripts/offense.mjs': compiled }); await f.run();
  const marker = path.join(f.outer, 'downloaded-code-ran');
  const next = { ...files('1.1.0'), 'scripts/offense.mjs': `import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(marker)},'executed');\n` };
  f.newer('1.1.0', next, [['1.0.0', { ...files('1.0.0'), 'scripts/offense.mjs': compiled }]]);
  const bootstrap = path.join(f.outer, 'fetch-fixture.mjs'), requests = path.join(f.outer, 'requests.jsonl');
  await writeFile(bootstrap, `import{appendFileSync}from'node:fs';const manifest=${JSON.stringify(f.server.manifest)},files=${JSON.stringify(next)};globalThis.fetch=async(url,options)=>{appendFileSync(${JSON.stringify(requests)},JSON.stringify({url:String(url),method:options.method,hasBody:!!options.body})+'\\n');const file=String(url).split('/skills/offense/')[1];if(file==='manifest.json')return Response.json(manifest);if(Object.hasOwn(files,file))return new Response(files[file]);throw Error('Unexpected request');};\n`);
  await assert.rejects(execute(process.execPath, ['--import', bootstrap, path.join(f.root, 'scripts/offense.mjs'), 'metadata', f.outer], { cwd: f.outer }), error => {
    assert.equal(error.code, 4); assert.match(error.stderr, /Start a new coding-agent session/); assert.equal(error.stdout, ''); return true;
  });
  await assert.rejects(access(marker), { code: 'ENOENT' });
  const calls = (await readFile(requests, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
  assert.ok(calls.length > 1); assert.ok(calls.every(call => call.method === 'GET' && !call.hasBody && call.url.startsWith('https://app.purpleteam.sh/skills/offense/')));
});

for (const [entry, args] of [['purple.mjs', ['triage', '/nonexistent-fixture', '--scan', '/missing-scan.json']], ['hosted-scan.mjs', ['/nonexistent-fixture']], ['hosted-assessment.mjs', ['--tool', 'checkov', '--project', '/nonexistent-fixture', '--run']], ['hardened-image.mjs', ['--project', '/nonexistent-fixture', '--image', 'gcr.io/distroless/nodejs24-debian13:nonroot', '--platform', 'linux/amd64', '--pull']]]) {
  test(`Purple ${entry} stops before local review or source upload when a skill update applies`, async t => {
    const current = Object.fromEntries(await Promise.all(SKILL_FILES.purple.map(async file => [file, await readFile('public/skills/purple/' + file, 'utf8')])));
    const version = current['SKILL.md'].match(/version:\s*"([^"]+)"/)[1], parts = version.split('.').map(Number);
    parts[2]++; const nextVersion = parts.join('.');
    const f = await fixture(t, current, 'purple'); f.newer(version, current, []); assert.equal((await f.run()).status, 'initialized');
    const next = { ...current, 'SKILL.md': current['SKILL.md'].replace(`version: "${version}"`, `version: "${nextVersion}"`) };
    f.newer(nextVersion, next, [[version, current]]);
    const bootstrap = path.join(f.outer, 'fetch-fixture.mjs'), requests = path.join(f.outer, 'requests.jsonl');
    await writeFile(bootstrap, `import{appendFileSync}from'node:fs';const manifest=${JSON.stringify(f.server.manifest)},files=${JSON.stringify(next)};globalThis.fetch=async(url,options)=>{appendFileSync(${JSON.stringify(requests)},JSON.stringify({url:String(url),method:options.method,hasBody:!!options.body})+'\\n');const file=String(url).split('/skills/purple/')[1];if(file==='manifest.json')return Response.json(manifest);if(Object.hasOwn(files,file))return new Response(files[file]);throw Error('Unexpected request');};\n`);
    await assert.rejects(execute(process.execPath, ['--import', bootstrap, path.join(f.root, 'scripts', entry), ...args], { cwd: f.outer }), error => {
      assert.equal(error.code, 4); assert.match(error.stderr, /Start a new coding-agent session/); assert.equal(error.stdout, ''); return true;
    });
    const calls = (await readFile(requests, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    assert.ok(calls.every(call => call.method === 'GET' && !call.hasBody && call.url.startsWith('https://app.purpleteam.sh/skills/purple/')));
  });
}

test('published manifests match every packaged resource and the declared skill versions', async () => {
  for (const [skill, paths] of Object.entries(SKILL_FILES)) {
    const manifest = JSON.parse(await readFile(`public/skills/${skill}/manifest.json`, 'utf8'));
    assert.deepEqual(manifest.files.map(file => file.path), paths);
    for (const file of manifest.files) {
      const bytes = await readFile(`public/skills/${skill}/${file.path}`);
      assert.equal(bytes.length, file.bytes); assert.equal(digest(bytes), file.sha256);
    }
    const text = await readFile(`public/skills/${skill}/SKILL.md`, 'utf8');
    assert.ok(text.includes(`version: "${manifest.version}"`));
  }
});
