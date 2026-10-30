import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { isZizmorInput, runZizmor, ZIZMOR_VERSION } from '../agent/zizmor.mjs';

async function fixture(callback, files = { '.github/workflows/ci.yml': 'name: fixture\non: push\njobs: {}\n' }) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-zizmor-test-'));
  try {
    for (const [name, content] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true });
      await writeFile(path.join(root, name), content);
    }
    return await callback(root, Object.keys(files));
  } finally { await rm(root, { recursive: true, force: true }); }
}

function finding(root, { file = '.github/workflows/ci.yml', rule = 'template-injection', row = 7 } = {}) {
  return { ident: rule, desc: 'PRIVATE_SOURCE_EMAIL alice@example.invalid',
    determinations: { severity: 'High', confidence: 'High', persona: 'Regular' },
    ignored: true, fixes: [{ title: 'PRIVATE_TOKEN_FAMILY', replacement: 'PRIVATE_SOURCE' }],
    locations: [{ symbolic: { kind: 'Related', key: { Local: { verbatim_path: path.join(root, file) } }, annotation: 'PRIVATE_SOURCE' },
      concrete: { location: { start_point: { row: 1 } }, feature: 'PRIVATE_SOURCE' } },
    { symbolic: { kind: 'Primary', key: { Local: { verbatim_path: path.join(root, file) } }, annotation: 'PRIVATE_SOURCE' },
      concrete: { location: { start_point: { row } }, feature: 'PRIVATE_SOURCE', comments: ['PRIVATE_SOURCE'] } }] };
}

test('Zizmor selects only root workflows and action definitions', () => {
  for (const name of ['.github/workflows/ci.yml', '.github/workflows/release.yaml', 'action.yml', '.github/actions/test/action.yaml'])
    assert.equal(isZizmorInput(name), true, name);
  for (const name of ['.github/workflows/nested/ci.yml', 'vendor/project/.github/workflows/ci.yml', 'package.json', 'zizmor.yml',
    '../action.yml', '/tmp/action.yml', './action.yml', 'a\\action.yml', 'a/../action.yml'])
    assert.equal(isZizmorInput(name), false, name);
});

test('Zizmor normalizes primary location and only persists constructed diagnostic text', async () => fixture(async (root, files) => {
  const reportPath = path.join(root, 'normalized.json');
  let observedWork;
  const checked = await runZizmor({ root, files, reportPath, execute: (binary, args, options) => {
    assert.equal(binary, '/usr/local/bin/zizmor');
    for (const flag of ['--offline', '--no-config', '--no-ignores', '--strict-collection', '--format=json-v1', '--no-exit-codes'])
      assert.ok(args.includes(flag), flag);
    assert.ok(!args.some(arg => arg.startsWith('--fix') || arg.includes('token')));
    assert.equal(args.at(-1), path.join(root, files[0]));
    assert.equal(args.at(-2), '--');
    assert.equal(options.shell, undefined);
    assert.equal(options.timeout, 120000);
    assert.equal(options.killSignal, 'SIGKILL');
    assert.equal(options.env.GITHUB_TOKEN, undefined);
    assert.equal(options.env.GH_TOKEN, undefined);
    assert.equal(options.env.ZIZMOR_CONFIG, undefined);
    assert.equal(options.env.ZIZMOR_OFFLINE, '1');
    observedWork = options.cwd;
    assert.notEqual(observedWork, root);
    return { status: 0, stdout: JSON.stringify([finding(root)]), stderr: 'PRIVATE_PROVIDER_ERROR alice@example.invalid' };
  } });
  assert.equal(checked.status, 'complete');
  assert.equal(checked.version, ZIZMOR_VERSION);
  assert.equal(checked.coverage.offlineAuditsOnly, true);
  assert.equal(checked.findings[0].file, '.github/workflows/ci.yml');
  assert.equal(checked.findings[0].line, 8);
  assert.equal(checked.findings[0].severity, 'HIGH');
  assert.equal(checked.findings[0].confidence, 'high');
  assert.equal(checked.findings[0].verification, 'scanner_finding');
  assert.ok(checked.findings[0].remediation.includes('environment variables'));
  for (const text of [JSON.stringify(checked), await readFile(reportPath, 'utf8')])
    for (const canary of ['PRIVATE_', 'alice@example.invalid', 'fixes', 'ignored']) assert.ok(!text.includes(canary), canary);
  await assert.rejects(readFile(observedWork), { code: 'ENOENT' });
}));

test('Zizmor marks no applicable files partial and never invokes a scanner', async () => {
  const checked = await runZizmor({ root: '/tmp', files: ['src/app.js'], execute: () => { throw Error('must not run'); } });
  assert.equal(checked.status, 'partial');
  assert.equal(checked.coverage.eligibleFiles, 0);
  assert.equal(checked.findings.length, 0);
});

test('Zizmor distinguishes malformed inputs, scanner failure, no collection and an invalid clean report', async () => fixture(async (root, files) => {
  for (const [response, expected] of [
    [{ status: 1, stdout: '', stderr: 'PRIVATE_YAML_ERROR' }, 'partial'],
    [{ status: 1, stdout: '[]' }, 'partial'],
    [{ status: 3, stdout: '' }, 'partial'],
    [{ status: 2, stdout: '[]' }, 'failed'],
    [{ status: 0, stdout: 'PRIVATE_INVALID_REPORT' }, 'failed'],
    [{ status: 0, stdout: '{}' }, 'failed'],
    [{ status: null, error: Object.assign(new Error('PRIVATE_TIMEOUT'), { code: 'ETIMEDOUT' }) }, 'failed'],
    [{ status: 0, signal: 'SIGKILL', stdout: '[]' }, 'failed']
  ]) {
    const checked = await runZizmor({ root, files, execute: () => response });
    assert.equal(checked.status, expected);
    assert.equal(checked.findings.length, 0);
    assert.ok(!JSON.stringify(checked).includes('PRIVATE_'));
  }
}));

test('Zizmor never declares complete when a finding has an unknown rule or external location', async () => fixture(async (root, files) => {
  for (const item of [finding(root, { rule: 'unrecognized-private-value' }), finding(root, { file: '../outside.yml' }),
    { ...finding(root), locations: [{ symbolic: { key: { Remote: { url: 'https://private.invalid/workflow' } } } }] }]) {
    const checked = await runZizmor({ root, files, execute: () => ({ status: 0, stdout: JSON.stringify([item]) }) });
    assert.equal(checked.status, 'partial');
    assert.equal(checked.findings.length, 0);
    assert.ok(!JSON.stringify(checked).includes('private-value'));
    assert.ok(!JSON.stringify(checked).includes('private.invalid'));
  }
}));

test('Zizmor bounds normalized findings, deduplicates locations, and flags report truncation', async () => fixture(async (root, files) => {
  const rows = Array.from({ length: 501 }, (_, row) => finding(root, { row }));
  const checked = await runZizmor({ root, files, execute: () => ({ status: 0, stdout: JSON.stringify([...rows, rows[0]]) }) });
  assert.equal(checked.status, 'partial');
  assert.equal(checked.findings.length, 500);
  const repeated = await runZizmor({ root, files, execute: () => ({ status: 0, stdout: JSON.stringify([rows[0], rows[0]]) }) });
  assert.equal(repeated.status, 'complete');
  assert.equal(repeated.findings.length, 1);
  assert.equal(repeated.findings[0].line, 1);
}));

test('Zizmor rejects unsafe paths and missing or symlinked staged files', async () => fixture(async (root, files) => {
  for (const unsafe of [['../action.yml'], ['/tmp/action.yml'], ['.github/workflows/ci.yml\n'], [...files, ...files]])
    await assert.rejects(runZizmor({ root, files: unsafe }), /staged absolute root/);
  const execute = () => { throw Error('must not run'); };
  const missingRoot = await runZizmor({ root: path.join(root, 'missing-root'), files, execute });
  assert.equal(missingRoot.status, 'failed');
  const missing = await runZizmor({ root, files: ['action.yml'], execute });
  assert.equal(missing.status, 'failed');
  await symlink(path.join(root, files[0]), path.join(root, 'action.yml'));
  const linked = await runZizmor({ root, files: ['action.yml'], execute });
  assert.equal(linked.status, 'failed');
}));

const realBinary = process.env.PURPLE_ZIZMOR_BINARY;
test('pinned real Zizmor catches unsafe workflows and actions, honors no project suppressions, and accepts a safe control',
  { skip: !realBinary }, async () => {
    assert.equal(spawnSync(realBinary, ['--version'], { encoding: 'utf8' }).stdout.trim(), `zizmor ${ZIZMOR_VERSION}`);
    const unsafe = `name: Unsafe fixture\non: pull_request_target\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n      - run: echo "\${{ github.event.pull_request.title }}" # zizmor: ignore[template-injection]\n`;
    const safe = `name: Safe fixture\non: pull_request\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Print the title as data\n        env:\n          PR_TITLE: \${{ github.event.pull_request.title }}\n        run: printf '%s\\n' "$PR_TITLE"\n`;
    const action = `name: Unsafe action\ndescription: Fixture action\ninputs:\n  message:\n    description: User supplied text\n    required: true\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo "\${{ inputs.message }}"\n`;
    await fixture(async (root, files) => {
      const checked = await runZizmor({ root, files, executable: realBinary });
      assert.equal(checked.status, 'complete');
      const found = new Set(checked.findings.filter(item => item.file.endsWith('unsafe.yml')).map(item => item.ruleId));
      for (const rule of ['template-injection', 'dangerous-triggers', 'unpinned-uses']) assert.ok(found.has(rule), rule);
      assert.ok(checked.findings.some(item => item.file === 'fixtures/action.yml' && item.ruleId === 'template-injection'));
      assert.ok(!checked.findings.some(item => item.file.endsWith('safe.yml') && !item.file.endsWith('unsafe.yml')));
      assert.equal(await readFile(path.join(root, '.github/workflows/unsafe.yml'), 'utf8'), unsafe);
      const safeOnly = await runZizmor({ root, files: ['.github/workflows/safe.yml'], executable: realBinary });
      assert.equal(safeOnly.status, 'complete');
      assert.equal(safeOnly.findings.length, 0);
      await writeFile(path.join(root, '.github/workflows/broken.yml'), 'jobs: [bad yaml\n');
      const broken = await runZizmor({ root, files: ['.github/workflows/broken.yml'], executable: realBinary });
      assert.equal(broken.status, 'partial');
      assert.equal(broken.findings.length, 0);
    }, { '.github/workflows/unsafe.yml': unsafe, '.github/workflows/safe.yml': safe, 'fixtures/action.yml': action,
      'zizmor.yml': 'rules:\n  template-injection:\n    disable: true\n', '.gitignore': '*\n' });
  });
