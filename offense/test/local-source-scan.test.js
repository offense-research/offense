import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, stat } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { localSourceScan, collectLocalSource } from '../tools/source-scan.mjs';
import { normalizeFindings } from '../tools/internal/scan-findings.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-local-source-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo'); await mkdir(repo);
  return { root, repo, output: path.join(root, 'report') };
}
const source = () => ({ files: [{ path: 'src/app.js', content: 'eval(request.input)' }], omitted: [], bytes: 19, scope: 'Synthetic tracked source fixture.' });

test('local source preview lists scoped tracked files without executing scanners or uploading source', async t => {
  const f = await fixture(t);
  execFileSync('git', ['init', '-q', f.repo]);
  await mkdir(path.join(f.repo, 'src'));
  await writeFile(path.join(f.repo, 'src/app.js'), 'const value = "PRIVATE_SOURCE_CANARY";');
  await writeFile(path.join(f.repo, '.env'), 'SECRET=PRIVATE_SOURCE_CANARY');
  await writeFile(path.join(f.repo, 'untracked.py'), 'PRIVATE_SOURCE_CANARY');
  execFileSync('git', ['-C', f.repo, 'add', '--', 'src/app.js', '.env']);
  const report = await localSourceScan(f.repo, { preview: true, execute() { throw Error('Scanner must not run'); } });
  assert.deepEqual(report.files, ['src/app.js']);
  assert.equal(report.sourceUpload, false); assert.equal(report.executesApplication, false);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
  assert.ok(report.omitted.some(file => file.path === '.env'));
  const collected = await collectLocalSource(f.repo, ['zizmor']); assert.equal(collected.files.length, 0);
});

test('local source scan runs fixed operator rules, filters snippets, and writes private reports outside checkout', async t => {
  const f = await fixture(t); let scans = 0;
  const result = await localSourceScan(f.repo, { tools: ['opengrep'], output: f.output, collect: source,
    execute(binary, args, options) {
      assert.equal(binary, 'opengrep'); assert.equal(options.env.OPENROUTER_API_KEY, undefined);
      if (args[0] === '--version') return { status: 0, stdout: '1.32.0\n' };
      scans++; assert.ok(args.includes('--taint-intrafile')); assert.ok(args.includes('--disable-nosem'));
      assert.equal(options.stdio[1], 'ignore');
      const root = args.at(-1);
      writeFileSync(args[args.indexOf('--output') + 1], JSON.stringify({ results: [{ check_id: 'purple.js.dynamic-eval',
        path: path.join(root, 'src/app.js'), start: { line: 1 }, extra: { severity: 'WARNING', message: 'Dynamic evaluation needs review.',
          lines: 'PRIVATE_SOURCE_CANARY', metavars: { value: 'PRIVATE_SOURCE_CANARY' }, dataflow_trace: ['PRIVATE_SOURCE_CANARY'] } }], errors: [] }));
      return { status: 0 };
    } });
  assert.equal(scans, 1); assert.equal(result.status, 'completed'); assert.equal(result.confirmedVulnerabilities, 0);
  const report = await readFile(result.json, 'utf8'); assert.ok(!report.includes('PRIVATE_SOURCE_CANARY'));
  assert.equal(JSON.parse(report).findings[0].file, 'src/app.js');
  assert.equal((await stat(result.json)).mode & 0o777, 0o600);
});

test('missing or wrong pinned tools and parser failures remain explicit incomplete outcomes', async t => {
  const f = await fixture(t);
  const missing = await localSourceScan(f.repo, { tools: ['opengrep'], output: f.output, collect: source,
    execute() { return { status: 0, stdout: '1.31.0\n' }; } });
  assert.equal(missing.status, 'failed');
  assert.equal(JSON.parse(await readFile(missing.json)).tools[0].error, 'pinned_tool_unavailable');
  const partial = await localSourceScan(f.repo, { tools: ['opengrep'], output: f.output, collect: source,
    execute(_binary, args) {
      if (args[0] === '--version') return { status: 0, stdout: '1.32.0' };
      writeFileSync(args[args.indexOf('--output') + 1], JSON.stringify({ results: [], errors: [{ message: 'PRIVATE_ERROR_CANARY' }] }));
      return { status: 0 };
    } });
  assert.equal(partial.status, 'partial'); assert.ok(!(await readFile(partial.json, 'utf8')).includes('PRIVATE_ERROR_CANARY'));
});

test('local report export rejects symlinks and checkout paths without overwriting unrelated files', async t => {
  const f = await fixture(t), protectedFile = path.join(f.root, 'protected.json');
  await writeFile(protectedFile, 'keep'); await mkdir(f.output);
  await symlink(protectedFile, path.join(f.output, 'scan.json'));
  const options = { tools: ['opengrep'], collect: source, execute() { return { status: 1 }; } };
  await assert.rejects(localSourceScan(f.repo, { ...options, output: f.output }), /regular file/);
  assert.equal(await readFile(protectedFile, 'utf8'), 'keep');
  await assert.rejects(localSourceScan(f.repo, { ...options, output: path.join(f.repo, 'report') }), /outside/);
  await assert.rejects(stat(path.join(f.repo, 'report')), { code: 'ENOENT' });
});

test('tracked symlinks cannot expose files outside the local scan root', async t => {
  const f = await fixture(t);
  execFileSync('git', ['init', '-q', f.repo]);
  await writeFile(path.join(f.root, 'outside.js'), 'PRIVATE_SOURCE_CANARY');
  await symlink(path.join(f.root, 'outside.js'), path.join(f.repo, 'link.js'));
  execFileSync('git', ['-C', f.repo, 'add', 'link.js']);
  const result = await collectLocalSource(f.repo);
  assert.equal(result.files.length, 0); assert.equal(result.omitted[0].reason, 'missing_symlink_or_non_file');
  assert.ok(!JSON.stringify(result).includes('PRIVATE_SOURCE_CANARY'));
});

test('omitted supported inputs prevent a complete local scan even when a scanner succeeds', async t => {
  const f = await fixture(t);
  const result = await localSourceScan(f.repo, { tools: ['opengrep'], output: f.output,
    collect: () => ({ ...source(), omitted: [{ path: 'missing.py', reason: 'missing_symlink_or_non_file' }] }),
    execute(_binary, args) {
      if (args[0] === '--version') return { status: 0, stdout: '1.32.0' };
      writeFileSync(args[args.indexOf('--output') + 1], JSON.stringify({ results: [], errors: [] }));
      return { status: 0 };
    } });
  assert.equal(result.status, 'partial');
  assert.equal(JSON.parse(await readFile(result.json)).coverage.incompleteSource, true);
});

test('temporary operator config prefixes do not change a finding identity or expose local directories', () => {
  const normalized = prefix => normalizeFindings('opengrep', { results: [{ check_id: `${prefix}.purple.js.request-sql-injection`,
    path: 'app.js', start: { line: 4 }, extra: { severity: 'ERROR', message: 'Request data reaches SQL.' } }] });
  const one = normalized('private.directory.run-one'), two = normalized('other.directory.run-two');
  assert.equal(one[0].ruleId, 'purple.js.request-sql-injection'); assert.equal(one[0].id, two[0].id);
  assert.ok(!JSON.stringify(one).includes('private.directory'));
});
