// Secret-free acceptance of the real repair/verifier/export/publisher pipeline.
// Only advisory intelligence, model responses and GitHub transport are synthetic.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const sourceFile = 'src/dependency-acceptance.cjs';
const testFile = 'test/dependency-acceptance-fixture.test.js';
const repaired = "const _ = require('lodash'); module.exports = items => _.map(items, 'name');\n";
const cleanEnv = () => ({ PATH: process.env.PATH, HOME: process.env.HOME, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
  npm_config_userconfig: '/dev/null', npm_config_registry: 'https://registry.npmjs.org/' });
async function command(argv, { cwd, input, timeout = 30 * 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env: cleanEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.on('data', chunk => { output = (output + chunk).slice(-100000); });
    child.stderr.on('data', chunk => process.stderr.write(chunk));
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${argv[0]} failed (${code}): ${output.slice(-3000)}`));
      else resolve(output.trim());
    });
    child.stdin.on('error', () => {}); child.stdin.end(input || '');
  });
}

async function syntheticModel() {
  const calls = [], errors = [];
  const actions = [
    ['purple_write_file', { path: testFile, content: 'weakened test' }],
    ['purple_write_file', { path: '.github/offense/dependency-policy.json', content: '{"checks":[]}' }],
    ['purple_write_file', { path: sourceFile, content: repaired }]
  ];
  const server = createServer(async (request, response) => {
    try {
      if (request.url.includes('/models')) {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ data: [{ id: 'purple-smoke', context_length: 64000 }] })); return;
      }
      assert.equal(request.url, '/v1/chat/completions');
      let raw = ''; for await (const chunk of request) { raw += chunk; assert.ok(raw.length < 2_000_000); }
      const body = JSON.parse(raw); calls.push(body);
      assert.deepEqual(body.tools.map(tool => tool.function.name).sort(), ['purple_list_files', 'purple_patch_file', 'purple_read_file', 'purple_write_file']);
      const action = actions[calls.length - 1];
      const tool = action && { id: `call_${calls.length}`, type: 'function', function: { name: action[0], arguments: JSON.stringify(action[1]) } };
      const message = tool ? { role: 'assistant', content: null, tool_calls: [tool] } : { role: 'assistant', content: 'Source repaired. Independent checks are still required.' };
      const usage = { prompt_tokens: 100, completion_tokens: 10, total_tokens: 110, cost: 0 };
      if (body.stream) {
        response.setHeader('content-type', 'text/event-stream');
        const chunk = delta => ({ id: `synthetic_${calls.length}`, object: 'chat.completion.chunk', created: 1, model: 'purple-smoke', choices: [{ index: 0, delta, finish_reason: null }] });
        response.write(`data: ${JSON.stringify(chunk(tool ? { role: 'assistant', tool_calls: [{ index: 0, ...tool }] } : message))}\n\n`);
        const end = chunk({}); end.choices[0].finish_reason = tool ? 'tool_calls' : 'stop'; end.usage = usage;
        response.end(`data: ${JSON.stringify(end)}\n\ndata: [DONE]\n\n`);
      } else {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ id: `synthetic_${calls.length}`, object: 'chat.completion', created: 1, model: 'purple-smoke', choices: [{ index: 0, message, finish_reason: tool ? 'tool_calls' : 'stop' }], usage }));
      }
    } catch (error) { errors.push(error); response.statusCode = 500; response.end('Synthetic assertion failed.'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { endpoint: `http://127.0.0.1:${server.address().port}/v1`, calls, errors,
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}

async function insideImage(input) {
  const { ciServices } = await import('./dependency-services.mjs');
  const { collectMetadata } = await import('../../offense/tools/purple.mjs');
  const { runDependencyFix, verifyDependencyFix } = await import('../../agent/dependency-fix.mjs');
  const { runHermesTask, HERMES_REVISION } = await import('../../agent/hermes-runtime.mjs');
  const { prepareArtifactOwnership, restoreArtifactOwnership } = await import('../../agent/artifact-ownership.mjs');
  const { reapRepositoryProcesses } = await import('../../agent/repository-isolation.mjs');
  const { exportBundle } = await import('./dependency-bundle.mjs');
  assert.equal(process.env.PURPLE_FIX_ISOLATE_COMMANDS, '1');
  for (const name of ['GH_TOKEN', 'GITHUB_TOKEN', 'OFFENSE_AGENT_MODEL_KEY', 'OPENROUTER_API_KEY']) assert.equal(process.env[name], undefined);
  await prepareArtifactOwnership(input.output);
  let model;
  try {
    const services = await ciServices();
    const finding = { id: 'GHSA-synthetic-acceptance', package: 'lodash', version: '4.17.20', severity: 'HIGH', summary: 'Synthetic acceptance advisory, not live security evidence' };
    // Keep real coverage/registry validation in services.collectMetadata. Only
    // the external advisory answer is deterministic, independent of OSV changes.
    services.analyze = async directory => {
      const metadata = await collectMetadata(directory);
      const lock = JSON.parse(await readFile(path.join(directory, 'package-lock.json')));
      const old = lock.packages['node_modules/lodash'].version === '4.17.20';
      return { repositoryRevision: input.revision, metadataFingerprint: metadata.fingerprint, warnings: [],
        vulnerabilityCheck: { status: 'complete', checkedAt: Date.now(), findings: old ? [finding] : [] },
        plans: old ? [{ name: 'lodash', currentVersion: '4.17.20', targetVersion: '4.17.21', considered: [{ version: '4.17.21', advisories: 0 }], parentOptions: [] }] : [] };
    };
    let report, feedback;
    if (input.mode === 'repair') {
      const scanFile = path.join(input.output, 'scan.json');
      await writeFile(scanFile, JSON.stringify(await services.analyze(input.directory)));
      model = await syntheticModel();
      services.agent = async request => {
        feedback = request.feedback.candidate;
        services.validateVerification(feedback);
        assert.equal(feedback.checks.filter(check => !check.passed).length, 1, 'exactly the planted compatibility test must fail');
        assert.match(feedback.checks.find(check => !check.passed).output, /synthetic patch compatibility/);
        return runHermesTask(request);
      };
      report = await runDependencyFix({ directory: input.directory, output: input.output, scanFile, repository: input.repository,
        sandboxed: true, model: 'purple-smoke', apiKey: 'synthetic-acceptance-key', modelEndpoint: model.endpoint,
        maxAttempts: 1, maxTurns: 8, commandTimeoutMs: 180000, maxDurationMs: 30 * 60000 }, services);
      assert.equal(report.status, 'ready_for_review', JSON.stringify(report.blockers));
      assert.equal(report.attempts.length, 1, 'must actually repair, not take the no-model path');
      assert.equal(report.runtime.revision, HERMES_REVISION);
      assert.equal(model.calls.length, 4); assert.deepEqual(model.errors, []);
      const replies = model.calls.at(-1).messages.filter(message => message.role === 'tool');
      for (const id of ['call_1', 'call_2']) assert.match(replies.find(reply => reply.tool_call_id === id)?.content || '', /read-only|outside the allowed code surface/, 'both test and policy edits must be denied');
      await writeFile(path.join(input.output, 'failed-candidate.json'), JSON.stringify(feedback));
    } else {
      assert.equal(input.mode, 'verify');
      report = await verifyDependencyFix({ reportFile: path.join(input.output, 'fix.json'), output: path.join(input.output, 'verification-ci'), sandboxed: true, commandTimeoutMs: 180000 }, services);
      assert.equal(report.status, 'ready_for_review', JSON.stringify(report.blockers));
      assert.ok(report.reverifiedFrom);
      Object.assign(process.env, { GITHUB_REPOSITORY: input.repository, GITHUB_RUN_ID: input.runId, OFFENSE_ENGINE_SHA: input.engineSha });
      await exportBundle(report.evidencePath, path.join(input.output, 'bundle.json'));
    }
    assert.equal(report.publishEligible, true);
    for (const phase of [report.baseline, report.candidate]) {
      services.validateVerification(phase);
      assert.equal(phase.integrity, true);
      assert.ok([...phase.setup, ...phase.checks].every(check => check.passed && !check.timedOut && !check.signal));
    }
    for (const file of [testFile, '.github/offense/dependency-policy.json']) {
      assert.deepEqual(await readFile(path.join(report.sourceDirectory, file)), await readFile(path.join(report.candidateDirectory, file)));
    }
    assert.equal(await readFile(path.join(report.candidateDirectory, sourceFile), 'utf8'), repaired);
    console.log(JSON.stringify({ mode: input.mode, status: report.status, installsPerCheckout: report.baseline.setup.length, checksPerCheckout: report.baseline.checks.length, modelCalls: model?.calls.length || 0 }));
  } finally {
    await model?.close(); await reapRepositoryProcesses();
    await restoreArtifactOwnership({ output: input.output, uid: input.uid, gid: input.gid });
  }
}

async function stubPublish(bundle, originalManifest, expected) {
  const { publishBundle } = await import('./publish-dependency-pr.mjs');
  const { loadPolicy, digest } = await import('./dependency-policy.mjs');
  const policy = await loadPolicy(), calls = [], blobs = new Map();
  const prefix = `/repos/${bundle.repository}`;
  const api = async (method, endpoint, body) => {
    calls.push({ method, endpoint, body });
    if (method === 'GET' && endpoint === prefix) return { default_branch: 'main', owner: { login: 'acceptance' }, html_url: 'https://github.invalid/acceptance/fixture' };
    if (method === 'GET' && endpoint === `${prefix}/git/ref/heads/main`) return { object: { sha: bundle.baseSha } };
    if (method === 'GET' && endpoint === `${prefix}/contents/package.json?ref=${bundle.baseSha}`) return { content: originalManifest.toString('base64') };
    if (method === 'GET' && endpoint.startsWith(`${prefix}/pulls?`)) return [];
    if (method === 'GET' && endpoint === `${prefix}/git/commits/${bundle.baseSha}`) return { tree: { sha: 'base-tree' } };
    if (method === 'POST' && endpoint === `${prefix}/git/blobs`) { const sha = digest(body.content); blobs.set(sha, body.content); return { sha }; }
    if (method === 'POST' && endpoint === `${prefix}/git/trees`) {
      assert.equal(body.base_tree, 'base-tree');
      assert.deepEqual(body.tree.map(file => ({ path: file.path, content: blobs.get(file.sha), mode: file.mode })), bundle.changes.map(({ path, content, mode }) => ({ path, content, mode })));
      return { sha: 'candidate-tree' };
    }
    if (method === 'POST' && endpoint === `${prefix}/git/commits`) { assert.equal(body.tree, 'candidate-tree'); assert.deepEqual(body.parents, [bundle.baseSha]); return { sha: 'candidate-commit' }; }
    if (method === 'POST' && endpoint === `${prefix}/git/refs`) { assert.equal(body.sha, 'candidate-commit'); return {}; }
    if (method === 'POST' && endpoint === `${prefix}/pulls`) { assert.equal(body.draft, true); assert.equal(body.base, 'main'); return { html_url: 'https://github.invalid/acceptance/fixture/pull/1' }; }
    throw new Error(`Unexpected publisher request: ${method} ${endpoint}`);
  };
  for (const mutate of [copy => { copy.runId += '-wrong'; }, copy => { copy.changes[0].content = Buffer.from('tampered').toString('base64'); }, copy => { copy.evidence.candidatePassed = false; }]) {
    const bad = structuredClone(bundle); mutate(bad);
    await assert.rejects(publishBundle(bad, { policy, api, expected }));
    assert.equal(calls.length, 0, 'invalid bundles must fail before API access');
  }
  assert.equal(await publishBundle(bundle, { policy, api, expected }), 'https://github.invalid/acceptance/fixture/pull/1');
  assert.equal(calls.filter(call => call.method === 'POST' && call.endpoint === `${prefix}/pulls`).length, 1);
  return { draft: true, changedFiles: bundle.changes.map(change => change.path), rejectedBundles: 3, githubTransport: 'stub' };
}

async function host() {
  const args = process.argv.slice(2), option = name => args[args.indexOf(name) + 1];
  assert.ok(args.includes('--image') && args.includes('--output'), 'Provide --image and --output for bounded reports.');
  const image = option('--image'), evidence = path.resolve(option('--output'));
  const { prepareSnapshot, prepareVerification, dockerArguments } = await import('../offense.mjs');
  const root = await mkdtemp(path.join(tmpdir(), 'offense-acceptance-'));
  const fixture = path.join(root, 'fixture'), output = path.join(root, 'job');
  await mkdir(evidence, { recursive: true });
  const engineSha = await command(['git', 'rev-parse', 'HEAD']);
  const expected = { repository: 'acceptance/fixture', runId: 'synthetic-acceptance', engineSha };
  try {
    assert.equal(await command(['git', 'status', '--porcelain', '--untracked-files=all']), '', 'Commit the controller and checks before building/running acceptance.');
    await command(['git', 'clone', '--quiet', '--no-hardlinks', '--', process.cwd(), fixture]);
    await command(['npm', 'install', '--package-lock-only', '--save-exact', '--ignore-scripts', '--no-audit', '--no-fund', 'lodash@4.17.20'], { cwd: fixture });
    await writeFile(path.join(fixture, sourceFile), "const _ = require('lodash'); module.exports = items => _.VERSION === '4.17.20' ? _.map(items, 'name') : [];\n");
    await writeFile(path.join(fixture, testFile), `import test from 'node:test';
import assert from 'node:assert/strict';
import names from '../${sourceFile}';
test('synthetic patch compatibility', () => {
  assert.deepEqual(names([{ name: 'Ada' }, { name: 'Grace' }]), ['Ada', 'Grace']);
  for (const key of ['GH_TOKEN', 'GITHUB_TOKEN', 'OFFENSE_AGENT_MODEL_KEY', 'OPENROUTER_API_KEY']) assert.equal(process.env[key], undefined);
});
`);
    await command(['git', 'add', 'package.json', 'package-lock.json', sourceFile, testFile], { cwd: fixture });
    await command(['git', '-c', 'user.name=Acceptance', '-c', 'user.email=acceptance@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Prepare synthetic patch-compatibility fixture'], { cwd: fixture });
    const pinned = await prepareSnapshot(fixture, output);
    for (const mode of ['repair', 'verify']) {
      if (mode === 'verify') await prepareVerification(path.join(output, 'fix.json'), path.join(output, 'verification-ci'));
      const name = `purple-fix-${randomBytes(12).toString('hex')}`;
      let completed = false;
      try {
        await command(['docker', 'network', 'create', '--internal', `${name}-network`]);
        await command(['docker', 'run', '--rm', '--detach', '--name', `${name}-proxy`, '--init', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '--cpus=0.5', '--user', '1000:1000', '--entrypoint', 'node', image, '--disable-sigusr1', '/opt/purple/agent/fix-egress-proxy.mjs']);
        await command(['docker', 'network', 'connect', '--alias', 'purple-egress', `${name}-network`, `${name}-proxy`]);
        const argv = dockerArguments({ directory: pinned.directory, output, image, uid: process.getuid(), gid: process.getgid(), name });
        argv[argv.length - 1] = '/opt/purple/scripts/ci/dependency-acceptance.mjs';
        console.log(`Acceptance: ${mode} in ${name}`);
        console.log(await command(['docker', ...argv, '--inside-image'], { input: JSON.stringify({ ...expected, mode, output, directory: pinned.directory, revision: pinned.revision, uid: process.getuid(), gid: process.getgid() }) }));
        completed = true;
      } finally {
        await command(['docker', 'rm', '--force', name, `${name}-proxy`]).catch(() => {});
        await command(['docker', 'network', 'rm', `${name}-network`]).catch(() => {});
        // A killed controller cannot restore its root-owned artifacts itself.
        if (!completed) await command(['docker', 'run', '--rm', '--interactive', '--init', '--read-only', '--network', 'none',
          '--cap-drop=ALL', '--cap-add=CHOWN', '--security-opt=no-new-privileges', '--user', '0:0', '--pids-limit=32', '--memory=128m', '--cpus=0.5',
          '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m', '--mount', `type=bind,source=${output},target=${output}`, '--entrypoint', 'node', image,
          '--disable-sigusr1', '/opt/purple/agent/dependency-fix-job.mjs'],
        { input: JSON.stringify({ mode: 'restore_ownership', output, artifactUid: process.getuid(), artifactGid: process.getgid() }), timeout: 60000 });
      }
    }
    const bundle = JSON.parse(await readFile(path.join(output, 'bundle.json')));
    const publication = await stubPublish(bundle, await readFile(path.join(fixture, 'package.json')), expected);
    assert.deepEqual(publication.changedFiles.sort(), ['package-lock.json', 'package.json', sourceFile].sort());
    const summary = { passed: true, ...expected, fixtureSha: pinned.revision, installsPerCheckout: 4, checksPerCheckout: 6, separateVerifier: true, ...publication,
      syntheticBoundaries: ['advisory intelligence', 'loopback model responses', 'GitHub API transport'], providerCredentialsUsed: false };
    await writeFile(path.join(evidence, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
    console.log(JSON.stringify(summary));
  } finally {
    // Reports only: never upload the job mount, model home, cache or checkouts.
    for (const file of ['fix.json', 'failed-candidate.json', 'verification-ci/fix.json']) {
      await copyFile(path.join(output, file), path.join(evidence, file.replaceAll('/', '-'))).catch(error => { if (error.code !== 'ENOENT') console.error(`Could not retain ${file}: ${error.code}`); });
    }
    await rm(root, { recursive: true, force: true });
  }
}

if (process.argv.includes('--inside-image')) {
  let raw = ''; for await (const chunk of process.stdin) { raw += chunk; assert.ok(raw.length < 16000); }
  await insideImage(JSON.parse(raw));
} else await host();
