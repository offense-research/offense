// Actual Hermes core + synthetic OpenAI-compatible model. No paid provider calls.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runHermesTask, HERMES_REVISION } from './hermes-runtime.mjs';

const values = process.argv.slice(2);
const option = name => { const index = values.indexOf(name); return index >= 0 ? values[index + 1] : undefined; };
const image = option('--image'), insideImage = values.includes('--inside-image');
const localCore = option('--local-core'), python = option('--python');
if (!image && !insideImage && (!localCore || !python)) throw new Error('Provide --image purple-hermes:local, or explicit --local-core and --python for a separately labeled installed-core smoke.');
const root = await mkdtemp(path.join(tmpdir(), 'purple-hermes-smoke-'));
await chmod(root, 0o755);
for (const name of ['candidate', 'output', 'candidate/test']) await mkdir(path.join(root, name), { recursive: true, mode: 0o777 });
await writeFile(path.join(root, 'candidate/app.js'), 'export const value = 1;\n', { mode: 0o666 });
await writeFile(path.join(root, 'candidate/test/normal.test.js'), 'normal-suite-must-stay-unchanged\n', { mode: 0o666 });
await writeFile(path.join(root, 'candidate/.env'), 'PRIVATE_CANARY=must-not-reach-model\n', { mode: 0o666 });
const calls = [], tools = ['purple_list_files', 'purple_patch_file', 'purple_read_file', 'purple_write_file'];
const actions = [
  ['purple_list_files', {}],
  ['purple_read_file', { path: 'app.js' }],
  ['purple_read_file', { path: '.env' }],
  ['purple_read_file', { path: '/proc/self/environ' }],
  ['purple_write_file', { path: 'test/normal.test.js', content: 'weakened test' }],
  ['terminal', { command: `printf forbidden > ${image ? '/smoke' : root}/unsafe-command` }],
  ['purple_patch_file', { path: 'app.js', oldText: 'value = 1', newText: 'value = 2' }],
  ['purple_write_file', { path: '@output/plan.json', content: JSON.stringify({ summary: 'Updated source with restricted Hermes tools', blockers: [], confirmed: false }) }]
];
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname.includes('/models')) {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ data: url.pathname.endsWith('/models') ? [{ id: 'purple-smoke', context_length: 64000 }] : { id: 'purple-smoke', context_length: 64000 } })); return;
    }
    assert.equal(url.pathname, '/v1/chat/completions');
    let raw = ''; for await (const chunk of request) { raw += chunk.toString(); if (raw.length > 2_000_000) throw new Error('Model request exceeded budget.'); }
    const body = JSON.parse(raw);
    assert.deepEqual(body.tools.map(tool => tool.function.name).sort(), tools);
    assert.ok(!raw.includes('must-not-reach-model'));
    calls.push(body);
    const action = actions[calls.length - 1];
    const tool = action ? { id: `call_${calls.length}`, type: 'function', function: { name: action[0], arguments: JSON.stringify(action[1]) } } : null;
    const message = tool ? { role: 'assistant', content: null, tool_calls: [tool] } : { role: 'assistant', content: 'Source edited. Existing tests and credentials remain unchanged. Purple must verify independently.' };
    if (body.stream) {
      response.setHeader('content-type', 'text/event-stream');
      const chunk = delta => ({ id: `synthetic_${calls.length}`, object: 'chat.completion.chunk', created: 1, model: 'purple-smoke', choices: [{ index: 0, delta, finish_reason: null }] });
      response.write('data: ' + JSON.stringify(chunk(tool ? { role: 'assistant', tool_calls: [{ index: 0, ...tool }] } : message)) + '\n\n');
      const end = chunk({}); end.choices[0].finish_reason = tool ? 'tool_calls' : 'stop'; end.usage = { prompt_tokens: 100, completion_tokens: 10, total_tokens: 110, cost: 0 };
      response.end('data: ' + JSON.stringify(end) + '\n\ndata: [DONE]\n\n');
    } else {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ id: `synthetic_${calls.length}`, object: 'chat.completion', created: 1, model: 'purple-smoke', choices: [{ index: 0, message, finish_reason: tool ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 100, completion_tokens: 10, total_tokens: 110, cost: 0 } }));
    }
  } catch { response.statusCode = 500; response.end('Synthetic model assertion failed.'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  const task = { protectedPaths: ['test/normal.test.js'], findings: [], outputContract: { summary: 'string', blockers: 'array' } };
  const input = { candidateDirectory: image ? '/smoke/candidate' : root+'/candidate', outputDirectory: image ? '/smoke/output' : root+'/output',
    task, model: 'purple-smoke', apiKey: 'synthetic-smoke-model-key', endpoint: `http://127.0.0.1:${server.address().port}/v1`, maxTurns: 12, timeoutMs: 90_000 };
  let result;
  if (image) {
    const program = `import {runHermesTask} from '/opt/purple/agent/hermes-runtime.mjs';let raw='';for await(const chunk of process.stdin)raw+=chunk;console.log(JSON.stringify(await runHermesTask(JSON.parse(raw))));`;
    result = await new Promise((resolve, reject) => {
      const child = spawn('docker', ['run', '--rm', '-i', '--read-only', '--network=host', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=1g',
        '--tmpfs=/tmp:rw,nosuid,nodev,size=256m', '--mount', `type=bind,source=${root},target=/smoke`, '--user=1000:1000', '--entrypoint=node', image, '--disable-sigusr1', '--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] });
      let out = '', err = '';
      child.stdout.on('data', c => { out += c; }); child.stderr.on('data', c => { err += c; });
      child.on('error', reject); child.on('close', code => { if (code !== 0) return reject(new Error(`Hermes image smoke failed (${code}): ${err.slice(-1000)}`)); try { resolve(JSON.parse(out)); } catch { reject(new Error('Hermes image returned invalid JSON.')); } });
      child.stdin.end(JSON.stringify(input));
    });
  } else result = await runHermesTask(input, insideImage ? {} : { hermesPath: localCore, python, allowUnpinnedForTest: true });
  assert.equal(result.status, 'completed', JSON.stringify(result));
  assert.match(await readFile(root+'/candidate/app.js','utf8'), /value = 2/);
  assert.equal(await readFile(root+'/candidate/test/normal.test.js','utf8'), 'normal-suite-must-stay-unchanged\n');
  assert.match(await readFile(root+'/candidate/.env','utf8'), /must-not-reach-model/);
  await assert.rejects(readFile(root+'/unsafe-command'), { code: 'ENOENT' });
  assert.equal(result.plan.summary, 'Updated source with restricted Hermes tools');
  assert.equal(result.usage.billingEligible, false);
  assert.ok(calls.length >= actions.length);
  if (image || insideImage) assert.equal(result.runtime.revision, HERMES_REVISION);
  console.log(JSON.stringify({ passed: true, scope: image || insideImage ? 'Pinned Hermes Docker image with fake model' : 'Explicit installed-core smoke; not pinned-image evidence', runtime: result.runtime, modelCalls: calls.length,
    checks: ['exact scoped tool allowlist', 'source patch and plan output', 'credential-file denial', 'absolute/process path denial', 'existing test preservation', 'unknown terminal tool rejected', 'unverified cost excluded from billing'], providerCredentialsUsed: false }));
} finally {
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true });
}
