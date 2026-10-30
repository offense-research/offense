import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { prepareApiTest, runApiTest, apiTestDockerArguments, writeApiImageContext, API_TEST_IMAGE } from '../tools/api-test.mjs';
import { apiImageFiles } from '../tools/api-test-image.mjs';

test('API image resource matches the preferred editable sources shipped in this package', async () => {
  for (const name of ['Dockerfile', 'schemathesis-sandbox.py', '.dockerignore'])
    assert.equal(apiImageFiles[name], await readFile(new URL('../tools/api-image/' + name, import.meta.url), 'utf8'));
});

const schema = { openapi: '3.0.3', info: { title: 'PRIVATE-PII-API-TITLE', version: '1' }, paths: {
  '/protected': { get: { security: [{ bearer: [] }], responses: { 200: { description: 'ok' }, 401: { description: 'unauthorized' } } } },
  '/parse': { post: { security: [], requestBody: { required: true, content: { 'application/json': { schema: {
    type: 'object', required: ['value'], properties: { value: { type: 'integer', minimum: 0, maximum: 100 } }
  } } } }, responses: { 200: { description: 'ok' }, 400: { description: 'invalid' } } } }
}, components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } } };

const server = vulnerable => `import http from 'node:http';
const vulnerable=${vulnerable};
http.createServer(async(req,res)=>{res.setHeader('content-type','application/json');
if(req.url.startsWith('/protected')){if(!vulnerable&&req.headers.authorization!=='Bearer '+process.env.PURPLE_TEST_TOKEN){res.statusCode=401;res.end('{}');return;}res.end('{"ok":true}');return;}
if(req.url.startsWith('/parse')){let text='';for await(const c of req)text+=c;let body;try{body=JSON.parse(text);}catch{body={};}if(typeof body?.value!=='number'||body.value<0||body.value>100){res.statusCode=vulnerable?500:400;res.end('{"private":"PRIVATE-BODY-alice@example.com"}');return;}res.end('{}');return;}
res.statusCode=404;res.end('{}');}).listen(Number(process.env.PORT),'127.0.0.1');`;

async function fixture(t, vulnerable = false) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-api-test-fixture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'server.mjs'), server(vulnerable));
  await writeFile(path.join(root, 'openapi.json'), JSON.stringify(schema));
  return { root, options: { project: root, schema: path.join(root, 'openapi.json'), command: ['node', 'server.mjs'], seconds: 5, examples: 3 } };
}

const emptyReport = () => ({ schemaVersion: 'purple.api-test.v1', tool: 'schemathesis', version: '4.32.4', status: 'complete', error: null,
  findings: [], confirmedVulnerabilities: 0, reproduction: { seed: 1729 }, coverage: { declaredOperations: 2, testedOperations: 2, generatedCases: 5, casesWithoutChecks: 0, operationsAcceptingValidInputs: 2 }, privacy: {} });

test('API preview stages only bounded regular app files and omits credentials and symlinks', async t => {
  const { root, options } = await fixture(t);
  await writeFile(path.join(root, '.env'), 'SECRET-TOKEN-DO-NOT-FORWARD');
  await mkdir(path.join(root, '.codex'));
  await writeFile(path.join(root, '.codex/auth.json'), '{"token":"DO-NOT-FORWARD"}');
  await writeFile(path.join(root, 'credentials.json'), 'DO-NOT-FORWARD');
  await symlink('/etc/passwd', path.join(root, 'outside.txt'));
  const result = await prepareApiTest(options);
  assert.equal(result.payload.files.length, 2);
  assert.equal(result.preview.automaticUpload, false);
  assert.equal(result.preview.skipped.hiddenOrCredential, 3);
  assert.equal(result.preview.skipped.symlinks, 1);
  assert.ok(!JSON.stringify(result.payload).includes('DO-NOT-FORWARD'));
  assert.ok(result.payload.files.every(file => !file.path.startsWith('.')));
});

test('API image arguments cannot expose host credentials, files, ports or network', () => {
  const args = apiTestDockerArguments('purple-api-test-12345678');
  assert.equal(args[args.indexOf('--network') + 1], 'none');
  assert.equal(args[args.indexOf('--user') + 1], '65532:65532');
  assert.equal(args[args.indexOf('--pull') + 1], 'never');
  assert.equal(args[args.indexOf('--host') + 1], 'unix:///var/run/docker.sock');
  assert.ok(args.includes('--read-only'));
  assert.ok(args.includes('no-new-privileges'));
  assert.ok(args.includes('ALL'));
  assert.ok(args.includes(API_TEST_IMAGE));
  for (const flag of ['--volume', '-v', '--mount', '--publish', '-p', '--env-file', '--privileged', '--env']) assert.ok(!args.includes(flag));
  assert.throws(() => apiTestDockerArguments('other-container'), /Invalid/);
  const scanner = apiTestDockerArguments('purple-api-test-abcdef12', { peer: 'purple-api-test-12345678' });
  assert.equal(scanner[scanner.indexOf('--network') + 1], 'container:purple-api-test-12345678');
  assert.ok(!scanner.includes('--pid'));
  assert.ok(!scanner.includes('--hostname'));
});

test('API helper rejects remote schemas, symlinks, shell commands and invalid budgets before execution', async t => {
  const { root, options } = await fixture(t);
  await assert.rejects(prepareApiTest({ ...options, schema: 'https://example.com/openapi.json' }));
  await symlink(options.schema, path.join(root, 'schema-link.json'));
  await assert.rejects(prepareApiTest({ ...options, schema: path.join(root, 'schema-link.json') }), /regular local/);
  await assert.rejects(prepareApiTest({ ...options, command: ['sh', '-c', 'printenv'] }), /explicit/);
  await assert.rejects(prepareApiTest({ ...options, seconds: 1000 }), /out of bounds/);
  await assert.rejects(prepareApiTest({ ...options, maxRequests: 0 }), /out of bounds/);
});

test('API reports cannot copy private free text from container output and no ambient credentials are forwarded', async t => {
  const { root, options } = await fixture(t), calls = [];
  const raw = emptyReport();
  raw.private = 'PII-PRIVATE-alice@example.com';
  raw.coverage.private = 'PII-PRIVATE-alice@example.com';
  raw.privacy.private = 'PII-PRIVATE-alice@example.com';
  raw.reproduction.private = 'PII-PRIVATE-alice@example.com';
  raw.findings = [{ ruleId: 'ignored_auth', code: 'ST401', operationIndex: 0, method: 'GET', title: 'PII-PRIVATE-alice@example.com', remediation: 'PII-PRIVATE-alice@example.com', raw: 'PII-PRIVATE-alice@example.com' }];
  const execute = (binary, args, execution) => {
    calls.push({ binary, args, execution });
    return { status: 0, stdout: args.includes('run') ? JSON.stringify(raw) : '' };
  };
  let appInput;
  const launch = async (_name, input) => { appInput = JSON.parse(input); return { kill() {} }; };
  const result = await runApiTest({ ...options, output: path.join(root, 'result') }, { execute, launch });
  const report = JSON.parse(await readFile(result.report));
  assert.equal(result.findings, 1);
  assert.ok(!JSON.stringify(report).includes('PII-PRIVATE'));
  assert.equal(report.findings[0].kind, 'security_candidate');
  assert.equal(report.findings[0].confirmed, false);
  assert.deepEqual(Object.keys(calls[0].execution.env).sort(), ['LANG', 'PATH']);
  assert.equal(calls.length, 4);
  assert.ok(calls[2].args.includes('rm'));
  assert.equal(appInput.schema, undefined);
  assert.equal(JSON.parse(calls[1].execution.input).files, undefined);
  assert.equal(JSON.parse(calls[1].execution.input).command, undefined);
  assert.equal(appInput.testToken, JSON.parse(calls[1].execution.input).testToken);
  assert.equal(calls[0].execution.env.DOCKER_HOST, undefined);
});

test('Docker failure still removes only the disposable sandbox and does not export raw errors', async t => {
  const { root, options } = await fixture(t), calls = [];
  const execute = (_binary, args) => { calls.push(args); return { status: 1, stdout: 'PRIVATE-RAW-ERROR', stderr: 'PRIVATE-TOKEN' }; };
  await assert.rejects(runApiTest({ ...options, output: path.join(root, 'failed') }, { execute }), error => !error.message.includes('PRIVATE') && /sandbox/.test(error.message));
  assert.equal(calls.length, 3);
  assert.equal(calls[0][calls[0].indexOf('--name') + 1], calls[2].at(-1));
  await assert.rejects(readFile(path.join(root, 'failed/api-test.json')), /ENOENT/);
});

test('API report symlink ancestors cannot redirect exports', async t => {
  const { root, options } = await fixture(t), other = await mkdtemp(path.join(os.tmpdir(), 'purple-api-report-target-'));
  t.after(() => rm(other, { recursive: true, force: true }));
  await symlink(other, path.join(root, 'redirect'));
  await assert.rejects(runApiTest({ ...options, output: path.join(root, 'redirect/reports') }, { execute: (_binary, args) => ({ status: 0, stdout: args.includes('run') ? JSON.stringify(emptyReport()) : '' }), launch: async () => ({ kill() {} }) }), /symlinks/);
  await assert.rejects(readFile(path.join(other, 'reports/api-test.json')), /ENOENT/);
});

test('API image context writes only fixed inspected files and preserves customizations', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-api-context-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'context');
  const first = await writeApiImageContext(target);
  assert.deepEqual(first.files, ['Dockerfile', 'schemathesis-sandbox.py', '.dockerignore']);
  assert.equal(first.execution, 'none');
  assert.equal(first.automaticUpload, false);
  assert.deepEqual(await writeApiImageContext(target), first);
  await writeFile(path.join(target, 'Dockerfile'), 'custom image instructions');
  await assert.rejects(writeApiImageContext(target), /Customized/);
  assert.equal(await readFile(path.join(target, 'Dockerfile'), 'utf8'), 'custom image instructions');
  await assert.rejects(writeApiImageContext(process.cwd()), /outside/);
  await symlink(root, path.join(root, 'linked'));
  await assert.rejects(writeApiImageContext(path.join(root, 'linked/elsewhere')), /symlinks/);
});

