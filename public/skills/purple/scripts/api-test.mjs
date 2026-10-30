#!/usr/bin/env node
// Local API testing only. No network client, account credential or automatic
// source upload is part of this helper. Explicit --run executes the chosen app
// in the already-installed no-network image.
import { lstat, readdir, readFile, realpath, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { updateBeforeRun } from './update.mjs';
import { apiImageFiles } from './api-test-image.mjs';

export const API_TEST_VERSION = '4.32.4';
export const API_TEST_IMAGE = 'purple-api-test:4.32.4';
export const API_TEST_LIMITS = Object.freeze({ files: 5000, bytes: 32 * 1024 * 1024, fileBytes: 8 * 1024 * 1024, schemaBytes: 256 * 1024 });
const HELP = `Usage: node api-test.mjs --write-image-context /tmp/purple-api-test-image
       node api-test.mjs --project TEST_APP --schema OPENAPI_FILE [--run] [--output DIRECTORY]
       [--port 8765] [--seed 1729] [--examples 10] [--seconds 20] [--max-requests 200] -- node server.mjs

Preview is the default. --run starts only the explicitly chosen Node/Python app
inside the prebuilt ${API_TEST_IMAGE} image. All test traffic stays on literal
127.0.0.1 inside a network-disabled container. No source or report is uploaded.
Use a disposable app snapshot with synthetic data and prepared dependencies.
No package installation, shell command, production URL or host environment is accepted.
`;
const hash = value => createHash('sha256').update(value).digest('hex');
const excludedName = name => name.startsWith('.') || /^(?:credentials(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|.*\.(?:pem|key|p12|pfx|keystore))$/i.test(name);
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value);
const integer = (value, fallback, low, high) => {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < low || value > high) throw Error('API test numeric option is out of bounds.');
  return value;
};

export async function prepareApiTest({ project, schema, command, port, seed, examples, seconds, maxRequests } = {}) {
  if (typeof project !== 'string' || typeof schema !== 'string' || !Array.isArray(command) || !command.length || command.length > 32 ||
      !['node', 'python3'].includes(command[0]) || command.some(value => typeof value !== 'string' || !value.length || value.length > 1000 || value.includes('\0'))) {
    throw Error('Choose an explicit test app, local OpenAPI file, and Node/Python argv after --.');
  }
  const root = await realpath(path.resolve(project));
  if (!(await lstat(root)).isDirectory()) throw Error('The test app must be a directory.');
  const schemaPath = path.resolve(schema), schemaStat = await lstat(schemaPath);
  if (!schemaStat.isFile() || schemaStat.isSymbolicLink() || schemaStat.size > API_TEST_LIMITS.schemaBytes) throw Error('Use one regular local OpenAPI JSON/YAML file of at most 256KiB.');
  const schemaBytes = await readFile(schemaPath);
  if (schemaBytes.length > API_TEST_LIMITS.schemaBytes || schemaBytes.toString('utf8').includes('\ufffd')) throw Error('The OpenAPI file must be bounded UTF-8 text.');
  const files = [], skipped = { hiddenOrCredential: 0, symlinks: 0, unsupportedNames: 0, nonFiles: 0 };
  let bytes = 0;
  async function visit(directory, prefix = '') {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (excludedName(entry.name)) { skipped.hiddenOrCredential++; continue; }
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (!/^[A-Za-z0-9_@+./-]{1,500}$/.test(relative)) { skipped.unsupportedNames++; continue; }
      const absolute = path.join(directory, entry.name), metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) { skipped.symlinks++; continue; }
      if (metadata.isDirectory()) { await visit(absolute, relative); continue; }
      if (!metadata.isFile()) { skipped.nonFiles++; continue; }
      if (metadata.size > API_TEST_LIMITS.fileBytes || files.length >= API_TEST_LIMITS.files || bytes + metadata.size > API_TEST_LIMITS.bytes) throw Error('The test app exceeds the sandbox snapshot budget; prepare a smaller isolated app.');
      const content = await readFile(absolute);
      bytes += content.length;
      if (content.length > API_TEST_LIMITS.fileBytes || bytes > API_TEST_LIMITS.bytes) throw Error('The test app changed or exceeded its snapshot budget.');
      files.push({ path: relative, contentBase64: content.toString('base64') });
    }
  }
  await visit(root);
  if (!files.length) throw Error('The selected test app has no supported regular files.');
  const payload = { schema: schemaBytes.toString('utf8'), files, command: [...command],
    port: integer(port, 8765, 1024, 65535), seed: integer(seed, 1729, 0, 4294967295), examples: integer(examples, 10, 1, 50),
    seconds: integer(seconds, 20, 5, 120), maxRequests: integer(maxRequests, 200, 10, 1000) };
  const snapshotHash = hash(JSON.stringify({ files, schema: payload.schema, command, port: payload.port }));
  return { payload, preview: { tool: 'schemathesis', version: API_TEST_VERSION, image: API_TEST_IMAGE, files: files.length, bytes,
    skipped, snapshotHash, seed: payload.seed, maxSeconds: payload.seconds, maxRequests: payload.maxRequests,
    target: 'isolated container loopback only', automaticUpload: false, appExecution: 'only with --run',
    limitation: 'Prepared Node/Python runtime dependencies must already be present; no external services or package installs are available.' } };
}

export function apiTestDockerArguments(name = 'purple-api-test-' + randomUUID(), { peer, detached = false } = {}) {
  if (!/^purple-api-test-[a-f0-9-]{8,80}$/.test(name)) throw Error('Invalid sandbox name.');
  if (peer !== undefined && !/^purple-api-test-[a-f0-9-]{8,80}$/.test(peer)) throw Error('Invalid app sandbox peer.');
  return ['--host', 'unix:///var/run/docker.sock', 'run', '--name', name, '--rm', ...(detached ? ['--detach'] : ['--interactive']), '--pull', 'never',
    '--network', peer ? `container:${peer}` : 'none', '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', '128', '--memory', '512m', '--cpus', '1', ...(peer ? [] : ['--hostname', 'purple-api-test']),
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=192m,mode=1777', ...(detached ? ['--entrypoint', 'python3'] : []), API_TEST_IMAGE,
    ...(detached ? ['-c', 'import time; time.sleep(180)'] : [])];
}

function safeReport(report) {
  if (!plain(report) || report.schemaVersion !== 'purple.api-test.v1' || report.version !== API_TEST_VERSION ||
      !['complete', 'partial', 'failed'].includes(report.status) || !Array.isArray(report.findings) || report.findings.length > 100 ||
      report.confirmedVulnerabilities !== 0) throw Error('Sandbox returned an invalid report.');
  const definitions = {
    ignored_auth: { kind: 'security_candidate', severity: 'HIGH', title: 'Authentication may not be enforced', remediation: 'Verify the operation requires authentication; add an authentication regression and enforce it in the handler.', codes: ['ST401'] },
    not_a_server_error: { kind: 'robustness_candidate', severity: 'MEDIUM', title: 'Generated input caused a server error', remediation: 'Reproduce the failing input locally and determine whether it has a security impact before treating it as a vulnerability.', codes: ['ST101', 'ST102'] },
    negative_data_rejection: { kind: 'validation_candidate', severity: 'MEDIUM', title: 'Schema-invalid input was accepted', remediation: 'Review the API contract and validate rejected input at the boundary; add a focused regression.', codes: ['ST201'] }
  };
  const findings = report.findings.map(item => {
    const definition = plain(item) && definitions[item.ruleId];
    if (!definition || !definition.codes.includes(item.code) || !Number.isInteger(item.operationIndex) || item.operationIndex < 0 || item.operationIndex > 24 || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(item.method)) throw Error('Invalid API finding.');
    const { codes, ...fixed } = definition;
    return { id: hash(`${item.operationIndex}:${item.code}`).slice(0, 32), tool: 'schemathesis', ruleId: item.ruleId, code: item.code,
      operationIndex: item.operationIndex, method: item.method, ...fixed, verification: 'requires_review_and_focused_regression', confirmed: false };
  });
  const errorCodes = [null, 'scanner_version_mismatch', 'app_start_failed', 'test_budget_exhausted', 'scanner_report_unavailable', 'invalid_test_input', 'sandbox_setup_failed', 'scanner_execution_failed', 'test_coverage_incomplete'];
  if (!errorCodes.includes(report.error)) throw Error('Invalid API test outcome.');
  const coverage = { scope: 'isolated_loopback_app', remoteTargets: false, checks: Object.keys(definitions), authorization: 'missing_or_invalid_auth_only', objectLevelAuthorization: 'not_assessed', crossOperationState: 'not_assessed' };
  for (const key of ['declaredOperations', 'testedOperations', 'generatedCases', 'casesWithoutChecks', 'operationsAcceptingValidInputs']) {
    if (report.coverage?.[key] !== undefined) coverage[key] = integer(report.coverage[key], 0, 0, 100000);
  }
  for (const key of ['boundedRun', 'budgetReached']) if (typeof report.coverage?.[key] === 'boolean') coverage[key] = report.coverage[key];
  return { schemaVersion: 'purple.api-test.v1', tool: 'schemathesis', version: API_TEST_VERSION, status: report.status, error: report.error,
    findings, confirmedVulnerabilities: 0, reproduction: { seed: integer(report.reproduction?.seed, 1729, 0, 4294967295), method: 'rerun_same_snapshot_schema_command_and_seed' }, coverage,
    privacy: { automaticUpload: false, rawRequestsSaved: false, rawResponsesSaved: false, rawAppOutputSaved: false } };
}

async function noSymlinkAncestors(destination) {
  const absolute = path.resolve(destination);
  let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try { if ((await lstat(current)).isSymbolicLink()) throw Error('API report paths cannot contain symlinks.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return absolute;
}

async function saveReport(directory, report) {
  const destination = await noSymlinkAncestors(directory);
  await mkdir(destination, { recursive: true, mode: 0o700 });
  await noSymlinkAncestors(destination);
  const target = path.join(destination, 'api-test.json');
  await noSymlinkAncestors(target);
  const temporary = path.join(destination, `.api-test-${randomUUID()}.json`);
  try { await writeFile(temporary, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); await rename(temporary, target); }
  finally { await rm(temporary, { force: true }); }
  return target;
}

export async function writeApiImageContext(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) throw Error('Choose an absolute temporary image context outside the project.');
  const destination = await noSymlinkAncestors(directory), project = await realpath(process.cwd());
  if (destination === path.parse(destination).root || destination === project || destination.startsWith(project + path.sep) || project.startsWith(destination + path.sep)) {
    throw Error('The image context must be outside the current project and its ancestors.');
  }
  const expectedNames = ['Dockerfile', 'schemathesis-sandbox.py', '.dockerignore'];
  if (!plain(apiImageFiles) || Object.keys(apiImageFiles).length !== 3 || expectedNames.some(name => typeof apiImageFiles[name] !== 'string')) throw Error('The installed image definition is incomplete.');
  let existing = [];
  try { existing = await readdir(destination); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (existing.some(name => !expectedNames.includes(name))) throw Error('Use a new image context directory; unrelated files are preserved.');
  for (const name of existing) {
    const target = path.join(destination, name), metadata = await lstat(target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (await readFile(target, 'utf8')) !== apiImageFiles[name]) throw Error('Customized image context files are preserved; choose a new directory.');
  }
  await mkdir(destination, { recursive: true, mode: 0o700 });
  await noSymlinkAncestors(destination);
  for (const name of expectedNames) if (!existing.includes(name)) await writeFile(path.join(destination, name), apiImageFiles[name], { mode: 0o600, flag: 'wx' });
  return { context: destination, image: API_TEST_IMAGE, files: expectedNames, execution: 'none', automaticUpload: false,
    next: 'Build this inspected context explicitly with Docker before running API tests.' };
}

async function launchApp(name, input, env) {
  const child = spawn('docker', ['--host', 'unix:///var/run/docker.sock', 'exec', '--interactive', name,
    'python3', '/opt/purple/schemathesis-sandbox.py', '--app'], { env, stdio: ['pipe', 'ignore', 'ignore'] });
  await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.stdin.once('error', reject);
    child.stdin.end(input, resolve);
  });
  return child;
}

export async function runApiTest(options, { execute = spawnSync, launch = launchApp } = {}) {
  const prepared = await prepareApiTest(options);
  const name = 'purple-api-test-' + randomUUID(), scannerName = 'purple-api-test-' + randomUUID();
  const env = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8' };
  const testToken = randomBytes(32).toString('hex');
  let result, app;
  try {
    const started = execute('docker', apiTestDockerArguments(name, { detached: true }), { encoding: 'utf8', env, timeout: 15000, maxBuffer: 65536, stdio: ['ignore', 'pipe', 'pipe'] });
    if (started.error || started.status !== 0) throw Error('The disposable app sandbox could not start.');
    // Separate filesystem and PID namespaces prevent tested app code from
    // replacing scanner reports/configuration, disabling its guard, or killing
    // its processes. They share only the app's already-no-egress network.
    app = await launch(name, JSON.stringify({ files: prepared.payload.files, command: prepared.payload.command,
      port: prepared.payload.port, seconds: prepared.payload.seconds, testToken }), env);
    const { files, command, ...scannerInput } = prepared.payload;
    result = execute('docker', apiTestDockerArguments(scannerName, { peer: name }), { input: JSON.stringify({ ...scannerInput, testToken }), encoding: 'utf8', env,
      timeout: (prepared.payload.seconds + 40) * 1000, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });
  } finally {
    // A killed Docker client can leave its container alive; explicitly remove
    // only this randomly named disposable sandbox, never another container.
    for (const container of [scannerName, name]) execute('docker', ['--host', 'unix:///var/run/docker.sock', 'rm', '--force', container], { encoding: 'utf8', env, timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
    app?.kill();
  }
  if (result.error || result.status !== 0) throw Error('API sandbox could not complete. Ensure local Docker is accessible and the pinned Purple API-test image is installed.');
  let report;
  try { report = safeReport(JSON.parse(result.stdout)); } catch { throw Error('API sandbox returned an invalid report; raw application output was not exported.'); }
  report.reproduction = { ...report.reproduction, snapshotHash: prepared.preview.snapshotHash };
  report.coverage = { ...report.coverage, stagedFiles: prepared.preview.files, stagedBytes: prepared.preview.bytes, skipped: prepared.preview.skipped };
  const output = await saveReport(options.output || path.join(path.resolve(options.project), '.purple/api-test'), report);
  return { status: report.status, findings: report.findings.length, confirmedVulnerabilities: 0, report: output, automaticUpload: false };
}

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length || argv.includes('--help')) { console.log(HELP); return; }
  if (argv[0] === '--write-image-context') {
    if (argv.length !== 2) throw Error('Provide only the explicit image context path.');
    const update = await updateBeforeRun('purple', import.meta.url);
    if (update.stop) return;
    console.log(JSON.stringify(await writeApiImageContext(argv[1]), null, 2));
    return;
  }
  const options = {}, args = [...argv]; let run = false;
  while (args.length) {
    const option = args.shift();
    if (option === '--') { options.command = args.splice(0); break; }
    if (option === '--run') { run = true; continue; }
    const key = ({ '--project': 'project', '--schema': 'schema', '--output': 'output', '--port': 'port', '--seed': 'seed', '--examples': 'examples', '--seconds': 'seconds', '--max-requests': 'maxRequests' })[option];
    if (!key || !args.length || args[0].startsWith('--')) throw Error('Unknown or incomplete API test option. Use --help.');
    const value = args.shift(); options[key] = ['port', 'seed', 'examples', 'seconds', 'maxRequests'].includes(key) ? Number(value) : value;
  }
  const update = await updateBeforeRun('purple', import.meta.url, { preview: !run });
  if (update.stop) return;
  if (!run) { const prepared = await prepareApiTest(options); console.log(JSON.stringify(prepared.preview, null, 2)); return; }
  const result = await runApiTest(options); console.log(JSON.stringify(result));
  if (result.status !== 'complete') process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => {
  console.error('API testing could not complete. Check the local app, schema, sandbox image and resource bounds; no raw app output was exported.');
  process.exitCode = 1;
});
