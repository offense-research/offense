import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink, access, copyFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { acquireHardenedImage, prepareHardenedImage, inspectDockerfile, parseHardenedImageReference, main } from '../tools/hardened-image.mjs';

const DIGEST = 'sha256:' + 'a'.repeat(64), ID = 'sha256:' + 'b'.repeat(64);
const IMAGE = 'dhi.io/node:24.16-debian13', PINNED = 'dhi.io/node@' + DIGEST;
const SOURCE = 'FROM node:24.16-bookworm-slim AS runtime\nWORKDIR /app\nCOPY server.mjs /app/server.mjs\nENTRYPOINT ["node"]\nCMD ["/app/server.mjs"]\n';
const HELPER = fileURLToPath(new URL('../tools/hardened-image.mjs', import.meta.url));

async function fixture(t, source = SOURCE) {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'purple-hardened-fixture-'));
  t.after(() => rm(outer, { recursive: true, force: true }));
  const project = path.join(outer, 'project'); await mkdir(project);
  await writeFile(path.join(project, 'Dockerfile'), source);
  return { outer, project, source, options: { project, image: IMAGE, platform: 'linux/amd64', output: path.join(outer, 'report') } };
}

function metadata(overrides = {}) {
  return { Id: ID, Os: 'linux', Architecture: 'amd64', RepoDigests: [PINNED],
    Config: { User: '65532:65532', Entrypoint: ['/nodejs/bin/node', 'DO_NOT_EXPORT_ARGUMENT'], Cmd: ['DO_NOT_EXPORT_COMMAND'],
      WorkingDir: '/app', Env: ['PRIVATE_TOKEN=DO_NOT_EXPORT_ENV'], Labels: { private: 'DO_NOT_EXPORT_LABEL' } }, ...overrides };
}

function fakeDocker({ pullStatus = 0, initial = metadata(), exact = metadata(), throwOnCall = false } = {}) {
  const calls = [];
  const execute = (command, args, options) => {
    calls.push({ command, args, options });
    assert.equal(command, 'docker');
    if (throwOnCall) throw Error('DO_NOT_EXPORT_EXCEPTION');
    if (args[0] === 'pull') return { status: pullStatus, stdout: 'DO_NOT_EXPORT_PULL', stderr: 'DO_NOT_EXPORT_ERROR' };
    assert.deepEqual(args.slice(0, 2), ['image', 'inspect']);
    const selected = calls.filter(call => call.args[0] === 'image').length === 1 ? initial : exact;
    if (selected === null) return { status: 1, stderr: 'DO_NOT_EXPORT_INSPECT_ERROR' };
    return { status: 0, stdout: typeof selected === 'string' ? selected : JSON.stringify([selected]) };
  };
  return { calls, execute };
}

test('only explicit references in the supported provider namespaces are accepted', () => {
  for (const reference of [IMAGE, 'dhi.io/python:3.13-debian13@' + DIGEST, 'cgr.dev/chainguard/node:latest', 'gcr.io/distroless/nodejs24-debian13:nonroot', PINNED])
    assert.equal(parseHardenedImageReference(reference).reference, reference);
  for (const reference of ['dhi.io/node', 'docker.io/node:24', 'dhi.io.evil/node:24', 'cgr.dev/another/node:latest', 'dhi.io/myorg/node:24', 'dhi.io/node:24;curl', '--help', 'https://user:secret@dhi.io/node:24', 'dhi.io/node@sha256:ABC', 'dhi.io/../node:24'])
    assert.throws(() => parseHardenedImageReference(reference));
});

test('preview inventories the chosen stage and runtime policy without Docker, writes or updater', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.project, 'package.json'), JSON.stringify({ engines: { node: '>=24.16' }, packageManager: 'pnpm@10.32.1', scripts: { private: 'DO_NOT_EXPORT_SOURCE' } }));
  await writeFile(path.join(f.project, '.node-version'), '24.16.0\n');
  const report = await acquireHardenedImage({ ...f.options, pull: true, preview: true }, { execute: () => { throw Error('Docker must not run'); } });
  assert.equal(report.acquisition.status, 'not_requested');
  assert.equal(report.proposal.status, 'not_generated');
  assert.equal(report.inventory.runtimePolicy.nodeEngines, '>=24.16');
  assert.equal(report.inventory.runtimePolicy.nodeVersion, '24.16.0');
  assert.equal(report.inventory.selectedStage.alias, 'runtime');
  assert.equal(JSON.stringify(report).includes('DO_NOT_EXPORT_SOURCE'), false);
  await assert.rejects(access(f.options.output), { code: 'ENOENT' });
});

test('successful pull resolves the exact source digest, re-inspects the pin and preserves Docker auth/context', async t => {
  const f = await fixture(t), fake = fakeDocker({ initial: metadata({ RepoDigests: ['unrelated.example/node@sha256:' + 'c'.repeat(64), PINNED] }) });
  const report = await acquireHardenedImage({ ...f.options, pull: true }, fake);
  assert.deepEqual(fake.calls.map(call => call.args), [
    ['pull', '--platform', 'linux/amd64', IMAGE], ['image', 'inspect', IMAGE], ['image', 'inspect', PINNED]
  ]);
  assert.ok(fake.calls.every(call => call.options.env === process.env));
  assert.ok(fake.calls.every(call => !call.args.includes('--host') && !call.args.includes('--context')));
  assert.equal(report.acquisition.status, 'acquired'); assert.equal(report.digest.status, 'resolved');
  assert.equal(report.metadata.imageConfigDigest, ID); assert.equal(report.metadata.registryDigest, DIGEST);
  assert.equal(report.metadata.configurationSummary.privilege, 'nonroot');
  assert.equal(report.metadata.configurationSummary.entrypointExecutable, '/nodejs/bin/node');
  assert.equal(report.compatibility.status, 'requires_review');
  assert.equal(report.signature.status, 'not_assessed');
  assert.equal(report.applicationBuilds.status, 'not_run'); assert.equal(report.applicationTests.status, 'not_run');
  assert.equal(report.vulnerabilityScan.status, 'not_run');
  assert.equal(report.proposal.status, 'available_requires_review');
  assert.equal(await readFile(path.join(f.project, 'Dockerfile'), 'utf8'), SOURCE);
  const files = await readdir(report.output);
  assert.deepEqual(files.sort(), ['Dockerfile.candidate', 'hardened-image.json', 'migration.patch', 'remediation.md']);
  const all = (await Promise.all(files.map(file => readFile(path.join(report.output, file), 'utf8')))).join('\n');
  assert.doesNotMatch(all, /DO_NOT_EXPORT/);
  assert.match(all, /repository_digest_may_identify_multi_platform_index/);
  const candidate = await readFile(path.join(report.output, 'Dockerfile.candidate'), 'utf8');
  assert.equal(candidate, SOURCE.replace('node:24.16-bookworm-slim', PINNED));
});

test('failed pull never inspects a cached image or emits an immutable proposal', async t => {
  const f = await fixture(t), fake = fakeDocker({ pullStatus: 1 });
  const report = await acquireHardenedImage({ ...f.options, image: IMAGE + '@' + DIGEST, pull: true }, fake);
  assert.equal(report.status, 'failed'); assert.equal(report.acquisition.status, 'failed');
  assert.equal(report.digest.status, 'supplied_not_resolved'); assert.equal(report.metadata.status, 'not_assessed');
  assert.equal(fake.calls.length, 1); assert.equal(report.proposal.reason, 'image_acquisition_failed');
  assert.deepEqual((await readdir(report.output)).sort(), ['hardened-image.json', 'remediation.md']);
  assert.doesNotMatch(await readFile(path.join(report.output, 'hardened-image.json'), 'utf8'), /DO_NOT_EXPORT/);
});

for (const [name, initial, exact] of [
  ['foreign repository digest', metadata({ RepoDigests: ['cgr.dev/chainguard/node@' + DIGEST] }), metadata()],
  ['ambiguous repository digests', metadata({ RepoDigests: [PINNED, 'dhi.io/node@sha256:' + 'c'.repeat(64)] }), metadata()],
  ['wrong architecture', metadata(), metadata({ Architecture: 'arm64' })],
  ['changed image config digest', metadata(), metadata({ Id: 'sha256:' + 'd'.repeat(64) })],
  ['missing exact digest', metadata(), metadata({ RepoDigests: [] })],
  ['invalid image config digest', metadata(), metadata({ Id: 'cached-local-tag' })],
  ['failed initial inspection', null, metadata()],
  ['malformed inspection output', '[not-json', metadata()]
]) test(`${name} cannot establish image acquisition`, async t => {
  const f = await fixture(t), fake = fakeDocker({ initial, exact });
  const report = await acquireHardenedImage({ ...f.options, pull: true }, fake);
  assert.equal(report.acquisition.status, 'failed'); assert.equal(report.digest.status, 'not_resolved');
  assert.equal(report.proposal.status, 'unavailable');
  assert.equal(report.metadata.status, 'failed');
});

test('explicit digest must match the pulled repository digest', async t => {
  const f = await fixture(t), fake = fakeDocker();
  const report = await acquireHardenedImage({ ...f.options, image: 'dhi.io/node@sha256:' + 'e'.repeat(64), pull: true }, fake);
  assert.equal(report.acquisition.status, 'failed');
  assert.equal(fake.calls.length, 2);
});

test('Docker execution exceptions are sanitized and remain failed acquisition', async t => {
  const f = await fixture(t), fake = fakeDocker({ throwOnCall: true });
  const report = await acquireHardenedImage({ ...f.options, pull: true }, fake);
  assert.equal(report.acquisition.status, 'failed');
  assert.doesNotMatch(JSON.stringify(report), /DO_NOT_EXPORT_EXCEPTION/);
});

for (const [label, failure, expected] of [
  ['missing CLI', { error: { code: 'ENOENT', message: 'DO_NOT_EXPORT_PRIVATE_PATH' } }, 'docker_cli_missing'],
  ['unreachable daemon', { status: 1, stderr: 'Cannot connect to the Docker daemon at unix:///private/docker.sock. DO_NOT_EXPORT' }, 'docker_connection_unavailable'],
  ['socket permissions', { status: 1, stderr: 'permission denied while trying to connect to the Docker daemon socket DO_NOT_EXPORT' }, 'docker_connection_unavailable'],
  ['registry authorization', { status: 1, stderr: 'unauthorized: authentication required bearer DO_NOT_EXPORT' }, 'registry_access_denied'],
  ['missing registry image', { status: 1, stderr: 'manifest unknown DO_NOT_EXPORT' }, 'registry_image_not_found'],
  ['registry DNS', { status: 1, stderr: 'lookup private-registry: no such host DO_NOT_EXPORT' }, 'registry_connection_failed'],
  ['timeout', { error: { code: 'ETIMEDOUT', message: 'DO_NOT_EXPORT' } }, 'registry_connection_failed']
]) test(`${label} produces a concrete fixed failure code without raw output`, async t => {
  const f = await fixture(t);
  const report = await acquireHardenedImage({ ...f.options, pull: true }, { execute: () => failure });
  assert.equal(report.acquisition.error, expected);
  const all = (await Promise.all((await readdir(report.output)).map(file => readFile(path.join(report.output, file), 'utf8')))).join('\n');
  assert.doesNotMatch(all, /DO_NOT_EXPORT/);
  assert.match(all, /existing Docker credential helper/);
});

test('bounded configuration summary excludes unknown usernames, executable arguments, Env and Labels', async t => {
  const f = await fixture(t), value = metadata({ Config: { User: 'SECRET_USER', Entrypoint: ['/SECRET/PATH', 'SECRET_ARGUMENT'], Cmd: ['SECRET_COMMAND'], Env: ['SECRET_ENV'], Labels: { private: 'SECRET_LABEL' }, WorkingDir: '/path\nSECRET_WORKDIR' } });
  const report = await acquireHardenedImage({ ...f.options, pull: true }, fakeDocker({ initial: value, exact: value }));
  assert.equal(report.metadata.configurationSummary.configuredUser, 'unrecognized');
  assert.equal(report.metadata.configurationSummary.privilege, 'unknown');
  assert.equal(report.metadata.configurationSummary.entrypointExecutable, 'unrecognized');
  assert.equal(report.metadata.configurationSummary.workingDirectory, 'unrecognized');
  assert.doesNotMatch(JSON.stringify(report), /SECRET/);
});

test('missing OCI configuration preserves unknown privilege rather than assuming root', async t => {
  const f = await fixture(t), value = metadata({ Config: null });
  const report = await acquireHardenedImage({ ...f.options, pull: true }, fakeDocker({ initial: value, exact: value }));
  assert.equal(report.metadata.configurationSummary.status, 'unavailable');
  assert.equal(report.metadata.configurationSummary.privilege, 'unknown');
});

test('without pull a tag creates only a local plan and does not invoke Docker', async t => {
  const f = await fixture(t);
  const report = await acquireHardenedImage(f.options, { execute: () => { throw Error('No Docker in plan mode'); } });
  assert.equal(report.status, 'planned'); assert.equal(report.acquisition.status, 'not_requested');
  assert.equal(report.proposal.reason, 'immutable_digest_required');
  assert.deepEqual((await readdir(report.output)).sort(), ['hardened-image.json', 'remediation.md']);
});

test('without pull a supplied digest creates an explicitly unverified proposal', async t => {
  const f = await fixture(t);
  const report = await acquireHardenedImage({ ...f.options, image: IMAGE + '@' + DIGEST }, { execute: () => { throw Error('No Docker in plan mode'); } });
  assert.equal(report.acquisition.status, 'not_requested'); assert.equal(report.digest.status, 'supplied_not_resolved');
  assert.equal(report.metadata.status, 'not_assessed'); assert.equal(report.proposal.status, 'available_requires_review');
});

for (const [label, source, stage] of [
  ['named intermediate stage', 'FROM node:24.16-bookworm-slim AS build\nRUN echo builder\nFROM node:24.16-bookworm-slim AS runtime\nENTRYPOINT ["node"]\nCMD ["server.mjs"]\n', 'build'],
  ['default final stage', 'FROM node:24.16-bookworm-slim AS build\nRUN echo builder\nFROM node:24.16-bookworm-slim AS runtime\nENTRYPOINT ["node"]\nCMD ["server.mjs"]\n', undefined],
  ['continued FROM', 'FROM --platform=linux/amd64 \\\n  node:24.16-bookworm-slim \\\n  AS runtime\nENTRYPOINT ["node"]\nCMD ["server.mjs"]\n', '0'],
  ['CRLF Dockerfile', SOURCE.replaceAll('\n', '\r\n'), undefined],
  ['Dockerfile without final newline', SOURCE.trimEnd(), undefined]
]) test(`${label} produces an applicable patch changing only its selected FROM token`, async t => {
  const f = await fixture(t, source);
  const report = await acquireHardenedImage({ ...f.options, stage, image: IMAGE + '@' + DIGEST });
  const candidate = await readFile(path.join(report.output, 'Dockerfile.candidate'), 'utf8');
  const parsed = inspectDockerfile(source), selected = stage === 'build' ? parsed.stages[0] : parsed.stages.at(-1);
  assert.equal(candidate, source.slice(0, selected.imageStart) + PINNED + source.slice(selected.imageEnd));
  assert.equal(await readFile(path.join(f.project, 'Dockerfile'), 'utf8'), source);
  // Apply the generated artifact in this disposable fixture to validate real
  // unified-diff syntax, including continued instructions and newline markers.
  const applied = spawnSync('git', ['apply', path.join(report.output, 'migration.patch')], { cwd: f.project, encoding: 'utf8' });
  assert.equal(applied.error, undefined);
  assert.equal(applied.status, 0, applied.stderr);
  assert.equal(await readFile(path.join(f.project, 'Dockerfile'), 'utf8'), candidate);
});

for (const [label, source, blocker] of [
  ['ARG FROM', 'ARG BASE=node:24\nFROM $BASE AS runtime\n', 'unresolved_from_variable'],
  ['inherited stage', 'FROM node:24 AS base\nFROM base AS runtime\n', 'selected_from_is_not_an_external_runtime_image'],
  ['heredoc', 'FROM node:24 AS build\nRUN <<EOF\nFROM node:22 AS fake\nEOF\n', 'unsupported_heredoc'],
  ['continued heredoc', 'FROM node:24 AS build\nRUN \\\n  <<EOF\nFROM node:22 AS fake\nEOF\n', 'unsupported_heredoc'],
  ['escape directive', '# escape=`\nFROM node:24\n', 'unsupported_escape_directive'],
  ['duplicate aliases', 'FROM node:24 AS runtime\nFROM node:24 AS runtime\n', 'duplicate_stage_alias']
]) test(`${label} is blocked without generating a misleading patch`, async t => {
  const f = await fixture(t, source);
  const report = await acquireHardenedImage({ ...f.options, image: IMAGE + '@' + DIGEST });
  assert.equal(report.compatibility.status, 'blocked'); assert.ok(report.compatibility.blockers.includes(blocker));
  assert.equal(report.proposal.status, 'unavailable');
  assert.deepEqual((await readdir(report.output)).sort(), ['hardened-image.json', 'remediation.md']);
});

test('runtime, libc, shell, RUN and platform changes remain compatibility blockers', async t => {
  const f = await fixture(t, 'FROM --platform=linux/arm64 node:22.3-alpine AS runtime\nRUN npm ci\nENTRYPOINT ["/bin/sh", "-c"]\nCMD node server.mjs\n');
  const { report } = await prepareHardenedImage(f.options);
  for (const code of ['selected_from_platform_differs', 'runtime_major_change', 'runtime_minor_change', 'libc_change', 'selected_stage_has_run_instructions', 'selected_stage_uses_shell_command'])
    assert.ok(report.compatibility.blockers.includes(code), code);
});

test('major-only tags and inherited entrypoints explicitly remain unverified', async t => {
  const f = await fixture(t, 'FROM node:24-bookworm-slim\nCMD ["node", "server.mjs"]\n');
  const { report } = await prepareHardenedImage({ ...f.options, image: 'gcr.io/distroless/nodejs24-debian13:nonroot' });
  assert.ok(report.compatibility.blockers.includes('runtime_minor_unknown'));
  assert.ok(report.compatibility.blockers.includes('inherited_entrypoint_or_cmd_requires_review'));
});

test('non-runtime image names cannot be inferred as Node or Python runtimes from a prefix', async t => {
  const f = await fixture(t);
  for (const name of ['node-exporter', 'python-exporter', 'node123', 'python-helper']) {
    const { report } = await prepareHardenedImage({ ...f.options, image: `dhi.io/${name}:24.16-debian13` });
    assert.equal(report.compatibility.candidateRuntime.family, null);
    assert.ok(report.compatibility.blockers.includes('runtime_family_unknown'));
  }
});

test('unresolved FROM platform cannot be mistaken for the selected platform', async t => {
  const f = await fixture(t, 'FROM --platform=$TARGETPLATFORM node:24.16-bookworm-slim\n');
  const { report } = await prepareHardenedImage(f.options);
  assert.ok(report.compatibility.blockers.includes('unresolved_from_platform'));
});

test('unsafe inputs, output in checkout, symlink destinations and existing reports preserve user files', async t => {
  const f = await fixture(t);
  for (const dockerfile of ['../Dockerfile', '/tmp/Dockerfile', 'Dockerfile\n+++ injected', 'Dockerfile\tname'])
    await assert.rejects(prepareHardenedImage({ ...f.options, dockerfile }));
  for (const stage of ['missing', '9']) await assert.rejects(prepareHardenedImage({ ...f.options, stage }));
  await assert.rejects(acquireHardenedImage({ ...f.options, platform: 'linux/386' }));
  await assert.rejects(acquireHardenedImage({ ...f.options, output: path.join(f.project, 'report') }));
  await mkdir(f.options.output); await writeFile(path.join(f.options.output, 'keep'), 'unchanged');
  const fake = fakeDocker();
  await assert.rejects(acquireHardenedImage({ ...f.options, pull: true }, fake));
  assert.equal(fake.calls.length, 0); assert.equal(await readFile(path.join(f.options.output, 'keep'), 'utf8'), 'unchanged');
  const linked = path.join(f.outer, 'link'); await symlink(f.options.output, linked);
  await assert.rejects(acquireHardenedImage({ ...f.options, output: path.join(linked, 'report') }));
  const dockerLink = path.join(f.project, 'Dockerfile.link'); await symlink(path.join(f.project, 'Dockerfile'), dockerLink);
  await assert.rejects(prepareHardenedImage({ ...f.options, dockerfile: 'Dockerfile.link' }));
});

test('default temporary output inside the selected project is rejected and its fresh directory removed', async t => {
  const f = await fixture(t), previous = process.env.TMPDIR;
  try {
    process.env.TMPDIR = f.project;
    await assert.rejects(acquireHardenedImage({ ...f.options, output: undefined }), /outside the project/);
  } finally { if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous; }
  assert.deepEqual(await readdir(f.project), ['Dockerfile']);
});

test('community CLI validates options without an updater or company network call', async t => {
  const f = await fixture(t);
  const previous = globalThis.fetch;
  globalThis.fetch = () => { throw Error('Community tools must not contact a company update endpoint'); };
  try {
    for (const argv of [['--wat'], ['--help', '--pull'], ['--image'], ['--pull', '--pull'], ['--project', 'x', '--project', 'y']])
      await assert.rejects(main(argv));
    await assert.rejects(main(['--project', '/missing-project', '--image', IMAGE, '--platform', 'linux/amd64']));
  } finally { globalThis.fetch = previous; }
});

test('community hardened helper remains self-contained and offline for help, preview and no-pull planning', async t => {
  const f = await fixture(t), installed = path.join(f.outer, 'installed'); await mkdir(installed);
  const helper = path.join(installed, 'hardened-image.mjs'); await copyFile(HELPER, helper);
  const updater = path.join(installed, 'update.mjs'); await writeFile(updater, "throw Error('Company updater must not load');\n");
  const help = spawnSync(process.execPath, [helper, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /No automatic update/);
  const argv = ['--project', f.project, '--image', IMAGE, '--platform', 'linux/amd64'];
  const preview = spawnSync(process.execPath, [helper, ...argv, '--pull', '--preview'], { encoding: 'utf8' });
  assert.equal(preview.status, 0, preview.stderr); assert.equal(JSON.parse(preview.stdout).acquisition.status, 'not_requested');
  const plan = spawnSync(process.execPath, [helper, ...argv, '--output', f.options.output], { encoding: 'utf8' });
  assert.equal(plan.status, 0, plan.stderr); assert.equal(JSON.parse(plan.stdout).acquisition.status, 'not_requested');
});
