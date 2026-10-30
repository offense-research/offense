import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { buildStackImage, collectStackEvidence, executeStackCommand, mapImageArchive, StackCollectionError } from '../scripts/stack-collection.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const CONFIG = Buffer.from(JSON.stringify({ os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: [] } }));
const IMAGE = 'sha256:' + hash(CONFIG), OTHER = 'sha256:' + 'b'.repeat(64);
const CONTAINER = 'c'.repeat(64), SENTINEL = 'DO_NOT_EXPORT_ENV_OR_LABEL_VALUES';
const imageInspect = () => ({ Id: IMAGE, RepoDigests: ['fixture.invalid/app@' + OTHER], Os: 'linux', Architecture: 'amd64',
  Config: { Env: ['TOKEN=' + SENTINEL], Labels: { token: SENTINEL } } });
const deploymentInspect = () => ({ Id: CONTAINER, Image: IMAGE, Config: { Image: 'offense-stack-fixture:local', Env: ['TOKEN=' + SENTINEL] },
  State: { Running: true, Status: 'running', StartedAt: '2026-10-28T00:00:00.000Z', Error: SENTINEL }, Mounts: [], HostConfig: { ReadonlyRootfs: true } });

function tar(entries) {
  const chunks = [];
  for (const [name, content] of Object.entries(entries)) {
    const bytes = Buffer.from(content), header = Buffer.alloc(512);
    header.write(name); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257);
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
const CLASSIC = tar({ [IMAGE.slice(7) + '.json']: CONFIG,
  'manifest.json': JSON.stringify([{ Config: IMAGE.slice(7) + '.json', RepoTags: ['fixture:local'], Layers: [] }]) });

async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-stack-collection-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const project = path.join(directory, 'repo');
  await executeStackCommand('git', ['init', '--quiet', project]);
  const git = async args => {
    const result = await executeStackCommand('git', ['-c', 'user.name=Offense fixture', '-c', 'user.email=fixture@example.invalid',
      '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', '-C', project, ...args]);
    assert.equal(result.code, 0); return result.stdout.toString().trim();
  };
  await writeFile(path.join(project, 'Dockerfile'), 'FROM scratch\nCOPY app /app\n');
  await writeFile(path.join(project, 'app'), 'tracked-build-input');
  await git(['add', '.']); await git(['commit', '--quiet', '-m', 'Source fixture']);
  const sourceRevision = await git(['rev-parse', 'HEAD']), sourceTree = await git(['rev-parse', 'HEAD^{tree}']);
  const declaration = { schemaVersion: 1, environment: 'test', sourceRevision, dockerfile: 'Dockerfile',
    image: { reference: 'offense-stack-fixture:local', digest: IMAGE, digestKind: 'image-config' } };
  await writeFile(path.join(project, 'offense-stack.json'), JSON.stringify(declaration));
  await git(['add', '.']); await git(['commit', '--quiet', '-m', 'Pin release declaration']);
  const sourceArchive = await executeStackCommand('git', ['-C', project, 'archive', '--format=tar', sourceRevision]);
  const receipt = { schemaVersion: 'offense.stack.build.v1', assertion: 'local_build_receipt', builtAt: '2026-10-28T00:00:00.000Z',
    repository: { revision: sourceRevision, tree: sourceTree }, archiveSha256: hash(sourceArchive.stdout),
    dockerfile: { path: 'Dockerfile', sha256: createHash('sha256').update(await readFile(path.join(project, 'Dockerfile'))).digest('hex') },
    image: { id: IMAGE, platform: { os: 'linux', architecture: 'amd64' } }, unrelated: SENTINEL };
  const buildReceipt = path.join(directory, 'build.json'); await writeFile(buildReceipt, JSON.stringify(receipt));
  const calls = [];
  const execute = async (command, args, options) => {
    if (command !== 'docker') return await executeStackCommand(command, args, options);
    calls.push({ command, args, options });
    if (args[0] === 'image' && args[1] === 'save') return { code: 0, stdout: CLASSIC };
    if (args[0] === 'image') return { code: 0, stdout: JSON.stringify([imageInspect()]) };
    if (args[0] === 'container' && args[1] === 'diff') return { code: 0, stdout: '' };
    if (args[0] === 'container') return { code: 0, stdout: JSON.stringify([deploymentInspect()]) };
    if (args[0] === 'build') {
      await writeFile(args[args.indexOf('--iidfile') + 1], IMAGE);
      return { code: 0, stdout: '' };
    }
    throw Error('Unexpected Docker command');
  };
  return { directory, project, git, sourceRevision, sourceTree, declaration, receipt, buildReceipt, execute, calls };
}

test('collects exact source, image and live deployment identities while dropping raw Docker/receipt data', async t => {
  const f = await fixture(t);
  const snapshot = await collectStackEvidence({ project: f.project, container: 'fixture', buildReceipt: f.buildReceipt, execute: f.execute });
  assert.equal(snapshot.schemaVersion, 'offense.stack.snapshot.v1');
  assert.equal(snapshot.repository.sourceRevision, f.sourceRevision);
  assert.equal(snapshot.repository.sourceTree, f.sourceTree);
  assert.notEqual(snapshot.repository.revision, f.sourceRevision);
  assert.equal(snapshot.declaration.tracked, true);
  assert.deepEqual(snapshot.repository.sourceChangesSinceBuild, []);
  assert.equal(snapshot.image.id, IMAGE); assert.equal(snapshot.image.revisionClaim, null);
  assert.equal(snapshot.deployment.imageId, IMAGE); assert.equal(snapshot.deployment.running, true);
  assert.equal(snapshot.build.assertion, 'local_build_receipt');
  assert.match(snapshot.build.receiptSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(snapshot.gaps, []);
  assert.ok(!JSON.stringify(snapshot).includes(SENTINEL));
  assert.ok(!JSON.stringify(snapshot).includes(f.project));
  assert.deepEqual(f.calls.map(call => call.args.slice(0, 2)), [['container', 'inspect'], ['container', 'diff'], ['container', 'inspect'], ['image', 'inspect'], ['image', 'save']]);
  assert.equal(snapshot.deployment.filesystemDiffObserved, true); assert.equal(snapshot.deployment.readOnlyRootfs, true);
  assert.equal(snapshot.image.configDigest, IMAGE); assert.equal(snapshot.image.identityKind, 'image-config');
  assert.equal(snapshot.image.mappingVerified, true);
});

test('source changes after a declared build are retained rather than hidden by a deployment-only commit', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.project, 'app'), 'different committed code');
  await f.git(['add', '.']); await f.git(['commit', '--quiet', '-m', 'Change application']);
  const snapshot = await collectStackEvidence({ project: f.project, container: 'fixture', buildReceipt: f.buildReceipt, execute: f.execute });
  assert.ok(snapshot.gaps.some(gap => gap.code === 'source_changed_since_build'));
  assert.deepEqual(snapshot.repository.sourceChangesSinceBuild, ['app']);
});

test('dirty tracked and untracked state never claims to be the captured HEAD', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.project, 'app'), 'uncommitted patch');
  await writeFile(path.join(f.project, 'unknown-file'), 'untracked');
  const snapshot = await collectStackEvidence({ project: f.project, execute: f.execute });
  assert.equal(snapshot.repository.dirtyTracked, true); assert.equal(snapshot.repository.untrackedCount, 1);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'repository_dirty'));
  assert.ok(snapshot.gaps.some(gap => gap.code === 'build_receipt_missing'));
  assert.ok(snapshot.gaps.some(gap => gap.code === 'deployment_missing'));
});

test('mutable image declarations stay explicit and uncommitted declaration bytes are not authoritative', async t => {
  const f = await fixture(t);
  delete f.declaration.image.digest; delete f.declaration.image.digestKind;
  await writeFile(path.join(f.project, 'offense-stack.json'), JSON.stringify(f.declaration));
  const snapshot = await collectStackEvidence({ project: f.project, execute: f.execute });
  assert.equal(snapshot.declaration.tracked, false);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'mutable_declared_image'));
  assert.ok(snapshot.gaps.some(gap => gap.code === 'declaration_not_committed'));
});

test('pinned references require an explicit digest kind and reject contradictory config digests', async t => {
  const f = await fixture(t);
  f.declaration.image = { reference: 'fixture.invalid/app@' + OTHER };
  await writeFile(path.join(f.project, 'offense-stack.json'), JSON.stringify(f.declaration));
  let snapshot = await collectStackEvidence({ project: f.project, execute: f.execute });
  assert.ok(snapshot.gaps.some(gap => gap.code === 'invalid_declaration_digest'));
  f.declaration.image.digestKind = 'manifest';
  await writeFile(path.join(f.project, 'offense-stack.json'), JSON.stringify(f.declaration));
  snapshot = await collectStackEvidence({ project: f.project, execute: f.execute });
  assert.equal(snapshot.declaration.image.digestKind, 'manifest');
  assert.equal(snapshot.declaration.image.digest, OTHER);
  f.declaration.image.digest = IMAGE; f.declaration.image.digestKind = 'image-config';
  await writeFile(path.join(f.project, 'offense-stack.json'), JSON.stringify(f.declaration));
  snapshot = await collectStackEvidence({ project: f.project, execute: f.execute });
  assert.ok(snapshot.gaps.some(gap => gap.code === 'invalid_declaration_digest'));
});

test('unavailable Docker and malformed receipt remain coverage gaps without leaking subprocess text', async t => {
  const f = await fixture(t);
  await writeFile(f.buildReceipt, '{"credential":"' + SENTINEL + '"}');
  const execute = async (command, args, options) => command === 'docker' ? { code: 1, stdout: SENTINEL, stderr: SENTINEL } : f.execute(command, args, options);
  const snapshot = await collectStackEvidence({ project: f.project, container: 'fixture', buildReceipt: f.buildReceipt, execute });
  assert.equal(snapshot.image, null); assert.equal(snapshot.deployment, null); assert.equal(snapshot.build, null);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'invalid_build_receipt'));
  assert.ok(!JSON.stringify(snapshot).includes(SENTINEL));
});

test('symlinked declaration and receipt are rejected before reading their targets', async t => {
  const f = await fixture(t);
  const external = path.join(f.directory, 'secret.json'); await writeFile(external, JSON.stringify(f.declaration));
  const declaration = path.join(f.project, 'linked.json'); await symlink(external, declaration);
  const receipt = path.join(f.directory, 'linked-receipt.json'); await symlink(f.buildReceipt, receipt);
  const snapshot = await collectStackEvidence({ project: f.project, declaration: 'linked.json', buildReceipt: receipt, execute: f.execute });
  assert.ok(snapshot.gaps.filter(gap => gap.code === 'symlink_refused').length >= 2);
});

test('build uses a clean immutable Git archive, disabled RUN networking and a locally asserted receipt', async t => {
  const f = await fixture(t);
  const built = await buildStackImage({ project: f.project, image: 'offense-stack-fixture:candidate', execute: f.execute });
  const build = f.calls.find(call => call.args[0] === 'build');
  assert.ok(build.args.includes('--network=none')); assert.ok(build.args.includes('--pull=false'));
  assert.equal(build.args.at(-1), '-'); assert.ok(Buffer.isBuffer(build.options.input));
  assert.ok(build.options.input.includes(Buffer.from('tracked-build-input')));
  assert.equal(built.receipt.repository.revision, await f.git(['rev-parse', 'HEAD']));
  assert.equal(built.receipt.image.id, IMAGE);
  assert.equal(built.receipt.assertion, 'local_build_receipt');
  assert.equal(built.receipt.archiveSha256, createHash('sha256').update(build.options.input).digest('hex'));
  assert.ok(!JSON.stringify(built).includes(SENTINEL));
});

test('build refuses changed source and tracked symlinks without invoking Docker', async t => {
  const dirty = await fixture(t);
  await writeFile(path.join(dirty.project, 'app'), 'pending fix');
  await assert.rejects(buildStackImage({ project: dirty.project, image: 'fixture:test', execute: dirty.execute }), { code: 'build_requires_clean_repository' });
  assert.equal(dirty.calls.length, 0);
  const linked = await fixture(t);
  await symlink('/etc/passwd', path.join(linked.project, 'external'));
  await linked.git(['add', '.']); await linked.git(['commit', '--quiet', '-m', 'Add link']);
  await assert.rejects(buildStackImage({ project: linked.project, image: 'fixture:test', execute: linked.execute }), { code: 'unsupported_build_context' });
  assert.equal(linked.calls.length, 0);
});

test('a concurrent change during Docker build cannot receive a current-source build receipt', async t => {
  const f = await fixture(t);
  const execute = async (command, args, options) => {
    const result = await f.execute(command, args, options);
    if (command === 'docker' && args[0] === 'build') await writeFile(path.join(f.project, 'app'), 'changed while Docker was building');
    return result;
  };
  await assert.rejects(buildStackImage({ project: f.project, image: 'fixture:test', execute }), { code: 'source_changed_during_build' });
});

test('command output bounds and errors use safe fixed categories', async () => {
  await assert.rejects(executeStackCommand('/usr/bin/printf', ['%s', 'x'.repeat(10000)], { maxBuffer: 100 }),
    error => error instanceof StackCollectionError && error.code === 'command_output_limit' && !error.message.includes('xxxx'));
  await assert.rejects(executeStackCommand('offense-missing-command-fixture', []), { code: 'command_unavailable' });
});

test('OCI index, platform manifest and config are separately hash-verified', () => {
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { digest: IMAGE }, layers: [] }));
  const manifestDigest = 'sha256:' + hash(manifest);
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [{ digest: manifestDigest,
    platform: { os: 'linux', architecture: 'amd64' } }] }));
  const indexDigest = 'sha256:' + hash(index);
  const bytes = tar({ ['blobs/sha256/' + IMAGE.slice(7)]: CONFIG,
    ['blobs/sha256/' + manifestDigest.slice(7)]: manifest, ['blobs/sha256/' + indexDigest.slice(7)]: index });
  const result = mapImageArchive(bytes, { id: indexDigest, platform: { os: 'linux', architecture: 'amd64' } });
  assert.equal(result.identityKind, 'index'); assert.equal(result.configDigest, IMAGE);
  assert.deepEqual(result.manifestDigests, [manifestDigest]); assert.deepEqual(result.indexDigests, [indexDigest]);
  const corrupted = tar({ ['blobs/sha256/' + IMAGE.slice(7)]: Buffer.from('{}'),
    ['blobs/sha256/' + manifestDigest.slice(7)]: manifest, ['blobs/sha256/' + indexDigest.slice(7)]: index });
  assert.throws(() => mapImageArchive(corrupted, { id: indexDigest, platform: { os: 'linux', architecture: 'amd64' } }), { code: 'image_descriptor_mismatch' });
});

test('tampered source archive hash and unavailable digest mapping remain gaps', async t => {
  const f = await fixture(t); f.receipt.archiveSha256 = 'f'.repeat(64);
  await writeFile(f.buildReceipt, JSON.stringify(f.receipt));
  const execute = async (command, args, options) => command === 'docker' && args[1] === 'save' ?
    { code: 1, stdout: '' } : f.execute(command, args, options);
  const snapshot = await collectStackEvidence({ project: f.project, buildReceipt: f.buildReceipt, execute });
  assert.ok(snapshot.gaps.some(gap => gap.code === 'source_archive_mismatch'));
  assert.ok(snapshot.gaps.some(gap => gap.code === 'image_digest_mapping_unavailable'));
  assert.equal(snapshot.image.mappingVerified, false); assert.equal(snapshot.image.configDigest, null);
});

test('build preflight rejects registry/frontend acquisition and RUN network overrides before building', async t => {
  for (const [dockerfile, code] of [
    ['# syntax=docker/dockerfile:1\nFROM scratch\n', 'unsupported_dockerfile_frontend'],
    ['ARG BASE\nFROM $BASE\n', 'unsupported_dockerfile_base'],
    ['FROM scratch\nADD https://fixture.invalid/source /app\n', 'unsupported_dockerfile_instruction'],
    ['FROM scratch\nCOPY --from=external.invalid/image:tag /app /app\n', 'external_copy_source'],
    ['FROM scratch\nRUN --network=default fetch-private-data\n', 'build_network_override'],
    ['FROM scratch\nRUN --network=none --network=default fetch-private-data\n', 'build_network_override'],
    ['FROM scratch\nRUN --mount=type=cache,target=/cache collect-data\n', 'unsupported_build_mount'],
    ['FROM scratch\nRUN --mount type=secret collect-data\n', 'unsupported_build_mount'],
  ]) {
    const f = await fixture(t);
    await writeFile(path.join(f.project, 'Dockerfile'), dockerfile);
    await f.git(['add', '.']); await f.git(['commit', '--quiet', '-m', 'Review build inputs']);
    await assert.rejects(buildStackImage({ project: f.project, image: 'fixture:local', execute: f.execute }), { code });
    assert.equal(f.calls.some(call => call.args[0] === 'build'), false);
  }
});

test('runtime filesystem changes and mount destinations are collected without host paths, options or credentials', async t => {
  const f = await fixture(t);
  const execute = async (command, args, options) => {
    if (command === 'docker' && args[0] === 'container' && args[1] === 'diff') return { code: 0, stdout: 'C /app\nA /manual-patch\nD /old\n' };
    if (command === 'docker' && args[0] === 'container' && args[1] === 'inspect') return { code: 0, stdout: JSON.stringify([{ ...deploymentInspect(),
      Mounts: [{ Type: 'bind', Source: '/private/' + SENTINEL, Destination: '/config', RW: false, Options: [SENTINEL] }],
    }]) };
    return f.execute(command, args, options);
  };
  const snapshot = await collectStackEvidence({ project: f.project, container: 'fixture', buildReceipt: f.buildReceipt, execute });
  assert.deepEqual(snapshot.deployment.filesystemChanges, [{ kind: 'C', path: '/app' }, { kind: 'A', path: '/manual-patch' }, { kind: 'D', path: '/old' }]);
  assert.deepEqual(snapshot.deployment.mounts, [{ type: 'bind', destination: '/config', readOnly: true }]);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'runtime_mounts_unassessed'));
  assert.ok(!JSON.stringify(snapshot).includes(SENTINEL));
});

test('failed filesystem evidence and a restarted container cannot be mistaken for a stable observation', async t => {
  const f = await fixture(t); let reads = 0;
  const execute = async (command, args, options) => {
    if (command === 'docker' && args[0] === 'container' && args[1] === 'diff') return { code: 1, stdout: '' };
    if (command === 'docker' && args[0] === 'container' && args[1] === 'inspect') {
      const value = deploymentInspect(); if (reads++) value.State.StartedAt = '2026-10-28T01:00:00.000Z';
      return { code: 0, stdout: JSON.stringify([value]) };
    }
    return f.execute(command, args, options);
  };
  const snapshot = await collectStackEvidence({ project: f.project, container: 'fixture', buildReceipt: f.buildReceipt, execute });
  assert.equal(snapshot.deployment.filesystemDiffObserved, false);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'filesystem_diff_unavailable'));
  assert.ok(snapshot.gaps.some(gap => gap.code === 'deployment_changed_during_collection'));
});
