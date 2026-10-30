import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdtemp, open, readFile, realpath, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const REVISION = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const MAX_JSON = 2 * 1024 * 1024;
const MAX_ARCHIVE = 64 * 1024 * 1024;
const MAX_IMAGE_ARCHIVE = 80 * 1024 * 1024;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const buffer = value => Buffer.isBuffer(value) ? value : Buffer.from(value || '');

export class StackCollectionError extends Error {
  constructor(code, message) { super(message); this.name = 'StackCollectionError'; this.code = code; }
}

// Deliberately never include subprocess stderr in exceptions: inspect/build
// diagnostics can contain registry addresses, source contents or credentials.
export async function executeStackCommand(command, args, { cwd, input, maxBuffer = MAX_JSON, timeout = 30_000 } = {}) {
  return await new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (command === 'git') for (const name of Object.keys(env)) if (name.startsWith('GIT_')) delete env[name];
    let child;
    try { child = spawn(command, args, { cwd, env, shell: false, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch { reject(new StackCollectionError('command_unavailable', 'A required local command could not start.')); return; }
    const chunks = []; let size = 0, stderrSize = 0, settled = false;
    const finish = (error, result) => {
      if (settled) return; settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(result);
    };
    const fail = (code, message) => { child.kill('SIGKILL'); finish(new StackCollectionError(code, message)); };
    const timer = setTimeout(() => fail('command_timeout', 'A local evidence command timed out; no complete result was established.'), timeout);
    child.once('error', () => finish(new StackCollectionError('command_unavailable', 'A required local command is unavailable or inaccessible.')));
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > maxBuffer) { fail('command_output_limit', 'Local evidence exceeded the supported size limit.'); return; }
      chunks.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrSize += chunk.length;
      if (stderrSize > 4 * 1024 * 1024) fail('command_output_limit', 'Local command diagnostics exceeded the supported size limit.');
    });
    child.once('close', code => finish(null, { code, stdout: Buffer.concat(chunks) }));
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

async function invoke(execute, command, args, options) {
  const result = await execute(command, args, options);
  if (!result || result.code !== 0) throw new StackCollectionError('command_failed', 'A local evidence command failed; review access and prerequisites locally.');
  return buffer(result.stdout);
}

function relativeFile(value, code = 'invalid_project_path') {
  if (typeof value !== 'string' || !value || value.length > 240 || path.isAbsolute(value) ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' || part === '.git') ||
      /[\x00-\x1f\x7f]/.test(value)) throw new StackCollectionError(code, 'Choose a regular project-relative file without traversal or Git internals.');
  return value;
}

function imageReference(value, { tagOnly = false } = {}) {
  if (typeof value !== 'string' || !value || value.length > 300 || value.startsWith('-') ||
      !/^[A-Za-z0-9][A-Za-z0-9._/:@-]*$/.test(value) || value.includes('://') ||
      value.includes('@') && !/^[^@]+@sha256:[a-f0-9]{64}$/.test(value) ||
      tagOnly && (value.includes('@') || DIGEST.test(value))) throw new StackCollectionError('invalid_image_reference', 'Choose an explicit image reference, without URLs, credentials or command options.');
  return value;
}

async function noSymlinks(filename) {
  const absolute = path.resolve(filename); let current = path.parse(absolute).root;
  for (const segment of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new StackCollectionError('symlink_refused', 'Evidence files and project paths must not pass through symbolic links.');
  }
}

async function regularBytes(filename, maximum = MAX_JSON) {
  await noSymlinks(filename);
  let handle;
  try {
    handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const info = await handle.stat();
    if (!info.isFile() || info.size > maximum) throw new StackCollectionError('invalid_evidence_file', 'Evidence must be a bounded regular file.');
    return await handle.readFile();
  } finally { await handle?.close(); }
}

function json(bytes, code) {
  try { const value = JSON.parse(buffer(bytes).toString('utf8')); if (object(value)) return value; }
  catch {}
  throw new StackCollectionError(code, 'Local evidence is not a supported JSON object.');
}

function gitArgs(project, args) { return ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', project, ...args]; }

async function repositoryAt(project, execute) {
  const root = await realpath(project || process.cwd());
  const top = (await invoke(execute, 'git', gitArgs(root, ['rev-parse', '--show-toplevel']))).toString().trim();
  if (await realpath(top) !== root) throw new StackCollectionError('repository_root_required', 'Choose the Git repository root for stack evidence.');
  const revision = (await invoke(execute, 'git', gitArgs(root, ['rev-parse', '--verify', 'HEAD^{commit}']))).toString().trim();
  const tree = (await invoke(execute, 'git', gitArgs(root, ['rev-parse', '--verify', 'HEAD^{tree}']))).toString().trim();
  if (!REVISION.test(revision) || !REVISION.test(tree)) throw new StackCollectionError('invalid_git_identity', 'The repository does not have a supported immutable Git identity.');
  const status = (await invoke(execute, 'git', gitArgs(root, ['status', '--porcelain=v1', '-z', '--untracked-files=normal']), { maxBuffer: 256 * 1024 })).toString();
  const entries = status.split('\0').filter(Boolean);
  const untrackedCount = entries.filter(entry => entry.startsWith('?? ')).length;
  const dirtyTracked = entries.some(entry => !entry.startsWith('?? '));
  return { root, repository: { revision, tree, sourceRevision: revision, sourceTree: tree, clean: entries.length === 0,
    dirty: entries.length > 0, dirtyTracked, untrackedCount, source: 'git_head', sourceChangesSinceBuild: [] } };
}

async function readDeclaration(root, filename, execute) {
  const absolute = path.resolve(root, filename || 'offense-stack.json');
  const relative = relativeFile(path.relative(root, absolute).split(path.sep).join('/'), 'invalid_declaration_path');
  const bytes = await regularBytes(absolute, 64 * 1024), value = json(bytes, 'invalid_declaration');
  if (value.schemaVersion !== 1 || !object(value.image) || typeof value.environment !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(value.environment)) throw new StackCollectionError('invalid_declaration', 'Use a version 1 stack declaration with an environment and image object.');
  const reference = imageReference(value.image.reference);
  let digest = value.image.digest, digestKind = value.image.digestKind;
  const pinned = reference.match(/@(?<digest>sha256:[a-f0-9]{64})$/)?.groups.digest;
  if (!digest && pinned) digest = pinned;
  if (!digest && DIGEST.test(reference)) digest = reference;
  if (digest !== undefined && (!DIGEST.test(digest) || !['manifest', 'image-config', 'index'].includes(digestKind)))
    throw new StackCollectionError('invalid_declaration_digest', 'An image digest needs an explicit manifest, index or image-config digest kind.');
  if (pinned && (digest !== pinned || !['manifest', 'index'].includes(digestKind))) throw new StackCollectionError('invalid_declaration_digest', 'The declared digest conflicts with its immutable image reference.');
  if (value.sourceRevision !== undefined && !REVISION.test(value.sourceRevision)) throw new StackCollectionError('invalid_source_revision', 'sourceRevision must be an exact Git commit.');
  const dockerfile = relativeFile(value.dockerfile || 'Dockerfile');
  let tracked = false;
  try {
    const committed = await invoke(execute, 'git', gitArgs(root, ['show', 'HEAD:' + relative]), { maxBuffer: 64 * 1024 });
    tracked = committed.equals(bytes);
  } catch {}
  return { path: relative, sha256: sha256(bytes), tracked, environment: value.environment, dockerfile,
    ...(value.sourceRevision ? { sourceRevision: value.sourceRevision } : {}),
    image: { reference, ...(digest ? { digest, digestKind } : {}) } };
}

function normalizeImage(value) {
  if (!object(value) || !DIGEST.test(value.Id) || !/^[a-z0-9_-]{1,40}$/.test(value.Os || '') || !/^[a-z0-9_-]{1,40}$/.test(value.Architecture || ''))
    throw new StackCollectionError('invalid_image_inspect', 'The selected image did not return a supported immutable identity.');
  const repoDigests = (Array.isArray(value.RepoDigests) ? value.RepoDigests : []).filter(item =>
    typeof item === 'string' && item.length <= 400 && /^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[a-f0-9]{64}$/.test(item)).slice(0, 32).sort();
  const revision = value.Config?.Labels?.['org.opencontainers.image.revision'];
  const mediaType = value.Descriptor?.mediaType;
  const identityKind = /(?:image\.index|manifest\.list)\./.test(mediaType || '') ? 'index' :
    /(?:image\.manifest|distribution\.manifest)\./.test(mediaType || '') ? 'manifest' : 'unknown';
  return { id: value.Id, repoDigests, platform: { os: value.Os, architecture: value.Architecture,
    ...(/^[a-z0-9_-]{1,40}$/.test(value.Variant || '') ? { variant: value.Variant } : {}) },
    identityKind, revisionClaim: REVISION.test(revision || '') ? revision : null };
}

// Read only the archive index and content-addressed metadata. Layer contents are
// never extracted or executed. Every descriptor traversed is checked by digest.
export function mapImageArchive(bytes, image) {
  const archive = buffer(bytes);
  if (archive.length > MAX_IMAGE_ARCHIVE) throw new StackCollectionError('image_archive_limit', 'The image archive exceeds the first-slice 80 MiB bound.');
  const files = new Map(); let offset = 0;
  const text = value => value.toString('utf8').replace(/\0.*$/s, '');
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512); offset += 512;
    if (header.every(value => value === 0)) break;
    const expected = parseInt(text(header.subarray(148, 156)).trim(), 8);
    let actual = 0; for (let i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : header[i];
    const sizeText = text(header.subarray(124, 136)).trim();
    const size = /^[0-7]+$/.test(sizeText) ? parseInt(sizeText, 8) : -1;
    if (!Number.isSafeInteger(expected) || expected !== actual || !Number.isSafeInteger(size) || size < 0 || offset + size > archive.length)
      throw new StackCollectionError('invalid_image_archive', 'The image archive has invalid bounded tar metadata.');
    const prefix = text(header.subarray(345, 500)), leaf = text(header.subarray(0, 100));
    const name = (prefix ? prefix + '/' : '') + leaf, type = header[156];
    const content = archive.subarray(offset, offset + size); offset += Math.ceil(size / 512) * 512;
    if (offset > archive.length || name.startsWith('/') || name.includes('\\') || name.split('/').some(part => part === '..') || files.has(name))
      throw new StackCollectionError('invalid_image_archive', 'The image archive has unsupported paths or duplicate entries.');
    if (type === 0 || type === 48) files.set(name, content);
    else if (type !== 53) throw new StackCollectionError('invalid_image_archive', 'The image archive has unsupported metadata entries.');
  }
  const readBlob = digest => {
    if (!DIGEST.test(digest || '')) throw new StackCollectionError('invalid_image_archive', 'An image descriptor has an invalid digest.');
    const bytes = files.get('blobs/sha256/' + digest.slice(7)) || files.get(digest.slice(7) + '.json');
    if (!bytes || sha256(bytes) !== digest.slice(7) || bytes.length > MAX_JSON) throw new StackCollectionError('image_descriptor_mismatch', 'Image descriptor content does not match its digest.');
    return json(bytes, 'invalid_image_descriptor');
  };
  const config = digest => {
    const value = readBlob(digest);
    if (value.os !== image.platform.os || value.architecture !== image.platform.architecture || !object(value.rootfs))
      throw new StackCollectionError('image_platform_mismatch', 'Image config does not match the selected platform.');
    return digest;
  };
  const manifests = [], indexes = [], seen = new Set(); let configDigest = null;
  const visit = (digest, depth = 0) => {
    if (depth > 3 || seen.has(digest)) throw new StackCollectionError('invalid_image_descriptor', 'The image descriptor graph is cyclic or too deep.');
    seen.add(digest); const value = readBlob(digest);
    if (Array.isArray(value.manifests)) {
      indexes.push(digest);
      const selected = value.manifests.filter(item => item.platform?.os === image.platform.os && item.platform?.architecture === image.platform.architecture &&
        (!image.platform.variant || item.platform.variant === image.platform.variant));
      if (selected.length !== 1) throw new StackCollectionError('image_platform_ambiguous', 'The image index does not select exactly one matching platform.');
      visit(selected[0].digest, depth + 1); return;
    }
    if (object(value.config)) { manifests.push(digest); configDigest = config(value.config.digest); return; }
    configDigest = config(digest);
  };
  try { visit(image.id); }
  catch (error) {
    // Classic docker-save has only manifest.json and the config file, while its
    // image ID already is the config digest. Never infer an OCI root from tags.
    const manifestBytes = files.get('manifest.json'); let values;
    try { values = manifestBytes && JSON.parse(manifestBytes); } catch {}
    if (!Array.isArray(values) || !values.some(item => typeof item.Config === 'string' &&
        files.has(item.Config) && sha256(files.get(item.Config)) === image.id.slice(7))) throw error;
    configDigest = config(image.id); manifests.length = 0; indexes.length = 0;
  }
  return { identityKind: indexes.includes(image.id) ? 'index' : manifests.includes(image.id) ? 'manifest' : 'image-config',
    configDigest, manifestDigests: manifests, indexDigests: indexes, mappingVerified: true, archiveSha256: sha256(archive) };
}

async function inspectImage(execute, reference) {
  const image = normalizeImage(await inspect(execute, 'image', reference));
  try {
    const bytes = await invoke(execute, 'docker', ['image', 'save', '--', image.id], { maxBuffer: MAX_IMAGE_ARCHIVE, timeout: 120_000 });
    return { image: { ...image, ...mapImageArchive(bytes, image) }, gap: null };
  } catch {
    return { image: { ...image, configDigest: null, manifestDigests: [], indexDigests: [], mappingVerified: false },
      gap: { code: 'image_digest_mapping_unavailable', message: 'A bounded image archive could not establish config/manifest/index digest relationships.' } };
  }
}

async function inspect(execute, kind, reference) {
  const output = await invoke(execute, 'docker', [kind, 'inspect', '--', reference], { maxBuffer: MAX_JSON, timeout: 30_000 });
  let values; try { values = JSON.parse(output); } catch {}
  if (!Array.isArray(values) || values.length !== 1 || !object(values[0])) throw new StackCollectionError('invalid_docker_inspect', 'Select exactly one inspectable local image or container.');
  return values[0];
}

async function preflightDockerfile(bytes, execute) {
  const source = bytes.toString('utf8').replace(/^\uFEFF/, '');
  if (/^\s*#\s*(?:syntax|escape)\s*=/mi.test(source)) throw new StackCollectionError('unsupported_dockerfile_frontend', 'The first stack builder uses the default Dockerfile frontend and escape syntax only.');
  const instructions = source.replace(/\\\r?\n/g, ' ').split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  const stages = new Set(); let stageCount = 0;
  for (const instruction of instructions) {
    if (instruction.includes('<<')) throw new StackCollectionError('unsupported_dockerfile_instruction', 'Dockerfile heredocs require a separately reviewed build workflow.');
    if (/^(?:ADD|ONBUILD)\b/i.test(instruction)) throw new StackCollectionError('unsupported_dockerfile_instruction', 'The first stack builder supports COPY instead of ADD and does not carry ONBUILD actions.');
    if (/^FROM\b/i.test(instruction)) {
      const match = instruction.match(/^FROM\s+(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*$/i);
      if (!match || match[1].includes('$') || match[1].startsWith('--')) throw new StackCollectionError('unsupported_dockerfile_base', 'Choose explicit locally available base images or scratch; expanded/platform-specific FROM directives need a separate workflow.');
      const base = match[1];
      if (base.toLowerCase() !== 'scratch' && !stages.has(base.toLowerCase())) {
        let value;
        try { value = await inspect(execute, 'image', imageReference(base)); }
        catch { throw new StackCollectionError('base_image_unavailable', 'A base image is not locally inspectable. Acquire the reviewed image separately before building.'); }
        if (Array.isArray(value.Config?.OnBuild) && value.Config.OnBuild.length) throw new StackCollectionError('unsupported_base_onbuild', 'The selected base contains ONBUILD actions and needs a separately reviewed build workflow.');
      }
      stages.add(String(stageCount++)); if (match[2]) stages.add(match[2].toLowerCase());
    }
    if (/^COPY\b/i.test(instruction)) {
      const from = instruction.match(/\s--from(?:=|\s+)(\S+)/i)?.[1];
      if (from && !stages.has(from.toLowerCase())) throw new StackCollectionError('external_copy_source', 'COPY --from must name a declared build stage; external images need a separate acquisition workflow.');
    }
    if (/^RUN\b/i.test(instruction)) {
      if (/\s--mount(?:=|\s)/i.test(instruction)) throw new StackCollectionError('unsupported_build_mount', 'The first stack builder does not use build cache, secret, SSH or bind mounts.');
      const overrides = [...instruction.matchAll(/\s--network(?:=([^\s]+)|\s+([^\s]+))/gi)];
      if (overrides.some(match => match[1] !== 'none'))
        throw new StackCollectionError('build_network_override', 'Dockerfile RUN instructions cannot override the disabled build network.');
    }
  }
  if (!stageCount) throw new StackCollectionError('unsupported_dockerfile_base', 'The Dockerfile must contain an explicit supported FROM stage.');
}

function normalizeDeployment(value, observedAt) {
  if (!/^[a-f0-9]{64}$/.test(value.Id || '') || !DIGEST.test(value.Image || '') || !object(value.State))
    throw new StackCollectionError('invalid_container_inspect', 'The selected container did not return a supported deployment identity.');
  const reference = imageReference(value.Config?.Image);
  const status = ['created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'].includes(value.State.Status) ? value.State.Status : 'unknown';
  const date = value.State.StartedAt;
  const mounts = Array.isArray(value.Mounts) ? value.Mounts.slice(0, 128).map(mount => ({
    type: ['bind', 'volume', 'tmpfs', 'npipe', 'cluster', 'image'].includes(mount.Type) ? mount.Type : 'unknown',
    destination: typeof mount.Destination === 'string' && mount.Destination.startsWith('/') && mount.Destination.length <= 512 &&
      !/[\x00-\x1f\x7f]/.test(mount.Destination) ? mount.Destination : '[unsupported destination]',
    readOnly: mount.RW === false,
  })) : null;
  return { adapter: 'docker', containerId: value.Id, imageId: value.Image, reference,
    running: value.State.Running === true, status, observedAt,
    startedAt: typeof date === 'string' && Number.isFinite(Date.parse(date)) ? date : null,
    mounts, readOnlyRootfs: value.HostConfig?.ReadonlyRootfs === true,
    filesystemDiffObserved: false, filesystemChanges: [] };
}

function filesystemChanges(bytes) {
  const lines = bytes.toString('utf8').split(/\r?\n/).filter(Boolean);
  if (lines.length > 1000) throw new StackCollectionError('filesystem_diff_limit', 'Container filesystem changes exceed the supported evidence bound.');
  return lines.map(line => {
    const match = line.match(/^([ACD]) (\/[^\x00-\x1f\x7f]*)$/);
    if (!match || match[2].length > 512) throw new StackCollectionError('filesystem_diff_unsupported', 'Container filesystem changes contain unsupported paths.');
    return { kind: match[1], path: match[2] };
  });
}

async function readReceipt(filename) {
  const bytes = await regularBytes(path.resolve(filename), 128 * 1024), receipt = json(bytes, 'invalid_build_receipt');
  if (receipt.schemaVersion !== 'offense.stack.build.v1' || receipt.assertion !== 'local_build_receipt' ||
      !REVISION.test(receipt.repository?.revision || '') || !REVISION.test(receipt.repository?.tree || '') ||
      !/^[a-f0-9]{64}$/.test(receipt.archiveSha256 || '') || !/^[a-f0-9]{64}$/.test(receipt.dockerfile?.sha256 || '') ||
      !DIGEST.test(receipt.image?.id || '') || !Number.isFinite(Date.parse(receipt.builtAt || '')))
    throw new StackCollectionError('invalid_build_receipt', 'The supplied local build receipt is incomplete or unsupported.');
  const dockerfile = relativeFile(receipt.dockerfile.path);
  const platform = receipt.image.platform;
  if (!object(platform) || !/^[a-z0-9_-]{1,40}$/.test(platform.os || '') || !/^[a-z0-9_-]{1,40}$/.test(platform.architecture || ''))
    throw new StackCollectionError('invalid_build_receipt', 'The local build receipt has an invalid platform.');
  // Import a fixed allowlist, not arbitrary local receipt fields.
  const identity = receipt.image;
  const identityKind = ['image-config', 'manifest', 'index', 'unknown'].includes(identity.identityKind) ? identity.identityKind : 'unknown';
  const digests = values => Array.isArray(values) ? values.filter(value => DIGEST.test(value)).slice(0, 4) : [];
  return { schemaVersion: receipt.schemaVersion, assertion: receipt.assertion,
    repository: { revision: receipt.repository.revision, tree: receipt.repository.tree }, archiveSha256: receipt.archiveSha256,
    dockerfile: { path: dockerfile, sha256: receipt.dockerfile.sha256 },
    image: { id: receipt.image.id, platform: { os: platform.os, architecture: platform.architecture,
      ...(/^[a-z0-9_-]{1,40}$/.test(platform.variant || '') ? { variant: platform.variant } : {}) }, identityKind,
      configDigest: DIGEST.test(identity.configDigest || '') ? identity.configDigest : null,
      manifestDigests: digests(identity.manifestDigests), indexDigests: digests(identity.indexDigests), mappingVerified: identity.mappingVerified === true },
    builtAt: receipt.builtAt, receiptSha256: sha256(bytes) };
}

export async function collectStackEvidence({ project = process.cwd(), image, container, declaration, buildReceipt,
  execute = executeStackCommand, now = () => new Date().toISOString() } = {}) {
  const capturedAt = now(), gaps = [];
  const addGap = (code, message) => gaps.push({ code, message });
  const { root, repository } = await repositoryAt(project, execute);
  const snapshot = { schemaVersion: 'offense.stack.snapshot.v1', capturedAt, repository, declaration: null, image: null, deployment: null, build: null, gaps };
  if (repository.dirty) addGap('repository_dirty', 'The working tree differs from HEAD; source identity refers to committed content only.');
  try {
    snapshot.declaration = await readDeclaration(root, declaration, execute);
    if (!snapshot.declaration.tracked) addGap('declaration_not_committed', 'The declaration is absent from HEAD or differs from its committed bytes.');
    if (!snapshot.declaration.image.digest) addGap('mutable_declared_image', 'The declaration does not pin an immutable image digest.');
    const sourceRevision = snapshot.declaration.sourceRevision;
    if (sourceRevision) {
      const resolved = (await invoke(execute, 'git', gitArgs(root, ['rev-parse', '--verify', sourceRevision + '^{commit}']))).toString().trim();
      const ancestor = await execute('git', gitArgs(root, ['merge-base', '--is-ancestor', sourceRevision, repository.revision]));
      if (resolved !== sourceRevision || ancestor.code !== 0) throw new StackCollectionError('source_not_ancestor', 'The declared build revision is not an ancestor of the current repository revision.');
      repository.sourceRevision = sourceRevision;
      repository.sourceTree = (await invoke(execute, 'git', gitArgs(root, ['rev-parse', '--verify', sourceRevision + '^{tree}']))).toString().trim();
      const differences = (await invoke(execute, 'git', gitArgs(root, ['diff', '--name-only', '-z', sourceRevision, repository.revision, '--']), { maxBuffer: 256 * 1024 })).toString().split('\0').filter(Boolean);
      repository.sourceChangesSinceBuild = differences.filter(file => file !== snapshot.declaration.path).map(file => file.replace(/[\x00-\x1f\x7f]/g, '?')).slice(0, 100);
      if (differences.some(file => file !== snapshot.declaration.path)) addGap('source_changed_since_build', 'Files besides the deployment declaration changed after the declared build revision.');
    }
    try {
      const bytes = await invoke(execute, 'git', gitArgs(root, ['show', repository.sourceRevision + ':' + snapshot.declaration.dockerfile]), { maxBuffer: 1024 * 1024 });
      snapshot.declaration.dockerfileSha256 = sha256(bytes);
    } catch { addGap('dockerfile_unavailable', 'The declared Dockerfile is not readable at the source revision.'); }
  } catch (error) {
    addGap(error instanceof StackCollectionError ? error.code : 'declaration_unavailable', error instanceof StackCollectionError ? error.message : 'The project stack declaration is missing or unreadable.');
  }
  if (buildReceipt) {
    try {
      snapshot.build = await readReceipt(buildReceipt);
      const archive = await invoke(execute, 'git', gitArgs(root, ['archive', '--format=tar', repository.sourceRevision]), { maxBuffer: MAX_ARCHIVE, timeout: 60_000 });
      if (sha256(archive) !== snapshot.build.archiveSha256) addGap('source_archive_mismatch', 'The local build receipt does not match the archived declared source revision.');
    }
    catch (error) { addGap(error instanceof StackCollectionError ? error.code : 'build_receipt_unavailable', 'The supplied local build receipt could not be validated.'); }
  } else addGap('build_receipt_missing', 'No local build receipt was supplied; an image revision label alone is not build provenance.');
  if (container) {
    try {
      if (typeof container !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(container)) throw new StackCollectionError('invalid_container_reference', 'Choose one explicit container name or ID.');
      const inspected = await inspect(execute, 'container', container);
      snapshot.deployment = normalizeDeployment(inspected, capturedAt);
      if (snapshot.deployment.mounts === null) addGap('runtime_mounts_unavailable', 'Container mount overrides could not be enumerated.');
      else if (snapshot.deployment.mounts.length || inspected.Mounts.length > 128)
        addGap('runtime_mounts_unassessed', 'Container mounts can override image contents and require separately verified configuration.');
      try {
        const changes = await invoke(execute, 'docker', ['container', 'diff', '--', snapshot.deployment.containerId], { maxBuffer: 1024 * 1024, timeout: 30_000 });
        snapshot.deployment.filesystemChanges = filesystemChanges(changes);
        snapshot.deployment.filesystemDiffObserved = true;
      } catch { addGap('filesystem_diff_unavailable', 'The selected container writable layer could not be completely observed.'); }
      try {
        const after = normalizeDeployment(await inspect(execute, 'container', snapshot.deployment.containerId), capturedAt);
        if (after.containerId !== snapshot.deployment.containerId || after.imageId !== snapshot.deployment.imageId ||
            after.startedAt !== snapshot.deployment.startedAt || after.status !== snapshot.deployment.status)
          addGap('deployment_changed_during_collection', 'Container identity or runtime state changed during evidence collection.');
      } catch { addGap('deployment_changed_during_collection', 'Container state could not be read back after filesystem collection.'); }
    } catch (error) { addGap(error instanceof StackCollectionError ? error.code : 'deployment_unavailable', 'The selected Docker deployment could not be observed.'); }
  } else addGap('deployment_missing', 'No container was selected; deployed state has not been observed.');
  const imageSelection = image || snapshot.build?.image.id || snapshot.deployment?.imageId || snapshot.declaration?.image.reference;
  if (imageSelection) {
    try {
      const observed = await inspectImage(execute, imageReference(imageSelection));
      snapshot.image = observed.image; if (observed.gap) gaps.push(observed.gap);
    }
    catch (error) { addGap(error instanceof StackCollectionError ? error.code : 'image_unavailable', 'The selected local image could not be inspected.'); }
  } else addGap('image_missing', 'No built image was selected or inferred.');
  return snapshot;
}

export async function buildStackImage({ project = process.cwd(), image, dockerfile = 'Dockerfile',
  execute = executeStackCommand, now = () => new Date().toISOString() } = {}) {
  const reference = imageReference(image, { tagOnly: true }), relative = relativeFile(dockerfile);
  const { root, repository } = await repositoryAt(project, execute);
  if (!repository.clean) throw new StackCollectionError('build_requires_clean_repository', 'Commit or isolate source changes before building; stack build uses only a clean Git HEAD archive.');
  const listing = (await invoke(execute, 'git', gitArgs(root, ['ls-tree', '-r', '-z', '--full-tree', repository.revision]), { maxBuffer: 2 * 1024 * 1024 })).toString();
  if (listing.split('\0').some(entry => /^(?:120000|160000) /.test(entry))) throw new StackCollectionError('unsupported_build_context', 'This first build adapter does not support tracked symlinks or submodules.');
  if (!listing.split('\0').some(entry => entry.endsWith('\t' + relative))) throw new StackCollectionError('dockerfile_not_committed', 'The selected Dockerfile must be a regular file committed at HEAD.');
  try {
    const attributes = await invoke(execute, 'git', gitArgs(root, ['show', repository.revision + ':.gitattributes']), { maxBuffer: 64 * 1024 });
    if (/filter\s*=\s*lfs/.test(attributes.toString())) throw new StackCollectionError('unsupported_build_context', 'Git LFS build inputs require a separately verified materialization workflow.');
  } catch (error) { if (error instanceof StackCollectionError && error.code === 'unsupported_build_context') throw error; }
  const dockerfileBytes = await invoke(execute, 'git', gitArgs(root, ['show', repository.revision + ':' + relative]), { maxBuffer: 1024 * 1024 });
  await preflightDockerfile(dockerfileBytes, execute);
  const archive = await invoke(execute, 'git', gitArgs(root, ['archive', '--format=tar', repository.revision]), { maxBuffer: MAX_ARCHIVE, timeout: 60_000 });
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-stack-build-'));
  try {
    const iid = path.join(directory, 'image-id');
    await invoke(execute, 'docker', ['build', '--network=none', '--pull=false', '--iidfile', iid,
      '--label', 'org.opencontainers.image.revision=' + repository.revision, '--tag', reference, '--file', relative, '-'],
    { cwd: root, input: archive, maxBuffer: 1024 * 1024, timeout: 10 * 60_000 });
    const id = (await regularBytes(iid, 256)).toString().trim();
    if (!DIGEST.test(id)) throw new StackCollectionError('invalid_build_identity', 'Docker did not produce a supported immutable image identity.');
    const observed = await inspectImage(execute, id), built = observed.image;
    if (built.id !== id) throw new StackCollectionError('build_identity_mismatch', 'The inspected image differs from the build output.');
    // Re-read HEAD/status: a concurrent edit does not invalidate the immutable
    // archived context, but must not be mislabeled as the current clean source.
    const after = await repositoryAt(root, execute);
    if (after.repository.revision !== repository.revision || !after.repository.clean) throw new StackCollectionError('source_changed_during_build', 'Source changed during the build; no current-source receipt was issued.');
    const receipt = { schemaVersion: 'offense.stack.build.v1', assertion: 'local_build_receipt', builtAt: now(),
      repository: { revision: repository.revision, tree: repository.tree }, archiveSha256: sha256(archive),
      dockerfile: { path: relative, sha256: sha256(dockerfileBytes) },
      image: { id: built.id, platform: built.platform, identityKind: built.identityKind, configDigest: built.configDigest,
        manifestDigests: built.manifestDigests, indexDigests: built.indexDigests, mappingVerified: built.mappingVerified } };
    return { receipt, image: built, reference, gaps: observed.gap ? [observed.gap] : [] };
  } finally { await rm(directory, { recursive: true, force: true }); }
}
