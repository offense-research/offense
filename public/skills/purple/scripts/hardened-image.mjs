#!/usr/bin/env node
// Local image acquisition and a reviewable proposal only. This helper never
// builds/runs an application, reads registry credentials, or uploads source.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, realpath, readFile, mkdir, mkdtemp, writeFile, rmdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PLATFORMS = new Set(['linux/amd64', 'linux/arm64']);
const MAX_DOCKERFILE = 256 * 1024;
const HASH = value => createHash('sha256').update(value).digest('hex');
const HELP = `Usage: node hardened-image.mjs --project ROOT --image PROVIDER/IMAGE:TAG --platform linux/amd64|linux/arm64
       [--dockerfile Dockerfile] [--stage ALIAS_OR_ZERO_BASED_INDEX] [--pull] [--output OUTSIDE_PROJECT] [--preview]

Supports explicit dhi.io, cgr.dev/chainguard and gcr.io/distroless images.
--preview is offline, writes nothing and executes no Docker commands.
Normal commands check skill updates, then write a local plan in a fresh external directory.
--pull acquires the selected image using the existing Docker context and registry access,
then inspects its immutable digest. Without --pull no registry request is made.
An immutable image produces a stage-specific Dockerfile proposal, never a source edit.
Compatibility, signature verification and application checks remain separate; no app is built or run.
`;

function plain(value) { return !!value && typeof value === 'object' && !Array.isArray(value); }

export function parseHardenedImageReference(value) {
  if (typeof value !== 'string' || value.length > 500 || !/^[a-z0-9][a-z0-9./:_@-]*$/.test(value))
    throw Error('Choose an explicit supported provider image reference without credentials or options.');
  const parts = value.split('@');
  if (parts.length > 2 || (parts.length === 2 && !DIGEST.test(parts[1])))
    throw Error('Use a lowercase sha256 image digest.');
  const beforeDigest = parts[0], colon = beforeDigest.lastIndexOf(':');
  const tag = colon > beforeDigest.lastIndexOf('/') ? beforeDigest.slice(colon + 1) : null;
  const repository = tag === null ? beforeDigest : beforeDigest.slice(0, colon);
  if ((tag !== null && !/^[a-z0-9_][a-z0-9_.-]{0,127}$/.test(tag)) || (!tag && parts.length === 1) ||
      !/^(?:dhi\.io\/[a-z0-9]+(?:[._-][a-z0-9]+)*|(?:cgr\.dev\/chainguard|gcr\.io\/distroless)\/[a-z0-9]+(?:[._-][a-z0-9]+)*)$/.test(repository))
    throw Error('Choose an explicit tag or digest from dhi.io, cgr.dev/chainguard or gcr.io/distroless.');
  return { reference: value, repository, tag, digest: parts[1] || null,
    provider: repository.startsWith('dhi.io/') ? 'docker_hardened_images' : repository.startsWith('cgr.dev/') ? 'chainguard' : 'distroless' };
}

async function noSymlinks(filename) {
  const absolute = path.resolve(filename);
  let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try { if ((await lstat(current)).isSymbolicLink()) throw Error('Project and output paths cannot contain symlinks.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return absolute;
}

function within(root, file) { return file === root || file.startsWith(root + path.sep); }

async function localText(filename, limit, optional = false) {
  await noSymlinks(filename);
  let info;
  try { info = await lstat(filename); }
  catch (error) { if (optional && error.code === 'ENOENT') return null; throw Error('A selected local input could not be read.'); }
  if (!info.isFile() || info.size > limit) throw Error('Use a bounded regular local input file.');
  const bytes = await readFile(filename);
  if (bytes.length > limit || bytes.toString('utf8').includes('\ufffd') || bytes.includes(0))
    throw Error('Local inputs must be bounded UTF-8 text.');
  return bytes.toString('utf8');
}

/** Parse ordinary Docker instructions without executing them. Positions refer
 * to the original bytes-as-UTF8 text, so only the selected image token changes. */
export function inspectDockerfile(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > MAX_DOCKERFILE) throw Error('Dockerfile exceeds its text budget.');
  const instructions = [], stages = [], issues = [];
  if (/^\s*#\s*escape\s*=\s*`/mi.test(source)) issues.push('unsupported_escape_directive');
  // Heredoc bodies may contain text resembling FROM. Do not treat them as stages.
  if (/^\s*(?:RUN|COPY|ADD)\b[^\r\n]*<</mi.test(source)) issues.push('unsupported_heredoc');
  if (issues.length) return { stages, instructions, issues };
  const lines = source.match(/[^\n]*\n|[^\n]+$/g) || [];
  let offset = 0, line = 1;
  for (let i = 0; i < lines.length; i++) {
    const start = offset, firstLine = line;
    let raw = lines[i]; offset += raw.length; line++;
    if (/^\s*(?:#|$)/.test(raw)) continue;
    while (/\\[ \t]*\r?\n$/.test(raw) && i + 1 < lines.length) {
      raw += lines[++i]; offset += lines[i].length; line++;
    }
    const flat = raw.replace(/\\[ \t]*\r?\n/g, match => ' '.repeat(match.length));
    const command = flat.match(/^\s*([A-Za-z]+)\s+([\s\S]*?)\s*$/);
    if (!command) { issues.push('unsupported_instruction_syntax'); continue; }
    const instruction = { name: command[1].toUpperCase(), value: command[2], line: firstLine, start, end: offset };
    if (['RUN', 'COPY', 'ADD'].includes(instruction.name) && instruction.value.includes('<<')) {
      issues.push('unsupported_heredoc'); break;
    }
    instructions.push(instruction);
    if (instruction.name !== 'FROM') continue;
    const match = flat.match(/^(\s*FROM\s+)(?:(--platform=([^\s]+))\s+)?([^\s]+)(?:\s+AS\s+([A-Za-z0-9_][A-Za-z0-9_.-]*))?\s*$/i);
    if (!match) { issues.push('unsupported_from_syntax'); continue; }
    const imageOffset = flat.indexOf(match[4], match[1].length + (match[2]?.length || 0));
    const stage = { index: stages.length, alias: match[5] || null, image: match[4],
      platform: match[3] || null, line: firstLine, imageStart: start + imageOffset,
      imageEnd: start + imageOffset + match[4].length, instructions: [] };
    stages.push(stage);
  }
  for (let i = 0; i < stages.length; i++) {
    const next = stages[i + 1]?.line ?? Infinity;
    stages[i].instructions = instructions.filter(item => item.line > stages[i].line && item.line < next);
  }
  if (!stages.length) issues.push('no_supported_from');
  const aliases = stages.filter(stage => stage.alias).map(stage => stage.alias.toLowerCase());
  if (new Set(aliases).size !== aliases.length) issues.push('duplicate_stage_alias');
  return { stages, instructions, issues: [...new Set(issues)] };
}

function runtime(reference) {
  const beforeDigest = reference.split('@')[0], base = beforeDigest.slice(beforeDigest.lastIndexOf('/') + 1);
  const colon = base.indexOf(':'), name = colon < 0 ? base : base.slice(0, colon), tag = colon < 0 ? '' : base.slice(colon + 1);
  const family = ['node', 'nodejs'].includes(name) || /^nodejs\d+(?:-debian\d+)?$/.test(name) ? 'node' :
    name === 'python' || /^python\d+(?:\.\d+)?(?:-debian\d+)?$/.test(name) ? 'python' : null;
  const distrolessVersion = name.match(/^(?:nodejs|python)(\d+)(?:\.(\d+))?/);
  const version = tag.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-_.]|$)/);
  const libc = /alpine/.test(`${name}:${tag}`) ? 'musl' : /bookworm|bullseye|buster|trixie|debian|slim/.test(`${name}:${tag}`) ? 'glibc' : null;
  return { family, major: version ? Number(version[1]) : distrolessVersion ? Number(distrolessVersion[1]) : null,
    minor: version?.[2] !== undefined ? Number(version[2]) : distrolessVersion?.[2] !== undefined ? Number(distrolessVersion[2]) : null,
    libc, basis: 'image_reference_only_not_runtime_observation' };
}

function compatibilityFor(stage, candidate, parsed, policy, platform) {
  const blockers = [...parsed.issues], reviews = ['image_entrypoint_user_workdir_paths_and_writable_directories_require_review'];
  if (/\$/.test(stage.image)) blockers.push('unresolved_from_variable');
  if (stage.image === 'scratch' || parsed.stages.some(item => item.alias?.toLowerCase() === stage.image.toLowerCase())) blockers.push('selected_from_is_not_an_external_runtime_image');
  if (stage.platform && stage.platform !== platform) blockers.push(/\$/.test(stage.platform) ? 'unresolved_from_platform' : 'selected_from_platform_differs');
  if (stage.instructions.some(item => item.name === 'RUN')) blockers.push('selected_stage_has_run_instructions');
  if (!stage.instructions.some(item => item.name === 'ENTRYPOINT') || !stage.instructions.some(item => item.name === 'CMD'))
    blockers.push('inherited_entrypoint_or_cmd_requires_review');
  for (const instruction of stage.instructions.filter(item => ['CMD', 'ENTRYPOINT'].includes(item.name))) {
    let argv;
    try { argv = JSON.parse(instruction.value); } catch {}
    if (!Array.isArray(argv) || !argv.every(value => typeof value === 'string') || /(?:^|\/)(?:sh|bash|ash|dash|zsh)$/.test(argv[0] || ''))
      blockers.push('selected_stage_uses_shell_command');
  }
  if (stage.instructions.some(item => ['ONBUILD', 'SHELL', 'ADD'].includes(item.name))) blockers.push('selected_stage_requires_manual_instruction_review');
  const original = runtime(stage.image), replacement = runtime(candidate.reference);
  if (!original.family || !replacement.family) blockers.push('runtime_family_unknown');
  else if (original.family !== replacement.family) blockers.push('runtime_family_change');
  if (original.major === null || replacement.major === null) blockers.push('runtime_major_unknown');
  else if (original.major !== replacement.major) blockers.push('runtime_major_change');
  if (original.minor === null || replacement.minor === null) blockers.push('runtime_minor_unknown');
  else if (original.minor !== replacement.minor) blockers.push('runtime_minor_change');
  if (!original.libc || !replacement.libc) blockers.push('libc_unknown');
  else if (original.libc !== replacement.libc) blockers.push('libc_change');
  if (policy.nodeEngines || policy.nodeVersion) reviews.push('project_runtime_policy_requires_check_against_actual_image_runtime');
  if (stage.instructions.some(item => item.name === 'COPY' && /--from(?:=|\s)/.test(item.value))) reviews.push('copied_artifacts_and_native_modules_require_abi_and_libc_checks');
  return { status: blockers.length ? 'blocked' : 'requires_review', blockers: [...new Set(blockers)], reviews,
    originalRuntime: original, candidateRuntime: replacement, evidence: 'static_dockerfile_and_reference_only' };
}

export async function prepareHardenedImage(options = {}) {
  if (typeof options.project !== 'string' || !PLATFORMS.has(options.platform)) throw Error('Choose an explicit project and linux/amd64 or linux/arm64 platform.');
  const project = await noSymlinks(options.project);
  if (await realpath(project) !== project || !(await lstat(project)).isDirectory()) throw Error('Use a real project directory.');
  const dockerfile = options.dockerfile ?? 'Dockerfile';
  if (typeof dockerfile !== 'string' || !/^[A-Za-z0-9_./-]{1,300}$/.test(dockerfile) || path.isAbsolute(dockerfile) || dockerfile.split('/').some(part => !part || part === '.' || part === '..'))
    throw Error('Choose a Dockerfile path relative to the project.');
  const filename = path.resolve(project, dockerfile);
  if (!within(project, filename)) throw Error('The Dockerfile must be inside the selected project.');
  const source = await localText(filename, MAX_DOCKERFILE), candidate = parseHardenedImageReference(options.image);
  const parsed = inspectDockerfile(source);
  let selected;
  if (options.stage === undefined) selected = parsed.stages.at(-1);
  else if (typeof options.stage === 'string' && /^\d+$/.test(options.stage)) selected = parsed.stages[Number(options.stage)];
  else if (typeof options.stage === 'string') selected = parsed.stages.find(stage => stage.alias?.toLowerCase() === options.stage.toLowerCase());
  if (!selected && options.stage !== undefined) throw Error('The selected Dockerfile stage was not found.');
  const policy = {};
  const manifest = await localText(path.join(project, 'package.json'), 256 * 1024, true);
  if (manifest) {
    try {
      const json = JSON.parse(manifest);
      if (typeof json.engines?.node === 'string' && /^[0-9vVxX*<>=~^|. +\-]{1,200}$/.test(json.engines.node)) policy.nodeEngines = json.engines.node;
      if (typeof json.packageManager === 'string' && /^(?:npm|pnpm|yarn)@[0-9]+(?:\.[0-9]+){1,2}(?:\+[a-z0-9.]+)?$/.test(json.packageManager)) policy.packageManager = json.packageManager;
    } catch { policy.manifestStatus = 'invalid'; }
  }
  for (const name of ['.node-version', '.nvmrc', '.python-version']) {
    const text = await localText(path.join(project, name), 1024, true);
    if (text !== null) {
      const value = text.trim();
      if (/^[a-zA-Z0-9._/*-]{1,100}$/.test(value)) policy[name === '.python-version' ? 'pythonVersion' : 'nodeVersion'] = value;
      else policy.runtimeFileStatus = 'requires_review';
    }
  }
  const report = { schemaVersion: 'purple.hardened-image.v1', status: 'planned', project, dockerfile,
    dockerfileSha256: HASH(source), platform: options.platform, candidate,
    inventory: { stages: parsed.stages.map(stage => ({ index: stage.index, alias: stage.alias, image: stage.image, platform: stage.platform, line: stage.line })),
      selectedStage: selected ? { index: selected.index, alias: selected.alias, image: selected.image, line: selected.line } : null,
      parsingIssues: parsed.issues, runtimePolicy: policy },
    acquisition: { status: 'not_requested', connection: 'existing_docker_cli_context' },
    digest: { status: candidate.digest ? 'supplied_not_resolved' : 'not_resolved' },
    metadata: { status: 'not_assessed' },
    compatibility: selected ? compatibilityFor(selected, candidate, parsed, policy, options.platform) :
      { status: 'blocked', blockers: parsed.issues, reviews: [], evidence: 'static_dockerfile_and_reference_only' },
    signature: { status: 'not_assessed' }, applicationBuilds: { status: 'not_run', baseline: 'not_run', candidate: 'not_run' },
    applicationTests: { status: 'not_run', baseline: 'not_run', candidate: 'not_run' },
    vulnerabilityScan: { status: 'not_run' },
    proposal: { status: 'unavailable', reason: candidate.digest ? 'dockerfile_not_targetable' : 'immutable_digest_required' },
    privacy: { sourceUploadedToPurple: false, registryCredentialsRead: false, applicationExecuted: false, rawDockerOutputSaved: false } };
  return { report, source, selected, parsed, candidate };
}

function dockerFailure(result) {
  if (result?.error?.code === 'ENOENT') return 'docker_cli_missing';
  const text = [result?.stderr, result?.error?.message].filter(value => typeof value === 'string').join('\n');
  if (/cannot connect to (?:the )?docker daemon|is the docker daemon running|error during connect|permission denied.*(?:docker|sock)|(?:docker|sock).*permission denied|failed to connect.*(?:daemon|docker|\.sock)/i.test(text))
    return 'docker_connection_unavailable';
  if (/unauthorized|authentication required|authorization failed|access denied|pull access denied|requested access.*denied|\b401\b|\b403\b/i.test(text)) return 'registry_access_denied';
  if (/manifest unknown|manifest.*not found|name unknown|repository.*not found|no matching manifest/i.test(text)) return 'registry_image_not_found';
  if (result?.error?.code === 'ETIMEDOUT' || /no such host|temporary failure in name resolution|tls handshake|certificate.*(?:unknown|expired|invalid)|connection (?:refused|reset)|network is unreachable|i\/o timeout|timed? ?out/i.test(text))
    return 'registry_connection_failed';
  return 'image_pull_failed';
}

function docker(execute, args) {
  try {
    const result = execute('docker', args, { env: process.env, encoding: 'utf8', timeout: args[0] === 'pull' ? 180000 : 20000,
      killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    return result && !result.error && result.status === 0 ? { ok: true, stdout: result.stdout } : { ok: false, error: dockerFailure(result) };
  } catch (error) { return { ok: false, error: dockerFailure({ error }) }; }
}

function inspect(execute, reference) {
  const result = docker(execute, ['image', 'inspect', reference]);
  if (!result.ok) return null;
  try {
    const values = JSON.parse(result.stdout);
    return Array.isArray(values) && values.length === 1 && plain(values[0]) ? values[0] : null;
  } catch { return null; }
}

function digestFor(metadata, candidate) {
  if (!Array.isArray(metadata?.RepoDigests)) return null;
  const values = [...new Set(metadata.RepoDigests.filter(value => typeof value === 'string' && value.startsWith(candidate.repository + '@'))
    .map(value => value.slice(candidate.repository.length + 1)).filter(value => DIGEST.test(value)))];
  if (candidate.digest) return values.includes(candidate.digest) ? candidate.digest : null;
  return values.length === 1 ? values[0] : null;
}

function safeMetadata(value, platform, pinnedReference) {
  if (!plain(value) || !DIGEST.test(value.Id || '') || `${value.Os}/${value.Architecture}` !== platform ||
      !Array.isArray(value.RepoDigests) || !value.RepoDigests.includes(pinnedReference)) return null;
  // Inspect contains Config.Env and Labels; retain neither, including on errors.
  return { status: 'available', pinnedReference, registryDigest: pinnedReference.split('@')[1],
    registryDigestKind: 'repository_digest_may_identify_multi_platform_index', imageConfigDigest: value.Id,
    platform, os: value.Os, architecture: value.Architecture, configurationSummary: configurationSummary(value.Config) };
}

function configurationSummary(config) {
  if (!plain(config)) return { status: 'unavailable', privilege: 'unknown', scope: 'configuration_missing' };
  const rawUser = plain(config) ? config.User : undefined;
  let user = 'unrecognized', privilege = 'unknown';
  if (rawUser === '' || rawUser === undefined || rawUser === null) { user = 'unset'; privilege = 'root'; }
  else if (typeof rawUser === 'string' && /^\d{1,10}(?::\d{1,10})?$/.test(rawUser)) {
    user = rawUser; privilege = Number(rawUser.split(':')[0]) === 0 ? 'root' : 'nonroot';
  } else if (['node', 'nonroot', 'nobody', 'python', 'root'].includes(rawUser)) {
    user = rawUser; privilege = rawUser === 'root' ? 'root' : 'unknown';
  }
  const known = new Set(['node', '/usr/local/bin/node', '/nodejs/bin/node', 'python', 'python3',
    '/bin/sh', '/bin/bash', 'docker-entrypoint.sh', '/usr/local/bin/docker-entrypoint.sh']);
  const entrypoint = plain(config) && Array.isArray(config.Entrypoint) ? config.Entrypoint : null;
  const executable = entrypoint?.[0];
  const entrypointExecutable = executable === undefined ? 'unset' : typeof executable === 'string' &&
    (known.has(executable) || /^\/usr\/bin\/python(?:3(?:\.\d{1,2})?)?$/.test(executable)) ? executable : 'unrecognized';
  const workdir = plain(config) && typeof config.WorkingDir === 'string' ? config.WorkingDir : '';
  return { status: 'available', configuredUser: user, privilege, namedUserUid: 'not_checked', entrypointExecutable,
    entrypointArgumentCount: entrypoint ? Math.min(entrypoint.length, 1000) : 0,
    commandArgumentCount: plain(config) && Array.isArray(config.Cmd) ? Math.min(config.Cmd.length, 1000) : 0,
    workingDirectory: workdir === '' ? 'unset' : /^\/[A-Za-z0-9_./-]{0,200}$/.test(workdir) ? workdir : 'unrecognized',
    scope: 'bounded_configuration_summary_full_configuration_requires_local_review' };
}

function proposalFor(prepared) {
  const { report, source, selected, parsed } = prepared;
  const pinned = report.metadata.pinnedReference || (prepared.candidate.digest ? `${prepared.candidate.repository}@${prepared.candidate.digest}` : null);
  if (!pinned || !selected || parsed.issues.length || /\$/.test(selected.image) ||
      selected.image === 'scratch' || parsed.stages.some(stage => stage.alias?.toLowerCase() === selected.image.toLowerCase())) return null;
  if (source.slice(selected.imageStart, selected.imageEnd) !== selected.image) throw Error('Selected FROM token did not match its source position.');
  const candidate = source.slice(0, selected.imageStart) + pinned + source.slice(selected.imageEnd);
  const originalLine = source.slice(0, selected.imageStart).split('\n').length;
  // Include the original context so ordinary git apply can validate this exact
  // proposal, including continued instructions, CRLF and missing final newline.
  const beforeLines = source.split('\n'), afterLines = candidate.split('\n');
  if (source.endsWith('\n')) { beforeLines.pop(); afterLines.pop(); }
  let patch = `--- a/${report.dockerfile}\n+++ b/${report.dockerfile}\n@@ -1,${beforeLines.length} +1,${afterLines.length} @@\n`;
  for (let index = 0; index < beforeLines.length; index++) {
    const marker = !source.endsWith('\n') && index === beforeLines.length - 1 ? '\\ No newline at end of file\n' : '';
    patch += index === originalLine - 1 ? `-${beforeLines[index]}\n${marker}+${afterLines[index]}\n${marker}` : ` ${beforeLines[index]}\n${marker}`;
  }
  report.proposal = { status: 'available_requires_review', pinnedReference: pinned, selectedStage: selected.index,
    originalDockerfileSha256: report.dockerfileSha256, candidateDockerfileSha256: HASH(candidate),
    files: ['Dockerfile.candidate', 'migration.patch'], sourceEdited: false };
  return { candidate, patch };
}

export function hardenedImagePrompt(report) {
  const name = JSON.stringify(report.dockerfile), pinned = report.proposal.pinnedReference || report.candidate.reference;
  const access = { docker_cli_missing: 'The Docker CLI was not found in the selected environment.',
    docker_connection_unavailable: 'The existing Docker daemon/context could not be reached with the current permissions.',
    registry_access_denied: 'The registry denied access. Reuse the selected Docker account and credential helper; this helper does not log in or read credentials.',
    registry_image_not_found: 'The selected registry reference or requested platform could not be found.',
    registry_connection_failed: 'The registry connection failed or timed out; check the selected environment network and registry trust.',
    image_pull_failed: 'The Docker pull did not succeed. Review the selected Docker connection and explicit image reference locally.',
    matching_registry_digest_unavailable: 'The successful pull did not yield a unique matching source repository digest.',
    immutable_image_metadata_mismatch: 'The digest-pinned image metadata did not match the pulled image identity and requested platform.' };
  return `# Hardened container migration review\n\n` +
    `Review the proposal for ${name}, stage ${report.inventory.selectedStage?.index ?? 'unresolved'}, on ${report.platform}.\n` +
    `Requested image: ${report.candidate.reference}. Immutable proposal image: ${pinned}.\n` +
    `Acquisition: ${report.acquisition.status}; digest: ${report.digest.status}; metadata: ${report.metadata.status}; compatibility: ${report.compatibility.status}; signature: ${report.signature.status}; application builds: ${report.applicationBuilds.status}; application tests: ${report.applicationTests.status}.\n\n` +
    (report.acquisition.error ? `${access[report.acquisition.error] || 'Image acquisition requires local review.'}\n\n` : '') +
    (report.candidate.provider === 'docker_hardened_images' ? 'DHI registry access may require an authenticated Docker account in the existing Docker credential helper. Preserve that configured account and registry scope; this helper does not initiate login or acquire additional entitlements.\n\n' : '') +
    `Compatibility blockers: ${report.compatibility.blockers.join(', ') || 'none detected by bounded static inspection'}.\n` +
    `Review: ${(report.compatibility.reviews || []).join(', ')}.\n\n` +
    `Use the coding agent's existing authorized repository and sandbox tools. Preserve working changes. Establish a passing baseline from the exact original Dockerfile/source snapshot, then build and test the candidate from the same snapshot, platform, context, build arguments and test settings. Do not apply this proposal without reviewing the listed blockers.\n\n` +
    `Check actual runtime versions against project runtime floors, libc/ABI and native modules; inspect copied artifacts, CA certificates, timezone data, executables, package manager/shell dependencies, entrypoint arguments, nonroot UID/GID, working directory, ports and required writable paths. A new base may inherit a different ENTRYPOINT or lack a shell/package manager. Resolve ARG or inherited-stage ambiguity manually.\n\n` +
    `Before sending any build context to the selected Docker builder, inspect .dockerignore, select only required source/artifacts and exclude .git, local env files, credentials, registry config, keys and production data. Use reviewed synthetic test data. Keep registry authentication in the existing Docker credential helper. Never place secrets in build arguments, Dockerfile ENV, image layers, logs or runtime tests. Confirm the intended builder/context; a remote builder receives the context.\n\n` +
    `Run the same meaningful baseline/candidate build and application startup/health or request tests in an isolated test environment. Keep baseline failures, candidate failures, omitted checks and unsupported services visible. Inspect the final candidate image configuration and effective nonroot behavior. This helper has performed none of these checks.\n\n` +
    `Verify publisher signatures against the provider's documented exact identity/issuer or public-key policy separately, bound to the selected registry digest. A digest pin is integrity identification, not signature verification. Scan both final image digests using the same current vulnerability database and preserve scan coverage and package provenance. No scan or signature result is implied by image acquisition.\n\n` +
    `Return a reviewed patch, image digest/platform, provenance, original/candidate commands and results, compatibility decisions and remaining blockers. Distinguish acquired image, static proposal, signature-verified image, vulnerability scan and application-verified migration. Do not push, publish or deploy unless requested.\n`;
}

async function outputDirectory(output, project) {
  if (output === undefined) {
    const tempRoot = await realpath(os.tmpdir());
    await noSymlinks(tempRoot);
    const destination = await mkdtemp(path.join(tempRoot, 'purple-hardened-image-'));
    if (within(project, destination)) { await rmdir(destination); throw Error('Choose an output directory outside the project.'); }
    return destination;
  }
  if (typeof output !== 'string' || !path.isAbsolute(output)) throw Error('Choose an absolute output directory outside the project.');
  const destination = await noSymlinks(output);
  if (within(project, destination) || within(destination, project)) throw Error('Output must be outside the project and its ancestors.');
  try { await mkdir(destination, { recursive: false, mode: 0o700 }); }
  catch { throw Error('Use a new output directory with an existing parent; existing files are preserved.'); }
  return destination;
}

export async function acquireHardenedImage(options = {}, { execute = spawnSync } = {}) {
  const prepared = await prepareHardenedImage(options), { report, candidate } = prepared;
  if (options.preview) { report.proposal = { status: 'not_generated', reason: 'preview_requested' }; return report; }
  // Validate/reserve output before any registry operation. A fresh output dir is
  // owned by this invocation; no prior report or unrelated file is overwritten.
  const output = await outputDirectory(options.output, report.project);
  if (options.pull) {
    const pulled = docker(execute, ['pull', '--platform', report.platform, candidate.reference]);
    report.acquisition = { ...report.acquisition, status: 'failed', error: pulled.error || 'image_pull_failed' };
    if (pulled.ok) {
      const initial = inspect(execute, candidate.reference), digest = digestFor(initial, candidate);
      if (!digest) {
        report.acquisition.error = 'matching_registry_digest_unavailable';
        report.metadata = { status: 'failed', error: 'matching_registry_digest_unavailable' };
      }
      else {
        const pinned = `${candidate.repository}@${digest}`, exact = inspect(execute, pinned);
        const metadata = safeMetadata(exact, report.platform, pinned);
        if (!metadata || initial?.Id !== exact?.Id || `${initial?.Os}/${initial?.Architecture}` !== report.platform) {
          report.acquisition.error = 'immutable_image_metadata_mismatch';
          report.metadata = { status: 'failed', error: 'immutable_image_metadata_mismatch' };
        } else {
          report.acquisition = { status: 'acquired', connection: 'existing_docker_cli_context', requestedReference: candidate.reference,
            pinnedReference: pinned, registryDigest: digest };
          report.metadata = metadata;
          report.digest = { status: 'resolved', registryDigest: digest, pinnedReference: pinned,
            kind: 'repository_digest_may_identify_multi_platform_index' };
        }
      }
    }
    report.status = report.acquisition.status === 'acquired' ? 'acquired' : 'failed';
  }
  // Failed acquisition must not fall back to a cached or merely supplied digest.
  const proposal = !options.pull || report.acquisition.status === 'acquired' ? proposalFor(prepared) : null;
  if (options.pull && !proposal && report.acquisition.status === 'failed') report.proposal = { status: 'unavailable', reason: 'image_acquisition_failed' };
  report.output = output;
  try {
    await writeFile(path.join(output, 'hardened-image.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    await writeFile(path.join(output, 'remediation.md'), hardenedImagePrompt(report), { flag: 'wx', mode: 0o600 });
    if (proposal) {
      await writeFile(path.join(output, 'Dockerfile.candidate'), proposal.candidate, { flag: 'wx', mode: 0o600 });
      await writeFile(path.join(output, 'migration.patch'), proposal.patch, { flag: 'wx', mode: 0o600 });
    }
  } catch {
    // Preserve partial review evidence rather than deleting user-visible files.
    throw Error('The local report could not be fully written; inspect the chosen output directory.');
  }
  return report;
}

export async function main(argv = process.argv.slice(2), { execute = spawnSync, runAutoUpdate } = {}) {
  if (argv.length === 1 && argv[0] === '--help') { console.log(HELP); return; }
  const options = {};
  const values = new Map([['--project', 'project'], ['--dockerfile', 'dockerfile'], ['--stage', 'stage'], ['--image', 'image'], ['--platform', 'platform'], ['--output', 'output']]);
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (seen.has(flag)) throw Error('Repeated hardened-image option.');
    seen.add(flag);
    if (flag === '--preview' || flag === '--pull') options[flag.slice(2)] = true;
    else if (values.has(flag) && argv[i + 1] && !argv[i + 1].startsWith('--')) options[values.get(flag)] = argv[++i];
    else throw Error('Unknown or incomplete hardened-image option. Use --help.');
  }
  if (!options.preview) {
    const update = await (runAutoUpdate || (async () => (await import('./update.mjs')).updateBeforeRun('purple', import.meta.url)))();
    if (update?.stop) return { status: 'skill_update_required' };
  }
  const result = await acquireHardenedImage(options, { execute });
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'failed') process.exitCode = 2;
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Hardened image operation could not complete. Check the explicit project, image, stage, platform and fresh external output path. No raw Docker output was exported.'); process.exitCode = 1; });
}
