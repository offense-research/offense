// Local review evidence is never included in the hosted dependency-metadata request.
import { readdir, readFile, lstat, realpath } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { parseDocument } from '../public/skills/purple/scripts/yaml.mjs';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';

const execute = promisify(execFile);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hashPattern = /^[a-f0-9]{64}$/;
const revisionPattern = /^[a-f0-9]{40,64}$/;
const skip = new Set(['node_modules', 'vendor', 'dist', 'build', 'coverage']);
const unsupportedLocks = new Map([
  ['yarn.lock', 'JavaScript (Yarn)'], ['bun.lock', 'JavaScript (Bun)'], ['bun.lockb', 'JavaScript (Bun)'],
  ['Cargo.lock', 'Rust'], ['poetry.lock', 'Python'], ['uv.lock', 'Python'], ['Pipfile.lock', 'Python'],
  ['go.sum', 'Go'], ['Gemfile.lock', 'Ruby'], ['composer.lock', 'PHP'],
]);
const unsupportedManifests = new Map([
  ['pyproject.toml', 'Python'], ['Pipfile', 'Python'], ['setup.py', 'Python'], ['setup.cfg', 'Python'],
  ['Cargo.toml', 'Rust'], ['go.mod', 'Go'], ['Gemfile', 'Ruby'], ['composer.json', 'PHP'],
]);
const relativePath = value => typeof value === 'string' && value.length > 0 && value.length <= 500 &&
  !path.posix.isAbsolute(value) && !value.includes('\\') && !value.includes('\0') &&
  value.split('/').every(part => part && part !== '.' && part !== '..');
const within = (root, target) => target === root || target.startsWith(root + path.sep);
const boundedText = (value, maximum = 4000) => typeof value === 'string' && value.trim().length > 0 && value.length <= maximum;
const packageIdentity = value => {
  const match = typeof value === 'string' && value.match(/^((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)@(\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i);
  return match ? { package: match[1], version: match[2] } : null;
};

async function localFile(root, relative, maximum = 2_000_000) {
  if (!relativePath(relative)) throw Error('Evidence paths must be relative and remain in their selected directory.');
  const filename = path.join(root, ...relative.split('/')), info = await lstat(filename);
  if (info.isSymbolicLink() || !info.isFile() || info.size > maximum) throw Error(`${relative}: evidence must be a bounded regular file.`);
  if (!within(root, await realpath(filename))) throw Error(`${relative}: evidence resolves outside its selected directory.`);
  const bytes = await readFile(filename);
  if (bytes.length > maximum) throw Error(`${relative}: evidence exceeds its byte limit.`);
  return bytes;
}

async function repositoryIdentity(root) {
  let revision = null;
  const result = (worktreeClean, worktreeReason) => ({ repositoryRevision: revision, worktreeClean, worktreeReason,
    worktreeIdentityMethod: 'read_only_index_tree_and_raw_blob_hashes' });
  try {
    const options = { cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 4_000_000,
      env: { PATH: process.env.PATH, GIT_OPTIONAL_LOCKS: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
        GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1' } };
    const readOnly = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.untrackedCache=false', '-c', 'protocol.allow=never'];
    const { stdout } = await execute('git', [...readOnly, 'rev-parse', '--verify', 'HEAD'], options);
    revision = stdout.trim();
    if (!revisionPattern.test(revision)) { revision = null; return result(null, 'repository_commit_unavailable'); }
    const gitRoot = (await execute('git', [...readOnly, 'rev-parse', '--show-toplevel'], options)).stdout.trim();
    if (await realpath(gitRoot) !== root) return result(null, 'selected_directory_is_not_the_repository_root');
    // status/diff/ls-files --modified may invoke configured clean filters. These commands only
    // list the index/tree/untracked names; file content is hashed directly in this process.
    const [indexOutput, treeOutput, otherOutput] = await Promise.all([
      execute('git', [...readOnly, 'ls-files', '--stage', '-z'], options),
      execute('git', [...readOnly, 'ls-tree', '-r', '-z', '--full-tree', revision], options),
      execute('git', [...readOnly, 'ls-files', '--others', '--exclude-standard', '-z'], options),
    ]);
    if (otherOutput.stdout) return result(false, 'untracked_files_present');
    const index = new Map(), tree = new Map();
    const indexRows = indexOutput.stdout.split('\0').filter(Boolean), treeRows = treeOutput.stdout.split('\0').filter(Boolean);
    if (indexRows.length > 30000 || treeRows.length > 30000) return result(null, 'repository_identity_file_limit');
    for (const row of indexRows) {
      const match = row.match(/^(\d{6}) ([a-f0-9]{40,64}) ([0-3])\t([\s\S]+)$/);
      if (!match || !relativePath(match[4]) || match[3] !== '0' || index.has(match[4])) return result(null, 'unsupported_or_conflicted_index');
      index.set(match[4], { mode: match[1], oid: match[2] });
    }
    for (const row of treeRows) {
      const match = row.match(/^(\d{6}) (blob|commit) ([a-f0-9]{40,64})\t([\s\S]+)$/);
      if (!match || !relativePath(match[4]) || tree.has(match[4])) return result(null, 'unsupported_repository_tree');
      tree.set(match[4], { mode: match[1], oid: match[3] });
    }
    if (index.size !== tree.size) return result(false, 'index_differs_from_commit');
    let bytesRead = 0;
    const deadline = Date.now() + 10000;
    for (const [relative, entry] of index) {
      const committed = tree.get(relative);
      if (!committed || committed.mode !== entry.mode || committed.oid !== entry.oid) return result(false, 'index_differs_from_commit');
      if (!['100644', '100755'].includes(entry.mode)) return result(null, 'symlink_or_submodule_requires_review');
      if (Date.now() > deadline) return result(null, 'repository_identity_time_limit');
      let bytes, info;
      try { info = await lstat(path.join(root, relative)); bytes = await localFile(root, relative, 12_000_000); }
      catch { return result(null, 'tracked_file_missing_unsafe_or_too_large'); }
      bytesRead += bytes.length;
      if (bytesRead > 64_000_000) return result(null, 'repository_identity_byte_limit');
      const oid = createHash(entry.oid.length === 64 ? 'sha256' : 'sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
      if (oid !== entry.oid) return result(false, 'raw_tracked_content_differs_from_commit');
      if (process.platform !== 'win32' && Boolean(info.mode & 0o111) !== (entry.mode === '100755')) return result(false, 'tracked_file_mode_differs_from_commit');
    }
    // Re-read the commit and index to reject edits staged while raw contents were inspected.
    const finalRevision = (await execute('git', [...readOnly, 'rev-parse', '--verify', 'HEAD'], options)).stdout.trim();
    const finalIndex = (await execute('git', [...readOnly, 'ls-files', '--stage', '-z'], options)).stdout;
    const finalOthers = (await execute('git', [...readOnly, 'ls-files', '--others', '--exclude-standard', '-z'], options)).stdout;
    if (finalRevision !== revision || finalIndex !== indexOutput.stdout || finalOthers) return result(null, 'repository_changed_during_identity_check');
    return result(true, 'raw_index_and_worktree_match_commit');
  } catch { return result(null, 'repository_identity_unavailable'); }
}

/** Inventory omitted ecosystems and declared patches. Contents and credentials remain local. */
export async function collectLocalEvidence(directory, { coveredManifests = [], supportedLockfiles = [] } = {}) {
  const root = await realpath(directory), manifests = [], unsupportedFiles = [], warnings = [], tasks = [], patches = [];
  const covered = new Set(coveredManifests), patchDeclarations = [], patchPackageFolders = [], foundLockfiles = [];
  let entries = 0, totalRead = 0;
  async function readMetadata(relative) {
    const bytes = await localFile(root, relative, 1_000_000);
    totalRead += bytes.length;
    if (totalRead > 8_000_000) throw Error('Local metadata inventory exceeds 8 MB; choose a project subdirectory.');
    return bytes.toString('utf8');
  }
  function declarePatches(config, relative) {
    const declarations = config?.patchedDependencies;
    if (!declarations || typeof declarations !== 'object' || Array.isArray(declarations)) return;
    for (const [identity, value] of Object.entries(declarations)) {
      if (patchDeclarations.length >= 200) { warnings.push('Local patch inventory limit reached; remaining declarations need review.'); break; }
      patchDeclarations.push({ identity, reference: typeof value === 'string' ? value : value?.path, manifest: relative });
    }
  }
  async function walk(folder, depth = 0) {
    if (depth > 12) { warnings.push(`${path.relative(root, folder)}: local evidence directory depth limit reached.`); return; }
    const listing = (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of listing) {
      if (++entries > 30000) throw Error('Local evidence exceeds 30,000 entries; choose a project subdirectory.');
      const filename = path.join(folder, entry.name), relative = path.relative(root, filename).split(path.sep).join('/');
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { if (!entry.name.startsWith('.') && !skip.has(entry.name)) await walk(filename, depth + 1); continue; }
      if (!entry.isFile()) continue;
      if (['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'].includes(entry.name) &&
        !(entry.name === 'package-lock.json' && listing.some(item => item.isFile() && item.name === 'npm-shrinkwrap.json'))) foundLockfiles.push(relative);
      const ecosystem = unsupportedLocks.get(entry.name) || unsupportedManifests.get(entry.name) || (/^requirements(?:[-_.][a-z0-9_.-]+)?\.txt$/i.test(entry.name) ? 'Python' : null);
      if (ecosystem) {
        const item = { path: relative, ecosystem, status: 'not_scanned',
          nextStep: `Use the coding agent's existing ${ecosystem} tooling to establish resolved versions and audit them separately. Preserve conditional, URL and range declarations as unresolved until resolution is reviewed.` };
        if (/^requirements.*\.txt$/i.test(entry.name)) {
          try {
            const lines = (await readMetadata(relative)).split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
            item.exactPins = lines.filter(line => /^[a-z0-9_.-]+(?:\[[a-z0-9_,.-]+\])?==[a-z0-9_.+-]+\s*(?:#.*)?$/i.test(line)).length;
            item.unresolvedDeclarations = lines.length - item.exactPins;
          } catch { warnings.push(`${relative}: requirements metadata could not be inspected within the local byte limit.`); }
        }
        unsupportedFiles.push(item);
        warnings.push(unsupportedLocks.has(entry.name) ? `${relative}: unsupported lockfile; not scanned.` : `${relative}: unsupported ${ecosystem} metadata; not scanned by Offense.`);
      }
      if (entry.name === 'package.json') {
        manifests.push(relative);
        try {
          const config = JSON.parse(await readMetadata(relative));
          declarePatches(config.pnpm, relative);
          if (config.dependencies?.['patch-package'] || config.devDependencies?.['patch-package']) patchPackageFolders.push(path.posix.dirname(relative));
        } catch { warnings.push(`${relative}: local manifest or patch declarations could not be inspected.`); }
      } else if (entry.name === 'pnpm-workspace.yaml') {
        try {
          const document = parseDocument(await readMetadata(relative), { uniqueKeys: true, strict: true });
          if (document.errors.length) throw Error('Invalid patch configuration.');
          declarePatches(document.toJS({ maxAliasCount: 0 }), relative);
        } catch { warnings.push(`${relative}: local patch declarations could not be inspected.`); }
      }
    }
  }
  await walk(root);
  for (const folder of patchPackageFolders) {
    const relativeFolder = path.posix.join(folder, 'patches');
    try {
      const directory = path.join(root, relativeFolder), info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink() || !within(root, await realpath(directory))) throw Error('Unsafe patch directory.');
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (patchDeclarations.length >= 200) { warnings.push('Local patch inventory limit reached; remaining artifacts need review.'); break; }
        if (!entry.isFile() || !entry.name.endsWith('.patch')) continue;
        const match = entry.name.match(/^(@[^+]+\+[^+]+|[^+]+)\+(\d+\.\d+\.\d+(?:[-.][a-z0-9.-]+)?)\.patch$/i);
        patchDeclarations.push({ identity: match ? `${match[1].replace('+', '/')}@${match[2]}` : null,
          reference: `patches/${entry.name}`, manifest: path.posix.join(folder, 'package.json') });
      }
    } catch (error) { if (error.code !== 'ENOENT') warnings.push(`${relativeFolder}: patch-package artifacts could not be inspected.`); }
  }
  const seen = new Set();
  for (const declaration of patchDeclarations) {
    const identity = packageIdentity(declaration.identity), base = path.posix.dirname(declaration.manifest);
    const relative = typeof declaration.reference === 'string' && relativePath(declaration.reference) ? path.posix.join(base, declaration.reference) : null;
    const key = `${declaration.identity}:${relative}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const patch = { ...(identity || {}), path: relative, declaredIn: declaration.manifest, status: 'unverified',
      nextStep: 'Retain the advisory match. Review the patch, verify the installed files and run the advisory-specific regression plus normal baseline/candidate checks. A patch declaration or hash alone is not mitigation proof.' };
    if (!identity || !relative || !relativePath(relative)) patch.blocker = 'The declared patch identity or path is unsupported; review locally.';
    else {
      try { patch.sha256 = digest(await localFile(root, relative)); }
      catch { patch.blocker = 'The declared patch is missing, unsafe or exceeds the local byte limit.'; }
    }
    patches.push(patch);
  }
  const uncoveredManifests = manifests.filter(manifest => !covered.has(manifest)).map(manifest => ({ path: manifest, status: 'unresolved',
    scope: /(?:^|\/)(?:archive|archived|examples|fixtures|context)(?:\/|$)/i.test(manifest) ? 'review_scope' : 'project',
    nextStep: 'Find or generate and review the covering lockfile with this project’s package manager. If this is an archived or vendored project, explicitly record its exclusion; do not silently treat it as scanned.' }));
  for (const manifest of uncoveredManifests) warnings.push(`${manifest.path}: no covering lockfile importer; dependency coverage is incomplete.`);
  tasks.push(...uncoveredManifests.map(item => ({ kind: 'resolve_manifest', path: item.path, nextStep: item.nextStep })),
    ...unsupportedFiles.map(item => ({ kind: 'audit_unsupported_ecosystem', path: item.path, nextStep: item.nextStep })),
    ...patches.map(item => ({ kind: 'verify_local_patch', path: item.path, package: item.package, version: item.version, nextStep: item.nextStep })));
  return { schemaVersion: 'offense.local-evidence.v1', ...await repositoryIdentity(root),
    coverage: { status: warnings.length ? 'partial' : 'complete', supportedLockfiles: [...new Set(supportedLockfiles.length ? supportedLockfiles : foundLockfiles)], uncoveredManifests,
      unsupportedFiles, warnings: [...new Set(warnings)], tasks }, patches };
}

const checkKey = check => JSON.stringify([check.id, check.workspace || '.', check.command]);
function passedCheck(check) {
  return check && boundedText(check.id, 120) && Array.isArray(check.command) && check.command.length > 0 && check.command.length <= 100 &&
    check.command.every(value => boundedText(value, 2048)) && (check.workspace === undefined || check.workspace === '.' || relativePath(check.workspace)) &&
    check.exitCode === 0 && check.setupPassed === true && check.timedOut === false && check.truncated === false && !check.signal && check.artifactVerified === true;
}
function validChecks(baseline, candidate) {
  if (!Array.isArray(baseline) || !Array.isArray(candidate) || !baseline.length || baseline.length > 100 || baseline.length !== candidate.length) return false;
  if (!baseline.every(passedCheck) || !candidate.every(passedCheck)) return false;
  const keys = values => values.map(checkKey).sort();
  return JSON.stringify(keys(baseline)) === JSON.stringify(keys(candidate));
}
function securityPassed(security) {
  if (!security || !boundedText(security.assertion, 2000) || !boundedText(security.reviewedFailureReason, 4000) || security.reviewedFailureReason.trim().length < 20 ||
    !boundedText(security.advisoryPrerequisites, 4000) || security.advisoryPrerequisites.trim().length < 20 ||
    !/^[a-z0-9._-]{3,120}$/i.test(security.assertionId || '') || !security.testArtifactVerified) return false;
  const baseline = security.baseline, candidate = security.candidate;
  return baseline?.exitCode === 1 && baseline.setupPassed === true && baseline.failureKind === 'security_assertion' &&
    baseline.timedOut === false && baseline.truncated === false && !baseline.signal && baseline.artifactVerified === true &&
    baseline.assertionMarkerVerified === true && passedCheck(candidate) && candidate.assertionMarkerVerified === true &&
    checkKey(baseline) === checkKey(candidate);
}

/** Assess only reviewed records whose artifacts were checked by loadReviewedEvidence. Never dismiss findings. */
export function assessVerificationRecord(record, { repositoryRevision, metadataFingerprint, currentMetadataFingerprint, worktreeClean, patches = [], findings = [], now = Date.now() } = {}) {
  const global = [];
  if (record?.schemaVersion !== 'offense.verification.v1') global.push('Unsupported local verification schema.');
  if (!revisionPattern.test(repositoryRevision || '') || record?.repositoryRevision !== repositoryRevision) global.push('Verification is missing the exact current repository commit or belongs to another commit.');
  if (worktreeClean !== true) global.push('Commit reviewed changes in the isolated candidate checkout before accepting commit-bound verification evidence.');
  if (!hashPattern.test(metadataFingerprint || '') || record?.metadataFingerprint !== metadataFingerprint) global.push('Verification belongs to different dependency metadata.');
  if (currentMetadataFingerprint !== undefined && currentMetadataFingerprint !== metadataFingerprint) global.push('Dependency metadata changed after the hosted audit; rescan the current checkout before accepting verification.');
  if (!revisionPattern.test(record?.baselineRevision || '')) global.push('A pinned baseline commit is required.');
  if (!boundedText(record?.reviewedBy, 200) || !Number.isFinite(record?.reviewedAt) || record.reviewedAt > now ||
    !Number.isFinite(record?.expiresAt) || record.expiresAt <= now || record.expiresAt <= record.reviewedAt || record.expiresAt - record.reviewedAt > 30 * 86400000) global.push('A current named review with an expiry of at most 30 days is required.');
  if (!Array.isArray(record?.findings) || record.findings.length > 2000) global.push('Verification findings must be a bounded array.');
  const recorded = Array.isArray(record?.findings) ? record.findings.filter(item => item && typeof item === 'object' && !Array.isArray(item)) : [], used = new Set();
  if (Array.isArray(record?.findings) && recorded.length !== record.findings.length) global.push('Malformed local finding records were not accepted.');
  const results = findings.map(finding => {
    const name = finding.package?.name, version = finding.package?.installedVersion, id = finding.advisoryId;
    const matches = recorded.filter(item => item.advisoryId === id && item.package === name && item.version === version);
    let status = 'advisory_match';
    const blockers = [...global];
    if (!matches.length) blockers.push('No reviewed local evidence was supplied for this advisory/package/version.');
    else if (matches.length !== 1) blockers.push('Duplicate local evidence cannot establish a unique finding assessment.');
    else {
      const item = matches[0]; used.add(item);
      if (!Array.isArray(item.behaviorChanges) || item.behaviorChanges.some(change => !boundedText(change?.description) || !boundedText(change?.verification))) blockers.push('Record runtime requirements, changed behavior and any test-mocking/coverage changes; use an empty list only when none changed.');
      if (item.testCoverageReviewed !== true) blockers.push('Review whether tests were weakened or replaced with mocks and retain integration coverage where needed.');
      const compatible = validChecks(item.normalChecks?.baseline, item.normalChecks?.candidate);
      if (!compatible) blockers.push('Normal baseline and candidate checks must pass with identical command/workspace coverage and verified logs.');
      const securityVerified = securityPassed(item.securityRegression);
      if (!securityVerified) blockers.push('Reproduce the advisory with an assertion-specific baseline failure and candidate pass; setup errors, generic crashes and normal-test success are insufficient.');
      let patchVerified = false;
      if (item.patch) {
        const artifact = patches.find(patch => patch.package === name && patch.version === version && patch.path === item.patch.path && patch.sha256 === item.patch.sha256 && !patch.blocker);
        patchVerified = !!artifact && item.patch.installedIdentityVerified === true && item.patch.appliedFilesVerified === true;
        if (!patchVerified) blockers.push('The reviewed patch hash, installed package identity and applied-file integrity must match the current checkout.');
      }
      if (!global.length && compatible && item.testCoverageReviewed === true && Array.isArray(item.behaviorChanges) &&
        !item.behaviorChanges.some(change => !boundedText(change?.description) || !boundedText(change?.verification))) {
        status = 'compatibility_verified';
        if (securityVerified && !item.patch) status = 'security_regression_verified';
        if (securityVerified && patchVerified) status = 'mitigation_verified';
      }
    }
    return { advisoryId: id, package: name, version, status, advisoryMatchRetained: true, blockers,
      nextStep: status === 'advisory_match' ? 'Complete the recorded local verification blockers; keep this match visible.' :
        status === 'compatibility_verified' ? 'Compatibility evidence is reviewed. Complete the advisory-specific security reproduction before claiming mitigation.' :
          'Keep the advisory match and local evidence linked to this commit; repeat verification when dependencies, source or patch artifacts change.' };
  });
  const warnings = [...global];
  if (recorded.some(item => !used.has(item))) warnings.push('Local records for absent or different advisory/package/version pairs were not accepted.');
  return { schemaVersion: 'offense.verification-assessment.v1', status: global.length || results.some(item => item.blockers.length) ? 'needs_review' : 'reviewed', findings: results,
    counts: Object.fromEntries(['advisory_match', 'compatibility_verified', 'mitigation_verified', 'security_regression_verified'].map(status => [status, results.filter(item => item.status === status).length])),
    warnings, confirmedVulnerabilities: 0,
    scope: 'Reviewed local evidence records with checked artifact hashes; commands are not rerun by this helper. No advisory is hidden and hosted confirmation/discovery metrics are unchanged.' };
}

/** Explicit, local-only opt-in: read a reviewed evidence file and verify its bounded artifacts. */
export async function loadReviewedEvidence(directory, evidenceFile, { metadataFingerprint, findings = [], localEvidence, now = Date.now() } = {}) {
  const root = await realpath(directory), filename = path.resolve(evidenceFile), info = await lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 2_000_000) throw Error('Local evidence must be a regular JSON file of at most 2 MB.');
  let record;
  try { record = JSON.parse(await readFile(filename, 'utf8')); }
  catch { throw Error('Invalid local evidence JSON; no verification was accepted.'); }
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw Error('Local evidence must be a reviewed verification object.');
  const artifactRoot = await realpath(path.dirname(filename));
  // Recheck files and the current commit after the audit; the earlier inventory can become stale.
  const inventory = await collectLocalEvidence(root, { supportedLockfiles: localEvidence?.coverage?.supportedLockfiles || [] });
  let currentMetadataFingerprint = null;
  try {
    if (!inventory.coverage.supportedLockfiles.length || inventory.coverage.supportedLockfiles.length > 20) throw Error('No bounded lockfile snapshot.');
    const files = [];
    for (const relative of inventory.coverage.supportedLockfiles) files.push({ path: relative, content: (await localFile(root, relative, 12_000_000)).toString('utf8') });
    const clean = sanitizeLockfiles(files);
    currentMetadataFingerprint = digest(JSON.stringify(clean.files.slice().sort((a, b) => a.path.localeCompare(b.path))));
  } catch { /* An unreadable or changed snapshot cannot be accepted as verified. */ }
  let artifactBytes = 0;
  const verified = new Map();
  async function artifact(reference, base = artifactRoot) {
    if (!reference || !hashPattern.test(reference.sha256 || '')) throw Error('A local evidence artifact needs a SHA-256 hash.');
    const key = `${base}:${reference.path}:${reference.sha256}`;
    if (verified.has(key)) return verified.get(key);
    const bytes = await localFile(base, reference.path);
    artifactBytes += bytes.length;
    if (artifactBytes > 20_000_000) throw Error('Local verification artifacts exceed 20 MB.');
    if (digest(bytes) !== reference.sha256) throw Error('A local verification artifact changed after review.');
    verified.set(key, bytes); return bytes;
  }
  if (Array.isArray(record.findings) && record.findings.length <= 2000) for (const item of record.findings) {
    if (!item || typeof item !== 'object') continue;
    for (const check of [...(Array.isArray(item.normalChecks?.baseline) ? item.normalChecks.baseline.slice(0, 101) : []),
      ...(Array.isArray(item.normalChecks?.candidate) ? item.normalChecks.candidate.slice(0, 101) : []), item.securityRegression?.baseline, item.securityRegression?.candidate]) {
      if (!check || typeof check !== 'object') continue;
      check.artifactVerified = false; check.assertionMarkerVerified = false;
      try {
        const log = (await artifact(check.log)).toString('utf8'); check.artifactVerified = true;
        if (check === item.securityRegression?.baseline || check === item.securityRegression?.candidate) {
          const outcome = check === item.securityRegression.baseline ? 'FAILED' : 'PASSED';
          const marker = `OFFENSE_SECURITY_ASSERTION_${outcome} ${item.securityRegression.assertionId}`;
          check.assertionMarkerVerified = log.split(/\r?\n/).some(line => line.trim() === marker);
        }
      } catch { /* Missing or changed artifacts remain explicit unverified blockers. */ }
    }
    if (item.securityRegression && typeof item.securityRegression === 'object') {
      item.securityRegression.testArtifactVerified = false;
      try { await artifact(item.securityRegression.test); item.securityRegression.testArtifactVerified = true; } catch { /* review required */ }
    }
    if (item.patch && typeof item.patch === 'object') {
      item.patch.installedIdentityVerified = false; item.patch.appliedFilesVerified = false;
      try {
        if (!/(?:^|\/)node_modules\/.+\/package\.json$/.test(item.patch.installedManifest?.path || '')) throw Error('An installed package manifest is required.');
        const manifest = JSON.parse((await artifact(item.patch.installedManifest, root)).toString('utf8'));
        item.patch.installedIdentityVerified = manifest.name === item.package && manifest.version === item.version;
        const installedRoot = await realpath(path.dirname(path.join(root, item.patch.installedManifest.path)));
        if (Array.isArray(item.patch.appliedFiles) && item.patch.appliedFiles.length > 0 && item.patch.appliedFiles.length <= 100) {
          for (const file of item.patch.appliedFiles) {
            await artifact(file, root);
            const resolved = await realpath(path.join(root, file.path));
            if (!within(installedRoot, resolved) || resolved === path.join(installedRoot, 'package.json')) throw Error('Applied-file evidence must belong to the installed patched package.');
          }
          item.patch.appliedFilesVerified = true;
        }
      } catch { /* a declared patch is not proof it was applied */ }
    }
  }
  return assessVerificationRecord(record, { ...inventory, metadataFingerprint, currentMetadataFingerprint, findings, patches: inventory.patches, now });
}
