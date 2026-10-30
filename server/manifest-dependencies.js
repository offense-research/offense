import semver from 'semver';

const packageName = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;
const dir = file => file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : '.';
const manifestPath = (base, location = '') => [base === '.' ? '' : base, location === '.' ? '' : location, 'package.json'].filter(Boolean).join('/');
const isObject = value => value && typeof value === 'object' && !Array.isArray(value);
export const manifestNotice = 'Manifest declarations do not identify installed versions or transitive dependencies. These checks sample one published version allowed by each supported declaration. A declaration with no match is not evidence that its range or the application is free of vulnerabilities.';

function missingLockfile(file) {
  let manifest = {};
  try { manifest = JSON.parse(file.content); } catch {}
  const manager = typeof manifest.packageManager === 'string' ? /^(npm|pnpm|yarn|bun)@/.exec(manifest.packageManager)?.[1] : null;
  const directory = dir(file.path), packageManager = manager || 'unknown';
  const commands = [];
  if (!manager || manager === 'npm') commands.push({ directory, command: 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund' });
  if (!manager || manager === 'pnpm') commands.push({ directory, command: 'pnpm install --lockfile-only --ignore-scripts' });
  return { manifest: file.path, directory, packageManager,
    expectedLockfiles: manager === 'pnpm' ? ['pnpm-lock.yaml'] : manager === 'yarn' ? ['yarn.lock'] : manager === 'bun' ? ['bun.lock', 'bun.lockb'] : manager === 'npm' ? ['package-lock.json', 'npm-shrinkwrap.json'] : ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'],
    commands,
    message: manager === 'yarn' || manager === 'bun' ? `${file.path}: no supported resolved dependency graph was found. Keep using ${manager} and ask your coding agent to audit its resolved dependencies; hosted upgrade simulations currently require an npm or pnpm lockfile.` :
      `${file.path}: no covering npm or pnpm lockfile was found. In an isolated checkout, use the project's existing package manager to generate the lockfile without lifecycle scripts, review and commit it, then sync this repository and retry. A newly generated lockfile describes a new resolution, not proof of what is deployed.` };
}

export function dependencyCoverage(files, graph, packages) {
  const covered = new Set();
  for (const node of graph.nodes || []) if (node.path === '') covered.add(manifestPath(dir(node.file), node.workspace || ''));
  for (const file of files.filter(file => /(^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(file.path))) {
    try {
      const lock = JSON.parse(file.content);
      if (!isObject(lock.packages)) continue;
      for (const [location, entry] of Object.entries(lock.packages)) if (isObject(entry) && !entry.link && !location.split('/').includes('node_modules')) covered.add(manifestPath(dir(file.path), location));
    } catch {}
  }
  const manifests = files.filter(file => /(^|\/)package\.json$/.test(file.path));
  const missingLockfiles = manifests.filter(file => !covered.has(file.path)).map(missingLockfile);
  const uncovered = new Set(missingLockfiles.map(item => item.manifest));
  const declarations = packages.filter(item => !item.resolved && item.files.some(file => uncovered.has(file)));
  const resolvedPackages = packages.filter(item => item.resolved).length;
  const status = missingLockfiles.length ? resolvedPackages ? 'partial' : 'manifest_only' : resolvedPackages || graph.nodes?.length ? 'resolved' : 'empty';
  return { status, complete: status === 'resolved' && !(graph.warnings || []).length,
    resolvedPackages, declaredPackages: declarations.length, missingLockfiles,
    notice: status === 'manifest_only' || status === 'partial' ? manifestNotice : status === 'empty' ? 'No supported npm/pnpm resolved dependency graph or package.json declarations were found. Add a supported project or use your coding agent to audit the repository with its native package manager.' : null,
    omissions: [] };
}

// Registry metadata and manifests are data only. No package resolution,
// installation, lifecycle hook, repository command, or source upload occurs.
export async function assessManifestDeclarations(packages, coverage, { fetchImpl = fetch, limit = 100 } = {}) {
  const uncovered = new Set(coverage.missingLockfiles.map(item => item.manifest));
  const declarations = packages.filter(item => !item.resolved && item.files.some(file => uncovered.has(file)));
  const candidates = [], omissions = [], seen = new Map(), deadline = AbortSignal.timeout(20000);
  const requests = [];
  for (const item of declarations) {
    const files = item.files.filter(file => uncovered.has(file));
    const range = typeof item.version === 'string' && item.version.length <= 200 && semver.validRange(item.version);
    const minimum = range ? semver.minVersion(range) : null;
    if (!packageName.test(item.name) || item.name.length > 214 || !minimum || semver.prerelease(minimum)) {
      omissions.push({ package: item.name, declaredRange: item.version, files, reason: 'This declaration is not a supported stable npm semver range. Resolve it with the project package manager and commit its lockfile.' }); continue;
    }
    const representative = minimum.version, key = `${item.name}@${representative}`;
    if (!seen.has(key)) {
      if (seen.size >= limit) { omissions.push({ package: item.name, declaredRange: item.version, files, reason: `Manifest assessment is limited to ${limit} package/version lookups. Generate a lockfile for complete resolved-version scanning.` }); continue; }
      seen.set(key, null); requests.push({ key, name: item.name, representative });
    }
    candidates.push({ ...item, files, version: representative, resolved: false, declaredRange: item.version,
      assessmentKind: semver.valid(item.version) ? 'declared_exact' : 'declared_range', versionEvidence: semver.valid(item.version) ? 'declared_exact' : 'declared_range' });
  }
  for (let offset = 0; offset < requests.length; offset += 6) {
    await Promise.all(requests.slice(offset, offset + 6).map(async ({ key, name, representative }) => {
      try {
        const response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(representative)}`, {
          headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.any([deadline, AbortSignal.timeout(5000)]) });
        if (!response.ok) throw new Error(response.status === 404 ? 'The minimum allowed version is not a published release.' : `npm metadata returned HTTP ${response.status}.`);
        const text = await response.text();
        if (text.length > 1_000_000) throw new Error('Published-version metadata exceeds the assessment limit.');
        const metadata = JSON.parse(text);
        if (metadata.name !== name || metadata.version !== representative) throw new Error('npm metadata did not confirm the selected representative version.');
        seen.set(key, { available: true });
      } catch (error) { seen.set(key, { available: false, reason: String(error.message).slice(0, 300) }); }
    }));
  }
  const checked = [];
  for (const item of candidates) {
    const result = seen.get(`${item.name}@${item.version}`);
    if (result?.available) checked.push(item);
    else omissions.push({ package: item.name, declaredRange: item.declaredRange, representativeVersion: item.version, files: item.files,
      reason: `${result?.reason || 'Published-version metadata was unavailable.'} No installed version was inferred; generate a lockfile and retry.` });
  }
  return { packages: checked, omissions, checkedAt: Date.now() };
}
