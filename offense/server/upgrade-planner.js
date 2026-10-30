import semver from 'semver';
import { checkVulnerabilities } from './osv.js';
import { dependencyImpact } from './dependency-graph.js';
import { bracesMitigation } from './braces-remediation.js';

const registry = 'https://registry.npmjs.org';
const packageName = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;

async function metadata(name, fetchImpl) {
  if (!packageName.test(name)) throw new Error('Invalid npm package name.');
  const response = await fetchImpl(`${registry}/${encodeURIComponent(name)}`, {
    headers: { Accept: 'application/vnd.npm.install-v1+json' }, signal: AbortSignal.timeout(20000)
  });
  if (!response.ok) throw new Error(`npm registry returned HTTP ${response.status} for ${name}.`);
  const body = await response.text();
  if (body.length > 12_000_000) throw new Error(`npm metadata for ${name} is too large to plan safely.`);
  const result = JSON.parse(body);
  if (!result.versions || typeof result.versions !== 'object') throw new Error(`npm registry returned no versions for ${name}.`);
  return result;
}

function publishedVersions(packument) {
  return Object.keys(packument.versions).filter(version => semver.valid(version) && !semver.prerelease(version))
    .sort(semver.compare);
}

function changes(before, after) {
  const result = [];
  for (const [field, label] of [['dependencies', 'dependency'], ['optionalDependencies', 'optional dependency'],
    ['peerDependencies', 'peer dependency'], ['engines', 'engine']]) {
    const previous = before?.[field] || {};
    const next = after?.[field] || {};
    for (const name of new Set([...Object.keys(previous), ...Object.keys(next)])) {
      if (previous[name] === next[name]) continue;
      result.push({ type: label, name, from: previous[name] || null, to: next[name] || null });
    }
  }
  return result;
}

function releaseChanges(packument, fromVersion, toVersion) {
  const between = publishedVersions(packument).filter(candidate => semver.gte(candidate, fromVersion) && semver.lte(candidate, toVersion));
  if (between.length > 1000) throw new Error('The upgrade spans more than 1,000 releases; narrow the target before planning.');
  const steps = [];
  for (let index = 1; index < between.length; index++) {
    const from = between[index - 1], to = between[index];
    const diff = changes(packument.versions[from], packument.versions[to]);
    const majorChange = semver.major(from) !== semver.major(to);
    const deprecated = packument.versions[to]?.deprecated || null;
    if (diff.length || majorChange || deprecated) steps.push({ from, to, changes: diff, majorChange, deprecated });
  }
  return { releases: between, steps };
}

// Assess each installed instance independently. A satisfying peer elsewhere in
// a monorepo does not establish that this package instance can resolve it.
function peerConstraints(graph, name, installedVersion, release, proposed = new Map()) {
  const peers = Object.entries(release.peerDependencies || {});
  const nodes = graph?.nodes || [], byId = new Map(nodes.map(node => [node.id, node]));
  const byLocation = new Map(nodes.map(node => [`${node.file}\0${node.path}`, node]));
  const instances = nodes.filter(node => node.name === name && node.version === installedVersion);
  const checks = [];
  let limited = false;
  instancesLoop: for (const instance of instances.length ? instances : [null]) {
    for (const [peer, requiredRange] of peers) {
      if (checks.length >= 2000) { limited = true; break instancesLoop; }
      const optional = release.peerDependenciesMeta?.[peer]?.optional === true;
      let resolved, absenceKnown = false;
      const explicit = instance?.requires?.find(edge => edge.name === peer && edge.type === 'peer') ||
        instance?.requires?.find(edge => edge.name === peer);
      if (explicit?.to && byId.has(explicit.to)) resolved = byId.get(explicit.to);
      else if (instance && /(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(instance.file)) {
        // Existing npm edges cover old peers; newly introduced peers need the
        // same nearest-instance resolution as the dependency graph.
        let base = instance.path;
        for (;;) {
          const path = `${base ? `${base}/` : ''}node_modules/${peer}`;
          resolved = byLocation.get(`${instance.file}\0${path}`);
          if (resolved || !base) break;
          const marker = base.lastIndexOf('/node_modules/');
          if (marker >= 0) base = base.slice(0, marker);
          else if (base.startsWith('node_modules/')) base = '';
          else base = base.includes('/') ? base.slice(0, base.lastIndexOf('/')) : '';
        }
        // A graph with omissions cannot prove that a missing peer is absent.
        absenceKnown = !(graph.warnings || []).length;
      }
      const replacement = resolved && proposed.get(peer);
      const version = replacement && replacement.from === resolved?.version ? replacement.to : resolved?.version;
      const supportedRange = typeof requiredRange === 'string' && semver.validRange(requiredRange);
      const compatible = !supportedRange ? null : resolved ?
        semver.valid(version) ? semver.satisfies(version, requiredRange) : null :
        absenceKnown ? optional : null;
      checks.push({ peer, requiredRange, installedVersion: resolved?.version || null,
        evaluatedVersion: version || null, optional, compatible,
        file: instance?.file || null, path: instance?.path ?? null,
        reason: !supportedRange ? 'Unsupported peer range; review it locally.' : resolved ?
          compatible === true ? 'Resolved peer satisfies the published range.' : compatible === false ?
            'Resolved peer does not satisfy the published range.' : 'Resolved peer version could not be assessed.' :
          absenceKnown ? optional ? 'Optional peer is not installed.' : 'Required peer is not installed.' :
            'Peer resolution is unknown for this package instance.' });
    }
  }
  if (limited) checks.push({ peer: '(remaining peers)', requiredRange: 'unknown', compatible: null,
    reason: 'Peer assessment reached its 2,000-context limit; inspect the remaining instances locally.' });
  return { status: checks.some(check => check.compatible === false) ? 'blocked' :
    checks.some(check => check.compatible === null) ? 'needs_review' : 'compatible', checks };
}

const peerRank = assessment => ({ compatible: 0, needs_review: 1, blocked: 2 })[assessment.status];
function peerWarnings(name, assessment) {
  return assessment.checks.filter(check => check.compatible !== true).map(check =>
    `${name}${check.file ? ` (${check.file}${check.path ? `:${check.path}` : ''})` : ''} requires peer ${check.peer}@${check.requiredRange}; ${check.reason}`);
}

function childRanges(release, name) {
  // npm optionalDependencies override dependencies of the same name, but an
  // accompanying peer declaration still constrains the coordinated upgrade.
  return [release.optionalDependencies?.[name] ?? release.dependencies?.[name], release.peerDependencies?.[name]]
    .filter(range => range !== undefined);
}

export async function planUpgrade(snapshot, name, version, { fetchImpl = fetch, check = checkVulnerabilities } = {}) {
  const cache = new Map();
  const readMetadata = async packageName => {
    if (!cache.has(packageName)) cache.set(packageName, metadata(packageName, fetchImpl));
    return cache.get(packageName);
  };
  if (!packageName.test(name) || !semver.valid(version)) throw new Error('Choose a pinned npm package version.');
  const currentFindings = snapshot.vulnerabilityCheck?.findings?.filter(item => item.package === name && item.version === version) || [];
  if (snapshot.vulnerabilityCheck?.status !== 'complete') throw new Error('Check CVEs before planning an upgrade.');
  if (!currentFindings.length) throw new Error('This version has no known advisories to plan a fix for.');
  const packument = await readMetadata(name);
  const versions = publishedVersions(packument);
  if (!packument.versions[version]) throw new Error('The installed version is missing from npm metadata.');
  const fixes = [...new Set(currentFindings.flatMap(item => item.fixedVersions || []))]
    .filter(candidate => semver.valid(candidate) && semver.gt(candidate, version)).sort(semver.compare);

  const candidateVersions = [...new Set(fixes.map(fix => versions.find(candidate => semver.gte(candidate, fix))).filter(Boolean))];
  if (!candidateVersions.length) candidateVersions.push(...versions.filter(candidate => semver.gt(candidate, version)).slice(0, 20));
  let targetVersion = null, targetPeers = null;
  const cleanCandidates = [];
  const considered = [];
  const seen = new Set();
  while (candidateVersions.length && seen.size < 20) {
    candidateVersions.sort(semver.compare);
    const candidate = candidateVersions.shift();
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    const result = await check([{ name, version: candidate, kind: 'runtime', resolved: true }], fetchImpl);
    if (result.status !== 'complete') throw new Error('Could not verify the target version against OSV.');
    const peers = peerConstraints(snapshot.graph, name, version, packument.versions[candidate]);
    considered.push({ version: candidate, advisories: result.findings.length,
      advisoryIds: result.findings.map(item => item.id).filter(Boolean), peerCompatibility: peers.status });
    if (!result.findings.length) {
      cleanCandidates.push({ version: candidate, peers });
      if (peers.status === 'compatible') { targetVersion = candidate; targetPeers = peers; break; }
      // A first clean fix can require incompatible peers. Look at bounded
      // subsequent releases before requiring a wider coordinated migration.
      const next = versions.find(published => semver.gt(published, candidate));
      if (next && !seen.has(next) && !candidateVersions.includes(next)) candidateVersions.push(next);
    }
    // A first fix may introduce another advisory. Follow its fixes too.
    for (const fix of result.findings.flatMap(item => item.fixedVersions || [])) {
      if (!semver.valid(fix) || semver.lte(fix, version)) continue;
      const next = versions.find(published => semver.gte(published, fix));
      if (next && !seen.has(next) && !candidateVersions.includes(next)) candidateVersions.push(next);
    }
  }
  if (!targetVersion && cleanCandidates.length) {
    const fallback = cleanCandidates.sort((a, b) => peerRank(a.peers) - peerRank(b.peers) || semver.compare(a.version, b.version))[0];
    targetVersion = fallback.version; targetPeers = fallback.peers;
  }
  if (!targetVersion) {
    const mitigation = bracesMitigation(snapshot, name, version, considered);
    if (mitigation) return mitigation;
    throw new Error(fixes.length ? 'No checked fix version is free of known advisories. Review newer releases or a mitigation.' : 'OSV lists no published fix version and no safe newer release was found.');
  }
  const { releases, steps } = releaseChanges(packument, version, targetVersion);
  const impact = dependencyImpact(snapshot.graph, name, version, targetVersion);
  const constraintWarnings = peerWarnings(`${name}@${targetVersion}`, targetPeers);
  if (targetPeers.status !== 'compatible' && seen.size >= 20) constraintWarnings.push('Peer-compatible target search reached its 20-release limit; inspect further releases locally.');
  let lookups = 0;
  for (const parent of impact.parents.filter(item => item.compatible === null)) {
    if (parent.isRoot || !semver.valid(parent.version) || lookups++ >= 6) {
      constraintWarnings.push(`The declared range from ${parent.name} requires local review.`); continue;
    }
    try {
      const info = await readMetadata(parent.name), installed = info.versions[parent.version];
      const declared = parent.type === 'peer' ? installed?.peerDependencies?.[name] :
        installed?.optionalDependencies?.[name] ?? installed?.dependencies?.[name] ?? installed?.peerDependencies?.[name];
      if (!semver.validRange(declared)) throw new Error('No supported declared range in published metadata.');
      parent.range = declared; parent.compatible = semver.satisfies(targetVersion, declared); parent.rangeSource = 'npm_registry';
    } catch (error) { constraintWarnings.push(`${parent.name}@${parent.version}: ${error.message}`); }
  }
  const parentOptions = [];
  for (const parent of impact.parents.filter(item => item.compatible === false)) {
    if (parent.isRoot) {
      parentOptions.push({ parent: parent.name, currentVersion: parent.version, action: 'Update the application dependency range.', version: null });
      continue;
    }
    if (!semver.valid(parent.version)) {
      parentOptions.push({ parent: parent.name, currentVersion: parent.version, version: null, action: 'Parent version needs manual review.' });
      continue;
    }
    if (parentOptions.length >= 6) {
      parentOptions.push({ parent: parent.name, currentVersion: parent.version, version: null, action: 'Not inspected because the plan reached its parent lookup limit.' });
      continue;
    }
    try {
      const parentMetadata = await readMetadata(parent.name);
      const candidates = publishedVersions(parentMetadata).filter(candidate => {
        if (!semver.gt(candidate, parent.version)) return false;
        const ranges = childRanges(parentMetadata.versions[candidate], name);
        return ranges.length && ranges.every(range => typeof range === 'string' && semver.validRange(range) && semver.satisfies(targetVersion, range));
      });
      let compatible = null, parentPeers = null;
      const checkedParents = [];
      for (const candidate of candidates.slice(0, 10)) {
        const result = await check([{ name: parent.name, version: candidate, kind: 'transitive', resolved: true }], fetchImpl);
        if (result.status !== 'complete') throw new Error('Could not verify the parent release against OSV.');
        if (!result.findings.length) {
          const peers = peerConstraints(snapshot.graph, parent.name, parent.version, parentMetadata.versions[candidate],
            new Map([[name, { from: version, to: targetVersion }]]));
          checkedParents.push({ version: candidate, peers });
          if (peers.status === 'compatible') { compatible = candidate; parentPeers = peers; break; }
        }
      }
      if (!compatible && checkedParents.length) {
        const fallback = checkedParents.sort((a, b) => peerRank(a.peers) - peerRank(b.peers) || semver.compare(a.version, b.version))[0];
        compatible = fallback.version; parentPeers = fallback.peers;
      }
      if (parentPeers) constraintWarnings.push(...peerWarnings(`${parent.name}@${compatible}`, parentPeers));
      if (parentPeers && parentPeers.status !== 'compatible' && candidates.length > 10) {
        constraintWarnings.push(`${parent.name}: peer-compatible parent search reached its 10-release limit; inspect further releases locally.`);
      }
      const parentReleaseChanges = compatible ? releaseChanges(parentMetadata, parent.version, compatible) : null;
      const upstream = compatible ? dependencyImpact(snapshot.graph, parent.name, parent.version, compatible).parents : [];
      const blockedUpstream = upstream.filter(item => item.compatible === false).length;
      const unassessedUpstream = upstream.filter(item => item.compatible == null).length;
      parentOptions.push({ parent: parent.name, currentVersion: parent.version, version: compatible || null,
        releases: parentReleaseChanges?.releases || [], steps: parentReleaseChanges?.steps || [], upstream,
        peerConstraints: parentPeers,
        action: compatible ? `OSV-checked parent release allows the target; ${parentReleaseChanges.steps.length} metadata change points across ${parentReleaseChanges.releases.length} releases. ${blockedUpstream} upstream range${blockedUpstream === 1 ? '' : 's'} block it.${unassessedUpstream ? ` ${unassessedUpstream} upstream constraints require review.` : ''}${parentPeers?.status !== 'compatible' ? ' Peer requirements still need coordination or review before applying it.' : ''}` : candidates.length ? 'No clean compatible parent release found among the first 10 candidates.' : 'No compatible parent release found.' });
    } catch (error) {
      parentOptions.push({ parent: parent.name, currentVersion: parent.version, version: null, action: `Could not inspect parent releases: ${error.message}` });
    }
  }
  return { name, currentVersion: version, targetVersion, checkedAt: Date.now(),
    releasesInspected: releases.length, releases, steps, considered, impact, parentOptions, peerConstraints: targetPeers,
    targetSelection: { policy: 'Prefer the smallest OSV-checked release compatible with every inspected peer context.',
      candidateLimit: 20, checkedCandidates: considered.length, peerStatus: targetPeers.status,
      limited: seen.size >= 20 && targetPeers.status !== 'compatible' },
    majorChange: semver.major(version) !== semver.major(targetVersion), constraintWarnings,
    note: 'Metadata and advisory checks do not prove source compatibility. Reproduce the vulnerability and run the repository test suite before changing production.' };
}
