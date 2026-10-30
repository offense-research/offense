import { checkVulnerabilities } from './osv.js';
import { buildDependencyGraph } from './dependency-graph.js';
import { planUpgrade } from './upgrade-planner.js';
import { pnpmGraph } from '../public/skills/purple/scripts/pnpm.mjs';
import { dependencyCoverage, assessManifestDeclarations } from './manifest-dependencies.js';
import { bindScanEvidence } from './rehearsal-identity.js';
import { sameScanEvidence, scanEvidenceKey } from '../shared/scan-evidence.js';

function packageName(location, entry) {
  if (entry.name) return entry.name;
  const offset = location.lastIndexOf('node_modules/');
  return offset < 0 ? '' : location.slice(offset + 'node_modules/'.length);
}

export function mapDependencies(files) {
  const packages = new Map();
  const warnings = [];
  function add(name, version, kind, file, resolved) {
    if (typeof name !== 'string' || typeof version !== 'string' || !name || !version || name.length > 214 || version.length > 200) {
      warnings.push(`${file} contains an unsupported dependency declaration; no version was inferred.`); return;
    }
    const key = `${name}\0${version}\0${resolved}`;
    const previous = packages.get(key);
    if (previous) {
      if (kind === 'runtime' || (kind === 'development' && previous.kind === 'transitive')) previous.kind = kind;
      if (!previous.files.includes(file)) previous.files.push(file);
    } else packages.set(key, { name, version, kind, resolved, files: [file] });
  }
  for (const file of files) {
    if (file.path.endsWith('pnpm-lock.yaml')) {
      try { const result = pnpmGraph(file); for (const item of result.packages) add(item.name, item.version, item.kind, file.path, true); warnings.push(...result.warnings); }
      catch (error) { warnings.push(error.message); }
      continue;
    }
    let manifest;
    try { manifest = JSON.parse(file.content); }
    catch { warnings.push(`${file.path} is not valid JSON.`); continue; }
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) { warnings.push(`${file.path} must contain a JSON object.`); continue; }
    if (file.path.endsWith('package.json') && !file.path.endsWith('package-lock.json')) {
      for (const [field, kind] of [['dependencies', 'runtime'], ['devDependencies', 'development'], ['optionalDependencies', 'runtime'], ['peerDependencies', 'peer']]) {
        if (manifest[field] === undefined) continue;
        if (!manifest[field] || typeof manifest[field] !== 'object' || Array.isArray(manifest[field])) { warnings.push(`${file.path}: ${field} must contain dependency declarations.`); continue; }
        for (const [name, version] of Object.entries(manifest[field])) add(name, version, kind, file.path, false);
      }
      continue;
    }
    const root = manifest.packages?.[''] || {};
    const runtime = new Set([...Object.keys(root.dependencies || {}), ...Object.keys(root.optionalDependencies || {})]);
    const development = new Set(Object.keys(root.devDependencies || {}));
    if (manifest.packages) {
      for (const [location, entry] of Object.entries(manifest.packages)) {
        if (!location.includes('node_modules/') || !entry?.version || entry.link) continue;
        const name = packageName(location, entry);
        const kind = runtime.has(name) ? 'runtime' : development.has(name) ? 'development' : 'transitive';
        add(name, entry.version, kind, file.path, true);
      }
    } else if (manifest.dependencies) {
      function walk(dependencies, direct = false) {
        for (const [name, entry] of Object.entries(dependencies || {})) {
          if (!entry || typeof entry !== 'object') continue;
          add(name, entry.version, direct ? entry.dev ? 'development' : 'runtime' : 'transitive', file.path, true);
          walk(entry.dependencies);
        }
      }
      walk(manifest.dependencies, true);
    }
  }
  return { packages: [...packages.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)), warnings };
}

export function createDependencyMapper(db, github, check = checkVulnerabilities, plan = planUpgrade, { fetchImpl = fetch, assessDeclarations = assessManifestDeclarations } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS dependency_snapshots (
    session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
    revision TEXT NOT NULL, scanned_at INTEGER NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (session_id, repository, installation_id)
  )`);
  const find = db.prepare(`SELECT repository, installation_id AS installationId, revision, scanned_at AS scannedAt, data
    FROM dependency_snapshots WHERE session_id = ?`);
  const findOne = db.prepare(`SELECT repository, installation_id AS installationId, revision, scanned_at AS scannedAt, data
    FROM dependency_snapshots WHERE session_id = ? AND repository = ? AND installation_id = ?`);
  const save = db.prepare(`INSERT INTO dependency_snapshots (session_id, repository, installation_id, revision, scanned_at, data)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (session_id, repository, installation_id) DO UPDATE SET
    revision = excluded.revision, scanned_at = excluded.scanned_at, data = excluded.data`);
  function snapshots(sessionId) {
    return find.all(sessionId).map(row => bindScanEvidence({ ...row, ...JSON.parse(row.data), data: undefined }));
  }
  function persist(sessionId, result) {
    result.evidenceIdentity = bindScanEvidence(result).evidenceIdentity;
    const { repository, installationId, revision, scannedAt, ...data } = result;
    save.run(sessionId, repository, installationId, revision, scannedAt, JSON.stringify(data));
  }
  async function addVulnerabilities(result) {
    try {
      const declarations = await assessDeclarations(result.packages, result.coverage, { fetchImpl });
      result.coverage.omissions = declarations.omissions;
      result.coverage.assessedDeclarations = declarations.packages.length;
      result.coverage.assessmentCheckedAt = declarations.checkedAt;
      result.warnings = [...new Set([...(result.inventoryWarnings || []), ...result.coverage.missingLockfiles.map(item => item.message),
        ...(result.coverage.omissions.length ? [`${result.coverage.omissions.length} manifest declaration(s) could not be assessed. Review coverage omissions and generate the project lockfile.`] : [])])];
      if (result.warnings.length) result.coverage.complete = false;
      result.vulnerabilityCheck = await check([...result.packages.filter(item => item.resolved), ...declarations.packages]);
      if (result.coverage.declaredPackages) {
        result.vulnerabilityCheck.scope = result.coverage.resolvedPackages ? 'resolved_and_declared_versions' : 'declared_versions';
        result.vulnerabilityCheck.declaredAssessment = { declarations: result.coverage.declaredPackages, checkedRepresentatives: declarations.packages.length, omittedDeclarations: declarations.omissions.length,
          notice: result.coverage.notice };
      }
    }
    catch (error) {
      result.vulnerabilityCheck = { source: 'OSV', status: 'failed', checkedAt: Date.now(),
        checkedPackages: 0, skippedPackages: result.packages.length, findings: [], error: error.message };
    }
    return result;
  }
  async function scan(sessionId, repository, installationId, { preserveOnFailure = false } = {}) {
    if (!github) throw new Error('GitHub App access is not configured.');
    const source = await github.dependencyFiles(installationId, repository);
    const mapped = mapDependencies(source.files);
    const graph = buildDependencyGraph(source.files);
    const coverage = dependencyCoverage(source.files, graph, mapped.packages);
    const inventoryWarnings = [...(source.warnings || []), ...mapped.warnings, ...graph.warnings];
    const result = { repository, installationId, revision: source.revision, mapperVersion: 3, scannedAt: Date.now(), lastSyncedAt: Date.now(),
      packages: mapped.packages, graph, coverage, inventoryWarnings, warnings: inventoryWarnings,
      files: source.files.map(file => file.path) };
    await addVulnerabilities(result);
    if (preserveOnFailure && result.vulnerabilityCheck?.status === 'failed') throw new Error('Advisory provider check failed.');
    persist(sessionId, result);
    return result;
  }
  async function recheck(sessionId, repository, installationId, { preserveOnFailure = false } = {}) {
    const row = findOne.get(sessionId, repository, installationId);
    if (!row) throw new Error('Scan repository dependencies first.');
    const result = { ...row, ...JSON.parse(row.data) };
    delete result.data;
    if (result.mapperVersion !== 3) return scan(sessionId, repository, installationId, { preserveOnFailure });
    await addVulnerabilities(result);
    if (preserveOnFailure && result.vulnerabilityCheck?.status === 'failed') throw new Error('Advisory provider check failed.');
    delete result.upgradePlans;
    persist(sessionId, result);
    return result;
  }
  async function upgradePlan(sessionId, repository, installationId, name, version, { force = false } = {}) {
    const row = findOne.get(sessionId, repository, installationId);
    if (!row) throw new Error('Scan repository dependencies first.');
    const snapshot = bindScanEvidence({ ...row, ...JSON.parse(row.data) });
    if (snapshot.coverage?.missingLockfiles?.length || snapshot.vulnerabilityCheck?.findings?.some(item => item.package === name && item.version === version && /^declared_/.test(item.assessmentKind || item.versionEvidence || ''))) {
      throw Object.assign(new Error('Generate and commit the project lockfile with its existing package manager, then sync and scan again before planning an upgrade. Manifest declarations do not identify installed versions or transitive dependency paths.'),
        { status: 400, code: 'lockfile_required', coverage: snapshot.coverage });
    }
    if (!snapshot.graph) throw new Error('Rescan packages to build the dependency graph.');
    if (!snapshot.graph.nodes?.length) throw new Error('A supported npm or pnpm lockfile is required for upgrade planning.');
    if (!snapshot.packages.some(item => item.name === name && item.version === version && item.resolved)) {
      throw new Error('Choose a pinned package version from this repository.');
    }
    const cached = snapshot.upgradePlans?.find(item => item.name === name && item.currentVersion === version);
    if (!force && cached?.plannerVersion === 3 && scanEvidenceKey(cached) && cached.plannedAt > Date.now() - 60 * 60_000 && sameScanEvidence(cached, snapshot)) return cached;
    const result = { ...await plan(snapshot, name, version), plannedAt: Date.now(), plannerVersion: 3,
      repository, installationId, revision: snapshot.revision, scannedAt: snapshot.scannedAt, evidenceIdentity: snapshot.evidenceIdentity,
      snapshotRevision: snapshot.revision, snapshotScannedAt: snapshot.scannedAt, advisoryCheckedAt: snapshot.vulnerabilityCheck?.checkedAt };
    const latestRow = findOne.get(sessionId, repository, installationId);
    const latest = latestRow && bindScanEvidence({ ...latestRow, ...JSON.parse(latestRow.data) });
    if (!latest || !sameScanEvidence(result, latest)) {
      throw new Error('Repository scan changed during planning. Refresh and try again.');
    }
    delete latest.data;
    latest.upgradePlans = [...(latest.upgradePlans || []).filter(item => item.name !== name || item.currentVersion !== version), result];
    persist(sessionId, latest);
    return result;
  }
  async function sync(sessionId, repository, installationId) {
    const row = findOne.get(sessionId, repository, installationId);
    if (!row) return scan(sessionId, repository, installationId);
    const previous = { ...row, ...JSON.parse(row.data) }; delete previous.data;
    if (previous.mapperVersion !== 3 || await github.dependencyRevision(installationId, repository) !== previous.revision) return scan(sessionId, repository, installationId);
    if (previous.vulnerabilityCheck?.status === 'failed' || (previous.vulnerabilityCheck?.checkedAt || 0) < Date.now() - 6 * 3600000) {
      await recheck(sessionId, repository, installationId);
    }
    // Preserve plans and scan timestamps when nothing changed. The API's repo
    // lock serializes this write with scan/recheck/upgrade-plan operations.
    const latest = findOne.get(sessionId, repository, installationId);
    const result = { ...latest, ...JSON.parse(latest.data), lastSyncedAt: Date.now() }; delete result.data;
    persist(sessionId, result);
    return result;
  }
  return { snapshots, scan, sync, recheck, upgradePlan };
}
