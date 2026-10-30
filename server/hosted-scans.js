import express from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { SCAN_LIMITS, sourceFiles } from './scan-input.js';
import { ARTIFACT_LIMITS, ARTIFACT_TOOLS } from './scan-artifacts.js';
import { webScanOrigin, issueWebTargetChallenge, verifyWebTargetChallenge } from './web-scan-target.js';
import { assessmentTool, TARGET_ASSESSMENTS } from '../shared/assessment-tools.js';
import { TOOL_CATALOG } from '../shared/tool-catalog.js';
import { assessmentInput, ASSESSMENT_MANIFEST } from './assessment-input.js';
import { assessmentResolvers } from './assessment-dns.js';
import { createScanUsage } from './scan-usage.js';
import { usageMetrics } from './usage-metrics.js';
import { transactionSync } from './db-transaction.js';
import { kubernetesScanVersion } from '../shared/kubernetes-scan.js';

const hash = value => createHash('sha256').update(value).digest('hex');
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const LEGACY_TOOLS = ['opengrep', 'trivy-vuln', 'gitleaks'];
const TOOL_IDS = new Set(TOOL_CATALOG.map(tool => tool.id));
export function hostedScanTools() { return { schemaVersion: 2, limits: { ...SCAN_LIMITS }, tools: TOOL_CATALOG.map(tool => ({ ...tool })) }; }

function selectedTools(input) {
  if (input?.tools === undefined) return [...LEGACY_TOOLS];
  if (!Array.isArray(input.tools) || !input.tools.length || input.tools.length > TOOL_CATALOG.length ||
      input.tools.some(id => typeof id !== 'string' || !TOOL_IDS.has(id)) || new Set(input.tools).size !== input.tools.length) {
    throw fail('Select one or more unique tool IDs from GET /v1/tools.');
  }
  const tools = TOOL_CATALOG.map(tool => tool.id).filter(id => input.tools.includes(id));
  if (tools.some(id => assessmentTool(id)) && tools.length !== 1) throw fail('Assessments require one selected tool per job.');
  if (tools.includes('trivy-sbom') && tools.length !== 1) throw fail('SBOM scans require trivy-sbom as the only selected tool.');
  if (tools.includes('spectral-owasp') && tools.length !== 1) throw fail('OpenAPI scans require spectral-owasp as the only selected tool.');
  if (tools.some(id => Object.values(ARTIFACT_TOOLS).some(ids => ids.includes(id))) && tools.length !== 1)
    throw fail('Artifact scans require one selected tool per job.');
  return tools;
}

function validateSbom(files, tools) {
  if (!tools.includes('trivy-sbom')) return;
  if (files.length !== 1 || !files[0].path.toLowerCase().endsWith('.json')) throw fail('SBOM scans require exactly one CycloneDX or SPDX JSON file.');
  let document;
  try { document = JSON.parse(files[0].content); } catch { throw fail('SBOM file must contain valid JSON.'); }
  if (!document || typeof document !== 'object' || Array.isArray(document) ||
      !(document.bomFormat === 'CycloneDX' || typeof document.spdxVersion === 'string' && document.spdxVersion.startsWith('SPDX-'))) {
    throw fail('SBOM file must be CycloneDX or SPDX JSON.');
  }
}

export function createHostedScans(db, { sandbox, encrypt, decrypt, metering, artifacts, targetSigningKey,
  assessmentTools = [], resolvers = assessmentResolvers, now = Date.now, onAuthenticatedPrincipal } = {}) {
  if (onAuthenticatedPrincipal !== undefined && typeof onAuthenticatedPrincipal !== 'function') throw new Error('Authenticated account initialization must be a function.');
  const enabledAssessments = new Set(assessmentTools);
  function requireAssessmentReady(tools) {
    if (sandbox?.tools && tools.some(id => !sandbox.tools.includes(id)))
      throw fail('This tool is not enabled on this deployment.', 503);
    if (tools.some(id => assessmentTool(id) && !enabledAssessments.has(id)))
      throw fail('This assessment is not enabled on this deployment.', 503);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS scan_keys (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL, revoked_at INTEGER
  ); CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, key_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
    input_bytes INTEGER NOT NULL, file_count INTEGER NOT NULL, result TEXT, error TEXT,
    UNIQUE(workspace_id, idempotency_key)
  ); CREATE INDEX IF NOT EXISTS scan_jobs_queue ON scan_jobs(status, created_at);
  CREATE INDEX IF NOT EXISTS scan_jobs_workspace ON scan_jobs(workspace_id, created_at);
  CREATE TABLE IF NOT EXISTS scan_sources (scan_id TEXT NOT NULL, path TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY(scan_id, path));
  CREATE TABLE IF NOT EXISTS scan_cleanup (scan_id TEXT PRIMARY KEY);`);
  db.exec(`CREATE TABLE IF NOT EXISTS scan_verified_targets (
    workspace_id TEXT NOT NULL, origin TEXT NOT NULL, proof TEXT NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY(workspace_id, origin)
  )`);
  const columns = new Set(db.prepare('PRAGMA table_info(scan_jobs)').all().map(column => column.name));
  if (!columns.has('selected_tools')) db.exec(`ALTER TABLE scan_jobs ADD COLUMN selected_tools TEXT NOT NULL DEFAULT '["opengrep","trivy-vuln","gitleaks"]'`);
  if (!columns.has('artifact_id')) db.exec('ALTER TABLE scan_jobs ADD COLUMN artifact_id TEXT');
  if (!columns.has('artifact_context')) db.exec('ALTER TABLE scan_jobs ADD COLUMN artifact_context TEXT');
  if (!columns.has('kubernetes_version')) db.exec('ALTER TABLE scan_jobs ADD COLUMN kubernetes_version TEXT');
  db.exec(`CREATE TABLE IF NOT EXISTS scan_artifacts (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, key_id TEXT NOT NULL, kind TEXT NOT NULL,
    object_key TEXT NOT NULL UNIQUE, size INTEGER NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT, deleted_at INTEGER
  ); CREATE INDEX IF NOT EXISTS scan_artifacts_expiry ON scan_artifacts(expires_at, deleted_at);`);
  const usageFacts = createScanUsage(db, { toolIds: [...TOOL_IDS], now });
  const checkMembership = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'memberships')").all().length === 2;
  transactionSync(db, () => usageFacts.backfill());
  function issueKey(workspace, user, { inTransaction = false } = {}) {
    const id = randomBytes(16).toString('hex'), token = `offense_sk_${randomBytes(32).toString('hex')}`;
    const insert = () => {
      if (db.prepare('SELECT COUNT(*) AS n FROM scan_keys WHERE workspace_id = ? AND revoked_at IS NULL').get(workspace).n >= 5) throw fail('Revoke an existing scan key first; five active keys are allowed.', 409);
      db.prepare('INSERT INTO scan_keys VALUES (?, ?, ?, ?, ?, NULL)').run(id, workspace, String(user), hash(token), now());
      return { id, token, createdAt: now() };
    };
    return inTransaction ? insert() : transactionSync(db, insert);
  }
  function authenticate(token) {
    if (typeof token !== 'string' || !/^(?:offense_sk_|purple_scan_)[a-f0-9]{64}$/.test(token)) return null;
    const principal = db.prepare('SELECT id, workspace_id, user_id, created_at AS createdAt FROM scan_keys WHERE token_hash = ? AND revoked_at IS NULL').get(hash(token));
    if (!principal) return null;
    if (checkMembership && !db.prepare('SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.user_id = ? AND m.workspace_id = ?').get(principal.user_id, principal.workspace_id)) return null;
    if (onAuthenticatedPrincipal) {
      if (!checkMembership) throw fail('Account initialization is temporarily unavailable.', 503);
      onAuthenticatedPrincipal({ userId: principal.user_id, workspaceId: principal.workspace_id });
    }
    return principal;
  }
  function targetChallenge(workspaceId, target) {
    if (![...TARGET_ASSESSMENTS].some(id => enabledAssessments.has(id))) throw fail('Live target assessments are not enabled on this deployment.', 503);
    return issueWebTargetChallenge({ target, workspaceId, key: targetSigningKey, now });
  }
  async function verifyTarget(workspaceId, challenge) {
    const proof = await verifyWebTargetChallenge({ challenge, workspaceId, key: targetSigningKey, now, ...resolvers });
    db.prepare('INSERT OR REPLACE INTO scan_verified_targets VALUES (?, ?, ?, ?)')
      .run(workspaceId, proof.origin, JSON.stringify(proof), proof.expiresAt);
    return { origin: proof.origin, verifiedAt: proof.verifiedAt, expiresAt: proof.expiresAt };
  }
  function beginArtifactUpload(token, metadata) {
    const principal = authenticate(token);
    if (!principal) throw fail('A valid Offense API key is required.', 401);
    if (!artifacts) throw fail('Artifact scanning is not configured.', 503);
    const { kind, size, sha256 } = metadata || {};
    if (kind === 'mobile-app') requireAssessmentReady(['mobsf-static']);
    if (!Object.hasOwn(ARTIFACT_LIMITS, kind) || !Number.isSafeInteger(size) || size < 1 || size > ARTIFACT_LIMITS[kind] ||
        !/^[a-f0-9]{64}$/.test(sha256 || '')) throw fail('Invalid artifact metadata.');
    return transactionSync(db, () => {
      const timestamp = now();
      if (db.prepare("SELECT COUNT(*) AS n FROM scan_artifacts WHERE workspace_id = ? AND expires_at > ? AND status IN ('pending','ready')")
        .get(principal.workspace_id, timestamp).n >= 2) throw fail('Two artifact uploads are already pending in this workspace.', 429);
      const id = randomBytes(16).toString('hex');
      const objectKey = `scan/${hash(principal.workspace_id).slice(0, 16)}/${id}`;
      db.prepare("INSERT INTO scan_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL)")
        .run(id, principal.workspace_id, principal.id, kind, objectKey, size, sha256, timestamp, timestamp + 30 * 60_000);
      return { id, objectKey, expiresAt: timestamp + 30 * 60_000 };
    });
  }
  function finishArtifactUpload(token, id, size) {
    const principal = authenticate(token);
    if (!principal) throw fail('A valid Offense API key is required.', 401);
    const row = db.prepare('SELECT * FROM scan_artifacts WHERE id = ? AND workspace_id = ? AND key_id = ?')
      .get(id, principal.workspace_id, principal.id);
    if (!row || row.status !== 'pending' || row.expires_at <= now() || row.size !== size)
      throw fail('Artifact upload is invalid or expired.', 409);
    db.prepare("UPDATE scan_artifacts SET status = 'ready' WHERE id = ?").run(id);
    return { id, kind: row.kind, size: row.size, sha256: row.sha256, expiresAt: row.expires_at };
  }
  function abandonArtifactUpload(token, id) {
    const principal = authenticate(token);
    if (!principal) return;
    db.prepare("UPDATE scan_artifacts SET status = 'abandoned' WHERE id = ? AND workspace_id = ? AND key_id = ? AND status = 'pending'")
      .run(id, principal.workspace_id, principal.id);
  }
  function get(id, workspace) {
    const row = db.prepare('SELECT * FROM scan_jobs WHERE id = ? AND workspace_id = ?').get(id, workspace);
    if (!row) return null;
    return { id: row.id, status: row.status, createdAt: row.created_at, startedAt: row.started_at, finishedAt: row.finished_at,
      ...(row.kubernetes_version ? { kubernetesVersion: row.kubernetes_version } : {}),
      fingerprint: row.fingerprint, selectedTools: JSON.parse(row.selected_tools), usage: { inputBytes: row.input_bytes, files: row.file_count,
        durationMs: row.started_at && row.finished_at ? Math.max(0, row.finished_at - row.started_at) : null },
      ...(metering ? { metering: metering.usage(row.id) } : {}),
      reportExpired: ['completed', 'partial'].includes(row.status) && !row.result,
      ...(row.result ? JSON.parse(row.result) : {}), ...(row.error ? { error: row.error } : {}) };
  }
  function createJob(principal, input, idempotency) {
    if (!sandbox || !encrypt || !decrypt) throw fail('Hosted scanning is not configured.', 503);
    if (typeof idempotency !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/.test(idempotency)) throw fail('Send an Idempotency-Key header (8–100 letters, numbers, underscores or hyphens).');
    const tools = selectedTools(input);
    const kubernetesVersion = kubernetesScanVersion({ ...input, tools });
    requireAssessmentReady(tools);
    const assessment = assessmentTool(tools[0]);
    const artifactTool = Object.values(ARTIFACT_TOOLS).some(ids => ids.includes(tools[0]));
    let source, artifact = null, artifactContext = null;
    if (artifactTool) {
      if (input?.files !== undefined || !/^[a-f0-9]{32}$/.test(input?.artifactId || ''))
        throw fail('Select one uploaded artifact by ID for this tool.');
      artifact = db.prepare('SELECT * FROM scan_artifacts WHERE id = ? AND workspace_id = ? AND key_id = ?')
        .get(input.artifactId, principal.workspace_id, principal.id);
      if (!artifact || !ARTIFACT_TOOLS[artifact.kind].includes(tools[0])) throw fail('Artifact not found for this tool.', 404);
      if (tools[0].startsWith('guarddog-')) {
        const packageName = input?.packageName, packageVersion = input?.packageVersion;
        if (typeof packageName !== 'string' || !/^(?:@?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?)$/.test(packageName) ||
            typeof packageVersion !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._+!-]{0,99}$/.test(packageVersion))
          throw fail('Package scans require a valid exact package name and version.');
        artifactContext = { packageName, packageVersion };
      }
      if (tools[0] === 'cosign-image') {
        const { expectedDigest, expectedIdentity, expectedIssuer } = input || {};
        if (!/^sha256:[a-f0-9]{64}$/.test(expectedDigest || '') ||
            typeof expectedIdentity !== 'string' || expectedIdentity.length < 1 || expectedIdentity.length > 240 ||
            !/^[\x21-\x7e]+$/.test(expectedIdentity) || /[\*?\[\]{}()|+^$\\]/.test(expectedIdentity) ||
            typeof expectedIssuer !== 'string' || expectedIssuer.length > 300 || !/^https:\/\//.test(expectedIssuer))
          throw fail('Cosign verification requires an exact image digest, signer identity and HTTPS issuer.');
        let issuer;
        try { issuer = new URL(expectedIssuer); } catch { throw fail('Invalid Cosign certificate issuer.'); }
        if (issuer.username || issuer.password || issuer.hash || issuer.search || issuer.origin !== expectedIssuer)
          throw fail('Cosign certificate issuer must be a canonical HTTPS origin.');
        artifactContext = { expectedDigest, expectedIdentity, expectedIssuer };
      }
      if (tools[0] === 'zap-passive-har') {
        try { artifactContext = { target: webScanOrigin(input?.target) }; }
        catch { throw fail('Passive HAR scans require a public HTTPS origin matching the captured responses.'); }
      }
      if (assessment) {
        const request = assessmentInput(tools[0], input, { artifact });
        artifactContext = { assessment: request };
      }
      source = { files: [], bytes: artifact.size, fingerprint: hash(`${artifact.kind}\0${artifact.sha256}`) };
    } else if (assessment) {
      if (input?.artifactId !== undefined) throw fail('This assessment does not accept an artifact.');
      let verifiedTarget;
      if (TARGET_ASSESSMENTS.has(tools[0])) {
        const origin = webScanOrigin(input.target);
        const proof = db.prepare('SELECT proof FROM scan_verified_targets WHERE workspace_id = ? AND origin = ? AND expires_at > ?')
          .get(principal.workspace_id, origin, now());
        if (proof) verifiedTarget = JSON.parse(proof.proof);
      }
      const request = assessmentInput(tools[0], input, { verifiedTarget });
      const content = JSON.stringify(request);
      if (Buffer.byteLength(content) > SCAN_LIMITS.totalBytes) throw fail('Assessment input exceeds 4 MiB.');
      source = { files: [{ path: ASSESSMENT_MANIFEST, content }], bytes: Buffer.byteLength(content), fingerprint: hash(content) };
    } else {
      if (input?.artifactId !== undefined) throw fail('This tool accepts uploaded text files, not an artifact ID.');
      source = sourceFiles(input?.files);
      validateSbom(source.files, tools);
      if (tools.includes('spectral-owasp') && (source.files.length !== 1 || !/\.(json|ya?ml)$/i.test(source.files[0].path)))
        throw fail('OpenAPI scans require one JSON or YAML document.');
    }
    const sourceFingerprint = kubernetesVersion ? hash(`${source.fingerprint}\0${kubernetesVersion}`) : source.fingerprint;
    const fingerprint = tools.join(',') === LEGACY_TOOLS.join(',') ? sourceFingerprint : hash(`${sourceFingerprint}\0${tools.join(',')}\0${JSON.stringify(artifactContext)}`);
    return transactionSync(db, () => {
      const existing = db.prepare('SELECT id, fingerprint FROM scan_jobs WHERE workspace_id = ? AND idempotency_key = ?').get(principal.workspace_id, idempotency);
      if (existing) {
        if (existing.fingerprint !== fingerprint) throw fail('This Idempotency-Key was used with different source files or tools.', 409);
        return get(existing.id, principal.workspace_id);
      }
      const timestamp = now();
      if (artifact && (artifact.status !== 'ready' || artifact.expires_at <= timestamp || artifact.used_by))
        throw fail('Artifact is expired or already used.', 409);
      if (db.prepare("SELECT COUNT(*) AS n FROM scan_jobs WHERE workspace_id = ? AND status IN ('queued','starting','running')").get(principal.workspace_id).n >= 2) throw fail('Two scans are already queued or running in this workspace.', 429);
      if (db.prepare('SELECT COUNT(*) AS n FROM scan_jobs WHERE workspace_id = ? AND created_at >= ?').get(principal.workspace_id, timestamp - 86400000).n >= 10 ||
          db.prepare('SELECT COUNT(*) AS n FROM scan_jobs WHERE created_at >= ?').get(timestamp - 86400000).n >= 50) throw fail('Daily hosted scan quota reached. Retry tomorrow.', 429);
      const id = randomBytes(16).toString('hex');
      const quote = metering?.quote({ tools, inputBytes: source.bytes, fileCount: artifact ? 1 : source.files.length });
      if (quote?.billable && input?.maxChargeMicros !== quote.maximumMicros)
        throw fail('Scanner price changed or no quote was supplied. Request a fresh quote before submitting.', 409);
      db.prepare(`INSERT INTO scan_jobs (id, workspace_id, user_id, key_id, idempotency_key, fingerprint, status,
        created_at, updated_at, input_bytes, file_count, selected_tools, artifact_id, artifact_context, kubernetes_version) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, principal.workspace_id, principal.user_id, principal.id, idempotency, fingerprint, timestamp, timestamp, source.bytes, artifact ? 1 : source.files.length, JSON.stringify(tools), artifact?.id || null, artifactContext ? JSON.stringify(artifactContext) : null, kubernetesVersion || null);
      if (metering) metering.reserve({ jobId: id, workspaceId: principal.workspace_id, quote });
      if (artifact) db.prepare("UPDATE scan_artifacts SET status = 'used', used_by = ? WHERE id = ? AND status = 'ready'").run(id, artifact.id);
      const insert = db.prepare('INSERT INTO scan_sources VALUES (?, ?, ?)');
      for (const file of source.files) insert.run(id, file.path, encrypt(file.content));
      usageFacts.capture(id);
      return get(id, principal.workspace_id);
    });
  }
  function create(principal, input, idempotency) {
    try { return createJob(principal, input, idempotency); }
    catch (error) {
      usageFacts.activity(principal?.workspace_id, 'submission_denied', Array.isArray(input?.tools) ? input.tools : []);
      throw error;
    }
  }
  function quote(input, workspaceId) {
    try {
      if (!metering) throw fail('Scanner metering is unavailable.', 503);
      const tools = selectedTools(input);
      requireAssessmentReady(tools);
      const offered = metering.quote({ tools, inputBytes: input?.inputBytes, fileCount: input?.fileCount });
      usageFacts.activity(workspaceId, 'quote_issued', tools);
      return offered;
    } catch (error) {
      usageFacts.activity(workspaceId, 'quote_denied', Array.isArray(input?.tools) ? input.tools : []);
      throw error;
    }
  }
  function usage(workspace) {
    if (!metering) throw fail('Scanner metering is unavailable.', 503);
    const jobs = db.prepare('SELECT id, status, created_at FROM scan_jobs WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 25').all(workspace)
      .map(row => ({ id: row.id, status: row.status, createdAt: row.created_at, metering: metering.usage(row.id) }));
    return { ...metering.status(workspace), jobs, analytics: usageMetrics(db, { workspaceId: workspace, now }) };
  }
  function tools(workspace) {
    const catalog = hostedScanTools();
    const available = tool => (!sandbox?.tools || sandbox.tools.includes(tool.id)) &&
      (!assessmentTool(tool.id) || enabledAssessments.has(tool.id));
    if (!metering) return { ...catalog, tools: catalog.tools.map(tool => ({ ...tool,
      availability: available(tool) ? 'available' : 'disabled' })), billing: { enabled: false, configured: false } };
    const account = metering.status(workspace);
    return { ...catalog, billing: { enabled: account.enabled, configured: true, currency: account.currency,
      unit: 'per_tool' }, tools: catalog.tools.map(tool => {
        if (!available(tool)) return { ...tool, availability: 'disabled', availabilityReason: 'Execution image and required egress must be verified before this tool is enabled.' };
        const price = metering.quote({ tools: [tool.id], inputBytes: 1, fileCount: 1 }).prices[0];
        return { ...tool, availability: 'available', unit: price.unit, basePriceMicros: price.basePriceMicros,
          additionalMiBPriceMicros: price.additionalMiBPriceMicros };
      }) };
  }
  let busy = false;
  async function dispatch() {
    if (busy) return;
    busy = true;
    try {
      transactionSync(db, () => usageFacts.backfill());
      db.prepare(`UPDATE scan_jobs SET result = NULL WHERE finished_at < ? AND result IS NOT NULL
        AND EXISTS (SELECT 1 FROM scan_usage_jobs u WHERE u.job_id=scan_jobs.id)`).run(now() - 30 * 86400000);
      if (artifacts) for (const stale of db.prepare(`SELECT id, object_key FROM scan_artifacts
        WHERE deleted_at IS NULL AND (expires_at < ? OR status IN ('transferred','abandoned')) LIMIT 10`).all(now())) {
        try {
          await artifacts.delete(stale.object_key);
          db.prepare('UPDATE scan_artifacts SET deleted_at = ? WHERE id = ?').run(now(), stale.id);
        } catch { /* retry from the next durable alarm */ }
      }
      for (const expired of db.prepare("SELECT id FROM scan_jobs WHERE status IN ('queued','starting','running') AND created_at < ?").all(now() - 30 * 60_000)) {
        transactionSync(db, () => {
          db.prepare("UPDATE scan_jobs SET status = 'failed', error = 'Scan queue or execution deadline exceeded.', finished_at = ?, updated_at = ? WHERE id = ?").run(now(), now(), expired.id);
          metering?.release(expired.id);
          usageFacts.capture(expired.id);
          db.prepare('DELETE FROM scan_sources WHERE scan_id = ?').run(expired.id);
          db.prepare('INSERT OR IGNORE INTO scan_cleanup VALUES (?)').run(expired.id);
        });
      }
      // Usage maintenance and expired reservations do not depend on an agent
      // binding. Restored histories must keep progressing with execution off.
      if (!sandbox) return;
      for (const entry of db.prepare('SELECT scan_id FROM scan_cleanup LIMIT 10').all()) {
        try {
          const cleanup = await sandbox.destroy(entry.scan_id);
          usageFacts.containerDuration(entry.scan_id, cleanup?.usage);
          db.prepare('DELETE FROM scan_cleanup WHERE scan_id = ?').run(entry.scan_id);
        } catch { /* retry on the next durable alarm */ }
      }
      // Only one scan container runs at a time. A durable alarm resumes this queue.
      const row = db.prepare("SELECT * FROM scan_jobs WHERE status IN ('starting','running','queued') ORDER BY CASE status WHEN 'queued' THEN 1 ELSE 0 END, created_at LIMIT 1").get();
      if (!row) return;
      try {
        if (now() - row.created_at > 30 * 60_000) throw new Error('Hosted scan exceeded its 30-minute queue/execution deadline.');
        if (!db.prepare('SELECT id FROM scan_keys WHERE id = ? AND revoked_at IS NULL').get(row.key_id)) throw new Error('The scan key was revoked.');
        let result;
        if (row.status === 'queued' || row.status === 'starting') {
          // Mark dispatch before the external call. Retrying uses the same container ID.
          db.prepare("UPDATE scan_jobs SET status = 'starting', started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?").run(now(), now(), row.id);
          usageFacts.capture(row.id);
          const artifact = row.artifact_id ? db.prepare('SELECT * FROM scan_artifacts WHERE id = ? AND used_by = ?').get(row.artifact_id, row.id) : null;
          if (row.artifact_id && (!artifact || artifact.deleted_at || artifact.expires_at <= now() || artifact.status !== 'used'))
            throw new Error('Artifact expired before scanner dispatch.');
          const files = artifact ? [] : db.prepare('SELECT path, content FROM scan_sources WHERE scan_id = ?').all(row.id).map(file => ({ path: file.path, content: decrypt(file.content) }));
          const selected = JSON.parse(row.selected_tools);
          const assessment = assessmentTool(selected[0]);
          const assessmentRequest = assessment ? artifact ? JSON.parse(row.artifact_context).assessment : JSON.parse(files[0].content) : null;
          result = await sandbox.start({ id: row.id, files: assessment ? [] : files, tools: JSON.parse(row.selected_tools),
            ...(row.kubernetes_version ? { kubernetesVersion: row.kubernetes_version } : {}),
            ...(assessmentRequest ? { assessment: assessmentRequest } : {}),
            ...(artifact ? { artifact: { objectKey: artifact.object_key, kind: artifact.kind, sha256: artifact.sha256, size: artifact.size,
              ...(row.artifact_context ? JSON.parse(row.artifact_context) : {}) } } : {}) });
          if (result.status !== 'running') throw new Error('The hosted scanner could not start.');
          db.prepare("UPDATE scan_jobs SET status = 'running', updated_at = ? WHERE id = ?").run(now(), row.id);
          usageFacts.capture(row.id);
          if (artifact) db.prepare("UPDATE scan_artifacts SET status = 'transferred' WHERE id = ?").run(artifact.id);
          db.prepare('DELETE FROM scan_sources WHERE scan_id = ?').run(row.id);
          return;
        }
        result = await sandbox.get(row.id);
        if (result.status === 'running') return;
        if (!['completed', 'partial', 'failed'].includes(result.status) || !Array.isArray(result.tools) || !Array.isArray(result.findings)) throw new Error('The scanner returned an invalid or missing result.');
        const selected = JSON.parse(row.selected_tools);
        const allSelectedComplete = selected.every(id => result.tools.some(tool => tool?.name === id && tool?.status === 'complete'));
        const status = result.status === 'completed' && !allSelectedComplete ? 'partial' : result.status;
        const { status: ignoredStatus, ...report } = result;
        if (status === 'partial' && ignoredStatus === 'completed') report.warnings = [...(Array.isArray(report.warnings) ? report.warnings : []), 'A selected scanner did not report complete coverage.'];
        if (JSON.stringify(report).length > 1_500_000) throw new Error('The scanner report exceeds its storage budget.');
        transactionSync(db, () => {
          metering?.settle({ jobId: row.id, status, tools: result.tools });
          db.prepare('UPDATE scan_jobs SET status = ?, result = ?, finished_at = ?, updated_at = ? WHERE id = ?')
            .run(status, JSON.stringify(report), now(), now(), row.id);
          usageFacts.capture(row.id);
        });
      } catch {
        transactionSync(db, () => {
          db.prepare("UPDATE scan_jobs SET status = 'failed', error = ?, finished_at = ?, updated_at = ? WHERE id = ?")
            .run('Hosted scan could not complete. Start a new scan; no clean result is implied.', now(), now(), row.id);
          metering?.release(row.id);
          usageFacts.capture(row.id);
          if (row.artifact_id) db.prepare("UPDATE scan_artifacts SET status = 'abandoned' WHERE id = ?").run(row.artifact_id);
        });
      } finally {
        const current = db.prepare('SELECT status FROM scan_jobs WHERE id = ?').get(row.id);
        if (['completed', 'partial', 'failed'].includes(current.status)) {
          db.prepare('DELETE FROM scan_sources WHERE scan_id = ?').run(row.id);
          db.prepare('INSERT OR IGNORE INTO scan_cleanup VALUES (?)').run(row.id);
          try {
            const cleanup = await sandbox.destroy(row.id);
            usageFacts.containerDuration(row.id, cleanup?.usage);
            db.prepare('DELETE FROM scan_cleanup WHERE scan_id = ?').run(row.id);
          } catch { /* retry on the next durable alarm */ }
        }
      }
    } finally { busy = false; }
  }
  return { issueKey, authenticate, beginArtifactUpload, finishArtifactUpload, abandonArtifactUpload,
    create, get, dispatch, tools, quote, usage, targetChallenge, verifyTarget };
}

export function createScanSandbox(url, key, fetchImpl = fetch) {
  if (!url || !key) return null;
  async function call(route, method, body) {
    const response = await fetchImpl(`${url.replace(/\/$/, '')}/scans${route}`, { method,
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(60_000) });
    if (!response.ok) throw new Error('Scan service unavailable.');
    return response.json();
  }
  return { start: input => call('', 'POST', input), get: id => call(`/${id}`, 'GET'), destroy: id => call(`/${id}`, 'DELETE') };
}

export function registerScanApi(app, { scans, dispatch = () => {} }) {
  const router = express.Router();
  const authenticate = (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.get('origin')) return res.status(403).json({ error: 'Use the hosted scan API from your coding agent.' });
    let principal;
    try { principal = scans.authenticate(req.get('authorization')?.replace(/^Bearer /, '')); }
    catch { return res.status(503).json({ error: 'Offense account information is temporarily unavailable.' }); }
    if (!principal) return res.status(401).json({ error: 'A valid Offense API key is required.' });
    req.scanPrincipal = principal; next();
  };
  app.get('/v1/tools', authenticate, (req, res) => res.json(scans.tools(req.scanPrincipal.workspace_id)));
  app.get('/v1/usage', authenticate, (req, res) => {
    try { res.json(scans.usage(req.scanPrincipal.workspace_id)); }
    catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  });
  app.post('/v1/quotes', authenticate, express.json({ limit: '16kb', strict: true }), (req, res) => {
    try { res.json(scans.quote(req.body, req.scanPrincipal.workspace_id)); }
    catch (error) { res.status(error.status || 400).json({ error: error.message }); }
  });
  app.post('/v1/targets/challenge', authenticate, express.json({ limit: '8kb', strict: true }), (req, res) => {
    try { res.json(scans.targetChallenge(req.scanPrincipal.workspace_id, req.body.target)); }
    catch (error) { res.status(error.status || 400).json({ error: error.message }); }
  });
  app.post('/v1/targets/verify', authenticate, express.json({ limit: '8kb', strict: true }), async (req, res) => {
    try { res.json(await scans.verifyTarget(req.scanPrincipal.workspace_id, req.body.challenge)); }
    catch { res.status(400).json({ error: 'Target ownership could not be verified. Check the DNS record and challenge expiry.' }); }
  });
  router.use(authenticate);
  router.use(express.json({ limit: '6mb', strict: true }));
  router.post('/', (req, res) => {
    try {
      const job = scans.create(req.scanPrincipal, req.body, req.get('idempotency-key'));
      res.set('Location', `/v1/scans/${job.id}`).set('Retry-After', '5').status(202).json(job);
      dispatch();
    } catch (error) { res.status(error.status || 400).json({ error: error.message }); }
  });
  router.get('/:id', (req, res) => {
    const result = scans.get(req.params.id, req.scanPrincipal.workspace_id);
    if (!result) return res.status(404).json({ error: 'Scan not found.' });
    res.json(result); dispatch();
  });
  router.use((req, res) => res.status(404).json({ error: 'Unknown hosted scan endpoint.' }));
  router.use((error, req, res, next) => res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: 'Invalid or oversized scan request.' }));
  app.use('/v1/scans', router);
}

export function registerScanKeys(app, { scans, db }) {
  app.get('/api/scan-keys', (req, res) => {
    const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('scan_jobs', 'scan_meter_jobs')")
      .all().map(table => table.name));
    const hasJobs = tables.has('scan_jobs');
    // These are hosted submission metrics, not all authenticated requests.
    // Unknown historical storage remains unknown rather than appearing unused.
    const activity = hasJobs ? `
      (SELECT MAX(j.created_at) FROM scan_jobs j WHERE j.workspace_id = k.workspace_id AND j.key_id = k.id) AS lastScanAt,
      (SELECT COUNT(*) FROM scan_jobs j WHERE j.workspace_id = k.workspace_id AND j.key_id = k.id) AS scanCount`
      : 'NULL AS lastScanAt, NULL AS scanCount';
    const spend = hasJobs && tables.has('scan_meter_jobs') ? `
      (SELECT COALESCE(SUM(m.charge_micros), 0) FROM scan_jobs j
        JOIN scan_meter_jobs m ON m.job_id = j.id AND m.workspace_id = j.workspace_id
        WHERE j.workspace_id = k.workspace_id AND j.key_id = k.id AND m.state = 'settled') AS spendMicros`
      : 'NULL AS spendMicros';
    res.json({ keys: db.prepare(`SELECT k.id, k.created_at AS createdAt, ${activity}, ${spend}
      FROM scan_keys k WHERE k.workspace_id = ? AND k.revoked_at IS NULL ORDER BY k.created_at DESC`).all(req.workspaceId) });
  });
  app.post('/api/scan-keys', (req, res) => {
    try { res.status(201).json(scans.issueKey(req.workspaceId, req.authUser.id)); }
    catch (error) { res.status(error.status || 400).json({ error: error.message }); }
  });
  app.delete('/api/scan-keys/:id', (req, res) => {
    db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ? AND workspace_id = ?').run(Date.now(), req.params.id, req.workspaceId);
    res.sendStatus(204);
  });
}
