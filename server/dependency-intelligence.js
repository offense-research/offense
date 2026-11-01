import { createHash } from 'node:crypto';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { mapDependencies } from './dependency-mapper.js';
import { buildDependencyGraph } from './dependency-graph.js';
import { checkVulnerabilities } from './osv.js';
import { planUpgrade } from './upgrade-planner.js';
import { buildUpgradeHandoff } from './upgrade-handoff.js';
import { transactionSync } from './db-transaction.js';
import { upgradeRoutes } from '../src/upgrade-routes.js';
import { AUDIT_SCHEMA_VERSION } from '../shared/offense-schema.js';
import { auditAgentPrompt, auditSummaryCounts, coordinateAuditPlans, planningBlocker, planningFailure, targetSelectionEvidence } from '../shared/offense-planning.js';
import { createOffenseTraceStore, offenseRequestTrace, pruneOffenseTraceEvents } from './offense-traces.js';
import { classifyTraceError } from '../shared/offense-trace.js';
import { explainVulnerabilityImpact } from '../shared/vulnerability-impact.js';
import { createSkillUsageStore } from './skill-usage.js';

export class AnalysisError extends Error {
  constructor(message, status = 400, code = 'invalid_request') { super(message); this.status = status; this.code = code; }
}
const severity = value => ({ CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' })[String(value).toUpperCase()] || 'unknown';
const rank = value => ({ critical: 4, high: 3, medium: 2, low: 1, unknown: 0 })[severity(value)];
const key = value => `${value.package || value.name}\0${value.version || value.currentVersion}`;
const fingerprint = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

// All public transports use this single controller: same quota rows, execution
// slots, sanitization, provider budget and existing upgrade-planning engine.
export function createDependencyIntelligence({ db, production = false, check = checkVulnerabilities, plan = planUpgrade,
  now = Date.now, fetchImpl = fetch, traceEnabled = true, traces } = {}) {
  db.exec('CREATE TABLE IF NOT EXISTS skill_rate_limits (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, count INTEGER NOT NULL)');
  const traceStore = traceEnabled && traces !== false ? traces || createOffenseTraceStore({ db, now }) : null;
  const usage = createSkillUsageStore({ db, now });
  let running = 0;
  function admit(req) {
    const timestamp = now(), hour = Math.floor(timestamp / 3600000), minute = Math.floor(timestamp / 60000);
    const client = createHash('sha256').update(String(production ? req.get('cf-connecting-ip') || 'unknown' : req.socket?.remoteAddress || 'unknown')).digest('hex');
    const quotas = [[`minute:${minute}:${client}`, 40, (minute + 1) * 60000], [`hour:${hour}:${client}`, 100, (hour + 1) * 3600000], [`global:${hour}`, 600, (hour + 1) * 3600000]];
    const allowed = transactionSync(db, () => {
      db.prepare('DELETE FROM skill_rate_limits WHERE expires_at <= ?').run(timestamp);
      if (quotas.some(([id, limit]) => (db.prepare('SELECT count FROM skill_rate_limits WHERE key = ?').get(id)?.count || 0) >= limit)) return false;
      for (const [id, , expires] of quotas) db.prepare('INSERT INTO skill_rate_limits VALUES (?, ?, 1) ON CONFLICT(key) DO UPDATE SET count = count + 1').run(id, expires);
      return true;
    });
    if (!allowed) return { status: 429, retryAfter: 60, error: 'Dependency analysis quota reached. Retry later; no scan was performed.' };
    if (running >= 2) return { status: 503, retryAfter: 10, error: 'Other dependency analyses are running. Retry shortly.' };
    return null;
  }
  function prepare(input, strict = false) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new AnalysisError('Provide a dependency metadata object.');
    if (strict && Object.keys(input).some(field => !['files', 'planLimit', 'planning', 'scanning'].includes(field))) throw new AnalysisError('Only files, planLimit, planning and scanning are accepted. Do not send provider credentials or source code.');
    if (strict && input.planLimit !== undefined && (!Number.isInteger(input.planLimit) || input.planLimit < 0 || input.planLimit > 10)) throw new AnalysisError('planLimit must be an integer from 0 to 10.');
    const scan = input.scanning;
    if (scan !== undefined && (!scan || typeof scan !== 'object' || Array.isArray(scan) || input.planning !== undefined ||
      Object.keys(scan).some(field => !['metadataFingerprint', 'packageOffset', 'advisoryOffset', 'batchFingerprint'].includes(field)) ||
      !/^[a-f0-9]{64}$/.test(scan.metadataFingerprint) || !Number.isInteger(scan.packageOffset) || scan.packageOffset < 0 || scan.packageOffset > 4900 || scan.packageOffset % 100 ||
      !Number.isInteger(scan.advisoryOffset) || scan.advisoryOffset < 0 || scan.advisoryOffset > 100000 ||
      !(scan.batchFingerprint === null || /^[a-f0-9]{64}$/.test(scan.batchFingerprint)) || (scan.advisoryOffset > 0 && !scan.batchFingerprint))) {
      throw new AnalysisError('Invalid advisory scanning continuation. Use scanning.next unchanged; do not combine scanning and planning.');
    }
    if (strict && input.planning !== undefined && (!input.planning || typeof input.planning !== 'object' || Array.isArray(input.planning) ||
      Object.keys(input.planning).some(field => !['metadataFingerprint', 'pendingTargetIds'].includes(field)) ||
      !/^[a-f0-9]{64}$/.test(input.planning.metadataFingerprint) || !Array.isArray(input.planning.pendingTargetIds) ||
      !input.planning.pendingTargetIds.length || input.planning.pendingTargetIds.length > 5000 ||
      input.planning.pendingTargetIds.some(id => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id)) ||
      new Set(input.planning.pendingTargetIds).size !== input.planning.pendingTargetIds.length || input.planLimit === 0)) {
      throw new AnalysisError('Planning continuation requires the recorded metadata fingerprint, unique pending target IDs, and a positive planLimit.');
    }
    if (strict && Array.isArray(input.files) && input.files.some(file => file && Object.keys(file).some(field => !['path', 'content'].includes(field)))) throw new AnalysisError('Each lockfile accepts only path and content.');
    try {
      const sanitized = sanitizeLockfiles(input.files), mapped = mapDependencies(sanitized.files);
      if (!mapped.packages.length) throw new Error('No supported exact npm or pnpm dependencies were found. Supply resolved lockfiles; package.json alone is not supported.');
      const graph = buildDependencyGraph(sanitized.files);
      return { files: sanitized.files, packages: mapped.packages, graph, warnings: [...new Set([...sanitized.warnings, ...mapped.warnings, ...(graph.warnings || [])])] };
    } catch (error) { throw new AnalysisError(error.message); }
  }
  function prepareTraced(input, strict, trace) {
    const started = now(); trace?.record('validation', 'started');
    try {
      const prepared = prepare(input, strict);
      trace?.record('validation', 'completed', { durationMs: Math.max(0, now() - started),
        counts: { files: prepared.files.length, packages: prepared.packages.length, coverageWarnings: prepared.warnings.length } });
      return prepared;
    } catch (error) {
      trace?.record('validation', 'rejected', { errorCode: classifyTraceError(error), durationMs: Math.max(0, now() - started) });
      throw error;
    }
  }
  async function execute(action) {
    // Recheck at execution as well as admission, so parser/transport scheduling
    // cannot oversubscribe the controller's two shared slots.
    if (running >= 2) throw new AnalysisError('Other dependency analyses are running. Retry shortly.', 503, 'busy');
    running++;
    const started = now(), deadline = AbortSignal.timeout(90_000);
    let requests = 0, bytes = 0;
    const boundedFetch = async (input, options = {}) => {
      const url = new URL(input);
      if (url.protocol !== 'https:' || url.username || url.password || !['api.osv.dev', 'registry.npmjs.org'].includes(url.hostname) || (url.port && url.port !== '443')) throw new Error('Unsupported intelligence provider URL.');
      if (++requests > 90 || now() - started > 90_000 || deadline.aborted) throw new Error('Hosted analysis reached its request/time budget. Narrow the package scope.');
      // Workers supports follow/manual, not Node's redirect:error. Manual plus
      // an explicit 3xx rejection preserves the same no-redirect boundary.
      const response = await fetchImpl(url.href, { ...options, redirect: 'manual', signal: AbortSignal.any([deadline, options.signal].filter(Boolean)) });
      if (response.status >= 300 && response.status < 400) throw new Error('Intelligence provider redirects are not accepted.');
      if (!response.body) return response;
      let responseBytes = 0;
      return new Response(response.body.pipeThrough(new TransformStream({ transform(chunk, controller) {
        responseBytes += chunk.byteLength; bytes += chunk.byteLength;
        if (responseBytes > 12_000_000 || bytes > 24_000_000) throw new Error('Upstream metadata exceeded the analysis byte budget.');
        controller.enqueue(chunk);
      } })), { status: response.status, statusText: response.statusText, headers: response.headers });
    };
    try { return await action(boundedFetch); }
    catch (error) { if (error instanceof AnalysisError) throw error; throw new AnalysisError(`Analysis incomplete: ${error.message}`, 502, 'analysis_incomplete'); }
    finally { running--; }
  }
  async function snapshot(prepared, boundedFetch, selected, trace, scanning) {
    const started = now(); trace?.record('advisory_scan', 'started');
    try {
      const vulnerabilityCheck = await check(selected || prepared.packages, boundedFetch, { scanning });
      if ((vulnerabilityCheck.status !== 'complete' && !(scanning && vulnerabilityCheck.status === 'partial' && vulnerabilityCheck.scanning?.next)) || !Array.isArray(vulnerabilityCheck.findings)) throw new Error('The advisory check did not complete.');
      trace?.record('advisory_scan', vulnerabilityCheck.status === 'partial' ? 'partial' : 'completed', { durationMs: Math.max(0, now() - started),
        counts: { checkedPackages: vulnerabilityCheck.checkedPackages ?? (selected || prepared.packages).length, advisoryMatches: vulnerabilityCheck.findings.length } });
      return { repository: 'local checkout', revision: 'local lockfile metadata', scannedAt: now(), files: prepared.files.map(file => file.path),
        packages: prepared.packages, graph: prepared.graph, warnings: prepared.warnings, vulnerabilityCheck };
    } catch (error) {
      trace?.record('advisory_scan', 'failed', { errorCode: 'provider_failure', durationMs: Math.max(0, now() - started) }); throw error;
    }
  }
  async function legacy(input, mode, req) {
    const trace = offenseRequestTrace(req), prepared = prepareTraced(input, false, trace);
    const selected = mode === 'plan' ? prepared.packages.filter(item => item.name === input.name && item.version === input.version) : null;
    if (selected && !selected.length) throw new AnalysisError('Choose an exact package/version present in these lockfiles.');
    return execute(async boundedFetch => {
      const current = await snapshot(prepared, boundedFetch, selected, trace);
      if (mode === 'scan') return { ...current, graph: undefined,
        coverage: 'npm lockfiles v2/v3 and pnpm lockfiles v6/v9; known advisory matches, not confirmed exploitability', protocolVersion: 1 };
      const started = now(); trace?.record('upgrade_planning', 'started');
      let upgrade;
      try {
        upgrade = await plan(current, input.name, input.version, { fetchImpl: boundedFetch });
        trace?.record('upgrade_planning', 'completed', { durationMs: Math.max(0, now() - started), counts: { plans: 1 } });
      } catch (error) { trace?.record('upgrade_planning', 'failed', { errorCode: classifyTraceError(error), durationMs: Math.max(0, now() - started) }); throw error; }
      return { plan: upgrade, ...buildUpgradeHandoff({ repository: current.repository, workers: [], snapshot: current, plan: upgrade }), protocolVersion: 1 };
    });
  }
  async function audit(input, req) {
    const trace = offenseRequestTrace(req), prepared = prepareTraced(input, true, trace);
    let planLimit = input.planLimit ?? 3;
    const metadataFingerprint = fingerprint(prepared.files.slice().sort((a, b) => a.path.localeCompare(b.path)));
    if (input.scanning && input.scanning.metadataFingerprint !== metadataFingerprint) throw new AnalysisError('Scanning continuation does not match these exact dependency files. Start a new full audit.', 409, 'stale_scanning_cursor');
    const targetId = (name, version) => fingerprint(['npm', name, version, metadataFingerprint]);
    const continuation = input.planning;
    const installedTargets = new Map(prepared.packages.map(pkg => [targetId(pkg.name, pkg.version), pkg]));
    if (continuation && (continuation.metadataFingerprint !== metadataFingerprint || continuation.pendingTargetIds.some(id => !installedTargets.has(id)))) {
      trace?.record('validation', 'rejected', { errorCode: 'stale_planning_cursor' });
      throw new AnalysisError('Planning continuation does not match these exact dependency files. Start a new full audit.', 409, 'stale_planning_cursor');
    }
    return execute(async boundedFetch => {
      const selectedIds = continuation?.pendingTargetIds.slice(0, planLimit);
      const selectedPackages = selectedIds?.map(id => installedTargets.get(id));
      const scanCursor = continuation ? undefined : input.scanning ? {
        packageOffset: input.scanning.packageOffset, advisoryOffset: input.scanning.advisoryOffset, batchFingerprint: input.scanning.batchFingerprint
      } : { packageOffset: 0, advisoryOffset: 0, batchFingerprint: null };
      const current = await snapshot(prepared, boundedFetch, selectedPackages, trace, scanCursor), checkResult = current.vulnerabilityCheck;
      const scanPage = !!(input.scanning || checkResult.scanning?.next);
      // Planning starts only after the client has retained the full inventory.
      if (scanPage) planLimit = 0;
      current.evidenceIdentity = metadataFingerprint;
      const grouped = new Map();
      for (const finding of [...checkResult.findings].sort((a, b) => rank(b.severity) - rank(a.severity) || key(a).localeCompare(key(b)))) {
        if (!grouped.has(key(finding))) grouped.set(key(finding), finding);
      }
      const targets = [...grouped.values()];
      const pendingIds = continuation?.pendingTargetIds || targets.map(finding => targetId(finding.package, finding.version));
      const attemptedIds = selectedIds || pendingIds.slice(0, planLimit);
      const remainingIds = pendingIds.filter(id => !attemptedIds.includes(id));
      const matchedIds = new Set(targets.map(finding => targetId(finding.package, finding.version)));
      const noLongerMatchedTargetIds = attemptedIds.filter(id => !matchedIds.has(id));
      const plans = [], blockers = [], rawPlans = [];
      for (const id of noLongerMatchedTargetIds) {
        const pkg = installedTargets.get(id);
        blockers.push({ targetId: id, package: pkg.name, version: pkg.version, status: 'needs_review',
          code: 'advisory_evidence_changed', category: 'analysis_incomplete', retryable: true,
          reason: 'The advisory provider no longer returned this target during planning. The original full scan must be retained; this is not evidence of a code fix.',
          nextAction: 'Refresh the full advisory scan and inspect changed or withdrawn advisory evidence before changing its status.' });
      }
      for (const finding of targets) {
        const id = targetId(finding.package, finding.version);
        if (!attemptedIds.includes(id)) {
          blockers.push({ targetId: id, package: finding.package, version: finding.version, status: 'not_planned',
            code: planLimit ? 'plan_limit' : 'not_requested', category: 'planning_deferred', retryable: true,
            reason: planLimit ? 'This response reached its planning limit. The advisory remains listed and can be planned in the next page.' : 'Upgrade planning was not requested.',
            nextAction: planLimit ? 'Continue with remediation.planning.next and retain this full advisory report.' : 'Request a positive planLimit to investigate a compatible remediation path.' });
          continue;
        }
        const planningStarted = now(); trace?.record('upgrade_planning', 'started', { counts: { planningTargets: 1 } });
        try {
          const upgrade = await plan(current, finding.package, finding.version, { fetchImpl: boundedFetch });
          rawPlans.push(upgrade);
          const routes = upgradeRoutes(upgrade), checked = routes.some(route => route.recommended);
          const status = upgrade.mitigation ? 'mitigation_proposed' : checked ? 'path_checked' : 'needs_review';
          plans.push({ id, targetId: id, package: finding.package, currentVersion: finding.version,
            proposedVersion: upgrade.targetVersion || null, status, compatibilityVerified: false,
            targetSelection: targetSelectionEvidence(upgrade), routes, evidence: upgrade,
            requiredReview: ['Inspect source/API migrations and advisory prerequisites.', 'Run original and candidate repository checks, then rescan the resolved tree.'] });
          const blocker = status !== 'path_checked' ? planningBlocker(upgrade, routes, 'The proposed mitigation or target still requires review and verification.') : null;
          if (blocker) blockers.push({ targetId: id, package: finding.package, version: finding.version, status, ...blocker });
          const traceCode = !blocker ? 'none' : ({ provider_failure: 'provider_failure', graph_truncated: 'graph_truncated',
            candidate_limit: 'analysis_incomplete', constraints_unknown: 'analysis_incomplete', peer_constraints: 'dependency_constraints',
            dependency_constraints: 'dependency_constraints', mitigation_requires_verification: 'verification_incomplete' })[blocker.code] || 'analysis_incomplete';
          trace?.record('upgrade_planning', status === 'path_checked' ? 'completed' : 'partial', { durationMs: Math.max(0, now() - planningStarted),
            errorCode: traceCode,
            counts: { plans: 1, blockers: status === 'path_checked' ? 0 : 1 } });
        } catch (error) {
          const failure = planningFailure(error);
          blockers.push({ targetId: id, package: finding.package, version: finding.version, status: 'blocked', ...failure });
          trace?.record('upgrade_planning', 'failed', { errorCode: failure.code === 'provider_failure' ? 'provider_failure' :
            failure.code === 'planning_budget_exhausted' ? 'planning_budget_exhausted' : 'analysis_incomplete',
            durationMs: Math.max(0, now() - planningStarted), counts: { blockers: 1 } });
        }
      }
      coordinateAuditPlans(plans, blockers);
      const findings = checkResult.findings.map(finding => {
        const pkg = prepared.packages.find(item => item.name === finding.package && item.version === finding.version);
        const remediation = plans.find(item => item.package === finding.package && item.currentVersion === finding.version);
        const blocker = blockers.find(item => item.package === finding.package && item.version === finding.version);
        return { id: fingerprint(['npm', finding.package, finding.version, finding.id]), advisoryId: finding.id,
          aliases: finding.advisory?.aliases || finding.cves || [], cves: finding.cves || [], severity: severity(finding.severity), providerSeverity: finding.severity,
          package: { ecosystem: 'npm', name: finding.package, installedVersion: finding.version, kind: finding.kind || pkg?.kind || 'unknown', lockfiles: pkg?.files || [] },
          summary: finding.summary, description: String(finding.advisory?.details || '').slice(0, 4000),
          impact: explainVulnerabilityImpact({ ...finding, kind: finding.kind || pkg?.kind || 'unknown' }),
          source: { provider: 'osv', id: finding.id, url: `https://osv.dev/vulnerability/${encodeURIComponent(finding.id)}`, references: finding.advisory?.references || [], cwes: finding.advisory?.cwes || [], modified: finding.advisory?.modified || null },
          affected: finding.advisory?.affected || [], advisoryListedFixedVersions: finding.fixedVersions || [],
          relevance: { status: 'needs_review', basis: 'locked_dependency_version_match', reason: 'Lockfile metadata cannot establish affected-function reachability, attacker-controlled input, deployed exposure or exploitability.' },
          verification: { status: 'advisory_match', confirmed: false },
          remediation: { targetId: targetId(finding.package, finding.version), status: remediation?.status || blocker?.status || 'not_planned', planId: remediation?.id || null, blocker: blocker?.reason || null } };
      });
      const coverage = { status: scanPage || continuation || prepared.warnings.length || checkResult.skippedPackages > 0 ? 'partial' : 'complete',
        ...(scanPage ? { advisoryScope: 'scan_page' } : {}),
        ...(continuation ? { planningOnly: true, advisoryScope: 'selected_planning_targets', checkedTargetIds: attemptedIds } : {}),
        checkedPackages: checkResult.checkedPackages ?? (selectedPackages || prepared.packages).length, skippedPackages: checkResult.skippedPackages || 0,
        lockfiles: current.files, packageManagers: [...new Set(current.files.map(file => file.endsWith('pnpm-lock.yaml') ? 'pnpm' : 'npm'))],
        warnings: prepared.warnings, sourceReachability: 'not_assessed', manifestsOnlySupported: false,
        limitations: ['Supported scope: npm v2/v3 and pnpm v6/v9 lockfiles.', 'Known advisory matches only; source reachability, repository tests and exploit reproduction are agent work.', 'Advisory-listed fixed versions are candidates, not automatically safe upgrade recommendations.',
          ...(continuation ? ['This is a planning continuation for selected packages, not a fresh full dependency scan. Retain and merge the original full audit.'] : [])] };
      const partialPlans = planLimit > 0 && blockers.length > 0;
      const planning = { schemaVersion: 'offense.planning.v1', scope: continuation ? 'planning_continuation' : 'full_audit',
        metadataFingerprint, totalTargets: pendingIds.length, attemptedTargetIds: attemptedIds, remainingTargetIds: remainingIds,
        noLongerMatchedTargetIds, hasMore: planLimit > 0 && remainingIds.length > 0,
        next: planLimit > 0 && remainingIds.length ? { metadataFingerprint, pendingTargetIds: remainingIds } : null,
        completedPages: 1, coordinationScope: 'this_response',
        note: 'An attempted or checked planning target is not a fixed or confirmed vulnerability. Failures retain concrete blockers and are not automatically retried.' };
      const report = { schemaVersion: AUDIT_SCHEMA_VERSION, capability: 'audit_dependencies', status: coverage.status === 'partial' || partialPlans ? 'partial' : 'complete',
        scannedAt: current.scannedAt, metadataFingerprint,
        ...(checkResult.scanning ? { scanning: { schemaVersion: 'offense.scanning.v1', metadataFingerprint,
          start: input.scanning || null, next: checkResult.scanning.next ? { metadataFingerprint, ...checkResult.scanning.next } : null,
          totalPackages: checkResult.scanning.totalPackages, completedPages: 1 } } : {}),
        providers: [{ id: 'osv', capability: 'known_vulnerabilities', checkedAt: checkResult.checkedAt || current.scannedAt }, ...(rawPlans.length ? [{ id: 'npm_registry', capability: 'upgrade_metadata' }] : [])],
        coverage, findings,
        summary: { ...auditSummaryCounts(findings, scanPage ? 'scan_page' : continuation ? 'planning_continuation' : 'full_audit'), critical: findings.filter(f => f.severity === 'critical').length, high: findings.filter(f => f.severity === 'high').length,
          affectedPackages: targets.length, checkedUpgradePaths: plans.filter(p => p.status === 'path_checked').length },
        remediation: { status: !planLimit ? 'not_requested' : partialPlans ? 'partial' : 'complete', plans, blockers, planning,
          verificationSteps: ['Confirm the checkout and dependency metadata still match this report.', 'Assess affected APIs and advisory prerequisites using source evidence; leave unknown applicability explicit.', 'Record passing original repository checks before changing dependencies.', 'Coordinate parent, peer, runtime and source migrations in an isolated candidate.', 'Run the same normal checks and a security-specific regression before and after; a setup error is not a reproduction. Rescan every final resolved package.', 'Record test-fixture changes, changed behavior and coverage, runtime floors, and independent checks of behavior replaced by mocks.', 'Return a reviewable patch with blockers. Compatibility checks alone do not confirm exploit remediation.'] } };
      report.remediation.agentPrompt = auditAgentPrompt(report);
      return report;
    });
  }
  const pruneTraces = (time = now()) => { try { return traceStore?.prune(time) || pruneOffenseTraceEvents(db, time); } catch { return { status: 'unavailable', removed: 0 }; } };
  if (!traceStore) pruneTraces();
  return { admit, legacy, audit, traces: traceStore, pruneTraces, usage };
}
