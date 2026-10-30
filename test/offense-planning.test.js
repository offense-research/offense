import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { coordinateAuditPlans, mergeAuditContinuation } from '../shared/offense-planning.js';

const files = [{ path: 'package-lock.json', content: { lockfileVersion: 3, packages: {
  '': { dependencies: { first: '^1.0.0', second: '^1.0.0', third: '^1.0.0' } },
  'node_modules/first': { version: '1.0.0' }, 'node_modules/second': { version: '1.0.0' }, 'node_modules/third': { version: '1.0.0' }
} } }];
const findings = ['first', 'second', 'third'].map((name, index) => ({ id: `GHSA-${name}`, package: name, version: '1.0.0',
  severity: index ? 'HIGH' : 'CRITICAL', cves: [index ? 'CVE-2026-10002' : 'CVE-2026-10001'], fixedVersions: ['1.0.1'], summary: name }));
const check = async packages => ({ status: 'complete', checkedPackages: packages.length, findings: findings.filter(finding => packages.some(pkg => pkg.name === finding.package && pkg.version === finding.version)) });
const plan = async (snapshot, name, version) => ({ name, currentVersion: version, targetVersion: '1.0.1',
  releases: ['1.0.0', '1.0.1'], steps: [], parentOptions: [], considered: [{ version: '1.0.1', advisories: 0 }], impact: { paths: [['application', name]], parents: [] } });
function fixture(t, overrides = {}) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  return createDependencyIntelligence({ db, check, plan, ...overrides });
}

test('bounded planning continues exact targets without repeating plans or whole-tree advisory scans', async t => {
  const checked = [], planned = [];
  const intelligence = fixture(t, { check: async packages => { checked.push(packages.map(pkg => pkg.name)); return check(packages); },
    plan: async (...args) => { planned.push(args[1]); return plan(...args); } });
  const original = await intelligence.audit({ files, planLimit: 1 });
  assert.equal(original.findings.length, 3); assert.equal(original.remediation.plans[0].package, 'first');
  assert.equal(original.remediation.planning.remainingTargetIds.length, 2);
  assert.ok(original.remediation.blockers.every(blocker => blocker.code === 'plan_limit' && blocker.category === 'planning_deferred'));
  const second = await intelligence.audit({ files, planLimit: 1, planning: original.remediation.planning.next });
  assert.equal(second.coverage.planningOnly, true); assert.equal(second.coverage.status, 'partial'); assert.equal(second.findings.length, 1);
  const combined = mergeAuditContinuation(original, second);
  const third = await intelligence.audit({ files, planLimit: 1, planning: combined.remediation.planning.next });
  const final = mergeAuditContinuation(combined, third);
  assert.deepEqual(checked.map(value => value.length), [3, 1, 1]);
  assert.deepEqual(planned, ['first', 'second', 'third']);
  assert.equal(final.status, 'complete'); assert.equal(final.remediation.status, 'complete');
  assert.equal(final.remediation.planning.next, null); assert.equal(final.remediation.planning.completedPages, 3);
  assert.equal(final.remediation.blockers.length, 0); assert.equal(final.summary.checkedUpgradePaths, 3);
  assert.equal(final.coverage.planningOnly, undefined); assert.equal(final.coverage.checkedPackages, 3);
  assert.equal(final.scannedAt, original.scannedAt); assert.equal(final.findings.length, original.findings.length);
  for (const finding of final.findings) assert.equal(finding.remediation.status, 'path_checked');
  assert.equal(original.remediation.plans.length, 1, 'merging does not mutate previous saved evidence');
  for (const finding of findings) assert.ok(final.remediation.agentPrompt.includes(finding.id));
  assert.ok(final.remediation.agentPrompt.includes('security-specific regression'));
});

test('continuation rejects changed metadata, unknown/duplicate IDs and non-progressing requests before providers run', async t => {
  let checks = 0;
  const intelligence = fixture(t, { check: async packages => { checks++; return check(packages); } });
  const original = await intelligence.audit({ files, planLimit: 1 });
  const next = original.remediation.planning.next;
  const changed = structuredClone(files); changed[0].content.packages['node_modules/first'].version = '1.0.2';
  for (const input of [
    { files: changed, planning: next }, { files, planning: { ...next, metadataFingerprint: 'a'.repeat(64) } },
    { files, planning: { ...next, pendingTargetIds: ['0'.repeat(64)] } },
    { files, planning: { ...next, pendingTargetIds: [next.pendingTargetIds[0], next.pendingTargetIds[0]] } },
    { files, planning: { ...next, pendingTargetIds: [] } }, { files, planning: next, planLimit: 0 },
    { files, planning: { ...next, token: 'never accepted' } }
  ]) await assert.rejects(() => intelligence.audit(input), /continuation|match|unique/i);
  assert.equal(checks, 1);
});

test('fingerprint-scoped target IDs remain stable for identical metadata and change on a dependency change', async t => {
  const intelligence = fixture(t);
  const a = await intelligence.audit({ files, planLimit: 1 });
  const b = await intelligence.audit({ files, planLimit: 1 });
  const changed = structuredClone(files); changed[0].content.packages['node_modules/unrelated'] = { version: '1.0.0' };
  const c = await intelligence.audit({ files: changed, planLimit: 1 });
  assert.equal(a.remediation.plans[0].targetId, b.remediation.plans[0].targetId);
  assert.notEqual(a.remediation.plans[0].targetId, c.remediation.plans[0].targetId);
  assert.equal(a.findings[0].id, c.findings[0].id, 'advisory identity remains stable while the planning snapshot changes');
});

test('operational failures, graph truncation, deferred work and incompatible parents have different next actions', async t => {
  const intelligence = fixture(t, { plan: async (...args) => {
    if (args[1] === 'first') throw Error('npm registry returned HTTP 503');
    const value = await plan(...args);
    if (args[1] === 'second') value.impact.truncated = true;
    else value.impact.parents = [{ name: 'parent', version: '1.0.0', compatible: false }];
    return value;
  } });
  const report = await intelligence.audit({ files, planLimit: 3 });
  const codes = new Map(report.remediation.blockers.map(blocker => [blocker.package, blocker]));
  assert.equal(codes.get('first').code, 'provider_failure'); assert.equal(codes.get('first').category, 'operational'); assert.equal(codes.get('first').retryable, true);
  assert.equal(codes.get('second').code, 'graph_truncated'); assert.match(codes.get('second').nextAction, /not proof.*incompatible/);
  assert.equal(codes.get('third').code, 'dependency_constraints'); assert.match(codes.get('third').nextAction, /parent releases/);
  assert.equal(report.remediation.planning.hasMore, false); assert.equal(report.status, 'partial');
});

test('failed planning target is retained once and does not prevent independent continuation', async t => {
  const intelligence = fixture(t, { plan: async (...args) => { if (args[1] === 'first') throw Error('Hosted analysis reached its request/time budget.'); return plan(...args); } });
  const original = await intelligence.audit({ files, planLimit: 1 });
  const page = await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next });
  const combined = mergeAuditContinuation(original, page);
  assert.equal(combined.remediation.plans.length, 2); assert.equal(combined.remediation.blockers.length, 1);
  assert.equal(combined.remediation.blockers[0].code, 'planning_budget_exhausted');
  assert.equal(combined.findings.find(finding => finding.package.name === 'first').remediation.status, 'blocked');
  assert.equal(combined.remediation.planning.hasMore, false); assert.equal(combined.status, 'partial');
});

test('shared-parent conflicts discovered on separate pages invalidate both combined routes', async t => {
  const intelligence = fixture(t, { plan: async (...args) => ({ ...await plan(...args),
    impact: { paths: [], parents: [{ name: 'shared-parent', version: '1.0.0', compatible: false }] },
    parentOptions: [{ parent: 'shared-parent', currentVersion: '1.0.0', version: args[1] === 'first' ? '2.0.0' : '3.0.0', upstream: [] }] }) });
  const original = await intelligence.audit({ files, planLimit: 1 });
  const page = await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next });
  const combined = mergeAuditContinuation(original, page);
  assert.equal(original.remediation.plans[0].status, 'path_checked');
  assert.equal(combined.summary.checkedUpgradePaths, 0);
  assert.ok(combined.remediation.plans.every(item => item.status === 'needs_review' && item.routes.every(route => !route.recommended)));
  assert.equal(combined.remediation.blockers.filter(item => item.code === 'coordinated_target_conflict').length, 3);
  assert.match(combined.remediation.agentPrompt, /Coordinated targets disagree/);
});

test('conflicting root declaration targets cannot be advertised as one coordinated upgrade', () => {
  const plans = ['first', 'second'].map((name, i) => ({ targetId: name, package: name, currentVersion: '1.0.0', status: 'path_checked',
    evidence: {}, routes: [{ recommended: true, blockers: [], changes: [{ name, currentVersion: '1.0.0', targetVersion: '1.0.1' }],
      rootUpdates: [{ file: 'pnpm-lock.yaml', workspace: 'app', name: 'shared', targetVersion: `${i + 2}.0.0` }] }] }));
  const { blockers } = coordinateAuditPlans(plans);
  assert.equal(blockers.length, 2); assert.ok(plans.every(item => item.status === 'needs_review'));
  assert.ok(blockers.every(item => item.code === 'coordinated_target_conflict'));
});

test('provider evidence changes during planning preserve original counts and require a fresh full scan', async t => {
  let change = false;
  const intelligence = fixture(t, { check: async packages => {
    const result = await check(packages);
    if (change) result.findings = result.findings.map(finding => ({ ...finding, id: finding.id + '-changed' }));
    return result;
  } });
  const original = await intelligence.audit({ files, planLimit: 1 }); change = true;
  const page = await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next });
  const combined = mergeAuditContinuation(original, page);
  assert.equal(combined.findings.length, original.findings.length);
  assert.equal(combined.summary.advisoryMatches, original.summary.advisoryMatches);
  assert.equal(combined.remediation.planning.changedAdvisoryEvidence.length, 2);
  assert.ok(combined.remediation.blockers.every(item => item.code === 'advisory_evidence_changed'));
  assert.equal(combined.status, 'partial');
});

test('no-longer-matching target is not credited as a fixed vulnerability', async t => {
  let clean = false;
  const intelligence = fixture(t, { check: async packages => clean ? { status: 'complete', checkedPackages: packages.length, findings: [] } : check(packages) });
  const original = await intelligence.audit({ files, planLimit: 1 }); clean = true;
  const page = await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next });
  const combined = mergeAuditContinuation(original, page);
  assert.equal(combined.findings.length, 3); assert.equal(combined.summary.confirmedVulnerabilities, 0);
  assert.equal(combined.remediation.planning.noLongerMatchedTargetIds.length, 2);
  assert.equal(combined.remediation.blockers.filter(item => item.code === 'advisory_evidence_changed').length, 2);
  assert.equal(combined.status, 'partial');
});

test('malformed or non-progressing pages never overwrite previously successful planning', async t => {
  const intelligence = fixture(t);
  const original = await intelligence.audit({ files, planLimit: 1 });
  const page = await intelligence.audit({ files, planLimit: 1, planning: original.remediation.planning.next });
  const mutations = [
    value => { value.metadataFingerprint = 'a'.repeat(64); },
    value => { value.remediation.planning.attemptedTargetIds = []; },
    value => { value.remediation.planning.remainingTargetIds = []; },
    value => { value.remediation.planning.next.pendingTargetIds = []; },
    value => { value.remediation.plans[0].package = 'unrelated'; },
    value => { value.findings[0].package.name = 'unrelated'; }
  ];
  for (const mutate of mutations) { const corrupted = structuredClone(page); mutate(corrupted); assert.throws(() => mergeAuditContinuation(original, corrupted), /continuation|Continuation/); }
  assert.equal(original.remediation.plans.length, 1); assert.equal(original.remediation.planning.remainingTargetIds.length, 2);
});

test('counts distinguish advisory IDs, CVE aliases, package versions and affected lockfile locations without discovery credit', async t => {
  const intelligence = fixture(t);
  const original = await intelligence.audit({ files, planLimit: 1 });
  const final = mergeAuditContinuation(original, await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next }));
  assert.equal(final.summary.advisoryMatches, 3); assert.equal(final.summary.distinctAdvisoryIds, 3); assert.equal(final.summary.distinctCves, 2);
  assert.equal(final.summary.affectedPackageVersions, 3); assert.equal(final.summary.affectedLockfiles, 1); assert.equal(final.summary.affectedPackageLockfileLocations, 3);
  assert.equal(final.summary.provenance.scope, 'full_audit'); assert.equal(final.summary.provenance.discoveredNewVulnerabilities, false);
  assert.equal(final.summary.provenance.exploitReproduced, false); assert.equal(final.summary.provenance.pullRequestsCreated, false);
  assert.equal(final.summary.confirmedVulnerabilities, 0);
});

test('selected target rationale records rejected advisory-bearing releases instead of recommending the first fixed version', async t => {
  const intelligence = fixture(t, { plan: async (...args) => ({ ...await plan(...args), targetVersion: '2.0.0',
    considered: [{ version: '1.0.1', advisories: 2, advisoryIds: ['GHSA-still-bad'] }, { version: '2.0.0', advisories: 0 }],
    targetSelection: { policy: 'Prefer the smallest checked clean compatible target.' } }) });
  const report = await intelligence.audit({ files, planLimit: 1 });
  const selection = report.remediation.plans[0].targetSelection;
  assert.equal(selection.chosenVersion, '2.0.0'); assert.equal(selection.rejectedCandidates[0].version, '1.0.1');
  assert.deepEqual(selection.rejectedCandidates[0].advisoryIds, ['GHSA-still-bad']); assert.equal(selection.compatibilityVerified, false);
  assert.match(report.remediation.agentPrompt, /retained advisory matches/);
});

test('merging complete plans preserves local coverage gaps from the original helper report', async t => {
  const intelligence = fixture(t);
  const original = await intelligence.audit({ files, planLimit: 1 });
  original.clientCoverage = { warnings: ['requirements.txt: unsupported Python ecosystem; not scanned.'] };
  original.status = 'partial';
  const combined = mergeAuditContinuation(original, await intelligence.audit({ files, planLimit: 2, planning: original.remediation.planning.next }));
  assert.equal(combined.remediation.status, 'complete'); assert.equal(combined.status, 'partial');
  assert.deepEqual(combined.clientCoverage.warnings, original.clientCoverage.warnings);
});
