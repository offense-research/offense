import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyMapper, mapDependencies } from '../server/dependency-mapper.js';

test('dependency map links exact npm versions to the repository and keeps workspaces separate', async () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    '': { dependencies: { express: '^5.1.0' }, devDependencies: { vite: '^6.1.0' } },
    'node_modules/express': { version: '5.1.0' },
    'node_modules/vite': { version: '6.1.0', dev: true },
    'node_modules/@scope/transitive': { version: '2.0.0' }
  } });
  const mapped = mapDependencies([{ path: 'package-lock.json', content: lock }]);
  assert.deepEqual(mapped.packages.map(item => [item.name, item.version, item.kind, item.resolved]), [
    ['@scope/transitive', '2.0.0', 'transitive', true],
    ['express', '5.1.0', 'runtime', true],
    ['vite', '6.1.0', 'development', true]
  ]);
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'abc123', files: [{ path: 'package-lock.json', content: lock }], warnings: [] }) };
    const mapper = createDependencyMapper(db, github, async () => ({ source: 'OSV', status: 'complete', checkedAt: 1,
      checkedPackages: 3, skippedPackages: 0, findings: [] }));
    await mapper.scan('workspace-one', 'owner/repo', 123);
    assert.equal(mapper.snapshots('workspace-one')[0].packages.length, 3);
    assert.equal(mapper.snapshots('workspace-one')[0].vulnerabilityCheck.status, 'complete');
    await mapper.recheck('workspace-one', 'owner/repo', 123);
    assert.deepEqual(mapper.snapshots('workspace-two'), []);
  } finally { db.close(); }
});

test('manifest-only dependencies are marked as declared ranges', () => {
  const mapped = mapDependencies([{ path: 'package.json', content: JSON.stringify({ dependencies: { react: '^19.0.0' } }) }]);
  assert.deepEqual(mapped.packages, [{ name: 'react', version: '^19.0.0', kind: 'runtime', resolved: false, files: ['package.json'] }]);
});

test('an unavailable CVE database is shown as a failed check, not zero advisories', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'abc123', files: [{ path: 'package.json',
      content: JSON.stringify({ dependencies: { react: '^19.0.0' } }) }], warnings: [] }) };
    const mapper = createDependencyMapper(db, github, async () => { throw new Error('OSV unavailable'); }, undefined,
      { fetchImpl: async () => ({ ok: true, text: async () => JSON.stringify({ name: 'react', version: '19.0.0' }) }) });
    const snapshot = await mapper.scan('workspace-one', 'owner/repo', 123);
    assert.equal(snapshot.vulnerabilityCheck.status, 'failed');
    assert.equal(snapshot.vulnerabilityCheck.error, 'OSV unavailable');
    assert.equal(mapper.snapshots('workspace-one')[0].vulnerabilityCheck.status, 'failed');
  } finally { db.close(); }
});

test('upgrade paths persist across mapper restarts, are workspace scoped, and expire when advisories refresh', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'revision1', warnings: [], files: [{ path: 'package-lock.json', content: JSON.stringify({
      lockfileVersion: 3, packages: { '': { dependencies: { example: '^1.0.0' } }, 'node_modules/example': { version: '1.0.0' } }
    }) }] }) };
    let plans = 0, checks = 0;
    const check = async () => ({ status: 'complete', checkedAt: ++checks, findings: [] });
    const plan = async (snapshot, name, version) => { plans++; return { name, currentVersion: version, targetVersion: '1.2.0' }; };
    let mapper = createDependencyMapper(db, github, check, plan);
    await mapper.scan('a', 'org/api', 1);
    const first = await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    mapper = createDependencyMapper(db, github, check, plan);
    assert.deepEqual(await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0'), first);
    assert.equal(plans, 1);
    assert.equal(first.snapshotRevision, 'revision1');
    assert.equal(mapper.snapshots('a')[0].upgradePlans.length, 1);
    await assert.rejects(mapper.upgradePlan('b', 'org/api', 1, 'example', '1.0.0'), /Scan repository/);
    await mapper.recheck('a', 'org/api', 1);
    assert.equal(mapper.snapshots('a')[0].upgradePlans, undefined);
    await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    assert.equal(plans, 2);
    await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0', { force: true });
    assert.equal(plans, 3);
  } finally { db.close(); }
});

test('advisory content changing while a path is planned cannot receive stale cached results', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'revision1', warnings: [], files: [{ path: 'package-lock.json', content: JSON.stringify({
      lockfileVersion: 3, packages: { '': {}, 'node_modules/example': { version: '1.0.0' } }
    }) }] }) };
    let finish, checkedAt = 0;
    const mapper = createDependencyMapper(db, github, async () => ({ status: 'complete', checkedAt: ++checkedAt, findings: checkedAt > 1 ? [{ id: 'new', package: 'example', version: '1.0.0' }] : [] }),
      () => new Promise(resolve => { finish = resolve; }));
    await mapper.scan('a', 'org/api', 1);
    const pending = mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    await mapper.recheck('a', 'org/api', 1);
    finish({ name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0' });
    await assert.rejects(pending, /scan changed/);
    assert.equal(mapper.snapshots('a')[0].upgradePlans, undefined);
  } finally { db.close(); }
});

test('an unchanged advisory refresh during upgrade planning preserves content identity and the pinned plan evidence', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'revision1', warnings: [], files: [{ path: 'package-lock.json', content: JSON.stringify({
      lockfileVersion: 3, packages: { '': {}, 'node_modules/example': { version: '1.0.0' } }
    }) }] }) };
    let finish, checkedAt = 0;
    const mapper = createDependencyMapper(db, github, async () => ({ status: 'complete', checkedAt: ++checkedAt, findings: [] }),
      () => new Promise(resolve => { finish = resolve; }));
    const original = await mapper.scan('a', 'org/api', 1);
    const pending = mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    await mapper.recheck('a', 'org/api', 1);
    finish({ name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0' });
    const plan = await pending, latest = mapper.snapshots('a')[0];
    assert.equal(plan.evidenceIdentity, original.evidenceIdentity);
    assert.equal(latest.evidenceIdentity, original.evidenceIdentity);
    assert.equal(plan.advisoryCheckedAt, 1); assert.equal(latest.vulnerabilityCheck.checkedAt, 2);
    assert.equal(latest.upgradePlans[0].evidenceIdentity, original.evidenceIdentity);
  } finally { db.close(); }
});

test('legacy cached plans are replaced once with fully scoped content-bound plan evidence', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const github = { dependencyFiles: async () => ({ revision: 'revision1', warnings: [], files: [{ path: 'package-lock.json', content: JSON.stringify({
      lockfileVersion: 3, packages: { '': {}, 'node_modules/example': { version: '1.0.0' } }
    }) }] }) };
    let calls = 0;
    const mapper = createDependencyMapper(db, github, async () => ({ status: 'complete', checkedAt: 1, findings: [] }),
      async () => { calls++; return { name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0' }; });
    await mapper.scan('a', 'org/api', 1);
    const first = await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    const row = db.prepare('SELECT data FROM dependency_snapshots').get(), data = JSON.parse(row.data);
    for (const field of ['evidenceIdentity', 'repository', 'installationId', 'revision', 'scannedAt']) delete data.upgradePlans[0][field];
    db.prepare('UPDATE dependency_snapshots SET data = ?').run(JSON.stringify(data));
    const rebound = await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0');
    assert.equal(calls, 2); assert.equal(rebound.repository, 'org/api'); assert.equal(rebound.installationId, 1);
    assert.equal(rebound.evidenceIdentity, first.evidenceIdentity);
    assert.deepEqual(await mapper.upgradePlan('a', 'org/api', 1, 'example', '1.0.0'), rebound); assert.equal(calls, 2);
  } finally { db.close(); }
});

test('automatic sync detects commits, reuses unchanged scans/plans, and rechecks aged advisories', async () => {
  const db = new DatabaseSync(':memory:');
  let revision = 'first', reads = 0, checks = 0;
  const files = [{ path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: {
    '': { name: 'app', dependencies: { semver: '^7.5.1' } }, 'node_modules/semver': { version: '7.5.1' }
  } }) }];
  const mapper = createDependencyMapper(db, {
    dependencyRevision: async () => revision,
    dependencyFiles: async () => { reads++; return { revision, files, warnings: [] }; }
  }, async () => { checks++; return { status: 'complete', checkedAt: Date.now(), findings: [] }; },
  async () => ({ name: 'semver', currentVersion: '7.5.1', targetVersion: '7.5.2' }));
  try {
    await mapper.sync('workspace', 'org/repo', 123);
    const plan = await mapper.upgradePlan('workspace', 'org/repo', 123, 'semver', '7.5.1');
    const unchanged = await mapper.sync('workspace', 'org/repo', 123);
    assert.equal(reads, 1); assert.equal(checks, 1); assert.equal(unchanged.upgradePlans[0].plannedAt, plan.plannedAt);
    assert.ok(unchanged.lastSyncedAt); assert.equal(unchanged.scannedAt, plan.snapshotScannedAt);
    revision = 'second';
    const changed = await mapper.sync('workspace', 'org/repo', 123);
    assert.equal(changed.revision, 'second'); assert.equal(reads, 2); assert.equal(checks, 2); assert.equal(changed.upgradePlans, undefined);
    const row = db.prepare('SELECT data FROM dependency_snapshots').get(), data = JSON.parse(row.data);
    data.vulnerabilityCheck.checkedAt = Date.now() - 7 * 3600000;
    db.prepare('UPDATE dependency_snapshots SET data = ?').run(JSON.stringify(data));
    await mapper.sync('workspace', 'org/repo', 123);
    assert.equal(reads, 2); assert.equal(checks, 3);
    assert.deepEqual(mapper.snapshots('other-workspace'), []);
  } finally { db.close(); }
});

test('planner v2 caches cannot bypass the new peer and path coverage checks',async()=>{
  const db=new DatabaseSync(':memory:');try{
    const github={dependencyFiles:async()=>({revision:'revision1',warnings:[],files:[{path:'package-lock.json',content:JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/example':{version:'1.0.0'}}})}]})};let calls=0;
    const mapper=createDependencyMapper(db,github,async()=>({status:'complete',checkedAt:1,findings:[]}),async()=>{calls++;return{name:'example',currentVersion:'1.0.0',targetVersion:'1.0.1'};});
    await mapper.scan('ws','org/repo',1);const first=await mapper.upgradePlan('ws','org/repo',1,'example','1.0.0');assert.equal(first.plannerVersion,3);
    const row=db.prepare('SELECT data FROM dependency_snapshots').get(),data=JSON.parse(row.data);data.upgradePlans[0].plannerVersion=2;db.prepare('UPDATE dependency_snapshots SET data=?').run(JSON.stringify(data));
    const refreshed=await mapper.upgradePlan('ws','org/repo',1,'example','1.0.0');assert.equal(calls,2);assert.equal(refreshed.plannerVersion,3);
    await mapper.upgradePlan('ws','org/repo',1,'example','1.0.0');assert.equal(calls,2);
  }finally{db.close();}
});
