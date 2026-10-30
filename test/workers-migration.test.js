import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { exportD1, TABLES } from '../scripts/export-d1.mjs';
import { createSkillUsageStore } from '../server/skill-usage.js';
import { createCliAuth } from '../server/cli-auth.js';

test('D1 migration schema and private export preserve existing workspace data', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'purple-d1-test-'));
  try {
    const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0002_hosted_scans.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0003_scan_metering.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0006_scan_usage.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0007_dependency_automation.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0008_skill_usage.sql', import.meta.url), 'utf8') + readFileSync(new URL('../migrations/0009_cli_auth.sql', import.meta.url), 'utf8');
    const sourcePath = path.join(dir, 'source.sqlite');
    const source = new DatabaseSync(sourcePath);
    source.exec(schema);
    source.prepare('INSERT INTO users VALUES (?, ?, ?, ?)').run('u1', '123', "owner's-login", 10);
    source.prepare('INSERT INTO workspaces VALUES (?, ?, ?, ?)').run('w1', JSON.stringify({ openrouter: { secret: 'encrypted-value' } }), 10, 10);
    source.prepare('INSERT INTO memberships VALUES (?, ?, ?)').run('u1', 'w1', 'owner');
    source.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run('s1', JSON.stringify({ userId: 'u1', workspaceId: 'w1' }), 10);
    source.prepare('INSERT INTO scan_keys VALUES (?, ?, ?, ?, ?, NULL)').run('k1', 'w1', 'u1', 'hashed-key', 10);
    source.prepare('INSERT INTO scan_sources VALUES (?, ?, ?)').run('scan1', 'app.js', 'encrypted-source');
    source.prepare('INSERT INTO scan_wallet_entries VALUES (?, ?, ?, ?, ?)').run('purchase:test', 'w1', 5_000_000, 'purchase', 10);
    source.prepare('INSERT INTO scan_usage_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run('scan1', 'w1', 10, 20, 100, 'completed', 1024, 1, 1, 10, 80, 90, 0, null, null);
    source.prepare('INSERT INTO scan_usage_tools VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run('scan1', 'checkov', 'complete', 50, 0, 0, 0, 0, 0, 0);
    source.prepare('INSERT INTO scan_usage_activity VALUES(?,?,?,?,?)').run('2026-10-26', 'w1', 'checkov', 'quote_issued', 2);
    source.prepare('INSERT INTO scan_usage_meta VALUES(?,?)').run('tracking_started_at', 10);
    source.prepare('INSERT INTO dependency_monitor VALUES(?,?,?,?,?,?)').run('w1', 'owner/repo', 1, 10, 20, 'watching');
    source.prepare('INSERT INTO dependency_automation_policies VALUES(?,?,?,?,?)')
      .run('w1', 'owner/repo', 1, JSON.stringify({ enabled: false, schedule: 'daily' }), 10);
    source.prepare('INSERT INTO dependency_automation_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run('auto1', 'w1', 'owner/repo', 1, 'scheduled', 'completed', 10, 20, 10, 'revision', 2, 'complete', null);
    const skillUsage = createSkillUsageStore({ db: source, now: () => 100 });
    skillUsage.start({ channel: 'mcp', operation: 'audit' }).finish({ status: 'completed', checkedPackages: 2, advisoryMatches: 1, severity: { high: 1 } });
    const auth = createCliAuth({db:source,scans:{issueKey(){throw Error('Not issued during backup test');}},baseUrl:'https://offense.sh',now:()=>100});
    auth.start({source:'backup-fixture'});
    source.close();

    const exported = await exportD1(sourcePath, path.join(dir, 'private-export'));
    assert.equal(exported.counts.users, 1);
    assert.equal(exported.counts.workspaces, 1);
    assert.equal(exported.counts.sessions, 1);
    assert.equal(Object.keys(exported.counts).length, TABLES.length);
    assert.equal(exported.counts.scan_usage_jobs, 1);
    assert.equal(exported.counts.cli_auth_devices, 1);
    assert.ok(exported.counts.cli_auth_limits > 0);
    assert.equal(exported.counts.skill_usage_days, 1);
    assert.equal(exported.counts.skill_usage_meta, 1);
    assert.equal(exported.counts.scan_usage_tools, 1);
    assert.equal(exported.counts.dependency_monitor, 1);
    assert.equal(exported.counts.dependency_automation_policies, 1);
    assert.equal(exported.counts.dependency_automation_runs, 1);
    assert.equal(statSync(exported.snapshot).mode & 0o077, 0);
    assert.equal(statSync(exported.dataSql).mode & 0o077, 0);

    const restored = new DatabaseSync(':memory:');
    restored.exec(schema);
    restored.exec(readFileSync(exported.dataSql, 'utf8'));
    assert.equal(restored.prepare('SELECT login FROM users WHERE id = ?').get('u1').login, "owner's-login");
    assert.equal(JSON.parse(restored.prepare('SELECT data FROM workspaces WHERE id = ?').get('w1').data).openrouter.secret, 'encrypted-value');
    assert.deepEqual({ ...restored.prepare('SELECT user_id, workspace_id FROM memberships').get() }, { user_id: 'u1', workspace_id: 'w1' });
    assert.equal(restored.prepare('SELECT token_hash FROM scan_keys').get().token_hash, 'hashed-key');
    assert.equal(restored.prepare('SELECT content FROM scan_sources').get().content, 'encrypted-source');
    assert.equal(restored.prepare('SELECT amount_micros FROM scan_wallet_entries').get().amount_micros, 5_000_000);
    assert.equal(restored.prepare('SELECT container_ms FROM scan_usage_jobs').get().container_ms, 90);
    assert.equal(restored.prepare('SELECT duration_ms FROM scan_usage_tools').get().duration_ms, 50);
    assert.equal(restored.prepare('SELECT count FROM scan_usage_activity').get().count, 2);
    assert.equal(restored.prepare('SELECT value FROM scan_usage_meta').get().value, 10);
    assert.equal(restored.prepare('SELECT attempted_at FROM dependency_monitor').get().attempted_at, 10);
    assert.equal(JSON.parse(restored.prepare('SELECT policy_json FROM dependency_automation_policies').get().policy_json).enabled, false);
    assert.equal(restored.prepare('SELECT advisory_matches FROM dependency_automation_runs').get().advisory_matches, 2);
    assert.equal(restored.prepare('SELECT advisory_matches FROM skill_usage_days').get().advisory_matches, 1);
    assert.equal(restored.prepare("SELECT value FROM skill_usage_meta WHERE key = 'tracking_started_at'").get().value, 100);
    assert.match(restored.prepare('SELECT device_hash FROM cli_auth_devices').get().device_hash, /^[a-f0-9]{64}$/);
    assert.equal(restored.prepare('SELECT status FROM cli_auth_devices').get().status, 'pending');
    restored.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
