import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { EventEmitter, once } from 'node:events';
import { mkdtemp, readFile, writeFile, lstat, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { portExposureScope, scanPortExposure } from '../scripts/port-exposure.mjs';
import { createOffenseCli } from '../scripts/offense-cli.mjs';

async function listener(t, host = '127.0.0.1') {
  let connections = 0, bytes = 0;
  const server = createServer(socket => {
    connections++;
    socket.on('data', data => { bytes += data.length; });
    socket.on('error', () => {});
  });
  server.listen(0, host); await once(server, 'listening');
  t.after(() => server.listening ? new Promise(resolve => server.close(resolve)) : undefined);
  return { port: server.address().port, server, connections: () => connections, bytes: () => bytes };
}

test('explicit port scope accepts boundary ports and rejects ambiguous or expanded targets', () => {
  const base = { target: '127.0.0.1', ports: '65535,1', expectedPorts: '1' };
  assert.deepEqual(portExposureScope(base).ports, [1, 65535]);
  assert.deepEqual(portExposureScope(base).expectedPorts, [1]);
  assert.equal(portExposureScope({ ...base, target: '0:0:0:0:0:0:0:1' }).target, '::1');
  assert.equal(portExposureScope({ ...base, target: '10.2.3.4' }).family, 4);
  const ports = Array.from({ length: 256 }, (_, i) => i + 1).join(',');
  assert.equal(portExposureScope({ ...base, ports }).ports.length, 256);
  for (const target of [undefined, 'localhost', '127.0.0.1/32', '127.0.0.1,127.0.0.2', 'http://127.0.0.1',
    '127.1', '0.0.0.0', '224.1.2.3', '255.255.255.255', '169.254.169.254', '::', 'ff02::1', 'fe80::1', 'fe80::1%eth0', '::ffff:127.0.0.1']) {
    assert.throws(() => portExposureScope({ ...base, target }), /literal|not supported/);
  }
  for (const invalid of [undefined, '', '0', '65536', '22-80', '22, 80', '22,22', '1.5', '01', ports + ',257']) {
    assert.throws(() => portExposureScope({ ...base, ports: invalid }), /ports/);
  }
  assert.throws(() => portExposureScope({ ...base, expectedPorts: '443' }), /within/);
});

test('TCP observations distinguish reachability from policy and never send application bytes', async t => {
  const first = await listener(t), second = await listener(t), closed = await listener(t);
  await new Promise(resolve => closed.server.close(resolve));
  const options = { target: '127.0.0.1', ports: [first.port, closed.port, second.port].join(','), expectedPorts: String(first.port) };
  const report = await scanPortExposure(options);
  assert.equal(report.status, 'complete'); assert.equal(report.policyStatus, 'violations');
  assert.deepEqual(report.summary, { selectedPorts: 3, attemptedPorts: 3, reachablePorts: 2, refusedPorts: 1, unknownPorts: 0,
    unexpectedPorts: 1, confirmedVulnerabilities: 0 });
  assert.equal(report.observations.find(item => item.port === closed.port).state, 'refused');
  assert.equal(report.observations.find(item => item.port === first.port).sourceAddress, '127.0.0.1');
  assert.deepEqual(report.findings.map(finding => finding.port), [second.port]);
  assert.equal(report.findings[0].severity, 'unknown'); assert.equal(report.findings[0].exploitability, 'not_tested');
  assert.ok(report.findings[0].unknowns.length); assert.match(report.findings[0].recommendedFix, /firewall/);
  const noPolicy = await scanPortExposure({ target: '127.0.0.1', ports: String(first.port) });
  assert.equal(noPolicy.policyStatus, 'not_provided'); assert.equal(noPolicy.findings.length, 0);
  const allowed = await scanPortExposure({ ...options, expectedPorts: options.ports });
  assert.equal(allowed.policyStatus, 'matched'); assert.equal(allowed.findings.length, 0);
  assert.equal(first.bytes() + second.bytes(), 0);
});

test('IPv6 loopback is scanned as a single literal target', async t => {
  let fixture;
  try { fixture = await listener(t, '::1'); }
  catch (error) {
    if (['EAFNOSUPPORT', 'EADDRNOTAVAIL'].includes(error.code)) { t.skip('IPv6 loopback unavailable'); return; }
    throw error;
  }
  const report = await scanPortExposure({ target: '::1', ports: String(fixture.port), expectedPorts: 'none' });
  assert.equal(report.scope.family, 6); assert.equal(report.summary.reachablePorts, 1);
  assert.equal(report.observations[0].sourceAddress, '::1'); assert.equal(report.policyStatus, 'violations');
});

test('timeouts and network errors remain unknown, not refused or policy success', async () => {
  const connect = ({ port }) => {
    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.setTimeout = (_ms, timeout) => queueMicrotask(() => port === 22 ? timeout() : socket.emit('error', { code: 'ENETUNREACH' }));
    return socket;
  };
  const report = await scanPortExposure({ target: '127.0.0.1', ports: '22,443', expectedPorts: 'none' }, { connect });
  assert.equal(report.status, 'partial'); assert.equal(report.policyStatus, 'unknown');
  assert.equal(report.summary.unknownPorts, 2); assert.equal(report.summary.refusedPorts, 0); assert.deepEqual(report.findings, []);
  assert.deepEqual(report.observations.map(item => [item.state, item.reason]), [['unknown', 'timeout'], ['unknown', 'connection_error']]);
});

test('cancellation preserves completed evidence and marks unattempted ports unknown', async () => {
  const controller = new AbortController();
  const connect = () => {
    const socket = new EventEmitter();
    socket.destroy = () => {}; socket.setTimeout = () => {};
    queueMicrotask(() => { socket.emit('connect'); controller.abort(); });
    return socket;
  };
  const report = await scanPortExposure({ target: '127.0.0.1', ports: '22,80,443', expectedPorts: '22' }, { connect, signal: controller.signal });
  assert.equal(report.status, 'partial'); assert.equal(report.stopReason, 'cancelled');
  assert.equal(report.summary.attemptedPorts, 1); assert.equal(report.summary.reachablePorts, 1);
  assert.equal(report.summary.unknownPorts, 2); assert.equal(report.policyStatus, 'unknown');
  assert.deepEqual(report.observations.slice(1).map(item => item.reason), ['not_attempted', 'not_attempted']);
});

test('CLI requires active authorization and preserves private reports without hosted configuration', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-ports-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stdout = [], stderr = [], fixture = await listener(t);
  // A malformed credential config must neither block this local command nor be read.
  await writeFile(path.join(directory, 'config.json'), 'not-json', { mode: 0o600 });
  const cli = createOffenseCli({ env: { OFFENSE_CONFIG_DIR: directory, OFFENSE_API_URL: 'invalid' },
    output: text => stdout.push(text), diagnostic: text => stderr.push(text),
    fetchImpl: () => { throw Error('No hosted requests allowed'); } });
  const output = path.join(directory, 'scan'), filename = path.join(output, 'port-exposure.json');
  const args = ['ports', 'scan', '--target', '127.0.0.1', '--ports', String(fixture.port), '--expected-ports', 'none', '--output', output];
  assert.equal(await cli.run(args), 0); assert.equal(JSON.parse(stdout.at(-1)).status, 'preview');
  assert.equal(await cli.run([...args, '--confirm-active-testing']), 0);
  assert.equal(await cli.run([...args, '--run']), 1);
  assert.equal(await cli.run([...args, '--run', '--preview', '--confirm-active-testing']), 1);
  assert.equal(await cli.run([...args, '--endpoint', 'https://offense.sh']), 1);
  assert.equal(fixture.connections(), 0); await assert.rejects(lstat(output), { code: 'ENOENT' });
  const run = [...args, '--run', '--confirm-active-testing'];
  assert.equal(await cli.run(run), 2);
  const saved = await readFile(filename, 'utf8');
  assert.equal(JSON.parse(saved).summary.unexpectedPorts, 1);
  assert.equal((await lstat(filename)).mode & 0o777, 0o600);
  assert.equal((await lstat(output)).mode & 0o777, 0o700);
  assert.equal(await cli.run(run), 1); assert.equal(await readFile(filename, 'utf8'), saved);
  assert.equal(fixture.connections(), 1);
  const linked = path.join(directory, 'linked'); await symlink(output, linked);
  assert.equal(await cli.run([...run.slice(0, -4), '--output', linked, '--run', '--confirm-active-testing']), 1);
  assert.equal(fixture.connections(), 1);
  const matched = ['ports', 'scan', '--target', '127.0.0.1', '--ports', String(fixture.port), '--expected-ports', String(fixture.port),
    '--output', path.join(directory, 'matched'), '--run', '--confirm-active-testing'];
  assert.equal(await cli.run(matched), 0); assert.equal(JSON.parse(stdout.at(-1)).policyStatus, 'matched');
});
