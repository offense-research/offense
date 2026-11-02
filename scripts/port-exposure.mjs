import { createConnection, isIP } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const limits = Object.freeze({ maxPorts: 256, concurrency: 8, startsPerSecond: 10, connectTimeoutMs: 2000, budgetMs: 120000 });

export function portExposureScope({ target, ports, expectedPorts } = {}) {
  const family = typeof target === 'string' && isIP(target);
  if (!family || target.includes('%')) throw Error('Choose one literal IPv4 or IPv6 address; hostnames, CIDRs and interface zones are not supported.');
  const address = family === 6 ? new URL(`http://[${target}]`).hostname.slice(1, -1) : target;
  const octets = address.split('.').map(Number);
  if (family === 4 && (octets[0] === 0 || octets[0] >= 224 || octets[0] === 169 && octets[1] === 254) ||
      family === 6 && (address === '::' || address.startsWith('ff') || /^fe[89ab]/.test(address) || address.startsWith('::ffff:'))) {
    throw Error('Unspecified, multicast, link-local and IPv4-mapped IPv6 targets are not supported.');
  }
  const parse = value => {
    if (typeof value !== 'string' || value.length > 1535 || !/^[1-9]\d{0,4}(?:,[1-9]\d{0,4})*$/.test(value)) {
      throw Error('Supply comma-separated TCP ports from 1 to 65535, without ranges, spaces or duplicates.');
    }
    const parsed = value.split(',').map(Number);
    if (parsed.length > limits.maxPorts || parsed.some(port => port > 65535) || new Set(parsed).size !== parsed.length) {
      throw Error('Choose at most 256 unique TCP ports from 1 to 65535.');
    }
    return parsed.sort((a, b) => a - b);
  };
  const selected = parse(ports), expected = expectedPorts === undefined ? null : expectedPorts === 'none' ? [] : parse(expectedPorts);
  if (expected?.some(port => !selected.includes(port))) throw Error('Expected ports must be within the selected scan ports; use none to expect no reachable ports.');
  return { target: address, family, protocol: 'tcp', ports: selected, expectedPorts: expected, limits,
    vantagePoint: 'This machine and its current network route; not necessarily the public internet.',
    authorization: 'Only scan an address and ports you own or have explicit permission to test. IP selection is not proof of ownership.',
    access: 'TCP connect and immediate disconnect only. No DNS, banners, application payloads, UDP, raw packets or exploitation.',
    privacy: 'Local private report; no Offense API, credentials, upload or charge.' };
}

export async function scanPortExposure(options, { signal, connect = createConnection } = {}) {
  const scope = portExposureScope(options);
  const startedAt = new Date().toISOString();
  const deadline = AbortSignal.timeout(limits.budgetMs);
  const stop = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const observations = scope.ports.map(port => ({ port, state: 'unknown', reason: 'not_attempted' }));
  function probe(port) {
    return new Promise(resolve => {
      let socket, finished = false;
      const finish = (state, reason) => {
        if (finished) return;
        const sourceAddress = socket?.localAddress || null;
        finished = true; stop.removeEventListener('abort', abort); socket?.destroy();
        resolve({ port, state, reason, sourceAddress });
      };
      const abort = () => finish('unknown', deadline.aborted ? 'deadline' : 'cancelled');
      if (stop.aborted) { abort(); return; }
      stop.addEventListener('abort', abort, { once: true });
      try {
        socket = connect({ host: scope.target, port, family: scope.family, autoSelectFamily: false });
        socket.once('connect', () => finish('reachable', 'tcp_connection_established'));
        socket.once('error', error => finish(error.code === 'ECONNREFUSED' ? 'refused' : 'unknown',
          error.code === 'ECONNREFUSED' ? 'connection_refused' : error.code === 'ETIMEDOUT' ? 'timeout' : 'connection_error'));
        socket.setTimeout(limits.connectTimeoutMs, () => finish('unknown', 'timeout'));
      } catch { finish('unknown', 'connection_error'); }
    });
  }
  const active = new Set();
  let nextStart = 0;
  for (let index = 0; index < observations.length && !stop.aborted; index++) {
    if (active.size >= limits.concurrency) await Promise.race(active);
    if (stop.aborted) break;
    try { await delay(Math.max(0, Math.ceil(nextStart - performance.now())), undefined, { signal: stop }); }
    catch { break; }
    if (stop.aborted) break;
    nextStart = performance.now() + 1000 / limits.startsPerSecond;
    const task = probe(observations[index].port).then(result => { observations[index] = result; }).finally(() => active.delete(task));
    active.add(task);
  }
  await Promise.all(active);
  const unexpected = observations.filter(item => item.state === 'reachable' && scope.expectedPorts !== null && !scope.expectedPorts.includes(item.port));
  const unknown = observations.filter(item => item.state === 'unknown').length;
  return { schemaVersion: 'offense.port-exposure.v1', status: unknown ? 'partial' : 'complete', startedAt,
    completedAt: new Date().toISOString(), scope, observations,
    stopReason: deadline.aborted ? 'deadline' : signal?.aborted ? 'cancelled' : 'finished',
    summary: { selectedPorts: observations.length, attemptedPorts: observations.filter(item => item.reason !== 'not_attempted').length,
      reachablePorts: observations.filter(item => item.state === 'reachable').length,
      refusedPorts: observations.filter(item => item.state === 'refused').length, unknownPorts: unknown,
      unexpectedPorts: unexpected.length, confirmedVulnerabilities: 0 },
    policyStatus: scope.expectedPorts === null ? 'not_provided' : unexpected.length ? 'violations' : unknown ? 'unknown' : 'matched',
    findings: unexpected.map(item => ({ id: `unexpected-tcp-${item.port}`, port: item.port, type: 'unexpected_exposure',
      severity: 'unknown', priority: 'review', exploitability: 'not_tested',
      evidence: `TCP connection to ${scope.target} port ${item.port} succeeded from this scanner; the supplied policy did not expect it.`,
      attackerOutcome: 'Someone with equivalent network access could attempt to interact with the listening service. No authentication bypass, data access or exploit was tested.',
      prerequisites: 'The attacker must have a route and network permissions equivalent to this scan. Further impact depends on the actual service and its protections.',
      businessImpact: 'An unintentionally reachable service adds an access path that may expose data or affect availability if its protections fail; neither outcome is established here.',
      unknowns: ['Service identity and owner', 'Authentication and vulnerabilities', 'Reachability from other networks, including the internet', 'Whether the supplied expected-port policy is current'],
      recommendedFix: 'Confirm the service owner and intended access. If unintended, restrict firewall ingress or the listening interface, or stop the unused service. Verify necessary clients still work and rescan from relevant networks.' })),
    limitations: ['Only selected TCP ports at the recorded time and vantage point were tested.',
      'Refusal does not prove no service exists; timeouts and other errors remain unknown.',
      'Port numbers do not establish service identity. Reachability does not establish exploitability or business necessity.',
      'An expected-port list is user-supplied policy, not independently verified intent. No firewall changes were made.'] };
}
