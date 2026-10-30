import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, lstat, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { collectKubernetesInventory } from '../scripts/kubernetes-collection.mjs';
import { createOffenseCli } from '../scripts/offense-cli.mjs';

const secret = 'never-persist-this-fixture-secret';
const result = value => ({ code: 0, stdout: Buffer.from(JSON.stringify(value)) });
const page = (kind, items = [], metadata = {}) => ({ apiVersion: 'v1', kind: kind + 'List', metadata: { resourceVersion: '72', ...metadata }, items });
const node = (name, labels = {}) => ({ metadata: { name, labels, annotations: { secret }, managedFields: [{ secret }] },
  spec: {}, status: { nodeInfo: { kubeletVersion: 'v1.33.5', osImage: 'Ubuntu 22.04.5 LTS', kernelVersion: '5.15.0-130-generic',
    containerRuntimeVersion: 'containerd://1.7.24', architecture: 'amd64', machineID: secret },
  addresses: [{ address: secret }], capacity: { cpu: '16', memory: '64Gi', 'nvidia.com/mig-1g.10gb': '14' },
  allocatable: { cpu: '15', 'nvidia.com/mig-1g.10gb': '12' }, conditions: [{ type: 'Ready', status: 'True', message: secret }] } });
const gpuLabels = { 'nvidia.com/gpu.product': 'NVIDIA-A100', 'nvidia.com/cuda.driver-version.full': '550.127.05',
  'nvidia.com/cuda.runtime-version.full': '12.4', 'nvidia.com/mig.strategy': 'mixed', 'nvidia.com/gpu.count': '2',
  'nvidia.com/gpu.replicas': '7', 'nvidia.com/mig-1g.10gb.count': '14', 'nvidia.com/gfd.timestamp': '1793145600',
  'nvidia.com/unrecognized': secret, custom: secret };

function fixture() {
  const data = new Map([
    ['/version', { gitVersion: 'v1.34.1', platform: 'linux/amd64' }],
    ['/apis', { groups: [{ name: 'nvidia.com', versions: [{ groupVersion: 'nvidia.com/v1' }, { groupVersion: 'nvidia.com/v1alpha1' }] }] }],
    ['/apis/nvidia.com/v1', { resources: [{ name: 'clusterpolicies', namespaced: false, verbs: ['get', 'list'] }] }],
    ['/apis/nvidia.com/v1alpha1', { resources: [{ name: 'nvidiadrivers', namespaced: false, verbs: ['list'] }] }],
    ['/api/v1/nodes', page('Node', [node('gpu-worker', gpuLabels)], { continue: 'next/+&token' })],
    ['/api/v1/nodes?continue', page('Node', [node('legacy-gpu', { 'nvidia.com/gpu.product': 'Tesla-T4', 'nvidia.com/cuda.driver.major': '535', 'nvidia.com/cuda.driver.minor': '183' })])],
    ['/api/v1/namespaces', page('Namespace', [{ metadata: { name: 'training' } }])],
    ['/api/v1/pods', page('Pod', [{ metadata: { name: 'training-1', namespace: 'training', labels: { secret },
      ownerReferences: [{ apiVersion: 'batch/v1', kind: 'Job', name: 'training', uid: 'job-uid' }] },
    spec: { nodeName: 'gpu-worker', runtimeClassName: 'nvidia', containers: [{ name: 'worker', image: 'example/train:7',
      command: [secret], args: [secret], env: [{ name: 'TOKEN', value: secret }], resources: { limits: { 'nvidia.com/mig-1g.10gb': '2' } } }],
    volumes: [{ name: 'data', persistentVolumeClaim: { claimName: 'checkpoints' } }, { name: 'token', secret: { secretName: secret } }] },
    status: { phase: 'Running', containerStatuses: [{ name: 'worker', imageID: 'containerd://sha256:' + 'a'.repeat(64), ready: true, restartCount: 3, state: { running: {} } }], message: secret } }])],
    ['/apis/apps/v1/deployments', page('Deployment')], ['/apis/apps/v1/daemonsets', page('DaemonSet')], ['/apis/apps/v1/statefulsets', page('StatefulSet')],
    ['/apis/batch/v1/jobs', page('Job', [{ metadata: { name: 'training', namespace: 'training' }, spec: { parallelism: 2, completions: 8 }, status: { active: 2, succeeded: 5, failed: 1 } }])],
    ['/apis/batch/v1/cronjobs', page('CronJob', [{ metadata: { name: 'nightly', namespace: 'training' }, spec: { suspend: true,
      jobTemplate: { spec: { template: { spec: { containers: [{ name: 'nightly', image: 'example/train:8', env: [{ value: secret }] }] } } } } } }])],
    ['/apis/policy/v1/poddisruptionbudgets', page('PodDisruptionBudget', [{ metadata: { name: 'training', namespace: 'training' },
      spec: { maxUnavailable: '25%' }, status: { disruptionsAllowed: 0, currentHealthy: 3, desiredHealthy: 3, expectedPods: 4 } }])],
    ['/api/v1/persistentvolumes', page('PersistentVolume', [{ metadata: { name: 'volume' }, spec: { storageClassName: 'fast', capacity: { storage: '500Gi' },
      persistentVolumeReclaimPolicy: 'Retain', claimRef: { name: 'checkpoints', namespace: 'training' }, csi: { driver: 'csi.example', volumeHandle: secret, volumeAttributes: { secret } } } }])],
    ['/api/v1/persistentvolumeclaims', page('PersistentVolumeClaim')],
    ['/apis/storage.k8s.io/v1/storageclasses', page('StorageClass', [{ metadata: { name: 'fast' }, provisioner: 'csi.example', parameters: { secret }, reclaimPolicy: 'Delete', volumeBindingMode: 'WaitForFirstConsumer' }])],
    ['/apis/storage.k8s.io/v1/csidrivers', page('CSIDriver')],
    ['/apis/nvidia.com/v1/clusterpolicies', { ...page('ClusterPolicy', [{ metadata: { name: 'cluster-policy' },
      spec: { driver: { enabled: false, version: '550.127.05', env: [{ value: secret }] }, mig: { strategy: 'mixed' } }, status: { state: 'ready' } }]), apiVersion: 'nvidia.com/v1' }],
    ['/apis/nvidia.com/v1alpha1/nvidiadrivers', { ...page('NVIDIADriver', [{ metadata: { name: 'driver' }, spec: { driverType: 'gpu', version: '570.172.08', env: [{ value: secret }] } }]), apiVersion: 'nvidia.com/v1alpha1' }],
  ]);
  const unexpected = [];
  const execute = async (command, args) => {
    if (command !== 'kubectl' || args[0] !== '--context' || args[1] !== 'fixture' || !args.includes('--request-timeout=15s') ||
        args.at(-3) !== 'get' || args.at(-2) !== '--raw') { unexpected.push({ command, args }); throw Error('unexpected command'); }
    const url = new URL(args.at(-1), 'http://fixture');
    const key = url.pathname + (url.searchParams.has('continue') ? '?continue' : '');
    if (url.searchParams.has('continue')) assert.equal(url.searchParams.get('continue'), 'next/+&token');
    if (!data.has(key)) { unexpected.push(key); throw Error('unexpected endpoint'); }
    const value = data.get(key);
    if (value instanceof Error) throw value;
    return result(value);
  };
  return { data, execute, unexpected, collect: (options = {}, dependencies = {}) => collectKubernetesInventory({ context: 'fixture', ...options }, { execute, ...dependencies }) };
}

test('read-only inventory preserves paginated Kubernetes, GPU, job and storage evidence without raw sensitive fields', async () => {
  const f = fixture(), snapshot = await f.collect({ kubeconfig: '/private/fixture-config' });
  assert.equal(snapshot.status, 'complete'); assert.deepEqual(f.unexpected, []);
  assert.equal(snapshot.server.gitVersion, 'v1.34.1'); assert.equal(snapshot.inventory.nodes.length, 2);
  assert.equal(snapshot.inventory.nodes[0].kubeletVersion, 'v1.33.5');
  assert.equal(snapshot.inventory.nodes[0].osImage, 'Ubuntu 22.04.5 LTS');
  assert.equal(snapshot.inventory.nodes[0].gpu.capacity['nvidia.com/mig-1g.10gb'], '14');
  assert.equal(snapshot.inventory.nodes[0].gpu.allocatable['nvidia.com/mig-1g.10gb'], '12');
  assert.equal(snapshot.inventory.nodes[0].gpu.labels['nvidia.com/gpu.count'], '2');
  assert.deepEqual(snapshot.gpu.observedNodes, ['gpu-worker', 'legacy-gpu']); assert.equal(snapshot.gpu.physicalDeviceCount, null);
  assert.equal(snapshot.coverage.nodes.resourceVersion, '72');
  assert.equal(snapshot.inventory.pods[0].pod.containers[0].restartCount, 3);
  assert.equal(snapshot.inventory.pods[0].pod.containers[0].imageID, 'containerd://sha256:' + 'a'.repeat(64));
  assert.deepEqual(snapshot.inventory.pods[0].pod.persistentVolumeClaims, ['checkpoints']);
  assert.equal(snapshot.inventory.jobs[0].observed.active, 2);
  assert.equal(snapshot.inventory.cronJobs[0].pod.containers[0].image, 'example/train:8');
  assert.equal(snapshot.inventory.disruptionBudgets[0].disruptionsAllowed, 0);
  assert.equal(snapshot.inventory.disruptionBudgets[0].maxUnavailable, '25%');
  assert.equal(snapshot.inventory.persistentVolumes[0].reclaimPolicy, 'Retain');
  assert.equal(snapshot.inventory.storageClasses[0].reclaimPolicy, 'Delete');
  assert.equal(snapshot.inventory.clusterPolicies[0].components.driver.enabled, false);
  assert.equal(snapshot.inventory.nvidiaDrivers[0].apiVersion, 'nvidia.com/v1alpha1');
  assert.equal(snapshot.inventory.nvidiaDrivers[0].driver.version, '570.172.08');
  assert.equal(snapshot.tools.nova.status, 'not_requested'); assert.equal(snapshot.tools.popeye.status, 'not_requested');
  assert.ok(!JSON.stringify(snapshot).includes(secret));
});

test('selector evidence resolves identities without persisting selectors, labels or rollout selector strings', async () => {
  const f = fixture();
  const pod = f.data.get('/api/v1/pods').items[0]; pod.metadata.uid = 'training-uid';
  const other = structuredClone(pod); other.metadata = { ...other.metadata, namespace: 'other', uid: 'other-uid' };
  const missing = structuredClone(pod); missing.metadata = { ...missing.metadata, name: 'unlabelled', uid: 'missing-uid', labels: {} };
  f.data.get('/api/v1/pods').items.push(other, missing);
  const pdb = f.data.get('/apis/policy/v1/poddisruptionbudgets').items[0];
  const policy = f.data.get('/apis/nvidia.com/v1/clusterpolicies').items[0];
  policy.spec.driver.upgradePolicy = { autoUpgrade: false, maxParallelUpgrades: 0, maxUnavailable: '25%',
    drain: { enable: true, force: false, deleteEmptyDir: false, timeoutSeconds: 0, podSelector: secret } };
  policy.spec.driver.usePrecompiled = false; policy.spec.driver.kernelModuleType = 'proprietary';
  f.data.get('/apis/nvidia.com/v1alpha1/nvidiadrivers').items[0].spec.nodeSelector = { custom: secret };
  for (const [selector, expected] of [
    [{ matchLabels: { secret } }, ['training-uid']],
    [{ matchExpressions: [{ key: 'secret', operator: 'In', values: [secret] }] }, ['training-uid']],
    [{ matchExpressions: [{ key: 'secret', operator: 'NotIn', values: [secret] }] }, ['missing-uid']],
    [{ matchExpressions: [{ key: 'secret', operator: 'Exists' }] }, ['training-uid']],
    [{ matchExpressions: [{ key: 'secret', operator: 'DoesNotExist' }] }, ['missing-uid']],
    [{}, ['training-uid', 'missing-uid']], [null, []]
  ]) {
    pdb.spec.selector = selector;
    const snapshot = await f.collect(), selected = snapshot.inventory.disruptionBudgets[0].podSelection;
    assert.equal(selected.status, 'complete'); assert.deepEqual(selected.matches.map(pod => pod.uid), expected);
    assert.equal(snapshot.evidenceVersion, 1);
    const driver = snapshot.inventory.clusterPolicies[0].driverConfiguration;
    assert.equal(driver.usePrecompiled, false); assert.equal(driver.kernelModuleType, 'proprietary');
    assert.equal(driver.upgradePolicy.autoUpgrade, false); assert.equal(driver.upgradePolicy.maxParallelUpgrades, 0);
    assert.equal(driver.upgradePolicy.drain.timeoutSeconds, 0); assert.equal(driver.upgradePolicy.drain.selectorConfigured, true);
    assert.deepEqual(snapshot.inventory.nvidiaDrivers[0].nodeSelection.matches.map(node => node.name), ['gpu-worker']);
    assert.ok(!JSON.stringify(snapshot).includes(secret));
  }
  pdb.spec.selector = { matchExpressions: [{ key: 'secret', operator: 'Unknown' }] };
  assert.equal((await f.collect()).inventory.disruptionBudgets[0].podSelection.status, 'partial');
  pdb.spec.selector = {}; f.data.set('/api/v1/pods', Error(secret));
  assert.equal((await f.collect()).inventory.disruptionBudgets[0].podSelection.status, 'partial');
});

test('denied reads, missing discovery metadata and malformed pages retain useful evidence as partial, not absent', async () => {
  const f = fixture();
  f.data.set('/api/v1/pods', Error(secret));
  f.data.set('/api/v1/nodes?continue', page('Node', [{ metadata: { name: 'unlabelled', labels: { 'nvidia.com/gpu.count': '4' } } }]));
  f.data.set('/apis/nvidia.com/v1alpha1', Error(secret));
  f.data.set('/api/v1/persistentvolumeclaims', {});
  const snapshot = await f.collect();
  assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.inventory.nodes.length, 2);
  assert.equal(snapshot.coverage.pods.status, 'unavailable'); assert.equal(snapshot.coverage.nvidiaDrivers.status, 'unavailable');
  assert.equal(snapshot.coverage.clusterPolicies.status, 'complete');
  assert.ok(snapshot.gaps.some(gap => gap.code === 'discovery_metadata_missing:unlabelled'));
  assert.ok(!JSON.stringify(snapshot).includes(secret));
});

test('absent NVIDIA APIs differ from unavailable discovery and GPU-free nodes are not physical hardware attestations', async () => {
  const f = fixture();
  f.data.set('/apis', { groups: [] }); f.data.set('/api/v1/nodes', page('Node', [{ metadata: { name: 'cpu-worker' }, status: {} }]));
  let snapshot = await f.collect();
  assert.equal(snapshot.status, 'complete'); assert.equal(snapshot.coverage.clusterPolicies.status, 'not_served');
  assert.deepEqual(snapshot.gpu.observedNodes, []); assert.equal(snapshot.gpu.physicalDeviceCount, null);
  f.data.set('/apis', Error('forbidden'));
  snapshot = await f.collect();
  assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.coverage.clusterPolicies.status, 'unavailable');
});

test('incomplete pagination never yields complete coverage or mixes resource versions', async () => {
  for (const replacement of [Error('expired continue token'), page('Node', [node('wrong-snapshot', gpuLabels)], { resourceVersion: '73' }),
    page('Node', [], { continue: 'next/+&token' })]) {
    const f = fixture(); f.data.set('/api/v1/nodes?continue', replacement);
    const snapshot = await f.collect();
    assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.coverage.nodes.status, 'partial');
    assert.deepEqual(snapshot.inventory.nodes.map(node => node.name), ['gpu-worker']);
  }
});

test('collection bounds retain partial inventories at the item limit and time limit', async () => {
  const f = fixture();
  for (const size of [5000, 5001]) {
    f.data.set('/api/v1/namespaces', page('Namespace', Array.from({ length: size }, (_, i) => ({ metadata: { name: `ns-${i}` } }))));
    const snapshot = await f.collect();
    assert.equal(snapshot.inventory.namespaces.length, 5000);
    assert.equal(snapshot.coverage.namespaces.status, size === 5000 ? 'complete' : 'partial');
  }
  let clock = 0;
  const snapshot = await f.collect({}, { now: () => (clock += 180_000) });
  assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.server, null);
  assert.ok(snapshot.gaps.some(gap => gap.code === 'collection_limit'));
});

test('optional local tools retain upgrade candidates and Popeye finding codes, never report messages or Helm values', async () => {
  const f = fixture();
  const sections = ['v1/nodes', 'v1/pods', 'batch/v1/jobs', 'policy/v1/poddisruptionbudgets', 'v1/persistentvolumes', 'v1/persistentvolumeclaims'].map(gvr =>
    ({ gvr, tally: { ok: 0, info: 0, warning: 1, error: 0, score: 50 }, issues: { 'training/worker': [{ level: 2, message: '[POP-500] ' + secret }] } }));
  const execute = async (command, args) => {
    if (command === 'kubectl') return f.execute(command, args);
    assert.equal(args[args.indexOf('--context') + 1], 'fixture');
    if (command === 'nova') return result([{ release: 'gpu-operator', chartName: 'gpu-operator', namespace: 'gpu-system',
      Installed: { version: '24.9.2', appVersion: '24.9.2' }, Latest: { version: '25.3.0' }, outdated: true, deprecated: false, description: secret, values: { secret } }]);
    assert.equal(command, 'popeye');
    return { ...result({ popeye: { score: 50, sections } }), code: 1 };
  };
  let snapshot = await f.collect({ withNova: true, withPopeye: true }, { execute });
  assert.equal(snapshot.status, 'complete'); assert.equal(snapshot.tools.nova.report[0].latest.version, '25.3.0');
  assert.equal(snapshot.tools.popeye.report.sections[0].issues[0].code, '[POP-500]');
  assert.equal(snapshot.tools.popeye.report.sections[0].issues[0].level, 2);
  assert.ok(!JSON.stringify(snapshot).includes(secret));
  for (const code of ['402', '404', '666', '708']) {
    sections[0].issues['training/worker'][0].message = `[POP-${code}] ` + secret;
    snapshot = await f.collect({ withPopeye: true }, { execute });
    assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.tools.popeye.status, 'partial');
  }
  sections[0].issues['training/worker'][0].message = '[POP-500] ' + secret;
  sections.pop();
  snapshot = await f.collect({ withPopeye: true }, { execute });
  assert.equal(snapshot.status, 'partial'); assert.equal(snapshot.tools.popeye.status, 'partial');
  snapshot = await f.collect({ withNova: true }, { execute: async (command, args) => command === 'kubectl' ? f.execute(command, args) : { code: 0, stdout: Buffer.from('No releases found\n') } });
  assert.equal(snapshot.tools.nova.status, 'complete'); assert.deepEqual(snapshot.tools.nova.report, []);
});

test('requested missing tools, unsupported output and missing chart metadata leave explicit gaps', async () => {
  for (const value of [Error(secret), {}, [{ release: 'a', chartName: 'a', Installed: { version: '1.0.0' }, Latest: {} }]]) {
    const f = fixture(), snapshot = await f.collect({ withNova: true }, { execute: async (command, args) => {
      if (command === 'kubectl') return f.execute(command, args);
      if (value instanceof Error) throw value;
      return result(value);
    } });
    assert.equal(snapshot.status, 'partial'); assert.notEqual(snapshot.tools.nova.status, 'complete');
    assert.ok(!JSON.stringify(snapshot).includes(secret));
  }
});

test('CLI preview is offline, run bypasses hosted login, and snapshots are private and cannot be overwritten', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'offense-k8s-test-')); t.after(() => rm(root, { recursive: true, force: true }));
  const output = path.join(root, 'report'), f = fixture(), stdout = [], stderr = []; let collected = 0;
  const cli = createOffenseCli({ env: { OFFENSE_API_URL: 'invalid endpoint', OFFENSE_CONFIG_DIR: '/no-such-config' },
    output: text => stdout.push(JSON.parse(text)), diagnostic: text => stderr.push(JSON.parse(text)),
    fetchImpl: async () => assert.fail('No Offense request allowed'), kubernetesCollect: async options => { collected++; return f.collect(options); } });
  const args = ['k8s', 'collect', '--context', 'fixture', '--output', output];
  assert.equal(await cli.run(args), 0); assert.equal(stdout.at(-1).status, 'preview'); assert.equal(collected, 0);
  await assert.rejects(lstat(output), { code: 'ENOENT' });
  for (const bad of [['k8s', 'collect'], [...args, '--endpoint', 'https://example.com'], [...args, '--preview', '--run'], [...args, 'extra']])
    assert.equal(await cli.run(bad), 1);
  assert.equal(collected, 0);
  assert.equal(await cli.run([...args, '--run']), 0); assert.equal(collected, 1);
  const filename = stdout.at(-1).snapshot, before = await readFile(filename, 'utf8');
  assert.equal(JSON.parse(before).inventory.nodes.length, 2);
  assert.equal((await lstat(filename)).mode & 0o777, 0o600); assert.equal((await lstat(output)).mode & 0o777, 0o700);
  assert.equal(await cli.run([...args, '--run']), 1); assert.equal(collected, 1); assert.equal(await readFile(filename, 'utf8'), before);
  await rm(filename); await symlink(path.join(root, 'victim'), filename);
  assert.equal(await cli.run([...args, '--run']), 1); assert.equal(collected, 1);
  await rm(filename); f.data.set('/api/v1/pods', Error(secret));
  assert.equal(await cli.run([...args, '--run']), 2); assert.equal(stdout.at(-1).status, 'partial');
  assert.equal(JSON.parse(await readFile(filename)).coverage.pods.status, 'unavailable');
  assert.ok(!JSON.stringify([...stdout, ...stderr]).includes(secret));
  const shared = path.join(root, 'shared'); await mkdir(shared, { mode: 0o755 });
  assert.equal(await cli.run(['k8s', 'collect', '--context', 'fixture', '--run', '--output', shared]), 1);
});
