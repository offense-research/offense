import test from 'node:test';
import assert from 'node:assert/strict';
import { assessKubernetesCompatibility } from '../shared/kubernetes-compatibility.js';
import { kubernetesEvidenceDigest, kubernetesEvidenceSchema, kubernetesTargetSchema } from '../shared/kubernetes-evidence.js';

const at = '2026-10-29T02:00:00Z';
const source = { kind: 'command-output', observedAt: at, artifactSha256: 'a'.repeat(64) };
const image = 'example/train@sha256:' + 'b'.repeat(64), imageID = 'containerd://sha256:' + 'c'.repeat(64);
function fixture() {
  const inventory = { schemaVersion: 'offense.kubernetes.inventory.v1', capturedAt: at,
    server: { gitVersion: 'v1.32.1' },
    coverage: Object.fromEntries(['server', 'nodes', 'pods', 'clusterPolicies', 'nvidiaDrivers', 'disruptionBudgets'].map(key => [key, { status: 'complete', observedAt: at }])),
    inventory: {
      nodes: [{ name: 'gpu-a', uid: 'node-a', kubeletVersion: 'v1.31.5', osImage: 'Ubuntu 22.04.5 LTS',
        kernelVersion: '5.15.0-130-generic', architecture: 'amd64', containerRuntimeVersion: 'containerd://1.7.24',
        gpu: { labels: { 'nvidia.com/gpu.product': 'NVIDIA-A100', 'nvidia.com/cuda.driver-version.full': '550.163.01',
          'nvidia.com/cuda.runtime-version.full': '12.4' }, capacity: { 'nvidia.com/gpu': '2' }, allocatable: { 'nvidia.com/gpu': '2' } } }],
      pods: [{ name: 'train', namespace: 'research', uid: 'pod-a', pod: { nodeName: 'gpu-a', containers: [
        { name: 'train', image, imageID, limits: { 'nvidia.com/gpu': '1' }, requests: {} }] } }],
      clusterPolicies: [{ name: 'cluster-policy', uid: 'policy-a', components: { driver: { enabled: true, version: '550.163.01' } },
        driverConfiguration: { usePrecompiled: false, kernelModuleType: 'proprietary' } }],
      nvidiaDrivers: [], disruptionBudgets: []
    } };
  const evidence = { schemaVersion: 'offense.kubernetes.evidence.v1', inventorySha256: kubernetesEvidenceDigest(inventory),
    profile: { manager: 'kubeadm', platform: 'bare-metal-pcie', source },
    controlPlane: { complete: true, apiServers: [{ id: 'cp-a', version: '1.32.1' }], source },
    gpuOperator: { version: '25.3.2', installation: 'cluster-policy', policyUid: 'policy-a', source },
    nodes: [{ nodeUid: 'node-a', osRelease: '22.04', driverVersion: '550.163.01', precompiled: false, kernelModuleType: 'proprietary', source }],
    workloads: [{ podUid: 'pod-a', containerName: 'train', imageReference: image, imageID, cudaRelease: '12.4.1',
      compatibilityMode: 'native', source: { ...source, kind: 'build-metadata' } }] };
  return structuredClone({ inventory, evidence, target: { schemaVersion: 'offense.kubernetes.target.v1', kubernetesVersion: '1.33.1' }, asOf: at });
}
const check = (report, id, subject) => {
  const result = report.checks.find(item => item.id === id && (!subject || item.subject === subject));
  assert.ok(result, `Missing check ${id} ${subject || ''}`);
  return result.verdict;
};
const run = input => { input.evidence.inventorySha256 = kubernetesEvidenceDigest(input.inventory); return assessKubernetesCompatibility(input); };

test('version-pinned checks are deterministic, cited, bound to evidence and never authorize rollout', () => {
  const input = fixture(), before = structuredClone(input), report = assessKubernetesCompatibility(input);
  assert.deepEqual(input, before); assert.deepEqual(assessKubernetesCompatibility(input), report);
  for (const id of ['kubernetes.api-skew', 'kubernetes.kubelet-skew', 'kubernetes.upgrade-hop', 'gpu.operator-transition',
    'gpu.operator-kubernetes', 'gpu.platform', 'gpu.driver-listed', 'gpu.driver-kernel', 'gpu.cuda-driver']) assert.equal(check(report, id), 'pass');
  assert.equal(report.verdict, 'unknown'); assert.equal(check(report, 'gpu.driver-disruption'), 'unknown');
  assert.equal(report.upgradeSafe, false); assert.equal(report.sequence, null); assert.equal(report.rolloutReadiness, 'not_evaluated');
  for (const key of ['inventorySha256', 'evidenceSha256', 'targetSha256', 'rulesSha256']) assert.match(report.bindings[key], /^[a-f0-9]{64}$/);
  assert.ok(report.checks.find(item => item.id === 'gpu.cuda-driver').sources[0].url.includes('/archive/12.4.1/'));
  assert.ok(report.notEvaluated.includes('Intermediate upgrade states'));
});

test('mixed API servers narrow skew and a worker can be valid now but block the next control-plane hop', () => {
  const f = fixture();
  f.evidence.controlPlane.apiServers.push({ id: 'cp-b', version: '1.31.7' });
  f.inventory.inventory.nodes[0].kubeletVersion = '1.32.1';
  let result = run(f);
  assert.equal(check(result, 'kubernetes.api-skew'), 'pass');
  assert.equal(check(result, 'kubernetes.kubelet-skew'), 'fail');
  assert.equal(check(result, 'kubernetes.upgrade-hop'), 'fail');
  f.evidence.controlPlane.apiServers.pop(); f.inventory.inventory.nodes[0].kubeletVersion = '1.29.9';
  result = run(f);
  assert.equal(check(result, 'kubernetes.kubelet-skew'), 'pass');
  assert.equal(check(result, 'kubernetes.target-retained-kubelet'), 'fail');
  f.inventory.inventory.nodes[0].kubeletVersion = '1.30.0';
  assert.equal(check(run(f), 'kubernetes.target-retained-kubelet'), 'pass');
  f.target.kubernetesVersion = '1.31.9';
  assert.equal(check(run(f), 'kubernetes.upgrade-hop'), 'fail');
});

test('missing topology, conflicting observation, vendor versions and incomplete coverage stay unknown', () => {
  for (const change of [f => { delete f.evidence.controlPlane; }, f => { f.evidence.controlPlane.complete = false; },
    f => { f.evidence.controlPlane.apiServers[0].version = '1.31.0'; },
    f => { f.evidence.controlPlane.apiServers[0].version = '1.32.1-provider'; }]) {
    const f = fixture(); change(f);
    assert.equal(check(run(f), 'kubernetes.control-plane'), 'unknown');
  }
  const f = fixture(); f.inventory.coverage.nodes.status = 'partial';
  assert.equal(check(run(f), 'inventory.coverage', 'nodes'), 'unknown');
  f.target.kubernetesVersion = '1.34.0';
  assert.equal(check(run(f), 'kubernetes.target-scope'), 'unknown');
  assert.equal(check(run(f), 'gpu.operator-kubernetes'), 'fail');
  const sparse = fixture();
  sparse.inventory.inventory.nodes[0].gpu = { labels: { 'nvidia.com/gpu.count': '1' }, capacity: {}, allocatable: {} };
  sparse.inventory.inventory.pods = []; sparse.evidence.workloads = [];
  delete sparse.evidence.gpuOperator;
  assert.equal(check(run(sparse), 'gpu.platform'), 'unknown', 'Sparse GPU discovery must not become GPU-free clearance.');
});

test('Operator calendar families, external drivers and unreviewed releases cannot be mistaken for support', () => {
  const f = fixture(); f.target.gpuOperatorVersion = '25.3.2'; f.evidence.gpuOperator.version = '24.9.2';
  assert.equal(check(run(f), 'gpu.operator-transition'), 'pass');
  assert.equal(check(run(f), 'gpu.operator-operands'), 'unknown');
  assert.equal(check(run(f), 'gpu.driver-listed'), 'unknown', 'Do not silently retain an old driver through new chart defaults.');
  f.evidence.gpuOperator.version = '24.6.2';
  assert.equal(check(run(f), 'gpu.operator-transition'), 'fail');
  f.evidence.gpuOperator.version = '24.7.2';
  assert.equal(check(run(f), 'gpu.operator-transition'), 'unknown');
  f.evidence.gpuOperator.version = '25.3.3';
  assert.equal(check(run(f), 'gpu.operator-transition'), 'fail');
  f.target.gpuOperatorVersion = '26.7.2';
  assert.equal(check(run(f), 'gpu.operator-transition'), 'unknown');
  f.inventory.inventory.clusterPolicies[0].components.driver.enabled = false;
  assert.equal(check(run(f), 'gpu.driver-ownership'), 'unknown');
  f.evidence.gpuOperator.installation = 'driver-crd';
  assert.equal(check(run(f), 'gpu.operator-identity'), 'unknown');
});

test('precompiled drivers obey kernel and branch constraints without treating an unlisted driver as incompatible', () => {
  const f = fixture(); f.inventory.inventory.nodes[0].kernelVersion = '6.8.0-52-generic';
  assert.equal(check(run(f), 'gpu.driver-kernel'), 'pass');
  f.evidence.nodes[0].precompiled = true; f.inventory.inventory.clusterPolicies[0].driverConfiguration.usePrecompiled = true;
  assert.equal(check(run(f), 'gpu.driver-kernel'), 'fail');
  f.inventory.inventory.nodes[0].kernelVersion = '5.15.0-130-generic';
  assert.equal(check(run(f), 'gpu.driver-kernel'), 'pass');
  f.target.driverVersion = '580.65.06';
  assert.equal(check(run(f), 'gpu.driver-listed'), 'pass');
  assert.equal(check(run(f), 'gpu.driver-kernel'), 'fail');
  f.target.driverVersion = '580.99.01';
  assert.equal(check(run(f), 'gpu.driver-listed'), 'unknown');
  f.inventory.inventory.nodes[0].architecture = 'arm64';
  assert.equal(check(run(f), 'gpu.platform'), 'unknown');
});

test('CUDA uses exact image-bound workload requirements, not CUDA labels or a coarse driver branch', () => {
  const f = fixture();
  for (const [driver, expected] of [['525.60.12', 'fail'], ['525.60.13', 'unknown'], ['550.54.14', 'unknown'], ['550.54.15', 'pass']]) {
    f.target.driverVersion = driver;
    assert.equal(check(run(f), 'gpu.cuda-driver'), expected, driver);
  }
  f.evidence.workloads[0].compatibilityMode = 'forward';
  assert.equal(check(run(f), 'gpu.cuda-driver'), 'unknown');
  f.evidence.workloads[0].compatibilityMode = 'native';
  f.evidence.workloads[0].imageID = 'sha256:' + 'd'.repeat(64);
  assert.equal(check(run(f), 'gpu.cuda-driver'), 'unknown');
  f.evidence.workloads = [];
  assert.equal(check(run(f), 'gpu.cuda-driver'), 'unknown');
  assert.equal(f.inventory.inventory.nodes[0].gpu.labels['nvidia.com/cuda.runtime-version.full'], '12.4');
  for (const change of [
    f => { f.evidence.workloads[0].cudaRelease = '__proto__'; },
    f => { f.evidence.workloads[0].cudaRelease = '12.5.0'; },
    f => { f.inventory.inventory.nodes[0].gpu.labels['nvidia.com/cuda.driver.major'] = '535'; },
    f => { f.inventory.inventory.pods[0].pod.nodeName = 'unobserved-node'; },
    f => { f.inventory.inventory.nodes[0].architecture = 'arm64'; }
  ]) {
    const f = fixture(); change(f);
    assert.equal(check(run(f), 'gpu.cuda-driver'), 'unknown');
  }
  const init = fixture();
  init.inventory.inventory.pods[0].pod.initContainers = init.inventory.inventory.pods[0].pod.containers;
  init.inventory.inventory.pods[0].pod.containers = [];
  init.target.driverVersion = '525.60.12';
  assert.equal(check(run(init), 'gpu.cuda-driver'), 'fail', 'GPU init containers also need compatible drivers.');
});

test('PDB evidence requires current generation and complete membership and never proves drain safety', () => {
  const f = fixture();
  const pdb = { name: 'train', namespace: 'research', uid: 'pdb-a', generation: 2, observedGeneration: 2, disruptionsAllowed: 0,
    podSelection: { status: 'complete', matches: [{ name: 'train', namespace: 'research', uid: 'pod-a' }] } };
  f.inventory.inventory.disruptionBudgets = [pdb];
  assert.equal(check(run(f), 'disruption.pdb'), 'fail');
  pdb.disruptionsAllowed = 1;
  assert.equal(check(run(f), 'disruption.pdb'), 'pass');
  assert.equal(run(f).upgradeSafe, false);
  pdb.observedGeneration = 1;
  assert.equal(check(run(f), 'disruption.pdb'), 'unknown');
  pdb.observedGeneration = 2; pdb.podSelection.status = 'partial';
  assert.equal(check(run(f), 'disruption.pdb'), 'unknown');
  pdb.podSelection.status = 'complete'; pdb.podSelection.matches[0].uid = 'replaced-pod';
  assert.equal(check(run(f), 'disruption.pdb'), 'unknown');
  delete pdb.podSelection; // Original v1 snapshots remain readable, not cleared.
  assert.equal(check(run(f), 'disruption.pdb'), 'unknown');
});

test('stale, future, unbound, duplicate and unsupported evidence fail closed without echoing invalid input', () => {
  const f = fixture(); f.inventory.server.gitVersion = '1.33.0';
  assert.equal(check(assessKubernetesCompatibility(f), 'evidence.binding'), 'unknown');
  f.inventory.capturedAt = '2026-10-27T00:00:00Z';
  assert.equal(check(run(f), 'evidence.freshness'), 'unknown');
  f.inventory.capturedAt = '2026-10-29T02:05:01Z';
  assert.equal(check(run(f), 'evidence.freshness'), 'unknown');
  const duplicate = fixture(); duplicate.evidence.nodes.push(structuredClone(duplicate.evidence.nodes[0]));
  assert.equal(check(run(duplicate), 'evidence.identities'), 'unknown');
  const invalid = fixture(); invalid.evidence.secret = 'sensitive-input-must-not-leak';
  const report = run(invalid);
  assert.equal(report.verdict, 'unknown'); assert.ok(!JSON.stringify(report).includes(invalid.evidence.secret));
  assert.equal(kubernetesEvidenceSchema.safeParse(invalid.evidence).success, false);
  assert.equal(kubernetesTargetSchema.safeParse({ ...invalid.target, execute: true }).success, false);
  const managed = fixture(); managed.evidence.profile.manager = 'eks';
  assert.equal(check(run(managed), 'platform.scope'), 'unknown');
  const missing = fixture(); missing.evidence.workloads[0].containerName = 'missing';
  assert.equal(check(run(missing), 'evidence.identities'), 'unknown');
  const malformed = fixture(); malformed.inventory.inventory.nodes[0].gpu.labels = null;
  assert.equal(check(run(malformed), 'input.schema'), 'unknown');
  delete malformed.inventory.inventory.nodes[0].gpu;
  delete malformed.inventory.coverage;
  assert.equal(check(run(malformed), 'input.schema'), 'unknown');
});

test('rule review expires independently of fresh inventory and evidence digests ignore object key order', () => {
  const f = fixture(); f.asOf = '2026-11-29T02:00:00Z'; f.inventory.capturedAt = f.asOf;
  for (const value of Object.values(f.inventory.coverage)) value.observedAt = f.asOf;
  for (const fact of [f.evidence.profile, f.evidence.controlPlane, f.evidence.gpuOperator, ...f.evidence.nodes, ...f.evidence.workloads]) fact.source.observedAt = f.asOf;
  assert.equal(check(run(f), 'rules.review'), 'unknown');
  assert.equal(kubernetesEvidenceDigest({ a: 1, b: { c: 2, d: 3 } }), kubernetesEvidenceDigest({ b: { d: 3, c: 2 }, a: 1 }));
  assert.throws(() => kubernetesEvidenceDigest({ a: NaN }), /JSON/);
});
