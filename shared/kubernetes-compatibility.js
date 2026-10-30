import rules from '../config/kubernetes-compatibility.json' with { type: 'json' };
import { kubernetesEvidenceDigest, kubernetesEvidenceSchema, kubernetesInventorySchema, kubernetesTargetSchema } from './kubernetes-evidence.js';

const version = value => {
  const match = typeof value === 'string' && /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/.exec(value);
  return match ? match.slice(1).map(Number) : null;
};
const compare = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const containers = pod => [...pod.pod.containers, ...(pod.pod.initContainers || []), ...(pod.pod.ephemeralContainers || [])];
const gpuResources = container => Object.keys({ ...container.requests, ...container.limits }).some(key => key.startsWith('nvidia.com/'));
const gpuNode = node => !!node.gpu && (Object.keys({ ...node.gpu.capacity, ...node.gpu.allocatable }).some(key => key.startsWith('nvidia.com/')) ||
  node.gpu.labels['nvidia.com/gpu.present'] === 'true' || !!node.gpu.labels['nvidia.com/gpu.product'] ||
  Number(node.gpu.labels['nvidia.com/gpu.count']) > 0 || node.gpu.labels['nvidia.com/mig.capable'] === 'true');
const unique = values => new Set(values).size === values.length;
const boundedKubernetes = v => v && v[0] === 1 && v[1] >= rules.kubernetes.minimumMinor && v[1] <= rules.kubernetes.maximumMinor;
const ruleDigest = kubernetesEvidenceDigest(rules);

// No I/O, implicit clock, model judgment, mutation, or upgrade execution. This
// evaluates current skew and proposed endpoint constraints, not a safe sequence.
export function assessKubernetesCompatibility({ inventory, evidence, target, asOf } = {}) {
  const checks = [], bindings = { inventorySha256: null, evidenceSha256: null, targetSha256: null, rulesSha256: ruleDigest };
  const time = typeof asOf === 'string' ? Date.parse(asOf) : NaN;
  const fresh = at => Number.isFinite(Date.parse(at)) && Date.parse(at) <= time + 300_000 && time - Date.parse(at) <= 86_400_000;
  const add = (id, subject, verdict, reason, paths = [], sourceIds = []) => checks.push({ id, subject, verdict, reason, evidence: paths,
    sources: sourceIds.map(id => ({ id, ...rules.sources[id] })) });
  const finish = () => ({ schemaVersion: 'offense.kubernetes.compatibility.v1', engineVersion: 1, asOf: Number.isFinite(time) ? new Date(time).toISOString() : null,
    rulesVersion: rules.version, bindings, verdict: checks.some(check => check.verdict === 'fail') ? 'fail' :
      checks.some(check => check.verdict === 'unknown') ? 'unknown' : 'pass', checks,
    upgradeSafe: false, rolloutReadiness: 'not_evaluated', sequence: null,
    notEvaluated: ['Intermediate upgrade states', 'Controller-manager, scheduler, kube-proxy and etcd compatibility',
      'CNI, CSI, admission webhooks, CRDs and manifest API migrations', 'Complete Operator operand resolution',
      'Kernel module build, Secure Boot and exact GPU board/platform requirements', 'Workload scheduling, capacity and recovery',
      'Current release support lifecycle, CVE remediation and compliance deadlines'],
    assurance: 'Only the named constraints were checked against supplied evidence. Digests bind content, not authenticity. No upgrade approval or runtime verification.' });
  if (!Number.isFinite(time)) { add('input.time', 'input', 'unknown', 'Supply an explicit ISO evaluation time.'); return finish(); }
  try {
    bindings.inventorySha256 = kubernetesEvidenceDigest(inventory);
    bindings.targetSha256 = kubernetesEvidenceDigest(target);
    if (evidence !== undefined) bindings.evidenceSha256 = kubernetesEvidenceDigest(evidence);
  } catch { add('input.json', 'input', 'unknown', 'Evidence must be bounded JSON.'); return finish(); }
  const parsedInventory = kubernetesInventorySchema.safeParse(inventory), parsedTarget = kubernetesTargetSchema.safeParse(target);
  if (!parsedInventory.success || !parsedTarget.success) {
    add('input.schema', 'input', 'unknown', 'Unsupported or malformed inventory/target contract.'); return finish();
  }
  inventory = parsedInventory.data; target = parsedTarget.data;
  const parsedEvidence = kubernetesEvidenceSchema.safeParse(evidence);
  if (!parsedEvidence.success || parsedEvidence.data.inventorySha256 !== bindings.inventorySha256) {
    add('evidence.binding', 'input', 'unknown', 'Supply valid supplemental evidence bound to this exact inventory digest.'); return finish();
  }
  evidence = parsedEvidence.data;
  const records = [evidence.profile, evidence.controlPlane, evidence.gpuOperator, ...evidence.nodes, ...evidence.workloads].filter(Boolean);
  const timely = fresh(inventory.capturedAt) && records.every(record => fresh(record.source.observedAt)) &&
    Object.values(inventory.coverage).every(value => !value.observedAt || fresh(value.observedAt));
  add('evidence.freshness', 'input', timely ? 'pass' : 'unknown', timely ? 'Evidence is within the 24-hour assessment window.' :
    'Evidence is stale or future-dated; recollect and rebind before assessing.', ['inventory.capturedAt', 'evidence.*.source.observedAt']);
  if (!timely) return finish();
  const reviewed = time >= Date.parse(rules.reviewedAt) && time <= Date.parse(rules.reviewAfter);
  add('rules.review', 'rules', reviewed ? 'pass' : 'unknown', reviewed ? 'Pinned rules are within their review window.' : 'The pinned rule bundle needs review.');
  if (!reviewed) return finish();
  const items = inventory.inventory, nodes = items.nodes, pods = items.pods;
  const nodeIds = nodes.map(node => node.uid), podIds = pods.map(pod => pod.uid);
  const identities = nodeIds.every(Boolean) && podIds.every(Boolean) && unique(nodeIds) && unique(podIds) &&
    unique(nodes.map(node => node.name)) && unique(evidence.nodes.map(node => node.nodeUid)) &&
    pods.every(pod => unique(containers(pod).map(container => container.name))) &&
    unique(evidence.workloads.map(workload => JSON.stringify([workload.podUid, workload.containerName]))) &&
    evidence.nodes.every(node => nodeIds.includes(node.nodeUid)) && evidence.workloads.every(workload =>
      pods.some(pod => pod.uid === workload.podUid && containers(pod).some(container => container.name === workload.containerName)));
  add('evidence.identities', 'input', identities ? 'pass' : 'unknown', identities ? 'Supplemental resource identities are unique and present.' :
    'Missing, duplicate or unmatched resource identities; do not choose one conflicting record.', ['inventory.inventory', 'evidence.nodes', 'evidence.workloads']);
  if (!identities) return finish();
  const profile = evidence.profile;
  const supported = profile?.manager === 'kubeadm' && profile.platform === 'bare-metal-pcie';
  add('platform.scope', 'cluster', supported ? 'pass' : 'unknown', supported ? 'Declared kubeadm and bare-metal PCIe scope.' :
    'Only explicitly declared kubeadm/bare-metal PCIe installations are modeled.', ['evidence.profile']);
  if (!supported) return finish();
  const complete = key => inventory.coverage[key]?.status === 'complete';
  for (const key of ['nodes', 'pods', 'clusterPolicies', 'nvidiaDrivers', 'disruptionBudgets']) {
    const absent = ['clusterPolicies', 'nvidiaDrivers'].includes(key) && inventory.coverage[key]?.status === 'not_served';
    add('inventory.coverage', key, complete(key) || absent ? 'pass' : 'unknown', complete(key) || absent ? 'Resource coverage is accounted for.' :
      'Partial or unavailable resource coverage cannot establish absence.', [`inventory.coverage.${key}`]);
  }
  const control = evidence.controlPlane, api = control?.apiServers.map(server => version(server.version)) || [];
  const apiKnown = control?.complete === true && unique(control.apiServers.map(server => server.id)) && api.length > 0 && api.every(boundedKubernetes);
  const observedApi = version(inventory.server?.gitVersion);
  const consistent = apiKnown && complete('server') && observedApi && api.some(v => compare(v, observedApi) === 0);
  add('kubernetes.control-plane', 'cluster', consistent ? 'pass' : 'unknown', consistent ? 'Complete supplied API-server set includes the observed endpoint.' :
    'All API-server versions are required; /version alone is insufficient or conflicts with supplied evidence.', ['evidence.controlPlane', 'inventory.server'], ['kubernetes-skew']);
  const targetKubernetes = version(target.kubernetesVersion);
  add('kubernetes.target-scope', 'cluster', boundedKubernetes(targetKubernetes) ? 'pass' : 'unknown',
    boundedKubernetes(targetKubernetes) ? 'Target is in the reviewed Kubernetes range.' : 'Target Kubernetes release is outside the reviewed rule range.', ['target.kubernetesVersion'], ['kubernetes-skew']);
  if (consistent) {
    const low = Math.min(...api.map(v => v[1])), high = Math.max(...api.map(v => v[1]));
    add('kubernetes.api-skew', 'cluster', high - low <= rules.kubernetes.apiServerSkew ? 'pass' : 'fail',
      'API servers must stay within one minor version.', ['evidence.controlPlane.apiServers'], ['kubernetes-skew']);
    if (boundedKubernetes(targetKubernetes)) add('kubernetes.upgrade-hop', 'cluster',
      api.every(v => compare(targetKubernetes, v) >= 0 && targetKubernetes[1] - v[1] <= rules.kubernetes.maximumUpgradeHop) ? 'pass' : 'fail',
      'The requested endpoint must not downgrade an API server or skip a Kubernetes minor.', ['evidence.controlPlane.apiServers', 'target.kubernetesVersion'], ['kubernetes-skew']);
  }
  for (const node of [...nodes].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const kubelet = version(node.kubeletVersion), known = consistent && kubelet?.[0] === 1 && kubelet[1] >= 25;
    const allowed = servers => servers.every(v => kubelet[1] <= v[1] && v[1] - kubelet[1] <= rules.kubernetes.kubeletSkew);
    add('kubernetes.kubelet-skew', node.name, !known ? 'unknown' : allowed(api) ? 'pass' : 'fail',
      'Kubelets must not be newer than any API server and must remain within the reviewed three-minor skew.', ['inventory.inventory.nodes', 'evidence.controlPlane'], ['kubernetes-skew']);
    add('kubernetes.target-retained-kubelet', node.name, !known || !boundedKubernetes(targetKubernetes) ? 'unknown' : allowed([...api, targetKubernetes]) ? 'pass' : 'fail',
      'Checks retaining this kubelet through the next control-plane hop; failure requires an earlier worker upgrade, not an impossible final target.',
      ['inventory.inventory.nodes', 'target.kubernetesVersion'], ['kubernetes-skew']);
  }
  if (!nodes.length) add('inventory.nodes', 'cluster', 'unknown', 'An empty node inventory cannot establish cluster compatibility.');
  const gpuNodes = nodes.filter(gpuNode);
  if (!gpuNodes.length) {
    add('gpu.observed', 'cluster', complete('nodes') && complete('pods') && !pods.some(pod => containers(pod).some(gpuResources)) &&
      !items.clusterPolicies.length && !items.nvidiaDrivers.length &&
      !target.gpuOperatorVersion && !target.driverVersion && !evidence.gpuOperator ? 'not_applicable' : 'unknown',
    'No GPU nodes observed; absence of labels is not a physical hardware attestation.');
  } else {
    const operator = evidence.gpuOperator;
    const selectedPolicies = items.clusterPolicies.filter(policy => policy.uid && policy.uid === operator?.policyUid);
    const policy = selectedPolicies.length === 1 ? selectedPolicies[0] : null;
    const policyKnown = complete('clusterPolicies') && items.clusterPolicies.length === 1 && policy && operator?.installation === 'cluster-policy' &&
      (complete('nvidiaDrivers') || inventory.coverage.nvidiaDrivers?.status === 'not_served') && !items.nvidiaDrivers.length;
    const operatorTarget = target.gpuOperatorVersion || operator?.version, matrixKnown = operatorTarget === rules.operator.version;
    add('gpu.operator-identity', 'cluster', policyKnown ? 'pass' : 'unknown', policyKnown ? 'One declared ClusterPolicy installation is identified.' :
      'Require an unambiguous ClusterPolicy installation; driver-CRD and mixed ownership are not modeled.', ['evidence.gpuOperator', 'inventory.inventory.clusterPolicies']);
    const from = version(operator?.version), to = version(operatorTarget);
    add('gpu.operator-transition', 'cluster', !policyKnown || !matrixKnown || !from || !to ||
      !['24.6', ...rules.operator.transitionFamilies].includes(from.slice(0, 2).join('.')) ? 'unknown' :
      rules.operator.transitionFamilies.includes(from.slice(0, 2).join('.')) && compare(to, from) >= 0 ? 'pass' : 'fail',
      'Only same-family or adjacent reviewed calendar-release transitions to the pinned Operator are covered; no downgrade.', ['evidence.gpuOperator', 'target.gpuOperatorVersion'], ['nvidia-platform']);
    add('gpu.operator-kubernetes', 'cluster', !matrixKnown || !targetKubernetes ? 'unknown' : targetKubernetes[0] === 1 &&
      targetKubernetes[1] >= rules.operator.kubernetesMinMinor && targetKubernetes[1] <= rules.operator.kubernetesMaxMinor ? 'pass' : 'fail',
      'The pinned Operator platform matrix covers Kubernetes 1.29–1.33.', ['target.kubernetesVersion', 'target.gpuOperatorVersion'], ['nvidia-platform']);
    const managed = policyKnown && policy.components?.driver?.enabled === true;
    add('gpu.driver-ownership', 'cluster', managed ? 'pass' : 'unknown', managed ? 'The selected policy explicitly enables managed drivers.' :
      'Missing/defaulted or externally managed drivers need a separate verified upgrade procedure.', ['inventory.inventory.clusterPolicies']);
    if (operatorTarget !== operator?.version) add('gpu.operator-operands', 'cluster', 'unknown',
      'A chart upgrade can change toolkit, plugin and driver defaults. Resolve rendered operand versions before sequencing.', ['target.gpuOperatorVersion']);
    const nodeDrivers = new Map();
    for (const node of [...gpuNodes].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const fact = evidence.nodes.find(value => value.nodeUid === node.uid);
      const labels = node.gpu.labels, observedDriver = labels['nvidia.com/cuda.driver-version.full'];
      const driverParts = version(fact?.driverVersion);
      const labelParts = [
        ['nvidia.com/cuda.driver-version.major', 'nvidia.com/cuda.driver-version.minor', 'nvidia.com/cuda.driver-version.revision'],
        ['nvidia.com/cuda.driver.major', 'nvidia.com/cuda.driver.minor', 'nvidia.com/cuda.driver.rev']
      ];
      const labelsAgree = driverParts && labelParts.every(keys => keys.every((key, index) => !Object.hasOwn(labels, key) ||
        /^\d+$/.test(labels[key]) && Number(labels[key]) === driverParts[index]));
      const os = typeof node.osImage === 'string' && /^Ubuntu (\d+\.\d+)(?:[.\s]|$)/.exec(node.osImage)?.[1];
      const factKnown = !!fact && labelsAgree && os === fact.osRelease && (!observedDriver || version(observedDriver) &&
        compare(version(observedDriver), driverParts) === 0) &&
        (policy?.driverConfiguration?.usePrecompiled == null || policy.driverConfiguration.usePrecompiled === fact.precompiled) &&
        (!policy?.driverConfiguration?.kernelModuleType || policy.driverConfiguration.kernelModuleType === fact.kernelModuleType) &&
        (policy?.driverConfiguration?.useOpenKernelModules == null || (policy.driverConfiguration.useOpenKernelModules ? 'open' : 'proprietary') === fact.kernelModuleType);
      add('gpu.node-evidence', node.name, factKnown ? 'pass' : 'unknown', factKnown ? 'Node-specific facts agree with available inventory.' :
        'Missing or conflicting OS/driver/configuration evidence; node labels alone are insufficient.', ['evidence.nodes', 'inventory.inventory.nodes']);
      const driver = target.driverVersion || (operatorTarget === operator?.version ? fact?.driverVersion : null);
      const driverVersion = version(driver), kernel = typeof node.kernelVersion === 'string' && /^(\d+\.\d+)\./.exec(node.kernelVersion)?.[1];
      const osRule = factKnown && rules.operator.ubuntu[fact.osRelease];
      if (factKnown && osRule && node.architecture === 'amd64' && driverVersion) nodeDrivers.set(node.uid, driverVersion);
      const platformKnown = matrixKnown && managed && osRule && node.architecture === rules.operator.architecture &&
        node.containerRuntimeVersion?.startsWith('containerd://') && rules.operator.gpuProducts.includes(labels['nvidia.com/gpu.product']);
      add('gpu.platform', node.name, platformKnown ? 'pass' : 'unknown', platformKnown ? 'Observed platform is in the narrowly reviewed matrix subset.' :
        'Platform, GPU product, architecture or management mode is outside the reviewed subset.', ['inventory.inventory.nodes', 'evidence.nodes'], ['nvidia-platform']);
      add('gpu.driver-listed', node.name, matrixKnown && factKnown && driverVersion && rules.operator.listedDrivers.includes(driver) ? 'pass' : 'unknown',
        'A listed driver is supported by this historical matrix; an unlisted driver is not automatically incompatible or recommended.', ['target.driverVersion', 'evidence.nodes'], ['nvidia-platform']);
      const kernelKnown = platformKnown && kernel && osRule.kernels.includes(kernel) && driverVersion;
      add('gpu.driver-kernel', node.name, !kernelKnown ? 'unknown' : fact.precompiled &&
        (!osRule.precompiledKernels.includes(kernel) || !rules.operator.precompiledDriverBranches[fact.osRelease].includes(driverVersion[0])) ? 'fail' : 'pass',
      'Checks documented kernel family and precompiled-driver branch constraints only, not module build or Secure Boot.', ['inventory.inventory.nodes', 'evidence.nodes', 'target.driverVersion'], ['nvidia-platform']);
    }
    for (const pod of [...pods].sort((a, b) => a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0)) {
      for (const container of containers(pod).filter(gpuResources)) {
        const fact = evidence.workloads.find(value => value.podUid === pod.uid && value.containerName === container.name);
        const node = nodes.find(value => value.name === pod.pod.nodeName);
        const subject = `${pod.namespace}/${pod.name}/${container.name}`;
        const bound = fact && /@sha256:[a-f0-9]{64}$/.test(fact.imageReference) && fact.imageReference === container.image &&
          !!container.imageID && fact.imageID === container.imageID;
        const driver = nodeDrivers.get(node?.uid);
        const cuda = bound && Object.hasOwn(rules.cuda, fact.cudaRelease) && rules.cuda[fact.cudaRelease];
        let verdict = 'unknown';
        if (cuda && driver && fact.compatibilityMode !== 'forward') {
          if (compare(driver, version(cuda.minorMinimumDriver)) < 0) verdict = 'fail';
          else if (compare(driver, version(cuda.nativeMinimumDriver)) >= 0) verdict = 'pass';
          // Meeting the minor floor alone does not prove PTX/features will run.
        }
        add('gpu.cuda-driver', subject, verdict, 'Checks the declared toolkit driver floor. Minor-only and forward compatibility need additional feature evidence; CUDA discovery labels are never workload evidence.',
          ['evidence.workloads', 'evidence.nodes', 'inventory.inventory.pods', 'target.driverVersion'], ['cuda-driver']);
      }
    }
    add('gpu.driver-disruption', 'cluster', 'unknown', 'Driver reloads interrupt GPU clients. No checkpoint, capacity or restore guarantee is established by these checks.',
      ['inventory.inventory.clusterPolicies', 'evidence.workloads'], ['driver-disruption']);
  }
  for (const pdb of items.disruptionBudgets) {
    const selection = pdb.podSelection;
    const known = complete('pods') && complete('disruptionBudgets') && selection?.status === 'complete' && Array.isArray(selection.matches) &&
      selection.matches.every(match => match?.uid && pods.some(pod => pod.uid === match.uid && pod.name === match.name &&
        pod.namespace === match.namespace && pod.namespace === pdb.namespace)) && unique(selection.matches.map(match => match.uid)) &&
      (selection.matches.length > 0 || pdb.expectedPods === 0) &&
      Number.isSafeInteger(pdb.generation) && pdb.generation >= 0 && pdb.observedGeneration === pdb.generation && Number.isSafeInteger(pdb.disruptionsAllowed) && pdb.disruptionsAllowed >= 0;
    add('disruption.pdb', `${pdb.namespace}/${pdb.name}`, !known ? 'unknown' : !selection.matches.length ? 'not_applicable' : pdb.disruptionsAllowed === 0 ? 'fail' : 'pass',
      'PDB budget snapshot only: zero does not permit general eviction of matching pods. Unhealthy-pod exceptions and drain feasibility are not evaluated; a positive count is not clearance.', ['inventory.inventory.disruptionBudgets']);
  }
  return finish();
}
