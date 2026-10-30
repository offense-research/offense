import path from 'node:path';
import { executeStackCommand } from './stack-collection.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const list = value => Array.isArray(value) ? value : [];
const text = value => typeof value === 'string' && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value) ? value : null;
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const bool = value => typeof value === 'boolean' ? value : null;
const pick = (value, keys, normalize = text) => Object.fromEntries(keys.map(key => [key, normalize(value?.[key])]));
const GPU_RESOURCE = /^nvidia\.com\/(?:gpu|mig-\d+g\.\d+gb)(?:\.shared)?$/;
const GPU_LABEL = /^nvidia\.com\/(?:gpu\.(?:present|product|count|family|memory|replicas|sharing-strategy|compute\.(?:major|minor))|cuda\.(?:driver\.(?:major|minor|rev)|driver-version\.(?:major|minor|revision|full)|runtime\.(?:major|minor)|runtime-version\.(?:major|minor|full))|mig\.(?:capable|strategy|config|config\.state)|mig-\d+g\.\d+gb\.(?:count|memory|replicas)|gfd\.timestamp)$/;
const MAX_ITEMS = 5000, MAX_BYTES = 64 * 1024 * 1024;
const POPEYE_SECTIONS = ['nodes', 'pods', 'jobs', 'poddisruptionbudgets', 'persistentvolumes', 'persistentvolumeclaims'];

export class KubernetesCollectionError extends Error {
  constructor(code, message) { super(message); this.name = 'KubernetesCollectionError'; this.code = code; }
}

export function kubernetesCollectionScope({ context, kubeconfig, withNova = false, withPopeye = false } = {}) {
  if (typeof context !== 'string' || !context || context.startsWith('-') || context.length > 512 || /[\x00-\x20\x7f]/.test(context))
    throw new KubernetesCollectionError('context_required', 'Choose an explicit trusted kubeconfig context with --context.');
  if (kubeconfig !== undefined && (typeof kubeconfig !== 'string' || !kubeconfig || /[\x00-\x1f\x7f]/.test(kubeconfig)))
    throw new KubernetesCollectionError('invalid_kubeconfig', 'Choose a local kubeconfig file.');
  return { context, ...(kubeconfig ? { kubeconfig: path.resolve(kubeconfig) } : {}), withNova, withPopeye,
    namespaces: 'all', access: 'Read-only Kubernetes API inventory. No exec, logs, node access, installs or mutations.',
    privacy: 'Private local output; no Offense upload. Resource names and image references remain sensitive.',
    prerequisites: 'Trust kubectl, optional tools, and kubeconfig authentication plugins; use a dedicated read-only identity.',
    optionalTools: {
      nova: withNova ? 'Reads Helm release Secrets locally and contacts the upstream chart metadata service. Newer is not compatible.' : 'not_requested',
      popeye: withPopeye ? 'Runs node, pod, job, disruption-budget and volume linters locally, including access-review POSTs and watches. Dependent reads may require additional RBAC.' : 'not_requested',
    } };
}

function identity(value) {
  if (!object(value) || !text(value.metadata?.name) || !text(value.kind) || !text(value.apiVersion)) throw Error('invalid resource');
  return { apiVersion: value.apiVersion, kind: value.kind, name: value.metadata.name,
    namespace: text(value.metadata.namespace), uid: text(value.metadata.uid), generation: count(value.metadata.generation) };
}

function resources(value, gpuOnly = false) {
  return Object.fromEntries(Object.entries(object(value) ? value : {}).filter(([key, val]) =>
    (GPU_RESOURCE.test(key) || !gpuOnly && ['cpu', 'memory', 'ephemeral-storage', 'pods'].includes(key)) && text(val) !== null));
}

function conditions(value) {
  return list(value).map(item => pick(item, ['type', 'status', 'reason', 'lastTransitionTime']));
}

function node(value) {
  const labels = Object.fromEntries(Object.entries(value.metadata?.labels || {}).filter(([key, val]) => GPU_LABEL.test(key) && text(val) !== null));
  return { ...identity(value), ...pick(value.status?.nodeInfo, ['kubeletVersion', 'kubeProxyVersion', 'osImage', 'kernelVersion', 'containerRuntimeVersion', 'architecture', 'operatingSystem']),
    roles: ['control-plane', 'master', 'worker'].filter(role => Object.hasOwn(value.metadata?.labels || {}, 'node-role.kubernetes.io/' + role)),
    unschedulable: value.spec?.unschedulable === true, conditions: conditions(value.status?.conditions),
    capacity: resources(value.status?.capacity), allocatable: resources(value.status?.allocatable),
    gpu: { source: 'Kubernetes node labels and advertised resources; not a host probe', labels,
      capacity: resources(value.status?.capacity, true), allocatable: resources(value.status?.allocatable, true) } };
}

function podSpec(spec, status = {}) {
  const containers = (values, statuses) => list(values).map(container => {
    const observed = list(statuses).find(item => item.name === container.name);
    return { name: text(container.name), image: text(container.image), requests: resources(container.resources?.requests),
      limits: resources(container.resources?.limits), imageID: text(observed?.imageID), ready: bool(observed?.ready),
      restartCount: count(observed?.restartCount), state: ['running', 'waiting', 'terminated'].find(key => object(observed?.state?.[key])) || null };
  });
  return { nodeName: text(spec?.nodeName), runtimeClassName: text(spec?.runtimeClassName),
    containers: containers(spec?.containers, status.containerStatuses), initContainers: containers(spec?.initContainers, status.initContainerStatuses),
    ephemeralContainers: containers(spec?.ephemeralContainers, status.ephemeralContainerStatuses),
    persistentVolumeClaims: list(spec?.volumes).flatMap(volume => text(volume.persistentVolumeClaim?.claimName) ? [volume.persistentVolumeClaim.claimName] : []) };
}

function workload(value) {
  const pod = value.kind === 'Pod', cron = value.kind === 'CronJob';
  const spec = cron ? value.spec?.jobTemplate?.spec : value.spec;
  return { ...identity(value), owners: list(value.metadata?.ownerReferences).map(owner => pick(owner, ['apiVersion', 'kind', 'name', 'uid'])),
    phase: text(value.status?.phase), conditions: conditions(value.status?.conditions),
    desired: pick(spec, ['replicas', 'parallelism', 'completions'], count), suspend: bool(value.spec?.suspend),
    observed: pick(value.status, ['observedGeneration', 'replicas', 'readyReplicas', 'availableReplicas', 'desiredNumberScheduled', 'numberReady', 'active', 'succeeded', 'failed'], count),
    pod: podSpec(pod ? value.spec : spec?.template?.spec, pod ? value.status : {}) };
}

function storage(value) {
  const spec = value.spec || {};
  return { ...identity(value), phase: text(value.status?.phase),
    storageClassName: text(spec.storageClassName), volumeName: text(spec.volumeName),
    claim: spec.claimRef ? pick(spec.claimRef, ['name', 'namespace', 'uid']) : null,
    capacity: text(spec.capacity?.storage || value.status?.capacity?.storage), requested: text(spec.resources?.requests?.storage),
    accessModes: list(spec.accessModes).filter(mode => ['ReadWriteOnce', 'ReadOnlyMany', 'ReadWriteMany', 'ReadWriteOncePod'].includes(mode)),
    volumeMode: text(spec.volumeMode), reclaimPolicy: text(value.reclaimPolicy || spec.persistentVolumeReclaimPolicy),
    provisioner: text(value.provisioner), csiDriver: text(spec.csi?.driver),
    volumeBindingMode: text(value.volumeBindingMode), allowVolumeExpansion: bool(value.allowVolumeExpansion),
    defaultClass: value.metadata?.annotations?.['storageclass.kubernetes.io/is-default-class'] === 'true' };
}

function policy(value) {
  const components = {};
  for (const name of ['driver', 'toolkit', 'devicePlugin', 'gfd', 'migManager', 'dcgm', 'dcgmExporter', 'validator']) {
    if (object(value.spec?.[name])) components[name] = { ...pick(value.spec[name], ['version', 'repository', 'image']), enabled: bool(value.spec[name].enabled) };
  }
  const driver = value.kind === 'ClusterPolicy' ? value.spec?.driver : value.spec;
  const upgrade = driver?.upgradePolicy;
  const deletion = section => ({ ...pick(section, ['force', 'deleteEmptyDir', 'enable'], bool),
    timeoutSeconds: count(section?.timeoutSeconds), selectorConfigured: typeof section?.podSelector === 'string' ? !!section.podSelector : null });
  return { ...identity(value), components, migStrategy: text(value.spec?.mig?.strategy),
    driver: pick(value.spec, ['driverType', 'version', 'repository', 'image']),
    driverConfiguration: { kernelModuleType: text(driver?.kernelModuleType), useOpenKernelModules: bool(driver?.useOpenKernelModules),
      usePrecompiled: bool(driver?.usePrecompiled), updateStrategy: text(value.spec?.daemonsets?.updateStrategy),
      upgradePolicy: object(upgrade) ? { autoUpgrade: bool(upgrade.autoUpgrade), maxParallelUpgrades: count(upgrade.maxParallelUpgrades),
        maxUnavailable: count(upgrade.maxUnavailable) ?? (/^(?:100|\d{1,2})%$/.test(upgrade.maxUnavailable) ? upgrade.maxUnavailable : null),
        waitForCompletion: deletion(upgrade.waitForCompletion), gpuPodDeletion: deletion(upgrade.gpuPodDeletion),
        podDeletion: deletion(upgrade.podDeletion), drain: deletion(upgrade.drain) } : null },
    state: text(value.status?.state), conditions: conditions(value.status?.conditions) };
}

// Evaluate selectors while raw labels are still local. Persist only resource
// references, never arbitrary selector keys/values or labels.
function selectorMatches(selector, labels) {
  if (selector == null) return false; // policy/v1 nil selector selects no pods.
  if (!object(selector) || Object.keys(selector).some(key => !['matchLabels', 'matchExpressions'].includes(key)) ||
      selector.matchLabels !== undefined && !object(selector.matchLabels) ||
      selector.matchExpressions !== undefined && !Array.isArray(selector.matchExpressions)) throw Error('invalid selector');
  const entries = Object.entries(selector.matchLabels || {}), expressions = selector.matchExpressions || [];
  if (entries.length + expressions.length > 64) throw Error('selector limit');
  const requirements = entries.map(([key, value]) => ({ key, operator: 'In', values: [value] })).concat(expressions);
  return requirements.map(requirement => {
    const { key, operator, values } = requirement || {};
    if (!text(key) || !['In', 'NotIn', 'Exists', 'DoesNotExist'].includes(operator) ||
        (['In', 'NotIn'].includes(operator) ? !Array.isArray(values) || !values.length || values.length > 64 || values.some(value => text(value) === null) :
          values !== undefined && (!Array.isArray(values) || values.length))) throw Error('invalid selector');
    const present = Object.hasOwn(labels, key);
    return operator === 'Exists' ? present : operator === 'DoesNotExist' ? !present :
      operator === 'In' ? present && values.includes(labels[key]) : !present || !values.includes(labels[key]);
  }).every(Boolean);
}

const RESOURCES = [
  ['nodes', '/api/v1/nodes', node],
  ['namespaces', '/api/v1/namespaces', identity],
  ['pods', '/api/v1/pods', workload],
  ['deployments', '/apis/apps/v1/deployments', workload],
  ['daemonSets', '/apis/apps/v1/daemonsets', workload],
  ['statefulSets', '/apis/apps/v1/statefulsets', workload],
  ['jobs', '/apis/batch/v1/jobs', workload],
  ['cronJobs', '/apis/batch/v1/cronjobs', workload],
  ['disruptionBudgets', '/apis/policy/v1/poddisruptionbudgets', value => ({ ...identity(value),
    minAvailable: typeof value.spec?.minAvailable === 'number' ? count(value.spec.minAvailable) : text(value.spec?.minAvailable),
    maxUnavailable: typeof value.spec?.maxUnavailable === 'number' ? count(value.spec.maxUnavailable) : text(value.spec?.maxUnavailable),
    ...pick(value.status, ['observedGeneration', 'disruptionsAllowed', 'currentHealthy', 'desiredHealthy', 'expectedPods'], count),
    conditions: conditions(value.status?.conditions) })],
  ['persistentVolumes', '/api/v1/persistentvolumes', storage],
  ['persistentVolumeClaims', '/api/v1/persistentvolumeclaims', storage],
  ['storageClasses', '/apis/storage.k8s.io/v1/storageclasses', storage],
  ['csiDrivers', '/apis/storage.k8s.io/v1/csidrivers', value => ({ ...identity(value), ...pick(value.spec, ['attachRequired', 'podInfoOnMount', 'storageCapacity'], bool) })],
];

function novaReport(value) {
  // Nova's stdout is an array, unlike its --output-file wrapper object.
  if (!Array.isArray(value) || value.length > MAX_ITEMS) throw Error('invalid nova report');
  return value.map(release => {
    if (!text(release.release) || !text(release.chartName) || !text(release.Installed?.version)) throw Error('invalid release');
    return { release: release.release, chart: release.chartName, namespace: text(release.namespace),
      installed: pick(release.Installed, ['version', 'appVersion', 'kubeVersion']), latest: pick(release.Latest, ['version', 'appVersion', 'kubeVersion']),
      outdated: bool(release.outdated), deprecated: bool(release.deprecated) };
  });
}

function popeyeReport(value) {
  const report = value?.popeye;
  if (!object(report) || !Array.isArray(report.sections) || report.sections.length > 50) throw Error('invalid popeye report');
  let issues = 0;
  const sections = report.sections.map(section => {
    if (!text(section.gvr) || !object(section.tally) ||
        ['ok', 'info', 'warning', 'error', 'score'].some(key => count(section.tally[key]) === null)) throw Error('invalid section');
    return { gvr: section.gvr, tally: pick(section.tally, ['ok', 'info', 'warning', 'error', 'score'], count),
      issues: Object.entries(section.issues || {}).flatMap(([resource, entries]) => {
        if (!text(resource) || !Array.isArray(entries)) throw Error('invalid issues');
        return entries.map(issue => {
          if (++issues > MAX_ITEMS || ![0, 1, 2, 3].includes(issue.level)) throw Error('invalid issue');
          return { resource, level: issue.level, code: /^\[POP-\d+\]/.exec(issue.message || '')?.[0] || null };
        });
      }) };
  });
  return { score: count(report.score), sections, hasErrors: Boolean(report.errors && Object.keys(report.errors).length) };
}

// kubectl's raw GET avoids discovery caches and never invokes apply, auth checks
// (which POST), exec, logs or a node process. Credentials stay with kubeconfig.
export async function collectKubernetesInventory(options = {}, { execute = executeStackCommand, now = Date.now } = {}) {
  const scope = kubernetesCollectionScope(options), start = now(), deadline = start + 180_000;
  const snapshot = { schemaVersion: 'offense.kubernetes.inventory.v1', capturedAt: new Date(start).toISOString(),
    evidenceVersion: 1,
    scope, status: 'partial', server: null, inventory: {}, coverage: {}, gaps: [],
    tools: { nova: { status: 'not_requested' }, popeye: { status: 'not_requested' } },
    assurance: 'Observed inventory only, not vulnerability clearance, hardware attestation or upgrade compatibility. Reads are not an atomic cluster snapshot.' };
  const common = ['--context', scope.context, ...(scope.kubeconfig ? ['--kubeconfig', scope.kubeconfig] : [])];
  const podLabels = new Map(), nodeLabels = new Map(), selectors = [];
  let bytes = 0;
  function gap(source, code) { snapshot.gaps.push({ source, code }); }
  async function json(command, args, timeout, accepted = [0]) {
    const result = await execute(command, args, { maxBuffer: 8 * 1024 * 1024, timeout });
    if (!accepted.includes(result?.code)) throw new KubernetesCollectionError('command_failed', 'A local collection command failed.');
    const data = Buffer.from(result.stdout || ''); bytes += data.length;
    if (data.length > 8 * 1024 * 1024 || bytes > MAX_BYTES) throw new KubernetesCollectionError('output_limit', 'Collection exceeded its output limit.');
    // Nova emits this exact non-JSON sentinel even with --format=json.
    if (command === 'nova' && data.toString('utf8').trim() === 'No releases found') return [];
    try { return JSON.parse(data.toString('utf8')); }
    catch { throw new KubernetesCollectionError('invalid_response', 'A local command returned unsupported JSON.'); }
  }
  async function get(endpoint) {
    if (now() >= deadline || bytes > MAX_BYTES) throw new KubernetesCollectionError('collection_limit', 'Collection reached its time or size limit.');
    return await json('kubectl', [...common, '--request-timeout=15s', 'get', '--raw', endpoint], Math.min(20_000, deadline - now()));
  }
  const failure = error => ['command_timeout', 'command_unavailable', 'command_output_limit', 'output_limit', 'collection_limit', 'invalid_response'].includes(error?.code) ? error.code : 'read_unavailable';
  async function collect(name, endpoint, normalize) {
    const items = [], seen = new Set(); let continuation = '', version;
    const coverage = snapshot.coverage[name] = { status: 'complete', endpoint, count: 0 };
    snapshot.inventory[name] = items;
    try {
      do {
        const query = new URLSearchParams({ limit: '500', ...(continuation ? { continue: continuation } : {}) });
        const page = await get(endpoint + '?' + query);
        if (!object(page) || !Array.isArray(page.items) || !object(page.metadata) || !text(page.metadata.resourceVersion) ||
            !text(page.apiVersion) || !/^[A-Za-z]+List$/.test(page.kind || '') ||
            page.metadata.continue !== undefined && typeof page.metadata.continue !== 'string') throw Error('invalid list');
        if (version !== undefined && version !== page.metadata.resourceVersion) throw Error('inconsistent list');
        coverage.resourceVersion = version = page.metadata.resourceVersion;
        for (const value of page.items) {
          if (items.length >= MAX_ITEMS) throw new KubernetesCollectionError('output_limit', 'Resource limit reached.');
          const item = normalize({ apiVersion: page.apiVersion, kind: page.kind.slice(0, -4), ...value });
          items.push(item);
          if (name === 'pods') podLabels.set(item, value.metadata?.labels || {});
          if (name === 'nodes') nodeLabels.set(item, value.metadata?.labels || {});
          if (name === 'disruptionBudgets') selectors.push({ item, selector: value.spec?.selector, resource: 'pods' });
          if (name === 'nvidiaDrivers') selectors.push({ item, selector: { matchLabels: value.spec?.nodeSelector || {} }, resource: 'nodes' });
        }
        continuation = page.metadata.continue || '';
        if (continuation.length > 16_384 || continuation && seen.has(continuation) || seen.size >= 20) throw Error('invalid continuation');
        seen.add(continuation);
      } while (continuation);
    } catch (error) { coverage.status = items.length ? 'partial' : 'unavailable'; gap(name, failure(error)); }
    coverage.count = items.length;
    coverage.observedAt = new Date(now()).toISOString();
  }
  try {
    const value = await get('/version');
    if (!text(value?.gitVersion)) throw Error('invalid version');
    snapshot.server = pick(value, ['gitVersion', 'platform']); snapshot.coverage.server = { status: 'complete', endpoint: '/version' };
  } catch (error) { snapshot.coverage.server = { status: 'unavailable', endpoint: '/version' }; gap('server', failure(error)); }
  for (const [name, endpoint, normalize] of RESOURCES) await collect(name, endpoint, normalize);
  let nvidiaVersions;
  try {
    const groups = await get('/apis');
    if (!Array.isArray(groups?.groups)) throw Error('invalid discovery');
    const nvidia = groups.groups.find(group => group.name === 'nvidia.com');
    if (nvidia && !Array.isArray(nvidia.versions)) throw Error('invalid discovery');
    nvidiaVersions = nvidia ? nvidia.versions.map(version => version.groupVersion) : [];
  } catch (error) { gap('nvidiaDiscovery', failure(error)); }
  for (const [name, resource, version] of [['clusterPolicies', 'clusterpolicies', 'v1'], ['nvidiaDrivers', 'nvidiadrivers', 'v1alpha1']]) {
    const endpoint = '/apis/nvidia.com/' + version;
    snapshot.inventory[name] = [];
    try {
      if (!nvidiaVersions) throw Error('discovery unavailable');
      let advertised = [];
      if (nvidiaVersions.includes('nvidia.com/' + version)) {
        const discovery = await get(endpoint);
        if (!Array.isArray(discovery?.resources)) throw Error('invalid discovery');
        advertised = discovery.resources;
      }
      const entry = advertised.find(item => item.name === resource);
      if (entry) {
        if (entry.namespaced !== false || !list(entry.verbs).includes('list')) throw Error('unsupported resource');
        await collect(name, endpoint + '/' + resource, policy);
      } else snapshot.coverage[name] = { status: 'not_served', endpoint };
    } catch (error) {
      snapshot.coverage[name] = { status: 'unavailable', endpoint }; gap(name, failure(error));
    }
  }
  const gpuNodes = snapshot.inventory.nodes.filter(item => Object.keys(item.gpu.capacity).length || Object.keys(item.gpu.allocatable).length ||
    item.gpu.labels['nvidia.com/gpu.present'] === 'true' || item.gpu.labels['nvidia.com/gpu.product'] ||
    Number(item.gpu.labels['nvidia.com/gpu.count']) > 0 || item.gpu.labels['nvidia.com/mig.capable'] === 'true');
  snapshot.gpu = { observedNodes: gpuNodes.map(item => item.name), physicalDeviceCount: null,
    note: 'Advertised GPU/MIG units can be shared replicas or partitions, not physical device counts. CUDA labels are discovery claims, not workload CUDA versions.' };
  let comparisons = 0;
  for (const { item, selector, resource } of selectors) {
    const selection = { status: 'complete', matches: [], source: resource,
      note: 'Selector matches in this non-atomic snapshot, not eviction clearance or driver ownership.' };
    item[resource === 'pods' ? 'podSelection' : 'nodeSelection'] = selection;
    try {
      selectorMatches(selector, {}); // Validate even when the selected list is empty.
      for (const [candidate, labels] of resource === 'pods' ? podLabels : nodeLabels) {
        if (resource === 'pods' && candidate.namespace !== item.namespace) continue;
        if (++comparisons > 100_000 || now() >= deadline) throw Error('selection limit');
        if (selectorMatches(selector, labels)) selection.matches.push(pick(candidate, ['name', 'namespace', 'uid']));
      }
      if (snapshot.coverage[resource]?.status !== 'complete') selection.status = 'partial';
    } catch { selection.status = 'partial'; }
    if (selection.status !== 'complete') gap('selection', 'incomplete:' + item.kind + ':' + item.name);
  }
  for (const item of gpuNodes) {
    const labels = item.gpu.labels;
    if (!labels['nvidia.com/gpu.product'] || !(labels['nvidia.com/cuda.driver-version.full'] ||
        labels['nvidia.com/cuda.driver-version.major'] && labels['nvidia.com/cuda.driver-version.minor'] ||
        labels['nvidia.com/cuda.driver.major'] && labels['nvidia.com/cuda.driver.minor'])) gap('gpu', 'discovery_metadata_missing:' + item.name);
  }
  for (const tool of ['nova', 'popeye']) {
    if (!(tool === 'nova' ? scope.withNova : scope.withPopeye)) continue;
    try {
      if (bytes > MAX_BYTES) throw new KubernetesCollectionError('output_limit', 'Collection exceeded its output limit.');
      const args = tool === 'nova' ? ['find', ...common, '--format=json', '--include-all', '--helm'] :
        [...common, '--all-namespaces', '--out=json', '--sections=' + POPEYE_SECTIONS.join(','), '--request-timeout=15s', '--logs', 'none', '--log-level=0'];
      const value = await json(tool, args, 120_000, tool === 'popeye' ? [0, 1] : [0]);
      const report = tool === 'nova' ? novaReport(value) : popeyeReport(value);
      const partial = tool === 'popeye' ? report.hasErrors || report.sections.some(section =>
        section.issues.some(issue => ['[POP-402]', '[POP-404]', '[POP-666]', '[POP-708]'].includes(issue.code))) ||
        POPEYE_SECTIONS.some(name => !report.sections.some(section => section.gvr.split('/').at(-1) === name)) :
        report.some(item => !item.latest.version);
      snapshot.tools[tool] = { status: partial ? 'partial' : 'complete', report };
      if (partial) gap(tool, 'tool_coverage_incomplete');
    } catch (error) { snapshot.tools[tool] = { status: 'unavailable' }; gap(tool, failure(error)); }
  }
  snapshot.status = snapshot.gaps.length ? 'partial' : 'complete';
  snapshot.finishedAt = new Date(now()).toISOString();
  return snapshot;
}
