import { createHash } from 'node:crypto';
import { z } from 'zod';

const text = z.string().min(1).max(512).regex(/^[^\x00-\x1f\x7f]+$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const source = z.strictObject({ kind: z.enum(['operator-declaration', 'command-output', 'build-metadata']),
  artifactSha256: digest, observedAt: z.iso.datetime() });
const fact = shape => z.strictObject({ ...shape, source });
const resource = z.looseObject({ name: text, uid: text.nullish(), namespace: text.nullish() });
const rows = item => z.array(item).max(5000);
const quantities = z.record(z.string(), z.string());
const container = z.looseObject({ name: text, image: text.nullish(), imageID: text.nullish(),
  requests: quantities.optional(), limits: quantities.optional() });
export const kubernetesInventorySchema = z.looseObject({
  schemaVersion: z.literal('offense.kubernetes.inventory.v1'), capturedAt: z.iso.datetime(),
  inventory: z.looseObject({
    nodes: rows(resource.extend({ kubeletVersion: text.nullish(), osImage: text.nullish(), kernelVersion: text.nullish(),
      containerRuntimeVersion: text.nullish(), architecture: text.nullish(),
      gpu: z.looseObject({ labels: quantities, capacity: quantities, allocatable: quantities }).optional() })),
    pods: rows(resource.extend({ pod: z.looseObject({ nodeName: text.nullish(), containers: rows(container),
      initContainers: rows(container).optional(), ephemeralContainers: rows(container).optional() }) })),
    clusterPolicies: rows(resource), nvidiaDrivers: rows(resource), disruptionBudgets: rows(resource)
  }),
  coverage: z.record(z.string(), z.looseObject({ status: text, observedAt: z.iso.datetime().optional() }))
});

// Supplemental facts are supplied evidence, not independently attested facts.
// Bind them to the entire snapshot and to resource UIDs, never just node names.
export const kubernetesEvidenceSchema = z.strictObject({
  schemaVersion: z.literal('offense.kubernetes.evidence.v1'), inventorySha256: digest,
  profile: fact({ manager: text, platform: text }).optional(),
  controlPlane: fact({ complete: z.boolean(), apiServers: z.array(z.strictObject({ id: text, version: text })).min(1).max(20),
    kubeadmVersion: text.optional(), etcdVersion: text.optional() }).optional(),
  gpuOperator: fact({ version: text, installation: text, policyUid: text }).optional(),
  nodes: z.array(fact({ nodeUid: text, osRelease: text, driverVersion: text,
    kernelModuleType: z.enum(['open', 'proprietary', 'auto', 'unknown']), precompiled: z.boolean() })).max(5000).default([]),
  workloads: z.array(fact({ podUid: text, containerName: text, imageReference: text, imageID: text,
    cudaRelease: text, compatibilityMode: z.enum(['native', 'minor', 'forward']),
    usesPtx: z.boolean().optional(), requiresNewerDriverFeatures: z.boolean().optional(),
    interruption: z.enum(['none', 'restart', 'checkpoint-and-restart', 'unknown']).optional(),
    restoreTestSha256: digest.optional() })).max(5000).default([])
});

export const kubernetesTargetSchema = z.strictObject({ schemaVersion: z.literal('offense.kubernetes.target.v1'),
  kubernetesVersion: text, gpuOperatorVersion: text.optional(), driverVersion: text.optional() });

// JSON-only, bounded canonicalization: no filesystem, network or clock access.
// Object key ordering is immaterial; array ordering remains part of the evidence.
export function kubernetesEvidenceDigest(value) {
  function canonical(item, depth = 0) {
    if (depth > 40) throw new Error('Kubernetes evidence exceeds the nesting limit.');
    if (item === null || typeof item === 'string' || typeof item === 'boolean' || typeof item === 'number' && Number.isFinite(item)) return item;
    if (Array.isArray(item)) return item.map(child => canonical(child, depth + 1));
    if (item && Object.getPrototypeOf(item) === Object.prototype) return Object.fromEntries(Object.keys(item).sort()
      .map(key => [key, canonical(item[key], depth + 1)]));
    throw new Error('Kubernetes evidence must contain only JSON values.');
  }
  const bytes = JSON.stringify(canonical(value));
  if (Buffer.byteLength(bytes) > 64 * 1024 * 1024) throw new Error('Kubernetes evidence exceeds the size limit.');
  return createHash('sha256').update(bytes).digest('hex');
}
