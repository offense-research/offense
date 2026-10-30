# Kubernetes and GPU compatibility evidence

`shared/kubernetes-evidence.js` defines the validated evidence and target
contracts. `shared/kubernetes-compatibility.js` exports the synchronous,
read-only `assessKubernetesCompatibility({ inventory, evidence, target, asOf })`.
It performs no network/filesystem access, cluster commands, model calls, or
mutations. Identical inputs and rule bundle produce identical reports.

This is a library, not yet an `offense k8s plan` command or hosted API. It checks
named constraints on observed state and a proposed endpoint. It does **not**
search intermediate versions, choose a sequence, or execute an upgrade.

## Inputs bind declarations to one snapshot

- `inventory`: the collector's `offense.kubernetes.inventory.v1` snapshot.
  Older v1 snapshots are accepted; missing newer facts remain unknown.
- `evidence`: strict `offense.kubernetes.evidence.v1`, with
  `inventorySha256: kubernetesEvidenceDigest(inventory)`. Recollecting or editing
  the snapshot requires reviewing and rebinding the supplemental evidence.
- `target`: strict `offense.kubernetes.target.v1`, required `kubernetesVersion`
  and optional `gpuOperatorVersion` / `driverVersion`. Versions must be exact
  releases for assessment; provider suffixes are not stripped into assumed
  upstream compatibility. Unknown target fields are rejected.
- `asOf`: an explicit ISO timestamp, supplied by the caller, never the machine
  clock. The caller is responsible for using the actual assessment time.

Every supplemental fact has a `source` with `kind` (`operator-declaration`,
`command-output`, or `build-metadata`), lowercase 64-hex `artifactSha256`, and
ISO `observedAt`. Retain the original artifacts privately for review. The
library does not fetch artifacts or authenticate their contents. Hashes bind
content, **not truth, signatures, or trusted identity**.

| Supplemental field | Required contents when supplied |
| --- | --- |
| `profile` | `manager`, `platform`, source. Currently only `kubeadm` / `bare-metal-pcie` is modeled. |
| `controlPlane` | `complete`, all `apiServers: [{ id, version }]`, source. The observed `/version` must match one server. Optional `kubeadmVersion` and `etcdVersion` are retained but not evaluated yet. |
| `gpuOperator` | Explicit installed `version`, `installation: 'cluster-policy'`, selected `policyUid`, source. Missing/defaulted or mixed driver ownership is not clearance. |
| `nodes[]` | `nodeUid`, Ubuntu `osRelease`, `driverVersion`, `kernelModuleType` (`open`, `proprietary`, `auto`, `unknown`), `precompiled`, source. UID must exist and available discovery/policy facts must agree. |
| `workloads[]` | `podUid`, `containerName`, digest-pinned `imageReference`, exact observed `imageID`, `cudaRelease`, `compatibilityMode` (`native`, `minor`, `forward`), source. Optional `usesPtx`, `requiresNewerDriverFeatures`, `interruption`, `restoreTestSha256` reserve evidence for later checks, not approval today. |

Node and workload arrays default to empty, not inferred facts. Duplicate or
unmatched identities invalidate assessment. Workload facts match regular, init,
and ephemeral containers requesting NVIDIA resources. GPU workloads without
advertised NVIDIA resources are not discovered by these checks. CUDA node
labels never substitute for an application's toolkit requirements. Runtime
image IDs are opaque: they must match, but are not assumed to be registry
manifest digests.

The digest function canonicalizes JSON object keys while retaining array order.
It rejects non-JSON values, nesting deeper than 40, and serialized inputs over
64 MiB. Schemas bound resource arrays and text. Inventory, observation times,
and supplemental facts must fall within 24 hours before `asOf`, with a
five-minute future tolerance. This freshness policy is an initial assessment
policy, not a vendor guarantee. Resource reads remain non-atomic.

## Example library call

Run from the repository on Node.js 24+. These are privately prepared local JSON
files, not automatic evidence discovery; `supplemental-evidence.json` must
already contain the reviewed snapshot binding and facts described above.

```js
import { readFile } from 'node:fs/promises';
import { assessKubernetesCompatibility } from './shared/kubernetes-compatibility.js';

const inventory = JSON.parse(await readFile('/private/reports/kubernetes-inventory.json', 'utf8'));
const evidence = JSON.parse(await readFile('/private/reports/supplemental-evidence.json', 'utf8'));
const report = assessKubernetesCompatibility({
  inventory,
  evidence,
  target: { schemaVersion: 'offense.kubernetes.target.v1', kubernetesVersion: '1.33.1' },
  asOf: new Date().toISOString()
});
console.log(JSON.stringify(report, null, 2));
```

The example target illustrates the pinned historical rules, not a recommendation
to install that Kubernetes release.

## Reports explain constraints, not rollout approval

`offense.kubernetes.compatibility.v1` reports contain engine/rule versions,
evaluation time, inventory/evidence/target/rules digests, and individual checks
with ID, subject, verdict, reason, evidence paths, and applicable source URLs,
document hashes, and sections. Invalid inputs produce a generic unknown result,
not an echo of potentially sensitive malformed fields. Valid resource names
and subjects are still sensitive; review reports before sharing.

- `pass`: the named constraint holds on the supplied evidence.
- `fail`: a modeled constraint is violated. For example, an old kubelet may
  block retaining workers during the next control-plane hop; that does not
  prove the final target is unreachable after an earlier worker upgrade.
- `unknown`: evidence or reviewed rules are insufficient, stale, or conflicting.
- `not_applicable`: a constraint does not apply to the observed scope.

The aggregate verdict prefers fail, then unknown, then pass. It never erases
individual unknowns. Every report includes `upgradeSafe: false`,
`rolloutReadiness: 'not_evaluated'`, and `sequence: null`, even when every named
constraint passes. GPU driver disruption always remains unknown: the existence
of checkpoint/restore declarations does not verify recovery. A positive PDB
disruption count is not node-drain clearance.

## Reviewed subset and rule maintenance

`config/kubernetes-compatibility.json` pins historical source documents and
their SHA-256 hashes. Initial coverage is deliberately limited:

- Kubernetes API servers 1.29–1.33: HA minor skew, no minor skipping/downgrades,
  kubelet skew (kubelets 1.25+), and retaining current kubelets through the next
  control-plane hop.
- GPU Operator 25.3.2: same-family / adjacent 24.9-family transition rules,
  Kubernetes platform range, explicit ClusterPolicy driver management.
- Ubuntu 22.04/24.04, containerd, amd64, bare-metal PCIe, NVIDIA-A100/Tesla-T4
  discovery labels; selected kernel families, exact listed drivers, and
  precompiled-kernel/driver-branch constraints. No blanket NVIDIA GPU support.
- CUDA 12.4.0/12.4.1 Linux driver floors, bound to the workload image and its
  observed node. A driver meeting only the minor-compatibility floor remains
  unknown; forward compatibility is not modeled.
- PDB snapshot membership, current observed generation and allowed disruptions.

This is **not** a current security-support matrix, CVE-remediation guarantee,
or compliance deadline engine. Module builds, Secure Boot, exact GPU board
requirements, all Operator operands, addons, storage/network drivers,
controller-manager/scheduler/kube-proxy/etcd, capacity and recovery remain
explicitly unevaluated.

Rules have an initial 30-day review window ending 2026-11-28T00:00:00Z. Outside
it, fresh observations still return unknown. To extend coverage or review the
bundle, read the version-specific upstream documents, update their content
hashes and rule version/dates, and add boundary cases that distinguish support
from unsupported assumptions. Do not merely advance the review date, treat
component defaults as exhaustive compatibility rules, or let model output
override deterministic unknowns/failures.
