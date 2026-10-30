import { sameScanEvidence } from '../shared/scan-evidence.js';

// Scan/sync responses contain package data; job evidence is loaded separately.
// Preserve it across background scans and explicitly invalidate old revisions.
export function mergeDependencySnapshot(previous, next) {
  const job = next.rehearsal || previous?.rehearsal;
  if (!job || job.repository !== next.repository || job.installationId !== next.installationId) return { ...next, rehearsal: null };
  return { ...next, rehearsal: { ...job, stale: !sameScanEvidence(job, next) } };
}
