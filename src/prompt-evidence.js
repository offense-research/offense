import { scanEvidenceKey } from '../shared/scan-evidence.js';

// Progress updates don't invalidate a prompt; changed scan or final evidence does.
export function promptEvidenceVersion(snapshot) {
  const rehearsal = snapshot?.rehearsal;
  return JSON.stringify([snapshot?.repository, snapshot?.installationId, snapshot?.revision,
    scanEvidenceKey(snapshot) || [snapshot?.scannedAt, snapshot?.vulnerabilityCheck?.checkedAt],
    rehearsal?.id, rehearsal?.status, rehearsal?.stale,
    ['completed', 'failed'].includes(rehearsal?.status) ? rehearsal?.updatedAt : null]);
}
