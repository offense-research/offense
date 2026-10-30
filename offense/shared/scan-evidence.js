// Browser-safe comparison of server-bound scan content. Observation timestamps
// remain available for audit; they are not content identities.
export const MAX_SCAN_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;

export function scanEvidenceKey(value) {
  return typeof value?.evidenceIdentity === 'string' && /^[a-f0-9]{64}$/.test(value.evidenceIdentity)
    ? value.evidenceIdentity : null;
}

export function sameScanEvidence(evidence, snapshot, now = Date.now()) {
  if (!evidence || !snapshot || evidence.repository !== snapshot.repository ||
    Number(evidence.installationId) !== Number(snapshot.installationId) ||
    (evidence.revision ?? evidence.snapshotRevision) !== snapshot.revision) return false;
  const observedAt = evidence.createdAt ?? evidence.plannedAt;
  if (Number.isFinite(observedAt) && (now - observedAt > MAX_SCAN_EVIDENCE_AGE_MS || observedAt > now + 60_000)) return false;
  const expected = scanEvidenceKey(evidence), current = scanEvidenceKey(snapshot);
  if (expected && current) return expected === current;
  // Older jobs/plans did not bind content. Keep their original stricter rule.
  return (evidence.scannedAt ?? evidence.snapshotScannedAt) === snapshot.scannedAt &&
    evidence.advisoryCheckedAt === snapshot.vulnerabilityCheck?.checkedAt;
}
