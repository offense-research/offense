import { ASSESSMENT_FAILURE_REASONS, assessmentFailureReason } from './assessment-egress.js';

const totalKey = 'assessment-network-failures';
const reasonsKey = 'assessment-network-failure-reasons';
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const duration = value => Number.isSafeInteger(value) && value >= 0 && value <= 60_000;

// Only fixed labels and bounded numeric summaries leave durable storage.
export function assessmentFailureSummary(kv, total = count(kv.get(totalKey))) {
  const stored = kv.get(reasonsKey), result = {};
  let remaining = count(total);
  for (const reason of ASSESSMENT_FAILURE_REASONS) {
    const value = stored?.[reason], n = Math.min(count(value?.count), remaining);
    if (!n) continue;
    result[reason] = { count: n };
    if (duration(value.minDurationMs) && duration(value.maxDurationMs) && value.minDurationMs <= value.maxDurationMs) {
      result[reason].minDurationMs = value.minDurationMs; result[reason].maxDurationMs = value.maxDurationMs;
    }
    remaining -= n;
  }
  if (remaining) result.unknown = { ...(result.unknown || {}), count: (result.unknown?.count || 0) + remaining };
  return result;
}

export function recordAssessmentFailure(kv, suppliedReason, durationMs) {
  const reason = assessmentFailureReason(suppliedReason), total = count(kv.get(totalKey));
  const reasons = assessmentFailureSummary(kv, total), previous = reasons[reason] || { count: 0 };
  const next = { count: previous.count + 1 };
  if (duration(durationMs)) {
    next.minDurationMs = Math.min(previous.minDurationMs ?? durationMs, durationMs);
    next.maxDurationMs = Math.max(previous.maxDurationMs ?? durationMs, durationMs);
  } else if (duration(previous.minDurationMs) && duration(previous.maxDurationMs)) {
    next.minDurationMs = previous.minDurationMs; next.maxDurationMs = previous.maxDurationMs;
  }
  reasons[reason] = next;
  kv.put(totalKey, total + 1); kv.put(reasonsKey, reasons);
}
