export function severityLevel(value) {
  const level = String(value || '').toLowerCase();
  if (level === 'moderate') return 'medium';
  return ['critical', 'high', 'medium', 'low'].includes(level) ? level : 'unknown';
}

export function severityRank(value) {
  return { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }[severityLevel(value)];
}
