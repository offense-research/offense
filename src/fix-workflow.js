import { findingReadiness } from './finding-readiness.js';

export function fixPathSummary(findings, plans = [], errors = []) {
  const packages = [...new Map(findings.map(finding => [`${finding.package}\0${finding.version}`, finding])).values()];
  const counts = { checked: 0, blocked: 0, pending: 0 };
  for (const finding of packages) {
    const plan = plans.find(value => value.name === finding.package && value.currentVersion === finding.version);
    const failed = errors.some(value => value.name === finding.package && value.version === finding.version);
    const readiness = findingReadiness(finding, plan);
    counts[failed || ['blocked', 'unknown'].includes(readiness.state) ? 'blocked' : readiness.state === 'unplanned' ? 'pending' : 'checked']++;
  }
  return { ...counts, total: packages.length, text: [counts.checked && `${counts.checked} ${counts.checked === 1 ? 'path' : 'paths'} checked`,
    counts.blocked && `${counts.blocked} ${counts.blocked === 1 ? 'needs' : 'need'} review`, counts.pending && `${counts.pending} not prepared`].filter(Boolean).join(' · ') };
}

export function repositoryMonitorStatus(monitor, { backgroundEnabled = true, updating = false } = {}) {
  if (monitor?.policy?.enabled === false || monitor?.status === 'paused') return { state: 'paused', label: 'Automatic checks paused' };
  if (monitor?.status === 'manual' || monitor?.policy?.onChange === false && monitor?.policy?.schedule === 'off') return { state: 'manual', label: 'Manual / integration checks' };
  if (monitor?.status === 'access_required') return { state: 'access_required', label: 'Access needed' };
  if (monitor?.status === 'retrying') return { state: 'retrying', label: 'Retrying' };
  if (updating || monitor?.status === 'checking') return { state: 'checking', label: 'Checking' };
  if (!backgroundEnabled) return { state: 'pending', label: 'Manual checks' };
  if (monitor?.status === 'watching') return { state: 'watching', label: 'Watching' };
  return { state: 'pending', label: backgroundEnabled ? 'Monitoring queued' : 'Checks while open' };
}
