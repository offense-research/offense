import { coordinatedChanges } from '../../public/skills/purple/scripts/workflow.mjs';
import { minorUpgrade } from './dependency-policy.mjs';
export function selectPlan(scan) {
  if (scan.vulnerabilityCheck?.status !== 'complete' || scan.warnings?.length) throw Error('Complete advisory evidence is required.');
  return (scan.plans || []).find(plan => scan.vulnerabilityCheck.findings.some(f => ['HIGH', 'CRITICAL'].includes(String(f.severity).toUpperCase()) && f.package === plan.name && f.version === plan.currentVersion) && (() => {
    try { return coordinatedChanges({ plans: [plan] }).every(c => minorUpgrade(c.currentVersion, c.targetVersion)); } catch { return false; }
  })());
}
