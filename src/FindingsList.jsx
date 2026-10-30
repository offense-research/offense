import React from 'react';
import { ArrowUpRight, ChevronRight, Package } from 'lucide-react';
import { severityLevel } from './severity.js';
import { findingReadiness } from './finding-readiness.js';
import VulnerabilityImpact from './VulnerabilityImpact.jsx';
import { explainVulnerabilityImpact } from '../shared/vulnerability-impact.js';

export default function FindingsList({ findings, total, limit, onShowMore, renderIssueActions, plans, busy, onPlan, renderPrompt, onExplore, manifestOnly = false }) {
  if (!findings.length) return <div className="findings-empty"><Package size={28}/><h3>{total ? 'No matching findings' : manifestOnly ? 'No matches in sampled declarations' : 'No known advisory matches'}</h3><p>{total ? 'Try a different package, CVE, or severity.' : manifestOnly ? 'This does not establish that the permitted ranges or transitive dependencies are clear. Generate a lockfile to check the resolved dependency tree.' : 'No matches were returned for the checked versions. Review scan coverage before drawing conclusions.'}</p></div>;
  return <div className="findings-list">
    <div className="findings-table-heading" aria-hidden="true"><span>Package & advisory</span><span>Severity</span><span>Upgrade readiness</span><span/></div>
    {findings.slice(0, limit).map(finding => {
      const severity = severityLevel(finding.severity);
      const plan = plans.find(value => value.name === finding.package && value.currentVersion === finding.version);
      const declared = finding.resolved === false;
      const readiness = findingReadiness(finding, plan, { manifestOnly });
      const impact = explainVulnerabilityImpact(finding, { manifestOnly });
      return <article className="finding-entry" key={JSON.stringify([finding.package, finding.version, finding.id, finding.versionEvidence || 'resolved', finding.declaredRange, finding.files])}><details className={`finding-row finding-severity-${severity}`}>
        <summary><div className="finding-identity"><span className="finding-package-icon" aria-hidden="true"><Package size={17}/></span><span><strong>{finding.package}<code>{declared ? finding.declaredRange : finding.version}</code></strong><small className="finding-advisory">{finding.cves?.[0] || finding.id}</small><small className="finding-summary finding-impact-summary">{impact.headline}</small>{declared && <small className="finding-declared">Potential risk in declared requirement · installed version unknown</small>}</span></div><span className={`severity-badge severity-${severity}`}>{severity}</span><span className="finding-target" data-readiness={readiness.state}><small>{readiness.label}</small>{readiness.target && <code>{readiness.target}</code>}</span><ChevronRight className="finding-chevron" size={16}/></summary>
        <div className="finding-expanded"><VulnerabilityImpact finding={finding} manifestOnly={manifestOnly} impact={impact}/><div className="finding-evidence-tags"><span>{finding.kind || 'Dependency'} dependency</span><span>{finding.cves?.join(', ') || finding.id}</span><a href={`https://osv.dev/vulnerability/${encodeURIComponent(finding.id)}`} target="_blank" rel="noopener noreferrer">Read advisory <ArrowUpRight size={13}/></a></div>
          {declared && <p>We checked the published version {finding.version}, which your declared requirement permits. Generate a lockfile and scan again to determine the actual resolved versions, including transitive dependencies.</p>}
          <div className="finding-next-actions"><button type="button" className="secondary-button" onClick={() => onExplore(finding)}>Explore dependency path</button>{!declared && !manifestOnly && <button type="button" className="secondary-button" onClick={() => onPlan(finding)} disabled={busy}>{busy ? 'Checking…' : plan ? 'Refresh upgrade path' : 'Check upgrade path'}</button>}{renderPrompt(finding, plan)}{renderIssueActions?.(finding)}</div>
          {plan && <div className="finding-plan-note" data-readiness={readiness.state}><strong>{readiness.label}{readiness.target ? `: ${plan.currentVersion} → ${readiness.target}` : ''}</strong><p>{readiness.detail}</p>{readiness.blockers.length > 0 && <ul>{readiness.blockers.map((blocker, index) => <li key={index}>{blocker}</li>)}</ul>}{plan.mitigation?.steps && <ol>{plan.mitigation.steps.map((step, index) => <li key={index}>{step}</li>)}</ol>}</div>}
        </div>
      </details></article>;
    })}
    {findings.length > limit && <button type="button" className="findings-show-more" onClick={onShowMore}>Show {Math.min(10, findings.length - limit)} more findings <span>{findings.length - limit} remaining</span></button>}
  </div>;
}
