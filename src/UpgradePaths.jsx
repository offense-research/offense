import React from 'react';
import { upgradeRoutes, routeEvidence } from './upgrade-routes.js';

function UpgradeRoute({ route, snapshot }) {
  return <article className={`upgrade-route ${route.recommended ? 'recommended' : ''}`}>
    <div className="upgrade-route-heading"><strong>{route.title}</strong><span className="upgrade-route-badge">{route.recommended ? 'Recommended' : 'Needs review'}</span></div>
    <p>{route.description}</p>
    <ol className="upgrade-route-track" aria-label={`${route.title}: steps`}>
      {route.changes.map((change, i) => <li key={`${change.name}:${change.currentVersion}:${i}`}><span className="upgrade-route-step">{i + 1}</span><div><strong>{change.name}</strong><div className="upgrade-route-versions"><code>{change.currentVersion}</code><span aria-label="upgrades to">→</span><code>{change.targetVersion}</code></div></div></li>)}
      <li className="upgrade-route-verify"><span className="upgrade-route-step">{route.changes.length + 1}</span><div><strong>Run checks & rescan</strong><small>{routeEvidence(route, snapshot.rehearsal, snapshot)}</small></div></li>
    </ol>
    {route.majorChange && <p className="dependency-warning">Major-version change. Review breaking API changes.</p>}
    {route.blockers.length > 0 && <ul className="upgrade-route-blockers">{route.blockers.map((blocker, i) => <li key={i}>{blocker}</li>)}</ul>}
    <p className="upgrade-route-next">{route.recommended ? 'Copy the package fix prompt to apply this path and verify the changes.' : 'Resolve these constraints in your coding agent before upgrading.'}</p>
  </article>;
}

export default function UpgradePaths({ plan, snapshot }) {
  const routes = upgradeRoutes(plan);
  if (!plan) return null;
  const lead = routes.find(route => route.recommended) || routes[0];
  const alternatives = routes.filter(route => route !== lead);
  return <section className="upgrade-routes" aria-label="Upgrade path comparison">
    <h4>Upgrade path</h4>
    {!lead ? <div className="upgrade-route"><strong>Manual remediation required</strong><p>{plan.mitigation?.reason || 'No checked fixed version is available.'} Review a patch, replacement or isolation in your coding agent.</p></div> : <UpgradeRoute route={lead} snapshot={snapshot}/>}
    {alternatives.length > 0 && <details className="upgrade-route-alternatives"><summary>Alternative paths ({alternatives.length})</summary>{alternatives.map(route => <UpgradeRoute key={route.id} route={route} snapshot={snapshot}/>)}</details>}
    <details className="upgrade-route-notes"><summary>How this path was checked</summary><p className="dashboard-muted">The plan records published targets and parent constraints where available. Simulation results are separate evidence; a plan alone does not establish compatibility or a verified security fix.</p>
      {(plan.considered || []).some(candidate => candidate.advisories > 0) && <><h5>Excluded versions</h5><ul>{plan.considered.filter(candidate => candidate.advisories > 0).map(candidate => <li key={candidate.version}>{candidate.version}: {candidate.advisories} known advisory {candidate.advisories === 1 ? 'match' : 'matches'} remained.</li>)}</ul></>}
      {plan.steps?.length > 0 && <><h5>Release review checkpoints ({plan.steps.length})</h5><p>Review these compatibility checkpoints before installing the chosen target.</p><ol>{plan.steps.map((step, i) => <li key={i}>{step.from} → {step.to}{step.majorChange ? ' · major version' : ''}{step.changes?.length ? ` · ${step.changes.length} metadata changes` : ''}</li>)}</ol></>}
    </details>
  </section>;
}
