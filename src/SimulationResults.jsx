import React from 'react';
import { describeBlastRadius } from './blast-radius.js';
import { simulationSummary } from './simulation-summary.js';

export default function SimulationResults({ rehearsal, snapshot, onContinue, renderAction }) {
  const report = simulationSummary(rehearsal, snapshot);
  const running = ['queued', 'planning', 'running'].includes(rehearsal.status);
  const stages = ['Queued', 'Plan upgrades', 'Test original + candidate', 'Review results'];
  const current = rehearsal.status === 'queued' ? 0 : rehearsal.status === 'planning' ? 1 : running ? 2 : 3;
  const firstBlocker = rehearsal.error && !rehearsal.stale
    ? { message: 'The sandbox could not finish.', nextStep: rehearsal.error }
    : report.assessment.blockers[0];
  const actionLabel = report.verified ? 'Prepare & copy fix prompt' : 'Prepare & copy troubleshooting prompt';
  return <section className="simulation-report" aria-label="Upgrade simulation" aria-busy={running}>
    <div className="simulation-heading"><span className="section-kicker">UPGRADE SIMULATION</span><strong role="status">{running ? 'Simulation in progress' : report.title}</strong></div>
    {running && <ol className="simulation-stages" aria-label="Simulation progress">{stages.map((stage, i) => <li key={stage} className={i < current ? 'done' : i === current ? 'current' : ''} aria-current={i === current ? 'step' : undefined}><span>{i < current ? '✓' : i + 1}</span>{stage}</li>)}</ol>}
    {running ? <div className="simulation-live" role="status"><span className="simulation-spinner"/>{rehearsal.progress?.phase || 'Waiting for the sandbox'}{rehearsal.progress?.total > 0 && <progress value={rehearsal.progress.completed} max={rehearsal.progress.total}>{rehearsal.progress.completed}/{rehearsal.progress.total}</progress>}<p>Usually a few minutes. This page updates automatically; you can leave and return.</p></div> : <>
      {firstBlocker ? <div className="simulation-next-action dependency-warning" role="status"><strong>{firstBlocker.message}</strong><p>{firstBlocker.nextStep}</p></div> : <p>{report.nextStep.replace(' below', '')}</p>}
      <div className="simulation-result-action">{renderAction ? renderAction({ passed: report.verified, label: actionLabel }) : onContinue ? <button type="button" className="primary-button" onClick={onContinue}>{report.verified ? 'Prepare fix prompt' : 'Prepare troubleshooting prompt'} →</button> : <a className="primary-button" href="#fix-prompt">{report.verified ? 'Prepare fix prompt' : 'Prepare troubleshooting prompt'} →</a>}</div>
      {!report.verified && <p className="dashboard-muted">The prompt includes these blockers. Compatibility has not been established.</p>}
    </>}
    {report.issues.map(issue => <p className="dependency-warning" role="status" key={issue}>{issue}</p>)}
    {report.scenarios.map((scenario, index) => <div key={index} className="simulation-scenario">
      <h3>Upgrade path {index + 1} · {scenario.status === 'not_tested' ? 'Not tested yet' : report.assessment.scenarios[index]?.compatibilityPassed ? 'Recorded checks passed' : 'Needs review'}</h3>
      {report.assessment.scenarios[index]?.blockers.length > 0 && <details className="simulation-blockers"><summary>What needs to pass before applying this path ({report.assessment.scenarios[index].blockers.length})</summary><ul>{report.assessment.scenarios[index].blockers.map(blocker => <li key={blocker.code}><strong>{blocker.message}</strong><p>{blocker.nextStep}</p></li>)}</ul></details>}
      <div className="simulation-metrics"><div><strong>{scenario.changes.length}</strong><span>proposed upgrades</span></div><div><strong>{scenario.totalDependencyChanges ?? 'Not measured'}</strong><span>resolved dependency changes</span></div><div><strong>{scenario.remainingAdvisories ?? 'Not checked'}</strong><span>remaining advisories</span></div><div><strong>{report.assessment.scenarios[index] && !report.assessment.scenarios[index].checksMatched ? 'Not comparable' : `${scenario.checks?.filter(check => check.passed === true).length || 0}/${scenario.checks?.length || 0}`}</strong><span>candidate checks passed</span></div></div>
      <h4>Dependency blast radius</h4><p className="simulation-blast-radius">{describeBlastRadius(scenario, rehearsal.impact, rehearsal.result?.baseline)}</p>
      <details className="simulation-impact-details"><summary>Dependency evidence and compatibility details</summary>
      <div className="simulation-paths">{scenario.changes.map((change, i) => {
        const impact = rehearsal.impact?.find(plan => plan.name === change.name && plan.currentVersion === change.currentVersion);
        return <article className="simulation-upgrade" key={`${change.name}:${change.currentVersion}:${i}`}><strong>{change.name}</strong><div className="simulation-version"><code>{change.currentVersion}</code><span aria-label="upgrades to">→</span><code>{change.targetVersion}</code></div>
          {impact?.truncated && <p className="dependency-warning">Dependency path analysis is incomplete. Inspect remaining parent constraints before applying this path.</p>}
          {impact?.constraintWarnings?.map((warning, index) => <p className="dependency-warning" key={`constraint:${index}`}>{warning}</p>)}
          {impact?.majorChange && <p className="dependency-warning">Major upgrade: review breaking API changes.</p>}
          {impact?.paths?.length ? <ul>{impact.paths.slice(0, 4).map((path, j) => <li key={j} className="simulation-chain">{path.map((name, k) => <React.Fragment key={k}>{k > 0 && <span aria-hidden="true">→</span>}<span className="simulation-node">{name}</span></React.Fragment>)}</li>)}</ul> : <p className="dashboard-muted">Dependency path unavailable; review the resolved changes below.</p>}
          {impact?.parents?.filter(parent => parent.compatible === false).map((parent, j) => <p className="dependency-warning" key={j}>{parent.name} requires {parent.range}; this target needs a parent upgrade or a reviewed override.</p>)}
          {impact?.parentOptions?.map((parent, j) => <p key={j}>Parent path: {parent.parent}{parent.version ? ` ${parent.currentVersion} → ${parent.version}` : ''}. {parent.action}</p>)}
          {impact?.steps?.length > 0 && <details><summary>Compatibility checkpoints</summary><ul>{impact.steps.map((step, j) => <li key={j}>{step.from} → {step.to}{step.majorChange ? ' · major release' : ''}{step.changes?.map((change, k) => <p key={k}>{change.type} {change.name}: {change.from || 'none'} → {change.to || 'none'}</p>)}</li>)}</ul></details>}
        </article>;
      })}</div></details>
      {scenario.dependencyChanges?.length > 0 && <details><summary>Resolved before / after ({scenario.totalDependencyChanges ?? scenario.dependencyChanges.length})</summary><div className="dependency-table-wrap"><table className="dependency-table"><thead><tr><th>Lockfile location</th><th>Before</th><th>After</th></tr></thead><tbody>{scenario.dependencyChanges.map((change, i) => <tr key={i}><td>{change.location}</td><td>{change.before?.version || 'Absent'}</td><td>{change.after?.version || 'Removed'}</td></tr>)}</tbody></table></div>{scenario.totalDependencyChanges > scenario.dependencyChanges.length && <p>Showing the first {scenario.dependencyChanges.length} changes.</p>}</details>}
      {scenario.unrehearsedFindings?.length > 0 && <p className="dependency-warning">{scenario.unrehearsedFindings.length} findings were not directly covered by this candidate. Include them in the fix prompt.</p>}
      <details><summary>Plan rationale</summary><p>{scenario.rationale}</p></details>
    </div>)}
    {rehearsal.blockers?.length > 0 && <details className="simulation-blockers"><summary>Package planning blockers ({rehearsal.blockers.length})</summary><ul>{rehearsal.blockers.map((blocker, i) => <li key={i}>{blocker.package}: {blocker.reason}</li>)}</ul></details>}
    {rehearsal.result && <details><summary>Commands, baseline and evidence</summary><pre>{JSON.stringify({ model: rehearsal.model, ...rehearsal.result }, null, 2)}</pre></details>}
  </section>;
}
