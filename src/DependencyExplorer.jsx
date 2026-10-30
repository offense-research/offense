import UpgradePaths from './UpgradePaths.jsx';
import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { dependencyChoices, dependencyMap, resolutionAdvice } from './dependency-map.js';
import { severityLevel, severityRank } from './severity.js';
import VulnerabilityImpact from './VulnerabilityImpact.jsx';
import { explainVulnerabilityImpact } from '../shared/vulnerability-impact.js';

const highestSeverity = item => severityLevel([...item.advisories].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0]?.severity);

export default function DependencyExplorer({ snapshot, plans, onPlan, busy, renderFix, initialPackage }) {
  const [selected, setSelected] = useState(() => initialPackage ? JSON.stringify([initialPackage.name, initialPackage.version]) : '');
  const [search, setSearch] = useState('');
  const [allPackages, setAllPackages] = useState(false);
  const [limit, setLimit] = useState(8);
  const [zoom, setZoom] = useState('auto');
  const [viewportWidth, setViewportWidth] = useState(0);
  const viewport = useRef(null);
  const titleId = useId(), markerId = useId().replaceAll(':', '');
  const choices = useMemo(() => dependencyChoices(snapshot).sort((a, b) => Math.max(0, ...b.advisories.map(item => severityRank(item.severity))) - Math.max(0, ...a.advisories.map(item => severityRank(item.severity))) || b.advisories.length - a.advisories.length || a.name.localeCompare(b.name)), [snapshot]);
  const focus = choices.find(item => item.key === selected) || choices.find(item => item.advisories.length) || choices[0];
  const map = useMemo(() => focus ? dependencyMap(snapshot.graph, focus.name, focus.version) : null, [snapshot.graph, focus?.key]);
  useEffect(() => {
    if (!viewport.current) return;
    const observer = new ResizeObserver(entries => setViewportWidth(entries[0].contentRect.width));
    observer.observe(viewport.current);
    return () => observer.disconnect();
  }, [focus?.key]);
  if (!focus) return null;
  const scale = (zoom === 'fit' || (zoom === 'auto' && viewportWidth >= 500)) && viewportWidth
    ? Math.min(1, viewportWidth / map.width) : 1;
  const plan = plans.find(plan => plan.name === focus.name && plan.currentVersion === focus.version);
  const advice = resolutionAdvice(plan);
  const manifestOnly = !!snapshot.coverage?.missingLockfiles?.length || snapshot.vulnerabilityCheck?.status === 'no_exact_versions';
  const impactFindings = [...focus.advisories].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const leadingImpact = impactFindings.length ? explainVulnerabilityImpact(impactFindings[0], { manifestOnly }) : null;
  const visible = choices.filter(item => (allPackages || item.advisories.length) && `${item.name} ${item.version}`.toLowerCase().includes(search.toLowerCase()));
  const affectedCount = choices.filter(item => item.advisories.length).length;
  const pick = node => {
    const choice = choices.find(item => item.name === node.name && item.version === node.version);
    if (choice) setSelected(choice.key);
  };
  return <section className="dependency-explorer" aria-labelledby={titleId}>
    <div className="explorer-heading"><h3 id={titleId}>Dependency map</h3><span className="explorer-total">{affectedCount} {affectedCount === 1 ? 'package' : 'packages'} with advisories</span></div>
    <div className="explorer-layout">
      <aside className="explorer-picker" aria-label="Choose a dependency">
        <label>Find a dependency<input type="search" value={search} onChange={e => { setSearch(e.target.value); setLimit(8); }} placeholder="Package name or version"/></label>
        <label className="explorer-toggle"><input type="checkbox" checked={allPackages} onChange={e => { setAllPackages(e.target.checked); setLimit(8); }}/> Show all packages</label>
        <label className="explorer-mobile-picker">Selected dependency<select value={focus.key} onChange={e => setSelected(e.target.value)}>
          {!visible.some(item => item.key === focus.key) && <option value={focus.key}>{focus.name}@{focus.version} · selected</option>}
          {visible.map(item => <option key={item.key} value={item.key}>{item.name}@{item.version} · {item.advisories.length} {item.advisories.length === 1 ? 'advisory' : 'advisories'}</option>)}
        </select></label>
        <div className="explorer-desktop-packages">
          <div className="explorer-package-list">{visible.slice(0, limit).map(item => <button type="button" key={item.key} aria-pressed={item.key === focus.key} onClick={() => setSelected(item.key)}>
            <span><strong>{item.name}</strong><small>{item.version}</small></span>
            {item.advisories.length ? <span className={`severity-badge severity-${highestSeverity(item)}`}>{highestSeverity(item)} · {item.advisories.length}</span> : <span className="explorer-count">No matches</span>}
          </button>)}</div>
          {visible.length > limit && <button className="secondary-button" onClick={() => setLimit(value => value + 12)}>Show more packages ({visible.length - limit})</button>}
        </div>
        {!visible.length && <p className="dashboard-muted">No packages match this filter.</p>}
      </aside>
      <div className="explorer-detail">
        <div className="explorer-focus"><div className="explorer-focus-name"><h4>{focus.name}<small>{focus.version}</small></h4>{focus.advisories.length > 0 && <span className={`severity-badge severity-${highestSeverity(focus)}`}>{highestSeverity(focus)}</span>}</div><span>{map.instances} lockfile {map.instances === 1 ? 'instance' : 'instances'} · {map.parents} direct dependents</span></div>
        {leadingImpact && <div className="explorer-risk-summary"><p><strong>What this could mean</strong>{leadingImpact.headline}</p>
          <details><summary>Understand the impact ({impactFindings.length} {impactFindings.length === 1 ? 'advisory' : 'advisories'})</summary>
            {impactFindings.map(finding => <article className="explorer-advisory-impact" key={finding.id}>
              <h4>{finding.cves?.[0] || finding.id}</h4><VulnerabilityImpact finding={finding} manifestOnly={manifestOnly} headingLevel={5}/>
            </article>)}
          </details>
        </div>}
        {map.nodes.length > 0 ? <>
          <div className="explorer-map-tools"><span>Arrows show dependencies</span><button className="secondary-button" onClick={() => setZoom('fit')}>Fit map</button><button className="secondary-button" onClick={() => setZoom('actual')}>Actual size</button></div>
          <div ref={viewport} className="explorer-map-scroll" tabIndex={0} aria-label={`Dependency relationships for ${focus.name}; scroll horizontally to explore`}>
            <div style={{ width: map.width * scale, height: map.height * scale, overflow: 'hidden', position: 'relative' }}><div className="explorer-canvas" style={{ width: map.width, height: map.height, transform: `scale(${scale})`, transformOrigin: '0 0' }}>
              <svg width={map.width} height={map.height} aria-hidden="true"><defs><marker id={markerId} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"/></marker></defs>{map.edges.map(edge => <path key={edge.key} d={`M ${edge.from.x + 190} ${edge.from.y + 30} C ${edge.from.x + 220} ${edge.from.y + 30}, ${edge.to.x - 30} ${edge.to.y + 30}, ${edge.to.x} ${edge.to.y + 30}`} markerEnd={`url(#${markerId})`}><title>{edge.from.name} requires {edge.to.name} {edge.range} ({edge.type})</title></path>)}</svg>
              {map.nodes.map(node => <button key={node.id} className={`explorer-node ${node.focus ? 'focused' : ''} ${node.path === '' ? 'root' : ''}`} style={{ left: node.x, top: node.y }} title={`${node.name}@${node.version} · ${node.file} · ${node.path || 'root'}`} disabled={!choices.some(item => item.name === node.name && item.version === node.version)} onClick={() => pick(node)}><strong>{node.name}</strong><span>{node.path === '' ? 'Project root' : node.version}</span></button>)}
            </div></div>
          </div>
          {map.truncated && <p className="explorer-legend">Showing part of this graph; more relationships exist.</p>}
          <details className="explorer-map-notes"><summary>About this map & relationship list</summary><p className="explorer-legend">Arrows mean “depends on.” Select a package node to explore it. Relationships come from the saved lockfile and do not prove runtime reachability. {map.truncated && 'This graph is bounded; some relationships are not shown.'}</p><ul>{map.edges.map(edge => <li key={edge.key}>{edge.from.name}@{edge.from.version} → {edge.to.name}@{edge.to.version} · requires {edge.range} · {edge.from.file}</li>)}</ul></details>
        </> : <p className="dependency-warning">No graph is available for this package. A supported lockfile is needed; no relationship is inferred.</p>}
        <div className="explorer-resolution" aria-label={`Resolution for ${focus.name}`}>
          {focus.advisories.length > 0 ? <>
            {!plan && <div className="explorer-resolution-intro"><h4>{advice.title}</h4><p className="dashboard-muted">Check the fixed version and any parent upgrades, then copy the package fix prompt.</p></div>}
            <UpgradePaths plan={plan} snapshot={snapshot}/>
            <div className="dependency-actions"><button className="secondary-button" disabled={busy} onClick={() => onPlan(focus.advisories[0])}>{busy ? 'Checking paths…' : plan ? 'Refresh upgrade path' : 'Check upgrade path'}</button>{renderFix(focus.advisories)}</div>
            <details><summary>Resolution guidance</summary><h4>{advice.title}</h4><ol>{advice.steps.map((step, i) => <li key={i}>{step}</li>)}</ol></details>
            <details><summary>Advisories in this package ({focus.advisories.length})</summary><ul>{focus.advisories.map(finding => <li key={finding.id}><a href={`https://osv.dev/vulnerability/${encodeURIComponent(finding.id)}`} target="_blank" rel="noreferrer">{finding.cves?.[0] || finding.id}</a> · {finding.summary}</li>)}</ul></details>
          </> : <><h4>No advisory matches for this version</h4><p className="dashboard-muted">This scan found no matches. It does not establish that the package is secure.</p></>}
        </div>
      </div>
    </div>
  </section>;
}
