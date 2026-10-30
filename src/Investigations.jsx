import { useAutoRefresh } from './useAutoRefresh.js';
import { notifyDataChanged } from './auto-refresh.js';
import React, { useEffect, useState } from 'react';
import { verificationCheck } from './verification.js';
import { ArrowRight, Check, ShieldAlert } from 'lucide-react';

function time(value) { return new Date(value).toLocaleString(); }

function VerificationResults({ report }) {
  const checks = [
    ['Original normal tests', report.baselineNormal],
    ['Original regression', report.baselineReproduction],
    ['Patched regression', report.patchedReproduction],
    ['Patched normal tests', report.patchedNormal]
  ];
  return <div className="dashboard-muted"><p>{report.verified && report.gateVersion === 2 ? 'Patch verified against the original and patched checkouts.' : 'Patch verification incomplete or failed.'}</p>
    {report.blocker && <p className="dependency-warning">{report.blocker}</p>}
    {report.verified && report.gateVersion !== 2 && <p>Earlier verification evidence needs re-verification under the strengthened gate.</p>}
    <ul>{checks.map(([label, check]) => <li key={label}>{label}: {verificationCheck(check, label === 'Original regression').label}</li>)}</ul>
    <details><summary>Test output</summary>{report.setup && <pre>Dependency setup: {JSON.stringify(report.setup, null, 2)}</pre>}{checks.map(([label, check]) => check && <pre key={label}>{label}{'\n'}{verificationCheck(check).output}</pre>)}</details>
  </div>;
}

export default function Investigations({ state, onNavigate }) {
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [showResolved, setShowResolved] = useState(false);
  const [error, setError] = useState('');
  const [syncError, setSyncError] = useState('');
  const [busy, setBusy] = useState(false);
  const [agentRun, setAgentRun] = useState(null);

  useEffect(() => {
    const id = Number(new URLSearchParams(window.location.search).get('investigation'));
    if (Number.isSafeInteger(id) && id > 0) open(id);
  }, []);

  useAutoRefresh(async signal => {
    const [detailResponse, runResponse] = await Promise.all([
      fetch(`/api/investigations/${selected.id}`, { signal }),
      fetch(`/api/investigations/${selected.id}/agent`, { signal })
    ]);
    if (!detailResponse.ok || !runResponse.ok) throw new Error('Investigation temporarily unavailable.');
    const [detail, run] = await Promise.all([detailResponse.json(), runResponse.json()]);
    if (!signal.aborted) { setSelected(detail); setAgentRun(run.run); }
  }, { enabled: !!selected && !busy, interval: 10000, dependencies: [selected?.id] });
  useAutoRefresh(async signal => {
    try {
      const response = await fetch('/api/investigations', { signal });
      if (!response.ok) throw new Error('Could not load investigations. Retrying automatically…');
      const data = await response.json();
      if (!signal.aborted) { setItems(data.investigations); setSyncError(''); }
    } catch (cause) { if (!signal.aborted) setSyncError(cause.message); throw cause; }
  }, { enabled: !busy });

  async function open(id) {
    if (selected?.id === id) { setSelected(null); setAgentRun(null); return; }
    try {
      const response = await fetch(`/api/investigations/${id}`, { credentials: 'same-origin' });
      if (!response.ok) throw new Error('Could not load investigation evidence.');
      setAgentRun(null); setSelected(await response.json());
      setError('');
    } catch (cause) { setError(cause.message); }
  }

  async function retryAnalysis(id) {
    setBusy(true);
    try {
      const response = await fetch(`/api/investigations/${id}/agent/retry`, { method: 'POST', credentials: 'same-origin' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not retry analysis.');
      setAgentRun(data.run); setError('');
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); notifyDataChanged(); }
  }

  async function resolve(id) {
    setBusy(true);
    try {
      const response = await fetch(`/api/investigations/${id}`, {
        method: 'PATCH', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'resolved' })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not resolve investigation.');
      setItems(items.map(item => item.id === id ? { ...item, status: 'resolved' } : item));
      setSelected(data);
      setError('');
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); notifyDataChanged(); }
  }

  const openItems = items.filter(item => item.status === 'open');
  const visible = showResolved ? items : openItems;
  return <section id="investigations" className="investigations-panel" aria-labelledby="investigations-title">
    <div className="investigations-heading"><div><h2 id="investigations-title">Investigations <span>{openItems.length} open</span></h2></div>{items.some(item => item.status === 'resolved') && <button className="secondary-button" onClick={() => setShowResolved(!showResolved)}>{showResolved ? 'Hide resolved' : 'Show resolved'}</button>}</div>
    {(error || syncError) && <p className="key-error" role="alert">{error || syncError}</p>}
    {visible.length ? <div className="investigations-list">{visible.map(item => <article key={item.id} className={`investigation ${item.status}`}>
      <button className="investigation-summary" onClick={() => open(item.id)} aria-expanded={selected?.id === item.id}><span className={`investigation-severity ${item.severity}`}>{item.severity}</span><span className="investigation-main"><strong>{item.title}</strong><small>{item.sourceWorker}{item.groupKey ? ` · ${item.groupKey.replaceAll('_', ' ')}` : ''} · {item.eventCount} related event{item.eventCount === 1 ? '' : 's'} · {time(item.lastSeen)}</small></span><ArrowRight size={17}/></button>
      {selected?.id === item.id && <div className="investigation-detail"><p>{selected.description}</p><p className="dashboard-muted">Suspected issue · awaiting verification.</p><details><summary>Related events · {selected.events.length}</summary><ul>{selected.events.map(event => <li key={event.eventId}><span>{time(event.receivedAt)}</span><strong>{event.reason}</strong>{event.requestId && <code>{event.requestId}</code>}</li>)}</ul></details>
        {state.config.agent && state.github && <div className="investigation-agent">{agentRun ? <div className="agent-run"><strong>Analysis: {agentRun.needsReverification ? 'needs re-verification' : agentRun.status.replaceAll('_', ' ')}</strong><small>{agentRun.repository}{agentRun.commitSha ? ` · ${agentRun.commitSha.slice(0, 12)}` : ''}</small>{agentRun.result && <details><summary>Analysis report</summary><pre>{agentRun.result}</pre></details>}{agentRun.verification && <VerificationResults report={agentRun.verification}/>} {agentRun.hasPatch && <a className="secondary-button" href={`/api/investigations/${item.id}/agent/patch`} download>Download patch and regression test</a>}{agentRun.error && <p role="alert">{agentRun.error}</p>}{(['failed', 'verification_failed'].includes(agentRun.status) || agentRun.needsReverification) && <button className="secondary-button" onClick={() => retryAnalysis(item.id)} disabled={busy}>{agentRun.needsReverification ? 'Re-verify investigation' : 'Retry investigation'}</button>}</div> : <div className="investigation-link-prompt"><p className="dashboard-muted">Link this Worker to its repository to start analysis.</p><button className="secondary-button" type="button" onClick={() => onNavigate('worker-repositories')}>Open Worker repositories <ArrowRight size={15}/></button></div>}</div>}
        {item.status === 'open' && <button className="secondary-button" onClick={() => resolve(item.id)} disabled={busy}><Check size={14}/> Mark resolved</button>}</div>}
    </article>)}</div> : <div className="investigations-empty"><ShieldAlert size={20}/><div><strong>{items.length ? 'No open investigations' : 'No investigations yet'}</strong><p>Offense is watching for suspicious log signals, repeated authentication failures, exceptions, and server error bursts.</p></div></div>}
  </section>;
}
