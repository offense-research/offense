import { useAutoRefresh } from './useAutoRefresh.js';
import { notifyDataChanged } from './auto-refresh.js';
import React, { useState } from 'react';
import { ArrowRight, Search } from 'lucide-react';
import Investigations from './Investigations.jsx';
import WorkerRepositories from './WorkerRepositories.jsx';
import DependencyMapper from './DependencyMapper.jsx';

function dateLabel(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
}

export default function WorkspaceDashboard({ state, section, onNavigate, onManage }) {
  const [activity, setActivity] = useState(null);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState({ worker: '', requestId: '', from: '', to: '' });
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [activeQuery, setActiveQuery] = useState(null);

  async function refresh(signal) {
    try {
      const responses = await Promise.all([
        fetch('/api/cloudflare/events', { credentials: 'same-origin', signal }),
        fetch('/api/cloudflare/batches', { credentials: 'same-origin', signal }),
        fetch('/api/vulnerabilities', { credentials: 'same-origin', signal }),
        ...(activeQuery !== null ? [fetch(`/api/events/search?${activeQuery}`, { signal })] : [])
      ]);
      if (responses.some(response => !response.ok)) throw new Error('Activity temporarily unavailable. Retrying automatically…');
      const [events, batches, vulnerabilities, searched] = await Promise.all(responses.map(response => response.json()));
      if (signal.aborted) return;
      if (searched) setSearchResults(searched.events);
      setActivity({ events, batches: batches.batches, vulnerabilities });
      setError('');
    } catch (cause) {
      if (!signal.aborted) setError(cause.message); throw cause;
    }
  }

  useAutoRefresh(refresh, { enabled: ['overview', 'events'].includes(section) && !searching, dependencies: [section, activeQuery] });

  const latest = activity?.batches?.[0];
  const events = searchResults ?? activity?.events?.events ?? [];
  async function search(event) {
    event.preventDefault();
    setSearching(true); setError('');
    try {
      const params = new URLSearchParams();
      if (filters.worker) params.set('worker', filters.worker);
      if (filters.requestId.trim()) params.set('requestId', filters.requestId.trim());
      if (filters.from) params.set('from', new Date(filters.from).toISOString());
      if (filters.to) params.set('to', new Date(filters.to).toISOString());
      const response = await fetch(`/api/events/search?${params}`, { credentials: 'same-origin' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Search failed.');
      setActiveQuery(params.toString()); setSearchResults(data.events);
    } catch (cause) { setError(cause.message); }
    finally { setSearching(false); }
  }
  if (section === 'investigations') return <Investigations state={state} onNavigate={onNavigate}/>;
  if (section === 'worker-repositories') return <WorkerRepositories state={state}/>;
  if (section === 'dependencies') return <DependencyMapper state={state} onNavigate={onNavigate}/>;
  if (section === 'overview') return <section id="overview" className="workspace-dashboard" aria-label="Workspace activity">
    <div className="dashboard-panel" style={{ marginBottom: 24 }}>
      <h2>Confirmed vulnerabilities</h2>
      <strong style={{ fontSize: 56 }}>{activity?.vulnerabilities?.metrics.total ?? '—'}</strong>
      <p className="dashboard-muted">{activity ? `${activity.vulnerabilities.metrics.customer} customer · ${activity.vulnerabilities.metrics.test} test fixture` : 'Loading discoveries…'}</p>
      <p className="dashboard-muted">Confirmed by reproduction and independently verified tests.</p>
      {activity?.vulnerabilities?.metrics.legacyUnreviewed > 0 && <p className="dashboard-muted">{activity.vulnerabilities.metrics.legacyUnreviewed} earlier records need verification under the strengthened gate.</p>}
      {activity?.vulnerabilities?.discoveries.map(discovery => <div key={discovery.id} style={{ marginTop: 16 }}>
        <strong>{discovery.repository}{discovery.isTest ? ' · Test fixture' : ''}</strong>
        <p>{discovery.summary}</p>
        <a className="secondary-button" href={`/?investigation=${discovery.investigationId}#investigations`}>View investigation <ArrowRight size={16}/></a>
      </div>)}
    </div>
    <div className="dashboard-stats">
      <div><span>EVENTS STORED</span><strong>{activity ? activity.events.count : '—'}</strong><small>Detection rules active</small></div>
      <div><span>LATEST BATCH</span><strong>{latest ? `${latest.acceptedCount} stored` : 'Waiting'}</strong><small>{latest ? dateLabel(latest.receivedAt) : 'No batches received yet'}</small></div>
    </div>
    {error && <div className="setup-warning" role="alert">{error}</div>}
    <details className="dashboard-panel"><summary>Monitored Workers · {state.collector?.sources?.length || 0}</summary><ul className="dashboard-sources">{(state.collector?.sources || []).map(source => <li key={source}>{source}</li>)}</ul></details>
  </section>;
  return <section id="events" className="workspace-dashboard" aria-label="Event logs">
    {error && <div className="setup-warning" role="alert">{error}</div>}
    <div className="dashboard-panel">
        <div className="dashboard-panel-heading"><div><h2>Event logs</h2></div></div>
        {state.config.clickhouse ? <form className="dashboard-search" onSubmit={search}>
          <label>Worker<select value={filters.worker} onChange={event => setFilters({ ...filters, worker: event.target.value })}><option value="">All Workers</option>{(state.collector?.sources || []).map(source => <option key={source} value={source}>{source}</option>)}</select></label>
          <label>Request ID<input value={filters.requestId} onChange={event => setFilters({ ...filters, requestId: event.target.value })} placeholder="Cloudflare Ray ID" maxLength="128"/></label>
          <details className="event-time-range"><summary>Time range</summary><label>From<input type="datetime-local" value={filters.from} onChange={event => setFilters({ ...filters, from: event.target.value })}/></label>
          <label>To<input type="datetime-local" value={filters.to} onChange={event => setFilters({ ...filters, to: event.target.value })}/></label></details>
          <div className="dashboard-search-actions"><button className="primary-button" disabled={searching}><Search size={14}/>{searching ? 'Searching…' : 'Search'}</button>{searchResults && <button type="button" className="secondary-button" onClick={() => { setSearchResults(null); setActiveQuery(null); notifyDataChanged(); setFilters({ worker: '', requestId: '', from: '', to: '' }); }}>Clear</button>}</div>
        </form> : <p className="dashboard-muted dashboard-search-note">Log search is temporarily unavailable.</p>}
        {searchResults && <p className="dashboard-muted">{searchResults.length} matching events · latest 50</p>}
        {!activity && !error && !searchResults ? <p className="dashboard-empty">Loading events…</p> : events.length ? <ul className="dashboard-events">{events.map((event, index) => <li key={event.id || `${event.timestamp}-${index}`}><div className="dashboard-event-top"><strong>{event.sourceWorker}</strong><time>{dateLabel(event.timestamp)}</time></div><div className="dashboard-event-meta"><span>{event.eventType || 'Worker event'}</span>{event.outcome && <span>{event.outcome}</span>}{event.responseStatus != null && <span>HTTP {event.responseStatus}</span>}{event.requestId && <span>Ray {event.requestId}</span>}</div>{event.logs?.length > 0 && <details className="dashboard-logs"><summary>Log messages · {event.logs.length}</summary>{event.logs.map((log, logIndex) => <p key={logIndex}><strong>{log.level}</strong> {log.message}</p>)}</details>}</li>)}</ul> : <div className="dashboard-empty"><strong>{searchResults ? 'No matching events' : 'Waiting for the first event'}</strong><p>{searchResults ? 'Try a different Worker, request ID, or time range.' : 'Send traffic to a monitored Worker. Its events will appear automatically.'}</p></div>}
    </div>
  </section>;
}
