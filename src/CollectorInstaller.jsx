import { useAutoRefresh } from './useAutoRefresh.js';
import { notifyDataChanged } from './auto-refresh.js';
import React, { useEffect, useRef, useState } from 'react';

export default function CollectorInstaller({ state, onInstalled }) {
  const accounts = state.cloudflare?.accounts || [];
  const [accountId, setAccountId] = useState(state.collector?.accountId || accounts[0]?.id || '');
  const [workers, setWorkers] = useState([]);
  const [workersLoaded, setWorkersLoaded] = useState(false);
  const [selected, setSelected] = useState(state.collector?.sources || []);
  const [workerFilter, setWorkerFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [savingSources, setSavingSources] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updated, setUpdated] = useState(false);
  const [error, setError] = useState('');
  const [syncError, setSyncError] = useState('');


  useEffect(() => { setWorkersLoaded(false); setWorkers([]); setLoading(true); }, [accountId]);
  const busy = installing || savingSources || updating;
  const savedSourcesKey = JSON.stringify(state.collector?.sources || []);
  const previousSources = useRef(state.collector?.sources || []);
  useEffect(() => {
    const next = state.collector?.sources || [], previous = previousSources.current;
    previousSources.current = next;
    setSelected(current => JSON.stringify([...current].sort()) === JSON.stringify([...previous].sort()) ? next : current);
  }, [savedSourcesKey]);
  useAutoRefresh(async signal => {
    try {
      const response = await fetch(`/api/cloudflare/workers?accountId=${encodeURIComponent(accountId)}`, { signal });
      const data = await response.json();
      if (!response.ok || !Array.isArray(data.workers)) throw new Error(data.error || 'Could not load Workers.');
      if (signal.aborted) return;
      setWorkers(data.workers); setWorkersLoaded(true); setSyncError('');
    } catch (cause) { if (!signal.aborted) setSyncError(/authorization|expired|reconnect/i.test(cause.message) ? 'Reconnect Cloudflare to load available Workers.' : `${cause.message} Retrying automatically…`); throw cause; }
    finally { if (!signal.aborted) setLoading(false); }
  }, { enabled: !!accountId && !busy, interval: 60000, dependencies: [accountId] });

  async function install() {
    setInstalling(true);
    setError('');
    try {
      const response = await fetch('/api/cloudflare/install', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountId, sources: selected })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Installation failed.');
      setSelected(data.collector.sources);
      onInstalled(data);
      notifyDataChanged();
    } catch (cause) { setError(cause.message); }
    finally { setInstalling(false); }
  }

  async function update() {
    setUpdating(true);
    setError('');
    try {
      const response = await fetch('/api/cloudflare/collector/update', { method: 'POST', credentials: 'same-origin' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Collector update failed.');
      setUpdated(true);
    } catch (cause) { setError(cause.message); }
    finally { setUpdating(false); }
  }

  async function saveSources() {
    setSavingSources(true);
    setError('');
    try {
      const response = await fetch('/api/cloudflare/collector/sources', {
        method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sources: selected })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not save source Workers.');
      setSelected(data.collector.sources);
      onInstalled(data);
      notifyDataChanged();
    } catch (cause) {
      setError(cause.message);
      const response = await fetch('/api/state', { credentials: 'same-origin' }).catch(() => null);
      if (response?.ok) {
        const current = await response.json();
        setSelected(current.collector?.sources || []);
        onInstalled(current);
      }
    } finally { setSavingSources(false); }
  }

  const installed = state.collector?.status === 'installed';
  const savedSources = state.collector?.sources || [];
  const visibleWorkers = [...new Set([...savedSources, ...[...workers].sort((a, b) => a.localeCompare(b))])];
  const displayedWorkers = visibleWorkers.filter(name => name.toLowerCase().includes(workerFilter.toLowerCase()));
  const sourcesChanged = selected.length !== savedSources.length || selected.some(name => !savedSources.includes(name));
  return <section id="collector" className="collector-card" aria-labelledby="collector-title">
    <h3 id="collector-title">{installed ? 'Monitored Workers' : 'Set up runtime monitoring'}</h3>
    <p>Choose which Workers send redacted logs to Offense for security monitoring.</p>
    {!installed && <p className="dashboard-muted">Installs a collector, Queue, and forwarding Worker in your account. Requires Cloudflare Workers Paid or Enterprise.</p>}
    {!installed && <>
      {accounts.length > 1 && <label className="field-label" htmlFor="collector-account">Account</label>}
      {accounts.length > 1 && <select id="collector-account" value={accountId} onChange={event => { setAccountId(event.target.value); setSelected([]); }}>
        {accounts.map(account => <option key={account.id} value={account.id}>{account.name}</option>)}
      </select>}
    </>}
    <div className="collector-source-heading"><span className="field-label">Source Workers</span></div>
    <label className="collector-worker-search"><span className="sr-only">Find a Cloudflare Worker</span><input type="search" value={workerFilter} onChange={event => setWorkerFilter(event.target.value)} placeholder={`Search ${workers.length} Workers`}/></label>
    {loading ? <p>Loading Workers…</p> : !workersLoaded ? <p>Worker list temporarily unavailable. Retrying automatically…</p> : displayedWorkers.length ? <div className="worker-choices">{displayedWorkers.map(name => <label key={name}><input type="checkbox" checked={selected.includes(name)} disabled={busy || (!workers.includes(name) && !selected.includes(name))} onChange={event => setSelected(event.target.checked ? [...selected, name] : selected.filter(value => value !== name))}/><span>{name}{!workers.includes(name) && ' · no longer found'}</span></label>)}</div> : <p>{workerFilter ? 'No Workers match that search.' : 'No Workers found in this account.'}</p>}
    {workersLoaded && selected.some(name => !workers.includes(name)) && <p>Uncheck Workers no longer found in Cloudflare before saving.</p>}
    {installed ? <><div className="collector-source-actions"><button className="primary-button" type="button" onClick={saveSources} disabled={busy || loading || !workersLoaded || !selected.length || !sourcesChanged || selected.some(name => !workers.includes(name))}>{savingSources ? 'Saving…' : 'Save source Workers'}</button><a className="secondary-button" href="#events">View event logs</a></div><details className="collector-maintenance"><summary>Connection and maintenance</summary><a className="secondary-button" href="/api/cloudflare/start">Reconnect Cloudflare</a><button className="secondary-button collector-update" type="button" onClick={update} disabled={busy}>{updating ? 'Updating…' : updated ? 'Pipeline updated' : 'Update pipeline'}</button></details></> : <>{!state.config.collector && <p className="config-note">Monitoring setup is temporarily unavailable.</p>}<button className="primary-button" type="button" onClick={install} disabled={installing || loading || !selected.length || !state.config.collector}>{installing ? 'Installing…' : state.collector ? 'Retry installation' : 'Install Offense collector'}</button></>}
    {(error || syncError) && <p className="key-error" role="alert">{error || syncError}</p>}
    {/reconnect/i.test(error || syncError) && <a className="secondary-button" href="/api/cloudflare/start">Reconnect Cloudflare</a>}
  </section>;
}
