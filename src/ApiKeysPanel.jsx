import React, { useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Check, Copy, Eye, EyeOff, KeyRound, MoreHorizontal, Plus, Search, Trash2, X } from 'lucide-react';
import './api-keys.css';

const date = value => Number.isFinite(value) ? new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(value) : '—';
const money = value => {
  if (!Number.isSafeInteger(value) || value < 0) return '—';
  if (value > 0 && value < 1000) return '< $0.001';
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 3 }).format(value / 1_000_000);
};
function lastScan(key) {
  if (!Number.isFinite(key.lastScanAt)) return key.scanCount === 0 ? 'Never' : '—';
  const seconds = Math.max(0, Math.floor((Date.now() - key.lastScanAt) / 1000));
  if (seconds < 60) return 'Just now';
  for (const [unit, size] of [['day', 86400], ['hour', 3600], ['minute', 60]]) {
    if (seconds >= size) return new Intl.RelativeTimeFormat('en-US', { numeric: 'always' }).format(-Math.floor(seconds / size), unit);
  }
}

export default function ApiKeysPanel({ keys, token, busy, error, heading, onCreate, onRevoke, onClearToken, onCopyError }) {
  const [query, setQuery] = useState(''), [menu, setMenu] = useState(null), [modal, setModal] = useState(null);
  const [creating, setCreating] = useState(false), [deleting, setDeleting] = useState(false);
  const [copied, setCopied] = useState(false), [revealed, setRevealed] = useState(false);
  const dialog = useRef(null), opener = useRef(null), createButton = useRef(null);
  const loaded = Array.isArray(keys), list = loaded ? keys : [];
  const filtered = list.filter(key => key.id.toLowerCase().includes(query.trim().toLowerCase()));
  const capacity = list.length >= 5;

  useEffect(() => {
    if (token) setModal({ type: 'new' });
    else setModal(previous => previous?.type === 'new' ? null : previous);
    setCopied(false); setRevealed(false);
  }, [token]);
  useEffect(() => {
    if (modal && !dialog.current.open) dialog.current.showModal();
    else if (!modal && dialog.current.open) dialog.current.close();
  }, [modal]);
  useEffect(() => {
    if (modal?.type === 'revoke' && loaded && !list.some(key => key.id === modal.key.id)) setModal(null);
  }, [keys, modal]);
  useEffect(() => {
    const outside = event => { if (!event.target.closest('.api-key-menu')) setMenu(null); };
    document.addEventListener('click', outside);
    return () => document.removeEventListener('click', outside);
  }, []);

  function close() {
    if (deleting) return;
    setModal(null);
    if (modal?.type === 'new') onClearToken();
    requestAnimationFrame(() => { if (opener.current?.isConnected) opener.current.focus(); });
  }
  async function create(event) {
    opener.current = event.currentTarget;
    setCreating(true); setMenu(null);
    try { await onCreate(); } finally { setCreating(false); }
  }
  async function revoke() {
    if (deleting || busy || !modal?.key) return;
    setDeleting(true);
    try {
      if (await onRevoke(modal.key.id)) {
        setModal(null);
        requestAnimationFrame(() => { (opener.current?.isConnected ? opener.current : createButton.current)?.focus(); });
      }
    } finally { setDeleting(false); }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(token); setCopied(true); }
    catch { onCopyError('Select the key field and copy it manually.'); }
  }

  return <div className="api-keys-panel">
    <header className="api-keys-heading">
      {heading || <div><h3>API keys</h3><p>Create and manage keys for your agents.</p></div>}
      <button ref={createButton} type="button" className="api-keys-create" disabled={busy || creating || !loaded || capacity}
        title={capacity ? 'Revoke a key before creating another.' : undefined} onClick={create}><Plus size={16}/>{creating ? 'Creating…' : 'New key'}</button>
    </header>
    {error && !modal && <p className="api-keys-error" role="alert">{error}</p>}
    <div className="api-keys-frame">
      <div className="api-keys-toolbar"><label className="api-keys-search"><Search size={16} aria-hidden="true"/>
        <span className="api-key-sr-only">Search API keys</span><input type="search" aria-label="Search API keys" placeholder="Search by key ID…" value={query} onChange={event => setQuery(event.target.value)}/>
        {query && <button type="button" className="api-key-icon-button" aria-label="Clear search" onClick={() => setQuery('')}><X size={14}/></button>}
      </label>{capacity && <span className="api-key-capacity">5 active keys · limit reached</span>}</div>
      <div className="api-keys-scroll" role="region" aria-label="API key activity" tabIndex={0}><table className="api-keys-table" aria-label="API keys">
        <thead><tr><th scope="col">Key</th><th scope="col" className="api-key-last-scan">Last scan</th><th scope="col" className="api-key-runs">Hosted runs</th><th scope="col" className="api-key-spend">Spend</th><th scope="col" className="api-key-created">Created</th><th scope="col" className="api-key-actions"><span className="api-key-sr-only">Actions</span></th></tr></thead>
        <tbody>{!loaded ? <tr className="api-keys-empty"><td colSpan={6}><span role="status">{error ? 'Keys are unavailable.' : 'Loading your keys…'}</span></td></tr>
          : filtered.length === 0 ? <tr className="api-keys-empty"><td colSpan={6}><KeyRound className="api-keys-empty-icon" size={24}/><strong>{query ? 'No matching keys' : 'No API keys yet'}</strong><p>{query ? 'Try another key ID.' : 'Create a key to connect your coding agent.'}</p></td></tr>
            : filtered.map(key => <tr key={key.id}>
              <th scope="row"><div className="api-key-identity"><KeyRound className="api-key-symbol" size={17}/><span><strong>API key</strong><code title={`Key ID: ${key.id}`}>ID {key.id.slice(0, 8)}…{key.id.slice(-4)}</code>
                <small className="api-key-mobile-meta" aria-hidden="true">{Number.isSafeInteger(key.scanCount) ? `${key.scanCount.toLocaleString()} runs · ${money(key.spendMicros)}` : 'Activity unavailable'}</small>
              </span></div></th>
              <td className="api-key-last-scan" title={Number.isFinite(key.lastScanAt) ? new Date(key.lastScanAt).toLocaleString() : undefined}>{lastScan(key)}</td>
              <td className="api-key-runs">{Number.isSafeInteger(key.scanCount) ? key.scanCount.toLocaleString() : '—'}</td>
              <td className="api-key-spend">{money(key.spendMicros)}</td>
              <td className="api-key-created" title={Number.isFinite(key.createdAt) ? new Date(key.createdAt).toLocaleString() : undefined}>{date(key.createdAt)}</td>
              <td className="api-key-actions"><details className="api-key-menu" open={menu === key.id}>
                <summary aria-label={`Actions for key ${key.id.slice(0, 8)}`} onClick={event => { event.preventDefault(); setMenu(previous => previous === key.id ? null : key.id); }}
                  onKeyDown={event => { if (event.key === 'Escape') { setMenu(null); event.currentTarget.focus(); } }}><MoreHorizontal size={19}/></summary>
                <div className="api-key-menu-content"><button type="button" onClick={event => {
                  opener.current = event.currentTarget.closest('details').querySelector('summary');
                  setModal({ type: 'revoke', key }); setMenu(null);
                }}><Trash2 size={14}/> Revoke key</button></div>
              </details></td>
            </tr>)}</tbody>
      </table></div>
      <footer className="api-keys-footer"><span>{loaded ? `${filtered.length}${query ? ` of ${list.length}` : ''} ${list.length === 1 ? 'key' : 'keys'}` : '—'}</span><a href="/skill">Connect your agent <ArrowUpRight size={13}/></a>{loaded && filtered.length > 0 && <span className="api-key-scroll-hint" aria-hidden="true">Swipe to see activity →</span>}</footer>
    </div>
    <dialog ref={dialog} className="api-key-dialog" aria-labelledby="api-key-dialog-title" onCancel={event => { event.preventDefault(); close(); }} onClose={close}
      onClick={event => { if (event.target === event.currentTarget) { const bounds = event.currentTarget.getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) close(); } }}>
      <div className="api-key-dialog-heading"><KeyRound size={20}/><h2 id="api-key-dialog-title">{modal?.type === 'revoke' ? 'Revoke this key?' : 'Your new API key'}</h2><button type="button" className="api-key-icon-button" onClick={close} disabled={deleting} aria-label="Close dialog"><X size={18}/></button></div>
      {modal?.type === 'new' && <>
        <p className="api-key-dialog-copy">Copy this key now. You won’t be able to see it again.</p>
        <div className="api-key-secret"><input aria-label="New Offense API key" autoComplete="off" type={revealed ? 'text' : 'password'} readOnly value={token} onFocus={event => event.target.select()}/>
          <button type="button" className="api-key-icon-button" aria-label={revealed ? 'Hide API key' : 'Show API key'} onClick={() => setRevealed(value => !value)}>{revealed ? <EyeOff size={17}/> : <Eye size={17}/>}</button>
        </div>
        <p className="api-key-copy-status" role="status">{copied ? 'Copied to clipboard.' : 'Use as OFFENSE_API_KEY, or sign in with the Offense CLI.'}</p>
        <div className="api-key-dialog-actions"><button type="button" className="api-key-button" onClick={close}>Done</button><button type="button" className="api-key-button is-primary" onClick={copy}>{copied ? <Check size={15}/> : <Copy size={15}/>}Copy key</button></div>
      </>}
      {modal?.type === 'revoke' && <>
        <p className="api-key-dialog-copy">Requests using this key will stop working.</p><code>ID {modal.key.id.slice(0, 8)}…{modal.key.id.slice(-4)}</code>
        <div className="api-key-dialog-actions"><button type="button" className="api-key-button" onClick={close} disabled={deleting}>Cancel</button><button type="button" className="api-key-button is-danger" onClick={revoke} disabled={deleting || busy}>{deleting ? 'Revoking…' : 'Revoke key'}</button></div>
      </>}
      {error && <p className="api-keys-error" role="alert">{error}</p>}
    </dialog>
  </div>;
}
