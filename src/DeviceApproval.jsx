import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, CheckCircle2, Github, KeyRound, ShieldCheck, XCircle } from 'lucide-react';
import { DEVICE_PERMISSION_LABELS as permissionLabels, validateDeviceApprovalRequest } from './device-approval.js';
import './device-approval.css';

const CODE_STORAGE = 'offense.device.user_code';
const normalizeCode = value => {
  const compact = String(value || '').toUpperCase().replace(/[\s-]/g, '');
  // Accept only the short comparison code. Never truncate a credential into
  // a plausible code or display a long device token supplied in a fragment.
  return /^[A-Z0-9]{0,8}$/.test(compact) ? compact.replace(/^(.{4})(.+)$/, '$1-$2') : '';
};
const validCode = value => /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
function saveCode(value) { try { if (validCode(value)) sessionStorage.setItem(CODE_STORAGE, value); else sessionStorage.removeItem(CODE_STORAGE); } catch {} }
function initialCode() {
  const fragment = new URLSearchParams(location.hash.slice(1)).get('code');
  let stored = ''; try { stored = sessionStorage.getItem(CODE_STORAGE) || ''; } catch {}
  const value = normalizeCode(fragment || stored);
  saveCode(value);
  if (fragment) history.replaceState(null, '', location.pathname + location.search);
  return value;
}
const errorMessage = value => ({ expired_token: 'This request expired. Run offense login again in your terminal.',
  access_denied: 'This request was declined. Start login again if you want to connect.',
  invalid_request: 'That code could not be found. Check the code shown in your terminal.' })[value?.error] || 'Could not check this request. Please try again.';

export default function DeviceApproval() {
  const [code, setCode] = useState(initialCode), [account, setAccount] = useState(null);
  const [request, setRequest] = useState(null), [result, setResult] = useState(''), [linkVersion, setLinkVersion] = useState(0);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const inspected = useRef(''), sequence = useRef(0);
  useEffect(() => {
    const receiveCode = () => {
      const incoming = new URLSearchParams(location.hash.slice(1)).get('code');
      if (!incoming) return;
      const next = normalizeCode(incoming);
      sequence.current++; inspected.current = '';
      setCode(next); setRequest(null); setResult(''); setError(''); setBusy(false);
      setLinkVersion(value => value + 1); saveCode(next);
      history.replaceState(null, '', location.pathname + location.search);
    };
    window.addEventListener('hashchange', receiveCode);
    return () => { window.removeEventListener('hashchange', receiveCode); sequence.current++; };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/state', { credentials: 'same-origin', cache: 'no-store', signal: controller.signal })
      .then(async response => { if (!response.ok) throw new Error('unavailable'); return response.json(); })
      .then(value => { if (!controller.signal.aborted) setAccount(value); })
      .catch(() => { if (!controller.signal.aborted) setError('Could not load your account. Reload this page to try again.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, []);

  async function inspect(value = code) {
    if (!validCode(value)) { setError('Enter the eight-character code shown in your terminal.'); return; }
    const current = ++sequence.current;
    setBusy(true); setError(''); setRequest(null); setResult(''); saveCode(value);
    try {
      const response = await fetch('/api/cli/device/inspect', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_code: value }) });
      const data = await response.json();
      if (sequence.current !== current) return;
      if (response.status === 401) { setAccount(previous => ({ ...previous, user: null })); setError('Sign in to review this request.'); return; }
      if (!response.ok) throw Object.assign(new Error(errorMessage(data)), { code: data.error });
      setRequest(validateDeviceApprovalRequest(data, value));
      if (data.status !== 'pending') { setResult(data.status); saveCode(''); }
    } catch (cause) {
      if (sequence.current === current) {
        if (cause.code === 'expired_token') saveCode('');
        setError(cause.message);
      }
    }
    finally { if (sequence.current === current) setBusy(false); }
  }
  useEffect(() => {
    if (!account?.user || !validCode(code) || inspected.current === code) return;
    inspected.current = code;
    void inspect(code);
  }, [account?.user, code, linkVersion]);

  async function decide(approved) {
    if (!request || request.status !== 'pending' || busy) return;
    const current = ++sequence.current;
    setBusy(true); setError('');
    try {
      const response = await fetch('/api/cli/device/approve', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_code: request.user_code, approved }) });
      const data = await response.json();
      if (sequence.current !== current) return;
      if (!response.ok) throw Object.assign(new Error(errorMessage(data)), { code: data.error });
      const expected = approved ? 'approved' : 'denied';
      if (data.status !== expected || data.workspace?.id !== request.workspace.id) throw new Error('The request could not be confirmed. Start login again in your terminal.');
      setResult(expected); saveCode('');
    } catch (cause) {
      if (sequence.current === current) {
        if (cause.code === 'expired_token') { setRequest(null); saveCode(''); }
        setError(cause.message);
      }
    }
    finally { if (sequence.current === current) setBusy(false); }
  }

  return <main className="device-page">
    <header><a className="device-brand" href="/">offense<span>.</span></a><a href="/account">Your account <ArrowRight size={15}/></a></header>
    <section className="device-panel" aria-labelledby="device-heading">
      <span className="device-symbol"><KeyRound size={23}/></span>
      <h1 id="device-heading">{result === 'approved' ? 'CLI connected.' : result === 'denied' ? 'Connection declined.' : 'Connect your terminal'}</h1>
      {loading ? <p role="status">Loading your account…</p> : result ? <div className="device-result" role="status">
        {result === 'approved' ? <CheckCircle2 size={24}/> : <XCircle size={24}/>}
        <p>{result === 'approved' ? 'Return to your terminal to finish setup. Your API key is delivered directly to the CLI.' : 'No API key was issued. You can close this page.'}</p>
        <a className="secondary-button" href="/account">Open your account <ArrowRight size={15}/></a>
      </div> : <>
        <p>Compare this code with the one in the terminal where you started <code>offense login</code>.</p>
        <form onSubmit={event => { event.preventDefault(); inspected.current = code; void inspect(); }}>
          <label htmlFor="offense-device-code">Terminal code</label>
          <input id="offense-device-code" name="user_code" autoComplete="off" autoCapitalize="characters" spellCheck="false" inputMode="text"
            value={code} onChange={event => { const next = normalizeCode(event.target.value); sequence.current++; setBusy(false); setCode(next); setRequest(null); setError(''); saveCode(next); }}
            placeholder="ABCD-EFGH" maxLength="9" readOnly={Boolean(request)} required/>
          {account?.user ? !request && <button className="secondary-button" type="submit" disabled={busy || !validCode(code)}>{busy ? 'Checking…' : 'Check code'} <ArrowRight size={15}/></button> :
            <a className={`primary-button device-signin ${account?.config?.github === false ? 'disabled' : ''}`}
              href={account?.config?.github === false ? undefined : '/api/auth/github/start?returnTo=/device'}
              aria-disabled={account?.config?.github === false} onClick={() => saveCode(code)}><Github size={17}/> Sign in with GitHub</a>}
        </form>
        {request && <div className="device-request">
          <dl><div><dt>Account</dt><dd>{account.user.login}</dd></div><div><dt>Workspace</dt><dd>{request.workspace.name}</dd></div></dl>
          <ul>{request.scopes.map(scope => <li key={scope}><ShieldCheck size={15}/><span>{permissionLabels[scope]}</span></li>)}</ul>
          <p className="device-warning">Approve only if you started this login. Anyone using this terminal’s key can spend this workspace’s available credit. A top-up still requires checkout.</p>
          <div className="device-actions"><button className="primary-button" type="button" onClick={() => void decide(true)} disabled={busy}>{busy ? 'Confirming…' : 'Approve CLI access'}</button>
            <button className="secondary-button" type="button" onClick={() => void decide(false)} disabled={busy}>Decline</button></div>
        </div>}
      </>}
      {error && <p className="device-error" role="alert">{error}</p>}
    </section>
    <footer>Offense · Offense Security</footer>
  </main>;
}
