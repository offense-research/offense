import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, BarChart3, BookOpen, Check, Copy, CreditCard, Github, KeyRound, LogOut, Settings, TerminalSquare, Wrench } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
import { notifyDataChanged } from './auto-refresh.js';
import { OFFENSE_INSTALL_PROMPT } from './SkillInstall.jsx';
import ScanKeys from './ScanKeys.jsx';
import ActivityDashboard from './ActivityDashboard.jsx';
import ToolCatalog from './ToolCatalog.jsx';
import { CommandSearchTrigger } from './CommandPalette.jsx';
import { resolveProductRoute } from './product-routing.js';
import EmailPreferences from './EmailPreferences.jsx';
import './agent-console.css';

const sections = [
  { id: 'start', label: 'Get started', icon: TerminalSquare, title: 'Connect your agent', description: 'Security tools in the coding workflow you already use.' },
  { id: 'tools', label: 'Tools', icon: Wrench, title: 'Security tools', description: 'Inspect a tool and its price before asking your agent to run it.' },
  { id: 'keys', label: 'API keys', icon: KeyRound, title: 'API keys', description: 'Create and manage keys for your agents.' },
  { id: 'activity', label: 'Activity', icon: BarChart3, title: 'Activity', description: 'Your security tool usage across Offense.' },
  { id: 'billing', label: 'Billing', icon: CreditCard, title: 'Billing', description: 'Prepaid credit for the hosted tools you choose to run.' },
  { id: 'settings', label: 'Settings', icon: Settings, title: 'Account settings', description: 'Your identity and communication preferences.' },
];
const sectionIds = new Set(sections.map(section => section.id));
const privateSections = new Set(['keys', 'activity', 'billing', 'settings']);
const returnSectionKey = 'offense.console.returnSection';
const canonicalSection = section => section === 'usage' ? 'activity' : section;
const initialTab = initialSection => {
  const params = new URLSearchParams(location.search);
  if (params.get('scannerPayment') === 'returned' || params.get('scannerSetup') === 'returned') return 'billing';
  const hash = canonicalSection(location.hash.slice(1)), initial = canonicalSection(resolveProductRoute(location.pathname, location.hash, location.search).section || initialSection);
  return sectionIds.has(hash) ? hash : sectionIds.has(initial) ? initial : 'start';
};

async function readJson(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
  let value;
  try { value = await response.json(); } catch { throw new Error('Offense could not load this information. Retrying automatically.'); }
  if (!response.ok) throw new Error(typeof value?.error === 'string' ? value.error : value?.error?.message || 'Offense could not load this information. Retrying automatically.');
  return value;
}

function Mark() {
  return <svg width="26" height="26" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M5 5h21v8H13v14h14V14h8v21H5V5Z" fill="currentColor"/><path d="M30 2h8v8h-8z" fill="currentColor"/></svg>;
}

function GettingStarted() {
  const [method, setMethod] = useState('agent'), [client, setClient] = useState('codex');
  const [copied, setCopied] = useState(''), [copyError, setCopyError] = useState('');
  const promptField = useRef(null), promptDetails = useRef(null), codeField = useRef(null);
  const cli = `npm install --global https://offense.sh/downloads/offense-cli.tgz\noffense login\noffense mcp install --client ${client} --project .`;
  const api = `curl https://offense.sh/v1/catalog\n\ncurl https://offense.sh/v1/tools \\\n  -H "Authorization: Bearer $OFFENSE_API_KEY"`;
  const value = method === 'agent' ? OFFENSE_INSTALL_PROMPT : method === 'cli' ? cli : api;
  async function copy() {
    try { await navigator.clipboard.writeText(value); setCopied(method); setCopyError(''); }
    catch {
      setCopyError(method === 'agent' ? 'Select and copy the installation prompt below.' : 'Select and copy the commands below.');
      if (method === 'agent' && promptDetails.current) promptDetails.current.open = true;
      requestAnimationFrame(() => { const field = method === 'agent' ? promptField.current : codeField.current; field?.focus(); field?.select(); });
    }
  }
  function choose(next) { setMethod(next); setCopied(''); setCopyError(''); }
  return <>
    <section className="console-install-card" aria-labelledby="console-install-heading">
      <div className="console-install-tabs" role="group" aria-label="Choose setup method">{[
        { id: 'agent', title: 'Coding agent' }, { id: 'cli', title: 'CLI' }, { id: 'api', title: 'API' }
      ].map(option => <button key={option.id} type="button" aria-pressed={method === option.id} onClick={() => choose(option.id)}>{option.title}</button>)}</div>
      <div className="console-install-content">
        <div className="console-install-heading"><div><h2 id="console-install-heading">{method === 'agent' ? 'Paste once. Work from your agent.' : method === 'cli' ? 'Install the Offense CLI' : 'One API key for hosted tools'}</h2><p>{method === 'agent' ? 'Copy the setup prompt into Codex, Claude Code, or Cursor.' : method === 'cli' ? 'Sign in in your browser, then connect your project.' : 'Browse the public catalog, then use your key for account tools.'}</p></div>
          <button type="button" className="console-primary" onClick={copy}>{copied === method ? <Check size={16}/> : <Copy size={16}/>} {copied === method ? 'Copied' : method === 'agent' ? 'Copy setup prompt' : 'Copy commands'}</button></div>
        {method === 'agent' ? <>
          <div className="console-prompt-preview"><TerminalSquare size={19}/><p>Set up Offense in this coding agent for the current project.</p><span>SKILL + MCP</span></div>
          <details className="console-prompt-inspect" ref={promptDetails}><summary>Read installation prompt</summary><textarea ref={promptField} aria-label="Offense installation prompt" value={OFFENSE_INSTALL_PROMPT} readOnly spellCheck="false" rows={9}/></details>
        </> : <>
          {method === 'cli' && <label className="console-client-picker">Coding agent<select value={client} onChange={event => { setClient(event.target.value); setCopied(''); }}><option value="codex">Codex</option><option value="claude">Claude Code</option><option value="cursor">Cursor</option></select></label>}
          <pre className="console-setup-code"><code>{value}</code></pre>
          {copyError && <textarea ref={codeField} aria-label="Offense setup commands" value={value} readOnly spellCheck="false" rows={5}/>}
        </>}
        <p className="console-copy-status" role="status">{copyError || (copied === method ? method === 'api' ? 'Copied. Set OFFENSE_API_KEY in your environment before authenticated requests.' : 'Copied. Start a new agent session after setup.' : '')}</p>
      </div>
      <div className="console-install-note">{method === 'api' ? <><KeyRound size={15}/><span>Create an API key in your account. Catalog access and basic advisory checks are free.</span></> : <><ArrowRight size={15}/><span>After installation, <strong>start a new agent session in this same project.</strong></span></>}</div>
    </section>
    <div className="console-start-next"><div><span className="console-overline">Your first check</span><p>“Check my dependencies for security issues and fix anything critical.”</p></div><a href="/skills/offense/SKILL.md">Read the skill <BookOpen size={16}/></a></div>
    <p className="console-start-footer">Basic dependency advisory checks are free. Hosted tools use prepaid credit and a price quote before each paid call.</p>
  </>;
}

export default function AgentConsole({ initialSection = 'start', onOperatorAccess }) {
  const [section, setSection] = useState(() => initialTab(initialSection));
  const [state, setState] = useState(null), [stateError, setStateError] = useState('');
  const [notice, setNotice] = useState(() => new URLSearchParams(location.search).get('error') || '');
  const [signingOut, setSigningOut] = useState(false);
  const [scannerPaymentReturned] = useState(() => new URLSearchParams(location.search).get('scannerPayment') === 'returned');
  const [scannerSetupReturned] = useState(() => new URLSearchParams(location.search).get('scannerSetup') === 'returned');
  const heading = useRef(null), focusPending = useRef(false);
  const definition = sections.find(item => item.id === section) || sections[0];
  const signedIn = Boolean(state?.user && state.workspaceId);
  useEffect(() => { onOperatorAccess?.(signedIn && state?.config?.operations === true); }, [signedIn, state?.config?.operations, onOperatorAccess]);
  useEffect(() => () => onOperatorAccess?.(false), [onOperatorAccess]);

  function navigate(next, { replace = false, focus = true } = {}) {
    if (!sectionIds.has(next)) return;
    focusPending.current = focus;
    if (section === next && focus) heading.current?.focus({ preventScroll: true });
    setSection(next);
    const url = new URL(location.href);
    if (next !== 'tools') url.searchParams.delete('tool');
    url.hash = next;
    if (location.href !== url.href) history[replace ? 'replaceState' : 'pushState'](null, '', `${url.pathname}${url.search}${url.hash}`);
  }
  useEffect(() => {
    // Keep this listener stable while Product updates its route in the same
    // browser event; replacing it mid-dispatch can miss Back/Forward changes.
    const sync = () => { const next = initialTab(); focusPending.current = true; setSection(next); };
    window.addEventListener('hashchange', sync); window.addEventListener('popstate', sync);
    return () => { window.removeEventListener('hashchange', sync); window.removeEventListener('popstate', sync); };
  }, []);
  useEffect(() => {
    const url = new URL(location.href);
    let changed = false;
    // Keep the visible payment destination in browser history after removing
    // the one-time return flag, including when /account normally opens keys.
    if (scannerPaymentReturned || scannerSetupReturned) url.hash = 'billing';
    else if (url.hash === '#usage') { url.hash = 'activity'; changed = true; }
    for (const name of ['scannerPayment', 'scannerSetup', 'signed_in', 'recovered', 'error']) {
      if (url.searchParams.has(name)) { url.searchParams.delete(name); changed = true; }
    }
    if (changed) history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
  }, []);
  useEffect(() => {
    if (!focusPending.current) return;
    focusPending.current = false;
    heading.current?.focus({ preventScroll: true });
  }, [section]);
  useAutoRefresh(async signal => {
    try {
      const next = await readJson('/api/state', { signal });
      if (!next || typeof next !== 'object' || next.user && typeof next.user.login !== 'string') throw new Error('Account information is incomplete. Retrying automatically.');
      if (signal.aborted) return;
      setState(previous => JSON.stringify(previous) === JSON.stringify(next) ? previous : next); setStateError('');
    } catch (cause) { if (!signal.aborted) setStateError(cause.message); throw cause; }
  }, { interval: 30000 });
  useEffect(() => {
    if (!signedIn) return;
    try {
      const requested = canonicalSection(sessionStorage.getItem(returnSectionKey));
      sessionStorage.removeItem(returnSectionKey);
      if (privateSections.has(requested) && !location.hash && !scannerPaymentReturned && !scannerSetupReturned) navigate(requested, { replace: true, focus: false });
    } catch { /* Session storage is an optional navigation convenience. */ }
  }, [signedIn, state?.workspaceId]);
  function rememberSignIn() { try { sessionStorage.setItem(returnSectionKey, privateSections.has(section) ? section : 'keys'); } catch { /* Sign-in works without browser storage. */ } }
  async function signOut() {
    setSigningOut(true); setNotice('');
    try {
      await readJson('/api/auth/logout', { method: 'POST', headers: { 'content-type': 'application/json' } });
      setState(null); location.assign('/app');
    } catch (cause) { setNotice(cause.message); setSigningOut(false); }
  }
  function saveContact(contact, action) {
    setState(previous => ({ ...previous, contact })); notifyDataChanged();
    if (action !== 'dismiss') setNotice(action === 'remove' ? 'Email removed.' : 'Email preferences saved.');
  }
  const signIn = <a href="/api/auth/github/start?returnTo=/account" className="console-primary" onClick={rememberSignIn} aria-disabled={state?.config?.github === false || undefined}
    {...(state?.config?.github === false ? { onClick: event => event.preventDefault() } : {})}><Github size={16}/> Continue with GitHub <ArrowRight size={15}/></a>;
  const pageHeading = <div className="console-page-heading"><h1 ref={heading} tabIndex={-1}>{definition.title}</h1><p>{definition.description}</p></div>;
  return <div className="agent-console">
    <header className="console-header"><div className="console-header-inner"><a className="console-brand" href="/" aria-label="Offense home"><Mark/><span>offense<span className="console-brand-dot">.</span></span></a><span className="console-header-label">Console</span>
      <div className="console-header-account"><CommandSearchTrigger/>{signedIn ? <><button type="button" className="console-profile" onClick={() => navigate('settings')} title={`Account: ${state.user.login}`}><span aria-hidden="true">{state.user.login.slice(0, 1).toUpperCase()}</span><strong>{state.user.login}</strong></button><button className="console-icon-button" type="button" onClick={signOut} disabled={signingOut} aria-label="Sign out"><LogOut size={17}/></button></> : <a href="/api/auth/github/start?returnTo=/account" className="console-signin" aria-disabled={state?.config?.github === false || undefined} onClick={event => state?.config?.github === false ? event.preventDefault() : rememberSignIn()}>Sign in <ArrowUpRight size={14}/></a>}</div>
    </div></header>
    <nav className="console-nav" aria-label="Offense console">{sections.map(item => { const Icon = item.icon; return <button type="button" key={item.id} onClick={() => navigate(item.id)} aria-current={section === item.id ? 'page' : undefined}><Icon size={16}/>{item.label}</button>; })}</nav>
    <main className="console-main">
      {notice && <div className="console-notice" role="status"><span>{notice}</span><button type="button" onClick={() => setNotice('')} aria-label="Dismiss notification">×</button></div>}
      {!(signedIn && ['keys', 'activity'].includes(section)) && pageHeading}
      {section === 'start' ? <GettingStarted/> : section === 'tools' ? <ToolCatalog/> : !signedIn ? <section className="console-auth-card" aria-label="Sign in to your account">
        {!state && !stateError ? <p className="console-muted" role="status">Checking your account…</p> : <><KeyRound size={25}/><h2>Sign in to manage {section === 'settings' ? 'your account' : section === 'keys' ? 'API keys' : section}.</h2><p>Get $5 in free credit for hosted tools. Your account works across devices.</p>{signIn}{state?.config?.github === false && <p className="console-error">GitHub sign-in is temporarily unavailable.</p>}</>}
        {stateError && <p className="console-error" role="alert">{stateError}</p>}
      </section> : section === 'keys' || section === 'billing' ? <ScanKeys key={`${state.workspaceId}:${section}`} mode={section} expanded heading={section === 'keys' ? pageHeading : undefined} scannerPaymentReturned={section === 'billing' && scannerPaymentReturned}/> : section === 'activity' ? <ActivityDashboard key={`activity:${state.workspaceId}`} heading={pageHeading}/> : <section className="console-settings">
        <div className="console-account-identity"><div><span className="console-overline">Signed in with GitHub</span><h2>{state.user.login}</h2><p>{state.company || 'Your Offense account'}</p></div><button type="button" className="console-secondary" onClick={signOut} disabled={signingOut}>Sign out <LogOut size={15}/></button></div>
        <EmailPreferences key={state.workspaceId} contact={state.contact} onSaved={saveContact}/>
        {state.config?.operations && <p className="console-operator-link"><a href="/metrics">Company metrics <ArrowUpRight size={14}/></a></p>}
        <div className="console-legacy-link"><span>Existing V1 projects and connections</span><a href="/legacy">Open V1 workspace <ArrowUpRight size={14}/></a></div>
      </section>}
    </main>
    <footer className="console-footer"><span>Offense Security</span><div><a href="/skill">Agent setup</a><a href="/skills/offense/SKILL.md">Documentation</a><a href="/v1/catalog">API catalog</a></div></footer>
  </div>;
}
