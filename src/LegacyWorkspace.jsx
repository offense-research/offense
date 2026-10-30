import IssueTrackerSettings from './IssueTrackers.jsx';
import EmailPreferences from './EmailPreferences.jsx';
import { CommandSearchTrigger } from './CommandPalette.jsx';
import { CLOUDFLARE_FEATURES, productSection } from './product-features.js';
import ScanKeys from './ScanKeys.jsx';
import { useAutoRefresh } from './useAutoRefresh.js';
import { createAutoRefresh, notifyDataChanged } from './auto-refresh.js';
import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, Check, CheckCircle2, Cloud, CreditCard, Eye, EyeOff, Github, GitBranch, KeyRound, LayoutDashboard, LockKeyhole, Menu, PlugZap, ScrollText, ShieldAlert, LogOut, X } from 'lucide-react';
import './style.css';
import './offense-theme.css';
import CollectorInstaller from './CollectorInstaller.jsx';
import WorkspaceDashboard from './WorkspaceDashboard.jsx';
import './product-design.css';

const STEPS = [
  { id: 'github', title: 'GitHub', subtitle: 'Dependency vulnerabilities', description: 'Choose the repositories Offense can scan for known vulnerabilities.', icon: Github, color: 'dark', action: 'Install GitHub App' },
  // Paused: Cloudflare connection. Retained for future re-enabling.
  ...(CLOUDFLARE_FEATURES ? [{ id: 'cloudflare', title: 'Cloudflare', subtitle: 'Optional · runtime monitoring', description: 'Give Offense a view of the account where your products live.', icon: Cloud, color: 'orange', action: 'Connect Cloudflare' }] : []),
  { id: 'openrouter', title: 'OpenRouter', subtitle: 'Optional · more simulations and agents', description: 'Use your key for additional hosted upgrade simulations. Model usage is billed to your OpenRouter account.', icon: KeyRound, color: 'violet', action: 'Add API key' },
];
const canOpen = (state, target) => Boolean(state?.company && (target === 'dependencies' ? state.github : CLOUDFLARE_FEATURES && state.collector?.status === 'installed'));
const DASHBOARD_SECTIONS = new Set(['overview', 'investigations', 'events', 'worker-repositories', 'dependencies']);
const SECTION_LABELS = { overview: 'Overview', investigations: 'Investigations', events: 'Event logs', 'worker-repositories': 'Worker repositories', dependencies: 'Dependencies', collector: 'Cloudflare collector', connections: 'Settings', billing: 'Account & API keys' };
const accountSection = () => location.hash.slice(1) || (['/account', '/billing', '/login'].includes(location.pathname.replace(/\/$/, '')) ? 'billing' : '');
const request = async (url, options = {}) => {
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers: { 'Content-Type': 'application/json', ...options.headers } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Something went wrong.');
  return data;
};
function PurpleMark({ small = false }) { return <svg className="offense-brand-mark" width={small ? 22 : 28} height={small ? 22 : 28} viewBox="0 0 40 40" fill="none" aria-hidden="true" style={{ flexShrink: 0 }}><path d="M5 5h21v8H13v14h14V14h8v21H5V5Z" fill="#ff2e17"/><path d="M30 2h8v8h-8z" fill="#ff2e17"/></svg>; }
function BrandIcon({ step }) {
  const Icon = step.icon;
  return <span className={`brand-icon ${step.color}`}><Icon size={22} strokeWidth={step.id === 'github' ? 2 : 2.2} /></span>;
}
function GitHubPermissionNote() {
  return <details className="github-permission-note"><summary>What GitHub access does Offense need?</summary>
    <p>Scanning uses read-only access to repository contents and details. Select <strong>Only select repositories</strong> on GitHub to limit which repositories Offense can access.</p>
    <p>GitHub grants code access at repository level, so this permission covers more than lockfiles. Dependency discovery reads manifests and lockfiles; hosted simulations read a temporary checkout of the selected revision.</p>
    <p>Offense’s scan app has no permission to push commits, open pull requests, or administer repositories. Those actions would need separate permission later.</p>
    <p>GitHub uses “act on your behalf” wording for account authorization, including sign-in. That wording does not mean Offense has write access. <a href="https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party#difference-between-installation-and-authorization" target="_blank" rel="noreferrer">How GitHub authorization works</a></p>
  </details>;
}

export default function LegacyWorkspace({ onOperatorAccess }) {
  const [state, setState] = useState(null);
  useEffect(() => { onOperatorAccess?.(Boolean(state?.user && state.config?.operations)); }, [state?.user, state?.config?.operations, onOperatorAccess]);
  useEffect(() => () => onOperatorAccess?.(false), [onOperatorAccess]);
  const [paymentReturned] = useState(() => new URLSearchParams(location.search).get('payment') === 'returned');
  const [scannerPaymentReturned] = useState(() => new URLSearchParams(location.search).get('scannerPayment') === 'returned');
  const [company, setCompany] = useState('');
  const [active, setActive] = useState('github');
  const [key, setKey] = useState('');
  const [keyError, setKeyError] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [bootstrapError, setBootstrapError] = useState('');
  const [mobileNav, setMobileNav] = useState(false);
  const [mobileViewport, setMobileViewport] = useState(() => window.matchMedia('(max-width: 800px)').matches);
  const menuTrigger = useRef(null);
  const sidebar = useRef(null);
  const mainContent = useRef(null);
  const pendingFocus = useRef(null);
  const lastDashboardSection = useRef('dependencies');
  const dashboardVisited = useRef(false);
  const [returnToTask, setReturnToTask] = useState(null);
  const [githubAccessError, setGithubAccessError] = useState('');
  const [requirement, setRequirement] = useState(null);
  const [view, setView] = useState('setup');
  const [section, setSection] = useState('connections');
  useEffect(() => {
    const media = window.matchMedia('(max-width: 800px)');
    const update = () => { setMobileViewport(media.matches); if (!media.matches) setMobileNav(false); };
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  useEffect(() => {
    if (!mobileViewport || !mobileNav || !state?.user) return;
    const drawer = sidebar.current;
    if (!drawer) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusable = () => [...drawer.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden');
    const frame = requestAnimationFrame(() => drawer.querySelector('.mobile-close')?.focus());
    function keydown(event) {
      if (event.key === 'Escape') { event.preventDefault(); setMobileNav(false); return; }
      if (event.key !== 'Tab') return;
      const items = focusable(), first = items[0], last = items.at(-1);
      if (!first) { event.preventDefault(); drawer.focus(); }
      else if (event.shiftKey && (document.activeElement === first || !drawer.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !drawer.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
    }
    function keepFocus(event) { if (!drawer.contains(event.target)) (focusable()[0] || drawer).focus(); }
    document.addEventListener('keydown', keydown);
    document.addEventListener('focusin', keepFocus);
    return () => {
      cancelAnimationFrame(frame);
      document.body.style.overflow = previousOverflow;
      document.removeEventListener('keydown', keydown);
      document.removeEventListener('focusin', keepFocus);
      menuTrigger.current?.focus({ preventScroll: true });
    };
  }, [mobileViewport, mobileNav, !!state?.user]);
  useEffect(() => {
    if (!pendingFocus.current || mobileNav) return;
    const selector = pendingFocus.current;
    pendingFocus.current = null;
    const frame = requestAnimationFrame(() => {
      const container = mainContent.current;
      const destination = (selector !== 'heading' && [...(container?.querySelectorAll(selector) || [])].find(element => element.getClientRects().length)) || [...(container?.querySelectorAll('[data-view-heading],h1,h2') || [])].find(element => element.getClientRects().length) || container;
      if (destination) { if (!destination.matches('button,input,a,[tabindex]')) destination.tabIndex = -1; destination.focus({ preventScroll: true }); }
    });
    return () => cancelAnimationFrame(frame);
  }, [view, section, mobileNav]);
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const openCollector = CLOUDFLARE_FEATURES && params.get('step') === 'collector';
    const requestedSection = scannerPaymentReturned ? 'billing' : productSection(accountSection(), true);
    const stop = createAutoRefresh(async signal => {
      try {
      const s = await request('/api/state', { signal });
      if (signal.aborted) return;
      setBootstrapError(''); setState(s);
      setCompany(s.company || s.user?.login || '');
      const needsCollector = CLOUDFLARE_FEATURES && params.get('connected') === 'cloudflare' && s.cloudflare && s.collector?.status !== 'installed';
      setActive(openCollector || needsCollector || requestedSection === 'collector' ? 'cloudflare' : 'github');
      if (requestedSection === 'billing') {
        setView('setup'); setSection('billing');
      } else if (canOpen(s, 'dependencies') && !needsCollector && !openCollector && requestedSection !== 'connections' && requestedSection !== 'collector') {
        setView('complete');
        setSection(DASHBOARD_SECTIONS.has(requestedSection) && canOpen(s, requestedSection) ? requestedSection : 'dependencies');
      } else setSection((openCollector || requestedSection === 'collector') && s.cloudflare ? 'collector' : 'connections');
      stop();
      } catch (error) { if (!signal.aborted) setBootstrapError(error.message); throw error; }
    }, { interval: 3000 });
    if (params.has('error')) setMessage(params.get('error'));
    else if (params.has('connected') && (params.get('connected') === 'github' || CLOUDFLARE_FEATURES)) setMessage(`${params.get('connected') === 'github' ? 'GitHub' : 'Cloudflare'} connected successfully.`);
    else if (params.has('choose_installation')) setMessage('Choose the GitHub account that has Offense installed.');
    else if (params.get('registered') === 'github') setMessage('Offense GitHub App created successfully. You can install it now.');
    else if (params.has('recovered')) setMessage('Signed in with GitHub. Your original connected workspace is now linked to this account.');
    else if (params.has('signed_in')) setMessage(requestedSection === 'billing' ? 'Your Offense account is ready.' : 'Signed in with GitHub. Choose repository access to start your first scan.');
    if (params.size) {
      const investigation = Number(params.get('investigation'));
      const retained = Number.isSafeInteger(investigation) && investigation > 0 ? `?investigation=${investigation}` : '';
      history.replaceState(null, '', `${location.pathname}${retained}${scannerPaymentReturned ? '#billing' : location.hash}`);
    }
    return stop;
  }, []);
  useEffect(() => {
    if (!state) return;
    const frame = requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    return () => cancelAnimationFrame(frame);
  }, [!!state, view, section]);
  useEffect(() => {
    if (!state) return;
    const syncLocation = () => {
      const target = productSection(accountSection(), !!state.github);
      const ready = canOpen(state, 'dependencies');
      const next = target === 'billing' ? 'billing' : DASHBOARD_SECTIONS.has(target) && canOpen(state, target) ? target : target === 'collector' && state.cloudflare ? 'collector' : target === 'connections' || !ready ? 'connections' : 'dependencies';
      setSection(next);
      setView(DASHBOARD_SECTIONS.has(next) ? 'complete' : 'setup');
      if (next === 'collector') setActive('cloudflare');
      pendingFocus.current = 'heading';
      setMobileNav(false);
    };
    window.addEventListener('popstate', syncLocation);
    window.addEventListener('hashchange', syncLocation);
    return () => { window.removeEventListener('popstate', syncLocation); window.removeEventListener('hashchange', syncLocation); };
  }, [state]);
  useAutoRefresh(async signal => {
    if (busy) return;
    const next = await request('/api/state', { signal });
    if (signal.aborted) return;
    setState(previous => JSON.stringify(previous) === JSON.stringify(next) ? previous : next);
    if (next.workspaceId !== state.workspaceId || (!state.github && next.github) || (DASHBOARD_SECTIONS.has(section) && !canOpen(next, section))) {
      const target = section === 'billing' ? 'billing' : canOpen(next, 'dependencies') ? 'dependencies' : 'connections';
      setSection(target); setView(target === 'dependencies' ? 'complete' : 'setup');
    }
  }, { enabled: !!state?.user && !busy, dependencies: [state?.workspaceId] });
  useAutoRefresh(async signal => {
    const data = await request('/api/agent/repositories', { signal });
    if (!signal.aborted) setGithubAccessError((data.warnings || []).find(value => /authorization|renew|401|403/i.test(value)) || '');
  }, { enabled: !!state?.company && !!state?.github && section === 'connections' && !busy, interval: 60000 });
  const current = STEPS.find(step => step.id === active);
  async function beginConnection(id) {
    setMessage('');
    if (id === 'cloudflare' && !CLOUDFLARE_FEATURES) return;
    if (state.config[id] && (id !== 'cloudflare' || state.config.encryption)) {
      setBusy(true);
      try {
        // Support existing deployments that create a workspace after sign-in.
        if (!state.company) {
          const next = await request('/api/company', { method: 'POST', body: JSON.stringify({ company: `${state.user.login} workspace` }) });
          updateWorkspace(next);
        }
        window.location.assign(`/api/${id}/start`);
      } catch (error) { setMessage(error.message); }
      finally { setBusy(false); }
      return;
    }
    setRequirement(id);
  }
  async function saveCompany(e) {
    e.preventDefault(); setBusy(true); setMessage('');
    try { updateWorkspace(await request('/api/company', { method: 'POST', body: JSON.stringify({ company }) })); }
    catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  async function saveKey(e) {
    e.preventDefault(); setBusy(true); setMessage(''); setKeyError('');
    try { const next = await request('/api/openrouter', { method: 'POST', body: JSON.stringify({ key }) }); updateWorkspace(next); setKey(''); setMessage('OpenRouter key verified and saved.'); if (canOpen(next, 'dependencies')) navigate('dependencies'); }
    catch (error) { setKeyError(error.message); }
    finally { setBusy(false); }
  }
  async function disconnect(id) {
    setBusy(true); setMessage('');
    try { setState(await request(`/api/${id}`, { method: 'DELETE' })); if (id === 'github') { setView('setup'); setSection('connections'); history.replaceState(null, '', '#connections'); } }
    catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  async function selectGitHubInstallation(installationId) {
    setBusy(true); setMessage('');
    try { updateWorkspace(await request('/api/github/select', { method: 'POST', body: JSON.stringify({ installationId }) })); setMessage('GitHub connected successfully.'); }
    catch (error) { setMessage(error.message); }
    finally { setBusy(false); }
  }
  function navigate(target, integration) {
    target = productSection(target, !!state.github);
    const next = target === 'billing' ? 'billing' : DASHBOARD_SECTIONS.has(target) && canOpen(state, target) ? target : target === 'collector' && state.cloudflare ? 'collector' : 'connections';
    if (next === 'connections' && integration === 'openrouter' && view === 'complete') setReturnToTask({ workspaceId: state.workspaceId, section });
    else if (next !== 'connections') setReturnToTask(null);
    pendingFocus.current = next === 'connections' && integration === 'openrouter' ? '#openrouter-key' : next === 'dependencies' && returnToTask?.workspaceId === state.workspaceId ? '#repository-tab-simulation' : 'heading';
    setSection(next);
    setView(DASHBOARD_SECTIONS.has(next) ? 'complete' : 'setup');
    if (next === 'collector') setActive('cloudflare');
    else if (next === 'connections' && STEPS.some(step => step.id === integration)) setActive(integration);
    history.pushState(null, '', `#${next}`);
    setMobileNav(false);
  }
  function updateWorkspace(next) {
    const becameReady = canOpen(next, 'dependencies') && !canOpen(state, 'dependencies');
    setState(next);
    notifyDataChanged();
    if (becameReady) {
      setView('complete');
      setSection('dependencies');
      history.replaceState(null, '', '#dependencies');
    }
  }
  function updateContact(contact, action) {
    setState(previous => ({ ...previous, contact }));
    notifyDataChanged();
    if (action !== 'dismiss') setMessage(action === 'remove' ? 'Email removed. Product emails are turned off.' : 'Email preferences saved.');
  }
  async function signOut() {
    setBusy(true);
    try { await request('/api/auth/logout', { method: 'POST' }); location.assign('/'); }
    catch (error) { setMessage(error.message); setBusy(false); }
  }
  if (!state) return <div className="loading"><PurpleMark /><span>{bootstrapError ? `${bootstrapError} Retrying automatically…` : 'Getting Offense ready...'}</span></div>;
  if (!state.user) return <main className="auth-screen"><a className="auth-brand logo" href="/"><PurpleMark/><span>offense<span className="logo-dot">.</span></span></a><div className="auth-panel"><div className="auth-symbol"><ShieldAlert size={26}/></div><h1>{state.legacyWorkspace ? 'Welcome back.' : 'Sign in to Offense'}</h1><p>{state.legacyWorkspace ? 'Sign in to bring your saved workspace and connections with you.' : 'One account, one API key, security tools for your coding agent.'}</p>{message && <div className="setup-warning" role="alert">{message}</div>}<a className={`primary-button auth-button ${state.config.github ? '' : 'disabled'}`} href={state.config.github ? '/api/auth/github/start?returnTo=/legacy' : undefined} aria-disabled={!state.config.github}><Github size={18}/> Continue with GitHub <ArrowRight size={16}/></a><div className="auth-separator"><span/>or<span/></div><a className="secondary-button auth-button" href="/skill">Use Offense in your coding agent <ArrowUpRight size={16}/></a><p className="auth-footnote"><LockKeyhole size={13}/> Signing in creates your account. Repository access is optional and requested separately.</p>{!state.config.github && <p>GitHub sign-in is being configured.</p>}</div><span className="auth-footer">Offense Security</span></main>;
  if (view === 'complete') { lastDashboardSection.current = section; dashboardVisited.current = true; }
  const taskReturn = returnToTask?.workspaceId === state.workspaceId ? returnToTask : null;
  return <div className="app-shell">
    {mobileViewport && mobileNav && <button className="sidebar-backdrop" aria-label="Close menu" aria-hidden="true" tabIndex={-1} onClick={() => setMobileNav(false)}/>}
    <aside id="workspace-navigation" ref={sidebar} className={`sidebar ${mobileNav ? 'open' : ''}`} inert={mobileViewport && !mobileNav} aria-hidden={mobileViewport && !mobileNav ? true : undefined} role={mobileViewport && mobileNav ? 'dialog' : undefined} aria-modal={mobileViewport && mobileNav ? true : undefined} aria-label="Workspace navigation" tabIndex={-1}>
      <div className="sidebar-top"><a className="logo" href={canOpen(state, 'dependencies') ? '#dependencies' : '#billing'} onClick={e => { e.preventDefault(); navigate(canOpen(state, 'dependencies') ? 'dependencies' : 'billing'); }}><PurpleMark /><span>offense<span className="logo-dot">.</span></span></a><button className="mobile-close icon-button" aria-label="Close menu" onClick={() => setMobileNav(false)}><X size={20}/></button></div>
      <div className="workspace-switch workspace-identity"><span className="workspace-avatar">{state.company ? state.company[0].toUpperCase() : 'P'}</span><span><strong>{state.company || 'Your workspace'}</strong></span></div>
      {canOpen(state, 'dependencies') && <><div className="sidebar-label nav-label">Security</div>
        <nav className="side-nav" aria-label="Monitor">
          {state.github && <button className={view === 'complete' && section === 'dependencies' ? 'selected' : ''} aria-current={view === 'complete' && section === 'dependencies' ? 'page' : undefined} onClick={() => navigate('dependencies')}><span className="nav-symbol"><GitBranch size={18}/></span>Dependencies</button>}
          {CLOUDFLARE_FEATURES && state.collector?.status === 'installed' && <><button className={view === 'complete' && section === 'overview' ? 'selected' : ''} aria-current={view === 'complete' && section === 'overview' ? 'page' : undefined} onClick={() => navigate('overview')}><span className="nav-symbol"><LayoutDashboard size={18}/></span>Overview</button>
          <button className={view === 'complete' && section === 'investigations' ? 'selected' : ''} aria-current={view === 'complete' && section === 'investigations' ? 'page' : undefined} onClick={() => navigate('investigations')}><span className="nav-symbol"><ShieldAlert size={18}/></span>Investigations</button>
          <button className={view === 'complete' && section === 'events' ? 'selected' : ''} aria-current={view === 'complete' && section === 'events' ? 'page' : undefined} onClick={() => navigate('events')}><span className="nav-symbol"><ScrollText size={18}/></span>Event logs</button></>}
        </nav></>}
      <div className="sidebar-label nav-label">Workspace</div>
      <nav className="side-nav" aria-label="Setup">
        <button className={section === 'billing' ? 'selected' : ''} aria-current={section === 'billing' ? 'page' : undefined} onClick={() => navigate('billing')}><span className="nav-symbol"><CreditCard size={18}/></span>Account &amp; API keys</button>
        {!state.company ? <button className="selected" aria-current="page" onClick={() => setMobileNav(false)}><span className="nav-symbol"><LayoutDashboard size={18}/></span>Create workspace</button> : <>
          <button className={view === 'setup' && section === 'connections' ? 'selected' : ''} aria-current={view === 'setup' && section === 'connections' ? 'page' : undefined} onClick={() => navigate('connections')}><span className="nav-symbol"><PlugZap size={18}/></span>Settings</button>
          {CLOUDFLARE_FEATURES && state.cloudflare && <button className={view === 'setup' && section === 'collector' ? 'selected' : ''} aria-current={view === 'setup' && section === 'collector' ? 'page' : undefined} onClick={() => navigate('collector')}><span className="nav-symbol"><Cloud size={18}/></span>Cloudflare collector {state.collector?.status === 'installed' && <Check size={14} className="nav-complete"/>}</button>}
          {CLOUDFLARE_FEATURES && state.github && state.collector?.status === 'installed' && <button className={view === 'complete' && section === 'worker-repositories' ? 'selected' : ''} aria-current={view === 'complete' && section === 'worker-repositories' ? 'page' : undefined} onClick={() => navigate('worker-repositories')}><span className="nav-symbol"><GitBranch size={18}/></span>Worker repositories</button>}
        </>}
        <button onClick={() => location.assign('/skill')}><span className="nav-symbol"><ArrowUpRight size={18}/></span>Use in your agent</button>
        {state.config.operations && <button className="metrics-nav-link" onClick={() => location.assign('/metrics')}><span className="nav-symbol"><LayoutDashboard size={18}/></span>Company metrics</button>}
      </nav>
      <div className="sidebar-account"><span className="account-avatar">{state.user.login.slice(0, 1).toUpperCase()}</span><span><strong>{state.user.login}</strong><small>GitHub account</small></span><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={signOut} disabled={busy}><LogOut size={16}/></button></div>
      <div className="sidebar-footer"><a href="/app">Offense console ↗</a></div>
    </aside>
    <main className="main" ref={mainContent} inert={mobileViewport && mobileNav} aria-hidden={mobileViewport && mobileNav ? true : undefined}>
      <header className="topbar"><button ref={menuTrigger} className="mobile-menu icon-button" aria-label="Open menu" aria-expanded={mobileNav} aria-controls="workspace-navigation" onClick={() => setMobileNav(true)}><Menu size={21}/></button><div className="breadcrumbs"><span>{state.company || 'Workspace'}</span><span className="slash">/</span><strong>{state.company ? SECTION_LABELS[section] : 'Create workspace'}</strong></div><CommandSearchTrigger/><a className="topbar-agent-link" href="/skill" aria-label="Use in your agent"><span>Use in your agent</span> <ArrowUpRight size={14}/></a></header>
      <div className="content">
        {message && <div className={`notice ${message.includes('successfully') || message.includes('saved') || message.includes('linked') ? 'success' : ''}`} role="status"><span>{message}</span><button aria-label="Dismiss notification" onClick={() => setMessage('')}><X size={16}/></button></div>}
        {section !== 'billing' && !state.github && !state.collector && (state.company || state.cloudflare) && <div className="workspace-recovery"><span>Already set up Offense on another device?</span><a className="secondary-button" href="/api/auth/github/start">Find existing workspace</a></div>}
        {canOpen(state, 'dependencies') && dashboardVisited.current && <div hidden={view !== 'complete'} inert={view !== 'complete'} aria-hidden={view !== 'complete' ? true : undefined}><WorkspaceDashboard key={state.workspaceId} state={{ ...state, paymentReturned }} section={view === 'complete' ? section : lastDashboardSection.current} onNavigate={navigate} onManage={() => navigate('connections')}/></div>}
        {section === 'billing' ? <><div className="progress-heading"><div><h2 data-view-heading>Account &amp; API keys</h2><p className="dashboard-muted">One API key for security tools. Add credit when you need it.</p></div></div><ScanKeys key={`billing:${state.workspaceId}`} scannerPaymentReturned={scannerPaymentReturned} expanded/></> : view === 'complete' ? null : CLOUDFLARE_FEATURES && section === 'collector' ? <CollectorInstaller key={state.workspaceId} state={state} onInstalled={updateWorkspace}/> : <>
          <div id="connections" className="progress-heading"><div><h2 data-view-heading>{state.github ? 'Settings' : 'Connect your first repository'}</h2><p className="dashboard-muted">{state.github ? 'Manage repository access and optional services.' : 'Signed in. Now choose which repositories Offense can read. GitHub requires this permission separately from sign-in. Dependency scans need no model key.'}</p></div>{state.github && <button className="primary-button" onClick={() => navigate(taskReturn?.section || 'dependencies')}>{taskReturn ? 'Back to upgrade test' : 'View vulnerabilities'} <ArrowRight size={17}/></button>}</div>
          <div className="step-layout"><div className="step-list">{STEPS.filter(step => state.github || active !== 'github' || step.id === 'github').map((step) => <button key={step.id} className={`step-item ${active === step.id ? 'active' : ''}`} onClick={() => { setActive(step.id); setSection('connections'); history.replaceState(null, '', '#connections'); }}><span className={`step-number ${state[step.id] ? 'done' : ''}`}>{state[step.id] ? <Check size={16}/> : <step.icon size={16}/>}</span><span className="step-text"><strong>{step.title}</strong><small>{step.subtitle}</small></span><ArrowRight className="step-arrow" size={18}/></button>)}</div>
            <div className="detail-card"><div className="detail-top"><span className={`detail-status ${state[active] ? 'done' : ''}`}><span/>{state[active] ? 'Connected' : 'Not connected'}</span></div><div className="detail-brand"><BrandIcon step={current}/><div><h3>{current.title}</h3></div></div><p className="detail-description">{current.description}</p>
              {CLOUDFLARE_FEATURES && active === 'cloudflare' && <>{state.cloudflare ? <div className="connected-box"><CheckCircle2 size={20}/><div><strong>{state.cloudflare.name}</strong><span>{state.cloudflare.accounts.length ? state.cloudflare.accounts.map(a => a.name).join(', ') : 'Access granted'}</span></div></div> : <div className="info-box"><Cloud size={17}/><p>You'll choose which Cloudflare accounts Offense can access on Cloudflare's consent screen.</p></div>}<div className="detail-actions">{state.cloudflare ? <><button className="secondary-button" onClick={() => beginConnection('cloudflare')} disabled={busy}>Reconnect permissions</button><button className="secondary-button" onClick={() => disconnect('cloudflare')} disabled={busy}>Disconnect</button></> : <button className="primary-button" onClick={() => beginConnection('cloudflare')}>{current.action} <ArrowUpRight size={17}/></button>}</div>{!state.config.cloudflare && <p className="config-note">Provider setup is required for this preview.</p>}{requirement === 'cloudflare' && <div className="setup-warning" role="alert"><strong>Cloudflare connection isn't ready yet</strong><p>Cloudflare connection is temporarily unavailable. Please try again later.</p></div>}</>}
              {active === 'github' && <><GitHubPermissionNote/>{state.github ? <div className="connected-box"><CheckCircle2 size={20}/><div><strong>{state.github.account}</strong><span>Repository access granted</span></div></div> : !state.githubInstallations?.length ? <div className="info-box"><Github size={17}/><p>Connect an existing Offense installation, or install it on a GitHub account.</p></div> : null}{state.githubInstallations?.length > 0 && <div className="github-installation-options"><p>Choose an additional GitHub account where Offense is installed:</p>{state.githubInstallations.map(item => <button key={item.installationId} className="secondary-button" onClick={() => selectGitHubInstallation(item.installationId)} disabled={busy}>{item.account}</button>)}</div>}<div className="detail-actions">{state.github ? <><a className="secondary-button" href="/api/github/install">Add GitHub organization <ArrowUpRight size={17}/></a>{githubAccessError && <a className="secondary-button" href="/api/github/start?sync=1">Reconnect GitHub</a>}<button className="secondary-button" onClick={() => disconnect('github')} disabled={busy}>Remove from Offense</button></> : state.githubInstallations?.length ? <a className="secondary-button" href="/api/github/install">Install on another account <ArrowUpRight size={17}/></a> : <button className="primary-button" onClick={() => beginConnection('github')}>Choose repository access <ArrowUpRight size={17}/></button>}</div>{!state.config.github && <p className="config-note">Provider setup is required for this preview.</p>}{requirement === 'github' && <div className="setup-warning" role="alert"><strong>GitHub installation isn't ready yet</strong><p>GitHub connection is temporarily unavailable. Please try again later.</p></div>}</>}
              {active === 'openrouter' && <>{state.openrouter ? <><div className="connected-box"><CheckCircle2 size={20}/><div><strong>{state.openrouter.label}</strong><span>Key ending in •••• {state.openrouter.last4}</span></div></div><div className="detail-actions"><button className="secondary-button" onClick={() => disconnect('openrouter')} disabled={busy}>Remove key</button></div></> : <form onSubmit={saveKey}><label className="field-label" htmlFor="openrouter-key">OpenRouter API key</label><div className="key-input"><KeyRound size={17}/><input id="openrouter-key" type={showKey ? 'text' : 'password'} value={key} onChange={e => { setKey(e.target.value); setKeyError(''); }} placeholder="sk-or-v1-..." autoComplete="off" required/><button type="button" aria-label={showKey ? 'Hide key' : 'Show key'} onClick={() => setShowKey(!showKey)}>{showKey ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div><p className="field-hint"><LockKeyhole size={13}/> Encrypted before storage. Never shown again.</p><div className="detail-actions"><button type="submit" className="primary-button" disabled={busy || !key || !state.config.encryption}>{busy ? 'Verifying...' : 'Verify & save key'} <ArrowRight size={17}/></button></div>{keyError && <p className="key-error" role="alert">{keyError}</p>}</form>}{!state.config.encryption && <p className="config-note">Key storage is temporarily unavailable. Please try again later.</p>}<a className="text-link" href="https://openrouter.ai/keys" target="_blank" rel="noreferrer">Get an OpenRouter key <ArrowUpRight size={14}/></a></>}

            </div></div>
          {state.github && <IssueTrackerSettings key={`trackers:${state.workspaceId}`} workspaceId={state.workspaceId}/>}
          <div className="billing-settings-link"><h3>Hosted security scans</h3><p className="dashboard-muted">Manage prepaid scan credit, pricing, and your agent’s scan keys.</p><button className="secondary-button" onClick={() => navigate('billing')}>Open billing &amp; scan keys <ArrowRight size={16}/></button></div>
          {state.github && state.contact && <EmailPreferences key={`email-settings:${state.user.githubId}`} contact={state.contact} onSaved={updateContact}/>}
          {state.github && <details className="workspace-settings"><summary>Workspace name (optional)</summary><form className="name-card" onSubmit={saveCompany}><label htmlFor="company">Display name</label><div className="name-row"><input id="company" value={company} onChange={e => setCompany(e.target.value)} minLength="2" maxLength="80" required/><button className="secondary-button" disabled={busy}>Save name</button></div></form></details>}
        </>}
      </div>
    </main>
  </div>;
}
