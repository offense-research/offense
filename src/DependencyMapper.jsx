import { useIssueTrackers, FindingIssueActions } from './IssueTrackers.jsx';
import DependencyExplorer from './DependencyExplorer.jsx';
import FindingsList from './FindingsList.jsx';
import RepositoryAutomation from './RepositoryAutomation.jsx';
import { ArrowRight, ArrowUpRight, ChevronDown, Copy, FlaskConical, GitBranch, GitFork, Github, Plus, Search, Settings2, ShieldAlert } from 'lucide-react';
import { CLOUDFLARE_FEATURES } from './product-features.js';
import SimulationResults from './SimulationResults.jsx';
import { INSTALL_PROMPT } from './SkillInstall.jsx';
import React, { useEffect, useRef, useState } from 'react';
import { useAutoRefresh } from './useAutoRefresh.js';
import { notifyDataChanged } from './auto-refresh.js';
import { severityLevel, severityRank } from './severity.js';
import { buildRemediationPrompt, prepareRepositoryPrompt } from './remediation-prompts.js';
import { promptEvidenceVersion } from './prompt-evidence.js';
import { mergeDependencySnapshot } from './rehearsal-evidence.js';
import ShareCard from './ShareCard.jsx';
import PromptPanel from './PromptPanel.jsx';
import LockfileGuidance from './LockfileGuidance.jsx';
import { sameScanEvidence } from '../shared/scan-evidence.js';
import { assessUpgradeRehearsal } from '../shared/upgrade-verification.js';
import { fixPathSummary, repositoryMonitorStatus } from './fix-workflow.js';

export default function DependencyMapper({ state, onNavigate }) {
  const { integrations: issueTrackers } = useIssueTrackers(state.workspaceId);
  const [repositories, setRepositories] = useState([]);
  const [monitoring, setMonitoring] = useState([]);
  const [simulationTrial, setSimulationTrial] = useState({ available: false });
  const [available, setAvailable] = useState(null);
  const [installations, setInstallations] = useState([]);
  const [adding, setAdding] = useState(false);
  const [choice, setChoice] = useState('');
  const [repoSearch, setRepoSearch] = useState('');
  const [accessWarnings, setAccessWarnings] = useState([]);
  const [mappings, setMappings] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [mapFocus, setMapFocus] = useState(null);
  const [repositoryPickerOpen, setRepositoryPickerOpen] = useState(false);
  const [repositoryTab, setRepositoryTab] = useState(() => state.paymentReturned ? 'simulation' : location.hash === '#fix-prompt' ? 'prompt' : 'findings');
  const [selectedRepository, setSelectedRepository] = useState(() => {
    try { return sessionStorage.getItem(`purple:repository:${state.workspaceId}`) || ''; } catch { return ''; }
  });
  useEffect(() => {
    try { if (selectedRepository) sessionStorage.setItem(`purple:repository:${state.workspaceId}`, selectedRepository); } catch { /* Storage is optional. */ }
  }, [state.workspaceId, selectedRepository]);
  const [findingLimit, setFindingLimit] = useState(10);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState('');
  const promptCache = useRef(new Map());
  const [plans, setPlans] = useState({});
  const [planRevision, setPlanRevision] = useState(0);
  const [planning, setPlanning] = useState('');
  const [promptPlanErrors, setPromptPlanErrors] = useState({});
  const [error, setError] = useState('');
  const [syncError, setSyncError] = useState('');
  const [startingRehearsal, setStartingRehearsal] = useState('');
  const [buyingCredit, setBuyingCredit] = useState(false);
  const [autoConsent, setAutoConsent] = useState(false);
  const [updatingAuto, setUpdatingAuto] = useState(false);

  async function buySimulation(autoTopUp = false) {
    setBuyingCredit(true); setError('');
    try {
      const response = await fetch(autoTopUp ? '/api/billing/auto-top-up' : '/api/billing/checkout', { method: 'POST', headers: { 'content-type': 'application/json' }, ...(autoTopUp ? { body: JSON.stringify({ enabled: true, consentVersion: '5-usd-below-1-cap-20-v1' }) } : {}) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not open payment checkout.');
      const url = new URL(data.url);
      if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname)) throw new Error('Unexpected payment checkout URL.');
      location.assign(url.href);
    } catch (cause) { setError(cause.message); setBuyingCredit(false); }
  }

  async function disableAutoTopUp() {
    setUpdatingAuto(true); setError('');
    try {
      const response = await fetch('/api/billing/auto-top-up', { method: 'DELETE' });
      const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Could not disable auto top-up.');
      setAutoConsent(false); setSimulationTrial(current => ({ ...current, autoTopUp: data.billing.autoTopUp }));
    } catch (cause) { setError(cause.message); }
    finally { setUpdatingAuto(false); }
  }

  async function startRehearsal(item) {
    const key = `${item.installationId}:${item.repository}`;
    setStartingRehearsal(key); setError(''); setRepositoryTab('simulation');
    try {
      const response = await fetch('/api/dependencies/rehearsal', { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...item, refresh: snapshots.some(snapshot => snapshot.repository === item.repository && snapshot.installationId === item.installationId && snapshot.rehearsal?.status === 'completed') }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not start the upgrade rehearsal.');
      if (data.rehearsal.trial) setSimulationTrial(current => ({ ...current, available: false, used: true }));
      else if (data.rehearsal.walletJobId && data.rehearsal.status === 'queued') setSimulationTrial(current => ({ ...current, canPay: false }));
      setSnapshots(current => current.map(snapshot => snapshot.repository === item.repository && snapshot.installationId === item.installationId ? { ...snapshot, rehearsal: data.rehearsal } : snapshot));
    } catch (cause) { setError(cause.message); }
    finally { setStartingRehearsal(''); notifyDataChanged(); }
  }

  async function refresh(signal) {
    try {
      const response = await fetch('/api/dependencies?cached=1', { credentials: 'same-origin', signal });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load dependencies.');
      if (signal.aborted) return;
      setMappings(data.mappings);
      setRepositories(data.repositories || []);
      setSnapshots(data.snapshots);
      setMonitoring(data.monitoring || []);
      setSimulationTrial(data.simulationTrial || { available: false });
      setSelectedRepository(current => (data.repositories || []).some(item => `${item.installationId}:${item.repository}` === current) ? current :
        [...(data.repositories || [])].sort((a, b) => {
          const count = item => data.snapshots.find(snapshot => snapshot.repository === item.repository && snapshot.installationId === item.installationId)?.vulnerabilityCheck?.findings?.length || 0;
          return count(b) - count(a);
        }).map(item => `${item.installationId}:${item.repository}`)[0] || '');
      setPlans(Object.fromEntries(data.snapshots.flatMap(snapshot => (snapshot.upgradePlans || []).filter(plan => plan.plannedAt > Date.now() - 3600000).map(plan =>
        [`${snapshot.installationId}:${snapshot.repository}:${plan.name}:${plan.currentVersion}`, plan]))));
      setSyncError('');
    } catch (cause) { if (!signal.aborted) setSyncError(cause.message); throw cause; }
    finally { if (!signal.aborted) setLoading(false); }
  }
  useAutoRefresh(refresh, { enabled: !adding && !scanning && !planning });

  async function loadAvailable(signal) {
    try {
      const response = await fetch('/api/agent/repositories', { signal });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load GitHub repositories.');
      if (signal.aborted) return;
      setAvailable(data.repositories); setMappings(data.mappings || []); setInstallations(data.installations || []);
      setAccessWarnings(data.warnings || []);
    } catch (cause) { if (!signal.aborted) setAccessWarnings([cause.message]); throw cause; }
  }
  useAutoRefresh(loadAvailable, { enabled: !adding && !scanning && !planning, interval: 60000 });
  // The persisted monitor owns automatic work and its cadence. Opening a tab
  // must not start an extra scan or bypass a paused repository policy.

  async function addRepository() {
    const item = available?.find(repo => `${repo.installationId}:${repo.fullName}` === choice);
    if (!item) return;
    setAdding(true); setError('');
    try {
      const response = await fetch('/api/dependencies/repositories', { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repository: item.fullName, installationId: item.installationId }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not add repository.');
      setRepositories(data.repositories); setMappings(data.mappings);
      setSelectedRepository(choice); setChoice(''); setFilter(''); setFindingLimit(10); setRepositoryPickerOpen(false);
      await scan(item.fullName, item.installationId);
    } catch (cause) { setError(cause.message); }
    finally { setAdding(false); notifyDataChanged(); }
  }
  async function removeRepository(item) {
    setAdding(true); setError('');
    try {
      const response = await fetch('/api/dependencies/repositories', { method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not remove repository.');
      setRepositories(data.repositories); setMappings(data.mappings);
    } catch (cause) { setError(cause.message); }
    finally { setAdding(false); notifyDataChanged(); }
  }

  async function scan(repository, installationId, action = 'scan') {
    const key = `${installationId}:${repository}`;
    setScanning(key); setError('');
    try {
      const response = await fetch(`/api/dependencies/${action}`, {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository, installationId })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not scan dependencies.');
      setSnapshots(current => [...current.filter(item => `${item.installationId}:${item.repository}` !== key),
        mergeDependencySnapshot(current.find(item => `${item.installationId}:${item.repository}` === key), data.snapshot)]);
      setPlans(current => Object.fromEntries(Object.entries(current).filter(([id]) => !id.startsWith(`${key}:`))));
    } catch (cause) { setError(cause.message); }
    finally { setScanning(''); notifyDataChanged(); }
  }

  async function requestPlan(repository, installationId, finding) {
    const key = `${installationId}:${repository}:${finding.package}:${finding.version}`;
    setPlanning(key); setError('');
    try {
      const response = await fetch('/api/dependencies/upgrade-plan', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository, installationId, name: finding.package, version: finding.version })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not plan this upgrade.');
      setPlans(current => ({ ...current, [key]: data.plan }));
      setPlanRevision(value => value + 1);
    } catch (cause) { setError(cause.message); }
    finally { setPlanning(''); }
  }

  async function prepareOneShot(item, snapshot, findings, onProgress) {
    const key = `${item.installationId}:${item.repository}`;
    setPlanning(`${key}:all`); setError('');
    try {
      // Read saved job evidence at copy time: a concurrent scan can otherwise
      // replace the UI snapshot just before this click.
      const response = await fetch('/api/dependencies?cached=1', { signal: AbortSignal.timeout(30000) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load the latest rehearsal evidence.');
      const latest = data.snapshots.find(value => value.repository === item.repository && value.installationId === item.installationId);
      if (!sameScanEvidence(snapshot, latest)) {
        throw new Error('The scan changed. The latest results will appear automatically; try copying again.');
      }
      const result = await prepareRepositoryPrompt({ repository: item.repository, snapshot: latest, findings,
        onProgress: progress => onProgress(`Preparing paths ${progress.completed}/${progress.total}${progress.package ? ` · ${progress.package}` : ''}`),
        loadPlan: async finding => {
          const response = await fetch('/api/dependencies/upgrade-plan', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...item, name: finding.package, version: finding.version }), signal: AbortSignal.timeout(120000)
          });
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || 'Could not generate update path.');
          if (!sameScanEvidence({ repository: item.repository, installationId: item.installationId, ...data.plan }, latest)) {
            throw new Error('The scan changed during planning. The latest results will appear automatically; try copying again.');
          }
          setPlans(current => ({ ...current, [`${key}:${finding.package}:${finding.version}`]: data.plan }));
          return data.plan;
        }
      });
      const finalResponse = await fetch('/api/dependencies?cached=1', { signal: AbortSignal.timeout(30000) });
      const finalData = await finalResponse.json();
      if (!finalResponse.ok) throw new Error('Could not confirm the latest scan. Try copying again.');
      const finalSnapshot = finalData.snapshots.find(value => value.repository === item.repository && value.installationId === item.installationId);
      if (promptEvidenceVersion(finalSnapshot) !== promptEvidenceVersion(latest)) {
        throw new Error('The scan or simulation changed while preparing your prompt. Copy again to include the latest results.');
      }
      setPromptPlanErrors(current => ({ ...current, [key]: { evidence: promptEvidenceVersion(latest), errors: result.planErrors } }));
      if (result.planErrors.length) setError(`${result.planErrors.length} package update path(s) could not be resolved. The prompt includes each blocker and remediation steps; no findings were omitted.`);
      return result.prompt;
    } finally { setPlanning(''); }
  }

  async function validatePreparedPrompt(item, snapshot, compatibilityPassed) {
    const response = await fetch('/api/dependencies?cached=1', { signal: AbortSignal.timeout(30000) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not confirm the latest scan.');
    const latest = data.snapshots.find(value => value.repository === item.repository && value.installationId === item.installationId);
    if (!sameScanEvidence(snapshot, latest) || promptEvidenceVersion(latest) !== promptEvidenceVersion(snapshot) ||
        assessUpgradeRehearsal(latest?.rehearsal, { snapshot: latest }).compatibilityPassed !== compatibilityPassed) {
      notifyDataChanged();
      throw new Error('The scan or simulation changed or expired. Prepare the prompt again to include the latest evidence.');
    }
  }

  if (!state.github) return null;
  const activeRepository = repositories.some(item => `${item.installationId}:${item.repository}` === selectedRepository)
    ? selectedRepository : [...repositories].sort((a, b) => {
      const count = item => snapshots.find(value => value.repository === item.repository && value.installationId === item.installationId)?.vulnerabilityCheck?.findings?.length || 0;
      return count(b) - count(a);
    }).map(item => `${item.installationId}:${item.repository}`)[0];
  const query = filter.trim().toLowerCase();
  const activeMonitor = monitoring.find(item => `${item.installationId}:${item.repository}` === activeRepository);
  const monitorStatus = repositoryMonitorStatus(activeMonitor, { backgroundEnabled: !!state.config.dependencySync, updating: !!scanning });
  const tabs = [
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'map', label: 'Dependency map', icon: GitFork },
    { id: 'simulation', label: 'Simulation', icon: FlaskConical },
    { id: 'prompt', label: 'Fix prompt', icon: Copy },
    { id: 'automation', label: 'Automation', icon: Settings2 }
  ];
  function selectTab(event) {
    const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
    if (!keys.includes(event.key)) return;
    event.preventDefault();
    const current = tabs.findIndex(tab => tab.id === repositoryTab);
    const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    setRepositoryTab(tabs[index].id);
    document.getElementById(`repository-tab-${tabs[index].id}`)?.focus();
  }
  function goToTab(id) {
    setRepositoryTab(id);
    requestAnimationFrame(() => document.getElementById(`repository-tab-${id}`)?.focus());
  }
  return <section id="dependencies" className="dependencies dashboard-panel" aria-labelledby="dependencies-title">
    <div className="repository-page-heading"><div><h1 id="dependencies-title">Dependency security</h1></div><button type="button" className="secondary-button add-repository-button" aria-expanded={repositoryPickerOpen || (!loading && !repositories.length)} aria-controls="add-repository-panel" onClick={() => setRepositoryPickerOpen(value => !value)}><Plus size={16}/> Add repository</button></div>
    {(error || syncError) && <p className="key-error" role="alert">{error || `${syncError} Retrying automatically…`}</p>}
    {(repositoryPickerOpen || (!loading && !repositories.length)) && <section id="add-repository-panel" className="dependency-repository-picker">
      <div className="repository-picker-title"><h2>Add a repository</h2><a href="/api/github/install">Manage GitHub access <ArrowUpRight size={14}/></a></div>
      {accessWarnings.some(value => /authorization|renew|401|403/i.test(value)) && <a className="secondary-button" href="/api/github/start?sync=1">Reconnect GitHub</a>}
      <p className="dashboard-muted">Choose a repository Offense can access. Missing an organization? <a href="/api/github/install">Add it on GitHub.</a></p>
      {installations.map(item => item.settingsUrl && <a className="repository-access-link" key={item.installationId} href={item.settingsUrl} target="_blank" rel="noopener noreferrer">{item.account} repository access <ArrowUpRight size={13}/></a>)}
      {accessWarnings.map((warning, index) => <p className="dependency-warning" key={index}>{warning}</p>)}
      {!available && <p className="dashboard-muted">Loading GitHub repositories…</p>}
      {available && <div className="repository-add-fields"><label className="dependency-search">Search repositories<input type="search" value={repoSearch} onChange={event => setRepoSearch(event.target.value)} placeholder="Organization or repository"/></label><label className="dependency-search">Available repositories<select value={choice} onChange={event => setChoice(event.target.value)} disabled={adding || !!scanning || !!planning}><option value="">Choose a repository</option>{available.filter(item => !repositories.some(repo => repo.repository === item.fullName && repo.installationId === item.installationId) && item.fullName.toLowerCase().includes(repoSearch.toLowerCase())).map(item => <option key={`${item.installationId}:${item.fullName}`} value={`${item.installationId}:${item.fullName}`}>{item.fullName}</option>)}</select></label><button className="primary-button" disabled={!choice || adding || !!scanning || !!planning} onClick={addRepository}>{adding ? 'Adding…' : 'Add and scan'} <ArrowRight size={15}/></button>{!available.length && <p className="dashboard-muted">No repositories available. <a href="/api/github/install">Update GitHub access.</a> This list updates automatically.</p>}</div>}
    </section>}
    {loading && !repositories.length && <div className="repository-loading" role="status"><span className="loading-bar"/><span className="loading-bar"/><span>Loading your repositories…</span></div>}
    {repositories.length > 0 && <div className="repository-context"><div className="repository-selector"><span className="repository-provider"><Github size={20}/></span><label>Repository<select aria-label="Repository" disabled={!!planning || !!scanning} value={activeRepository} onChange={event => { setSelectedRepository(event.target.value); setMapFocus(null); setFilter(''); setSeverityFilter('all'); setFindingLimit(10); setRepositoryTab('findings'); }}>{repositories.map(item => <option key={`${item.installationId}:${item.repository}`} value={`${item.installationId}:${item.repository}`}>{item.repository}</option>)}</select></label><ChevronDown size={14} aria-hidden="true"/></div><span className="repository-watch" data-status={monitorStatus.state} role="status"><span/>{monitorStatus.label}</span></div>}
    {repositories.filter(item => `${item.installationId}:${item.repository}` === activeRepository).map(item => {
      const key = `${item.installationId}:${item.repository}`;
      const snapshot = snapshots.find(value => value.installationId === item.installationId && value.repository === item.repository);
      const check = snapshot?.vulnerabilityCheck;
      const findings = [...(check?.findings || [])].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
      const monitor = monitoring.find(value => value.repository === item.repository && value.installationId === item.installationId);
      const rehearsal = snapshot?.rehearsal;
      const rehearsalRunning = ['queued', 'planning', 'running'].includes(rehearsal?.status);
      const pnpmRepository = snapshot?.files?.some(file => file.endsWith('pnpm-lock.yaml'));
      const criticalCount = findings.filter(finding => severityLevel(finding.severity) === 'critical').length;
      const highCount = findings.filter(finding => severityLevel(finding.severity) === 'high').length;
      const affectedPackages = new Set(findings.map(finding => `${finding.package}:${finding.version}`)).size;
      const repositoryPlans = Object.entries(plans).filter(([name]) => name.startsWith(`${key}:`)).map(([, plan]) => plan);
      const visibleFindings = findings.filter(finding => (severityFilter === 'all' || severityLevel(finding.severity) === severityFilter) && (!query || [finding.package, finding.version, finding.id, finding.summary, ...(finding.cves || [])].some(text => String(text).toLowerCase().includes(query))));
      const busy = !!planning || !!scanning;
      const assessment = assessUpgradeRehearsal(rehearsal, { snapshot });
      const promptVersion = `${state.workspaceId}:${promptEvidenceVersion(snapshot)}:${planRevision}:${assessment.compatibilityPassed}`;
      const requiresLockfile = !!snapshot?.coverage?.missingLockfiles?.length || check?.status === 'no_exact_versions';
      const declaredAssessment = !!snapshot?.coverage?.declaredPackages || /declared_versions/.test(check?.scope || '');
      const preparationErrors = promptPlanErrors[key]?.evidence === promptEvidenceVersion(snapshot) ? promptPlanErrors[key].errors : [];
      const preparation = fixPathSummary(findings, repositoryPlans, preparationErrors);
      const promptProps = scope => ({ cache: promptCache.current, cacheKey: `${key}:${scope}:${promptVersion}`, disabled: busy,
        validate: () => validatePreparedPrompt(item, snapshot, assessment.compatibilityPassed) });
      const repoPrompt = (label = 'Prepare repo fix prompt', primary = true) => <PromptPanel key={`${key}:all:${promptVersion}`} {...promptProps('all')} label={label} primary={primary} preparationSummary={preparation.text} prepare={onProgress => prepareOneShot(item, snapshot, findings, onProgress)}/>;
      const lockfileGuidance = requiresLockfile && <LockfileGuidance repository={item.repository} snapshot={snapshot} busy={busy} onRescan={() => scan(item.repository, item.installationId)}/>;
      const runButton = requiresLockfile ? <button type="button" className="secondary-button" onClick={() => goToTab('prompt')}>Prepare a lockfile <ArrowRight size={15}/></button> : pnpmRepository ? <PromptPanel {...promptProps('agent-simulation')} key={`${key}:agent-simulation:${promptVersion}`} primary label="Copy agent simulation prompt" prepare={async onProgress => `${await prepareOneShot(item, snapshot, findings, onProgress)}\n\nNext, rehearse these upgrades in your agent's isolated test environment using the repository's existing pnpm version. Follow Offense's hosted skill at https://offense.sh/skills/purple/SKILL.md. Record the same baseline and candidate checks, exact resolved dependency changes, and a fresh advisory rescan. Treat compatibility results separately from exploit reproduction. Return the report and updated remediation prompt; do not deploy or merge.`}/> : state.openrouter || simulationTrial.available || simulationTrial.canPay || rehearsalRunning ? <button className={rehearsal ? "secondary-button" : "primary-button"} disabled={!!startingRehearsal || busy || rehearsalRunning || !snapshot} onClick={() => startRehearsal(item)}><FlaskConical size={16}/>{startingRehearsal === key ? 'Starting…' : rehearsalRunning ? 'Simulation running…' : rehearsal?.status === 'completed' ? 'Run new simulation' : rehearsal?.status === 'failed' ? 'Retry simulation' : !state.openrouter && simulationTrial.available ? 'Run free simulation' : !state.openrouter && simulationTrial.canPay ? 'Run simulation · use balance' : 'Simulate an upgrade'}</button> : <>{simulationTrial.paymentsEnabled && <button className="primary-button" disabled={buyingCredit || busy || !!startingRehearsal} onClick={() => buySimulation(false)}>{buyingCredit ? 'Opening checkout…' : 'Add $5 to balance'}</button>}<button className="secondary-button" onClick={() => onNavigate('connections', 'openrouter')}>Use your OpenRouter key <ArrowRight size={15}/></button></>;
      return <div className="dependency-repository" key={key}>
        {repositoryTab === 'findings' && <div className="automation-path"><p>{monitor?.policy?.enabled === false ? 'Background checks are paused for this repository.' : state.config.dependencySync ? 'Offense can check repository changes and review new advisories while you are away.' : 'Choose checks for your pipeline or agent, or run Check again when you need a result.'}</p><button type="button" className="secondary-button" onClick={() => goToTab('automation')}>Automation settings <ArrowRight size={14}/></button></div>}
        {check?.status === 'complete' && findings.length > 0 && !requiresLockfile && repositoryTab === 'findings' && <div className="repository-primary-actions" aria-label="Repository fix actions">{repoPrompt()}<button type="button" className="secondary-button" disabled={busy} onClick={() => goToTab('simulation')}><FlaskConical size={16}/> Test upgrade</button></div>}
        {repositoryTab === 'findings' && <div className="repository-summary" aria-label="Repository scan summary">
          <div className="repository-stat"><span>{declaredAssessment ? 'Potential advisory matches' : 'Advisory matches'}</span><strong>{check?.status === 'complete' ? findings.length : '—'}</strong><small>{check?.checkedPackages ?? snapshot?.packages.filter(value => value.resolved).length ?? 0} {declaredAssessment ? 'version samples checked · incomplete coverage' : 'package versions checked'}</small></div>
          <button className="repository-stat" data-severity="critical" onClick={() => { setSeverityFilter('critical'); goToTab('findings'); }}><span><i/>Critical</span><strong>{check?.status === 'complete' ? criticalCount : '—'}</strong><small>Highest priority</small></button>
          <button className="repository-stat" data-severity="high" onClick={() => { setSeverityFilter('high'); goToTab('findings'); }}><span><i/>High</span><strong>{check?.status === 'complete' ? highCount : '—'}</strong><small>Review next</small></button>
          <div className="repository-stat"><span>Affected packages</span><strong>{check?.status === 'complete' ? affectedPackages : '—'}</strong><small>{declaredAssessment ? 'Requirements needing review' : 'Grouped upgrade targets'}</small></div>
        </div>}
        <div className="repository-scan-caption"><span>{busy ? 'Updating scan…' : check?.checkedAt ? `Last scan ${new Date(check.checkedAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })}` : 'Scan queued'}{snapshot?.revision && <> · <code>{snapshot.revision.slice(0, 7)}</code></>}</span><span>Advisory matches need verification.</span><button type="button" className="secondary-button" disabled={adding || busy} onClick={() => scan(item.repository, item.installationId)}>Check again</button></div>
        {(monitor?.status === 'access_required' || monitor?.status === 'retrying') && <p className="dependency-warning" role="status">{monitor.status === 'access_required' ? <>Repository access changed. <a href="/api/github/install">Restore GitHub access</a> to resume scans.</> : 'Couldn’t check GitHub. Keeping your last results and retrying automatically.'}</p>}
        {snapshot?.warnings?.length > 0 && <div className="scan-coverage-note" role="status"><ShieldAlert size={15}/><span>{snapshot.warnings.length} scan coverage {snapshot.warnings.length === 1 ? 'warning' : 'warnings'}. Results may be incomplete.</span><button type="button" aria-controls="scan-coverage-details" onClick={() => { const details = document.getElementById('scan-coverage-details'); if (details) { details.open = true; details.scrollIntoView({ block: 'center' }); } }}>Review coverage</button></div>}
        <div className="repository-tabs" role="tablist" aria-label="Repository security views">{tabs.map(tab => <button type="button" role="tab" id={`repository-tab-${tab.id}`} aria-controls={`repository-panel-${tab.id}`} aria-selected={repositoryTab === tab.id} tabIndex={repositoryTab === tab.id ? 0 : -1} onKeyDown={selectTab} onClick={() => setRepositoryTab(tab.id)} key={tab.id}><tab.icon size={16}/>{tab.label}{tab.id === 'findings' && check?.status === 'complete' && <span className="repository-tab-count">{findings.length}</span>}{tab.id === 'simulation' && rehearsalRunning && <span className="tab-running-dot"/>}</button>)}</div>
        <div className="repository-tab-panel" role="tabpanel" id={`repository-panel-${repositoryTab}`} aria-labelledby={`repository-tab-${repositoryTab}`} tabIndex={0}>
          {repositoryTab === 'findings' && <>
            {lockfileGuidance}
            <div className="findings-toolbar"><label className="findings-search"><Search size={16}/><input aria-label="Search findings" type="search" value={filter} onChange={event => { setFilter(event.target.value); setFindingLimit(10); }} placeholder="Search packages or CVEs…"/></label><select aria-label="Filter findings by severity" value={severityFilter} onChange={event => { setSeverityFilter(event.target.value); setFindingLimit(10); }}><option value="all">All severities</option>{['critical', 'high', 'medium', 'low', 'unknown'].map(severity => <option key={severity} value={severity}>{severity === 'medium' ? 'Moderate' : severity[0].toUpperCase() + severity.slice(1)}</option>)}</select><span>{visibleFindings.length} {visibleFindings.length === 1 ? 'finding' : 'findings'}</span></div>
            {check?.status === 'complete' ? <FindingsList renderIssueActions={finding => <FindingIssueActions key={JSON.stringify([item.repository, finding.package, finding.version, finding.id])} integrations={issueTrackers} repository={item.repository} installationId={item.installationId} snapshot={snapshot} finding={finding} onSettings={() => onNavigate('connections')}/>} manifestOnly={requiresLockfile} findings={visibleFindings} total={findings.length} limit={findingLimit} onShowMore={() => setFindingLimit(value => value + 10)} plans={repositoryPlans} busy={busy} onPlan={finding => requestPlan(item.repository, item.installationId, finding)} onExplore={finding => { setMapFocus({ name: finding.package, version: finding.version }); goToTab('map'); }} renderPrompt={finding => <PromptPanel key={`${key}:advisory:${finding.id}:${promptVersion}`} {...promptProps(`advisory:${finding.package}:${finding.version}:${finding.id}`)} label={requiresLockfile || finding.resolved === false ? "Copy advisory review prompt" : "Prepare advisory fix prompt"} preparationSummary={fixPathSummary([finding], repositoryPlans, preparationErrors).text} {...(requiresLockfile || finding.resolved === false ? { prompt: buildRemediationPrompt({ repository: item.repository, snapshot, findings: [finding] }) } : { prepare: onProgress => prepareOneShot(item, snapshot, [finding], onProgress) })}/> }/> : <div className="scan-pending-state"><ShieldAlert size={28}/><h3>{check?.status === 'failed' ? 'The scan needs attention' : check?.status === 'no_exact_versions' ? 'A lockfile is needed' : 'Checking dependencies'}</h3><p>{check?.error || (check?.status === 'no_exact_versions' ? 'Add a supported npm or pnpm lockfile to check exact package versions.' : 'Results appear here automatically when the scan finishes.')}</p>{check?.status === 'failed' && <button className="secondary-button" onClick={() => goToTab('prompt')}>Continue in your agent <ArrowRight size={15}/></button>}</div>}

          </>}
          {repositoryTab === 'map' && (requiresLockfile ? lockfileGuidance : snapshot ? <DependencyExplorer key={key} initialPackage={mapFocus} snapshot={snapshot} plans={repositoryPlans} busy={busy} onPlan={finding => requestPlan(item.repository, item.installationId, finding)} renderFix={packageFindings => <PromptPanel key={`${key}:${packageFindings[0]?.package}:${packageFindings[0]?.version}:${promptVersion}`} {...promptProps(`package:${packageFindings[0]?.package}:${packageFindings[0]?.version}`)} label="Prepare package fix prompt" preparationSummary={fixPathSummary(packageFindings, repositoryPlans, preparationErrors).text} primary disabled={busy} prepare={onProgress => prepareOneShot(item, snapshot, packageFindings, onProgress)}/>}/> : <div className="findings-empty"><GitFork size={28}/><h3>Your dependency map is on its way</h3><p>It will appear when the first scan completes.</p></div>)}
          {repositoryTab === 'simulation' && (requiresLockfile ? lockfileGuidance : <>
            {!rehearsal && <div className="simulation-intro"><div className="simulation-intro-icon"><FlaskConical size={24}/></div><div><h2>Try the upgrade before you commit</h2><p>We test upgrade targets in an isolated copy of <strong>{item.repository}</strong>. Your repository stays unchanged.</p></div></div>}
            {rehearsal && <SimulationResults rehearsal={rehearsal} snapshot={snapshot} onContinue={() => goToTab('prompt')} renderAction={({ label }) => repoPrompt(label)}/>}
            {state.paymentReturned && simulationTrial.paymentsEnabled && <p className="dashboard-muted" role="status">{simulationTrial.canPay ? 'Your balance is ready. Start a run below.' : 'Confirming with Whop. Your balance or auto top-up setting will update after verification.'}</p>}
            {findings.length > 0 && !requiresLockfile && <div className={`simulation-start${rehearsal ? ' simulation-rerun' : ''}`}><div>{runButton}<span>{pnpmRepository ? 'Uses your agent’s sandbox.' : state.openrouter ? 'Planning uses your OpenRouter key.' : simulationTrial.available ? 'First simulation included. No API key needed.' : rehearsalRunning ? 'You can leave this page and return.' : simulationTrial.canPay ? `$${((simulationTrial.availableMicros || 0) / 1000000).toFixed(4)} available. OpenRouter cost + 30%; unused balance stays yours.` : simulationTrial.paymentsEnabled ? 'Add $5, then pay OpenRouter cost + 30% per run. Basic scans stay free.' : simulationTrial.used ? 'Your free simulation has been used.' : 'Connect OpenRouter to run hosted simulations.'}</span></div></div>}
            {!requiresLockfile && (simulationTrial.paymentsEnabled || simulationTrial.autoTopUp?.enabled || simulationTrial.autoTopUp?.pending) && <div className="simulation-billing">
              <p><strong>Hosted balance: ${((simulationTrial.balanceMicros || 0) / 1000000).toFixed(4)}</strong> · OpenRouter usage + 30%. We reserve up to $0.10 per run and deduct the actual cost; infrastructure failures return the charge.</p>
              {(simulationTrial.canPay || simulationTrial.available || rehearsalRunning) && <button className="secondary-button" disabled={buyingCredit || !simulationTrial.paymentsEnabled} onClick={() => buySimulation(false)}>Add $5 to balance</button>}
              <details><summary>Auto top-up (optional)</summary>
                <p>Add $5 when your balance falls below $1, up to $20 in any 24 hours. Turn it off here anytime. An already submitted payment may still finish.</p>
                {simulationTrial.autoTopUp?.enabled || simulationTrial.autoTopUp?.pending ? <><p role="status">{simulationTrial.autoTopUp.enabled ? 'Auto top-up is on.' : 'Waiting for Whop to confirm your saved payment method.'}</p><button className="secondary-button" disabled={updatingAuto} onClick={disableAutoTopUp}>Turn off auto top-up</button></> : <>
                  <label><input type="checkbox" checked={autoConsent} onChange={event => setAutoConsent(event.target.checked)}/> I authorize $5 auto top-ups below $1, capped at $20 per 24 hours.</label>
                  <button className="secondary-button" disabled={!autoConsent || buyingCredit || !simulationTrial.paymentsEnabled} onClick={() => buySimulation(true)}>Save payment method for auto top-up</button>
                </>}
                {simulationTrial.autoTopUp?.error && <p role="status">{simulationTrial.autoTopUp.error}</p>}
              </details>
              {simulationTrial.paymentBlocked && <p role="alert">Your balance is under payment review. Contact Offense before continuing.</p>}
            </div>}
            {rehearsal?.billing && <p className="dashboard-muted">This run: OpenRouter ${rehearsal.billing.providerCostUsd.toFixed(6)} + 30% = ${(rehearsal.billing.chargedMicros / 1000000).toFixed(6)}{rehearsal.billing.refunded ? ' · returned to your balance' : ''}.</p>}

            {rehearsal?.status === 'completed' && !rehearsal.stale && <p className="simulation-reuse-note">Saved results stay available. A new run uses your key or balance.</p>}
            {!rehearsal && <div className="simulation-explainer"><div><span>01</span><strong>Check upgrade paths</strong><p>Resolve fixed versions and parent constraints.</p></div><div><span>02</span><strong>Run repository checks</strong><p>Compare the original and candidate checkouts.</p></div><div><span>03</span><strong>Get evidence for your fix</strong><p>Keep test results and blockers in the prompt.</p></div></div>}
            {!findings.length && <p className="dashboard-muted">There are no checked advisory matches to rehearse for this scan.</p>}
        <details className="simulation-privacy"><summary>Code access & sandbox privacy</summary><p>Dependency scans read package manifests and lockfiles. Hosted simulations clone the selected revision into a temporary sandbox and run repository checks. The checkout is temporary; it does not change your source repository. Reports, dependency metadata and command output are retained; command output can contain source snippets.</p><p>Repository commands receive no GitHub or model key. Dependency installation uses public npm package registries. Paid model planning receives dependency metadata, not repository source files. This is a hosted code execution workflow, not a zero-trust or zero-retention guarantee.</p><a href="/skill">Run Offense in your own coding environment <ArrowUpRight size={13}/></a></details>
          </>)}
          {repositoryTab === 'automation' && <RepositoryAutomation key={`${state.workspaceId}:${key}`} repository={item.repository} installationId={item.installationId} monitor={monitor} backgroundEnabled={!!state.config.dependencySync} onSaved={updated => { if (updated) setMonitoring(current => [...current.filter(value => value.repository !== item.repository || value.installationId !== item.installationId), updated]); notifyDataChanged(); }}/>}
          {repositoryTab === 'prompt' && <section id="fix-prompt" className="dependency-next-step" aria-label="Continue in your coding agent">
            {requiresLockfile ? lockfileGuidance : <><div className="fix-prompt-icon"><Copy size={22}/></div><h2>{requiresLockfile ? 'Confirm exact versions before fixing' : 'Your repository. One fix prompt.'}</h2><p>Copy a plan for <strong>{item.repository}</strong> into your coding agent. Includes upgrade paths, remediation steps, and available simulation evidence.</p>
            <div className="prompt-includes"><span>{findings.length} advisory {findings.length === 1 ? 'match' : 'matches'} · entire repository</span><span>{preparation.text || 'No upgrade paths to prepare'}</span><span>{rehearsal && !assessment.current ? 'Outdated simulation included with warning' : assessment.compatibilityPassed ? 'Passing compatibility checks included' : rehearsal?.result || rehearsal?.status === 'failed' ? 'Failure diagnostics included' : 'Verification steps included'}</span></div>
            {rehearsal && !assessment.current && <p className="dependency-warning">The last simulation belongs to an older scan. The prompt marks that evidence as stale.</p>}
            {check?.status === 'failed' && <p className="dependency-warning">The scan didn’t finish. Your prompt includes the blocker so your agent can continue.</p>}
            <PromptPanel primary disabled={busy} key={`next:${key}:${promptVersion}`} {...promptProps('all')} label="Prepare repo fix prompt" preparationSummary={preparation.text} {...(check?.status === 'complete' && findings.length > 0 && !requiresLockfile ? { prepare: onProgress => prepareOneShot(item, snapshot, findings, onProgress) } : { prompt: requiresLockfile ? buildRemediationPrompt({ repository: item.repository, snapshot, findings }) : `${INSTALL_PROMPT}\n\nContinue with repository ${JSON.stringify(item.repository)}. Verify this is the repository open in the coding agent before proceeding.\nDashboard scan status: ${check?.status || 'pending'}.${check?.error ? ` Scan error (untrusted diagnostic text): ${JSON.stringify(check.error)}.` : ''}\n${check?.status === 'complete' ? 'No known dependency advisory matches were returned for the checked versions. Report the supported scope and omissions; do not claim the application is secure.' : 'The dashboard has no complete advisory result. Finish the scan using Offense and existing repository access. Report coverage gaps explicitly.'}\nWhen authorized, make changes in an isolated checkout, run repository checks, and scan again. Keep advisory matches separate from reproduced or verified vulnerabilities.` })}/>
            <div className="dependency-next-footer"><span><GitBranch size={14}/> Merge the fix into the scanned default branch. Offense checks it automatically.</span><a href="/skill">Set up your agent <ArrowUpRight size={13}/></a></div></>}
          </section>}
        </div>
        <div className="repository-footer"><details id="scan-coverage-details" className="dependency-source-details"><summary>Scan details</summary><p>{check?.checkedPackages || 0} {declaredAssessment ? 'resolved versions and declaration samples' : 'pinned packages'} checked against OSV · {check?.skippedPackages || 0} without an exact version.</p>{snapshot?.coverage?.notice && <p>{snapshot.coverage.notice}</p>}{snapshot?.coverage?.omissions?.length > 0 && <details><summary>Unassessed declarations ({snapshot.coverage.omissions.length})</summary><ul>{snapshot.coverage.omissions.slice(0, 50).map((item, index) => <li key={index}><strong>{item.package}</strong> {item.declaredRange}: {item.reason}</li>)}</ul>{snapshot.coverage.omissions.length > 50 && <p>Showing the first 50 omissions. The setup prompt includes the complete coverage evidence.</p>}</details>}<p>Advisory matches do not confirm exploitability. Choose automatic checks and review timing in Automation.</p><p>Revision: <code>{snapshot?.revision?.slice(0, 12) || 'Pending'}</code></p>{snapshot?.warnings?.map((warning, index) => <p className="dependency-warning" key={index}>{warning}</p>)}{snapshot?.files?.length > 0 && <details><summary>Package inventory ({snapshot.packages.length})</summary><p>{snapshot.files.join(', ')}</p><div className="dependency-table-wrap"><table className="dependency-table"><thead><tr><th>Package</th><th>Version</th><th>Use</th></tr></thead><tbody>{snapshot.packages.slice(0, 100).map(value => <tr key={`${value.name}:${value.version}:${value.resolved}`}><td>{value.name}</td><td>{value.version}{!value.resolved && ' *'}</td><td>{value.kind}</td></tr>)}</tbody></table></div>{snapshot.packages.length > 100 && <p>Showing the first 100 package versions.</p>}</details>}<button className="secondary-button" disabled={adding || busy} onClick={() => removeRepository(item)}>Remove repository</button></details>{snapshot && check?.status === 'complete' && !declaredAssessment && snapshot.coverage?.complete !== false && <details className="dependency-share"><summary>Share scan</summary><ShareCard snapshots={[snapshot]} repositories={[item]}/></details>}</div>
      </div>;
    })}
  </section>;
}
