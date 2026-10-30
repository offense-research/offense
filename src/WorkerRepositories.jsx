import { useAutoRefresh } from './useAutoRefresh.js';
import { mergeDrafts, notifyDataChanged } from './auto-refresh.js';
import React, { useRef, useState } from 'react';
import { Check, ExternalLink, GitBranch } from 'lucide-react';

function repositoryKey(repository) { return `${repository.installationId}:${repository.fullName}`; }

export default function WorkerRepositories({ state }) {
  const sources = state.collector?.sources || [];
  const [repositories, setRepositories] = useState([]);
  const [installations, setInstallations] = useState([]);
  const [appInfo, setAppInfo] = useState(null);
  const [warnings, setWarnings] = useState([]);
  const [mappings, setMappings] = useState([]);
  const [drafts, setDrafts] = useState({});
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [busyWorker, setBusyWorker] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const savedDrafts = useRef({});

  async function refresh(signal) {
    try {
      const response = await fetch('/api/agent/repositories', { credentials: 'same-origin', signal });
      const access = await response.json();
      if (!response.ok) throw new Error(access.error || 'Could not load repositories.');
      if (signal.aborted) return;
      setRepositories([...access.repositories].sort((a, b) => a.fullName.localeCompare(b.fullName)));
      setInstallations(access.installations); setAppInfo(access.app); setWarnings(access.warnings || []);
      setMappings(access.mappings);
      const next = Object.fromEntries(access.mappings.map(link => [link.sourceWorker, repositoryKey({ installationId: link.installationId, fullName: link.repository })]));
      const previous = savedDrafts.current; savedDrafts.current = next;
      setDrafts(current => mergeDrafts(current, previous, next));
    } catch (cause) { if (!signal.aborted) setWarnings([`${cause.message} Retrying automatically…`]); throw cause; }
    finally { if (!signal.aborted) setLoading(false); }
  }
  const connectedInstallationsKey = JSON.stringify(state.connectedGithubInstallations || []);
  useAutoRefresh(refresh, { enabled: !!state.github && state.config.agent && !busyWorker, interval: 60000,
    dependencies: [connectedInstallationsKey] });

  async function save(sourceWorker, selectedKey) {
    setBusyWorker(sourceWorker);
    setError(''); setNotice('');
    try {
      const selected = repositories.find(repo => repositoryKey(repo) === selectedKey);
      if (selectedKey && !selected) throw new Error('Select a repository that Offense can access.');
      const response = await fetch('/api/agent/mappings', {
        method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sourceWorker, repository: selected?.fullName || '', installationId: selected?.installationId || 0 })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not save repository link.');
      setMappings(data.mappings);
      setDrafts(current => ({ ...current, [sourceWorker]: selectedKey }));
      setNotice(selected ? `${sourceWorker} is linked. Analysis will start for its open investigations.` : `${sourceWorker} is unlinked.`);
    } catch (cause) { setError(cause.message); }
    finally { setBusyWorker(''); notifyDataChanged(); }
  }

  async function selectInstallation(installationId) {
    setBusyWorker('github');
    try {
      const response = await fetch('/api/github/select', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ installationId }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not connect installation.');
      setBusyWorker(''); notifyDataChanged();
    } catch (cause) { setError(cause.message); setBusyWorker(''); }
  }

  if (!state.config.agent || !state.github || !sources.length) return <section className="dashboard-panel"><h2>Worker repositories</h2><p>Connect GitHub and choose Workers to monitor before linking their source code.</p><a className="secondary-button" href="#connections">Manage connections</a></section>;
  const linked = sources.filter(worker => mappings.some(mapping => mapping.sourceWorker === worker)).length;
  return <section id="worker-repositories" className="worker-repositories dashboard-panel" aria-labelledby="worker-repositories-title">
    <div className="worker-repositories-heading"><div><h2 id="worker-repositories-title">Worker repositories <span>{linked}/{sources.length} linked</span></h2></div></div>
    <p className="dashboard-muted">Link Workers to their source code. Linking starts automatic analysis of existing and future investigations.</p>
    {error && <p className="key-error" role="alert">{error}</p>}
    {notice && <p className="worker-repositories-notice" role="status">{notice}</p>}
    <details className="github-access-panel" open={appInfo?.isPublic === false || undefined}><summary>Manage GitHub access</summary>
      <p>Missing a repository? Grant Offense access on the organization that owns it.</p>
      <div className="github-access-accounts">{installations.map(installation => <span key={installation.installationId}>{installation.account} · {installation.accountType || 'account'}</span>)}</div>
      {appInfo?.isPublic === false ? <p className="github-access-warning">The Offense development App is private, so GitHub currently allows installation only on its owner account, {appInfo.owner}. {state.user?.login === appInfo.owner ? <>Make it public in <a href={`https://github.com/settings/apps/${appInfo.slug}/advanced`} target="_blank" rel="noopener noreferrer">GitHub App settings <ExternalLink size={12}/></a> to enable organization installs.</> : <>Ask {appInfo.owner} to make the App public before your organization can install it.</>}</p> : null}
      <div className="github-access-actions">{appInfo?.isPublic !== false && <a className="secondary-button" href="/api/github/install">Install on organization <ExternalLink size={14}/></a>}<a className="secondary-button" href="/api/github/start">Connect existing installation <ExternalLink size={14}/></a></div>
      <small>New organizations and repository access update automatically when you return to Offense. An organization owner may need to approve the installation request in GitHub.</small>
      <div className="worker-repositories-access">{installations.map(installation => <a key={installation.installationId} className="secondary-button" href={installation.settingsUrl} target="_blank" rel="noopener noreferrer">{installation.account} access <ExternalLink size={14}/></a>)}</div>
    </details>
    {warnings.some(value => /authorization|renew|401|403/i.test(value)) && <a className="secondary-button" href="/api/github/start?sync=1">Reconnect GitHub</a>}
    {warnings.map((warning, index) => <p className="key-error" role="alert" key={index}>GitHub installation unavailable: {warning}</p>)}
    {state.githubInstallations?.length > 0 && <div className="worker-repositories-pending"><strong>Choose an installation to add</strong>{state.githubInstallations.map(item => <button key={item.installationId} className="secondary-button" onClick={() => selectInstallation(item.installationId)} disabled={!!busyWorker}>{item.account} · #{item.installationId}</button>)}</div>}
    <div className="worker-repositories-tools"><label>Find a GitHub repository<input type="search" value={filter} onChange={event => setFilter(event.target.value)} placeholder="Search accessible repositories"/></label></div>
    {filter && !repositories.some(repo => repo.fullName.toLowerCase().includes(filter.toLowerCase())) && <p className="dashboard-muted">No accessible repository matches “{filter}”. {installations.length && installations.every(item => item.repositorySelection === 'all') ? 'Offense already sees every repository in the connected account. Find or install Offense on the GitHub account that owns this project.' : 'Check GitHub App access or connect an installation on the account that owns the repository.'}</p>}
    <div className="worker-repositories-list">{sources.map(worker => {
      const savedMapping = mappings.find(mapping => mapping.sourceWorker === worker);
      const saved = savedMapping ? repositoryKey({ installationId: savedMapping.installationId, fullName: savedMapping.repository }) : '';
      const draft = drafts[worker] ?? saved;
      const options = repositories.filter(repo => !filter || repo.fullName.toLowerCase().includes(filter.toLowerCase()) || repositoryKey(repo) === draft || repositoryKey(repo) === saved);
      if (savedMapping && !options.some(repo => repositoryKey(repo) === saved)) options.unshift({ fullName: savedMapping.repository, installationId: savedMapping.installationId, account: 'Access removed', unavailable: true });
      return <div className="worker-repository" key={worker}>
        <div className="worker-repository-name"><GitBranch size={17}/><div><strong>{worker}</strong>{!savedMapping && <small>No repository linked</small>}</div>{savedMapping && <Check size={15} className="worker-repository-check"/>}</div>
        <div className="worker-repository-controls"><label><span className="sr-only">GitHub repository for {worker}</span><select value={draft} onChange={event => setDrafts(current => ({ ...current, [worker]: event.target.value }))} disabled={loading || busyWorker === worker}><option value="">Choose a repository</option>{options.map(repo => <option key={repositoryKey(repo)} value={repositoryKey(repo)} disabled={repo.unavailable}>{repo.fullName} · {repo.account}</option>)}</select></label>{draft !== saved && <button className="secondary-button" disabled={loading || !!busyWorker || !draft} onClick={() => save(worker, draft)}>Save link</button>}{savedMapping && <button className="secondary-button" disabled={loading || !!busyWorker} onClick={() => save(worker, '')}>Unlink</button>}</div>
      </div>;
    })}</div>

  </section>;
}
