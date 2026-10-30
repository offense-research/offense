import React, { useEffect, useState } from 'react';
import { ArrowUpRight } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
const names = {linear:'Linear',jira:'Jira'};
async function request(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'content-type':'application/json', ...options.headers } });
  const data = await response.json(); if (!response.ok) throw Error(data.error || 'Could not reach issue tracker.'); return data;
}
export function useIssueTrackers(workspaceId) {
  const [integrations,setIntegrations] = useState([]), [error,setError] = useState('');
  async function refresh(signal) { try {
    const response = await fetch('/api/issue-trackers', { signal });
    // A frontend rollout can precede optional tracker support in the API.
    if (response.status === 404) { if (!signal?.aborted) { setIntegrations([]); setError(''); } return; }
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Could not reach issue tracker.');
    if (!signal?.aborted) { setIntegrations(data.integrations || []); setError(''); }
  } catch(cause) { if (!signal?.aborted) setError(cause.message); } }
  useEffect(() => { setIntegrations([]); setError(''); }, [workspaceId]);
  useAutoRefresh(refresh, { enabled: !!workspaceId, interval:30000, dependencies:[workspaceId] });
  return {integrations,error,refresh};
}
function TrackerSetting({ integration, refresh }) {
  const {provider,connected,target} = integration;
  const [editing,setEditing] = useState(false), [options,setOptions] = useState(null), [choice,setChoice] = useState({}), [busy,setBusy] = useState(false), [error,setError] = useState('');
  const selecting = connected && (editing || !target);
  useEffect(() => {
    if (!selecting) return;
    const controller = new AbortController(); setOptions(null); setError('');
    const query = new URLSearchParams({ ...(choice.siteId?{siteId:choice.siteId}:{}), ...(choice.projectId?{projectId:choice.projectId}:{}) });
    request(`/api/issue-trackers/${provider}/destinations?${query}`,{signal:controller.signal}).then(data=>{if (!controller.signal.aborted) setOptions(data);}).catch(cause=>{if (!controller.signal.aborted) setError(cause.message);});
    return ()=>controller.abort();
  },[provider,selecting,choice.siteId,choice.projectId]);
  async function save(event) { event.preventDefault(); setBusy(true); setError(''); try { await request(`/api/issue-trackers/${provider}/target`,{method:'PUT',body:JSON.stringify(choice)}); await refresh(); setEditing(false); } catch(cause) {setError(cause.message);} finally {setBusy(false);} }
  async function disconnect() {setBusy(true);setError('');try{await request(`/api/issue-trackers/${provider}`,{method:'DELETE'});await refresh();setChoice({});setEditing(false);}catch(cause){setError(cause.message);}finally{setBusy(false);}}
  function select(label,field,values,change) {return <label>{label}<select aria-label={label} value={choice[field]||''} required onChange={event=>setChoice(change?change(event.target.value):{...choice,[field]:event.target.value})}><option value="">Choose {label.toLowerCase()}</option>{values?.map(value=><option key={value.id} value={value.id}>{value.name}</option>)}</select></label>;}
  return <div className="tracker-setting"><div className="tracker-heading"><div><strong>{names[provider]}</strong><p>{connected ? target?.name || 'Choose where findings go' : 'Send findings with their remediation plan'}</p></div>{!connected ? <a className="secondary-button" href={`/api/issue-trackers/${provider}/start`}>Connect <ArrowUpRight size={14}/></a> : <div className="tracker-buttons">{target && <button className="secondary-button" onClick={()=>{setChoice({});setEditing(value=>!value);}} disabled={busy}>{editing?'Cancel':'Change destination'}</button>}<button className="text-link" onClick={disconnect} disabled={busy}>Disconnect</button></div>}</div>
    {selecting && <form className="tracker-destination" onSubmit={save}>
      {!options && !error && <p role="status">Loading destinations…</p>}
      {options && provider==='linear' && select('Team','teamId',options.teams)}
      {options && provider==='jira' && <>{select('Site','siteId',options.sites,siteId=>({siteId}))}{choice.siteId && select('Project','projectId',options.projects,projectId=>({siteId:choice.siteId,projectId}))}{choice.projectId && select('Issue type','issueTypeId',options.issueTypes)}</>}
      {options && ((provider==='linear' && choice.teamId) || (provider==='jira' && choice.issueTypeId)) && <button className="secondary-button" disabled={busy}>{busy?'Saving…':'Save destination'}</button>}
      {options && (provider==='linear' ? !options.teams.length : !options.sites.length) && <p>No accessible destinations. Check your tracker permissions.</p>}
    </form>}{error && <p className="key-error" role="alert">{error}</p>}</div>;
}
export default function IssueTrackerSettings({workspaceId}) {
  const {integrations,error,refresh}=useIssueTrackers(workspaceId);
  const visible = integrations.filter(integration => integration.configured || integration.connected);
  if (!visible.length && !error) return null;
  return <section className="tracker-settings"><h3>Issue tracking</h3>{error && <p role="alert" className="key-error">{error}</p>}{visible.map(integration=><TrackerSetting key={integration.provider} integration={integration} refresh={refresh}/>)}</section>;
}
export function FindingIssueActions({integrations, repository, installationId, snapshot, finding, onSettings}) {
  const [busy,setBusy]=useState(''),[error,setError]=useState(''),[issues,setIssues]=useState({});
  async function create(provider) {setBusy(provider);setError('');try{const data=await request('/api/dependencies/issue',{method:'POST',body:JSON.stringify({provider,repository,installationId,revision:snapshot.revision,package:finding.package,version:finding.version,advisoryId:finding.id})});setIssues(current=>({...current,[provider]:data.issue}));}catch(cause){setError(cause.message);}finally{setBusy('');}}
  const available=integrations.filter(integration=>integration.connected && integration.target);
  if (!available.length) {
    const configured = integrations.filter(integration => integration.configured || integration.connected);
    if (!configured.length) return null;
    return <button type="button" className="text-link" onClick={onSettings}>{configured.some(integration => integration.connected) ? 'Choose issue destination' : 'Connect issue tracker'}</button>;
  }
  return <div className="finding-issue-actions">{available.map(({provider})=>issues[provider]?<a key={provider} className="secondary-button" href={issues[provider].url} target="_blank" rel="noopener noreferrer">{issues[provider].issueKey}<ArrowUpRight size={13}/></a>:<button key={provider} type="button" className="secondary-button" disabled={!!busy} onClick={()=>create(provider)}>{busy===provider?'Creating…':`Create ${names[provider]} issue`}</button>)}{error && <p role="alert" className="key-error">{error}</p>}</div>;
}
