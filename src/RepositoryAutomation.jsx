import React, { useEffect, useId, useState } from 'react';
import { ArrowUpRight, Check, Copy, Download, ShieldCheck } from 'lucide-react';
import { defaultAutomationPolicy, normalizeAutomationPolicy } from '../shared/offense-policy.js';
import './repository-automation.css';

const serialize = value => JSON.stringify(value, null, 2);
function policyValue(value) {
  try { return normalizeAutomationPolicy(value || defaultAutomationPolicy()); }
  catch { return defaultAutomationPolicy(); }
}
const date = value => Number.isFinite(value) && value > 0
  ? new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : null;
const triggerName = value => ({ initial: 'First automatic check', dependency_change: 'Repository changed', scheduled: 'Scheduled review' })[value] || 'Automatic check';
const resultName = value => ({ completed: 'Completed', partial: 'Incomplete', failed: 'Failed', interrupted: 'Interrupted', running: 'Running' })[value] || 'Not recorded';
const duration = value => Number.isFinite(value) ? value < 1000 ? 'under 1 second' : `${Math.ceil(value / 1000)} seconds` : null;
const command = event => `node offense-automation.mjs --event ${event} --policy offense.config.json .`;

function Toggle({ checked, onChange, label, children, disabled }) {
  return <label className="automation-toggle"><input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} disabled={disabled}/>
    <span><strong>{label}</strong>{children && <small>{children}</small>}</span>
  </label>;
}

function CodeCopy({ label, value, onCopy }) {
  return <div className="automation-code"><pre><code>{value}</code></pre><button type="button" className="secondary-button" onClick={() => onCopy(value, label)} aria-label={`Copy ${label}`}><Copy size={14}/><span>Copy</span></button></div>;
}

export default function RepositoryAutomation({ repository, installationId, monitor, backgroundEnabled, onSaved }) {
  const id = useId();
  const incoming = serialize(policyValue(monitor?.policy));
  const [saved, setSaved] = useState(() => policyValue(monitor?.policy));
  const [draft, setDraft] = useState(() => policyValue(monitor?.policy));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [copyFallback, setCopyFallback] = useState(null);
  const dirty = serialize(draft) !== serialize(saved);
  // A background refresh may update status without discarding an unfinished form.
  useEffect(() => {
    const next = JSON.parse(incoming);
    if (!dirty) setDraft(next);
    setSaved(next);
  }, [incoming]);

  function update(field, value) {
    setDraft(current => ({ ...current, [field]: value }));
    setError(''); setNotice('');
  }
  function gate(field, value) {
    setDraft(current => ({ ...current, gate: { ...current.gate, [field]: value } }));
    setError(''); setNotice('');
  }
  async function save(event) {
    event.preventDefault(); setSaving(true); setError(''); setNotice('');
    try {
      const policy = normalizeAutomationPolicy(draft);
      const response = await fetch('/api/dependencies/automation', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repository, installationId, policy }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not save automation settings.');
      const next = normalizeAutomationPolicy(data.policy);
      setSaved(next); setDraft(next);
      onSaved?.(data.monitoring);
      setNotice(next.enabled ? 'Automation settings saved. Download the updated configuration for any pipeline or agent integration.' : 'Background checks paused. You can still run a manual check. Export the updated configuration to pause pipeline and agent checks.');
    } catch (cause) { setError(cause.message || 'Could not save automation settings.'); }
    finally { setSaving(false); }
  }
  async function copy(value, label) {
    setCopyFallback(null);
    try { await navigator.clipboard.writeText(value); setNotice(`${label} copied.`); }
    catch { setCopyFallback({ value, label }); setNotice('Clipboard access is unavailable. Select and copy the text below.'); }
  }
  function downloadConfiguration() {
    const url = URL.createObjectURL(new Blob([`${serialize(saved)}\n`], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'offense.config.json';
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice('Configuration downloaded. Install it with your pipeline or agent integration.');
  }
  const latest = monitor?.latestRun;
  const recent = Array.isArray(monitor?.recentRuns) ? monitor.recentRuns.slice(0, 10) : [];
  const enabledBackground = saved.enabled && (saved.onChange || saved.schedule !== 'off');
  const stateLabel = !saved.enabled ? 'Paused' : enabledBackground ? backgroundEnabled ? 'Background checks enabled' : 'Background service unavailable'
    : saved.preDeploy || saved.postDeploy || saved.agentRun ? 'Integration checks configured' : 'Manual checks';
  const sdkExample = `import { checkRepository, assertSecurityDecision } from '@purpleteam/offense/node';\n\nconst result = await checkRepository({\n  directory: '.', event: 'pre_deploy', policy\n});\nassertSecurityDecision(result.decision);\nawait deploy();`;
  return <section className="repository-automation" aria-labelledby={`${id}-heading`}>
    <div className="automation-heading"><div><h2 id={`${id}-heading`}>Let Offense handle the routine checks</h2><p>Choose when security checks run. Start with repository changes and a daily review for newly reported advisories.</p></div><span className="automation-state" data-enabled={saved.enabled}><ShieldCheck size={15}/>{stateLabel}</span></div>
    {!backgroundEnabled && <p className="dependency-warning" role="status">This server does not have background repository checks enabled. Use Check again, or connect the pipeline and agent integration below. Saved settings do not start a background service.</p>}
    <dl className="automation-status-grid">
      <div><dt>Latest automatic check</dt><dd>{latest ? resultName(latest.status) : 'No runs yet'}</dd><small>{latest ? `${triggerName(latest.trigger)}${date(latest.startedAt) ? ` · ${date(latest.startedAt)}` : ''}` : 'The first background check will appear here.'}</small></div>
      <div><dt>Next background check</dt><dd>{!saved.enabled ? 'Paused' : !enabledBackground ? 'No background schedule' : !backgroundEnabled ? 'Service unavailable' : date(monitor?.nextCheckAt) || 'Waiting for the scheduler'}</dd><small>{saved.onChange && saved.enabled ? 'Repository changes are checked about every five minutes.' : 'Uses your saved review schedule.'}</small></div>
      <div><dt>Latest advisory matches</dt><dd>{Number.isInteger(latest?.advisoryMatches) ? latest.advisoryMatches : '—'}</dd><small>{latest?.coverageStatus === 'complete' ? 'Matches still need application review.' : latest ? 'Coverage is incomplete or unavailable.' : 'No automatic result recorded yet.'}</small></div>
      <div><dt>Latest run duration</dt><dd>{duration(latest?.durationMs) || '—'}</dd><small>{latest?.revision ? `Revision ${String(latest.revision).slice(0, 12)}` : 'Duration is recorded when a run finishes.'}</small></div>
    </dl>

    <form onSubmit={save}>
      <div className="automation-enable"><Toggle checked={draft.enabled} onChange={value => update('enabled', value)} label="Enable automatic checks" disabled={saving}>Pause background checks for this repository. Apply the updated configuration to pause pipeline and agent checks.</Toggle></div>
      <fieldset disabled={saving} className="automation-settings"><legend>Background repository checks</legend>
        <Toggle checked={draft.onChange} onChange={value => update('onChange', value)} label="When the repository changes">Check the connected default branch for changed dependencies and code revisions.</Toggle>
        <label className="automation-select" htmlFor={`${id}-schedule`}><span>Review existing dependencies for new advisories</span><select aria-label="Review existing dependencies for new advisories" id={`${id}-schedule`} value={draft.schedule} onChange={event => update('schedule', event.target.value)}><option value="daily">Every day · recommended</option><option value="weekly">Every week</option><option value="off">No scheduled reviews</option></select><small>New advisories can affect a version you already use, even when your code has not changed.</small></label>
        <p className="automation-note">Offense runs these checks while you are away. Findings appear in this repository; these checks do not edit or deploy code.</p>
      </fieldset>

      <fieldset disabled={saving} className="automation-settings"><legend>Checks in your pipeline and agents</legend>
        <p>Choose the events your integration should check, then install the saved configuration below.</p>
        <Toggle checked={draft.preDeploy} onChange={value => update('preDeploy', value)} label="Before deployment">Check the candidate before your deployment step runs.</Toggle>
        <Toggle checked={draft.postDeploy} onChange={value => update('postDeploy', value)} label="After deployment">Record a follow-up report. This cannot stop a deployment that has already completed.</Toggle>
        <Toggle checked={draft.agentRun} onChange={value => update('agentRun', value)} label="At an agent operation">Let the application hosting your agent call a security check at a defined point in its workflow.</Toggle>
        <p className="automation-note">Saving these choices does not install a pipeline or agent hook. The integration must call Offense at each chosen event.</p>
      </fieldset>

      <fieldset disabled={saving} className="automation-settings"><legend>What should happen when a check finds risk?</legend>
        <div className="automation-form-grid"><label className="automation-select" htmlFor={`${id}-mode`}><span>Before deployment and agent operations</span><select aria-label="Before deployment and agent operations" id={`${id}-mode`} value={draft.gate.mode} onChange={event => gate('mode', event.target.value)}><option value="report">Report findings and continue</option><option value="block">Stop the configured operation</option></select></label>
          <label className="automation-select" htmlFor={`${id}-severity`}><span>Advisories that trigger the response</span><select aria-label="Advisories that trigger the response" id={`${id}-severity`} value={draft.gate.minimumSeverity} onChange={event => gate('minimumSeverity', event.target.value)}><option value="high">High and critical</option><option value="critical">Critical only</option></select></label>
          <label className="automation-select" htmlFor={`${id}-incomplete`}><span>If a blocking check cannot finish</span><select aria-label="If a blocking check cannot finish" id={`${id}-incomplete`} value={draft.gate.onIncomplete} onChange={event => gate('onIncomplete', event.target.value)}><option value="block">Stop and request review</option><option value="report">Report the incomplete check and continue</option></select></label></div>
        <p className="automation-note">A blocking response applies to the operation wrapped by your integration. Background and post-deployment checks report results. An incomplete check is never recorded as a pass.</p>
      </fieldset>

      <div className="automation-save"><button type="submit" className="primary-button" disabled={saving || !dirty}>{saving ? 'Saving…' : 'Save automation'}</button><button type="button" className="secondary-button" disabled={saving} onClick={() => { setDraft(defaultAutomationPolicy()); setNotice('Recommended settings selected. Save to apply them.'); setError(''); }}>Use recommended settings</button>{dirty && <span>Unsaved changes</span>}</div>
    </form>
    {error && <p className="key-error" role="alert">{error} Your changes have not been saved. Try Save automation again.</p>}
    {notice && <p className="automation-notice" role="status"><Check size={15}/>{notice}</p>}
    {copyFallback && <label className="automation-copy-fallback">{copyFallback.label}<textarea readOnly value={copyFallback.value} onFocus={event => event.target.select()} rows={8}/></label>}

    <section className="automation-integration" aria-labelledby={`${id}-integration`}>
      <h3 id={`${id}-integration`}>Connect your pipeline or build security into your agent</h3>
      <p>Use the same security policy in CI and in agents you build or host. Your application calls the check directly, so a user does not have to ask the agent to run it.</p>
      <ol className="automation-setup-steps"><li><strong>Save and download your policy.</strong><p>Keep <code>offense.config.json</code> with the repository or application that runs the check. Update that copy whenever you change these settings.</p>
          <div className="automation-downloads"><button type="button" className="secondary-button" disabled={dirty || saving} onClick={downloadConfiguration}><Download size={15}/> Download configuration</button><button type="button" className="secondary-button" disabled={dirty || saving} onClick={() => copy(serialize(saved), 'Configuration')}><Copy size={15}/> Copy configuration</button></div>{dirty && <p className="automation-note">Save your changes before exporting the configuration.</p>}</li>
        <li><strong>Call the check at the event you selected.</strong><p><a href="/downloads/offense-automation.mjs" download="offense-automation.mjs">Download the standalone Node.js helper <Download size={13}/></a> into your CI checkout. Place the before-deployment command before the actual deployment step and require it to succeed.</p>
          <CodeCopy label="before-deployment command" value={command('pre_deploy')} onCopy={copy}/>
          <details><summary>After-deployment and agent-operation commands</summary><CodeCopy label="after-deployment command" value={command('post_deploy')} onCopy={copy}/><CodeCopy label="agent-operation command" value={command('agent_run')} onCopy={copy}/></details>
          <p className="automation-note">These checks inspect supported npm and pnpm lockfiles. Post-deployment checks review the checked-out dependency metadata; they do not probe the live site.</p></li>
        <li><strong>For an agent you host, wrap the operation in application code.</strong><p><a href="/downloads/offense-sdk.tgz" download="offense-sdk.tgz">Download the JavaScript SDK <Download size={13}/></a>, install it with <code>npm install ./offense-sdk.tgz</code>, and load your saved policy as <code>policy</code>.</p>
          <CodeCopy label="agent lifecycle example" value={sdkExample} onCopy={copy}/>
          <p className="automation-note">Use <code>event: 'agent_run'</code> at an agent workflow boundary. Your application must act on the decision. Merely making a tool available to a model does not guarantee that the model calls it.</p></li></ol>
      <details className="automation-mcp"><summary>Also expose Offense as a tool in Claude Agent SDK or OpenCode</summary><p>These configurations make the read-only dependency tool available. Keep the direct check above for a required deployment or agent-operation check.</p><h4>Claude Agent SDK</h4><CodeCopy label="Claude Agent SDK MCP configuration" value={serialize({ mcpServers: { offense: { type: 'http', url: 'https://offense.sh/mcp' } }, allowedTools: ['mcp__offense__*'] })} onCopy={copy}/><a href="https://code.claude.com/docs/en/agent-sdk/mcp" target="_blank" rel="noopener noreferrer">Claude Agent SDK MCP documentation <ArrowUpRight size={12}/></a><h4>OpenCode SDK</h4><CodeCopy label="OpenCode SDK MCP configuration" value={serialize({ mcp: { offense: { type: 'remote', url: 'https://offense.sh/mcp', enabled: true, oauth: false, timeout: 120000 } } })} onCopy={copy}/><p>Pass this object as <code>config</code> when calling <code>createOpencode</code>.</p><a href="https://opencode.ai/docs/sdk/" target="_blank" rel="noopener noreferrer">OpenCode SDK documentation <ArrowUpRight size={12}/></a></details>
    </section>
    <section className="automation-history" aria-labelledby={`${id}-history`}><h3 id={`${id}-history`}>Recent automatic checks</h3><p>Up to ten recent background runs for this repository. Pipeline and agent checks return their results to the application that called them.</p>
      {!recent.length ? <p className="automation-empty">No automatic checks have been recorded yet.</p> : <ol>{recent.map((run, index) => <li key={run.id || `${run.startedAt}:${index}`}><div><strong>{triggerName(run.trigger)}</strong><span data-outcome={run.status}>{resultName(run.status)}</span></div><p>{date(run.startedAt) || 'Time unavailable'}{duration(run.durationMs) && ` · ${duration(run.durationMs)}`}{Number.isInteger(run.advisoryMatches) && ` · ${run.advisoryMatches} advisory ${run.advisoryMatches === 1 ? 'match' : 'matches'}`}</p>{run.coverageStatus !== 'complete' && <small>Coverage {run.coverageStatus === 'partial' ? 'incomplete' : 'unavailable'}; review the result before acting.</small>}{run.errorCode && <small>{run.errorCode === 'interrupted' ? 'The run stopped before it finished. A later check will retry.' : 'The provider request did not finish. The previous result is retained.'}</small>}</li>)}</ol>}
    </section>
  </section>;
}
