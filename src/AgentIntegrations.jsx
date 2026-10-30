import React, { useRef, useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import './agent-integrations.css';

const snippets = {
  claude: { label: 'Claude Agent SDK', title: 'Merge into your query options', source: 'https://code.claude.com/docs/en/agent-sdk/mcp',
    code: JSON.stringify({ mcpServers: { offense: { type: 'http', url: 'https://offense.sh/mcp' } } }, null, 2) },
  opencode: { label: 'OpenCode', title: 'Merge into your OpenCode configuration', source: 'https://opencode.ai/docs/mcp-servers/',
    code: JSON.stringify({ mcp: { offense: { type: 'remote', url: 'https://offense.sh/mcp', enabled: true, oauth: false, timeout: 120000 } } }, null, 2) }
};

export default function AgentIntegrations() {
  const [platform, setPlatform] = useState('claude');
  const [copied, setCopied] = useState(false), [error, setError] = useState('');
  const field = useRef(null);
  const snippet = snippets[platform];
  async function copy() {
    try { await navigator.clipboard.writeText(snippet.code); setCopied(true); setError(''); }
    catch { setError('Select and copy the configuration below.'); field.current?.focus(); field.current?.select(); }
  }
  return <section className="agent-integrations" aria-labelledby="agent-integrations-heading">
    <h2 id="agent-integrations-heading">CLI and application integrations</h2>
    <p>Use the CLI to sign in and connect your coding agent. For applications you build, use the SDK or the free read-only dependency MCP endpoint below.</p>
    <pre><code>{`node offense-cli.mjs login
node offense-cli.mjs mcp install --client codex --project .`}</code></pre>
    <p>Start a new coding-agent session after installing MCP. Keep the CLI credential out of project settings.</p>
    <div className="agent-integration-downloads">
      <a href="/downloads/offense-sdk.tgz" download><Download size={15}/> Download JavaScript SDK</a>
      <a href="/downloads/offense-cli.mjs" download><Download size={15}/> Download Offense CLI</a>
    </div>
    <label className="agent-integration-platform">Agent platform<select value={platform} onChange={event => { setPlatform(event.target.value); setCopied(false); setError(''); }}>
      {Object.entries(snippets).map(([key, item]) => <option value={key} key={key}>{item.label}</option>)}
    </select></label>
    <div className="agent-integration-code-label"><span>{snippet.title}</span><button type="button" onClick={copy}>{copied ? <Check size={14}/> : <Copy size={14}/>} {copied ? 'Configuration copied' : 'Copy MCP configuration'}</button></div>
    <textarea ref={field} aria-label={`${snippet.label} MCP configuration`} value={snippet.code} readOnly spellCheck="false"/>
    <p className="agent-integration-copy-status" role="status">{error || (copied ? 'Copied. Merge this with your existing configuration.' : '')}</p>
    <p>Connecting a tool makes it available to the agent. To guarantee a check before deployment or before starting an agent run, call the automation CLI or SDK from your application at that step.</p>
    <div className="agent-integration-lifecycle"><h3>Choose when checks run</h3><a href="/downloads/offense-automation.mjs" download>Download the automation helper</a>
      <p>Save a reviewed policy as <code>offense.config.json</code> and invoke the helper from your own pipeline or agent lifecycle. Existing V1 repository automation remains in the <a href="/legacy#dependencies">V1 workspace</a>.</p>
      <pre><code>node offense-automation.mjs --event pre_deploy --policy offense.config.json .</code></pre>
      <p>Enable the pre-deploy trigger and choose a blocking rule to stop that step when findings meet your severity threshold. Post-deploy checks report after deployment. Your pipeline or host must call the integration; saving a setting does not install it.</p>
    </div>
    <p className="agent-integration-reference"><a href={snippet.source} target="_blank" rel="noopener noreferrer">{snippet.label} MCP documentation</a><span> · </span><a href="/account">Open your account</a></p>
  </section>;
}
