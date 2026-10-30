import React from 'react';
import { FileLock2 } from 'lucide-react';
import PromptPanel from './PromptPanel.jsx';
import { buildLockfilePrompt } from './remediation-prompts.js';

export default function LockfileGuidance({ repository, snapshot, busy, onRescan }) {
  const missing = snapshot.coverage?.missingLockfiles || [];
  return <section className="lockfile-guidance" aria-label="Scan without a lockfile">
    <div className="lockfile-guidance-heading"><FileLock2 size={22}/><div><h3>Scan package requirements</h3><p>We can flag potential risks from your manifests. A lockfile is needed to confirm exact versions and simulate an upgrade.</p></div></div>
    <p>No source changes are made by this scan. Transitive dependencies and deployed versions remain unknown.</p>
    {missing.length > 0 && <ul>{missing.map(item => <li key={item.manifest}><strong>{item.manifest}</strong>{item.commands?.length === 1 && <code>{item.commands[0].command}</code>}</li>)}</ul>}
    <p>Have your coding agent add the lockfile with the project’s existing package manager. Once the change is reviewed and merged into your default branch, check the repository again.</p>
    <div className="lockfile-guidance-actions"><PromptPanel label="Copy lockfile setup prompt" primary prompt={buildLockfilePrompt({ repository, snapshot })}/><button type="button" className="secondary-button" disabled={busy} onClick={onRescan}>{busy ? 'Checking…' : 'Check again'}</button></div>
  </section>;
}
