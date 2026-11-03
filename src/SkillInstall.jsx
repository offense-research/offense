import React, { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Check, Copy, Github, TerminalSquare } from 'lucide-react';
import './skill-install.css';
import AgentIntegrations from './AgentIntegrations.jsx';
import { CommandSearchTrigger } from './CommandPalette.jsx';

export const INSTALL_PROMPT = `Install Offense for this coding agent, then scan the current repository's dependencies.

Use this agent's preferred existing connections: Composio, native connectors, MCP tools, authenticated CLIs, or local tools. Honor the selected GitHub/Cloudflare account and repository scope. Reuse the current checkout when available. If only remote repository access is available, fetch the supported lockfiles at one commit through the preferred connection and scan a temporary dependency snapshot. Do not require a new connection or OAuth flow when existing access is sufficient.

Use curl or Node.js fetch to retrieve the files below.
Fetch and read https://offense.sh/skills/purple/SKILL.md.
Install it as SKILL.md in your supported project skill directory: .agents/skills/purple for Codex, .claude/skills/purple for Claude Code, or .pi/skills/purple for Pi. For another agent, use its documented project skill directory. Preserve any existing customized Offense installation.

Download these supporting files into that skill's scripts/ directory and inspect them before running:
https://offense.sh/skills/purple/scripts/hosted-scan.mjs
https://offense.sh/skills/purple/scripts/hosted-artifact-scan.mjs
https://offense.sh/skills/purple/scripts/hosted-assessment.mjs
https://offense.sh/skills/purple/scripts/git-history-bundle.mjs
https://offense.sh/skills/purple/scripts/source-scan.mjs
https://offense.sh/skills/purple/scripts/api-test.mjs
https://offense.sh/skills/purple/scripts/api-test-image.mjs
https://offense.sh/skills/purple/scripts/hardened-image.mjs
https://offense.sh/skills/purple/scripts/purple.mjs
https://offense.sh/skills/purple/scripts/metadata.mjs
https://offense.sh/skills/purple/scripts/pnpm.mjs
https://offense.sh/skills/purple/scripts/yaml.mjs
https://offense.sh/skills/purple/scripts/evidence.mjs
https://offense.sh/skills/purple/scripts/reachability.mjs
https://offense.sh/skills/purple/scripts/syntax.mjs
https://offense.sh/skills/purple/scripts/workflow.mjs
https://offense.sh/skills/purple/scripts/rehearsal-runner.mjs
https://offense.sh/skills/purple/scripts/update.mjs

Download https://offense.sh/skills/purple/references/delivery.md into that skill's references/ directory for the optional PR delivery step.
Download https://offense.sh/skills/purple/references/api-testing.md into that skill's references/ directory for optional sandbox API tests. Local source/workflow scans use source-scan.mjs with pinned Opengrep and Zizmor. API tests use api-test.mjs with an explicitly built isolated image; installing the skill does not build an image, run the application, upload source, or test a production API.
Download https://offense.sh/skills/purple/references/hardened-containers.md into that skill's references/ directory. When later requested, hardened-image.mjs can inspect a Dockerfile, pull a selected compatible hardened base through existing Docker access and prepare a digest-pinned migration proposal. Installation does not pull images or change Docker settings.
Download https://offense.sh/skills/purple/references/hosted-assessments.md into that skill's references/ directory for optional hosted deployment, cloud, API, infrastructure, secret-verification and mobile checks. Installing these resources does not sign in, buy credit, upload source, send cloud tokens or start active tests. The assessment helper defaults to offline preview; a later --run requires the workspace scan key, a matching quote and sufficient credit. Live target ownership and active-testing confirmations apply as described in the reference.
Read https://offense.sh/skills/purple/manifest.json for the release version and file checksums. After inspecting the updater, run node /absolute/path/to/purple/scripts/update.mjs --skill purple to verify the installation and record its managed file hashes. It updates unchanged files only; if customizations require review, keep them intact and report the staged update. Never use --accept-local without reviewing and merging those changes first. Exit code 4 requires a new session before continuing.

Follow the skill and run its scan. It sends sanitized dependency names, versions, ranges and relative lockfile paths to Offense, excluding source code and credentials. When a complete executable checkout is available, run local function reachability and applicability triage too. Report affected API call paths separately from unresolved or unobserved paths. Return the findings, checked upgrade paths, assessment evidence, local report, and connection used. Use your existing model; no Offense sign-in, GitHub App, Cloudflare connection or OpenRouter key is needed. Do not extract or forward connector tokens. Do not change application code or cloud resources during this initial scan.

If a preferred connection lacks a required capability, try another already authorized connection with the same account and repository scope. If repository access, a filesystem/terminal, Node 20+, or network access is still missing, explain that specific gap instead of claiming a scan ran. A dependency snapshot supports scanning; reproduction and tests require an executable checkout.

Finish by explicitly telling me to start a new coding-agent session in this same project to load the installed skill before using it for my next task. Running the helper during installation does not prove the client has loaded the skill. If the client also needs a full restart, give its exact restart steps.`;

export const OFFENSE_INSTALL_PROMPT = `Set up Offense, a product of Offense Security, in this coding agent for the current project. After setup, it should guide a security assessment, explain findings and consequences, and help me choose fixes. This request is installation only.

Read https://offense.sh/skills/offense/SKILL.md, its manifest at https://offense.sh/skills/offense/manifest.json, and https://offense.sh/skills/offense/references/install.md. Inspect and install the skill and its listed resources in this client's documented project skill directory, such as .agents/skills/offense for Codex or .claude/skills/offense for Claude Code. Preserve customized installations and unrelated instructions. Verify the manifest checksums and follow the documented updater behavior. Use this agent's preferred existing repository connections, preserve the selected account and repository scope, and reuse the current checkout. Do not extract or forward connector tokens or source code during setup.

Reuse an existing equivalent Offense CLI installation. Otherwise download https://offense.sh/downloads/offense-cli.mjs into a suitable local tool directory and inspect it before executing it. Preserve customized installations and unrelated project instructions. Do not install globally or overwrite existing client settings silently.

For hosted tool access, run node /absolute/path/to/offense-cli.mjs login. In a remote terminal, use login --no-browser and give me the approval URL and short terminal code. I must sign in and explicitly approve this request in my own browser. Never approve device access on my behalf, ask me to paste a token into chat, or put the returned credential in project files. The CLI stores its credential in its private user configuration. Reuse an existing valid login when available. If I defer sign-in, retain the free dependency capability and explain that paid tools still need account access.

After successful account sign-in, run node /absolute/path/to/offense-cli.mjs mcp install --client codex --project . for Codex. For another supported coding agent, select that client's documented name from mcp install --help. Inspect existing settings and merge only the Offense entry, preserving other servers and customized entries. The local stdio MCP server reads the private CLI credential at runtime; no API key belongs in the project's MCP settings. If I choose free checks without signing in, follow the installation reference's anonymous MCP setup or HTTPS helper instead. Verify the client's actual effective configuration and tool discovery, and report any concrete unsupported client or access limitation. A provider refusal remains subject to its supported review process; do not replay it through another client, model, transport or permission setting.

Offense provides one API key for security tools. Free dependency advisory checks remain available without a key; paid hosted tools use prepaid credit. Setup must not buy credit, upload source, start a paid call, scan or modify the application, publish, or deploy. When later requested, use the CLI to request a price quote before a paid call. Opening a top-up checkout is separate from payment approval.

Finish by explicitly telling me: "Start a new coding-agent session in this same project to load the installed skill and MCP configuration." If this client requires a full application restart, give its exact restart steps. CLI login works immediately, but installation on disk does not prove that the current agent session has loaded its new tools.`;

export const FIX_WORKFLOW_PROMPT = `Use Offense to find and fix my vulnerable dependencies.

Use the current project and this agent's existing model and preferred authorized repository connections. Reuse the installed Offense skill and its documented tools. Installed skill instructions describe the version check to run before analysis; preserve customized files and report staged updates for review. If files update and require a restart, stop and tell me to start a new session in this project before continuing. Use offense.audit_dependencies or the installed HTTPS/CLI helper for advisory analysis. Source review, upgrade checks and regression tests run in this agent's authorized local environment. Advanced local helpers may be installed separately and may retain a purple directory name for compatibility; verify the installed manifest before invoking them. Preserve the selected account, repository scope, package manager and unrelated working changes. No web workspace, GitHub App installation, Cloudflare connection or OpenRouter key is required for the core workflow.

1. Discover — Identify manifests, lockfiles and exact dependency versions. Invoke the installed Offense capability first and identify the transport used. Scan sanitized metadata for known vulnerabilities, retain local coverage follow-up for unsupported ecosystems and uncovered manifests, and inspect existing dependency patches.
2. Prioritize — Review severity, advisory prerequisites, source reachability and attacker-controlled inputs. Keep unknowns visible; an advisory match or static path alone is not a confirmed exploit.
3. Remediate — Choose compatible upgrades, including required parent changes. Continue pending planning pages while retaining the original full scan; distinguish budget limits, truncated analysis, provider failures and actual dependency constraints. If an upgrade is blocked, investigate a scoped compatibility repair or targeted patch rather than forcing conflicting versions. Keep a result or concrete blocker for every finding.
4. Verify — Establish passing baseline tests and builds, add security regressions that fail for the actual issue before and pass after the fix where feasible, run the normal checks again, and rescan the final resolved tree. Record changed runtime floors, behavior defaults and any normal tests replaced with mocks, preserving an independent check of affected behavior. Verify existing patches with current integrity and regression evidence; retain metadata matches separately from reviewed mitigations. Distinguish verified dependency remediation from reproduced security fixes.
5. Deliver — Open a draft PR containing only the verified fix and supporting evidence through an existing authorized connection. Include affected advisories, applicability, exact changes, before/after commands and results, final scan coverage and remaining limitations. Verify the published head and report actual CI state. If access or verification blocks delivery, return the reviewable patch and precise blocker instead of claiming a PR exists.

Output: a verified security fix ready for review, with its PR link and evidence. Do not merge or deploy. Do not send source code or connector credentials to the dependency intelligence service. If there are no actionable findings, report that result without creating an empty PR.`;

export default function SkillInstall() {
  const [copied, setCopied] = useState(false), [error, setError] = useState('');
  const [advancedCopied, setAdvancedCopied] = useState(false), [advancedError, setAdvancedError] = useState('');
  const [workflowCopied, setWorkflowCopied] = useState(false), [workflowError, setWorkflowError] = useState('');
  const field = useRef(null), advancedField = useRef(null);
  const workflowField = useRef(null);
  useEffect(() => {
    if (workflowError) { workflowField.current?.focus(); workflowField.current?.select(); }
  }, [workflowError]);
  async function copy(advanced = false) {
    const value = advanced ? INSTALL_PROMPT : OFFENSE_INSTALL_PROMPT, target = advanced ? advancedField : field;
    try {
      await navigator.clipboard.writeText(value);
      if (advanced) { setAdvancedCopied(true); setAdvancedError(''); } else { setCopied(true); setError(''); }
    } catch {
      target.current?.focus(); target.current?.select();
      if (advanced) setAdvancedError('Select and copy the Offense prompt below.'); else setError('Select and copy the prompt below.');
    }
  }
  async function copyWorkflow() {
    try {
      await navigator.clipboard.writeText(FIX_WORKFLOW_PROMPT);
      setWorkflowCopied(true); setWorkflowError('');
    } catch {
      setWorkflowError('Select and copy the workflow below.');
      workflowField.current?.focus(); workflowField.current?.select();
    }
  }
  return <main className="skill-page">
    <header className="skill-page-header">
      <a className="skill-brand" href="/" aria-label="Offense home"><span aria-hidden="true">✳</span> offense<span className="skill-brand-dot">.</span></a>
      <div className="skill-header-actions"><CommandSearchTrigger/><a className="skill-back" href="/account" aria-label="Your account"><ArrowLeft size={15}/><span>Your account</span></a></div>
    </header>
    <section className="skill-prompt" aria-label="Install Offense">
      <div className="skill-prompt-heading">
        <div className="skill-prompt-title"><span className="skill-terminal-icon" aria-hidden="true"><TerminalSquare size={21}/></span><div><h1>Set up Offense in your agent</h1><p>Guided security checks. Understand what to fix and why.</p></div></div>
        <button type="button" onClick={() => copy()}>{copied ? <Check size={16}/> : <Copy size={16}/>} {copied ? 'Copied' : 'Copy prompt'}</button>
      </div>
      <div className="skill-prompt-editor">
        <div className="skill-editor-label"><span>Installation prompt</span><span>Read-only</span></div>
        <textarea ref={field} aria-label="Offense installation prompt" value={OFFENSE_INSTALL_PROMPT} readOnly spellCheck="false"/>
      </div>
      <div className="skill-prompt-footer"><span>Paste into your coding agent. Approve CLI sign-in in your own browser.<strong className="skill-session-reminder">After installation, start a new agent session in this same project.</strong></span><a href="/skills/offense/SKILL.md">Read SKILL.md <ArrowRight size={13}/></a></div>
      <span className={`skill-copy-status ${error ? 'has-error' : ''}`} role="status">{error || (copied ? 'Copied. Paste to install, then start a new agent session in this project.' : '')}</span>
    </section>
    <div className="skill-agent-support"><span>MCP + skill</span><span>Codex</span><span>Claude Code</span><span>Cursor</span><span>Compatible coding agents</span></div>
    <section className="skill-details" aria-label="What you get">
      <div><span className="skill-detail-number">01</span><div><h2>Connect once</h2><p>Sign in through the CLI. Your private API key works across security tools.</p></div></div>
      <div><span className="skill-detail-number">02</span><div><h2>Ask about your app</h2><p>Your agent selects relevant checks and quotes paid calls before running them.</p></div></div>
      <div><span className="skill-detail-number">03</span><div><h2>Keep control</h2><p>Understand the findings, consequences and fix choices before requesting changes.</p><button type="button" className="skill-workflow-copy" onClick={copyWorkflow}>{workflowCopied ? <Check size={13}/> : <Copy size={13}/>} {workflowCopied ? 'Workflow copied' : 'Copy fix workflow'}</button><span className="skill-workflow-status" role="status">{workflowError || (workflowCopied ? 'After installation, paste this into a new agent session in the same project.' : '')}</span>{workflowError && <textarea ref={workflowField} className="skill-workflow-fallback" aria-label="Dependency fix workflow" value={FIX_WORKFLOW_PROMPT} readOnly spellCheck="false"/>}</div></div>
    </section>
    <AgentIntegrations/>
    <section className="skill-advanced-install" aria-label="Advanced local workflows"><details>
      <summary>Advanced local workflows</summary>
      <p>Add source and GitHub Actions checks, sandbox API tests, hardened container bases and upgrade rehearsals. This separate prompt installs Offense and starts an initial dependency scan.</p>
      <button type="button" className="secondary-button" onClick={() => copy(true)}>{advancedCopied ? <Check size={15}/> : <Copy size={15}/>} Copy advanced prompt</button>
      <textarea ref={advancedField} aria-label="Advanced local workflow prompt" value={INSTALL_PROMPT} readOnly spellCheck="false"/>
      <span className="skill-advanced-copy-status" role="status">{advancedError || (advancedCopied ? 'Copied. Install and scan, then start a new agent session in this same project.' : '')}</span>
    </details></section>
    <footer className="skill-page-footer">
      <details><summary>Coverage and advanced workflows</summary><p>The first capability, <code>offense.audit_dependencies</code>, checks npm v2/v3 and pnpm v6/v9 lockfiles against known advisories. Local preparation needs a filesystem, Node 20+, and HTTPS access. Source relevance and exploitability need review; advisory matches are not confirmed vulnerabilities.</p><p>Installed helpers check for updates on each normal run. Unchanged installations update automatically; customized files stay intact while the new release is staged for review. Start a new session after updating. Older installations need a one-time refresh to get the updater.</p><p>Diagnostics keep stage/outcome codes, timings and counts for up to seven days. Conversations, source, identities and free-form errors are excluded from these traces. Local trace.json files are shared only when you choose.</p><p>Only sanitized dependency metadata is sent. For local function reachability and deterministic upgrade rehearsals, the <a href="/skills/purple/SKILL.md">advanced Offense skill</a> remains available.</p></details>
      <a href="/account"><Github size={15}/> Open your account <ArrowRight size={13}/></a>
    </footer>
  </main>;
}
