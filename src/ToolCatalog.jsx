import React, { useEffect, useId, useRef, useState } from 'react';
import { ArrowUpRight, Box, Boxes, Check, ChevronDown, Code2, Copy, FileText, Fingerprint, Globe2, Layers3, Search, Smartphone, X } from 'lucide-react';
import { useAutoRefresh } from './useAutoRefresh.js';
import './tool-catalog.css';

const categories = [
  { id: 'dependencies', label: 'Dependencies', icon: Boxes },
  { id: 'source', label: 'Code & secrets', icon: Fingerprint },
  { id: 'containers', label: 'Containers', icon: Box },
  { id: 'infrastructure', label: 'Infrastructure', icon: Layers3 },
  { id: 'web', label: 'Web & API', icon: Globe2 },
  { id: 'mobile', label: 'Mobile', icon: Smartphone },
  { id: 'other', label: 'Other', icon: Code2 }
];
const toolCategories = {
  'dependency-audit': 'dependencies', 'osv-scanner': 'dependencies', 'trivy-vuln': 'dependencies', 'trivy-sbom': 'dependencies',
  'openssf-scorecard': 'dependencies',
  'guarddog-npm': 'dependencies', 'guarddog-pypi': 'dependencies',
  opengrep: 'source', semgrep: 'source', gitleaks: 'source', 'gitleaks-history': 'source', zizmor: 'source', 'trufflehog-verified': 'source',
  'trivy-image': 'containers', 'cosign-image': 'containers',
  'trivy-config': 'infrastructure', 'prowler-cloudflare': 'infrastructure', checkov: 'infrastructure',
  'k8s-deprecations': 'infrastructure', 'k8s-manifest-validate': 'infrastructure',
  'spectral-owasp': 'web', 'zap-passive-har': 'web', nuclei: 'web', katana: 'web', httpx: 'web', schemathesis: 'web', 'zap-api': 'web', sslyze: 'web',
  'mobsf-static': 'mobile'
};
const inputNames = {
  'source-files': 'Source files', 'sanitized-lockfiles': 'Sanitized lockfiles', 'sbom-json': 'SBOM document',
  'image-tar': 'Image archive', 'git-bundle': 'Git history bundle', 'package-archive': 'Package archive',
  'openapi-text': 'OpenAPI document', 'cosign-save': 'Image provenance bundle', 'web-har': 'Captured web responses',
  'cloud-account': 'Selected Cloudflare account', 'verified-api': 'Verified staging API',
  'verified-target': 'Verified deployment', 'public-repository': 'Public GitHub repository', 'mobile-app': 'APK or IPA archive'
};
const categoryFor = tool => categories.find(category => category.id === toolCategories[tool.id]) || categories.at(-1);
const money = value => Number.isSafeInteger(value) && value >= 0 ? new Intl.NumberFormat('en-US', {
  style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 6
}).format(value / 1_000_000) : null;
const bounded = tool => ['bounded_assessment', 'bounded_job', 'assessment'].includes(tool.unit);
const selectedTool = () => {
  const id = new URLSearchParams(location.search).get('tool');
  return /^[a-z0-9-]{1,80}$/.test(id || '') ? id : null;
};

function ToolPrice({ tool, billing }) {
  if (tool.availability !== 'available') return <span className="tool-price is-unavailable">Unavailable</span>;
  if (tool.priceMicros === 0) return <span className="tool-price is-free">Free<small>{tool.id === 'dependency-audit' ? 'No account needed' : 'Per hosted call'}</small></span>;
  if (billing?.enabled !== true) return <span className="tool-price is-unavailable">Pricing unavailable</span>;
  const price = money(tool.basePriceMicros);
  return <span className={`tool-price${price ? '' : ' is-unavailable'}`}>{price ? <>From {price}<small>{bounded(tool) ? 'per bounded assessment' : 'per hosted call'}</small></> : 'Price unavailable'}</span>;
}

function ToolCard({ tool, billing }) {
  const category = categoryFor(tool), Icon = category.icon;
  const [copied, setCopied] = useState(false), [copyError, setCopyError] = useState(false);
  const fallback = useRef(null);
  const command = tool.id === 'dependency-audit' && tool.priceMicros === 0 ? 'offense audit .' : `offense tools show ${tool.id}`;
  const free = tool.priceMicros === 0;
  const input = tool.kubernetesVersions ? 'Rendered manifests + target version' : tool.id === 'sslyze' ? 'Verified HTTPS hostname' : inputNames[tool.inputType] || (typeof tool.inputType === 'string' ? tool.inputType.replaceAll('-', ' ') : 'See tool contract');
  const available = tool.availability === 'available';
  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true); setCopyError(false);
    } catch {
      setCopied(false); setCopyError(true);
      requestAnimationFrame(() => { fallback.current?.focus(); fallback.current?.select(); });
    }
  }
  return <article className={`tool-card tool-category-${category.id}${available ? '' : ' is-unavailable'}`} data-tool-id={tool.id}>
    <div className="tool-card-top"><span className="tool-card-icon"><Icon size={20} strokeWidth={1.6}/></span><span className="tool-card-category">{category.label}</span></div>
    <div className="tool-card-identity"><h2>{tool.name}</h2><code>{tool.id}</code></div>
    <p className="tool-card-description">{tool.coverage || 'Inspect the tool contract for supported checks and coverage.'}</p>
    <div className="tool-card-input"><FileText size={12}/><span>{input}</span></div>
    <details className="tool-card-details">
      <summary aria-label={`View ${tool.name} details`}><ToolPrice tool={tool} billing={billing}/><span className="tool-details-action">Details <ChevronDown size={14}/></span></summary>
      <div className="tool-card-expanded">
        <dl><div><dt>Access</dt><dd>{!available ? 'Not enabled on this deployment' : free && tool.id === 'dependency-audit' ? 'No account or API key needed' : free ? 'Offense API key' : 'Offense API key and prepaid credit'}</dd></div></dl>
        {Array.isArray(tool.kubernetesVersions) && <dl><div><dt>Required Kubernetes target</dt><dd>{tool.kubernetesVersions.join(', ')}</dd></div></dl>}
        {!available && tool.availabilityReason && <p className="tool-availability-reason">{tool.availabilityReason}</p>}
        {!free && <p className="tool-price-note">Your agent checks the input contract and maximum-price quote before a paid call.</p>}
        {!free && available && billing?.enabled === true && !bounded(tool) && Number.isSafeInteger(tool.additionalMiBPriceMicros) && tool.additionalMiBPriceMicros > 0 &&
          <p className="tool-price-note">First MiB from {money(tool.basePriceMicros) || 'the quoted base price'}; each additional started MiB adds {money(tool.additionalMiBPriceMicros)}.</p>}
        <div className="tool-command-label">{command === 'offense audit .' ? 'Check dependencies' : 'Inspect the tool'}</div>
        <div className="tool-command"><code>{command}</code><button type="button" onClick={() => { void copy(); }} aria-label={`Copy command for ${tool.name}`}>{copied ? <Check size={14}/> : <Copy size={14}/>}<span>{copied ? 'Copied' : 'Copy'}</span></button></div>
        {copyError && <textarea ref={fallback} className="tool-command-fallback" aria-label={`Command for ${tool.name}`} readOnly value={command} rows={2} spellCheck="false"/>}
        {(copied || copyError) && <p className="tool-copy-status" role="status">{copyError ? 'Select and copy the command above.' : 'Command copied.'}</p>}
      </div>
    </details>
  </article>;
}

export default function ToolCatalog() {
  const searchId = useId();
  const [catalog, setCatalog] = useState(null), [error, setError] = useState('');
  const [query, setQuery] = useState(() => selectedTool() || ''), [category, setCategory] = useState('all');
  const [selection, setSelection] = useState(() => selectedTool() ? { id: selectedTool() } : null);
  const catalogRoot = useRef(null), handledSelection = useRef(null);
  const searchInput = useRef(null);
  useEffect(() => {
    const sync = () => {
      const id = selectedTool();
      setQuery(id || ''); setCategory('all'); setSelection(id ? { id } : null);
    };
    window.addEventListener('popstate', sync);
    return () => window.removeEventListener('popstate', sync);
  }, []);
  useEffect(() => {
    if (!catalog || !selection || handledSelection.current === selection || !catalog.tools.some(tool => tool.id === selection.id)) return;
    const frame = requestAnimationFrame(() => {
      const card = catalogRoot.current?.querySelector(`[data-tool-id="${selection.id}"]`);
      const details = card?.querySelector('details');
      if (!details) return;
      handledSelection.current = selection;
      details.open = true;
      card.scrollIntoView({ block: 'center', behavior: 'auto' });
      details.querySelector('summary')?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [catalog, selection]);
  useAutoRefresh(async signal => {
    try {
      const response = await fetch('/v1/catalog', { signal, credentials: 'omit', cache: 'no-store' });
      if (!response.ok) throw new Error('Could not update the tool catalog.');
      const next = await response.json();
      if (!Array.isArray(next?.tools) || new Set(next.tools.map(tool => tool?.id)).size !== next.tools.length || next.tools.some(tool =>
        !/^[a-z0-9-]{1,80}$/.test(tool?.id || '') || typeof tool.name !== 'string' || !tool.name.trim() ||
        tool.coverage !== undefined && typeof tool.coverage !== 'string' ||
        tool.availabilityReason !== undefined && typeof tool.availabilityReason !== 'string')) throw new Error('The tool catalog returned an incomplete response.');
      if (!signal.aborted) { setCatalog(next); setError(''); }
    } catch (cause) {
      if (!signal.aborted) setError(cause.message === 'The tool catalog returned an incomplete response.' ? cause.message : 'Could not update the tool catalog.');
      throw cause;
    }
  }, { interval: 45000 });
  const term = query.trim().toLowerCase();
  const matching = catalog?.tools.filter(tool => [tool.name, tool.id, tool.coverage || '', tool.inputType || '', inputNames[tool.inputType] || ''].join(' ').toLowerCase().includes(term)) || [];
  const visible = matching.filter(tool => category === 'all' || categoryFor(tool).id === category);
  const represented = new Set(catalog?.tools.map(tool => categoryFor(tool).id) || []);
  const clear = () => { setQuery(''); setCategory('all'); searchInput.current?.focus(); };
  return <section ref={catalogRoot} className="tools-catalog" aria-label="Security tool catalog">
    <div className="tools-toolbar"><div className="tools-search"><Search size={17}/><label className="tools-sr-only" htmlFor={searchId}>Find a tool</label>
      <input ref={searchInput} id={searchId} type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search tools, coverage, or input…" autoComplete="off"/>
      {query && <button type="button" className="tools-search-clear" onClick={() => { setQuery(''); searchInput.current?.focus(); }} aria-label="Clear tool search"><X size={15}/></button>}</div>
      <span className="tools-result-count" role="status" aria-live="polite">{catalog ? `${visible.length} ${visible.length === 1 ? 'tool' : 'tools'}` : 'Tool catalog'}</span>
    </div>
    {catalog && <div className="tools-categories" role="group" aria-label="Filter tools by category">
      <button type="button" aria-pressed={category === 'all'} onClick={() => setCategory('all')}>All tools <span>{matching.length}</span></button>
      {categories.filter(item => represented.has(item.id)).map(item => <button type="button" key={item.id} aria-pressed={category === item.id} onClick={() => setCategory(item.id)}>{item.label}{' '}<span>{matching.filter(tool => categoryFor(tool).id === item.id).length}</span></button>)}
    </div>}
    {error && <p className="tools-error" role="alert">{error} Retrying automatically.{catalog && ' Showing the last available tools.'}</p>}
    {!catalog && !error && <div className="tools-loading" role="status"><span/> Loading tools…</div>}
    {catalog && !visible.length && <div className="tools-empty"><Search size={25}/><h2>{catalog.tools.length ? 'No matching tools' : 'No tools available yet'}</h2><p>{catalog.tools.length ? 'Try a different search or category.' : 'The catalog will update automatically.'}</p>{catalog.tools.length > 0 && <button type="button" onClick={clear}>Clear filters</button>}</div>}
    <div className="tools-grid">{visible.map(tool => <ToolCard key={tool.id} tool={tool} billing={catalog.billing}/>)}</div>
    {catalog && <footer className="tools-catalog-footer"><span><span className="tools-live-dot"/> Prices and availability update automatically.</span><a href="/v1/catalog">API catalog <ArrowUpRight size={12}/></a></footer>}
  </section>;
}
