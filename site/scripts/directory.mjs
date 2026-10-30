import { TOOL_CATALOG } from '../../shared/tool-catalog.js';
import { landingCatalog } from './catalog.mjs';

export const directoryCategories = {
  all: 'All tools', dependencies: 'Dependencies', source: 'Source & secrets',
  infrastructure: 'Infrastructure', web: 'Web & API', mobile: 'Mobile',
};

// Upstream engine licenses, checked against their public repositories. These
// are not licenses for Offense, its rule packs, scanner images or provider data.
const upstream = {
  Opengrep: ['opengrep/opengrep', 'main/LICENSE', 'LGPL-2.1'],
  Trivy: ['aquasecurity/trivy', 'main/LICENSE', 'Apache-2.0'],
  Gitleaks: ['gitleaks/gitleaks', 'master/LICENSE', 'MIT'],
  GuardDog: ['DataDog/guarddog', 'v3/LICENSE', 'Apache-2.0'],
  Spectral: ['stoplightio/spectral', 'develop/LICENSE', 'Apache-2.0'],
  Cosign: ['sigstore/cosign', 'main/LICENSE', 'Apache-2.0'],
  ZAP: ['zaproxy/zaproxy', 'main/LICENSE', 'Apache-2.0'],
  Zizmor: ['zizmorcore/zizmor', 'main/LICENSE', 'MIT'],
  'OSV-Scanner': ['google/osv-scanner', 'main/LICENSE', 'Apache-2.0'],
  'Semgrep OSS': ['semgrep/semgrep', 'develop/LICENSE', 'LGPL-2.1'],
  Pluto: ['FairwindsOps/pluto', 'master/LICENSE', 'Apache-2.0'],
  Kubeconform: ['yannh/kubeconform', 'master/LICENSE', 'Apache-2.0'],
  Nuclei: ['projectdiscovery/nuclei', 'dev/LICENSE.md', 'MIT'],
  Prowler: ['prowler-cloud/prowler', 'master/LICENSE', 'Apache-2.0'],
  Schemathesis: ['schemathesis/schemathesis', 'master/LICENSE', 'MIT'],
  SSLyze: ['nabla-c0d3/sslyze', 'release/LICENSE.txt', 'AGPL-3.0'],
  Katana: ['projectdiscovery/katana', 'dev/LICENSE.md', 'MIT'],
  httpx: ['projectdiscovery/httpx', 'dev/LICENSE.md', 'MIT'],
  'OpenSSF Scorecard': ['ossf/scorecard', 'main/LICENSE', 'Apache-2.0'],
  Checkov: ['bridgecrewio/checkov', 'main/LICENSE', 'Apache-2.0'],
  TruffleHog: ['trufflesecurity/trufflehog', 'main/LICENSE', 'AGPL-3.0'],
  MobSF: ['MobSF/Mobile-Security-Framework-MobSF', 'master/LICENSE', 'GPL-3.0'],
};
const localVersions = { opengrep: '1.32.0', zizmor: '1.31.1' };
const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const icon = name => `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="/icons.svg#${escape(name)}"></use></svg>`;
const pathFor = id => `/tools/${encodeURIComponent(id)}`;

function page({ title, description, path, body }) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#141414">
  <title>${escape(title)} | Offense</title>
  <meta name="description" content="${escape(description)}">
  <link rel="canonical" href="https://offense.sh${escape(path)}">
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escape(title)} | Offense">
  <meta property="og:description" content="${escape(description)}">
  <meta property="og:url" content="https://offense.sh${escape(path)}">
  <meta property="og:image" content="https://offense.sh/social/offense-logo.jpg">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="icon" type="image/svg+xml" href="/offense-mark.svg">
  <link rel="stylesheet" href="/src/styles.css?v=14">
  <link rel="stylesheet" href="/src/directory.css?v=1">
  <script type="module" src="/src/directory.js?v=1"></script>
</head>
<body class="directory-page">
  <a class="skip-link" href="#main">Skip to content</a>
  <header class="site-header"><div class="header-inner">
    <a class="brand" href="/" aria-label="Offense home">offense</a>
    <span class="header-index">YOUR AGENT. ONE WAY IN.</span>
    <nav class="directory-nav" aria-label="Main navigation"><a href="/tools"${path === '/tools' ? ' aria-current="page"' : ''}>Tools</a><a href="https://offense.sh/skill">Agent setup</a></nav>
    <a class="button button-small" href="https://offense.sh/app#tools">Open portal ${icon('arrow-up-right')}</a>
  </div></header>
  <main id="main" class="container">${body}</main>
  <footer class="directory-footer container"><a class="brand" href="/">offense</a><span>Security tools for your agent.</span><a href="https://offense.sh/v1/catalog">Live API catalog ${icon('arrow-up-right')}</a><a href="https://offense.sh/skill">Setup guide ${icon('arrow-up-right')}</a></footer>
</body>
</html>`;
}

function dataBoundary(tool) {
  if (tool.id === 'dependency-audit') return 'The free audit sends sanitized dependency metadata to Offense for advisory analysis. It does not upload source code or execute your application. Public advisory and package metadata providers are used.';
  if (tool.inputType === 'verified-target') return 'Offense sends bounded network requests to your verified public HTTPS origin. Verify target ownership before a job; only scan systems you are authorized to assess.';
  if (tool.inputType === 'verified-api') return 'Your OpenAPI document is uploaded to Offense. Active requests go to one ownership-verified staging API. Explicit active-testing consent is required; do not use a production target.';
  if (tool.inputType === 'cloud-account') return 'The selected Cloudflare account ID and a separate read-only API token go to Offense for the assessment. Your Offense key is not a Cloudflare credential. Review account scope before submission.';
  if (tool.inputType === 'public-repository') return 'Only the selected public GitHub owner/repository is needed. Offense retrieves published Scorecard data; it does not receive repository credentials or perform a fresh scan. Data licensing is separate from the engine license.';
  if (tool.id === 'trufflehog-verified') return 'Selected files are uploaded to Offense. Live verification contacts a curated set of credential providers. Explicit live-verification consent is required; only submit credentials you are authorized to verify.';
  return 'The selected files or artifact are uploaded to Offense for hosted analysis. Review the input before uploading: it may contain private source, credentials or customer data. The scope is limited to the supplied input.';
}

function card(tool, heading = 'h2') {
  return `<article class="directory-card" data-directory-tool="${escape(tool.id)}" data-category="${escape(tool.category)}" data-search="${escape([tool.id, tool.title, tool.engine, tool.input, tool.description, directoryCategories[tool.category]].join(' ').toLowerCase())}">
    <div class="directory-card-top"><span class="directory-engine">${icon(tool.icon)} ${escape(tool.engine)}</span><span class="directory-badge${tool.id === 'dependency-audit' ? ' is-free' : ''}">${tool.id === 'dependency-audit' ? 'Free audit' : 'Hosted tool'}</span></div>
    <${heading}><a href="${pathFor(tool.id)}">${escape(tool.title)} ${icon('arrow-up-right')}</a></${heading}>
    <p>${escape(tool.description)}</p>
    <div class="directory-card-bottom"><span>${escape(tool.input)}</span>${localVersions[tool.id] ? '<span class="directory-local">Local helper available</span>' : `<code>${escape(tool.id)}</code>`}</div>
  </article>`;
}

function indexPage(tools) {
  return page({ title: 'Security tool directory', description: 'Explore Offense security tools by task, engine and input. Review coverage, data boundaries, local options and hosted usage before running a scan.', path: '/tools', body: `
    <section class="directory-hero" aria-labelledby="directory-title">
      <div><p class="eyebrow">THE TOOL DIRECTORY</p><h1 id="directory-title">Security tools.<br><span>Know what you’re running.</span></h1><p class="directory-intro">Find the right check for your project. Inspect its scope, choose how to run it, and put your agent to work.</p></div>
      <div class="directory-total"><strong>${tools.length}</strong><span>tools, one way in</span><a href="https://offense.sh/skill">Set up your agent ${icon('arrow-up-right')}</a></div>
    </section>
    <section class="directory-browser" aria-label="Browse security tools" data-directory>
      <form class="directory-search" role="search" hidden>
        <label for="tool-search">Find a security tool</label><div class="directory-search-field">${icon('search')}<input id="tool-search" name="q" type="search" maxlength="200" placeholder="Search tools…" autocomplete="off" aria-controls="directory-results"><button type="reset">Reset</button></div>
      </form>
      <div class="directory-toolbar"><div class="directory-filters" role="group" aria-label="Tool category" hidden>${Object.entries(directoryCategories).map(([id, label]) => `<button type="button" data-category-filter="${id}" aria-pressed="${id === 'all'}">${escape(label)}</button>`).join('')}</div><p id="directory-count" role="status" aria-live="polite" aria-atomic="true">${tools.length} tools</p></div>
      <noscript><p>All tools are listed below. Enable JavaScript to search and filter.</p></noscript>
      <div id="directory-results" class="directory-grid">${tools.map(tool => card(tool)).join('\n')}</div>
      <div class="directory-empty" hidden><span class="eyebrow">NO MATCHES</span><h2>No tools found.</h2><p>Try another search or clear the category filter.</p><button type="button" class="button" data-directory-reset>Show all tools ${icon('arrow-up-right')}</button></div>
      <p class="directory-disclaimer">A listing describes a tool’s scope, not live availability. Paid hosted jobs require an account and a reviewed price quote. <a href="https://offense.sh/v1/catalog">Check the live catalog ${icon('arrow-up-right')}</a></p>
    </section>` });
}

function detailPage(tool, tools) {
  const free = tool.id === 'dependency-audit';
  const source = upstream[tool.engine];
  const local = localVersions[tool.id];
  if (!free && !source) throw new Error(`Missing directory upstream for ${tool.id}.`);
  const command = free ? 'offense audit . --plan-limit 0' : `offense login\noffense tools show ${tool.id}`;
  const related = tools.filter(other => other.category === tool.category && other.id !== tool.id).slice(0, 2);
  return page({ title: tool.title, description: tool.description, path: pathFor(tool.id), body: `
    <nav class="directory-breadcrumb" aria-label="Breadcrumb"><a href="/tools">All tools</a><span aria-hidden="true">/</span><a href="/tools?category=${escape(tool.category)}">${escape(directoryCategories[tool.category])}</a><span aria-hidden="true">/</span><span aria-current="page">${escape(tool.engine)}</span></nav>
    <section class="directory-detail-hero"><p class="eyebrow">${escape(tool.engine)} <span>/</span> ${escape(tool.id)}</p><h1>${escape(tool.title)}</h1><p class="directory-intro">${escape(tool.description)}</p><div class="directory-tags"><span class="directory-badge${free ? ' is-free' : ''}">${free ? 'Free · no account' : 'Hosted · quoted per job'}</span>${local ? '<span class="directory-badge">Local helper available</span>' : ''}</div></section>
    <div class="directory-detail-layout">
      <div class="directory-detail-content">
        <section aria-labelledby="scope-title"><p class="eyebrow">01 / THE CONTRACT</p><h2 id="scope-title">Coverage, without the guesswork.</h2><ul class="directory-points">${tool.points.map(point => `<li>${escape(point)}</li>`).join('')}</ul>${tool.kubernetesVersions ? `<p>Required <code>kubernetesVersion</code>: ${tool.kubernetesVersions.map(version => `<code>${escape(version)}</code>`).join(', ')}. Render Helm or Kustomize before submitting.</p>` : ''}<p class="directory-note">Findings are evidence for review, not confirmed exploits. Partial or failed checks must not be treated as a clean result.</p></section>
        <section aria-labelledby="data-title"><p class="eyebrow">02 / YOUR DATA</p><h2 id="data-title">What leaves your machine.</h2><p>${escape(dataBoundary(tool))}</p></section>
        <section aria-labelledby="usage-title"><p class="eyebrow">03 / IN YOUR WORKFLOW</p><h2 id="usage-title">${free ? 'Run a free advisory audit.' : 'Inspect first. Run deliberately.'}</h2><p>${free ? 'Install the CLI using the setup guide, then run this in the project you are authorized to audit. This command sends sanitized dependency metadata; it does not edit the project.' : 'After CLI setup, sign in and inspect the tool’s current contract and pricing. These commands do not start a scan or spend credit.'}</p>
          <div class="directory-code"><div><span>CLI / ${free ? 'ADVISORY AUDIT' : 'READ-ONLY DISCOVERY'}</span><button type="button" data-directory-copy="tool-command" hidden>Copy command</button></div><pre><code id="tool-command">${escape(command)}</code></pre><p class="directory-copy-status" role="status"></p></div>
          <p>${free ? 'In MCP, use offense.audit_dependencies with sanitized lockfile metadata prepared by the installed helper.' : `In authenticated MCP, call <code>offense.security_tools</code> with <code>{}</code> and find <code>${escape(tool.id)}</code>. Review the input contract, get a maximum-price quote with <code>offense.security_quote</code>, then use <code>offense.security_call</code> only with authorized input, a spending cap and an idempotency key.`}</p><a class="text-link" href="/skills/offense/references/${free ? 'install' : 'tools'}.md">Read the ${free ? 'installation' : 'CLI and MCP'} guide ${icon('arrow-up-right')}</a>
        </section>
        <section aria-labelledby="local-title"><p class="eyebrow">04 / EXECUTION OPTIONS</p><h2 id="local-title">${local ? 'Keep source scanning local.' : 'Local and self-hosted options.'}</h2><p>${local ? `The Offense local source-scan helper supports ${escape(tool.engine)} ${local}. It requires a local Git checkout and the separately installed, pinned scanner. Source and reports stay local; it does not execute your application. The hosted CLI does not bundle this scanner.` : 'The full Offense platform is not yet a supported public self-hosted distribution. Do not treat this catalog listing as a locally installed Offense tool.'}</p>${local ? `<a class="text-link" href="/skills/offense/references/local-tools.md">Local helper setup ${icon('arrow-up-right')}</a>` : source ? `<p>You can inspect the upstream engine’s own installation instructions. Its defaults, rules and coverage may differ from the Offense integration.</p><a class="text-link" href="https://github.com/${source[0]}">Upstream project ${icon('arrow-up-right')}</a>` : '<p>The independent local dependency-engine candidate remains unpublished. The free hosted audit above is available without an account.</p>'}</section>
      </div>
      <aside class="directory-run" aria-label="Tool access">
        <p class="eyebrow">${free ? 'FREE ADVISORY CHECK' : 'OFFENSE HOSTED'}</p><h2>${free ? 'Start with your dependencies.' : 'Let us run the scanner.'}</h2><p>${free ? 'No account, API key or model key required.' : 'One API key. Isolated execution. A price quote before you submit.'}</p>
        <a class="button" href="https://offense.sh${free ? '/skill' : '/app#tools'}">${free ? 'Set up your agent' : 'View availability & pricing'} ${icon('arrow-up-right')}</a>
        <dl><div><dt>Engine</dt><dd>${escape(tool.engine)}</dd></div><div><dt>Input</dt><dd>${escape(tool.input)}</dd></div><div><dt>Billing</dt><dd>${free ? 'Free advisory audit' : 'Prepaid · quote required'}</dd></div>${source ? `<div><dt>Upstream license</dt><dd><a href="https://github.com/${source[0]}/blob/${source[1]}">${source[2]} ${icon('arrow-up-right')}</a></dd></div>` : ''}</dl>
        ${source ? `<a class="text-link" href="https://github.com/${source[0]}">View engine source ${icon('arrow-up-right')}</a><p class="directory-small">Engine license only. Rules, datasets and images may have separate terms. Offense’s full source release is still in preparation.</p>` : '<p class="directory-small">Offense’s full source release is still in preparation. This page does not announce a public repository.</p>'}
        ${free ? '' : '<p class="directory-small">Availability is deployment-controlled. Failed or partial jobs release their prepaid reservation.</p>'}
      </aside>
    </div>
    ${related.length ? `<section class="directory-related"><p class="eyebrow">KEEP EXPLORING</p><h2>Related checks.</h2><div class="directory-grid">${related.map(other => card(other, 'h3')).join('')}</div></section>` : ''}` });
}

export function directoryPages() {
  const contracts = new Map(TOOL_CATALOG.map(tool => [tool.id, tool]));
  const tools = Object.entries(landingCatalog()).map(([id, detail]) => ({ ...contracts.get(id), ...detail, id }));
  const pages = new Map([['tools.html', indexPage(tools)]]);
  for (const tool of tools) pages.set(`tools/${tool.id}.html`, detailPage(tool, tools));
  return pages;
}
