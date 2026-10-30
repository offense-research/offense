import { TOOL_CATALOG } from '../../shared/tool-catalog.js';
import { toolDetails as scannerDetails } from '../src/catalog-descriptions.js';

const additions = {
  'dependency-audit': { engine: 'Offense', category: 'dependencies', icon: 'dependency', input: 'Sanitized lockfiles',
    points: ['Basic npm/pnpm dependency advisory checks are free and require no account or model key.',
      'Only sanitized dependency metadata is sent; source relevance and exploitability need review.',
      'Your coding agent reviews applicability, edits the project, runs tests and verifies the fix.'] },
  nuclei: { engine: 'Nuclei', category: 'web', icon: 'target', input: 'Verified deployment', active: true },
  'prowler-cloudflare': { engine: 'Prowler', category: 'infrastructure', icon: 'layers', input: 'Selected Cloudflare account',
    points: ['An optional tool for a specifically selected Cloudflare account; no cloud connection is needed for other tools.',
      'Uses explicitly supplied read-only account access for the bounded assessment.',
      'Cloud configuration findings require review in the context of your account.'] },
  schemathesis: { engine: 'Schemathesis', category: 'web', icon: 'code', input: 'Verified staging API', active: true },
  'zap-api': { engine: 'ZAP', category: 'web', icon: 'globe', input: 'Verified staging API', active: true },
  sslyze: { engine: 'SSLyze', category: 'web', icon: 'shield', input: 'Verified HTTPS hostname', active: true },
  checkov: { engine: 'Checkov', category: 'infrastructure', icon: 'layers', input: 'Infrastructure files' },
  'trufflehog-verified': { engine: 'TruffleHog', category: 'source', icon: 'key', input: 'Source files',
    points: ['Live verification contacts a curated set of credential providers; inspect the tool contract first.',
      'Checks supplied files, with secret values redacted from reports; Git history is excluded.',
      'Only submit credentials you are authorized to verify. Installation never starts this check.'] },
  'mobsf-static': { engine: 'MobSF', category: 'mobile', icon: 'package', input: 'APK or IPA archive' },
};

export function landingCatalog() {
  const canonical = [{ id: 'dependency-audit', name: 'Dependency advisory intelligence',
    coverage: 'Known dependency advisories for supported npm/pnpm lockfiles; applicability and fixes are reviewed by your agent' }, ...TOOL_CATALOG];
  const tools = Object.fromEntries(canonical.map(tool => {
    const detail = scannerDetails[tool.id] || additions[tool.id];
    if (!detail) throw new Error(`Landing metadata missing for canonical tool ${tool.id}.`);
    return [tool.id, { ...detail, provider: `OFFENSE / ${detail.engine.toUpperCase()}`, status: 'IN OFFENSE', title: tool.name,
      description: tool.coverage, points: detail.points || [tool.coverage,
        detail.active ? 'Requires target ownership verification and explicit authorization before a bounded active check.' : 'Inspects only the supplied input within the tool’s documented coverage.',
        'Review the input contract, current availability and maximum-price quote before calling this tool. Findings need application-specific review.'],
      url: 'https://offense.sh/app#tools', action: 'View tool and pricing' }];
  }));
  const ids = new Set(canonical.map(tool => tool.id));
  if (Object.keys(scannerDetails).some(id => !ids.has(id))) throw new Error('Landing contains a tool outside the canonical catalog.');
  return tools;
}

const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

export function renderToolRows(tools) {
  return Object.entries(tools).map(([id, tool]) => `<article class="tool-row" data-tool="${escape(id)}" data-category="${escape(tool.category)}">
              <span class="tool-row-icon"><svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="/icons.svg#${escape(tool.icon)}"></use></svg></span>
              <div class="tool-row-name"><h3>${escape(tool.title)}</h3><p>${escape(tool.engine)} <span>/ ${escape(tool.input)}</span></p></div>
              <span class="tool-status status-available"><i aria-hidden="true"></i>${id === 'dependency-audit' ? 'Free' : 'In Offense'}</span>
              <button type="button" class="tool-row-action" data-details="${escape(id)}" aria-label="View ${escape(tool.title.toLowerCase())} details"><span>Details</span><svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="/icons.svg#arrow-up-right"></use></svg></button>
            </article>`).join('\n            ');
}
