import { workspaceInstallations } from '../server/github-installations.js';

export function publicState(s, user = null, workspaceId = null, { defaultCompany, config }) {
  return {
    user: user ? { login: user.login, githubId: user.githubId } : null,
    workspaceId,
    legacyWorkspace: !user && Boolean((s.company && s.company !== defaultCompany) || s.cloudflare || s.github || s.openrouter || s.collectorInstall),
    company: s.company || '',
    cloudflare: s.cloudflare ? { name: s.cloudflare.name || 'Cloudflare account', accounts: s.cloudflare.accounts || [] } : null,
    collector: s.collectorInstall ? { accountId: s.collectorInstall.accountId, sources: s.collectorInstall.sources, status: s.collectorInstall.status, attached: s.collectorInstall.attached } : null,
    github: s.github ? { account: s.github.account, installationId: s.github.installationId } : null,
    connectedGithubInstallations: workspaceInstallations(s),
    openrouter: s.openrouter ? { label: s.openrouter.label || 'Verified key', last4: s.openrouter.last4 } : null,
    complete: Boolean(s.company && s.cloudflare && s.github && s.openrouter && s.collectorInstall?.status === 'installed'),
    config
  };
}
