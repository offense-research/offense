import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { installationTokenRequest } from './github-permissions.js';
import { configuredWorkers } from './worker-discovery.js';

const api = 'https://api.github.com';
const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'purple-agent' };

export function createGitHubApp({ appId, privateKeyPath, privateKey, fetchImpl = fetch }) {
  if (!/^\d+$/.test(String(appId || '')) || (!privateKeyPath && !privateKey)) return null;

  function jwt() {
    const now = Math.floor(Date.now() / 1000);
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const content = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 540, iss: String(appId) })}`;
    const signature = createSign('RSA-SHA256').update(content).sign(privateKey || readFileSync(privateKeyPath));
    return `${content}.${signature.toString('base64url')}`;
  }

  async function request(url, token, options = {}) {
    const response = await fetchImpl(url, { ...options, headers: { ...headers, Authorization: `Bearer ${token}`, ...options.headers }, signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw Object.assign(new Error(`GitHub returned HTTP ${response.status}.`), { status: response.status });
    return response.json();
  }

  async function installationToken(installationId, repository) {
    if (!Number.isSafeInteger(installationId) || installationId <= 0) throw new Error('Invalid GitHub installation.');
    const input = installationTokenRequest(repository);
    const data = await request(`${api}/app/installations/${installationId}/access_tokens`, jwt(), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input)
    });
    if (!data.token) throw new Error('GitHub did not issue an installation token.');
    return data.token;
  }

  async function repositories(installationId) {
    const token = await installationToken(installationId);
    const found = [];
    for (let page = 1; page <= 10; page++) {
      const data = await request(`${api}/installation/repositories?per_page=100&page=${page}`, token);
      found.push(...(data.repositories || []).filter(repo => !repo.archived).map(repo => ({ fullName: repo.full_name, private: repo.private, sizeKb: repo.size || 0 })));
      if ((data.repositories || []).length < 100) break;
    }
    return found;
  }

  async function workerRepositories(installationId) {
    const repos = await repositories(installationId);
    const found = [];
    let cursor = 0;
    await Promise.all(Array.from({ length: 4 }, async () => {
      while (cursor < repos.length) {
        const repo = repos[cursor++];
        const token = await installationToken(installationId, repo.fullName);
        let tree;
        try { tree = await request(`${api}/repos/${repo.fullName}/git/trees/HEAD?recursive=1`, token); }
        catch (error) { if (error.status === 409) continue; throw error; }
        if (tree.truncated) throw new Error(`Cannot completely inspect ${repo.fullName}. Link its Workers manually.`);
        const configs = (tree.tree || []).filter(file => file.type === 'blob' &&
          /(^|\/)wrangler\.(jsonc?|toml)$/.test(file.path) &&
          !file.path.split('/').some(part => ['node_modules', 'vendor', '.git'].includes(part)));
        if (configs.length > 30) throw new Error(`Too many Worker configs in ${repo.fullName}. Link its Workers manually.`);
        const workers = [];
        for (const file of configs) {
          if (file.size > 100000) continue;
          const blob = await request(`${api}/repos/${repo.fullName}/git/blobs/${file.sha}`, token);
          if (blob.encoding === 'base64') workers.push(...configuredWorkers(file.path, Buffer.from(blob.content, 'base64').toString('utf8')));
        }
        found.push({ ...repo, installationId, workers: [...new Set(workers)] });
      }
    }));
    return found;
  }

  async function dependencyRevision(installationId, fullName) {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName || '')) throw new Error('Invalid repository.');
    const token = await installationToken(installationId, fullName);
    const repo = await request(`${api}/repos/${fullName}`, token);
    const commit = await request(`${api}/repos/${fullName}/commits/${encodeURIComponent(repo.default_branch)}`, token);
    if (!/^[a-f0-9]{40}$/.test(commit.sha || '')) throw new Error('GitHub did not return a checkout commit.');
    return commit.sha;
  }

  async function dependencyFiles(installationId, fullName) {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName || '')) throw new Error('Invalid repository.');
    const token = await installationToken(installationId, fullName);
    const repository = await request(`${api}/repos/${fullName}`, token);
    const commit = await request(`${api}/repos/${fullName}/commits/${encodeURIComponent(repository.default_branch)}`, token);
    if (!/^[a-f0-9]{40}$/.test(commit.sha || '') || !/^[a-f0-9]{40}$/.test(commit.commit?.tree?.sha || '')) throw new Error('GitHub did not return a checkout commit.');
    const tree = await request(`${api}/repos/${fullName}/git/trees/${commit.commit.tree.sha}?recursive=1`, token);
    if (tree.truncated) throw new Error('Repository tree is too large to scan completely.');
    const candidates = (tree.tree || []).filter(file => file.type === 'blob' &&
      !file.path.split('/').some(part => ['node_modules', 'vendor', '.git'].includes(part)) &&
      /(^|\/)(?:(?:package-lock|npm-shrinkwrap|package)\.json|pnpm-lock\.yaml)$/.test(file.path));
    const locks = candidates.filter(file => /(^|\/)(?:(?:package-lock|npm-shrinkwrap)\.json|pnpm-lock\.yaml)$/.test(file.path));
    const lockDirs = new Set(locks.map(file => file.path.slice(0, file.path.lastIndexOf('/') + 1)));
    const manifests = candidates.filter(file => file.path.endsWith('/package.json') || file.path === 'package.json')
      .filter(file => !lockDirs.has(file.path.slice(0, file.path.lastIndexOf('/') + 1)));
    const eligible = [...locks, ...manifests];
    const selected = eligible.slice(0, 20);
    const warnings = [];
    if (eligible.length > selected.length) warnings.push(`Scanned ${selected.length} of ${eligible.length} package files.`);
    const files = [];
    for (const file of selected) {
      if (file.size > 3_000_000) { warnings.push(`${file.path} exceeds the 3 MB scan limit.`); continue; }
      const blob = await request(`${api}/repos/${fullName}/git/blobs/${file.sha}`, token);
      if (blob.encoding !== 'base64' || !blob.content) { warnings.push(`${file.path} could not be decoded.`); continue; }
      files.push({ path: file.path, content: Buffer.from(blob.content, 'base64').toString('utf8') });
    }
    return { revision: commit.sha, files, warnings };
  }

  async function installationInfo(installationId) {
    if (!Number.isSafeInteger(installationId) || installationId <= 0) throw new Error('Invalid GitHub installation.');
    const installation = await request(`${api}/app/installations/${installationId}`, jwt());
    const url = new URL(installation.html_url);
    if (url.protocol !== 'https:' || url.hostname !== 'github.com' || !url.pathname.includes('/settings/installations/')) {
      throw new Error('GitHub returned an invalid installation settings URL.');
    }
    return { settingsUrl: url.toString(), repositorySelection: installation.repository_selection,
      accountType: installation.account?.type === 'Organization' ? 'Organization' : 'User' };
  }

  async function appInfo() {
    const app = await request(`${api}/app`, jwt());
    if (!/^[A-Za-z0-9-]+$/.test(app.slug || '')) throw new Error('GitHub returned an invalid App slug.');
    const response = await fetchImpl(`${api}/apps/${app.slug}`, {
      headers: { ...headers }, signal: AbortSignal.timeout(15000)
    });
    if (![200, 404].includes(response.status)) throw new Error(`Could not check GitHub App visibility: HTTP ${response.status}.`);
    return { slug: app.slug, owner: app.owner?.login || '', ownerType: app.owner?.type || '',
      isPublic: response.status === 200 };
  }

  return { installationToken, repositories, workerRepositories, dependencyRevision, dependencyFiles, installationInfo, appInfo };
}
