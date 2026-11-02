import { readFile, appendFile } from 'node:fs/promises';
import { validateBundle } from './dependency-bundle.mjs';
import { loadPolicy, validateManifest, validateLock, digest } from './dependency-policy.mjs';
import { fileURLToPath } from 'node:url';
async function api(method, endpoint, body) {
  const response = await fetch(`https://api.github.com${endpoint}`, { method, redirect: 'error', signal: AbortSignal.timeout(30000), headers: {
    authorization: `Bearer ${process.env.GH_TOKEN}`, accept: 'application/vnd.github+json', 'content-type': 'application/json'
  }, ...(body ? { body: JSON.stringify(body) } : {}) });
  if (!response.ok) throw Error(`GitHub request failed: ${response.status}`);
  return response.json();
}
export async function publishBundle(bundle, { policy, api, expected, summaryFile } = {}) {
  validateBundle(bundle, { ...expected, policy });
  const prefix = `/repos/${bundle.repository}`;
  const repo = await api('GET', prefix);
  const ref = await api('GET', `${prefix}/git/ref/heads/${encodeURIComponent(repo.default_branch)}`);
  if (ref.object.sha !== bundle.baseSha) throw Error('Default branch moved; run the agent again.');
  for (const c of bundle.changes) {
    const value = Buffer.from(c.content, 'base64').toString('utf8');
    if (c.path.endsWith('package.json')) {
      const before = await api('GET', `${prefix}/contents/${c.path}?ref=${bundle.baseSha}`);
      validateManifest(JSON.parse(Buffer.from(before.content, 'base64')), JSON.parse(value));
    }
    if (c.path.endsWith('package-lock.json')) validateLock(JSON.parse(value));
  }
  // Deterministic branch; never overwrite another run or maintainer edits.
  const branch = `offense/dependencies-${bundle.baseSha.slice(0, 12)}-${digest(JSON.stringify(bundle.changes)).slice(0, 12)}`;
  const existing = await api('GET', `${prefix}/pulls?state=all&head=${encodeURIComponent(repo.owner.login + ':' + branch)}`);
  if (existing.length) {
    return existing[0].html_url;
  } else {
    const base = await api('GET', `${prefix}/git/commits/${bundle.baseSha}`);
    const tree = [];
    for (const change of bundle.changes) {
      const blob = await api('POST', `${prefix}/git/blobs`, { encoding: 'base64', content: change.content });
      tree.push({ path: change.path, mode: '100644', type: 'blob', sha: blob.sha });
    }
    const created = await api('POST', `${prefix}/git/trees`, { base_tree: base.tree.sha, tree });
    const commit = await api('POST', `${prefix}/git/commits`, { message: 'Upgrade dependencies with Offense verification', tree: created.sha, parents: [bundle.baseSha] });
    if ((await api('GET', `${prefix}/git/ref/heads/${encodeURIComponent(repo.default_branch)}`)).object.sha !== bundle.baseSha) throw Error('Default branch moved during publication.');
    await api('POST', `${prefix}/git/refs`, { ref: `refs/heads/${branch}`, sha: commit.sha });
    const pr = await api('POST', `${prefix}/pulls`, { title: 'Upgrade dependencies with Offense verification', head: branch, base: repo.default_branch, draft: true,
      body: `${bundle.body}\n\nCI evidence: ${repo.html_url}/actions/runs/${bundle.runId}\n\nAutomated compatibility/advisory checks passed. Human review and PR CI are required before merging.` });
    if (summaryFile) await appendFile(summaryFile, `Draft PR: ${pr.html_url}\n`);
    return pr.html_url;
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const raw = await readFile(process.argv[2]);
  if (raw.length > 12_000_000) throw Error('Bundle too large.');
  const policy = await loadPolicy();
  const expected = { repository: process.env.GITHUB_REPOSITORY, runId: process.env.GITHUB_RUN_ID, engineSha: process.env.OFFENSE_ENGINE_SHA };
  console.log(await publishBundle(JSON.parse(raw), { policy, api, expected, summaryFile: process.env.GITHUB_STEP_SUMMARY }));
}
