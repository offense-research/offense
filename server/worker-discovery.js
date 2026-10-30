import { parse as parseJson } from 'jsonc-parser';
import { parse as parseToml } from 'smol-toml';

export function configuredWorkers(path, content) {
  let config;
  try {
    const errors = [];
    config = path.endsWith('.toml') ? parseToml(content) : parseJson(content, errors, { allowTrailingComma: true });
    if (errors.length) return [];
  } catch { return []; }
  return [...new Set([config?.name, ...Object.values(config?.env || {}).map(env => env?.name)]
    .filter(name => typeof name === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(name)))];
}

export function uniqueWorkerLinks(workers, repositories, existing) {
  const linked = new Set(existing.map(item => item.sourceWorker));
  return workers.filter(worker => !linked.has(worker)).flatMap(worker => {
    const matches = repositories.filter(repo => repo.workers.includes(worker));
    return matches.length === 1 ? [{ sourceWorker: worker, repository: matches[0].fullName, installationId: matches[0].installationId }] : [];
  });
}

export function createWorkerDiscovery(github) {
  const cache = new Map();
  return async function discover(installations, workers) {
    const repositories = [];
    const warnings = [];
    for (const installation of installations) {
      const id = installation.installationId;
      let pending = cache.get(id);
      if (!pending || pending.expires < Date.now()) {
        pending = { expires: Date.now() + 10 * 60_000, promise: github.workerRepositories(id) };
        cache.set(id, pending);
      }
      try { repositories.push(...await pending.promise); }
      catch (error) { cache.delete(id); warnings.push(`${installation.account}: ${error.message}`); }
    }
    return { repositories: repositories.filter(repo => repo.workers.some(worker => workers.includes(worker))), warnings };
  };
}
