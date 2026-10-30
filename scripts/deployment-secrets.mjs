import { readFileSync } from 'node:fs';

// Require every existing runtime secret so a partial vault cannot silently
// remove a production credential. Resource bindings are always inherited.
export function mergeDeploymentBindings(existing, supplied, { preserveMissing = [] } = {}) {
  const suppliedByName = new Map(supplied.map(binding => [binding.name, binding]));
  const allowed = new Set(preserveMissing);
  const missing = existing.filter(binding => binding.type === 'secret_text' &&
    !suppliedByName.has(binding.name) && !allowed.has(binding.name)).map(binding => binding.name);
  if (missing.length) throw new Error(`Missing runtime secrets in Infisical: ${missing.join(', ')}.`);
  return [...existing.map(binding => {
    const replacement = suppliedByName.get(binding.name);
    suppliedByName.delete(binding.name);
    return replacement || { name: binding.name, type: 'inherit' };
  }), ...suppliedByName.values()];
}

export function deploymentSecrets(env, target, { read = file => readFileSync(file, 'utf8') } = {}) {
  const managed = env.PURPLE_SECRETS_SOURCE === 'infisical';
  if (managed && env.PURPLE_SECRETS_ENVIRONMENT !== (target === 'production' ? 'prod' : 'staging')) {
    throw new Error('Infisical environment does not match the deployment target.');
  }
  const valueFor = key => env[!managed && target === 'staging' &&
    (key.startsWith('CLICKHOUSE_') || key.startsWith('WHOP_') || key.startsWith('SCAN_') || key === 'OPENROUTER_API_KEY') ? `STAGING_${key}` : key];
  const privateKey = () => {
    if (env.GITHUB_APP_PRIVATE_KEY) return env.GITHUB_APP_PRIVATE_KEY;
    if (managed) throw new Error('GITHUB_APP_PRIVATE_KEY is missing from this Infisical environment.');
    return read('data-purple/github-app-private-key.pem');
  };
  const agent = keyPath => {
    if (managed && (!env.PURPLE_AGENT_SHARED_KEY || !env.PURPLE_AGENT_URL)) throw new Error('Configure PURPLE_AGENT_SHARED_KEY and PURPLE_AGENT_URL in this Infisical environment.');
    const key = managed ? env.PURPLE_AGENT_SHARED_KEY : keyPath ? read(keyPath).trim() : null;
    if (!key) return null;
    return { key, url: managed ? env.PURPLE_AGENT_URL :
      (target === 'production' ? 'https://agent.example.invalid' : 'https://agent-staging.example.invalid') };
  };
  return { valueFor, privateKey, agent };
}
