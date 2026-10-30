import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

export function infisicalInvocation(environment, command, args = [], { env = process.env, cwd = process.cwd(), home = homedir() } = {}) {
  if (!['dev', 'staging', 'prod'].includes(environment)) throw new Error('Choose an explicit Infisical environment: dev, staging or prod.');
  if (!command) throw new Error('Provide the command to run after the environment.');
  const yamlPath = path.join(cwd, '.infisical.yaml'), jsonPath = path.join(cwd, '.infisical.json');
  let config = {};
  if (existsSync(yamlPath)) config = parse(readFileSync(yamlPath, 'utf8')) || {};
  else if (existsSync(jsonPath)) config = JSON.parse(readFileSync(jsonPath, 'utf8'));
  const project = env.INFISICAL_PROJECT_ID || config['secrets-management']?.['project-id'] || config.workspaceId;
  if (!/^[a-zA-Z0-9_-]{8,100}$/.test(project || '')) throw new Error('Link Purple first with npm run secrets:init, or set INFISICAL_PROJECT_ID.');
  const domain = env.INFISICAL_DOMAIN || config.general?.domain || config.domain || 'https://app.infisical.com';
  const url = new URL(domain);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Infisical must use an HTTPS instance URL without credentials or query parameters.');
  // Keep ambient app credentials out of the Infisical process. It must supply
  // this environment's values; missing secrets never fall back to local .env.
  const childEnv = {};
  for (const key of ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'TERM', 'TMPDIR', 'TMP', 'TEMP',
    'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'SSL_CERT_FILE', 'SSL_CERT_DIR']) {
    if (env[key] != null) childEnv[key] = env[key];
  }
  for (const key of ['INFISICAL_TOKEN', 'INFISICAL_ORG']) if (env[key]) childEnv[key] = env[key];
  if (!env.INFISICAL_TOKEN) childEnv.INFISICAL_PROFILE = env.INFISICAL_PROFILE || 'purple';
  childEnv.INFISICAL_PROJECT_ID = project;
  childEnv.PURPLE_SECRETS_SOURCE = 'infisical';
  childEnv.PURPLE_SECRETS_ENVIRONMENT = environment;
  const localBinary = path.join(home, '.local/bin/infisical');
  return { executable: existsSync(localBinary) ? localBinary : 'infisical',
    args: ['sm', 'run', `--env=${environment}`, `--projectId=${project}`, `--domain=${url.href.replace(/\/$/, '')}`,
      '--path=/', '--expand=false', '--secret-overriding=false', '--telemetry=false', '--', command, ...args],
    env: childEnv };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [environment, command, ...args] = process.argv.slice(2);
    const invocation = infisicalInvocation(environment, command, args);
    const child = spawn(invocation.executable, invocation.args, { env: invocation.env, stdio: 'inherit' });
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
    child.on('error', error => {
      console.error(error.code === 'ENOENT' ? 'Install Infisical CLI 0.44.8 or newer before using this command.' : 'Could not start Infisical.');
      process.exitCode = 1;
    });
    child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
