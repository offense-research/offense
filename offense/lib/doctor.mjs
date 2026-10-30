import { access, lstat, stat, realpath, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';

async function available(command, env = process.env) {
  for (const directory of String(env.PATH || '').split(path.delimiter).filter(Boolean)) {
    const file = path.join(directory, command);
    try { if ((await stat(file)).isFile()) { await access(file, constants.X_OK); return true; } } catch {}
  }
  return false;
}

export async function doctor(directory = '.', { env = process.env } = {}) {
  const root = await realpath(directory);
  if (!(await lstat(root)).isDirectory()) throw Error('Select a project directory.');
  const listing = await readdir(root, { withFileTypes: true });
  const tools = {};
  for (const command of ['git', 'docker', 'opengrep', 'zizmor', 'cosign']) tools[command] = { executableAvailable: await available(command, env), connection: 'not_checked', executed: false };
  return { schemaVersion: 'purple.doctor.v1', status: Number(process.versions.node.split('.')[0]) >= 24 ? 'ready' : 'runtime_required',
    runtime: { node: process.versions.node, minimumNodeMajor: 24, platform: process.platform, architecture: process.arch },
    project: { rootDirectoryExists: true, rootLockfiles: listing.filter(entry => entry.isFile() && ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'].includes(entry.name)).map(entry => entry.name) },
    transport: { stdioMcp: 'available', tool: 'offense.audit_dependencies', legacyTool: 'purple.audit_dependencies', activeClientConnection: 'not_observable_from_this_process' },
    tools, provider: { model: 'not_used', companyAccount: 'not_required', hostedPurpleApi: 'not_used',
      auditNetworkDestinations: ['https://api.osv.dev', 'https://registry.npmjs.org'], updatePolicy: 'manual_git_or_package_updates' },
    privacy: { networkRequests: 0, credentialFilesRead: false, applicationExecuted: false },
    limitations: ['Executable availability does not establish Docker connection, scanner version or active MCP registration.', 'A model refusal or client permission prompt must be diagnosed in that client; this command does not change permission policies.'] };
}
