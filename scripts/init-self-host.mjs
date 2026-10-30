import { mkdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createAccounts } from '../server/accounts.js';
import { createHostedScans } from '../server/hosted-scans.js';

// Explicit local operator bootstrap, never a remotely accessible signup bypass.
const [destination, ...extra] = process.argv.slice(2);
if (!destination || extra.length) throw new Error('Usage: node scripts/init-self-host.mjs <new-private-state-directory>');
const requested = path.resolve(destination);
const directory = path.join(await realpath(path.dirname(requested)), path.basename(requested));
const checkout = await realpath(fileURLToPath(new URL('../', import.meta.url)));
if (directory === checkout || directory.startsWith(checkout + path.sep)) throw new Error('Keep self-hosted credentials and state outside the source checkout.');
if (/[\r\n"\\]/.test(directory)) throw new Error('Use a state path without quotes, backslashes or line breaks.');
await mkdir(directory, { mode: 0o700 }); // refuse an existing directory
const db = new DatabaseSync(path.join(directory, 'purple.sqlite'));
try {
  const accounts = createAccounts(db);
  const user = accounts.upsertUser(`selfhost:${randomBytes(16).toString('hex')}`, 'local-operator');
  const workspace = accounts.ensureWorkspace(user.id);
  const scans = createHostedScans(db);
  const key = scans.issueKey(workspace.id, user.id);
  await writeFile(path.join(directory, 'api-key.json'), JSON.stringify({ key: key.token, keyId: key.id, workspaceId: workspace.id }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  await writeFile(path.join(directory, 'server.env'), [
    'OFFENSE_SELF_HOSTED=true', 'HOST=127.0.0.1', 'PORT=3217', 'PUBLIC_URL=http://127.0.0.1:3217',
    `DATA_DIR="${directory}"`, `ENCRYPTION_KEY=${randomBytes(32).toString('hex')}`,
    'OFFENSE_TRACE_ENABLED=false', 'SCAN_BILLING_ENABLED=false', 'WHOP_BILLING_ENABLED=false', ''
  ].join('\n'), { mode: 0o600, flag: 'wx' });
  console.log('Created private server.env, api-key.json and SQLite state. No credentials were printed. Back up all three together.');
} finally { db.close(); }
