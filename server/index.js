import { publicState } from '../shared/public-state.js';
import { createIssueTrackers, registerIssueTrackerRoutes } from './issue-trackers.js';
import { GITHUB_SCAN_PERMISSIONS } from './github-permissions.js';
import { createSimulationBilling, registerBillingWebhook, registerBillingRoutes } from './whop-billing.js';
import { createContactEmails, registerContactEmailRoutes } from './contact-emails.js';
import { createDependencyMonitor } from './dependency-monitor.js';
import { createHostedScans, createScanSandbox, registerScanApi, registerScanKeys } from './hosted-scans.js';
import { createDockerScanSandbox } from './docker-scan-sandbox.js';
import { configuredAssessmentTools } from './assessment-config.js';
import { createScanMetering } from './scan-metering.js';
import { createWelcomeCredit } from './welcome-credit.js';
import { scanBillingConfig } from './scan-billing-config.js';
import { createScanWhopBilling, registerScanBillingWebhook, registerScanBillingRoutes } from './scan-whop-billing.js';
import { registerSkillApi } from './skill-api.js';
import { registerOffenseApi } from './offense-api.js';
import { createCliAuth, registerCliAuthPublic, registerCliAuthBrowser } from './cli-auth.js';
import { createToolGateway, registerOffensePlatform } from './offense-platform.js';
import { publicOrigins, requestPublicOrigin, productOrigin, LOGIN_RETURN_PATHS } from './public-origins.js';
import { createDiscoveryDashboard, registerDiscoveryDashboard, isMetricsOperator } from './discovery-dashboard.js';
import { providerJson as jsonResponse } from './provider-request.js';
import { registerOperationsMetrics } from './operations-metrics.js';
import { registerUsageMetrics } from './usage-metrics.js';
import { registerScanActivity } from './scan-activity.js';
import { createToolCallMetrics, registerToolCallMetrics } from './tool-call-metrics.js';
import { createJsonDraft, mergeJsonDraft } from './json-draft.js';
import { transactionSync } from './db-transaction.js';
import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installCollector, listWorkers, syncCollectorSources, updateCollector, updateForwarder } from './cloudflare-installer.js';
import { createEventStore } from './event-store.js';
import { createCloudflareAuth } from './cloudflare-auth.js';
import { createAccounts } from './accounts.js';
import { connectInstallation, purpleInstallations, resolveInstallationConnections, workspaceInstallations } from './github-installations.js';
import { createClickHouse } from './clickhouse.js';
import { createGitHubApp } from './github-app.js';
import { createAgentRunner } from './agent-runner.js';
import { createDependencyMapper } from './dependency-mapper.js';
import { createWorkerDiscovery, uniqueWorkerLinks } from './worker-discovery.js';
import { registerDependencyRoutes } from './dependency-routes.js';
import { createRehearsalSandbox, createUpgradeRehearsals } from './upgrade-rehearsal.js';

const app = express();
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const selfHosted = process.env.OFFENSE_SELF_HOSTED === 'true';
if (selfHosted && (process.env.SCAN_BILLING_ENABLED === 'true' || process.env.PURPLE_AGENT_URL || process.env.WHOP_BILLING_ENABLED === 'true'))
  throw new Error('Self-hosted source execution cannot use hosted billing or an external agent service.');
const port = Number(process.env.PORT || 3217);
const host = process.env.HOST || '127.0.0.1';
const base = (process.env.PUBLIC_URL || `http://localhost:${port}`).replace(/\/$/, '');
const publicUrl = new URL(base);
const publicIngestHost = process.env.PURPLE_INGEST_URL ? new URL(process.env.PURPLE_INGEST_URL).hostname : null;
const keyHex = process.env.ENCRYPTION_KEY || '';
const encryptionKey = /^[a-f0-9]{64}$/i.test(keyHex) ? Buffer.from(keyHex, 'hex') : null;
if (selfHosted && !encryptionKey) throw new Error('Self-hosted execution requires a persistent 32-byte hexadecimal ENCRYPTION_KEY.');
const defaultCompany = (process.env.DEFAULT_COMPANY || '').trim();
const dataDir = process.env.DATA_DIR || path.join(root, 'data');
const githubManifestSetupToken = process.env.GITHUB_MANIFEST_SETUP_TOKEN || '';
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const db = new DatabaseSync(path.join(dataDir, 'purple.sqlite'));
db.exec(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)`);
db.exec(`CREATE TABLE IF NOT EXISTS ingest_tokens (token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, created_at INTEGER NOT NULL)`);
const eventStore = createEventStore(db);
const accounts = createAccounts(db);
const contactEmails = createContactEmails(db);
const toolCallMetrics = createToolCallMetrics({ db });
registerOperationsMetrics(app, { db, key: process.env.OPERATIONS_METRICS_KEY, callMetrics: toolCallMetrics });
const clickhouse = createClickHouse({
  url: process.env.CLICKHOUSE_URL, user: process.env.CLICKHOUSE_USER,
  password: process.env.CLICKHOUSE_PASSWORD, database: process.env.CLICKHOUSE_DATABASE,
  table: process.env.CLICKHOUSE_TABLE
});
const githubApp = createGitHubApp({ appId: process.env.GITHUB_APP_ID, privateKey: process.env.GITHUB_APP_PRIVATE_KEY, privateKeyPath: process.env.PURPLE_SECRETS_SOURCE === 'infisical' ? undefined : path.join(dataDir, 'github-app-private-key.pem') });
const agentRunner = createAgentRunner(db, { github: githubApp, decrypt, dataDir,
  model: process.env.PURPLE_AGENT_MODEL || 'deepseek/deepseek-v4.1-flash',
  image: process.env.PURPLE_AGENT_IMAGE || 'purple-pi-agent:0.2',
  searchLogs: clickhouse?.search });
const dependencyMapper = createDependencyMapper(db, githubApp);
const dependencyMonitor = createDependencyMonitor(db, { github: githubApp, mapper: dependencyMapper, runner: agentRunner });
const simulationBilling = createSimulationBilling(db, { apiKey: process.env.WHOP_API_KEY,
  webhookSecret: process.env.WHOP_WEBHOOK_SECRET, enabled: process.env.WHOP_BILLING_ENABLED === 'true',
  sandbox: process.env.WHOP_SANDBOX === 'true', publicUrl: base });
const rehearsals = createUpgradeRehearsals(db, { billing: simulationBilling, platformModelKey: process.env.OPENROUTER_API_KEY, mapper: dependencyMapper, github: githubApp, decrypt,
  sandbox: createRehearsalSandbox(process.env.PURPLE_AGENT_URL, process.env.PURPLE_AGENT_SHARED_KEY) });
const scanMetering = createScanMetering(db, scanBillingConfig(process.env));
const welcomeCredit = createWelcomeCredit(db);
const scanBilling = createScanWhopBilling(db, { meter: scanMetering, apiKey: process.env.WHOP_API_KEY,
  assessmentTools: configuredAssessmentTools(process.env),
  webhookSecret: process.env.SCAN_WHOP_WEBHOOK_SECRET, enabled: process.env.SCAN_BILLING_ENABLED === 'true',
  sandbox: process.env.WHOP_SANDBOX === 'true', publicUrl: productOrigin(base) });
const hostedScans = createHostedScans(db, { encrypt: encryptionKey ? encrypt : null, decrypt,
  onAuthenticatedPrincipal: selfHosted ? undefined : ({ userId, workspaceId }) => welcomeCredit.grantForUser(userId, workspaceId),
  targetSigningKey: encryptionKey,
  assessmentTools: configuredAssessmentTools(process.env),
  sandbox: selfHosted ? await createDockerScanSandbox({ image: process.env.OFFENSE_SOURCE_IMAGE }) :
    createScanSandbox(process.env.PURPLE_AGENT_URL, process.env.PURPLE_AGENT_SHARED_KEY), metering: scanMetering });
const productBase = productOrigin(base);
const trustedOrigins = publicOrigins(base);
if (['localhost', '127.0.0.1'].includes(publicUrl.hostname)) {
  for (const name of ['localhost', '127.0.0.1']) trustedOrigins.add(`http://${name}:5173`);
}
const cliAuth = createCliAuth({ db, scans: hostedScans, baseUrl: productBase, allowedOrigins: trustedOrigins });
const toolGateway = createToolGateway({ scans: hostedScans, billing: scanBilling, accounts, dispatch: () => { void hostedScans.dispatch().catch(() => {}); }, baseUrl: productBase });
const discoveryDashboard = createDiscoveryDashboard(db);
agentRunner.recoverInterrupted();
let agentBusy = false;
async function dispatchAgents() {
  try { await simulationBilling.dispatch(); } catch { console.error('Payment balance maintenance is temporarily unavailable.'); }
  try { await scanBilling.dispatch(); } catch { console.error('Scanner payment reconciliation is temporarily unavailable.'); }
  try { await dependencyMonitor.dispatch(); }
  catch (error) { console.error('Dependency monitor failed:', error.message); }
  await hostedScans.dispatch();
  try { discoveryDashboard.capture(); } catch (error) { console.error('Discovery metrics capture failed:', error.message); }
  if (agentBusy) return;
  agentBusy = true;
  try {
    agentRunner.enqueueMapped();
    await agentRunner.processOne();
    await rehearsals.dispatch();

  } catch (error) { console.error(`Pi dispatch failed: ${error.message}`); }
  finally { agentBusy = false; }
}
setInterval(dispatchAgents, 10000).unref();
setImmediate(dispatchAgents);
let flushing = false;
let lastExportError = '';
async function flushClickHouse() {
  if (!clickhouse || flushing) return;
  flushing = true;
  try {
    for (let n = 0; n < 10; n++) {
      const rows = eventStore.pendingExport();
      if (!rows.length) break;
      await clickhouse.insert(rows);
      eventStore.markExported(rows);
    }
    lastExportError = '';
  } catch (error) {
    if (error.message !== lastExportError) console.error(`ClickHouse export paused: ${error.message}`);
    lastExportError = error.message;
  } finally { flushing = false; }
}
if (clickhouse) {
  setInterval(flushClickHouse, 5000).unref();
  setImmediate(flushClickHouse);
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  if (req.hostname === publicIngestHost && !(req.method === 'POST' && req.path === '/api/ingest')) return res.sendStatus(404);
  next();
});
app.use(toolCallMetrics.middleware());
registerScanApi(app, { scans: hostedScans, dispatch: () => { void hostedScans.dispatch().catch(() => {}); } });
registerCliAuthPublic(app, { auth: cliAuth });
registerOffensePlatform(app, { gateway: toolGateway, scans: hostedScans, billing: scanBilling, baseUrl: productBase });
const dependencyIntelligence = registerSkillApi(app, { db, traceEnabled: process.env.OFFENSE_TRACE_ENABLED !== 'false' });
setInterval(() => dependencyIntelligence.pruneTraces(), 60_000).unref();
registerOffenseApi(app, { intelligence: dependencyIntelligence, publicUrl: publicUrl.href, gateway: toolGateway, allowedOrigins: [...trustedOrigins], callMetrics: toolCallMetrics });
app.use('/api/ingest', express.json({ limit: '256kb' }));
registerBillingWebhook(app, simulationBilling, express);
registerScanBillingWebhook(app, scanBilling, express, () => {
  void scanBilling.dispatch().catch(() => console.error('Scanner payment reconciliation is temporarily unavailable.'));
});
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => {
  if (req.method === 'GET' && ['localhost', '127.0.0.1'].includes(publicUrl.hostname) &&
      ['localhost', '127.0.0.1'].includes(req.hostname) && req.hostname !== publicUrl.hostname) {
    return res.redirect(308, `${base}${req.originalUrl}`);
  }
  next();
});
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'POST' && req.path === '/api/ingest') return next();
  const cookie = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('purple_session='));
  let id = cookie?.slice('purple_session='.length);
  if (!/^[a-f0-9]{64}$/.test(id || '')) id = null;
  let row = id && db.prepare('SELECT data FROM sessions WHERE id = ?').get(id);
  if (!row) {
    id = randomBytes(32).toString('hex');
    row = { data: '{}' };
    db.prepare('INSERT INTO sessions (id, data, updated_at) VALUES (?, ?, ?)').run(id, row.data, Date.now());
    const secure = publicUrl.protocol === 'https:' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `purple_session=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`);
  }
  req.browserSessionId = id;
  const browserDraft = createJsonDraft(JSON.parse(row.data), (data, baseline) => transactionSync(db, () => {
    const current = db.prepare('SELECT data FROM sessions WHERE id = ?').get(req.browserSessionId);
    if (!current) throw Object.assign(new Error('Browser session expired. Sign in again.'), { status: 401 });
    const merged = mergeJsonDraft(baseline, data, JSON.parse(current.data));
    db.prepare('UPDATE sessions SET data = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(merged), Date.now(), req.browserSessionId);
    return merged;
  }));
  req.browserSession = browserDraft.value;
  req.saveBrowser = browserDraft.save;
  req.authUser = req.browserSession.userId ? accounts.findUser(req.browserSession.userId) : null;
  const workspace = req.authUser ? accounts.ensureWorkspace(req.authUser.id, req.browserSession.workspaceId) : null;
  if (workspace) {
    welcomeCredit.grantForUser(req.authUser.id, workspace.id);
    req.workspaceId = workspace.id;
    req.sessionId = workspace.id;
    const workspaceDraft = createJsonDraft(JSON.parse(workspace.data), (data, baseline) => accounts.saveWorkspace(workspace.id, data, baseline));
    req.session = workspaceDraft.value;
    req.save = workspaceDraft.save;
    if (req.browserSession.workspaceId !== workspace.id) {
      req.browserSession.workspaceId = workspace.id;
      req.saveBrowser();
    }
  } else {
    req.workspaceId = null;
    req.sessionId = id;
    req.session = req.authUser ? {} : req.browserSession;
    req.save = req.authUser ? () => { throw new Error('Create a workspace first.'); } : req.saveBrowser;
  }
  next();
});
app.use((req, res, next) => {
  const redirect = res.redirect;
  res.redirect = function (code, target) {
    let location = typeof code === 'string' ? code : target;
    const status = typeof code === 'number' ? code : 302;
    if (requestPublicOrigin(req, base) === 'https://offense.sh' && typeof location === 'string' && /^\/(?:[?#]|$)/.test(location)) location = '/app' + location.slice(1);
    return redirect.call(this, status, location);
  };
  next();
});
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.get('origin');
    const allowed = new Set(trustedOrigins);
    if (['localhost', '127.0.0.1'].includes(publicUrl.hostname)) {
      for (const name of ['localhost', '127.0.0.1']) {
        allowed.add(`http://${name}:${port}`);
        allowed.add(`http://${name}:5173`);
      }
    }
    if (origin && !allowed.has(origin)) return res.status(403).json({ error: 'Invalid request origin.' });
  }
  next();
});
app.use('/api', (req, res, next) => {
  if (req.path === '/state' || req.path === '/ingest' || req.path === '/github/callback' || req.path.startsWith('/auth/')) return next();
  if (!req.authUser) return res.status(401).json({ error: 'Sign in with GitHub first.' });
  if (!req.workspaceId && !['/company', '/operator/discoveries', '/operator/usage', '/operator/skill-usage', '/operator/tool-calls'].includes(req.path)) return res.status(409).json({ error: 'Create a workspace first.' });
  next();
});

registerScanKeys(app, { scans: hostedScans, db });
registerCliAuthBrowser(app, { auth: cliAuth });

registerDiscoveryDashboard(app, { dashboard: discoveryDashboard, operatorIds: process.env.OPERATIONS_GITHUB_IDS });
registerUsageMetrics(app, { db, operatorIds: process.env.OPERATIONS_GITHUB_IDS });
registerScanActivity(app, { db });
registerToolCallMetrics(app, { store: toolCallMetrics, operatorIds: process.env.OPERATIONS_GITHUB_IDS });

const config = {
  dependencySync: true,
  cloudflare: Boolean(process.env.CLOUDFLARE_CLIENT_ID && process.env.CLOUDFLARE_CLIENT_SECRET),
  github: Boolean(process.env.GITHUB_APP_SLUG && process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
  encryption: Boolean(encryptionKey),
  collector: /^https:\/\//.test(process.env.PURPLE_INGEST_URL || ''),
  clickhouse: Boolean(clickhouse),
  agent: Boolean(githubApp)
};
const cloudflareAuth = createCloudflareAuth({ clientId: process.env.CLOUDFLARE_CLIENT_ID, clientSecret: process.env.CLOUDFLARE_CLIENT_SECRET, encrypt, decrypt });
const collectorInstallLocks = new Set();
function encrypt(value) {
  if (!encryptionKey) throw new Error('ENCRYPTION_KEY is not configured');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map(x => x.toString('base64url')).join('.');
}
function decrypt(value) {
  if (!encryptionKey || !value) return null;
  const [iv, tag, ciphertext] = value.split('.').map(x => Buffer.from(x, 'base64url'));
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
function equal(a, b) {
  if (!a || !b) return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function redirectError(res, message) { res.redirect(`/?error=${encodeURIComponent(message)}`); }
function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}
function saveGitHubAppSettings(details) {
  const slug = String(details.slug || '');
  const clientId = String(details.client_id || '');
  const clientSecret = String(details.client_secret || '');
  if (!/^[a-z0-9-]+$/.test(slug) || !/^[A-Za-z0-9.]+$/.test(clientId) || !/^[A-Za-z0-9]+$/.test(clientSecret)) {
    throw new Error('GitHub returned incomplete App credentials.');
  }
  const envPath = path.join(root, '.env');
  const updates = {
    GITHUB_APP_SLUG: slug,
    GITHUB_CLIENT_ID: clientId,
    GITHUB_CLIENT_SECRET: clientSecret,
    GITHUB_APP_ID: String(details.id || ''),
    GITHUB_MANIFEST_SETUP_TOKEN: ''
  };
  const existing = readFileSync(envPath, 'utf8').split(/\r?\n/);
  const seen = new Set();
  const lines = existing.map(line => {
    const name = line.split('=', 1)[0];
    if (!(name in updates)) return line;
    seen.add(name);
    return `${name}=${updates[name]}`;
  });
  for (const [name, value] of Object.entries(updates)) if (!seen.has(name)) lines.push(`${name}=${value}`);
  const tempPath = `${envPath}.${process.pid}.tmp`;
  writeFileSync(tempPath, `${lines.filter((line, index) => line || index !== lines.length - 1).join('\n')}\n`, { mode: 0o600 });
  renameSync(tempPath, envPath);
  if (details.pem) writeFileSync(path.join(dataDir, 'github-app-private-key.pem'), details.pem, { mode: 0o600 });
  process.env.GITHUB_APP_SLUG = slug;
  process.env.GITHUB_CLIENT_ID = clientId;
  process.env.GITHUB_CLIENT_SECRET = clientSecret;
  config.github = true;
  return slug;
}

function stateFor(req) {
  return { ...publicState(req.session, req.authUser, req.workspaceId, { defaultCompany, config }),
    contact: req.authUser ? contactEmails.get(req.authUser.id) : null,
    config: { ...config, operations: isMetricsOperator(req.authUser, process.env.OPERATIONS_GITHUB_IDS) },
    githubInstallations: req.browserSession.githubInstallations?.userId === req.authUser?.id &&
      req.browserSession.githubInstallations?.workspaceId === req.workspaceId &&
      Date.now() - req.browserSession.githubInstallations.created < 10 * 60_000
      ? req.browserSession.githubInstallations.options : [] };
}
registerContactEmailRoutes(app, contactEmails);
const issueTrackers = createIssueTrackers(db, { env: process.env, encrypt: encryptionKey ? encrypt : null, decrypt });
registerIssueTrackerRoutes(app, issueTrackers);
registerBillingRoutes(app, simulationBilling);
registerScanBillingRoutes(app, scanBilling);

app.get('/api/state', (req, res) => res.json(stateFor(req)));

app.get('/api/auth/github/start', (req, res) => {
  if (!config.github) return redirectError(res, 'GitHub sign-in is not configured.');
  const state = randomBytes(24).toString('base64url');
  req.browserSession.githubLoginReturnTo = LOGIN_RETURN_PATHS.includes(req.query.returnTo) ? req.query.returnTo : null;
  req.browserSession.githubLoginOrigin = requestPublicOrigin(req, base);
  req.browserSession.githubLoginState = state;
  req.browserSession.githubLoginStarted = Date.now();
  req.saveBrowser();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.search = new URLSearchParams({ client_id: process.env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state }).toString();
  res.redirect(url.href);
});

async function finishGitHubSignIn(req, res) {
  if (!req.browserSession.githubLoginStarted || Date.now() - req.browserSession.githubLoginStarted > 10 * 60_000) return redirectError(res, 'GitHub sign-in expired. Try again.');
  const loginOrigin = trustedOrigins.has(req.browserSession.githubLoginOrigin) ? req.browserSession.githubLoginOrigin : publicUrl.origin;
  delete req.browserSession.githubLoginOrigin;
  const loginReturnTo = LOGIN_RETURN_PATHS.includes(req.browserSession.githubLoginReturnTo) ? req.browserSession.githubLoginReturnTo : null;
  delete req.browserSession.githubLoginReturnTo;
  delete req.browserSession.githubLoginState;
  delete req.browserSession.githubLoginStarted;
  req.saveBrowser();
  if (!req.query.code) return redirectError(res, 'GitHub did not return an authorization code.');
  try {
    const token = await jsonResponse('https://github.com/login/oauth/access_token', {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: String(req.query.code), redirect_uri: `${loginOrigin}/api/github/callback` })
    });
    if (!token.access_token) throw new Error(token.error_description || 'No access token returned');
    const profile = await jsonResponse('https://api.github.com/user', {
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' }
    });
    if (!Number.isSafeInteger(profile.id) || !profile.login) throw new Error('GitHub did not return a user identity.');
    const user = accounts.upsertUser(profile.id, profile.login);
    contactEmails.suggestFromGitHub(user.id, profile.email);
    const legacy = Object.fromEntries(['company', 'cloudflare', 'github', 'openrouter', 'collectorInstall', 'complete']
      .filter(key => req.browserSession[key] !== undefined).map(key => [key, req.browserSession[key]]));
    const hasLegacy = Boolean((legacy.company && legacy.company !== defaultCompany) || legacy.cloudflare || legacy.github || legacy.openrouter || legacy.collectorInstall);
    let workspace = hasLegacy ? accounts.claimLegacy(user.id, req.browserSessionId, legacy) : accounts.workspaceForUser(user.id);
    let recovered = false;
    let matching = [];
    try {
      const installations = await jsonResponse('https://api.github.com/user/installations?per_page=100', {
        headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' }
      });
      matching = purpleInstallations(installations, process.env.GITHUB_APP_SLUG);
      const candidates = (installations.installations || [])
        .filter(installation => installation.app_slug === process.env.GITHUB_APP_SLUG &&
          installation.account?.type === 'User' && installation.account.id === profile.id)
        .map(installation => accounts.unclaimedPersonalInstall(installation.account.login, installation.id))
        .filter(candidate => candidate && candidate.id !== req.browserSessionId);
      if (candidates.length === 1) {
        workspace = accounts.claimLegacy(user.id, candidates[0].id, candidates[0].data);
        db.prepare('DELETE FROM sessions WHERE id = ?').run(candidates[0].id);
        recovered = true;
      }
    } catch { /* Preserve sign-in authorization even when installation discovery fails. */ }
    const connectUser = data => {
      for (const installation of matching) connectInstallation(data, installation);
      data.githubAuthorization = { userId: user.id, checkedAt: 0, secret: encrypt(JSON.stringify({ ...token,
        expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : null })) };
    };
    workspace ||= accounts.ensureWorkspace(user.id);
    if (workspace) welcomeCredit.grantForUser(user.id, workspace.id);
    if (workspace) accounts.updateWorkspace(workspace.id, connectUser, 'github-sign-in');
    else accounts.updateAccountConnections(user.id, connectUser);
    const nextId = randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (id, data, updated_at) VALUES (?, ?, ?)').run(nextId, JSON.stringify({ userId: user.id, workspaceId: workspace?.id || null }), Date.now());
    db.prepare('DELETE FROM sessions WHERE id = ?').run(req.browserSessionId);
    res.setHeader('Set-Cookie', `purple_session=${nextId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${publicUrl.protocol === 'https:' ? '; Secure' : ''}`);
    res.redirect(loginReturnTo || (recovered ? '/?signed_in=1&recovered=1' : '/?signed_in=1'));
  } catch (error) { redirectError(res, `Could not sign in with GitHub: ${error.message}`); }
}

app.post('/api/auth/logout', (req, res) => {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(req.browserSessionId);
  res.setHeader('Set-Cookie', `purple_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${publicUrl.protocol === 'https:' ? '; Secure' : ''}`);
  res.json({ signedOut: true });
});

app.post('/api/company', (req, res) => {
  const company = String(req.body?.company || '').trim();
  if (company.length < 2 || company.length > 80) return res.status(400).json({ error: 'Enter a company name between 2 and 80 characters.' });
  req.session.company = company;
  if (!req.workspaceId) {
    const workspaceId = randomBytes(32).toString('hex');
    const created = accounts.createWorkspace(req.authUser.id, workspaceId, req.session);
    req.session = JSON.parse(created.data);
    req.workspaceId = workspaceId;
    req.sessionId = workspaceId;
    req.browserSession.workspaceId = workspaceId;
    req.saveBrowser();
  } else req.save();
  res.json(stateFor(req));
});
app.delete('/api/openrouter', (req, res) => {
  delete req.session.openrouter;
  req.session.complete = false;
  req.save();
  res.json(stateFor(req));
});
app.post('/api/openrouter', async (req, res) => {
  const key = String(req.body?.key || '').trim();
  if (!encryptionKey) return res.status(503).json({ error: 'The server needs ENCRYPTION_KEY before it can save a key.' });
  if (!key.startsWith('sk-or-') || key.length > 256) return res.status(400).json({ error: 'Enter a valid OpenRouter API key.' });
  try {
    const response = await fetch('https://openrouter.ai/api/v1/key', {
      headers: { Authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(15000)
    });
    if (response.status === 401 || response.status === 403) {
      return res.status(401).json({ error: 'OpenRouter rejected this key. Check that you pasted an active API key from openrouter.ai/keys.' });
    }
    if (!response.ok) {
      return res.status(503).json({ error: `OpenRouter is unavailable right now (HTTP ${response.status}). Please try again.` });
    }
    const data = await response.json();
    if (!data?.data || typeof data.data !== 'object') {
      return res.status(503).json({ error: 'OpenRouter returned an unexpected response. Please try again.' });
    }
    req.session.openrouter = { secret: encrypt(key), last4: key.slice(-4), label: data.data?.label || 'Verified key' };
    req.session.complete = false;
    req.save();
    res.json(stateFor(req));
  } catch (error) {
    res.status(503).json({ error: error.name === 'TimeoutError' ? 'OpenRouter took too long to respond. Please try again.' : 'Could not reach OpenRouter. Please try again.' });
  }
});

app.get('/api/cloudflare/start', (req, res) => {
  if (!config.cloudflare || !encryptionKey) return redirectError(res, 'Cloudflare connection needs server credentials. See .env.example.');
  const state = randomBytes(24).toString('base64url');
  req.browserSession.cloudflareState = state;
  req.saveBrowser();
  const url = new URL('https://dash.cloudflare.com/oauth2/auth');
  url.search = new URLSearchParams({ response_type: 'code', client_id: process.env.CLOUDFLARE_CLIENT_ID, redirect_uri: `${base}/api/cloudflare/callback`, scope: [...new Set(((process.env.CLOUDFLARE_SCOPES || 'account-settings.read') + ' offline_access').split(/\s+/))].join(' '), state }).toString();
  res.redirect(url.href);
});
app.get('/api/cloudflare/callback', async (req, res) => {
  if (req.query.error) return redirectError(res, 'Cloudflare authorization was canceled.');
  if (!equal(String(req.query.state || ''), req.browserSession.cloudflareState)) return redirectError(res, 'Cloudflare session expired. Please try again.');
  delete req.browserSession.cloudflareState;
  req.saveBrowser();
  if (!req.query.code) return redirectError(res, 'Cloudflare did not return an authorization code.');
  try {
    const token = await jsonResponse('https://dash.cloudflare.com/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${process.env.CLOUDFLARE_CLIENT_ID}:${process.env.CLOUDFLARE_CLIENT_SECRET}`).toString('base64')}` },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: `${base}/api/cloudflare/callback` })
    });
    const accounts = await jsonResponse('https://api.cloudflare.com/client/v4/accounts', { headers: { Authorization: `Bearer ${token.access_token}` } });
    const list = (accounts.result || []).map(a => ({ id: a.id, name: a.name })).filter(a => a.id && a.name);
    req.session.cloudflare = { accessToken: encrypt(token.access_token), expiresAt: Date.now() + (Number(token.expires_in) || 3600) * 1000, refreshToken: token.refresh_token ? encrypt(token.refresh_token) : null, accounts: list, name: list.length === 1 ? list[0].name : `${list.length} Cloudflare account${list.length === 1 ? '' : 's'}` };
    req.session.complete = false;
    req.save();
    res.redirect(req.session.collectorInstall?.status === 'installed' ? '/?connected=cloudflare#collector' : '/?connected=cloudflare');
  } catch (error) { redirectError(res, `Could not connect Cloudflare: ${error.message}`); }
});
app.delete('/api/cloudflare', (req, res) => {
  delete req.session.cloudflare;
  req.session.complete = false;
  req.save();
  res.json(stateFor(req));
});

app.get('/api/cloudflare/workers', async (req, res) => {
  const accountId = String(req.query.accountId || '');
  if (!req.session.cloudflare) return res.status(401).json({ error: 'Connect Cloudflare first.' });
  if (!req.session.cloudflare.accounts.some(account => account.id === accountId)) return res.status(403).json({ error: 'Select a connected Cloudflare account.' });
  try {
    const workers = await listWorkers(await cloudflareAuth.accessToken(req.sessionId, req.session.cloudflare, req.save), accountId);
    res.json({ workers: workers.filter(name => !name.startsWith('purple-collector-') && !name.startsWith('purple-forwarder-')) });
  } catch (error) {
    res.status(error.status === 401 || error.status === 403 ? 403 : 502).json({ error: `Could not list Workers: ${error.message}` });
  }
});

app.post('/api/cloudflare/install', async (req, res) => {
  const accountId = String(req.body?.accountId || '');
  const sources = req.body?.sources;
  if (!req.session.cloudflare) return res.status(401).json({ error: 'Connect Cloudflare first.' });
  if (!req.session.cloudflare.accounts.some(account => account.id === accountId)) return res.status(403).json({ error: 'Select a connected Cloudflare account.' });
  if (!Array.isArray(sources) || !sources.length || sources.length > 25 || sources.some(name => typeof name !== 'string' || !/^[a-zA-Z0-9_-]{1,63}$/.test(name)) || new Set(sources).size !== sources.length) {
    return res.status(400).json({ error: 'Select 1 to 25 distinct source Workers.' });
  }
  const ingestUrl = process.env.PURPLE_INGEST_URL || '';
  if (!/^https:\/\//.test(ingestUrl)) return res.status(503).json({ error: 'A public HTTPS Purple ingest URL must be configured before installation.' });
  if (collectorInstallLocks.has(req.sessionId)) return res.status(409).json({ error: 'An installation is already running. Please wait.' });
  if (req.session.collectorInstall?.status === 'installed') return res.status(409).json({ error: 'Purple is already installed for this workspace.' });
  if (req.session.collectorInstall && (req.session.collectorInstall.accountId !== accountId || JSON.stringify(req.session.collectorInstall.sources) !== JSON.stringify(sources))) {
    return res.status(409).json({ error: 'An installation is in progress. Retry with the same account and Workers.' });
  }
  if (!req.session.collectorInstall) {
    const id = randomBytes(5).toString('hex');
    const ingestToken = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(ingestToken).digest('hex');
    db.prepare('INSERT INTO ingest_tokens (token_hash, session_id, created_at) VALUES (?, ?, ?)').run(tokenHash, req.sessionId, Date.now());
    req.session.collectorInstall = { accountId, sources, queue: `purple-events-${id}`, collector: `purple-collector-${id}`, forwarder: `purple-forwarder-${id}`, ingestToken: encrypt(ingestToken), attached: [], status: 'installing' };
    req.save();
  }
  collectorInstallLocks.add(req.sessionId);
  try {
    const install = req.session.collectorInstall;
    await installCollector({
      token: await cloudflareAuth.accessToken(req.sessionId, req.session.cloudflare, req.save), accountId, sources, install, ingestUrl,
      ingestToken: decrypt(install.ingestToken), save: req.save
    });
    res.json(stateFor(req));
  } catch (error) {
    res.status(error.status === 401 || error.status === 403 ? 403 : 502).json({ error: `Cloudflare installation stopped: ${error.message} You can retry after fixing it.` });
  } finally {
    collectorInstallLocks.delete(req.sessionId);
  }
});

app.post('/api/cloudflare/collector/update', async (req, res) => {
  const install = req.session.collectorInstall;
  if (!req.session.cloudflare || install?.status !== 'installed') return res.status(403).json({ error: 'Connect Cloudflare and install the collector first.' });
  if (!req.session.cloudflare.accounts.some(account => account.id === install.accountId)) return res.status(403).json({ error: 'Reconnect the Cloudflare account used for this collector.' });
  if (collectorInstallLocks.has(req.sessionId)) return res.status(409).json({ error: 'A collector update is already running.' });
  collectorInstallLocks.add(req.sessionId);
  try {
    const token = await cloudflareAuth.accessToken(req.sessionId, req.session.cloudflare, req.save);
    await updateCollector(token, install);
    await updateForwarder(token, install, process.env.PURPLE_INGEST_URL, decrypt(install.ingestToken));
    res.json({ updated: true });
  } catch (error) {
    res.status(error.status === 401 || error.status === 403 ? 403 : 502).json({ error: `Could not update collector: ${error.message}` });
  } finally {
    collectorInstallLocks.delete(req.sessionId);
  }
});

app.put('/api/cloudflare/collector/sources', async (req, res) => {
  const install = req.session.collectorInstall;
  if (!req.session.cloudflare || install?.status !== 'installed') return res.status(403).json({ error: 'Connect Cloudflare and install the collector first.' });
  if (!req.session.cloudflare.accounts.some(account => account.id === install.accountId)) return res.status(403).json({ error: 'Reconnect the Cloudflare account used for this collector.' });
  if (collectorInstallLocks.has(req.sessionId)) return res.status(409).json({ error: 'A collector change is already running.' });
  collectorInstallLocks.add(req.sessionId);
  try {
    await syncCollectorSources(await cloudflareAuth.accessToken(req.sessionId, req.session.cloudflare, req.save), install, req.body?.sources, req.save);
    res.json(stateFor(req));
  } catch (error) {
    res.status(error.status === 401 || error.status === 403 ? 403 : error.status === 400 ? 400 : 502)
      .json({ error: `Could not update source Workers: ${error.message}` });
  } finally {
    collectorInstallLocks.delete(req.sessionId);
  }
});

app.post('/api/ingest', (req, res) => {
  const bearer = req.get('authorization') || '';
  if (!/^Bearer [A-Za-z0-9_-]{43}$/.test(bearer)) return res.sendStatus(401);
  const tokenHash = createHash('sha256').update(bearer.slice(7)).digest('hex');
  const token = db.prepare('SELECT session_id FROM ingest_tokens WHERE token_hash = ?').get(tokenHash);
  if (!token) return res.sendStatus(401);
  const events = req.body?.events;
  if (!Array.isArray(events) || !events.length || events.length > 100 || events.some(event =>
    !event || event.schema !== 'purple.tail.v1' || typeof event.sourceWorker !== 'string' || !event.sourceWorker ||
    (event.queueMessageId != null && (typeof event.queueMessageId !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(event.queueMessageId))))) {
    return res.status(400).json({ error: 'Invalid event batch.' });
  }
  try {
    const receipt = eventStore.receiveBatch(token.session_id, events);
    res.json(receipt);
    if (clickhouse) setImmediate(flushClickHouse);
  } catch {
    res.status(503).json({ error: 'Could not persist event batch. Retry delivery.' });
  }
});

app.get('/api/cloudflare/events', (req, res) => {
  if (!req.session.collectorInstall) return res.status(404).json({ error: 'Collector is not installed.' });
  const count = db.prepare('SELECT COUNT(*) AS count FROM events WHERE session_id = ?').get(req.sessionId).count;
  const events = db.prepare('SELECT payload FROM events WHERE session_id = ? ORDER BY id DESC LIMIT 10').all(req.sessionId).map(row => JSON.parse(row.payload));
  res.json({ count, events });
});

app.get('/api/cloudflare/batches', (req, res) => {
  if (!req.session.collectorInstall) return res.status(404).json({ error: 'Collector is not installed.' });
  res.json({ batches: eventStore.recentBatches(req.sessionId) });
});
app.get('/api/vulnerabilities', (req, res) => res.json({
  metrics: agentRunner.vulnerabilities.metrics(req.sessionId),
  discoveries: agentRunner.vulnerabilities.list(req.sessionId)
}));

app.get('/api/investigations', (req, res) => res.json({ investigations: eventStore.investigations(req.sessionId) }));
app.get('/api/investigations/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid investigation ID.' });
  const investigation = eventStore.investigation(req.sessionId, id);
  if (!investigation) return res.status(404).json({ error: 'Investigation not found.' });
  res.json(investigation);
});
const discoverWorkers = githubApp ? createWorkerDiscovery(githubApp) : null;
async function syncGitHubAccess(req) {
  const auth = req.session.githubAuthorization;
  if (!auth || auth.userId !== req.authUser?.id || auth.checkedAt > Date.now() - 60_000) return;
  let token = JSON.parse(decrypt(auth.secret));
  if (token.expiresAt && token.expiresAt < Date.now() + 60_000) {
    if (!token.refresh_token) throw new Error('Refresh GitHub access to renew your authorization.');
    const renewed = await jsonResponse('https://github.com/login/oauth/access_token', {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET,
        grant_type: 'refresh_token', refresh_token: token.refresh_token })
    });
    if (!renewed.access_token) throw new Error('Refresh GitHub access to renew your authorization.');
    token = { ...renewed, expiresAt: renewed.expires_in ? Date.now() + renewed.expires_in * 1000 : null };
    auth.secret = encrypt(JSON.stringify(token));
  }
  const available = [];
  for (let page = 1; page <= 10; page++) {
    const data = await jsonResponse(`https://api.github.com/user/installations?per_page=100&page=${page}`, {
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' }
    });
    available.push(...purpleInstallations(data, process.env.GITHUB_APP_SLUG));
    if ((data.installations || []).length < 100) break;
  }
  for (const installation of available) connectInstallation(req.session, installation);
  auth.checkedAt = Date.now();
  req.save();
}
async function autoLinkWorkers(req) {
  if (!discoverWorkers) return [];
  const workers = (req.session.collectorInstall?.sources || []).filter(worker => !(req.session.autoLinkDisabledWorkers || []).includes(worker));
  const existing = agentRunner.mappings(req.sessionId);
  if (workers.every(worker => existing.some(link => link.sourceWorker === worker))) return [];
  const discovery = await discoverWorkers(workspaceInstallations(req.session), workers);
  if (discovery.warnings.length) return discovery.warnings;
  for (const link of uniqueWorkerLinks(workers, discovery.repositories, agentRunner.mappings(req.sessionId))) {
    await agentRunner.setMapping(req.sessionId, link.sourceWorker, link.repository, link.installationId, { onlyIfUnlinked: true });
  }
  return discovery.warnings;
}
app.get('/api/agent/repositories', async (req, res) => {
  const syncWarnings = [];
  try { await syncGitHubAccess(req); } catch (error) { syncWarnings.push(error.message); }
  const connected = workspaceInstallations(req.session);
  if (!githubApp || !connected.length) return res.status(503).json({ error: 'Connect the GitHub App before assigning a repository.' });
  try {
    const appInfoPromise = githubApp.appInfo().catch(() => null);
    const results = await Promise.allSettled(connected.map(async installation => {
      const [repositories, info] = await Promise.all([
        githubApp.repositories(installation.installationId), githubApp.installationInfo(installation.installationId)
      ]);
      return { installation: { ...installation, ...info }, repositories: repositories.map(repo => ({ ...repo, installationId: installation.installationId, account: installation.account })) };
    }));
    const available = results.filter(result => result.status === 'fulfilled').map(result => result.value);
    if (!available.length) throw new Error('No connected installation is currently accessible.');
    const appInfo = await appInfoPromise;
    const discoveryWarnings = await autoLinkWorkers(req);
    res.json({ mappings: agentRunner.mappings(req.sessionId), repositories: available.flatMap(item => item.repositories), installations: available.map(item => item.installation),
      app: appInfo, warnings: [...syncWarnings, ...discoveryWarnings, ...results.filter(result => result.status === 'rejected').map(result => result.reason.message)] });
  }
  catch (error) { res.status(502).json({ error: `Could not list installed repositories: ${error.message}` }); }
});
app.get('/api/agent/mappings', (req, res) => res.json({ mappings: agentRunner.mappings(req.sessionId) }));
registerDependencyRoutes(app, { trackers: issueTrackers, github: githubApp, mapper: dependencyMapper, runner: agentRunner, monitor: dependencyMonitor, syncGitHubAccess, autoLinkWorkers,
  rehearsals, dispatchRehearsals: () => { void rehearsals.dispatch().catch(error => console.error('Rehearsal dispatch failed', error.message)); } });
app.put('/api/agent/mappings', async (req, res) => {
  const worker = req.body?.sourceWorker;
  const repository = req.body?.repository;
  const installationId = Number(req.body?.installationId);
  const sources = req.session.collectorInstall?.sources || [];
  if (!sources.includes(worker) || typeof repository !== 'string') return res.status(400).json({ error: 'Choose an installed source Worker and repository.' });
  if (repository && !workspaceInstallations(req.session).some(item => item.installationId === installationId)) return res.status(400).json({ error: 'Choose a connected GitHub installation.' });
  try {
    await agentRunner.setMapping(req.sessionId, worker, repository, repository ? installationId : 0);
    const disabled = new Set(req.session.autoLinkDisabledWorkers || []);
    if (repository) disabled.delete(worker); else disabled.add(worker);
    req.session.autoLinkDisabledWorkers = [...disabled];
    req.save();
    agentRunner.enqueueMapped();
    setImmediate(dispatchAgents);
    res.json({ mappings: agentRunner.mappings(req.sessionId) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});
app.get('/api/investigations/:id/agent', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0 || !eventStore.investigation(req.sessionId, id)) return res.status(404).json({ error: 'Investigation not found.' });
  res.json({ run: agentRunner.run(req.sessionId, id) });
});
app.get('/api/investigations/:id/agent/patch', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0 || !eventStore.investigation(req.sessionId, id)) return res.status(404).json({ error: 'Investigation not found.' });
  const patch = agentRunner.patch(req.sessionId, id);
  if (!patch) return res.status(404).json({ error: 'No patch is available for this investigation.' });
  res.type('text/x-diff').set('Content-Disposition', `attachment; filename="purple-investigation-${id}.patch"`).send(patch);
});
app.post('/api/investigations/:id/agent/retry', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id <= 0 || !eventStore.investigation(req.sessionId, id)) return res.status(404).json({ error: 'Investigation not found.' });
  if (!agentRunner.retry(req.sessionId, id)) return res.status(409).json({ error: 'Only failed or unverified analyses can be retried.' });
  setImmediate(dispatchAgents);
  res.json({ run: agentRunner.run(req.sessionId, id) });
});
app.patch('/api/investigations/:id', (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.status;
  if (!Number.isSafeInteger(id) || id <= 0 || !['open', 'resolved'].includes(status)) return res.status(400).json({ error: 'Invalid investigation update.' });
  if (!eventStore.setInvestigationStatus(req.sessionId, id, status)) return res.status(404).json({ error: 'Investigation not found.' });
  res.json(eventStore.investigation(req.sessionId, id));
});
app.get('/api/events/search', async (req, res) => {
  if (!clickhouse) return res.status(503).json({ error: 'ClickHouse search is not configured yet.' });
  const worker = String(req.query.worker || '');
  const requestId = String(req.query.requestId || '');
  if (worker.length > 128 || requestId.length > 128 || (requestId && !/^[A-Za-z0-9._:-]+$/.test(requestId))) {
    return res.status(400).json({ error: 'Invalid search filters.' });
  }
  const from = req.query.from ? Date.parse(String(req.query.from)) : null;
  const to = req.query.to ? Date.parse(String(req.query.to)) : null;
  if ((req.query.from && !Number.isFinite(from)) || (req.query.to && !Number.isFinite(to)) ||
      (from != null && to != null && from >= to)) return res.status(400).json({ error: 'Enter a valid time range.' });
  try {
    const events = await clickhouse.search(req.workspaceId, { worker, requestId, from, to, limit: req.query.limit });
    res.json({ events });
  } catch {
    res.status(503).json({ error: 'ClickHouse search is temporarily unavailable.' });
  }
});

// One-time owner setup. The link is private to this development tailnet and is
// disabled as soon as the GitHub App credentials have been saved.
app.get('/admin/github/register', (req, res) => {
  if (config.github || !githubManifestSetupToken || !equal(String(req.query.token || ''), githubManifestSetupToken)) return res.sendStatus(404);
  req.browserSession.githubManifestAuthorized = Date.now();
  req.saveBrowser();
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.redirect('/admin/github/confirm');
});
app.get('/admin/github/confirm', (req, res) => {
  if (config.github || !req.browserSession.githubManifestAuthorized || Date.now() - req.browserSession.githubManifestAuthorized > 10 * 60_000) return res.sendStatus(404);
  const state = randomBytes(24).toString('base64url');
  req.browserSession.githubManifestState = state;
  req.browserSession.githubManifestStarted = Date.now();
  req.saveBrowser();
  const manifest = {
    name: 'Purple Dev imranye',
    url: base,
    description: 'Purple development GitHub App',
    hook_attributes: { url: `${base}/api/github/webhook`, active: false },
    redirect_url: `${base}/admin/github/manifest/callback`,
    callback_urls: [`${base}/api/github/callback`],
    setup_url: `${base}/api/github/setup`,
    public: false,
    default_events: [],
    default_permissions: GITHUB_SCAN_PERMISSIONS,
    request_oauth_on_install: false,
    setup_on_update: false
  };
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.send(`<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Create Purple GitHub App</title><style>body{font:16px system-ui;background:#f8f7f4;color:#28222e;max-width:540px;margin:12vh auto;padding:24px}main{background:white;border:1px solid #e9e3ed;border-radius:16px;padding:28px}h1{font-size:28px}p{line-height:1.55;color:#68606d}button{border:0;border-radius:9px;background:#814de0;color:white;font-weight:700;padding:14px 18px;font-size:15px}</style><main><h1>Create the Purple GitHub App</h1><p>This opens GitHub on your own device. GitHub will create a private development App with read access to only the repositories you select during installation. Purple will securely save the returned App credentials on this server.</p><form method="post" action="https://github.com/settings/apps/new?state=${encodeURIComponent(state)}"><input type="hidden" name="manifest" value="${htmlEscape(JSON.stringify(manifest))}"><button type="submit">Continue to GitHub</button></form></main></html>`);
});
app.get('/admin/github/manifest/callback', async (req, res) => {
  if (config.github) return res.redirect('/?registered=github');
  if (!equal(String(req.query.state || ''), req.browserSession.githubManifestState) || !req.browserSession.githubManifestStarted || Date.now() - req.browserSession.githubManifestStarted > 60 * 60_000) return redirectError(res, 'GitHub App registration session expired.');
  const code = String(req.query.code || '');
  if (!/^[A-Za-z0-9_-]{10,256}$/.test(code)) return redirectError(res, 'GitHub did not return a valid App registration code.');
  try {
    const details = await jsonResponse(`https://api.github.com/app-manifests/${code}/conversions`, { method: 'POST', headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } });
    saveGitHubAppSettings(details);
    delete req.browserSession.githubManifestState;
    delete req.browserSession.githubManifestStarted;
    delete req.browserSession.githubManifestAuthorized;
    req.saveBrowser();
    res.redirect('/?registered=github');
  } catch (error) { redirectError(res, `Could not finish GitHub App registration: ${error.message}`); }
});

app.get('/api/github/start', (req, res) => {
  if (!config.github) return redirectError(res, 'GitHub App settings are missing. See .env.example.');
  const state = randomBytes(24).toString('base64url');
  req.browserSession.githubOauthState = state;
  req.browserSession.githubOauthStarted = Date.now();
  req.browserSession.githubSyncInstallations = req.query.sync === '1';
  delete req.browserSession.pendingInstallationId;
  delete req.browserSession.githubInstallations;
  req.saveBrowser();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.search = new URLSearchParams({ client_id: process.env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state }).toString();
  res.redirect(url.href);
});
function startGitHubInstall(req, res) {
  delete req.browserSession.githubSyncInstallations;
  const state = randomBytes(24).toString('base64url');
  req.browserSession.githubInstallState = state;
  req.browserSession.githubInstallStarted = Date.now();
  req.saveBrowser();
  res.redirect(`https://github.com/apps/${encodeURIComponent(process.env.GITHUB_APP_SLUG)}/installations/new?state=${encodeURIComponent(state)}`);
}
app.get('/api/github/install', (req, res) => startGitHubInstall(req, res));
app.post('/api/github/select', (req, res) => {
  const pending = req.browserSession.githubInstallations;
  const installationId = Number(req.body?.installationId);
  if (!pending || pending.userId !== req.authUser.id || pending.workspaceId !== req.workspaceId ||
      Date.now() - pending.created > 10 * 60_000 ||
      !pending.options.some(item => item.installationId === installationId)) {
    return res.status(400).json({ error: 'GitHub installation selection expired. Try connecting again.' });
  }
  const selected = pending.options.find(item => item.installationId === installationId);
  connectInstallation(req.session, selected);
  req.save();
  delete req.browserSession.githubInstallations;
  req.saveBrowser();
  res.json(stateFor(req));
});
app.get('/api/github/setup', (req, res) => {
  const id = Number(req.query.installation_id);
  if (!req.browserSession.githubInstallStarted || Date.now() - req.browserSession.githubInstallStarted > 10 * 60_000 ||
      (req.query.state && !equal(String(req.query.state), req.browserSession.githubInstallState)) ||
      !Number.isSafeInteger(id) || id <= 0) return redirectError(res, 'GitHub installation session expired. Please try again.');
  delete req.browserSession.githubInstallState;
  delete req.browserSession.githubInstallStarted;
  const oauthState = randomBytes(24).toString('base64url');
  req.browserSession.githubOauthState = oauthState;
  req.browserSession.githubOauthStarted = Date.now();
  req.browserSession.pendingInstallationId = id;
  req.saveBrowser();
  const url = new URL('https://github.com/login/oauth/authorize');
  url.search = new URLSearchParams({ client_id: process.env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state: oauthState }).toString();
  res.redirect(url.href);
});
app.get('/api/github/callback', async (req, res) => {
  if (equal(String(req.query.state || ''), req.browserSession.githubLoginState)) return finishGitHubSignIn(req, res);
  if (!req.authUser || !req.workspaceId) return redirectError(res, 'Sign in before connecting a GitHub installation.');
  if (req.query.error) return redirectError(res, 'GitHub authorization was canceled.');
  if (!equal(String(req.query.state || ''), req.browserSession.githubOauthState) ||
      !req.browserSession.githubOauthStarted || Date.now() - req.browserSession.githubOauthStarted > 10 * 60_000) return redirectError(res, 'GitHub session expired. Please try again.');
  const installationId = req.browserSession.pendingInstallationId;
  const syncInstallations = req.browserSession.githubSyncInstallations === true;
  delete req.browserSession.githubSyncInstallations;
  delete req.browserSession.githubOauthState;
  delete req.browserSession.githubOauthStarted;
  delete req.browserSession.pendingInstallationId;
  req.saveBrowser();
  if (!req.query.code) return redirectError(res, 'GitHub did not return an authorization code.');
  try {
    const token = await jsonResponse('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: String(req.query.code), redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback` })
    });
    if (!token.access_token) throw new Error(token.error_description || 'No access token returned');
    const profile = await jsonResponse('https://api.github.com/user', {
      headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' }
    });
    if (String(profile.id) !== req.authUser.githubId) throw new Error('GitHub authorized a different account. Sign in to Purple with that account first.');
    const data = await jsonResponse('https://api.github.com/user/installations?per_page=100', { headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'X-GitHub-Api-Version': '2022-11-28' } });
    req.session.githubAuthorization = { userId: req.authUser.id, checkedAt: 0,
      secret: encrypt(JSON.stringify({ ...token, expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : null })) };
    req.save();
    const options = purpleInstallations(data, process.env.GITHUB_APP_SLUG);
    if (!installationId && options.length === 0) return startGitHubInstall(req, res);
    const selection = resolveInstallationConnections(req.session, options, { installationId, sync: syncInstallations });
    if (selection.choices.length) {
      req.browserSession.githubInstallations = { userId: req.authUser.id, workspaceId: req.workspaceId,
        created: Date.now(), options: selection.choices };
      req.saveBrowser();
      return res.redirect('/?step=github&choose_installation=1#connections');
    }
    for (const installation of selection.connections) connectInstallation(req.session, installation);
    req.save();
    res.redirect(req.session.collectorInstall?.status === 'installed' ? '/?connected=github#worker-repositories' : '/?connected=github#dependencies');
  } catch (error) { redirectError(res, `Could not verify GitHub installation: ${error.message}`); }
});
app.delete('/api/github', (req, res) => {
  delete req.session.dependencyRepositories;
  delete req.session.githubAuthorization;
  delete req.session.github;
  delete req.session.githubInstallations;
  db.prepare("DELETE FROM agent_runs WHERE session_id = ? AND status = 'queued'").run(req.sessionId);
  db.prepare('DELETE FROM worker_repositories WHERE session_id = ?').run(req.sessionId);
  req.session.complete = false;
  req.save();
  res.json(stateFor(req));
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  res.status(error.status || 500).json({ error: error.status ? error.message : 'Could not save workspace. Please try again.' });
});
app.use(express.static(path.join(root, 'dist')));
app.get('/{*path}', (req, res) => res.sendFile(path.join(root, 'dist', 'index.html')));
app.listen(port, host, () => console.log(`Purple is running at ${base}`));
