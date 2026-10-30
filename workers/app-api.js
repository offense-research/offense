import { createIssueTrackers, registerIssueTrackerRoutes } from '../server/issue-trackers.js';
import { createSimulationBilling, registerBillingWebhook, registerBillingRoutes } from '../server/whop-billing.js';
import { createContactEmails, registerContactEmailRoutes } from '../server/contact-emails.js';
import { createDependencyMonitor } from '../server/dependency-monitor.js';
import { createHostedScans, createScanSandbox, registerScanApi, registerScanKeys } from '../server/hosted-scans.js';
import { configuredAssessmentTools } from '../server/assessment-config.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createWelcomeCredit } from '../server/welcome-credit.js';
import { scanBillingConfig } from '../server/scan-billing-config.js';
import { createScanWhopBilling, registerScanBillingWebhook, registerScanBillingRoutes } from '../server/scan-whop-billing.js';
import { createDiscoveryDashboard, registerDiscoveryDashboard, isMetricsOperator } from '../server/discovery-dashboard.js';
import { registerSkillApi } from '../server/skill-api.js';
import { registerOffenseApi } from '../server/offense-api.js';
import { createCliAuth, registerCliAuthPublic, registerCliAuthBrowser } from '../server/cli-auth.js';
import { createToolGateway, registerOffensePlatform } from '../server/offense-platform.js';
import { publicOrigins, requestPublicOrigin, productOrigin, LOGIN_RETURN_PATHS } from '../server/public-origins.js';
import { providerJson as jsonResponse } from '../server/provider-request.js';
import { registerOperationsMetrics } from '../server/operations-metrics.js';
import { registerUsageMetrics } from '../server/usage-metrics.js';
import { registerScanActivity } from '../server/scan-activity.js';
import { createToolCallMetrics, registerToolCallMetrics } from '../server/tool-call-metrics.js';
import { createJsonDraft, mergeJsonDraft } from '../server/json-draft.js';
import { transactionSync } from '../server/db-transaction.js';
import express from 'express';
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { installCollector, listWorkers, syncCollectorSources, updateCollector, updateForwarder } from './installer.js';
import { createEventStore } from '../server/event-store.js';
import { createCloudflareAuth } from '../server/cloudflare-auth.js';
import { createAccounts } from '../server/accounts.js';
import { connectInstallation, purpleInstallations, resolveInstallationConnections, workspaceInstallations } from '../server/github-installations.js';
import { createClickHouse } from '../server/clickhouse.js';
import { createGitHubApp } from '../server/github-app.js';
import { createAgentRunner } from './agent-runner.js';
import { createDependencyMapper } from '../server/dependency-mapper.js';
import { createWorkerDiscovery, uniqueWorkerLinks } from '../server/worker-discovery.js';
import { registerDependencyRoutes } from '../server/dependency-routes.js';
import { createRehearsalSandbox, createUpgradeRehearsals } from '../server/upgrade-rehearsal.js';

export function createWorkerApp({ db, env, schedule }) {
const app = express();
const port = 443;
const base = (env.PUBLIC_URL || 'https://app.purpleteam.sh').replace(/\/$/, '');
const publicUrl = new URL(base);
const publicIngestHost = env.PURPLE_INGEST_URL ? new URL(env.PURPLE_INGEST_URL).hostname : null;
const keyHex = env.ENCRYPTION_KEY || '';
const encryptionKey = /^[a-f0-9]{64}$/i.test(keyHex) ? Buffer.from(keyHex, 'hex') : null;
const defaultCompany = (env.DEFAULT_COMPANY || '').trim();
db.exec(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)`);
db.exec(`CREATE TABLE IF NOT EXISTS ingest_tokens (token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, created_at INTEGER NOT NULL)`);
const eventStore = createEventStore(db);
const accounts = createAccounts(db);
const contactEmails = createContactEmails(db);
const toolCallMetrics = createToolCallMetrics({ db });
registerOperationsMetrics(app, { db, key: env.OPERATIONS_METRICS_KEY, callMetrics: toolCallMetrics });
const clickhouse = createClickHouse({
  url: env.CLICKHOUSE_URL, user: env.CLICKHOUSE_USER,
  password: env.CLICKHOUSE_PASSWORD, database: env.CLICKHOUSE_DATABASE,
  table: env.CLICKHOUSE_TABLE
});
const githubApp = createGitHubApp({ appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_APP_PRIVATE_KEY });
const agentSandbox = env.PURPLE_AGENT_URL && env.PURPLE_AGENT_SHARED_KEY ? {
  async startInvestigation(input) {
    const evidence = { ...input, logs: input.logs.slice(0, 20).map(event => ({ ...event,
      logs: (event.logs || []).slice(0, 10).map(log => ({ ...log, message: String(log.message || '').slice(0, 300) })) })) };
    const response = await fetch(`${env.PURPLE_AGENT_URL}/run`, {
      method: 'POST',
      headers: { authorization: `Bearer ${env.PURPLE_AGENT_SHARED_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify(evidence), signal: AbortSignal.timeout(60_000)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Pi service returned ${response.status}.`);
    return result;
  },
  async getInvestigation(runId, attemptId) {
    const response = await fetch(`${env.PURPLE_AGENT_URL}/runs/${runId}${attemptId ? `?attempt=${attemptId}` : ''}`, {
      headers: { authorization: `Bearer ${env.PURPLE_AGENT_SHARED_KEY}` }, signal: AbortSignal.timeout(30_000)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Pi service returned ${response.status}.`);
    return result;
  }
} : null;
const agentRunner = createAgentRunner(db, { github: githubApp, decrypt,
  model: env.PURPLE_AGENT_MODEL || 'deepseek/deepseek-v4.1-flash',
  sandbox: agentSandbox,
  searchLogs: clickhouse?.search || searchRecentEvents });
const dependencyMapper = createDependencyMapper(db, githubApp);
const dependencyMonitor = createDependencyMonitor(db, { github: githubApp, mapper: dependencyMapper, runner: agentRunner });
const simulationBilling = createSimulationBilling(db, { apiKey: env.WHOP_API_KEY,
  webhookSecret: env.WHOP_WEBHOOK_SECRET, enabled: env.WHOP_BILLING_ENABLED === 'true',
  sandbox: env.WHOP_SANDBOX === 'true', publicUrl: base });
const rehearsals = createUpgradeRehearsals(db, { billing: simulationBilling, platformModelKey: env.OPENROUTER_API_KEY, mapper: dependencyMapper, github: githubApp, decrypt,
  sandbox: createRehearsalSandbox(env.PURPLE_AGENT_URL, env.PURPLE_AGENT_SHARED_KEY) });
const scanBillingSettings = scanBillingConfig(env);
const scanMetering = createScanMetering(db, scanBillingSettings);
const welcomeCredit = createWelcomeCredit(db);
const scanBilling = createScanWhopBilling(db, { meter: scanMetering, apiKey: env.WHOP_API_KEY,
  assessmentTools: configuredAssessmentTools(env),
  webhookSecret: env.SCAN_WHOP_WEBHOOK_SECRET, enabled: env.SCAN_BILLING_ENABLED === 'true',
  sandbox: env.WHOP_SANDBOX === 'true', publicUrl: productOrigin(base) });
const hostedScans = createHostedScans(db, { encrypt: encryptionKey ? encrypt : null, decrypt,
  onAuthenticatedPrincipal: ({ userId, workspaceId }) => welcomeCredit.grantForUser(userId, workspaceId),
  targetSigningKey: encryptionKey,
  assessmentTools: configuredAssessmentTools(env),
  sandbox: createScanSandbox(env.PURPLE_AGENT_URL, env.PURPLE_AGENT_SHARED_KEY), metering: scanMetering,
  artifacts: env.SCAN_ARTIFACTS });
const productBase = productOrigin(base);
const trustedOrigins = publicOrigins(base);
if (['localhost', '127.0.0.1'].includes(publicUrl.hostname)) {
  for (const name of ['localhost', '127.0.0.1']) trustedOrigins.add(`http://${name}:5173`);
}
const cliAuth = createCliAuth({ db, scans: hostedScans, baseUrl: productBase, allowedOrigins: trustedOrigins });
const toolGateway = createToolGateway({ scans: hostedScans, billing: scanBilling, accounts, dispatch: () => schedule(hostedScans.dispatch()), baseUrl: productBase });
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
    await agentRunner.pollRunning();
    await agentRunner.processOne();
    await rehearsals.dispatch();

  } catch (error) { console.error(`Pi dispatch failed: ${error.message}`); }
  finally { agentBusy = false; }
}
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
function dispatchSoon() { schedule(dispatchAgents()); }
function flushSoon() { if (clickhouse) schedule(flushClickHouse()); }

function searchRecentEvents(workspaceId, filters = {}) {
  const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 100);
  const clauses = ['session_id = ?'];
  const params = [workspaceId];
  if (filters.worker) { clauses.push("json_extract(payload, '$.sourceWorker') = ?"); params.push(filters.worker); }
  if (filters.requestId) { clauses.push("json_extract(payload, '$.requestId') = ?"); params.push(filters.requestId); }
  if (filters.from != null) { clauses.push('received_at >= ?'); params.push(filters.from); }
  if (filters.to != null) { clauses.push('received_at < ?'); params.push(filters.to); }
  const rows = db.prepare(`SELECT id, received_at AS receivedAt, payload FROM events
    WHERE ${clauses.join(' AND ')} ORDER BY received_at DESC, id DESC LIMIT ?`).all(...params, limit);
  return rows.map(row => ({ id: row.id, receivedAt: row.receivedAt, ...JSON.parse(row.payload) }));
}

app.disable('x-powered-by');
app.get('/health', (req, res) => {
  if (env.PURPLE_RELEASE) res.setHeader('X-Purple-Release', env.PURPLE_RELEASE);
  try {
    db.prepare('SELECT 1 AS ok').get();
    res.json({ status: 'ok', service: publicUrl.hostname, database: 'sqlite-do',
      scannerBilling: scanBillingSettings.enabled, assessmentTools: configuredAssessmentTools(env) });
  } catch {
    res.status(503).json({ status: 'error', service: publicUrl.hostname, database: 'error' });
  }
});
app.use((req, res, next) => {
  if (req.hostname === publicIngestHost && !(req.method === 'POST' && req.path === '/api/ingest')) return res.sendStatus(404);
  next();
});
app.use(toolCallMetrics.middleware());
registerScanApi(app, { scans: hostedScans, dispatch: () => schedule(hostedScans.dispatch()) });
registerCliAuthPublic(app, { auth: cliAuth });
registerOffensePlatform(app, { gateway: toolGateway, scans: hostedScans, billing: scanBilling, baseUrl: productBase });
const dependencyIntelligence = registerSkillApi(app, { db, production: true, traceEnabled: env.OFFENSE_TRACE_ENABLED !== 'false' });
registerOffenseApi(app, { intelligence: dependencyIntelligence, publicUrl: publicUrl.href, gateway: toolGateway, allowedOrigins: [...trustedOrigins], callMetrics: toolCallMetrics });
app.use('/api/ingest', express.json({ limit: '256kb' }));
registerBillingWebhook(app, simulationBilling, express);
registerScanBillingWebhook(app, scanBilling, express, () => schedule(scanBilling.dispatch()));
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
  if (env.PURPLE_RELEASE) res.setHeader('X-Purple-Release', env.PURPLE_RELEASE);
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

registerDiscoveryDashboard(app, { dashboard: discoveryDashboard, operatorIds: env.OPERATIONS_GITHUB_IDS });
registerUsageMetrics(app, { db, operatorIds: env.OPERATIONS_GITHUB_IDS });
registerScanActivity(app, { db });
registerToolCallMetrics(app, { store: toolCallMetrics, operatorIds: env.OPERATIONS_GITHUB_IDS });

const config = {
  dependencySync: true,
  cloudflare: Boolean(env.CLOUDFLARE_CLIENT_ID && env.CLOUDFLARE_CLIENT_SECRET),
  github: Boolean(env.GITHUB_APP_SLUG && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
  encryption: Boolean(encryptionKey),
  collector: /^https:\/\//.test(env.PURPLE_INGEST_URL || ''),
  clickhouse: Boolean(clickhouse),
  agent: Boolean(githubApp && agentSandbox)
};
const cloudflareAuth = createCloudflareAuth({ clientId: env.CLOUDFLARE_CLIENT_ID, clientSecret: env.CLOUDFLARE_CLIENT_SECRET, encrypt, decrypt });
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
function publicState(s, user = null, workspaceId = null) {
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
function redirectError(res, message) { res.redirect(`/?error=${encodeURIComponent(message)}`); }
function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function stateFor(req) {
  return { ...publicState(req.session, req.authUser, req.workspaceId),
    contact: req.authUser ? contactEmails.get(req.authUser.id) : null,
    config: { ...config, operations: isMetricsOperator(req.authUser, env.OPERATIONS_GITHUB_IDS) },
    githubInstallations: req.browserSession.githubInstallations?.userId === req.authUser?.id &&
      req.browserSession.githubInstallations?.workspaceId === req.workspaceId &&
      Date.now() - req.browserSession.githubInstallations.created < 10 * 60_000
      ? req.browserSession.githubInstallations.options : [] };
}
registerContactEmailRoutes(app, contactEmails);
const issueTrackers = createIssueTrackers(db, { env: env, encrypt: encryptionKey ? encrypt : null, decrypt });
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
  url.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state }).toString();
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
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code: String(req.query.code), redirect_uri: `${loginOrigin}/api/github/callback` })
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
      matching = purpleInstallations(installations, env.GITHUB_APP_SLUG);
      const candidates = (installations.installations || [])
        .filter(installation => installation.app_slug === env.GITHUB_APP_SLUG &&
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
  url.search = new URLSearchParams({ response_type: 'code', client_id: env.CLOUDFLARE_CLIENT_ID, redirect_uri: `${base}/api/cloudflare/callback`, scope: [...new Set(((env.CLOUDFLARE_SCOPES || 'account-settings.read') + ' offline_access').split(/\s+/))].join(' '), state }).toString();
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
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${env.CLOUDFLARE_CLIENT_ID}:${env.CLOUDFLARE_CLIENT_SECRET}`).toString('base64')}` },
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
  const ingestUrl = env.PURPLE_INGEST_URL || '';
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
    await updateForwarder(token, install, env.PURPLE_INGEST_URL, decrypt(install.ingestToken));
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
    if (clickhouse) flushSoon();
    if (receipt.accepted) dispatchSoon();
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
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
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
    available.push(...purpleInstallations(data, env.GITHUB_APP_SLUG));
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
  rehearsals, dispatchRehearsals: () => schedule(rehearsals.dispatch()) });
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
    dispatchSoon();
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
  dispatchSoon();
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
    const filters = { worker, requestId, from, to, limit: req.query.limit };
    let events;
    try { events = clickhouse ? await clickhouse.search(req.workspaceId, filters) : searchRecentEvents(req.workspaceId, filters); }
    catch { events = searchRecentEvents(req.workspaceId, filters); }
    res.json({ events });
  } catch {
    res.status(503).json({ error: 'Event search is temporarily unavailable.' });
  }
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
  url.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state }).toString();
  res.redirect(url.href);
});
function startGitHubInstall(req, res) {
  delete req.browserSession.githubSyncInstallations;
  const state = randomBytes(24).toString('base64url');
  req.browserSession.githubInstallState = state;
  req.browserSession.githubInstallStarted = Date.now();
  req.saveBrowser();
  res.redirect(`https://github.com/apps/${encodeURIComponent(env.GITHUB_APP_SLUG)}/installations/new?state=${encodeURIComponent(state)}`);
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
  url.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback`, state: oauthState }).toString();
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
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code: String(req.query.code), redirect_uri: `${requestPublicOrigin(req, base)}/api/github/callback` })
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
    const options = purpleInstallations(data, env.GITHUB_APP_SLUG);
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
return { app, hostedScans, toolCallMetrics, flushClickHouse, dispatchAgents, pruneTraces: () => dependencyIntelligence.pruneTraces() };
}
