import express from 'express';
import { hostedScanTools } from './hosted-scans.js';

const failure = (message, status = 400, code = 'invalid_request') => Object.assign(new Error(message), { status, code });
const empty = { type: 'object', properties: {}, additionalProperties: false };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const toolId = { type: 'string', maxLength: 80, pattern: '^[a-z0-9-]+$' };
const dimensionProperties = { tool: toolId, inputBytes: { type: 'integer', minimum: 0, maximum: 100_000_000 }, fileCount: { type: 'integer', minimum: 1, maximum: 400 } };
export const SECURITY_MCP_TOOLS = [
  { name: 'offense.security_tools', title: 'Offense security tool catalog', description: 'List available security tools, coverage and per-tool USD prices for this API key. Does not run a scan.', inputSchema: empty, annotations: { readOnlyHint: true } },
  { name: 'offense.security_quote', title: 'Quote a security tool call', description: 'Get the maximum USD-micro cost before submitting a security tool job. A quote does not charge the account.', inputSchema: { type: 'object', additionalProperties: false, required: ['tool', 'inputBytes', 'fileCount'], properties: dimensionProperties }, annotations: { readOnlyHint: true } },
  { name: 'offense.security_call', title: 'Run an Offense security tool', description: 'Submit one authorized security tool job using prepaid credit. Requires a previously reviewed maximum charge and an idempotency key. Input must follow the selected tool catalog contract; artifacts and target assessments retain their upload/ownership requirements. This may consume prepaid credit.', inputSchema: { type: 'object', additionalProperties: false, required: ['tool', 'input', 'maxChargeMicros', 'idempotencyKey'], properties: { tool: toolId, input: { type: 'object' }, maxChargeMicros: { type: 'integer', minimum: 0, maximum: 1_000_000_000 }, idempotencyKey: { type: 'string', minLength: 8, maxLength: 128 } } }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } },
  { name: 'offense.security_result', title: 'Read an Offense security result', description: 'Read the status, findings and settled charge for a job created in this API key account.', inputSchema: { type: 'object', additionalProperties: false, required: ['id'], properties: { id: { type: 'string', pattern: '^[a-f0-9]{32}$' } } }, annotations: { readOnlyHint: true } },
  { name: 'offense.account', title: 'Offense account and balance', description: 'Read the current API key account and prepaid security-tool balance. Does not reveal API keys or provider credentials.', inputSchema: empty, annotations: { readOnlyHint: true } },
  { name: 'offense.topup', title: 'Create an Offense balance top-up link', description: 'Create or reuse a Whop checkout URL for the advertised one-time credit purchase. The user completes and approves payment on Whop; creating a link does not charge a card or grant credit.', inputSchema: empty, annotations: { readOnlyHint: false, destructiveHint: false } },
];

export function createToolGateway({ scans, billing, accounts, dispatch = () => {}, baseUrl }) {
  function principal(token) {
    const value = scans.authenticate(token);
    if (!value) throw failure('Sign in with the Offense CLI or supply a valid Offense API key.', 401, 'invalid_api_key');
    return value;
  }
  function account(token) {
    const value = principal(token), user = accounts.findUser(value.user_id);
    if (!user) throw failure('This API key account is unavailable.', 401, 'invalid_api_key');
    const workspace = accounts.workspaceForUser(user.id, value.workspace_id);
    if (!workspace || workspace.id !== value.workspace_id) throw failure('This API key no longer has account access.', 401, 'invalid_api_key');
    return { user: { login: user.login }, workspace: { id: workspace.id, name: JSON.parse(workspace.data).company || user.login },
      key: { id: value.id, createdAt: value.createdAt }, billing: billing.status(workspace.id),
      links: { account: `${baseUrl}/account`, tools: `${baseUrl}/v1/catalog`, topup: `${baseUrl}/account#billing` } };
  }
  function requireTool(id, value) {
    const tool = scans.tools(value.workspace_id).tools.find(tool => tool.id === id);
    if (!tool) throw failure('Unknown security tool. List the Offense catalog first.', 404, 'unknown_tool');
    if (tool.availability !== 'available') throw failure('This tool is not enabled on this deployment.', 503, 'tool_unavailable');
  }
  function errorDetails(error, token) {
    if (error.status !== 402) return {};
    const value = scans.authenticate(token);
    return { topupUrl: `${baseUrl}/account#billing`, ...(value ? { billing: billing.status(value.workspace_id) } : {}) };
  }
  async function execute(name, args, token) {
    const value = principal(token);
    if (name === 'offense.security_tools') return scans.tools(value.workspace_id);
    if (name === 'offense.account') return account(token);
    if (name === 'offense.topup') return billing.checkout(value.workspace_id, value.user_id);
    if (name === 'offense.security_quote') {
      requireTool(args.tool, value);
      return scans.quote({ tools: [args.tool], inputBytes: args.inputBytes, fileCount: args.fileCount }, value.workspace_id);
    }
    if (name === 'offense.security_result') {
      const result = scans.get(args.id, value.workspace_id);
      if (!result) throw failure('Tool call not found.', 404, 'not_found');
      dispatch(); return result;
    }
    if (name === 'offense.security_call') {
      requireTool(args.tool, value);
      if (!object(args.input) || ['tools', 'maxChargeMicros', 'idempotencyKey', 'workspaceId'].some(key => key in args.input)) throw failure('Supply tool input separately from billing and account fields.');
      if (!Number.isSafeInteger(args.maxChargeMicros) || args.maxChargeMicros < 0) throw failure('Review a maximum-price quote before calling a paid tool.');
      const job = scans.create(value, { ...args.input, tools: [args.tool], maxChargeMicros: args.maxChargeMicros }, args.idempotencyKey);
      dispatch(); return job;
    }
    throw failure('Unknown Offense capability.', 404, 'unknown_tool');
  }
  return { authenticate: token => { try { return principal(token); } catch (error) { if (error.status === 401) return null; throw error; } }, account, execute, errorDetails };
}

export function registerOffensePlatform(app, { gateway, scans, billing, baseUrl }) {
  const token = req => req.get('authorization')?.replace(/^Bearer /, '');
  const protect = (req, res, next) => {
    res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff');
    if (req.get('origin')) return res.status(403).json({ error: { code: 'invalid_origin', message: 'Use the Offense API from your CLI or coding agent.' } });
    try {
      if (!gateway.authenticate(token(req))) return res.status(401).json({ error: { code: 'invalid_api_key', message: 'A valid Offense API key is required.' } });
    } catch {
      return res.status(503).json({ error: { code: 'account_unavailable', message: 'Offense account information is temporarily unavailable.' } });
    }
    next();
  };
  app.get('/v1/catalog', (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const catalog = scans.tools('__public_tool_catalog__');
      res.json({ schemaVersion: 1, company: 'Offense Security', product: 'Offense', currency: 'usd',
        authentication: 'One Offense API key for hosted security tools; basic dependency advisory checks are free.',
        tools: [{ id: 'dependency-audit', name: 'Dependency advisory intelligence', availability: 'available', priceMicros: 0,
          inputType: 'sanitized-lockfiles', endpoint: '/api/offense/audit', mcpTool: 'offense.audit_dependencies' }, ...catalog.tools],
        billing: catalog.billing, accountUrl: `${baseUrl}/account` });
    } catch { res.status(503).json({ error: { code: 'catalog_unavailable', message: 'The security tool catalog is temporarily unavailable.' } }); }
  });
  app.get('/v1/account', protect, (req, res) => {
    try { res.json(gateway.account(token(req))); }
    catch (error) { res.status(error.status || 503).json({ error: { code: error.code || 'account_unavailable', message: error.status ? error.message : 'Offense account information is temporarily unavailable.' } }); }
  });
  app.post('/v1/billing/topups', protect, express.json({ limit: '1kb', strict: true }), async (req, res) => {
    if (!object(req.body) || Object.keys(req.body).length) return res.status(400).json({ error: { code: 'invalid_request', message: 'Top-up amount and account are fixed by the server. Send an empty object.' } });
    try { res.json(await gateway.execute('offense.topup', {}, token(req))); }
    catch (error) { res.status(error.status || 503).json({ error: { code: error.code || 'checkout_unavailable', message: error.status ? error.message : 'Whop checkout is temporarily unavailable.' } }); }
  });
  app.post('/v1/call/:tool', protect, express.json({ limit: '6mb', strict: true }), async (req, res) => {
    try {
      if (!object(req.body)) throw failure('Provide a tool input object.');
      const { maxChargeMicros, ...input } = req.body;
      const result = await gateway.execute('offense.security_call', { tool: req.params.tool, input, maxChargeMicros, idempotencyKey: req.get('idempotency-key') }, token(req));
      res.set('Location', `/v1/scans/${result.id}`).set('Retry-After', '5').status(202).json(result);
    } catch (error) { res.status(error.status || 503).json({ error: { code: error.code || (error.status === 402 ? 'insufficient_balance' : 'call_failed'), message: error.status ? error.message : 'Offense security tool request could not complete.' }, ...gateway.errorDetails(error, token(req)) }); }
  });
  app.use((error, req, res, next) => {
    if (req.path !== '/v1/billing/topups' && !req.path.startsWith('/v1/call/')) return next(error);
    res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: { code: 'invalid_request', message: 'Invalid or oversized Offense request.' } });
  });
}
