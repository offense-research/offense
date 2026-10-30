import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { CfWorkerJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/cfworker';
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from '@modelcontextprotocol/sdk/types.js';
import { auditInputSchema, auditOutputSchema, OFFENSE_SERVICE_TITLE, OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';
import { beginOffenseRequest, offenseRequestTrace } from './offense-traces.js';
import { classifyTraceError } from '../shared/offense-trace.js';
import { measureSkillAnalysis, skillOperation } from './skill-usage-request.js';
import { SECURITY_MCP_TOOLS } from './offense-platform.js';
import { markToolCallOutcome } from './tool-call-metrics.js';

export const OFFENSE_MCP_TOOL = 'offense.audit_dependencies';
const loopbacks = new Set(['127.0.0.1', 'localhost', '[::1]']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const validId = value => typeof value === 'string' || Number.isSafeInteger(value);

function rpcError(res, status, code, message, id) {
  return res.status(status).json({ jsonrpc: '2.0', ...(validId(id) ? { id } : {}), error: { code, message } });
}

function approvedHost(req, publicUrl, origins) {
  try {
    const supplied = req.get('host');
    const host = new URL(`${publicUrl.protocol}//${supplied}/`);
    if (!supplied || host.username || host.password || host.host !== supplied.toLowerCase()) return false;
    return loopbacks.has(publicUrl.hostname) ? loopbacks.has(host.hostname) : origins.some(origin => new URL(origin).host === host.host);
  } catch { return false; }
}

// MCP 2025-11-25 Streamable HTTP, JSON responses only. Each request gets a
// fresh stateless SDK server/transport: there is no user or MCP session store.
// https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
export function registerOffenseMcp(app, { audit, admit = () => null, traces, usage, gateway, allowedOrigins, callMetrics, publicUrl = 'http://localhost:3217' } = {}) {
  if (typeof audit !== 'function') throw new Error('Offense MCP requires an audit capability.');
  const publicLocation = new URL(publicUrl);
  if (!['http:', 'https:'].includes(publicLocation.protocol) || publicLocation.username || publicLocation.password ||
      (publicLocation.protocol === 'http:' && !loopbacks.has(publicLocation.hostname))) throw new Error('Offense MCP requires HTTPS or an explicit loopback URL.');
  const schemaValidator = new CfWorkerJsonSchemaValidator();
  const validateArguments = schemaValidator.getValidator(auditInputSchema);
  const validateReport = schemaValidator.getValidator(auditOutputSchema);
  const origins = [publicLocation.origin, ...(allowedOrigins || [])].filter(origin => {
    try { const value = new URL(origin); return value.origin === origin && value.protocol === 'https:'; } catch { return false; }
  });
  const securityValidators = new Map(SECURITY_MCP_TOOLS.map(tool => [tool.name, schemaValidator.getValidator(tool.inputSchema)]));
  const router = express.Router();
  router.use((req, res, next) => {
    const trace = beginOffenseRequest(req, res, { store: traces, transport: 'mcp' });
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'X-Offense-Version': OFFENSE_SERVICE_VERSION });
    if (!approvedHost(req, publicLocation, origins)) { trace.reject('invalid_host'); return rpcError(res, 403, -32000, 'This host does not serve Offense MCP.'); }
    if (req.get('origin') && req.get('origin') !== publicLocation.origin && !origins.includes(req.get('origin'))) { trace.reject('invalid_origin'); return rpcError(res, 403, -32000, 'Origin is not allowed.'); }
    if (req.path !== '/') { trace.reject('not_found'); return rpcError(res, 404, -32601, 'Unknown MCP endpoint.'); }
    // This deployment does not offer server-pushed SSE or session deletion.
    if (req.method !== 'POST') { trace.reject('unsupported_method'); res.set('Allow', 'POST'); return rpcError(res, 405, -32000, 'Use POST for this stateless MCP endpoint.'); }
    if (!req.is('application/json')) { trace.reject('unsupported_media_type'); return rpcError(res, 415, -32000, 'Content-Type must be application/json.'); }
    next();
  });
  router.use(express.json({ limit: '2mb', strict: true }));
  router.post('/', async (req, res) => {
    const message = req.body;
    const trace = offenseRequestTrace(req);
    // The current transport requires a single message, even though the SDK
    // retains optional batching support for older protocol versions.
    if (!object(message) || message.jsonrpc !== '2.0' || ('id' in message && !validId(message.id))) {
      trace?.reject('invalid_request');
      return rpcError(res, 400, -32600, 'Send one valid JSON-RPC 2.0 message.');
    }
    if ('method' in message && (typeof message.method !== 'string' || !message.method || ('params' in message && !object(message.params)))) {
      trace?.reject('invalid_request');
      return rpcError(res, 400, -32600, 'Invalid JSON-RPC method or parameters.', message.id);
    }
    // Count a protocol tool attempt before admission and argument validation,
    // independently of whether it creates a new job. Metadata/polling tools
    // remain transport requests, already measured by the HTTP middleware.
    const operation = message.method === 'tools/call' && 'id' in message
      ? message.params?.name === OFFENSE_MCP_TOOL ? skillOperation(message.params.arguments)
        : message.params?.name === 'offense.security_call' ? 'hosted_scan' : null
      : null;
    let attempt, finished = false;
    if (operation) {
      try { attempt = callMetrics?.start({ kind: 'tool', channel: 'mcp', operation }); } catch { /* Counting cannot interrupt a tool call. */ }
    }
    const finishCall = status => {
      if (finished) return;
      finished = true;
      try { attempt?.finish({ status }); } catch { /* No caller data is logged. */ }
      markToolCallOutcome(req, status);
    };
    res.once('finish', () => finishCall(res.statusCode >= 500 ? 'failed' : res.statusCode >= 400 ? 'rejected' : 'completed'));
    res.once('close', () => { if (!res.writableFinished) finishCall('failed'); });
    // Only real tool requests consume the same admission budget as the HTTP API.
    if (message.method === 'tools/call' && 'id' in message && message.params?.name === OFFENSE_MCP_TOOL) {
      let denied;
      try { denied = await admit(req); }
      catch (error) { finishCall('failed'); throw error; }
      if (denied) {
        finishCall(denied.status >= 400 && denied.status < 500 ? 'rejected' : 'failed');
        trace?.reject(denied.status === 429 ? 'quota_exceeded' : 'busy');
        if (denied.retryAfter) res.set('Retry-After', String(denied.retryAfter));
        return rpcError(res, denied.status, -32000, denied.error || 'Offense is temporarily unavailable.', message.id);
      }
    }
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true, maxRequestBodySize: 2 * 1024 * 1024 });
    const server = new Server({ name: 'offense', title: OFFENSE_SERVICE_TITLE, version: OFFENSE_SERVICE_VERSION }, {
      capabilities: { tools: {} }, jsonSchemaValidator: schemaValidator,
      instructions: 'Offense by Offense Security provides free dependency advisory intelligence and prepaid security tools. Use one Offense API key for hosted tools. Inspect the catalog and maximum-price quote before submitting a paid call; a Whop top-up link needs human payment approval. Never expose provider credentials or API keys. Advisory matches and scanner signals require review and are not confirmed vulnerabilities. Planning pages alone are not full dependency scans.'
    });
    server.setRequestHandler(ListToolsRequestSchema, async request => {
      if (request.params?.cursor) { trace?.reject('invalid_request'); throw new McpError(ErrorCode.InvalidParams, 'This tool list has no pagination cursor.'); }
      return { tools: [{ name: OFFENSE_MCP_TOOL, title: 'Offense dependency audit',
        description: 'Use Purple to audit sanitized npm/pnpm dependency metadata for known advisory matches and checked upgrade paths. Resume deferred targets with remediation.planning.next while retaining the full scan and coordinating plans across pages. Does not read source, run tests, edit files, confirm exploitability or use a model key.',
        inputSchema: auditInputSchema, outputSchema: auditOutputSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } },
        ...(gateway?.authenticate(req.get('authorization')?.replace(/^Bearer /, '')) ? SECURITY_MCP_TOOLS : [])] };
    });
    server.setRequestHandler(CallToolRequestSchema, async request => {
      if (gateway && securityValidators.has(request.params.name)) {
        if (request.params.task) throw new McpError(ErrorCode.InvalidParams, 'Background MCP tasks are not supported.');
        const token = req.get('authorization')?.replace(/^Bearer /, '');
        try {
          if (!securityValidators.get(request.params.name)(request.params.arguments || {}).valid) throw Object.assign(new Error('Follow the advertised security tool input schema.'), { status: 400, code: 'invalid_input' });
          const result = await gateway.execute(request.params.name, request.params.arguments || {}, token);
          finishCall('completed');
          return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false };
        } catch (error) {
          finishCall(error.status >= 400 && error.status < 500 ? 'rejected' : 'failed');
          const safe = Number.isInteger(error.status) && error.status >= 400 && error.status < 600;
          const result = { status: 'error', error: { code: safe ? error.code || (error.status === 402 ? 'insufficient_balance' : 'security_call_failed') : 'security_call_failed', message: safe ? error.message : 'Offense security tool request could not complete.' }, ...gateway.errorDetails(error, token) };
          return { content: [{ type: 'text', text: JSON.stringify(result) }], isError: true };
        }
      }
      if (request.params.name !== OFFENSE_MCP_TOOL) { trace?.reject('invalid_request'); throw new McpError(ErrorCode.InvalidParams, 'Unknown Offense tool.'); }
      if (request.params.task) { trace?.reject('invalid_request'); throw new McpError(ErrorCode.InvalidParams, 'Background MCP tasks are not supported.'); }
      try {
        const report = await measureSkillAnalysis(usage, { channel: 'mcp', operation: skillOperation(request.params.arguments) }, async () => {
          const validated = validateArguments(request.params.arguments);
          if (!validated.valid) throw Object.assign(new Error('Invalid dependency metadata arguments. Follow the advertised tool schema.'), { status: 400, code: 'invalid_input' });
          const result = await audit(request.params.arguments, req);
          if (!validateReport(result).valid) throw Object.assign(new Error('Dependency analysis returned an incomplete result. No clean result was established.'), { code: 'response_invalid' });
          return result;
        });
        trace?.outcome(report.status === 'partial' ? 'partial' : 'completed');
        finishCall('completed');
        return { content: [{ type: 'text', text: JSON.stringify(report) }], structuredContent: report, isError: false };
      } catch (error) {
        finishCall(error.status >= 400 && error.status < 500 ? 'rejected' : 'failed');
        trace?.outcome(error.status >= 400 && error.status < 500 ? 'rejected' : 'failed', classifyTraceError(error));
        const failure = { status: 'error', error: { code: typeof error.code === 'string' ? error.code : error.status === 400 ? 'invalid_input' : 'analysis_incomplete',
          message: error.message || 'Dependency analysis did not complete. No clean result was established.' } };
        // The advertised output schema describes successful audit reports.
        // SDK clients validate any structuredContent against that schema even
        // for isError results, so errors belong in text content only.
        return { content: [{ type: 'text', text: JSON.stringify(failure) }], isError: true };
      }
    });
    try {
      await server.connect(transport);
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      const request = new Request(`${publicLocation.origin}/mcp`, { method: 'POST', headers });
      const response = await transport.handleRequest(request, { parsedBody: message });
      for (const [name, value] of response.headers) res.set(name, value);
      const text = await response.text();
      try {
        if (JSON.parse(text)?.error) { trace?.reject('invalid_request'); finishCall('rejected'); }
      } catch {}
      finishCall(response.status >= 500 ? 'failed' : response.status >= 400 ? 'rejected' : 'completed');
      res.status(response.status).send(text);
    } catch {
      finishCall('failed');
      trace?.outcome('failed', 'analysis_incomplete');
      if (!res.headersSent) rpcError(res, 500, -32603, 'MCP request could not complete.', message.id);
    } finally { await server.close(); }
  });
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    offenseRequestTrace(req)?.reject('invalid_request');
    const large = error.type === 'entity.too.large';
    rpcError(res, large ? 413 : 400, large ? -32000 : -32700, large ? 'Dependency metadata exceeds 2 MB.' : 'Invalid JSON.');
  });
  app.use('/mcp', router);
}
