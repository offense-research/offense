import express from 'express';
import { auditInputSchema, auditOutputSchema, AUDIT_SCHEMA_VERSION, OFFENSE_SERVICE_TITLE, OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';
import { registerOffenseMcp } from './offense-mcp.js';
import { beginOffenseRequest, offenseRequestTrace } from './offense-traces.js';
import { classifyTraceError } from '../shared/offense-trace.js';
import { AUTOMATION_POLICY_SCHEMA, SECURITY_EVENTS, defaultAutomationPolicy } from '../shared/offense-policy.js';
import { measureSkillAnalysis, skillOperation } from './skill-usage-request.js';

export function registerOffenseApi(app, { intelligence, publicUrl, gateway, allowedOrigins, callMetrics } = {}) {
  if (!intelligence) throw new Error('A shared dependency intelligence controller is required.');
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff');
    const trace = beginOffenseRequest(req, res, { store: intelligence.traces, transport: 'https' });
    res.set('X-Offense-Version', OFFENSE_SERVICE_VERSION);
    if (req.get('origin')) { trace.reject('invalid_origin'); return res.status(403).json({ error: { code: 'invalid_origin', message: 'Use Offense from your server or agent integration.' } }); }
    next();
  });
  router.get('/capabilities', (req, res) => res.json({ schemaVersion: AUDIT_SCHEMA_VERSION,
    service: { name: 'offense', title: OFFENSE_SERVICE_TITLE, version: OFFENSE_SERVICE_VERSION },
    integrations: { sdk: '/downloads/offense-sdk.tgz', cli: '/downloads/offense-automation.mjs',
      automation: { schemaVersion: AUTOMATION_POLICY_SCHEMA, events: SECURITY_EVENTS, defaults: defaultAutomationPolicy(),
        repositoryScheduling: 'Connected workspace repositories use dashboard automation settings.',
        lifecycle: 'Your pipeline or agent host must invoke deployment and agent-run checks. Adding MCP makes a tool available; it does not enforce its use.' } },
    capabilities: [{
    name: 'audit_dependencies', mcpTool: 'offense.audit_dependencies', endpoint: '/api/offense/audit', inputSchema: auditInputSchema, outputSchema: auditOutputSchema,
    coverage: ['npm lockfile v2/v3', 'pnpm lockfile v6/v9'], authentication: 'none', mutatesRepository: false, runsModel: false,
    scanning: { protocol: 'offense.scanning.v1', continuation: 'scanning.next', persistentServerState: false,
      merge: 'Retain the full lockfiles and every contiguous scan page. Only the merged chain establishes full coverage; plan upgrades afterward.' },
    planning: { protocol: 'offense.planning.v1', continuation: 'remediation.planning.next', maxTargetsPerResponse: 10,
      fullScanRequiredForCompleteCoverage: true, persistentServerState: false, continuationRechecksOnlySelectedTargets: true,
      merge: 'Retain original full coverage and findings, merge planning pages, and check shared-parent/root conflicts across every page.' }
  }] }));
  router.post('/audit', (req, res, next) => {
    const denied = intelligence.admit(req);
    if (!denied) return next();
    offenseRequestTrace(req)?.reject(denied.status === 429 ? 'quota_exceeded' : 'busy');
    res.set('Retry-After', String(denied.retryAfter));
    res.status(denied.status).json({ error: { code: denied.status === 429 ? 'quota_exceeded' : 'busy', message: denied.error } });
  }, express.json({ limit: '2mb', strict: true }), async (req, res) => {
    try {
      const report = await measureSkillAnalysis(intelligence.usage, { channel: 'https', operation: skillOperation(req.body) },
        () => intelligence.audit(req.body, req));
      offenseRequestTrace(req)?.outcome(report.status === 'partial' ? 'partial' : 'completed');
      res.json(report);
    }
    catch (error) {
      offenseRequestTrace(req)?.outcome(error.status >= 400 && error.status < 500 ? 'rejected' : 'failed', classifyTraceError(error));
      res.status(error.status || 502).json({ error: { code: error.code || 'analysis_incomplete', message: error.message } });
    }
  });
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    offenseRequestTrace(req)?.reject('invalid_request');
    res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: { code: 'invalid_request', message: error.type === 'entity.too.large' ? 'Dependency metadata exceeds 2 MB.' : 'Invalid JSON dependency metadata.' } });
  });
  router.use((req, res) => { offenseRequestTrace(req)?.reject('not_found'); return res.status(404).json({ error: { code: 'not_found', message: 'Unknown Offense capability.' } }); });
  app.use('/api/offense', router);
  registerOffenseMcp(app, { audit: intelligence.audit, admit: intelligence.admit, traces: intelligence.traces, usage: intelligence.usage, publicUrl, gateway, allowedOrigins, callMetrics });
}
