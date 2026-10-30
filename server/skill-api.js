import express from 'express';
import { createDependencyIntelligence } from './dependency-intelligence.js';
import { beginOffenseRequest, offenseRequestTrace } from './offense-traces.js';
import { classifyTraceError } from '../shared/offense-trace.js';
import { OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';
import { measureSkillAnalysis } from './skill-usage-request.js';

// Legacy Purple clients retain their wire format while sharing all work limits
// with the capability API and MCP transport.
export function registerSkillApi(app, options = {}) {
  const intelligence = options.intelligence || createDependencyIntelligence(options);
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); res.set('X-Content-Type-Options', 'nosniff');
    const trace = beginOffenseRequest(req, res, { store: intelligence.traces, transport: 'https' });
    res.set('X-Offense-Version', OFFENSE_SERVICE_VERSION);
    if (req.method !== 'POST' || !['/scan', '/plan'].includes(req.path)) { trace.reject('not_found'); return res.status(404).json({ error: 'Unknown skill endpoint.' }); }
    if (req.get('origin')) { trace.reject('invalid_origin'); return res.status(403).json({ error: 'Use the Purple skill from your coding agent.' }); }
    const denied = intelligence.admit(req);
    if (denied) { trace.reject(denied.status === 429 ? 'quota_exceeded' : 'busy'); res.set('Retry-After', String(denied.retryAfter)); return res.status(denied.status).json({ error: denied.error }); }
    next();
  });
  router.use(express.json({ limit: '2mb', strict: true }));
  router.post(['/scan', '/plan'], async (req, res) => {
    try { res.json(await measureSkillAnalysis(intelligence.usage, { channel: 'legacy', operation: req.path === '/plan' ? 'planning' : 'audit' },
      () => intelligence.legacy(req.body, req.path.slice(1), req))); }
    catch (error) {
      offenseRequestTrace(req)?.outcome(error.status >= 400 && error.status < 500 ? 'rejected' : 'failed', classifyTraceError(error));
      res.status(error.status || 502).json({ error: error.message });
    }
  });
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    offenseRequestTrace(req)?.reject('invalid_request');
    res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: error.type === 'entity.too.large' ? 'Dependency metadata exceeds 2 MB.' : 'Invalid JSON dependency metadata.' });
  });
  app.use('/api/skill', router);
  return intelligence;
}
