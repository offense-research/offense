import { isMetricsOperator } from './discovery-dashboard.js';
import { skillUsageMetrics } from './skill-usage.js';

export function registerSkillUsageMetrics(app, { db, operatorIds }) {
  app.get('/api/operator/skill-usage', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Cookie');
    if (!req.authUser) return res.status(401).json({ error: 'Sign in to view company metrics.' });
    if (!isMetricsOperator(req.authUser, operatorIds)) return res.status(403).json({ error: 'Company metrics are restricted to Purple operators.' });
    if (Object.keys(req.query).some(key => key !== 'days') || req.query.days !== undefined &&
        (typeof req.query.days !== 'string' || !/^(7|30|90)$/.test(req.query.days))) {
      return res.status(400).json({ error: 'Choose only a days parameter of 7, 30 or 90.' });
    }
    try { res.json(skillUsageMetrics(db, { days: req.query.days === undefined ? 30 : Number(req.query.days) })); }
    catch { res.status(503).json({ error: 'Skill usage metrics are temporarily unavailable.' }); }
  });
}
