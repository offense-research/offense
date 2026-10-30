import { ASSESSMENT_TOOLS } from '../shared/assessment-tools.js';

// Existing deployments keep their original tool set until each new execution
// image and its egress path has been verified and explicitly enabled.
export function configuredAssessmentTools(env = {}) {
  let selected;
  try { selected = JSON.parse(env.SCAN_ASSESSMENT_TOOLS_JSON || '[]'); }
  catch { throw new Error('SCAN_ASSESSMENT_TOOLS_JSON must be a JSON array of tool IDs.'); }
  const supported = new Set(ASSESSMENT_TOOLS.map(tool => tool.id));
  if (!Array.isArray(selected) || selected.length > supported.size || new Set(selected).size !== selected.length ||
      selected.some(id => !supported.has(id))) throw new Error('Select distinct supported assessment tool IDs.');
  return [...selected];
}
