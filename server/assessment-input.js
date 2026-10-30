import { sourceFiles } from './scan-input.js';
import { webScanOrigin, publicWebScanAddress } from './web-scan-target.js';
import { assessmentTool, TARGET_ASSESSMENTS } from '../shared/assessment-tools.js';

const fail = message => Object.assign(new Error(message), { status: 400 });
export const ASSESSMENT_MANIFEST = 'purple-assessment.json';

// Repeated at the execution boundary: callers cannot choose commands, templates,
// provider URLs, request budgets, resolved IPs or runtime environment variables.
export function assessmentInput(toolId, input, { verifiedTarget, artifact } = {}) {
  const tool = assessmentTool(toolId);
  if (!tool) throw fail('Unknown assessment tool.');
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('Invalid assessment input.');
  const options = { budgetSeconds: tool.budgetSeconds, maxRequests: tool.maxRequests, maxConnections: tool.maxConnections };
  let files = [], credentials = {};
  if (TARGET_ASSESSMENTS.has(toolId)) {
    options.target = webScanOrigin(input.target);
    if (!verifiedTarget || verifiedTarget.origin !== options.target || !Array.isArray(verifiedTarget.addresses) ||
        !verifiedTarget.addresses.length || verifiedTarget.addresses.some(ip => !publicWebScanAddress(ip)))
      throw fail('Verify ownership through /v1/targets before scanning this target.');
    options.resolvedAddresses = [...verifiedTarget.addresses];
    if (tool.inputType === 'verified-api') {
      files = sourceFiles(input.files).files;
      if (files.length !== 1 || !files[0].path.endsWith('.json')) throw fail('API assessments require one OpenAPI JSON document.');
      let schema;
      try { schema = JSON.parse(files[0].content); } catch { throw fail('Supply valid OpenAPI JSON.'); }
      if (!/^3\.[01]\./.test(schema?.openapi || '') || !schema.paths || typeof schema.paths !== 'object')
        throw fail('Supply an OpenAPI 3.0 or 3.1 document.');
      let operations = 0;
      let nodes = 0;
      const walk = (value, depth = 0) => {
        if (++nodes > 12000 || depth > 40) throw fail('API schema exceeds its bounds.');
        if (!value || typeof value !== 'object') return;
        for (const [key, child] of Object.entries(value)) {
          if (key === '$ref' && (typeof child !== 'string' || !child.startsWith('#/')) || ['$id', '$dynamicRef', '$recursiveRef', 'callbacks', 'webhooks', 'externalValue', 'externalDocs'].includes(key))
            throw fail('Remote references, callbacks, webhooks and external examples are not supported.');
          walk(child, depth + 1);
        }
      };
      walk(schema);
      for (const [route, item] of Object.entries(schema.paths)) {
        if (!route.startsWith('/') || route.startsWith('//') || route.includes('\\') || /[\r\n?#]/.test(route)) throw fail('Invalid API path.');
        for (const method of Object.keys(item || {})) if (/^(get|put|post|delete|patch|options|head|trace)$/.test(method)) operations++;
      }
      if (operations < 1 || operations > 25) throw fail('API assessments support between 1 and 25 operations.');
    } else if (input.files !== undefined) throw fail('This assessment takes a target, not source files.');
    if (['schemathesis', 'zap-api'].includes(toolId) && input.confirmActiveTesting !== true)
      throw fail('Set confirmActiveTesting to true for active testing of this staging target.');
  } else if (toolId === 'openssf-scorecard') {
    if (typeof input.repository !== 'string' || input.repository.length > 140 ||
        !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,38})\/[a-zA-Z0-9_.-]{1,100}$/.test(input.repository) ||
        ['.', '..'].includes(input.repository.split('/')[1]) || input.repository.endsWith('.git'))
      throw fail('Supply a public GitHub repository as owner/repository.');
    if (input.files !== undefined || input.target !== undefined || input.apiToken !== undefined || input.artifactId !== undefined)
      throw fail('Published Scorecard assessment accepts one public repository, without files, targets or credentials.');
    options.repository = input.repository;
  } else if (toolId === 'prowler-cloudflare') {
    if (typeof input.accountId !== 'string' || !/^[a-f0-9]{32}$/.test(input.accountId) ||
        typeof input.apiToken !== 'string' || !/^[A-Za-z0-9_-]{20,200}$/.test(input.apiToken))
      throw fail('Supply the Cloudflare account ID and a read-only API token.');
    options.accountId = input.accountId;
    credentials = { apiToken: input.apiToken };
    if (input.files !== undefined) throw fail('Cloud account assessments do not accept source files.');
  } else if (toolId === 'mobsf-static') {
    if (!artifact || artifact.kind !== 'mobile-app' || !['apk', 'ipa'].includes(input.format))
      throw fail('Mobile analysis requires an uploaded mobile-app artifact and format apk or ipa.');
    options.format = input.format;
  } else {
    files = sourceFiles(input.files).files;
    if (toolId === 'trufflehog-verified' && input.confirmLiveVerification !== true)
      throw fail('Set confirmLiveVerification to true to verify credentials found in these files.');
  }
  return { tool: toolId, files, options, credentials };
}
