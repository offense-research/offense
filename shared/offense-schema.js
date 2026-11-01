// Provider-neutral contract shared by the REST API and MCP tool discovery.
export const AUDIT_SCHEMA_VERSION = 'offense.audit.v1';
export const OFFENSE_SERVICE_VERSION = '0.7.0';
export const OFFENSE_SERVICE_TITLE = 'Offense Security';
export const auditInputSchema = {
  type: 'object', additionalProperties: false, required: ['files'],
  properties: {
    files: { type: 'array', minItems: 1, maxItems: 20,
      description: 'Locally sanitized npm v2/v3 or pnpm v6/v9 lockfile metadata. The server cannot read local paths. Do not send source, credentials or registry URLs.',
      items: { type: 'object', additionalProperties: false, required: ['path', 'content'], properties: {
        path: { type: 'string', maxLength: 240, description: 'Unique relative lockfile path.' },
        content: { anyOf: [{ type: 'string', maxLength: 2_000_000 }, { type: 'object' }], description: 'Sanitized lockfile document; use the installed Offense helper to prepare it.' }
      } } },
    planLimit: { type: 'integer', minimum: 0, maximum: 10, default: 3,
      description: 'Maximum affected package/version pairs to plan in this response, highest severity first. Zero scans only. Follow remediation.planning.next for remaining targets; omitted or failed paths remain explicit blockers.' },
    scanning: { type: 'object', additionalProperties: false,
      required: ['metadataFingerprint', 'packageOffset', 'advisoryOffset', 'batchFingerprint'],
      description: 'Use scanning.next unchanged with the same complete sanitized files to continue advisory scanning. Retain all prior pages; a continuation alone is never a complete audit. Do not combine with planning.',
      properties: {
        metadataFingerprint: { type: 'string', pattern: '^[a-f0-9]{64}$' },
        packageOffset: { type: 'integer', minimum: 0, maximum: 4900, multipleOf: 100 },
        advisoryOffset: { type: 'integer', minimum: 0, maximum: 100000 },
        batchFingerprint: { anyOf: [{ type: 'null' }, { type: 'string', pattern: '^[a-f0-9]{64}$' }] }
      } },
    planning: { type: 'object', additionalProperties: false, required: ['metadataFingerprint', 'pendingTargetIds'],
      description: 'Use remediation.planning.next unchanged with the same sanitized files to continue planning. This checks only selected planning targets; retain and merge the original full advisory report.',
      properties: {
        metadataFingerprint: { type: 'string', pattern: '^[a-f0-9]{64}$' },
        pendingTargetIds: { type: 'array', minItems: 1, maxItems: 5000, uniqueItems: true,
          items: { type: 'string', pattern: '^[a-f0-9]{64}$' } }
      } }
  }
};

export const auditOutputSchema = {
  type: 'object', required: ['schemaVersion', 'capability', 'status', 'findings', 'coverage', 'remediation', 'summary', 'providers'],
  properties: {
    schemaVersion: { const: AUDIT_SCHEMA_VERSION }, capability: { const: 'audit_dependencies' },
    status: { enum: ['complete', 'partial'] }, findings: { type: 'array', items: { type: 'object' } },
    coverage: { type: 'object' }, remediation: { type: 'object' }, summary: { type: 'object' }, providers: { type: 'array', items: { type: 'object' } }
  }
};
