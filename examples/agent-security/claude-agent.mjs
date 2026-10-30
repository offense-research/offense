import { claudeMcpOptions } from '@purpleteam/offense';
import { checkRepository, assertSecurityDecision } from '@purpleteam/offense/node';

// `query` is the official @anthropic-ai/claude-agent-sdk query function supplied
// by your application. Passing it in also permits offline lifecycle tests.
export async function* runClaudeWithSecurity({ query, directory, trustedPolicy, prompt, client, options = {} }) {
  const security = await checkRepository({ directory, policy: trustedPolicy, event: 'agent_run', ...(client ? { client } : {}) });
  assertSecurityDecision(security.decision);
  yield { type: 'security_decision', security };
  // Exposing MCP tools permits later agent-directed audits. The host-side call
  // above is what actually guarantees a configured lifecycle check happens.
  const securityTools = claudeMcpOptions();
  yield* query({ prompt, options: { ...options, cwd: directory,
    mcpServers: { ...securityTools.mcpServers, ...(options.mcpServers || {}) },
    allowedTools: [...new Set([...(options.allowedTools || []), ...securityTools.allowedTools])] } });
}
