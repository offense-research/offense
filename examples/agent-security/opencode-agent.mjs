import { opencodeMcpConfig } from '@purpleteam/offense';
import { checkRepository, assertSecurityDecision } from '@purpleteam/offense/node';

// Pass createOpencode from @opencode-ai/sdk. No SDK server or model starts until
// the configured agent_run security decision permits the run.
export async function runOpenCodeWithSecurity({ createOpencode, directory, trustedPolicy, prompt, client, config = {} }) {
  const security = await checkRepository({ directory, policy: trustedPolicy, event: 'agent_run', ...(client ? { client } : {}) });
  assertSecurityDecision(security.decision);
  const securityTools = opencodeMcpConfig();
  const opencode = await createOpencode({ config: { ...config, mcp: { ...securityTools.mcp, ...(config.mcp || {}) } } });
  try {
    const session = await opencode.client.session.create({ body: { title: 'Security-aware agent run' }, query: { directory } });
    if (!session.data?.id) throw Error('OpenCode did not create a session.');
    const result = await opencode.client.session.prompt({ path: { id: session.data.id }, query: { directory },
      body: { parts: [{ type: 'text', text: prompt }] } });
    return { security, result };
  } finally { opencode.server.close(); }
}
