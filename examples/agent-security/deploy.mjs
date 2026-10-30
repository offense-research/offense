import { checkRepository, assertSecurityDecision } from '@purpleteam/offense/node';

// Wire this wrapper into the application that owns deployment. `deploy` must be
// your trusted deployment function, outside the agent's shell or tool registry.
export async function deployWithSecurity({ directory, trustedPolicy, deploy, client }) {
  const before = await checkRepository({ directory, policy: trustedPolicy, event: 'pre_deploy', ...(client ? { client } : {}) });
  assertSecurityDecision(before.decision);
  const deployment = await deploy();
  const after = await checkRepository({ directory, policy: trustedPolicy, event: 'post_deploy', ...(client ? { client } : {}) });
  return { deployment, before, after };
}
