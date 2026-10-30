# Offense for agent hosts

Use Offense as a tool inside an agent, or call it directly from the code that starts an agent run or deploys an application. A host-side check runs because your code invokes it; an MCP connection only makes a tool available to the model.

This package is distributed as a downloadable archive and is not published to the npm registry. Install the client archive in your application:

```sh
npm install https://offense.sh/downloads/offense-sdk.tgz
```

Node.js 20+ is required for repository collection. The main client also supports hosts with `fetch`, Web Crypto and AbortSignal APIs. It does not run a model, install dependencies or execute package scripts.

Clients default to the canonical `https://offense.sh` origin. An explicit `baseUrl`
can retain a legacy `https://app.purpleteam.sh` integration or select a self-hosted
service. The package name remains `@purpleteam/offense` for import compatibility.
Maintainers build the archive with `node scripts/build-agent-sdk.mjs`; that command
does not publish this repository, the community edition or an npm package.

```js
import { defaultAutomationPolicy } from '@purpleteam/offense';
import { checkRepository, assertSecurityDecision } from '@purpleteam/offense/node';

const trustedPolicy = {
  ...defaultAutomationPolicy(),
  preDeploy: true,
  gate: { mode: 'block', minimumSeverity: 'high', onIncomplete: 'block' }
};
const result = await checkRepository({ directory: '/app/checkout', event: 'pre_deploy', policy: trustedPolicy });
assertSecurityDecision(result.decision);
await deploy(); // Your application's existing trusted function.
```

Use `assertSecurityDecision(decision, { requirePassed: true })` when the caller requires a complete passing result and will not accept a disabled trigger or an explicit report-only override. The default assertion respects policy: it throws for `block`, while `report` and `skip` remain visible decisions. A result with `passed: null` is unknown, never a clean result. Passing a severity threshold is not a security attestation or a verified exploit fix.

Policies can enable dependency-change and scheduled monitoring in Purple, and `pre_deploy`, `post_deploy` or `agent_run` checks in an integration. Defaults enable change monitoring and daily rechecks, while deployment and agent hooks stay disabled until selected. A standalone SDK does not register a scheduler or deployment hook by saving a policy. Invoke it from your host, CI job or scheduler. Post-deploy checks report the supplied checkout's dependencies; they do not inspect the deployed artifact or undo a completed deployment.

Keep the policy and deployment wrapper in configuration controlled by the host. A model that can edit its own policy, bypass the wrapper, or directly invoke a separate deploy credential can bypass that integration. MCP availability and prompt instructions are not an enforcement boundary.

## Agent tools and lifecycle checks

The `examples` directory contains Claude Agent SDK, OpenCode SDK and deployment wrappers. Claude uses `claudeMcpOptions()` in its `query` options; OpenCode uses `opencodeMcpConfig()` in the server configuration. These configure the existing read-only remote MCP audit. They do not prove a provider credential is configured or start a paid model. Install the relevant agent SDK in your host separately.

For a custom tool runtime, `createAuditTool({ policy, event })` returns a name, JSON input schema and `execute` function. Its policy and lifecycle event are captured by the host and are not model-controlled tool arguments. Tools accept explicit lockfile metadata, not filesystem paths the hosted service could open. For deterministic checks, use `checkRepository` in trusted lifecycle code instead of relying on the model to choose this tool.

## Input and coverage

Repository collection reads supported npm v2/v3 and pnpm v6/v9 lockfiles, inventories manifest paths, and sends sanitized metadata to `POST /api/offense/audit`. Registry URLs, scripts, integrity data and credentials are stripped. Dependency names, versions and relative paths may contain private information and are transmitted. Source files and `.npmrc` are not uploaded by this dependency client. Missing lockfiles, unsupported managers, symlinks, search bounds and uncovered workspaces remain incomplete coverage. The report fingerprint must match the sanitized request, and stale or malformed responses cannot pass a gate.

Use `createOffenseClient().check({ files, event, policy })` when your host already holds explicit dependency metadata. `audit({ files })` throws on transport or malformed responses; `check` returns a structured unknown decision on those operational failures. Optional `onEvent` callbacks receive bounded counts, timing and outcome codes; no source text, secrets or dependency names are sent to that callback. Persist these in the host's own telemetry if needed. The anonymous audit API does not automatically link these calls to a Purple customer's billing or usage dashboard.

## Metered hosted tools

`createHostedScanClient({ apiKey })` accesses the existing authenticated hosted scanner API separately. Its key stays in your host; do not put it into prompts or model-visible arguments. The catalogue is deployment-specific, and some assessments may be disabled until rollout.

```js
import { createHostedScanClient } from '@purpleteam/offense';

const scans = createHostedScanClient({ apiKey: process.env.OFFENSE_API_KEY });
const files = [{ path: 'example.js', content: '/* explicitly selected source */' }];
const tools = ['opengrep'];
const inputBytes = files.reduce((sum, file) => sum + new TextEncoder().encode(file.content).byteLength, 0);
const quote = await scans.quote({ tools, inputBytes, fileCount: files.length });
// Decide this budget in host configuration, before allowing an agent tool call.
const job = await scans.submit({ input: { tools, files }, quote,
  maxChargeMicros: 100_000, idempotencyKey: 'host-job-12345' });
const current = await scans.get(job.id);
```

Quote and submit are separate actions. Submit requires a quote from that client, matching tools, an explicit charge ceiling in millionths of a US dollar, and a stable idempotency key. It never retries a paid submission automatically. The server enforces balance, workspace attribution, metering and quotas. Existing target-ownership checks and artifact-upload prerequisites still apply; this initial SDK does not create target proofs or upload binary artifacts. A queued, failed, partial or expired job is not a passing security result. Poll or resume explicitly using the returned scan ID.

## Standalone lifecycle command

Download `offense-automation.mjs` and export `offense.config.json` from Purple. It is bundled and needs no npm install:

```sh
node offense-automation.mjs --event pre_deploy --policy offense.config.json /app/checkout
```

Exit 0 means the configured reporting/gating policy permits continuation; inspect `decision.passed` for the actual threshold result. Exit 1 blocks a configured gate, 2 means invalid configuration or incomplete evidence, and 3 means the selected trigger is disabled. An enabled blocking gate explicitly configured with `onIncomplete: "report"` instead exits 0 with `passed: null` and a warning for missing evidence; known above-threshold findings still block. Handle post-deploy failures as alerts in your own pipeline rather than claiming that an already completed deployment was blocked.

SDK configuration references: [Claude Agent SDK MCP](https://code.claude.com/docs/en/agent-sdk/mcp), [Claude hooks](https://code.claude.com/docs/en/agent-sdk/hooks), [OpenCode SDK](https://opencode.ai/docs/sdk/), [OpenCode MCP](https://opencode.ai/docs/mcp-servers/). Integration examples were checked against these primary sources; no real agent/model run is performed by the tests.
