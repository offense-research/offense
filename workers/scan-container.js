import { sourceFiles } from '../server/scan-input.js';
import { ARTIFACT_LIMITS, ARTIFACT_TOOLS, limitArtifactStream } from '../server/scan-artifacts.js';
import { webScanOrigin } from '../server/web-scan-target.js';
import { Buffer } from 'node:buffer';
import { assessmentTool } from '../shared/assessment-tools.js';
import { assessmentInput } from '../server/assessment-input.js';
import { assessmentNetworkPolicy } from './assessment-egress.js';
import { warmAssessmentGateway } from './assessment-egress-client.js';
import { assessmentFailureSummary } from './assessment-failure-metrics.js';
import { kubernetesScanVersion } from '../shared/kubernetes-scan.js';

const artifactPath = '/tmp/purple-scan/artifact';
const containerObservation = durationMs => Number.isSafeInteger(durationMs) && durationMs >= 0 && durationMs <= 24 * 60 * 60_000
  ? { observer: 'container_controller', containerDurationMs: durationMs } : null;

export function validateScanArtifact(input) {
  const artifact = input?.artifact;
  if (!artifact || typeof artifact !== 'object' || !Object.hasOwn(ARTIFACT_LIMITS, artifact.kind) ||
      !Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > ARTIFACT_LIMITS[artifact.kind] ||
      !/^[a-f0-9]{64}$/.test(artifact.sha256 || '') ||
      !/^scan\/[a-f0-9]{16}\/[a-f0-9]{32}$/.test(artifact.objectKey || '') ||
      !Array.isArray(input.tools) || input.tools.length !== 1 || !ARTIFACT_TOOLS[artifact.kind].includes(input.tools[0]) ||
      !Array.isArray(input.files) || input.files.length !== 0) throw new Error('Invalid scanner artifact.');
  if (artifact.kind === 'package-archive') {
    if (typeof artifact.packageName !== 'string' || !/^(?:@?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?)$/.test(artifact.packageName) ||
        typeof artifact.packageVersion !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._+!-]{0,99}$/.test(artifact.packageVersion))
      throw new Error('Invalid scanner package coordinates.');
  } else if (artifact.packageName !== undefined || artifact.packageVersion !== undefined) {
    throw new Error('Invalid scanner artifact.');
  }
  if (artifact.kind === 'cosign-save') {
    let issuer;
    try { issuer = new URL(artifact.expectedIssuer); } catch { throw new Error('Invalid image signer policy.'); }
    if (!/^sha256:[a-f0-9]{64}$/.test(artifact.expectedDigest || '') ||
        typeof artifact.expectedIdentity !== 'string' || artifact.expectedIdentity.length < 1 || artifact.expectedIdentity.length > 240 ||
        !/^[\x21-\x7e]+$/.test(artifact.expectedIdentity) || /[\*?\[\]{}()|+^$\\]/.test(artifact.expectedIdentity) ||
        artifact.expectedIssuer.length > 300 || issuer.protocol !== 'https:' || issuer.username || issuer.password ||
        issuer.search || issuer.hash || issuer.origin !== artifact.expectedIssuer)
      throw new Error('Invalid image signer policy.');
  } else if (artifact.expectedDigest !== undefined || artifact.expectedIdentity !== undefined || artifact.expectedIssuer !== undefined) {
    throw new Error('Invalid scanner artifact.');
  }
  if (artifact.kind === 'web-har') {
    try { if (webScanOrigin(artifact.target) !== artifact.target) throw new Error(); }
    catch { throw new Error('Invalid passive web scan origin.'); }
  } else if (artifact.target !== undefined) throw new Error('Invalid scanner artifact.');
  return artifact;
}

export function scanRunnerInput(files, tools, artifact, kubernetesVersion) {
  kubernetesScanVersion({ tools, kubernetesVersion });
  return { files, ...(tools === undefined ? {} : { tools }),
    ...(kubernetesVersion ? { kubernetesVersion } : {}),
    ...(artifact ? { artifact: { kind: artifact.kind, size: artifact.size, sha256: artifact.sha256, path: artifactPath,
      ...(artifact.kind === 'package-archive' ? { packageName: artifact.packageName, packageVersion: artifact.packageVersion } : {}),
      ...(artifact.kind === 'cosign-save' ? { expectedDigest: artifact.expectedDigest,
        expectedIdentity: artifact.expectedIdentity, expectedIssuer: artifact.expectedIssuer } : {}),
      ...(artifact.kind === 'web-har' ? { target: artifact.target } : {}) } } : {}) };
}

export function validateAssessmentRequest(input, artifact) {
  const tool = assessmentTool(input?.tools?.[0]);
  if (!tool || input.tools.length !== 1 || !input.assessment || input.assessment.tool !== tool.id)
    throw new Error('Invalid assessment request.');
  const { files, options, credentials } = input.assessment;
  const request = assessmentInput(tool.id, { files: ['source-files', 'verified-api'].includes(tool.inputType) ? files : undefined,
    target: options?.target, repository: options?.repository, accountId: options?.accountId, apiToken: credentials?.apiToken,
    confirmActiveTesting: true, confirmLiveVerification: true, format: options?.format }, {
    artifact, verifiedTarget: { origin: options?.target, addresses: options?.resolvedAddresses }
  });
  return { tool, request };
}

async function importArtifact(container, bucket, artifact) {
  if (!bucket) throw new Error('Scanner artifact storage is unavailable.');
  const object = await bucket.get(artifact.objectKey);
  const objectHash = object?.checksums?.sha256 && Buffer.from(object.checksums.sha256).toString('hex');
  // R2 can omit its optional checksum on objects written by other authorized
  // clients. The in-container SHA-256 check below is always required before
  // any untrusted artifact is scanned.
  if (!object?.body || object.size !== artifact.size || objectHash && objectHash !== artifact.sha256)
    throw new Error('Scanner artifact is missing or its checksum differs.');
  const directory = await container.exec(['mkdir', '-p', '/tmp/purple-scan']);
  if ((await directory.output()).exitCode !== 0) throw new Error('Scanner artifact directory is unavailable.');
  const write = await container.exec(['dd', `of=${artifactPath}`, 'bs=1M', 'status=none'], {
    stdin: limitArtifactStream(object.body, artifact.size), stdout: 'ignore', stderr: 'ignore'
  });
  if ((await write.output()).exitCode !== 0) throw new Error('Scanner artifact transfer failed.');
  const checksum = await container.exec(['sha256sum', artifactPath]);
  const output = await checksum.output();
  if (output.exitCode !== 0 || new TextDecoder().decode(output.stdout).trim().split(/\s+/)[0] !== artifact.sha256)
    throw new Error('Scanner artifact changed during transfer.');
  await bucket.delete(artifact.objectKey);
}

export function scanController(ctx, env = {}, { warmGateway = warmAssessmentGateway } = {}) {
  return {
    async start(input) {
      const previous = ctx.storage.kv.get('scan');
      if (previous) return { status: previous.status === 'starting' ? 'running' : previous.status };
      const artifact = input.artifact === undefined ? null : validateScanArtifact(input);
      const assessment = input.assessment === undefined ? null : validateAssessmentRequest(input, artifact);
      if (!assessment && input.tools?.some(id => assessmentTool(id))) throw new Error('Assessment payload is missing.');
      const files = artifact || assessment ? [] : sourceFiles(input.files).files;
      const container = ctx.container;
      const image = assessment ? assessment.tool.image : 'scan';
      if (!container || !container.images[image]) throw new Error('Scanner image unavailable.');
      // Store the intent first: a retried request never launches a second scan.
      const startedAt = Date.now(); let containerStartedAt = null, gatewayWarmup, gatewayWarmupAbort;
      ctx.storage.kv.put('scan', { status: 'starting', startedAt });
      await ctx.storage.setAlarm(Date.now() + 12 * 60_000);
      try {
        container.start({ image: container.images[image], entrypoint: ['sleep', 'infinity'], enableInternet: false, instance: 'standard-2' });
        containerStartedAt = Date.now();
        ctx.storage.kv.put('scan', { status: 'starting', startedAt, containerStartedAt });
        if (assessment?.tool.image === 'assessment-network') {
          const policy = assessmentNetworkPolicy(assessment.request);
          ctx.storage.kv.put('assessment-policy', policy);
          // Start readiness while the isolated VM boots. Scanner-specific
          // socket deadlines begin only after the gateway is available.
          gatewayWarmupAbort = new AbortController();
          gatewayWarmup = warmGateway({ gatewayURL: env.ASSESSMENT_EGRESS_URL, key: env.ASSESSMENT_EGRESS_KEY,
            signal: gatewayWarmupAbort.signal });
          void gatewayWarmup.catch(() => {});
        }
        await container.setInactivityTimeout(12 * 60_000);
        if (assessment?.tool.image === 'assessment-network') {
          await gatewayWarmup;
          const outbound = ctx.exports.AssessmentOutbound({ props: { scanId: input.id } });
          await container.interceptAllOutboundHttp(outbound);
          await container.interceptOutboundHttps('*', outbound);
          await container.exec(['node', '/opt/purple/agent/assessment-tunnel-proxy.mjs'], { stdout: 'ignore', stderr: 'ignore' });
          const ready = await container.exec(['timeout', '7', 'node', '--input-type=module', '-e',
            "import net from 'node:net';let ready=false;for(let i=0;i<50;i++){ready=await new Promise(resolve=>{const s=net.connect(8799,'127.0.0.1');s.once('connect',()=>{s.destroy();resolve(true)});s.once('error',()=>resolve(false));s.setTimeout(100,()=>{s.destroy();resolve(false)})});if(ready)break;await new Promise(r=>setTimeout(r,100))}if(!ready)process.exit(1)"]);
          if ((await ready.output()).exitCode !== 0) throw new Error('Assessment network proxy did not become ready.');
        }
        if (artifact) await importArtifact(container, env.SCAN_ARTIFACTS, artifact);
        const payload = assessment ? { ...assessment.request,
          ...(artifact ? { artifact: { kind: artifact.kind, size: artifact.size, sha256: artifact.sha256, path: artifactPath } } : {}) }
          : scanRunnerInput(files, input.tools, artifact, input.kubernetesVersion);
        const stdin = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(payload))); controller.close(); } });
        const module = assessment ? assessment.tool.image === 'assessment-network' ? 'assessment-network.mjs' : 'assessment-offline.mjs' : 'scan-runner.mjs';
        await container.exec(['timeout', '--kill-after=5', '660', 'node', `/opt/purple/agent/${module}`], {
          stdin, stdout: 'ignore', stderr: 'ignore',
          ...(assessment ? { env: { PURPLE_ASSESSMENT_PROXY: 'http://127.0.0.1:8799', PURPLE_ASSESSMENT_RESULT_PATH: '/tmp/purple-scan-result.json' } } : {})
        });
        ctx.storage.kv.put('scan', { status: 'running', startedAt, containerStartedAt });
        return { status: 'running' };
      } catch {
        gatewayWarmupAbort?.abort();
        await gatewayWarmup?.catch(() => {});
        if (artifact && env.SCAN_ARTIFACTS) await env.SCAN_ARTIFACTS.delete(artifact.objectKey).catch(() => {});
        await container.destroy().catch(() => {});
        const observation = containerStartedAt === null ? null : containerObservation(Date.now() - containerStartedAt);
        ctx.storage.kv.put('scan', { status: 'failed', startedAt, containerStartedAt,
          ...(observation ? { execution: observation } : {}), tools: [], findings: [], error: 'Could not start the isolated scanner.' });
        throw new Error('Could not start the isolated scanner.');
      }
    },
    async get() {
      const job = ctx.storage.kv.get('scan');
      if (!job) return { status: 'missing' };
      if (!['running', 'starting'].includes(job.status)) return job;
      if (!ctx.container?.running || Date.now() - job.startedAt > 12 * 60_000) return { status: 'failed', tools: [], findings: [], error: 'Scanner stopped or timed out.' };
      const process = await ctx.container.exec(['cat', '/tmp/purple-scan-result.json']);
      const output = await process.output();
      if (output.exitCode !== 0) return { status: 'running' };
      if (output.stdout.byteLength > 1_500_000) throw new Error('Scanner report too large.');
      const result = JSON.parse(new TextDecoder().decode(output.stdout));
      // Ignore any executable-supplied timing claim. This measures observed VM
      // wall time, including startup and report polling, not CPU time or an invoice.
      delete result.execution;
      const observation = job.containerStartedAt === null || job.containerStartedAt === undefined ? null : containerObservation(Date.now() - job.containerStartedAt);
      if (observation) result.execution = observation;
      const policy = ctx.storage.kv.get('assessment-policy');
      if (policy) {
        // A CLI may finish while its final tunnel is still streaming. Do not
        // settle until all tunnel lifecycles have recorded their outcome.
        if ((ctx.storage.kv.get('assessment-active-count') || 0) > 0) return { status: 'running' };
        const opened = ctx.storage.kv.get('assessment-connections') || 0;
        const failures = ctx.storage.kv.get('assessment-network-failures') || 0;
        if ((!opened && policy.tool !== 'trufflehog-verified' || failures) && result.status === 'completed') {
          result.status = 'partial';
          result.tools = result.tools.map(tool => ({ ...tool, status: 'partial' }));
          result.warnings = ['The network scope or connection budget prevented complete coverage.'];
        }
        result.coverage = { ...(result.coverage || {}), outboundConnections: opened, networkFailures: failures,
          networkFailureReasons: assessmentFailureSummary(ctx.storage.kv, failures) };
      }
      return result;
    },
    async destroy() {
      const job = ctx.storage.kv.get('scan');
      let usage = job?.execution || null;
      const wasRunning = ctx.container?.running;
      if (wasRunning) await ctx.container.destroy();
      if (wasRunning && job?.containerStartedAt !== null && job?.containerStartedAt !== undefined)
        usage = containerObservation(Date.now() - job.containerStartedAt);
      // Repeated cleanup RPCs reuse the final observation instead of adding
      // time after the VM has already been destroyed.
      if (job?.status === 'expired') usage = job.execution || null;
      ctx.storage.kv.put('scan', { status: 'expired', ...(usage ? { execution: usage } : {}) });
      await ctx.storage.deleteAlarm();
      return { status: 'destroyed', ...(usage ? { usage } : {}) };
    }
  };
}

export async function scanService(request, env) {
  const url = new URL(request.url), match = /^\/scans\/([a-f0-9]{32})$/.exec(url.pathname);
  if (match && ['GET', 'DELETE'].includes(request.method)) {
    const stub = env.AGENT.getByName(`scan-${match[1]}`);
    return Response.json(request.method === 'DELETE' ? await stub.destroyScan() : await stub.readScan());
  }
  if (url.pathname !== '/scans' || request.method !== 'POST') return new Response('Not found', { status: 404 });
  const reader = request.body?.getReader();
  if (!reader) return new Response('Missing source', { status: 400 });
  const chunks = []; let size = 0;
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    size += value.byteLength;
    if (size > 6 * 1024 * 1024) { await reader.cancel(); return new Response('Source too large', { status: 413 }); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const input = JSON.parse(new TextDecoder().decode(bytes));
  if (!/^[a-f0-9]{32}$/.test(input.id || '')) return new Response('Invalid scan ID', { status: 400 });
  if (input.artifact === undefined && input.assessment === undefined) sourceFiles(input.files);
  else if (input.artifact === undefined) validateAssessmentRequest(input, null);
  else validateScanArtifact(input);
  return Response.json(await env.AGENT.getByName(`scan-${input.id}`).startScan(input), { status: 202 });
}
