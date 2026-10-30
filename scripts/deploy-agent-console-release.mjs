// Explicit publication helper. Build/validation remain credential-free and
// separate; runtime secrets enter only private upload files via Infisical.
import { execFileSync } from 'node:child_process';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { inspectAgentConsoleCandidate, regularBytes, digest } from './build-agent-console-release.mjs';
import { CLIENT_PATCH_KIND, inspectClientPatchCandidate, verifyPublishedClientPatchResources } from './build-client-patch-release.mjs';
import { SKILL_CLIENT_KIND, inspectSkillClientCandidate, verifyPublishedSkillClientResources } from './build-skill-client-release.mjs';
import { mergeDeploymentBindings } from './deployment-secrets.mjs';
import { workerUpload } from './worker-upload.mjs';

export function connectedCloudflare() {
  return { request(args) {
    try { return JSON.parse(execFileSync('composio', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 24 * 1024 * 1024, timeout: 120000 })); }
    catch { throw Error('Cloudflare request failed; credential-bearing output suppressed.'); }
  }, async download(url) {
    const target = new URL(url);
    if (target.protocol !== 'https:') throw Error('Invalid HTTPS module download.');
    const response = await fetch(target, { signal: AbortSignal.timeout(30000), redirect: 'error', cache: 'no-store' });
    if (!response.ok) throw Error('Cannot read the currently active Worker module.');
    return { bytes: await response.arrayBuffer(), contentType: response.headers.get('content-type') };
  } };
}
export async function deployAgentConsoleRelease({ artifactFile, validationFile, expectedVersion, recordDirectory = 'docs/e2e', kind = 'agent_console_frontend_only' }, { transport = connectedCloudflare(), env = process.env } = {}) {
  if (!['agent_console_frontend_only', CLIENT_PATCH_KIND, SKILL_CLIENT_KIND].includes(kind)) throw Error('Choose an explicit supported release scope.');
  if (env.PURPLE_SECRETS_SOURCE !== 'infisical' || env.PURPLE_SECRETS_ENVIRONMENT !== 'prod') throw Error('Use the production Infisical wrapper.');
  if (!/^[a-f0-9-]{36}$/.test(expectedVersion || '')) throw Error('An explicit expected production version is required.');
  const inspector = kind === CLIENT_PATCH_KIND ? inspectClientPatchCandidate : kind === SKILL_CLIENT_KIND ? inspectSkillClientCandidate : inspectAgentConsoleCandidate;
  const candidate = await inspector(artifactFile);
  const validationBytes = await regularBytes(validationFile, 512000), validation = JSON.parse(validationBytes);
  const { module, proof, proofBytes, deployment: previousDeployment } = candidate;
  if (expectedVersion !== proof.previousVersionId || !validation.passed || validation.artifactSha256 !== digest(module) || validation.proofSha256 !== digest(proofBytes) ||
    validation.baselineSha256 !== proof.baselineSha256 || validation.backendSha256 !== proof.backendSha256 || !Number.isFinite(Date.parse(validation.checkedAt)) ||
    Date.now() - Date.parse(validation.checkedAt) > 24 * 3600000 || Date.parse(validation.checkedAt) > Date.now() + 300000) throw Error('The exact candidate and proof need a current passing artifact validation.');
  if (kind === CLIENT_PATCH_KIND) {
    if (validation.kind !== kind) throw Error('Client patch validation must name its explicit release scope.');
    await verifyPublishedClientPatchResources(candidate, { download: url => transport.download(url) });
  }
  if (kind === SKILL_CLIENT_KIND) {
    if (validation.kind !== kind) throw Error('Skill release validation must name its explicit release scope.');
    await verifyPublishedSkillClientResources(candidate, { download: url => transport.download(url) });
  }
  const account = '00000000000000000000000000000000', workerId = '00000000000000000000000000000000';
  const base = `https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/purple-app`;
  const proxy = (suffix, file) => transport.request(['proxy', base + suffix, '--toolkit', 'cloudflare', '-X', file ? 'POST' : 'GET', ...(file ? ['-H', 'content-type: application/json', '-d', '@' + file] : [])]);
  function current() {
    const response = proxy('/deployments');if (!response.success) throw Error('Cannot verify current production deployment.');
    const versions = response.result?.deployments?.[0]?.versions;
    if (!Array.isArray(versions) || versions.length !== 1 || versions[0].percentage !== 100) throw Error('A split production rollout is active.');
    return versions[0].version_id;
  }
  if (current() !== expectedVersion) throw Error('Production changed; prepare from the new active module.');
  const settingsResponse = proxy('/settings');if (!settingsResponse.success) throw Error('Cannot read production settings.');
  const settings = settingsResponse.result;
  if (settings.bindings?.find(binding => binding.name === 'PURPLE_RELEASE')?.text !== proof.previousRelease) throw Error('The production release differs from the reviewed baseline.');
  // Match the full source hash, not only its short health/version label.
  const download = proxy('');if (!download.binary_data?.url) throw Error('Cannot obtain the active module for exact comparison.');
  const body = await transport.download(download.binary_data.url);
  const multipart = await new Response(body.bytes, { headers: { 'content-type': body.contentType || download.binary_data.content_type || download.headers?.['content-type'] } }).formData();
  const modules = [];
  for (const [name, value] of multipart) modules.push({ name: typeof value === 'string' ? name : value.name || name, bytes: typeof value === 'string' ? Buffer.from(value) : Buffer.from(await value.arrayBuffer()) });
  if (modules.length !== 1 || modules[0].name !== 'app-staging.js' || digest(modules[0].bytes) !== proof.baselineSha256) throw Error('Active production module does not match the exact reviewed baseline.');
  const supplied = settings.bindings.flatMap(binding => binding.type === 'secret_text' && env[binding.name] ? [{ name: binding.name, type: 'secret_text', text: env[binding.name] }] :
    binding.type === 'plain_text' ? [{ ...binding, text: binding.name === 'PURPLE_RELEASE' ? proof.release : binding.text }] : []);
  const bindings = mergeDeploymentBindings(settings.bindings, supplied);
  // The connected version API rejects the legacy settings API's empty placement
  // object. Omit that default and verify it is inherited unchanged on readback.
  const preservedSettings = Object.fromEntries(['compatibility_date', 'compatibility_flags', 'placement', 'limits', 'cache_options'].filter(key => settings[key] !== undefined &&
    !(key === 'placement' && settings[key] && Object.keys(settings[key]).length === 0)).map(key => [key, settings[key]]));
  const inheritedSettings = ['observability', 'logpush', 'tail_consumers', 'usage_model', ...(!Object.hasOwn(preservedSettings, 'placement') ? ['placement'] : [])].filter(key => settings[key] !== undefined);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'purple-console-publish-'));
  try {
    const metadata = { main_module: 'app-staging.js', bindings, exports: { PurpleState: { type: 'durable-object', storage: 'sqlite' } }, ...preservedSettings,
      annotations: { workers_message: kind === CLIENT_PATCH_KIND ? 'Offense client patch metadata only; production backend, frontend and other resources preserved' :
        kind === SKILL_CLIENT_KIND ? 'Offense managed skill release; production backend, frontend and unrelated resources preserved' :
          'Agent console: frontend assets only; production backend and client packages preserved' } };
    const upload = workerUpload({ metadata, module, accountId: account, workerId, maximumBytes: 4_000_000 });
    const versionFile = path.join(directory, 'version.json');await writeFile(versionFile, upload.body, { mode: 0o600, flag: 'wx' });
    if (current() !== expectedVersion) throw Error('Production changed before upload.');
    const uploaded = transport.request(['execute', 'CLOUDFLARE_CREATE_WORKER_VERSION', '-d', '@' + versionFile]);
    if (!uploaded.successful || !uploaded.data?.result?.id) {
      let detail = JSON.stringify({ error: uploaded.error, errors: uploaded.data?.errors, message: uploaded.data?.message });
      detail = detail.replaceAll(module.toString('base64'), '[module omitted]').replaceAll(module.toString(), '[module omitted]');
      for (const binding of bindings) if (typeof binding.text === 'string' && binding.text.length >= 4) {
        detail = detail.replaceAll(binding.text, '[redacted]').replaceAll(JSON.stringify(binding.text).slice(1, -1), '[redacted]');
      }
      for (const value of Object.values(env)) if (typeof value === 'string' && value.length >= 8) {
        detail = detail.replaceAll(value, '[redacted]').replaceAll(JSON.stringify(value).slice(1, -1), '[redacted]');
      }
      detail = detail.replace(/(?:Bearer\s+|(?:token|secret|password|api_key)["\s:=]+)[A-Za-z0-9_./+=-]{8,}/gi, '[redacted]');
      throw Error('Version upload failed: ' + detail.slice(0, 1200));
    }
    const version = uploaded.data.result;
    if (current() !== expectedVersion) throw Error('Production changed during upload; candidate was not activated.');
    const activationFile = path.join(directory, 'deployment.json');await writeFile(activationFile, JSON.stringify({ strategy: 'percentage', versions: [{ version_id: version.id, percentage: 100 }], code_update_strategy: { mode: 'immediate' } }), { mode: 0o600, flag: 'wx' });
    if (!proxy('/deployments', activationFile).success || current() !== version.id) throw Error('The requested candidate was not confirmed active.');
    const readback = proxy('/settings');if (!readback.success) throw Error('Candidate is active but production settings readback failed; inspect the previous version before continuing.');
    const canonical = value => JSON.stringify(value, function(_key, item) { return item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item; });
    const changedSettings = [...Object.keys(preservedSettings), ...inheritedSettings].filter(key => canonical(readback.result[key]) !== canonical(settings[key]));
    const deployedAt = new Date().toISOString();
    const record = { ...proof, deployedAt, environment: 'production', source: 'infisical', version: version.number, versionId: version.id,
      previousDeployment, rollback: { versionId: expectedVersion, release: proof.previousRelease, moduleSha256: proof.baselineSha256 },
      activeVersionVerified: true, statefulApiVerified: false, bindingCount: bindings.length, preservedSettings: Object.keys(preservedSettings), inheritedSettings, settingsPreserved: !changedSettings.length, changedSettings,
      uploadPayloadBytes: upload.body.length, artifactValidationSha256: digest(validationBytes), artifactValidation: validation };
    const latest = { deployedAt, source: 'infisical', environment: 'production', version: version.number, versionId: version.id, previousVersionId: expectedVersion,
      moduleSha256: proof.moduleSha256, release: proof.release, uploadPayloadBytes: upload.body.length, bindingCount: bindings.length, activeVersionVerified: true, statefulApiVerified: false };
    await writeFile(path.join(recordDirectory, kind === CLIENT_PATCH_KIND ? 'offense-client-patch-production.json' : kind === SKILL_CLIENT_KIND ? 'skill-client-production.json' : 'agent-console-production.json'), JSON.stringify(record, null, 2)+'\n', { mode: 0o600 });
    await writeFile(path.join(recordDirectory, 'last-app-deployment.json'), JSON.stringify(latest, null, 2)+'\n', { mode: 0o600 });
    if (changedSettings.length) throw Error('The candidate is active but preserved Worker settings changed; inspect the recorded rollback version.');
    console.log(JSON.stringify({ deployed: true, version: version.number, versionId: version.id, release: proof.release, backendUnchanged: true,
      ...(kind === CLIENT_PATCH_KIND ? { clientMetadataUpdated: true } : kind === SKILL_CLIENT_KIND ? { skillResourcesUpdated: true } : { priorClientsPreserved: true }) }));
    return { record, latest };
  } finally { await rm(directory, { recursive: true, force: true }); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [artifactFile, validationFile, expectedVersion, kind] = process.argv.slice(2);
  if (!expectedVersion || ![5, 6].includes(process.argv.length)) throw Error('Usage: deploy-agent-console-release.mjs CANDIDATE.js VALIDATION.json EXPECTED_ACTIVE_VERSION [agent_console_frontend_only|offense_client_patch|offense_skill_release]');
  await deployAgentConsoleRelease({ artifactFile, validationFile, expectedVersion, ...(kind ? { kind } : {}) });
}
