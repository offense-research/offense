// Trusted container controller. Credentials arrive on stdin, never Docker argv
// or a repository subprocess environment. Customer source is evidence only.
import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { runDependencyFix, verifyDependencyFix } from './dependency-fix.mjs';
import { runHermesTask } from './hermes-runtime.mjs';
import { prepareArtifactOwnership, restoreArtifactOwnership } from './artifact-ownership.mjs';
import { reapRepositoryProcesses } from './repository-isolation.mjs';

async function main() {
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk.toString();
    if (Buffer.byteLength(text) > 128000) throw new Error('Dependency-fix input exceeds its limit.');
  }
  let input;
  try { input = JSON.parse(text); } catch { throw new Error('Invalid dependency-fix job.'); }
  text = '';
  if (typeof input.output !== 'string' || !path.isAbsolute(input.output)) throw new Error('An absolute output path is required.');
  const uid = input.artifactUid ?? Number(process.env.PURPLE_FIX_OUTPUT_UID), gid = input.artifactGid ?? Number(process.env.PURPLE_FIX_OUTPUT_GID);
  if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) throw new Error('Provide the host artifact owner identity.');
  if (input.mode === 'restore_ownership') {
    await restoreArtifactOwnership({ output: input.output, uid, gid }); return;
  }
  if (process.env.PURPLE_FIX_ISOLATE_COMMANDS !== '1') throw new Error('Repository UID isolation is required by the job controller.');
  await mkdir(input.output, { recursive: true, mode: 0o700 });
  await prepareArtifactOwnership(input.output);
  const redact = value => String(value).split(input.apiKey || '\0').join('[REDACTED]');
  try {
    const report = input.mode === 'verify' ? await verifyDependencyFix({ reportFile: input.reportFile, output: input.verificationOutput, sandboxed: true }) : await runDependencyFix({ ...input, sandboxed: true }, {
      agent: request => runHermesTask({ ...request, model: input.model, apiKey: input.apiKey,
        maxTurns: input.maxTurns, timeoutMs: input.agentTimeoutMs || 180000 })
    });
    process.stdout.write(JSON.stringify({ status: report.status, evidencePath: report.evidencePath,
      reportPath: report.reportPath, patch: report.patch, handoff: report.handoff })+'\n');
    process.exitCode = ['ready_for_review', 'no_changes'].includes(report.status) ? 0 : 2;
  } catch (error) {
    const failure = { status: 'blocked', error: redact(error.message).slice(0, 1500), runtime: 'hermes' };
    await writeFile(path.join(input.output, 'job-error.json'), JSON.stringify(failure, null, 2)+'\n', { mode: 0o600 });
    process.stderr.write(failure.error+'\n'); process.exitCode = 2;
  } finally {
    await reapRepositoryProcesses();
    await restoreArtifactOwnership({ output: input.output, uid, gid });
  }
}
await main();
