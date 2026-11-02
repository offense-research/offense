import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadPolicy, allowedPath, digest, validateCheckMatrix } from './dependency-policy.mjs';
export function validateBundle(bundle, { repository, runId, engineSha, policy, now = Date.now() }) {
  if (bundle.version !== 1 || bundle.repository !== repository || bundle.runId !== runId || bundle.engineSha !== engineSha || bundle.policyHash !== digest(JSON.stringify(policy)) ||
    !/^[a-f0-9]{40}$/.test(bundle.baseSha || '') || !Number.isFinite(bundle.finishedAt) || now - bundle.finishedAt > 3600_000 || bundle.finishedAt > now + 30000) throw Error('Bundle identity or freshness mismatch.');
  if (!Array.isArray(bundle.changes) || !bundle.changes.length || bundle.changes.length > 40 || new Set(bundle.changes.map(c => c.path)).size !== bundle.changes.length) throw Error('Invalid change set.');
  let bytes = 0;
  for (const c of bundle.changes) {
    if (!allowedPath(c.path, policy) || c.mode !== '100644' || !['A', 'M'].includes(c.status) || typeof c.content !== 'string') throw Error('Forbidden change.');
    const value = Buffer.from(c.content, 'base64'); bytes += value.length;
    if (value.toString('base64') !== c.content || digest(value) !== c.sha256) throw Error('Changed file digest mismatch.');
  }
  if (bytes > 8_000_000 || typeof bundle.body !== 'string' || bundle.body.length > 60000) throw Error('Bundle exceeds limits.');
  if (!bundle.evidence?.baselinePassed || !bundle.evidence.candidatePassed || !bundle.evidence.advisoriesComplete || bundle.evidence.newAdvisories !== 0) throw Error('Verification is incomplete.');
  return bundle;
}
export async function exportBundle(reportFile, destination) {
  const { validateArtifacts } = await import('../../agent/pr-handoff.mjs');
  const { candidatePolicy } = await import('./dependency-services.mjs');
  const { report, body, changes } = await validateArtifacts(reportFile, path.join(path.dirname(reportFile), 'pr-handoff.json'));
  if (!report.reverifiedFrom) throw Error('Independent re-verification is required.');
  const policy = await loadPolicy();
  await candidatePolicy(report.sourceDirectory, report.candidateDirectory, policy);
  for (const phase of [report.baseline, report.candidate]) validateCheckMatrix(phase, policy);
  const bundle = { version: 1, repository: process.env.GITHUB_REPOSITORY, runId: process.env.GITHUB_RUN_ID, engineSha: process.env.OFFENSE_ENGINE_SHA,
    baseSha: report.revision, finishedAt: report.finishedAt, policyHash: digest(JSON.stringify(policy)),
    body, changes: changes.map(c => ({ ...c, sha256: digest(Buffer.from(c.content || '', 'base64')) })),
    evidence: { baselinePassed: true, candidatePassed: true, advisoriesComplete: true, newAdvisories: report.newAdvisories.length } };
  validateBundle(bundle, { repository: bundle.repository, runId: bundle.runId, engineSha: bundle.engineSha, policy });
  await writeFile(destination, JSON.stringify(bundle), { flag: 'wx', mode: 0o600 });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) await exportBundle(...process.argv.slice(2));
