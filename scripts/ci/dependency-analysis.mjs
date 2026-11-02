import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const engine = process.env.OFFENSE_AUDIT_ENGINE;
const { analyze, collectMetadata } = await import(engine ? pathToFileURL(path.resolve(engine, 'offense/tools/purple.mjs')).href : '../../offense/tools/purple.mjs');
import { loadPolicy, reviewedCoverage } from './dependency-policy.mjs';
export async function ciMetadata(directory) {
  return reviewedCoverage(directory, await collectMetadata(directory), await loadPolicy());
}
export async function ciAnalyze(directory, options) {
  const metadata = await ciMetadata(directory);
  const result = await analyze(directory, options);
  const scan = JSON.parse(await readFile(result.json, 'utf8'));
  const known = metadata.reviewedExclusions.map(f => `${f}: no covering lockfile importer was found; verify coverage.`);
  scan.warnings = scan.warnings.filter(w => !known.includes(w));
  scan.reviewedExclusions = metadata.reviewedExclusions;
  await writeFile(result.json, JSON.stringify(scan, null, 2));
  return result;
}
