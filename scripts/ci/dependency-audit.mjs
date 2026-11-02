import { appendFile, readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ciAnalyze, ciMetadata } from './dependency-analysis.mjs';
const [project, output, base] = process.argv.slice(2);
if (!project || !output) throw Error('Usage: dependency-audit.mjs PROJECT OUTPUT [BASE_PROJECT]');
await mkdir(output, { recursive: true });
// Write the inventory before enforcing coverage so failures remain inspectable.
const { pathToFileURL } = await import('node:url');
const { collectMetadata } = await import(process.env.OFFENSE_AUDIT_ENGINE ? pathToFileURL(path.resolve(process.env.OFFENSE_AUDIT_ENGINE, 'offense/tools/purple.mjs')).href : '../../offense/tools/purple.mjs');
await writeFile(path.join(output, 'inventory.json'), JSON.stringify(await collectMetadata(project), null, 2));
await ciMetadata(project);
const result = await ciAnalyze(project, { output: path.join(output, 'head'), planLimit: 0 });
const report = JSON.parse(await readFile(result.json, 'utf8'));
let added = null;
if (base) {
  const prior = await ciAnalyze(base, { output: path.join(output, 'base'), planLimit: 0 });
  const old = JSON.parse(await readFile(prior.json, 'utf8'));
  const keys = new Set(old.vulnerabilityCheck.findings.map(f => `${f.id}:${f.package}:${f.version}`));
  added = report.vulnerabilityCheck.findings.filter(f => !keys.has(`${f.id}:${f.package}:${f.version}`)).length;
}
if (report.warnings.length) throw Error('Audit coverage is incomplete.');
const summary = `## Offense dependency audit\n${report.vulnerabilityCheck.findings.length} advisory matches; ${added ?? 'not compared'} new matches.\n\nAdvisories are report-only, not proof of exploitability. Dependency-free distribution manifests: ${report.reviewedExclusions.join(', ')}. No application code was executed.\n`;
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
else console.log(summary);
