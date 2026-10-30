import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { updaterMain } from './skill-updater.mjs';
export { updateBeforeRun, checkSkillUpdates, validateRelease } from './skill-updater.mjs';

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  updaterMain(process.argv.slice(2), import.meta.url).catch(error => { console.error('Skill updates: ' + error.message); process.exitCode = 2; });
}
