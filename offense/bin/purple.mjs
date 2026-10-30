#!/usr/bin/env node
// Compatibility entrypoint for existing Purple Community installations.
import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { main, HELP } from './offense.mjs';
export { main, HELP };
if (process.argv[1] && await realpath(process.argv[1]).catch(() => null) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Offense: ${error.message}`); process.exitCode = 1; });
}
