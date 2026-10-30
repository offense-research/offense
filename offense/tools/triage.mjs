import { main as run } from './purple.mjs';
export const main = (argv = process.argv.slice(2)) => run(['triage', ...argv]);
