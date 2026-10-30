#!/usr/bin/env node
import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createOffenseCli } from '../lib/hosted-cli.mjs';
export function hostedCli(options = {}) {
  return createOffenseCli({ ...options, cliPath: fileURLToPath(import.meta.url) });
}
if (process.argv[1] && await realpath(process.argv[1]).catch(() => null) === fileURLToPath(import.meta.url)) {
  process.exitCode = await hostedCli().run(process.argv.slice(2));
}
