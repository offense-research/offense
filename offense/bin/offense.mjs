#!/usr/bin/env node
import path from 'node:path';
import { realpath } from 'node:fs/promises';
import { OFFENSE_SERVICE_VERSION } from '../shared/offense-schema.js';
import { fileURLToPath } from 'node:url';

export const HELP = `Offense ${OFFENSE_SERVICE_VERSION}
Usage: offense scan [PROJECT] [--plan-limit 0..30] [--output DIRECTORY] [--preview]
       offense metadata [PROJECT]
       offense doctor [PROJECT]
       offense mcp
       offense triage [PROJECT] --scan scan.json [options]
       offense rehearse [PROJECT] --scan scan.json --sandboxed [options]
       offense source-scan [PROJECT] [options]
       offense api-test [options]
       offense hardened-image [options]

Node 24+. Dependency intelligence runs locally and queries only OSV/npm.
No Offense sign-in, Cloudflare connection, model key or hosted company API is required.
Scans produce local scan.json and remediation.md; previews and doctor stay offline.
MCP exposes offense.audit_dependencies (plus the purple.audit_dependencies compatibility alias) over stdio. Your agent controls source review,
changes and tests. Local app/tool execution requires its separate explicit command.
Use offense COMMAND --help for a tool's options. Updates are manual through reviewed Git/package releases.
Optional hosted account tools use offense-hosted; local commands never need that login.
`;

export async function main(argv = process.argv.slice(2)) {
  const args = [...argv], command = args.shift();
  if (!command || ['--help', '-h', 'help'].includes(command)) { console.log(HELP); return; }
  if (['--version', '-v'].includes(command)) { console.log(OFFENSE_SERVICE_VERSION); return; }
  if (command === 'mcp') {
    if (args.length) throw Error('offense mcp takes no arguments; configure it as a project-scoped stdio MCP server.');
    return (await import('../lib/mcp.mjs')).serveMcp();
  }
  if (command === 'doctor') {
    if (args.includes('--help')) { console.log('Usage: offense doctor [PROJECT]\nOffline runtime and executable-availability checks only; no credentials or client configuration is read.'); return; }
    if (args.length > 1 || args.some(arg => arg.startsWith('--'))) throw Error('Usage: offense doctor [PROJECT]');
    const result = await (await import('../lib/doctor.mjs')).doctor(args[0] || '.');
    console.log(JSON.stringify(result, null, 2)); if (result.status !== 'ready') process.exitCode = 2;
    return result;
  }
  if (command === 'metadata') {
    if (args.includes('--help')) { console.log('Usage: offense metadata [PROJECT]\nInventory and sanitize supported lockfiles locally. No network, application execution or file writes.'); return; }
    if (args.length > 1 || args.some(arg => arg.startsWith('--'))) throw Error('Usage: offense metadata [PROJECT]');
    const result = await (await import('../lib/metadata.mjs')).collectMetadata(args[0] || '.');
    console.log(JSON.stringify(result, null, 2)); return result;
  }
  if (command === 'scan' || command === 'audit') return (await import('../tools/purple.mjs')).main(['scan', ...args]);
  const tool = { triage: 'triage', rehearse: 'rehearse', 'source-scan': 'source-scan', 'api-test': 'api-test', 'hardened-image': 'hardened-image' }[command];
  if (!tool) throw Error('Unknown Offense command. Use offense --help.');
  return (await import(`../tools/${tool}.mjs`)).main(args);
}
if (process.argv[1] && await realpath(process.argv[1]).catch(() => null) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Offense: ${error.message}`); process.exitCode = 1; });
}
