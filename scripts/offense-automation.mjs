#!/usr/bin/env node
import { open } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createOffenseClient, defaultAutomationPolicy, normalizeAutomationPolicy } from '../sdk/index.mjs';
import { checkRepository } from '../sdk/node.mjs';

const help = 'Usage: node offense-automation.mjs --event manual|pre_deploy|post_deploy|agent_run|dependency_change|scheduled --policy offense.config.json [directory]\n       node offense-automation.mjs --print-default-policy\nNode 20+. Performs a bounded dependency advisory check without package scripts, edits or model calls. A configured pre-deploy/agent gate blocks with exit 1; incomplete evidence exits 2; a skipped trigger exits 3. An explicit gate onIncomplete:report override exits 0 with passed:null and a warning. Report mode does not block on known findings. post_deploy never undoes a completed deployment. Settings alone do not register CI hooks.';

export async function automationMain(argv = process.argv.slice(2), { stdout = console.log, stderr = console.error, fetchImpl } = {}) {
  if (argv.includes('--help') || argv.includes('-h')) { stdout(help); return 0; }
  if (argv.length === 1 && argv[0] === '--print-default-policy') { stdout(JSON.stringify(defaultAutomationPolicy(), null, 2)); return 0; }
  let event = 'manual', policyFile, directory, baseUrl = 'https://app.purpleteam.sh';
  const seen = new Set();
  try {
    for (let index = 0; index < argv.length; index++) {
      const argument = argv[index];
      if (['--event', '--policy', '--endpoint'].includes(argument)) {
        if (seen.has(argument) || !argv[index + 1] || argv[index + 1].startsWith('--')) throw Error('Missing or repeated CLI option.');
        seen.add(argument); const value = argv[++index];
        if (argument === '--event') event = value;
        if (argument === '--policy') policyFile = value;
        if (argument === '--endpoint') baseUrl = value;
      } else if (argument.startsWith('-') || directory !== undefined) throw Error('Unknown CLI argument.');
      else directory = argument;
    }
    let policy = defaultAutomationPolicy();
    if (policyFile) {
      const handle = await open(policyFile, 'r');
      try {
        const info = await handle.stat();
        if (!info.isFile() || info.size > 16_000) throw Error('Policy file exceeds its size limit.');
        const buffer = Buffer.alloc(16_001); let length = 0;
        while (length < buffer.length) { const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null); if (!bytesRead) break; length += bytesRead; }
        if (length > 16_000) throw Error('Policy file exceeds its size limit.');
        policy = normalizeAutomationPolicy(JSON.parse(buffer.subarray(0, length).toString('utf8')));
      } finally { await handle.close(); }
    }
    const result = await checkRepository({ directory: directory || '.', event, policy,
      client: createOffenseClient({ baseUrl, ...(fetchImpl ? { fetchImpl } : {}) }) });
    stdout(JSON.stringify({ schemaVersion: 'offense.lifecycle.v1', event, ...result }, null, 2));
    if (result.decision.action === 'block') return 1;
    if (result.decision.action === 'skip') return 3;
    if (result.decision.passed === null || result.error) {
      const overridden = result.decision.enabled && result.decision.action === 'report' && ['pre_deploy', 'agent_run'].includes(event) &&
        policy.gate.mode === 'block' && policy.gate.onIncomplete === 'report';
      if (overridden) { stderr('Offense: security evidence is incomplete. Your explicit report-on-incomplete gate policy permits continuation; this is not a passing security check.'); return 0; }
      return 2;
    }
    return 0;
  } catch { stderr('Offense automation could not establish a security result. Check the event, trusted policy file, project directory and endpoint.'); return 2; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await automationMain();
