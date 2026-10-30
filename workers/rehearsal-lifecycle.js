// Separate from the Cloudflare class so retention and failure cleanup are testable.
export function rehearsalOutboundAllowed(address) {
  const url = new URL(address);
  return url.protocol === 'https:' && ['registry.npmjs.org', 'registry.yarnpkg.com'].includes(url.hostname);
}

export async function finishRehearsal(ctx, result) {
  // Persist the bounded report before destroying the filesystem. The report can
  // include command output; it is not a promise of zero source-code retention.
  ctx.storage.kv.put('rehearsal', result);
  await ctx.container?.destroy();
  await ctx.storage.deleteAlarm();
  return result;
}

export async function readRehearsal(ctx) {
  const job = ctx.storage.kv.get('rehearsal');
  if (!job) return { status: 'missing' };
  if (job.status !== 'running') {
    // A previous cleanup failure must be retried even after the result is saved.
    if (ctx.container?.running) await ctx.container.destroy();
    return job;
  }
  if (!ctx.container?.running || Date.now() - job.startedAt > 13 * 60_000) {
    return finishRehearsal(ctx, { status: 'failed', error: 'Upgrade rehearsal sandbox stopped or timed out.' });
  }
  const process = await ctx.container.exec(['cat', '/tmp/purple-rehearsal-result.json']);
  const output = await process.output();
  if (output.exitCode !== 0) return job;
  const text = new TextDecoder().decode(output.stdout);
  if (text.length > 1500000) return finishRehearsal(ctx, { status: 'failed', error: 'Rehearsal result exceeds storage limits.' });
  let result;
  try { result = JSON.parse(text); }
  catch { return finishRehearsal(ctx, { status: 'failed', error: 'Invalid rehearsal result.' }); }
  if (!result || Array.isArray(result) || !['completed', 'failed'].includes(result.status)) {
    return finishRehearsal(ctx, { status: 'failed', error: 'Invalid rehearsal result.' });
  }
  return finishRehearsal(ctx, result);
}
