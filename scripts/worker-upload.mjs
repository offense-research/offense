// Keep the credential-bearing JSON in a private temporary file. The connected
// upload receives its path, never secret values in command arguments or logs.
// Account for base64 expansion when bounding a Worker with embedded assets.
export function workerUpload({ metadata, module, accountId, workerId, maximumBytes = 5_000_000 }) {
  if (!metadata || metadata.main_module !== 'app-staging.js' || !Buffer.isBuffer(module) ||
      !/^[a-f0-9]{32}$/.test(accountId || '') || !/^[a-f0-9]{32}$/.test(workerId || '') ||
      !Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw Error('Invalid Worker upload inputs.');
  const payload = { ...metadata, account_id: accountId, worker_id: workerId,
    modules: [{ name: metadata.main_module, content_type: 'application/javascript+module', content_base64: module.toString('base64') }] };
  const body = Buffer.from(JSON.stringify(payload));
  if (body.byteLength > maximumBytes) throw Error('Worker exceeds the bounded version upload budget.');
  return { body, contentType: 'application/json' };
}
