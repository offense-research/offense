// Receives only a short-lived, manifest-scoped upload session on stdin.
// The JSON result is consumed by the deployment orchestrator, not logged.
import { readFile } from 'node:fs/promises';

async function readSession() {
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  process.stdin.setEncoding('utf8');
  process.stdin.resume();
  process.stdout.write('Ready for asset upload session on stdin (input hidden).\n');
  return new Promise((resolve, reject) => {
    let input = '';
    const receive = chunk => {
      input += chunk;
      if (!input.includes('\n')) return;
      process.stdin.off('data', receive);
      process.stdin.pause();
      if (process.stdin.isTTY) process.stdin.setRawMode(false);
      try { resolve(JSON.parse(input.trim())); } catch { reject(new Error('Invalid upload session.')); }
    };
    process.stdin.on('data', receive);
  });
}

const { accountId, jwt, buckets } = await readSession();
const site = JSON.parse(await readFile(new URL('../.cloudflare-build/bundle.json', import.meta.url), 'utf8'));
let completionToken = buckets.length === 0 ? jwt : undefined;
let uploadedFiles = 0;
for (const bucket of buckets) {
  const form = new FormData();
  for (const hash of bucket) {
    const file = site.files[hash];
    if (!file) throw new Error('Upload session requested an unknown file.');
    form.append(hash, new Blob([file.base64], { type: file.contentType }), hash);
  }
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/assets/upload?base64=true`, {
    method: 'POST', headers: { Authorization: `Bearer ${jwt}` }, body: form,
    redirect: 'manual', signal: AbortSignal.timeout(45000),
  });
  if (!response.ok) throw new Error(`Cloudflare asset transfer failed: HTTP ${response.status}.`);
  const result = await response.json();
  if (result.success === false) throw new Error('Cloudflare rejected the asset transfer.');
  completionToken = result.result?.jwt || result.jwt || completionToken;
  uploadedFiles += bucket.length;
}
if (!completionToken) throw new Error('No completion token returned.');
process.stdout.write(JSON.stringify({ completionToken, uploadedFiles }) + '\n');
