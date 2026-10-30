import { Buffer } from 'node:buffer';
import { artifactHeaders, limitArtifactStream } from '../server/scan-artifacts.js';

export async function uploadScanArtifact(request, env, state, { fixedLengthStream = globalThis.FixedLengthStream } = {}) {
  const url = new URL(request.url);
  let publicOrigin = '';
  try { publicOrigin = new URL(env.PUBLIC_URL).origin; } catch { /* Fail closed below. */ }
  if (url.protocol !== 'https:' || url.origin !== publicOrigin || request.headers.has('origin'))
    return new Response('Not found', { status: 404 });
  if (!env.SCAN_ARTIFACTS) return Response.json({ error: 'Artifact uploads are unavailable.' }, { status: 503 });
  const token = request.headers.get('authorization')?.replace(/^Bearer /, '') || '';
  let reservation, metadataParsed = false, phase = 'headers';
  try {
    const metadata = artifactHeaders(request);
    metadataParsed = true;
    // This RPC authenticates and reserves a server-generated R2 key before the body is consumed.
    phase = 'reservation';
    reservation = await state.beginArtifactUpload(token, metadata);
    if (!request.body) throw Object.assign(new Error('Artifact body is empty.'), { status: 400 });
    const expectedHash = Uint8Array.from(Buffer.from(metadata.sha256, 'hex')).buffer;
    phase = 'stream';
    if (typeof fixedLengthStream !== 'function') throw new Error('Bounded artifact streaming is unavailable.');
    const sized = new fixedLengthStream(metadata.size);
    const copying = limitArtifactStream(request.body, metadata.size).pipeTo(sized.writable);
    phase = 'r2-put';
    const [stored] = await Promise.all([
      env.SCAN_ARTIFACTS.put(reservation.objectKey, sized.readable, { sha256: expectedHash }), copying
    ]);
    phase = 'checksum';
    const storedHash = stored?.checksums?.sha256 && Buffer.from(stored.checksums.sha256).toString('hex');
    if (!stored || stored.size !== metadata.size || storedHash !== metadata.sha256)
      throw Object.assign(new Error('Artifact size or checksum did not match.'), { status: 400 });
    phase = 'finalization';
    const result = await state.finishArtifactUpload(token, reservation.id, stored.size);
    return Response.json(result, { status: 201, headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    if (metadataParsed && !Number.isInteger(error?.status))
      console.error('Scan artifact upload failed', { phase, category: error?.name || 'Error' });
    if (reservation) {
      await env.SCAN_ARTIFACTS.delete(reservation.objectKey).catch(() => {});
      await state.abandonArtifactUpload(token, reservation.id).catch(() => {});
    }
    const status = !metadataParsed ? 400 : Number.isInteger(error?.status) && error.status >= 400 && error.status <= 503 ? error.status :
      /^Artifact body (exceeds|is shorter)/.test(error?.message || '') ? 400 : 502;
    const messages = { 400: 'Invalid artifact upload.', 401: 'A valid Purple scan key is required.',
      403: 'Artifact upload is forbidden.', 404: 'Artifact upload was not found.',
      409: 'Artifact upload is invalid or expired.', 429: 'Artifact upload limit reached.',
      503: 'Artifact uploads are unavailable.' };
    return Response.json({ error: messages[status] || 'Artifact upload failed.' },
      { status, headers: { 'Cache-Control': 'no-store' } });
  }
}
