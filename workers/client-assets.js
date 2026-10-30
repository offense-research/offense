const canonical = 'https://offense.sh';

export function isClientAsset(path) {
  return path.startsWith('/downloads/') || path.startsWith('/share/') || path === '/skills/offense/scripts/cli.mjs';
}

// Public client distributions live on the static site. Legacy installations
// retain byte-for-byte downloads without a redirect or forwarded credentials.
export async function legacyClientAsset(request, fetchImpl = fetch) {
  const url = new URL(request.url);
  if (!isClientAsset(url.pathname) || !['GET', 'HEAD'].includes(request.method) || url.origin === canonical)
    return new Response('Not found', { status: 404 });
  const headers = new Headers();
  if (url.pathname.startsWith('/share/') && request.headers.has('range')) headers.set('range', request.headers.get('range'));
  return fetchImpl(new URL(url.pathname, canonical), { method: request.method, headers, redirect: 'manual' });
}
