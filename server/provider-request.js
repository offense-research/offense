export async function providerJson(url, options = {}, fetchImpl = fetch) {
  const headers = new Headers(options.headers);
  const host = new URL(url).hostname;
  // Unlike Node fetch, Workers fetch does not provide a default User-Agent.
  // GitHub rejects these requests with a plain-text 403 before authentication.
  if ((host === 'api.github.com' || host === 'github.com') && !headers.get('User-Agent')?.trim()) {
    headers.set('User-Agent', 'purple');
  }
  const response = await fetchImpl(url, { ...options, headers, signal: AbortSignal.timeout(10000) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error_description || data.message || `Provider returned ${response.status}`);
  return data;
}
