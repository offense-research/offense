export function createCloudflareAuth({ clientId, clientSecret, encrypt, decrypt, fetchImpl = fetch }) {
  const refreshing = new Map();
  async function accessToken(workspaceId, connection, save) {
    if (!connection) throw new Error('Connect Cloudflare first.');
    if (!connection.refreshToken || (connection.expiresAt && connection.expiresAt > Date.now() + 60_000)) return decrypt(connection.accessToken);
    let pending = refreshing.get(workspaceId);
    if (!pending) {
      pending = (async () => {
        const response = await fetchImpl('https://dash.cloudflare.com/oauth2/token', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}` },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: decrypt(connection.refreshToken) }),
          signal: AbortSignal.timeout(15000)
        });
        const token = await response.json();
        if (!response.ok || !token.access_token) throw new Error('Cloudflare authorization expired. Reconnect Cloudflare to continue.');
        return { accessToken: encrypt(token.access_token),
          refreshToken: token.refresh_token ? encrypt(token.refresh_token) : connection.refreshToken,
          expiresAt: Date.now() + (Number(token.expires_in) || 3600) * 1000 };
      })();
      refreshing.set(workspaceId, pending);
      pending.finally(() => { if (refreshing.get(workspaceId) === pending) refreshing.delete(workspaceId); }).catch(() => {});
    }
    Object.assign(connection, await pending);
    save();
    return decrypt(connection.accessToken);
  }
  return { accessToken };
}
