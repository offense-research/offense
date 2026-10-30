// Cloudflare serves matching static assets before invoking this fallback.
const appPages = new Set(['/account', '/app', '/activity', '/usage', '/billing', '/device', '/login', '/metrics', '/skill', '/health', '/legacy']);
const appPrefixes = ['/api/', '/v1/', '/assets/', '/skills/'];

export default {
  fetch(request, env) {
    const pathname = new URL(request.url).pathname;
    const page = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
    if (appPages.has(page) || pathname === '/mcp' || appPrefixes.some(prefix => pathname.startsWith(prefix))) {
      // Preserve the original host, query, method, headers, and streaming body.
      // The binding stays within this Cloudflare account; no public HTTP hop.
      return env.OFFENSE_APP.fetch(request);
    }
    return new Response('Not found', {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  },
};
