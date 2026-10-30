const PRODUCT_ORIGINS = ['https://offense.sh', 'https://app.purpleteam.sh'];

// Aliases are operator-maintained exact origins, never caller-supplied URLs.
export function publicOrigins(base) {
  const url = new URL(base);
  return new Set([url.origin, ...(PRODUCT_ORIGINS.includes(url.origin) ? PRODUCT_ORIGINS : [])]);
}
export function requestPublicOrigin(req, base) {
  const host = req.get('host');
  return [...publicOrigins(base)].find(origin => new URL(origin).host === host?.toLowerCase()) || new URL(base).origin;
}
export function productOrigin(base) {
  return PRODUCT_ORIGINS.includes(new URL(base).origin) ? PRODUCT_ORIGINS[0] : new URL(base).origin;
}
export const LOGIN_RETURN_PATHS = ['/metrics', '/billing', '/account', '/activity', '/usage', '/device', '/app', '/legacy'];
