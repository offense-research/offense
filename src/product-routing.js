const legacySections = new Set(['dependencies', 'connections', 'collector', 'overview', 'investigations', 'events', 'worker-repositories']);

// Bookmarked V1 workflows stay reachable while fresh visits open the agent console.
export function resolveProductRoute(pathname, hash = '', search = '') {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/device') return { surface: 'device' };
  if (path === '/metrics') return { surface: 'metrics' };
  if (path === '/skill') return { surface: 'skill' };
  if (path === '/legacy' || new URLSearchParams(search).get('payment') === 'returned') return { surface: 'legacy' };
  if (['/', '/app', '/login'].includes(path) && legacySections.has(hash.slice(1))) return { surface: 'legacy' };
  return { surface: 'console', section: ['/activity', '/usage'].includes(path) ? 'activity' : path === '/billing' ? 'billing' : path === '/account' ? 'keys' : 'start' };
}
