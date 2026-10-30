// Paused while the product focuses on GitHub dependency discovery and fixes.
// Keep the runtime integration, collector and dashboards intact for re-enabling.
export const CLOUDFLARE_FEATURES = false;
const runtimeSections = new Set(['overview', 'investigations', 'events', 'worker-repositories', 'collector']);
export function productSection(target, connected) {
  if (!CLOUDFLARE_FEATURES && runtimeSections.has(target)) return connected ? 'dependencies' : 'connections';
  return target;
}
