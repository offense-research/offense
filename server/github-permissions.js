// Scanning never requests repository writes or user/account permissions.
export const GITHUB_SCAN_PERMISSIONS = Object.freeze({ contents: 'read' });

export function installationTokenRequest(repository) {
  // Inventory needs repository metadata only. Code-read tokens must name a repo.
  if (repository === undefined) return { permissions: { metadata: 'read' } };
  const parts = typeof repository === 'string' ? repository.split('/') : [];
  if (parts.length !== 2 || parts.some(part => !/^[A-Za-z0-9_.-]+$/.test(part) || part === '.' || part === '..')) {
    throw new Error('A valid owner/repository is required for repository code access.');
  }
  return { permissions: { ...GITHUB_SCAN_PERMISSIONS }, repositories: [parts[1]] };
}
