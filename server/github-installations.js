export function purpleInstallations(data, appSlug) {
  return (data.installations || [])
    .filter(item => item.app_slug === appSlug && Number.isSafeInteger(item.id) && item.id > 0 &&
      item.account && typeof item.account.login === 'string')
    .map(item => ({ installationId: item.id, account: item.account.login }));
}

export function workspaceInstallations(session) {
  const seen = new Set();
  return [session.github, ...(Array.isArray(session.githubInstallations) ? session.githubInstallations : [])]
    .filter(item => {
      if (!item || !Number.isSafeInteger(Number(item.installationId)) || Number(item.installationId) <= 0 ||
          typeof item.account !== 'string' || seen.has(Number(item.installationId))) return false;
      seen.add(Number(item.installationId));
      return true;
    })
    .map(item => ({ installationId: Number(item.installationId), account: item.account }));
}

export function connectInstallation(session, installation) {
  const connected = workspaceInstallations(session);
  if (!connected.some(item => item.installationId === installation.installationId)) connected.push(installation);
  if (!session.github) session.github = installation;
  session.githubInstallations = connected;
}

// Only pass installations returned for the signed-in GitHub user, never the
// App-wide installation list, which can include other customers' accounts.
export function resolveInstallationConnections(session, available, { installationId, sync = false } = {}) {
  if (installationId !== undefined) {
    const requested = available.find(item => item.installationId === installationId);
    if (!requested) throw new Error('The installation is not available to your GitHub user.');
    return { connections: [requested], choices: [] };
  }
  if (sync) return { connections: available, choices: [] };
  const connected = new Set(workspaceInstallations(session).map(item => item.installationId));
  const additional = available.filter(item => !connected.has(item.installationId));
  return additional.length > 1
    ? { connections: [], choices: additional }
    : { connections: additional, choices: [] };
}
