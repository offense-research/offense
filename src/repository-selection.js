export function selectRepository(repositories, snapshots, selected) {
  return repositories.some(item => `${item.installationId}:${item.repository}` === selected)
    ? selected : [...repositories].sort((a, b) => {
      const count = item => snapshots.find(value => value.repository === item.repository && value.installationId === item.installationId)?.vulnerabilityCheck?.findings?.length || 0;
      return count(b) - count(a);
    }).map(item => `${item.installationId}:${item.repository}`)[0];
}
