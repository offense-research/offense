import { readdir } from 'node:fs/promises';
import path from 'node:path';

// Lockfiles define installation boundaries, including independent packages in
// repositories whose root test script delegates to api/, links/, or apps/.
export async function npmProjects(root) {
  const ignored = new Set(['node_modules', '.git', '.wrangler', '.next', '.expo', 'vendor', 'coverage']);
  const projects = [];
  let visited = 0;
  async function walk(relative, depth) {
    if (++visited > 10000 || depth > 12) throw new Error('Repository exceeds dependency setup scan limits.');
    const entries = await readdir(path.join(root, relative), { withFileTypes: true });
    if (entries.some(entry => entry.isFile() && ['package-lock.json', 'npm-shrinkwrap.json'].includes(entry.name))) {
      projects.push(relative || '.');
      if (projects.length > 20) throw new Error('Repository has more than 20 independent npm lockfiles.');
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory() && !ignored.has(entry.name)) await walk(path.join(relative, entry.name), depth + 1);
    }
  }
  await walk('', 0);
  return projects;
}
