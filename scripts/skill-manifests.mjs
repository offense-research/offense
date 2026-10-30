import { readFile, writeFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { validateRelease } from './skill-updater.mjs';

export const SKILL_FILES = {
  offense: ['SKILL.md', 'references/install.md', 'references/verification.md', 'references/tools.md', 'references/local-tools.md', 'references/stack.md', 'scripts/offense.mjs', 'scripts/cli.mjs', 'scripts/update.mjs'],
  purple: ['SKILL.md', 'references/delivery.md', 'references/api-testing.md', 'references/hardened-containers.md', 'references/hosted-assessments.md', 'scripts/update.mjs', 'scripts/hosted-scan.mjs',
    'scripts/source-scan.mjs', 'scripts/api-test.mjs', 'scripts/api-test-image.mjs', 'scripts/hardened-image.mjs',
    'scripts/hosted-artifact-scan.mjs', 'scripts/hosted-assessment.mjs', 'scripts/git-history-bundle.mjs', 'scripts/purple.mjs',
    'scripts/metadata.mjs', 'scripts/pnpm.mjs', 'scripts/yaml.mjs', 'scripts/evidence.mjs', 'scripts/reachability.mjs',
    'scripts/syntax.mjs', 'scripts/workflow.mjs', 'scripts/rehearsal-runner.mjs'],
};

export async function buildSkillManifests(root = 'public/skills', historyFile = 'scripts/skill-release-history.json') {
  const history = JSON.parse(await readFile(historyFile, 'utf8'));
  for (const [skill, paths] of Object.entries(SKILL_FILES)) {
    const directory = path.join(root, skill), text = await readFile(path.join(directory, 'SKILL.md'), 'utf8');
    const version = text.match(/\n\s+version:\s*"([^"]+)"/)?.[1];
    const files = await Promise.all(paths.map(async file => {
      const filename = path.join(directory, file), info = await lstat(filename);
      if (!info.isFile() || info.isSymbolicLink()) throw Error('Cannot release a non-regular skill resource: ' + filename);
      const bytes = await readFile(filename);
      return { path: file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    }));
    const manifest = validateRelease({ schemaVersion: 1, skill, version, minimumNodeMajor: 20, files,
      previousReleases: history.packages[skill] || [] }, skill);
    await writeFile(path.join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  }
}
