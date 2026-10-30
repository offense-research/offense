// Regenerate the pure-data API image resource from its preferred editable files.
// This prepares text only: it performs no Docker, application or network work.
import { readFile, writeFile } from 'node:fs/promises';

const source = new URL('../tools/api-image/', import.meta.url);
const apiImageFiles = {
  Dockerfile: await readFile(new URL('Dockerfile', source), 'utf8'),
  'schemathesis-sandbox.py': await readFile(new URL('schemathesis-sandbox.py', source), 'utf8'),
  '.dockerignore': await readFile(new URL('.dockerignore', source), 'utf8'),
};
await writeFile(new URL('../tools/api-test-image.mjs', import.meta.url),
  `// Fixed, inspected image build inputs. Importing this file performs no I/O.\nexport const apiImageFiles = ${JSON.stringify(apiImageFiles)};\n`);
