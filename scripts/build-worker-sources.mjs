import { readFile, writeFile } from 'node:fs/promises';

// Needed by the Worker installer and its Node tests, without a cloud account
// or a Wrangler deployment build. Generated content is source, never secrets.
await writeFile(new URL('../workers/source-text.generated.js', import.meta.url),
  `export const collectorCode = ${JSON.stringify(await readFile(new URL('../workers/collector.js', import.meta.url), 'utf8'))};\n` +
  `export const forwarderCode = ${JSON.stringify(await readFile(new URL('../workers/forwarder.js', import.meta.url), 'utf8'))};\n`);
