import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { landingCatalog, renderToolRows } from './catalog.mjs';
import { directoryPages } from './directory.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = new URL('../dist/', import.meta.url);

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const tools = landingCatalog();
let html = await readFile(`${root}index.html`, 'utf8');
if (!html.includes('<!-- canonical-tools:start -->') || !html.includes('<!-- canonical-tools:end -->')) throw new Error('Canonical catalog markers are missing.');
// Avoid Opengrep 1.32.0's partial parse of literal HTML-comment openers here.
html = html.replace(/[<]!-- canonical-tools:start -->[\s\S]*?[<]!-- canonical-tools:end -->/, `<!-- canonical-tools:start -->\n            ${renderToolRows(tools)}\n            <!-- canonical-tools:end -->`)
  .replace(/(data-scanner-count>)\d+/g, `$1${Object.keys(tools).length}`)
  .replace(/(id="catalog-count"[^>]*>)\d+ tools/, `$1${Object.keys(tools).length} tools`);
await writeFile(new URL('index.html', output), html);
await cp(`${root}src`, new URL('src/', output), { recursive: true });
await cp(`${root}public`, output, { recursive: true });
const pages = directoryPages();
await mkdir(new URL('tools/', output), { recursive: true });
for (const [path, page] of pages) await writeFile(new URL(path, output), page);
const sitemap = await readFile(`${root}public/sitemap.xml`, 'utf8');
await writeFile(new URL('sitemap.xml', output), sitemap.replace('</urlset>',
  [...pages.keys()].map(path => `  <url><loc>https://offense.sh/${path.replace(/\.html$/, '')}</loc></url>`).join('\n') + '\n</urlset>'));
await writeFile(new URL('src/catalog.js', output), `// Built from the canonical Offense catalog and reviewed landing descriptions.\nexport const toolDetails = ${JSON.stringify(tools, null, 2)};\nexport const scannerToolCount = ${Object.keys(tools).length};\nexport const scannerEngineCount = ${new Set(Object.values(tools).map(tool => tool.engine)).size};\n`);
// These are generated once by the root build. Never keep a second editable copy
// in site/public, where static assets would silently shadow newer app releases.
const publicRoot = new URL('../../public/', import.meta.url);
for (const directory of ['downloads', 'skills']) await cp(new URL(directory, publicRoot), new URL(`${directory}/`, output), { recursive: true });
console.log(`Built static site with ${Object.keys(tools).length} canonical tools and root client artifacts in dist/.`);
