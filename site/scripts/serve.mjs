import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index < 0 ? fallback : args[index + 1];
};
const repositoryRoot = resolve(fileURLToPath(new URL('../', import.meta.url)));
const root = resolve(repositoryRoot, option('--directory', '.'));
const port = Number(option('--port', '4173'));
const host = option('--host', '127.0.0.1');
const types = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.mp4': 'video/mp4',
};

createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    let path = resolve(root, relative);
    if (!path.startsWith(`${root}${sep}`)) {
      response.writeHead(403).end('Forbidden');
      return;
    }
    // Development serves public assets at the same URLs used by the static build.
    if (root === repositoryRoot) {
      try {
        await stat(path);
      } catch {
        path = resolve(root, 'public', relative);
      }
    }
    if (!['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(405, { Allow: 'GET, HEAD' }).end();
      return;
    }
    // Match Cloudflare's extensionless .html routes without an SPA fallback.
    // /tools is also a directory, so check the sibling HTML before reading it.
    if (!extname(path)) {
      const html = `${path}.html`;
      if (await stat(html).then(info => info.isFile()).catch(() => false)) {
        if (pathname.endsWith('/')) {
          const url = new URL(request.url, 'http://localhost');
          response.writeHead(308, { Location: '/' + relative.replace(/\/+$/, '') + url.search }).end();
          return;
        }
        path = html;
      }
    }
    const body = await readFile(path);
    response.writeHead(200, {
      'Content-Type': types[extname(path)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    });
    response.end(request.method === 'HEAD' ? undefined : body);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
  }
}).listen(port, host, () => console.log(`Offense → http://${host}:${port}`));
