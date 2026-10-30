// Assets are compressed inside the deployment bundle. Return their original
// bytes as a stream; transport encoding remains Cloudflare's responsibility.
export function assetBody(asset) {
  const bytes = Uint8Array.from(atob(typeof asset === 'string' ? asset : asset.gzip), char => char.charCodeAt(0));
  if (typeof asset === 'string') return bytes;
  return new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } })
    .pipeThrough(new DecompressionStream('gzip'));
}

const contentTypes = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.md': 'text/markdown; charset=utf-8', '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.tgz': 'application/gzip',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2'
};

export function staticAssetResponse(assets, path, request) {
  const exact = assets[path];
  if (!exact && ['/assets/', '/skills/', '/share/', '/downloads/'].some(prefix => path.startsWith(prefix))) {
    return new Response('Not found', { status: 404 });
  }
  const asset = exact || assets['/index.html'];
  const extension = exact ? path.slice(path.lastIndexOf('.')) : '.html';
  const headers = new Headers({
    'content-type': contentTypes[extension] || 'application/octet-stream',
    'cache-control': asset === assets['/index.html'] || /^\/skills\/[^/]+\/manifest\.json$/.test(path) ? 'no-store' : ['/skills/', '/downloads/'].some(prefix => path.startsWith(prefix)) ? 'public, max-age=300' : 'public, max-age=31536000, immutable',
    'x-content-type-options': 'nosniff'
  });
  if (path.startsWith('/downloads/')) {
    const filename = path.slice('/downloads/'.length);
    if (/^[A-Za-z0-9._-]+$/.test(filename)) headers.set('content-disposition', `attachment; filename="${filename}"`);
  }
  if (path.startsWith('/share/')) headers.set('access-control-allow-origin', '*');
  // Media is stored uncompressed by the packager so single-range playback can
  // slice the original bytes without buffering/decompressing the whole bundle.
  if (['.mp4', '.webm'].includes(extension)) {
    if (typeof asset !== 'string') return new Response('Invalid media packaging', { status: 500 });
    const bytes = assetBody(asset), size = bytes.byteLength;
    headers.set('accept-ranges', 'bytes'); headers.set('content-length', String(size));
    const range = request.method === 'GET' && request.headers.get('range');
    if (range) {
      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      let start = match?.[1] ? Number(match[1]) : null;
      let end = match?.[2] ? Number(match[2]) : null;
      if (start === null && end !== null) { start = Math.max(0, size - end); end = size - 1; }
      else end = end === null ? size - 1 : Math.min(end, size - 1);
      if (!match || start === null || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || end < start || start < 0) {
        headers.set('content-range', `bytes */${size}`); headers.set('content-length', '0');
        return new Response(null, { status: 416, headers });
      }
      headers.set('content-range', `bytes ${start}-${end}/${size}`);
      headers.set('content-length', String(end - start + 1));
      return new Response(bytes.slice(start, end + 1), { status: 206, headers });
    }
    return new Response(request.method === 'HEAD' ? null : bytes, { headers });
  }
  return new Response(request.method === 'HEAD' ? null : assetBody(asset), { headers });
}
