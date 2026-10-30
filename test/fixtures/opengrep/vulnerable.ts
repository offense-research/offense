import { readFile as read } from 'node:fs/promises';

export async function nextProxy(request: Request) {
  const destination = new URL(request.url).searchParams.get('destination');
  // ruleid: purple.js.request-ssrf
  return fetch(destination);
}

export async function expressRead(req: Request) {
  // ruleid: purple.js.request-path-traversal
  return read(req.params.filename);
}
