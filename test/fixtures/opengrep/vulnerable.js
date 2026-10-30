import { exec as runShell } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export function unsafeSql(req) {
  const id = req.query.id;
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  // ruleid: purple.js.request-sql-injection
  db.query(sql);
}

export function unsafeSqlOptions(req) {
  // ruleid: purple.js.request-sql-injection
  pool.query({ text: req.body.query, values: ['constant'] });
}

export function unsafePrisma(req) {
  // ruleid: purple.js.request-sql-injection
  prisma.$queryRawUnsafe(req.body.query);
}

export function unsafeShell(req) {
  const command = 'convert ' + req.body.filename;
  // ruleid: purple.js.request-command-injection
  runShell(command);
}

export function unsafeRead(req) {
  const filename = path.join('/srv/reports', req.params.name);
  // ruleid: purple.js.request-path-traversal
  fs.readFile(filename, () => {});
}

export function normalizedStillUnsafe(req) {
  // ruleid: purple.js.request-path-traversal
  fs.readFileSync(path.normalize(req.query.file));
}

export function parsedStillUnsafe(request) {
  const destination = new URL(request.query.url);
  // ruleid: purple.js.request-ssrf
  fetch(destination);
}

export async function honoProxy(c) {
  const destination = c.req.query('url');
  // ruleid: purple.js.request-ssrf
  return fetch(destination);
}

function readReport(filename) {
  // ruleid: purple.js.request-path-traversal
  return fs.readFileSync(filename);
}

export function readViaHelper(req) {
  return readReport(req.query.file);
}
