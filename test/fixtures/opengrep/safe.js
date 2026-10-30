import { execFile } from 'node:child_process';
import fs from 'node:fs';

export async function safeQueries(req) {
  db.query('SELECT * FROM users WHERE name = $1', [req.query.name]);
  pool.query({ text: 'SELECT * FROM users WHERE name = $1', values: [req.query.name] });
  connection.execute('SELECT * FROM users WHERE name = ?', [req.query.name]);
  db.query('SELECT * FROM users WHERE id = ' + Number(req.query.id));
}

export function fixedExecutable(req) {
  execFile('/usr/bin/printf', ['%s', req.body.message], { shell: false });
}

export function fixedRead(req) {
  fs.readFile('/srv/reports/index.json', () => {});
  fs.readFile('/srv/reports/' + Number.parseInt(req.params.id, 10) + '.json', () => {});
}

export async function fixedDestination(req) {
  return fetch('https://api.example.test/submit', {
    method: 'POST',
    body: JSON.stringify(req.body)
  });
}
