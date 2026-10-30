import test from 'node:test';
import assert from 'node:assert/strict';
import { assessmentDns } from '../server/assessment-dns.js';

test('fixed DNS resolver uses the Workers-compatible no-follow mode and extracts only requested records', async () => {
  const calls = [];
  const result = await assessmentDns('app.purpleteam.sh', 'A', async (url, options) => {
    calls.push({ url, options });
    return Response.json({ Status: 0, Answer: [{ type: 1, data: '104.21.1.2' }, { type: 28, data: '2606:4700::1' }] });
  });
  assert.equal(calls[0].options.redirect, 'manual');
  assert.equal(new URL(calls[0].url).origin, 'https://cloudflare-dns.com');
  assert.deepEqual(result, ['104.21.1.2']);
});

test('resolver redirects are rejected without following another destination', async () => {
  let calls = 0;
  await assert.rejects(() => assessmentDns('app.purpleteam.sh', 'A', async () => {
    calls++; return new Response(null, { status: 302, headers: { location: 'https://elsewhere.invalid/dns' } });
  }), /DNS is unavailable/);
  assert.equal(calls, 1);
});
