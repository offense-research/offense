import test from 'node:test';
import assert from 'node:assert/strict';
import { workerUpload } from '../scripts/worker-upload.mjs';

const ids = { accountId: 'a'.repeat(32), workerId: 'b'.repeat(32) };

test('version upload preserves exact Worker bytes and multiline secret metadata in the connected API shape', () => {
  const module = Buffer.from('export default {fetch(){return new Response("Purple ✳");}};\n');
  const metadata = { main_module: 'app-staging.js', bindings: [{ name: 'KEY', type: 'secret_text', text: 'test\nmultiline\nvalue' }],
    exports: { PurpleState: { type: 'durable-object', storage: 'sqlite' } }, compatibility_date: '2026-10-21', compatibility_flags: ['nodejs_compat'] };
  const upload = workerUpload({ metadata, module, ...ids });
  const payload = JSON.parse(upload.body);
  assert.deepEqual(payload.bindings, metadata.bindings);
  assert.deepEqual(payload.exports, metadata.exports);
  assert.equal(payload.account_id, ids.accountId); assert.equal(payload.worker_id, ids.workerId);
  assert.deepEqual(Buffer.from(payload.modules[0].content_base64, 'base64'), module);
  assert.equal(payload.modules[0].content_type, 'application/javascript+module');
  assert.equal(upload.contentType, 'application/json');
});

test('embedded-asset Worker fits the upload budget while oversized or invalid artifacts are rejected', () => {
  const module = Buffer.alloc(3_200_000, 65);
  const upload = workerUpload({ metadata: { main_module: 'app-staging.js' }, module, ...ids });
  assert.ok(upload.body.byteLength < 5_000_000);
  assert.ok(upload.body.byteLength > 4_000_000);
  assert.ok(Buffer.byteLength(module.toString('base64')) > 4_000_000);
  assert.throws(() => workerUpload({ metadata: { main_module: 'app-staging.js' }, module, ...ids, maximumBytes: 100 }), /exceeds/);
  assert.throws(() => workerUpload({ metadata: { main_module: '../other.js' }, module, ...ids }), /Invalid/);
});
