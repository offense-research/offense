import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// Exercise the Zod implementation used by the production MCP SDK, rather than
// assuming the root package is the copy that validates incoming messages.
const require = createRequire(import.meta.url);
const sdkRequire = createRequire(require.resolve('@modelcontextprotocol/sdk/server/index.js'));
const { z } = sdkRequire('zod/v4');

for (const container of ['array', 'set', 'map']) {
  test(`Zod rejects an oversized ${container} before walking attacker-controlled elements`, () => {
    let parsed = 0;
    const value = z.preprocess(input => {
      parsed += 1;
      return input;
    }, z.string());
    const schema = container === 'map' ? z.map(z.string(), value).check(z.maxSize(2)) : z[container](value).max(2);
    const values = Array.from({ length: 256 }, (_, i) => i);
    const input = container === 'array' ? values
      : container === 'set' ? new Set(values)
        : new Map(values.map((entry, index) => [String(index), entry]));
    const result = schema.safeParse(input);

    assert.equal(result.success, false);
    assert.equal(parsed, 0, 'size limits must stop element work before validation can allocate per-element errors');
    assert.equal(result.error.issues.length, 1, 'oversized input must produce a bounded size error');
    assert.equal(result.error.issues[0].code, 'too_big');
  });

  test(`Zod still validates normal ${container} contents and rejects invalid elements within the limit`, () => {
    const schema = container === 'map' ? z.map(z.string(), z.string()).check(z.maxSize(2)) : z[container](z.string()).max(2);
    const input = values => container === 'array' ? values
      : container === 'set' ? new Set(values)
        : new Map(values.map((entry, index) => [String(index), entry]));

    assert.deepEqual(schema.parse(input(['ok', 'also ok'])), input(['ok', 'also ok']));
    const result = schema.safeParse(input([42]));
    assert.equal(result.success, false);
    assert.equal(result.error.issues[0].code, 'invalid_type');
  });
}
