import test from 'node:test';
import assert from 'node:assert/strict';
import collector from '../workers/collector.js';

test('collector redacts credentials split across structured log arguments', async () => {
  const sent = [];
  await collector.tail([{
    scriptName: 'auth', eventTimestamp: Date.now(), outcome: 'ok',
    logs: [
      { level: 'warn', message: ['password:', 'correct-horse-battery-staple'] },
      { level: 'warn', message: ['token', 'portable-secret-value'] }
    ]
  }], { PURPLE_EVENTS: { sendBatch: async batch => sent.push(...batch) } });

  assert.equal(JSON.stringify(sent).includes('correct-horse-battery-staple'), false);
  assert.equal(JSON.stringify(sent).includes('portable-secret-value'), false);
  assert.equal(sent[0].body.logs[0].message, 'password=[REDACTED]');
  assert.equal(sent[0].body.logs[1].message, 'token [REDACTED]');
});
