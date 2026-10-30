import test from 'node:test';
import assert from 'node:assert/strict';
import { assessmentFailureSummary, recordAssessmentFailure } from '../workers/assessment-failure-metrics.js';

const fixture = entries => {
  const values = new Map(entries);
  return { values, get: key => values.get(key), put: (key, value) => values.set(key, value) };
};

test('tunnel causes retain only fixed counts and bounded duration ranges across reconstruction', () => {
  const kv = fixture();
  recordAssessmentFailure(kv, 'connection_deadline', 60_000);
  recordAssessmentFailure(kv, 'connection_deadline', 59_999);
  recordAssessmentFailure(kv, 'request_cancelled', 30_001);
  recordAssessmentFailure(kv, 'PRIVATE_PROVIDER_URL_TOKEN', Number.POSITIVE_INFINITY);
  const restored = fixture([...kv.values]);
  assert.equal(restored.get('assessment-network-failures'), 4);
  assert.deepEqual(assessmentFailureSummary(restored), {
    unknown: { count: 1 }, request_cancelled: { count: 1, minDurationMs: 30_001, maxDurationMs: 30_001 },
    connection_deadline: { count: 2, minDurationMs: 59_999, maxDurationMs: 60_000 }
  });
  assert.equal(JSON.stringify([...restored.values]).includes('PRIVATE_'), false);
});

test('old aggregate failures remain unknown and malformed stored diagnostics never leak private fields', () => {
  const kv = fixture([['assessment-network-failures', 3], ['assessment-network-failure-reasons', {
    private_url: { count: 2, raw: 'PRIVATE_SOURCE' },
    response_cancelled: { count: 1, minDurationMs: -1, maxDurationMs: 90_000, error: 'PRIVATE_TOKEN' }
  }]]);
  assert.deepEqual(assessmentFailureSummary(kv), { response_cancelled: { count: 1 }, unknown: { count: 2 } });
  recordAssessmentFailure(kv, 'websocket_error', 2);
  assert.equal(kv.get('assessment-network-failures'), 4);
  assert.equal(JSON.stringify(assessmentFailureSummary(kv)).includes('PRIVATE_'), false);
  assert.equal(JSON.stringify(kv.get('assessment-network-failure-reasons')).includes('PRIVATE_'), false);
});
