import test from 'node:test';
import assert from 'node:assert/strict';
import { createAutoRefresh, mergeDrafts } from '../src/auto-refresh.js';

function environment() {
  let now = 0, sequence = 0;
  const queue = new Map(), events = new EventTarget(), page = new EventTarget(), network = { onLine: true };
  page.hidden = false;
  return { window: events, document: page, navigator: network,
    timers: { setTimeout(fn, delay) { const id = ++sequence; queue.set(id, { at: now + delay, fn }); return id; }, clearTimeout(id) { queue.delete(id); } },
    async tick(ms = 0) {
      const end = now + ms;
      for (let limit = 0; limit < 100; limit++) {
        await Promise.resolve(); await Promise.resolve();
        const next = [...queue.entries()].filter(([, item]) => item.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) { now = end; return; }
        now = next[1].at; queue.delete(next[0]); next[1].fn();
      }
      throw new Error('Unbounded refresh loop');
    }
  };
}

test('automatic updates pause when hidden/offline, resume on return, and stop after unmount', async () => {
  const env = environment(); let calls = 0;
  const stop = createAutoRefresh(async () => { calls++; }, { ...env, interval: 10 });
  await env.tick(); assert.equal(calls, 1);
  await env.tick(10); assert.equal(calls, 2);
  env.document.hidden = true; env.document.dispatchEvent(new Event('visibilitychange'));
  await env.tick(100); assert.equal(calls, 2);
  env.document.hidden = false; env.document.dispatchEvent(new Event('visibilitychange')); env.window.dispatchEvent(new Event('focus'));
  await env.tick(); assert.equal(calls, 3);
  env.navigator.onLine = false; env.window.dispatchEvent(new Event('offline'));
  await env.tick(100); assert.equal(calls, 3);
  env.navigator.onLine = true; env.window.dispatchEvent(new Event('online'));
  await env.tick(); assert.equal(calls, 4);
  stop(); env.window.dispatchEvent(new Event('focus')); await env.tick(100); assert.equal(calls, 4);
});

test('slow reads never overlap and aborted reads restart immediately after returning', async () => {
  const env = environment(); const signals = []; let complete;
  const stop = createAutoRefresh(signal => { signals.push(signal); return new Promise(resolve => { complete = resolve; }); }, { ...env, interval: 10 });
  await env.tick(); await env.tick(100); env.window.dispatchEvent(new Event('focus')); await env.tick(); assert.equal(signals.length, 1);
  env.document.hidden = true; env.document.dispatchEvent(new Event('visibilitychange')); assert.equal(signals[0].aborted, true);
  env.document.hidden = false; env.document.dispatchEvent(new Event('visibilitychange')); complete();
  await env.tick(); assert.equal(signals.length, 2);
  stop(); assert.equal(signals[1].aborted, true); complete(); await env.tick(100); assert.equal(signals.length, 2);
});

test('failed automatic reads back off and successful recovery restores the normal interval', async () => {
  const env = environment(); let calls = 0;
  const stop = createAutoRefresh(async () => { if (++calls <= 2) throw new Error('Provider unavailable'); }, { ...env, interval: 10 });
  await env.tick(); assert.equal(calls, 1);
  await env.tick(19); assert.equal(calls, 1); await env.tick(1); assert.equal(calls, 2);
  await env.tick(39); assert.equal(calls, 2); await env.tick(1); assert.equal(calls, 3);
  await env.tick(10); assert.equal(calls, 4); stop();
});

test('automatic updates merge saved links without replacing unsaved repository choices', () => {
  assert.deepEqual(mergeDrafts({ api: 'draft', links: 'old', extra: '' }, { api: 'old', links: 'old', extra: 'saved' },
    { api: 'remote', links: 'new', extra: 'remote', added: 'new' }), { api: 'draft', links: 'new', extra: '', added: 'new' });
});
