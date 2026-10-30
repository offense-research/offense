import { assessmentResolvers } from '../server/assessment-dns.js';
import { publicWebScanAddress, webScanOrigin } from '../server/web-scan-target.js';
import { assessmentFailureReason } from './assessment-egress-failure.js';
export { ASSESSMENT_FAILURE_REASONS, assessmentFailureReason } from './assessment-egress-failure.js';

export const ASSESSMENT_GATEWAY = 'purple-assessment-egress.invalid';
const PROVIDERS = Object.freeze({ 'prowler-cloudflare': ['api.cloudflare.com'],
  'openssf-scorecard': ['api.scorecard.dev'],
  'trufflehog-verified': ['api.github.com', 'slack.com'] });

export function assessmentNetworkPolicy(request) {
  if (PROVIDERS[request.tool]) return { tool: request.tool, hosts: PROVIDERS[request.tool], maxConnections: request.tool === 'openssf-scorecard' ? 1 : 200,
    expiresAt: Date.now() + 10 * 60_000 };
  const origin = webScanOrigin(request.options?.target);
  const addresses = request.options?.resolvedAddresses;
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > 32 || addresses.some(ip => !publicWebScanAddress(ip)))
    throw new Error('Verified target addresses are unavailable.');
  return { tool: request.tool, hosts: [new URL(origin).hostname], addresses, maxConnections: request.tool === 'httpx' ? 1 : request.tool === 'katana' ? 50 : 200,
    expiresAt: Date.now() + 10 * 60_000 };
}

export async function assessmentDestination(policy, host, resolvers = assessmentResolvers) {
  if (!policy || policy.expiresAt <= Date.now() || !policy.hosts.includes(host) ||
      !/^[a-z0-9.-]+$/.test(host)) throw new Error('Assessment destination is outside the job scope.');
  const addresses = policy.addresses || await resolvers.resolveAddresses(host);
  if (!Array.isArray(addresses) || !addresses.length || addresses.some(ip => !publicWebScanAddress(ip)))
    throw new Error('Assessment destination must resolve exclusively to public IPs.');
  return addresses.find(ip => !ip.includes(':')) || addresses[0];
}

export function limitedTunnel(stream, limit = 8 * 1024 * 1024) {
  let bytes = 0;
  return stream.pipeThrough(new TransformStream({ transform(chunk, controller) {
    if ((bytes += chunk.byteLength) > limit) throw new Error('Assessment connection exceeded its byte budget.');
    controller.enqueue(chunk);
  } }));
}

// A tunnel can fail after its HTTP response headers have already been sent.
// Keep both streaming directions under one lifecycle so those failures still
// reach the Durable Object before a scan can be treated as complete.
export function assessmentTunnel({ onFailure, onClose = async () => {},
  limitBytes = 8 * 1024 * 1024, timeoutMs = 60_000 } = {}) {
  if (typeof onFailure !== 'function' || typeof onClose !== 'function' ||
      !Number.isSafeInteger(limitBytes) || limitBytes < 1 || limitBytes > 8 * 1024 * 1024 ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000)
    throw new Error('Invalid assessment tunnel lifecycle.');
  const abort = new AbortController(), streams = new Set();
  let state = 'open', bytes = 0, failure, cleanup, finish, firstReason;
  const startedAt = Date.now();
  const finished = new Promise(resolve => { finish = resolve; });
  const genericError = () => Object.assign(new Error('Assessment tunnel did not complete.'),
    firstReason ? { assessmentFailureReason: firstReason } : {});
  const cleanupOnce = () => {
    if (cleanup) return cleanup;
    clearTimeout(timer);
    abort.abort(genericError());
    for (const entry of streams) {
      // Abort the source even if its peer has stopped pulling. A hostile or
      // broken stream's cancellation promise must not hold cleanup open.
      void entry.reader.cancel().catch(() => {});
    }
    cleanup = Promise.resolve().then(onClose).catch(() => {});
    return cleanup;
  };
  const fail = (reason = 'unknown') => {
    if (failure) return failure;
    if (state !== 'open') return cleanup || Promise.resolve();
    state = 'failed'; firstReason = assessmentFailureReason(reason);
    failure = (async () => {
      const closed = cleanupOnce();
      let recorded = true;
      try { await onFailure(firstReason, { durationMs: Math.max(0, Math.min(timeoutMs, Math.round(Date.now() - startedAt))) }); } catch { recorded = false; }
      // Do not pass TLS bytes, upstream exception strings or credentials into
      // scanner-visible errors, logs or the persistent failure counter.
      for (const entry of streams) try { entry.controller.error(genericError()); } catch {}
      await closed;
      finish({ failed: true, failureRecorded: recorded });
    })();
    return failure;
  };
  const close = async () => {
    if (failure) return failure;
    if (state !== 'open') return cleanup;
    state = 'closing';
    await cleanupOnce();
    state = 'closed'; finish({ failed: false, failureRecorded: false });
  };
  const timer = setTimeout(() => { void fail('connection_deadline'); }, timeoutMs);

  const wrap = (source, direction) => {
    if (state !== 'open' || !source || typeof source.getReader !== 'function' ||
        !['request', 'response'].includes(direction)) throw new Error('Assessment tunnel stream is unavailable.');
    const entry = { reader: source.getReader(), controller: null };
    streams.add(entry);
    return new ReadableStream({
      start(controller) { entry.controller = controller; },
      async pull(controller) {
        try {
          const result = await entry.reader.read();
          if (state === 'failed') { await failure; return; }
          if (state !== 'open') { try { controller.close(); } catch {} return; }
          if (result.done) {
            streams.delete(entry); entry.reader.releaseLock(); controller.close();
            if (direction === 'response') await close();
            return;
          }
          if (!(result.value instanceof Uint8Array)) { await fail(`${direction}_stream_error`); return; }
          if ((bytes += result.value.byteLength) > limitBytes) {
            await fail('byte_budget'); return;
          }
          controller.enqueue(result.value);
        } catch {
          if (state === 'open') await fail(`${direction}_stream_error`);
          else if (failure) await failure;
          else try { controller.close(); } catch {}
        }
      },
      async cancel() {
        if (state === 'open') await fail(`${direction}_cancelled`);
        else if (failure) await failure;
        streams.delete(entry);
        await entry.reader.cancel().catch(() => {});
      }
    });
  };
  return { signal: abort.signal, finished, wrap, fail, close };
}
