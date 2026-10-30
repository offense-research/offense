import { collectorCode, forwarderCode } from './source-text.generated.js';
const apiRoot = 'https://api.cloudflare.com/client/v4';

export async function cloudflareApi(token, accountId, route, options = {}) {
  const response = await fetch(`${apiRoot}/accounts/${accountId}${route}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...options.headers },
    signal: AbortSignal.timeout(20000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.success === false) {
    const reason = data.errors?.map(error => error.message).filter(Boolean).join('; ') || `HTTP ${response.status}`;
    const error = new Error(response.status === 401 ? 'Cloudflare authorization expired. Reconnect your account and retry.' : response.status === 403 ? `Cloudflare needs additional permission. Reconnect with Workers Scripts Write and Queues Write. ${reason}` : reason);
    error.status = response.status;
    throw error;
  }
  return data.result;
}

export async function listWorkers(token, accountId) {
  const scripts = await cloudflareApi(token, accountId, '/workers/scripts');
  return (Array.isArray(scripts) ? scripts : []).map(script => script.id).filter(name => typeof name === 'string');
}

async function uploadWorker(token, accountId, name, code, bindings) {
  const form = new FormData();
  form.append('metadata', JSON.stringify({
    main_module: 'worker.js',
    compatibility_date: '2026-10-01',
    bindings
  }));
  form.append('worker.js', new Blob([code], { type: 'application/javascript+module' }), 'worker.js');
  await cloudflareApi(token, accountId, `/workers/scripts/${encodeURIComponent(name)}`, { method: 'PUT', body: form });
}

export async function updateCollector(token, install) {
  if (install.status !== 'installed' || !install.queue || !install.collector) throw new Error('The collector must be installed first.');
  await uploadWorker(token, install.accountId, install.collector, collectorCode, [
    { name: 'PURPLE_EVENTS', type: 'queue', queue_name: install.queue }
  ]);
}

export async function updateForwarder(token, install, ingestUrl, ingestToken) {
  if (install.status !== 'installed' || !install.forwarder) throw new Error('The forwarding Worker must be installed first.');
  await uploadWorker(token, install.accountId, install.forwarder, forwarderCode, [
    { name: 'PURPLE_INGEST_URL', type: 'secret_text', text: ingestUrl },
    { name: 'PURPLE_INGEST_TOKEN', type: 'secret_text', text: ingestToken }
  ]);
}

export async function installCollector({ token, accountId, sources, install, ingestUrl, ingestToken, save }) {
  if (!/^https:\/\//.test(ingestUrl)) throw new Error('A public HTTPS Purple ingest URL is required.');
  if (!Array.isArray(sources) || !sources.length || sources.length > 25) throw new Error('Select 1 to 25 source Workers.');
  const available = await listWorkers(token, accountId);
  if (sources.some(source => !available.includes(source))) throw new Error('A selected Worker is no longer available in this account.');
  if (sources.some(source => source === install.collector || source === install.forwarder)) throw new Error('Purple Workers cannot tail themselves.');

  if (!install.queueId) {
    const queue = await cloudflareApi(token, accountId, '/queues', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queue_name: install.queue })
    });
    install.queueId = queue.queue_id;
    save();
  }
  if (!install.forwarderDeployed) {
    await uploadWorker(token, accountId, install.forwarder, forwarderCode, [
      { name: 'PURPLE_INGEST_URL', type: 'secret_text', text: ingestUrl },
      { name: 'PURPLE_INGEST_TOKEN', type: 'secret_text', text: ingestToken }
    ]);
    install.forwarderDeployed = true;
    save();
  }
  if (!install.consumerAttached) {
    await cloudflareApi(token, accountId, `/queues/${encodeURIComponent(install.queueId)}/consumers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'worker', script_name: install.forwarder, settings: { batch_size: 10, max_retries: 5 } })
    });
    install.consumerAttached = true;
    save();
  }
  if (!install.collectorDeployed) {
    await uploadWorker(token, accountId, install.collector, collectorCode, [
      { name: 'PURPLE_EVENTS', type: 'queue', queue_name: install.queue }
    ]);
    install.collectorDeployed = true;
    save();
  }
  for (const source of sources) {
    if (install.attached.includes(source)) continue;
    const route = `/workers/scripts/${encodeURIComponent(source)}/script-settings`;
    const settings = await cloudflareApi(token, accountId, route);
    const consumers = Array.isArray(settings.tail_consumers) ? settings.tail_consumers : [];
    if (!consumers.some(consumer => consumer.service === install.collector)) {
      await cloudflareApi(token, accountId, route, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tail_consumers: [...consumers, { service: install.collector }] })
      });
    }
    install.attached.push(source);
    save();
  }
  install.status = 'installed';
  save();
  return install;
}

export async function syncCollectorSources(token, install, sources, save) {
  if (install.status !== 'installed') throw new Error('Install the collector before changing source Workers.');
  if (!Array.isArray(sources) || !sources.length || sources.length > 25 || new Set(sources).size !== sources.length ||
      sources.some(source => typeof source !== 'string' || !/^[a-zA-Z0-9_-]{1,63}$/.test(source) ||
        source.startsWith('purple-collector-') || source.startsWith('purple-forwarder-'))) {
    throw Object.assign(new Error('Choose 1 to 25 distinct source Workers.'), { status: 400 });
  }
  const available = await listWorkers(token, install.accountId);
  if (sources.some(source => !available.includes(source))) throw Object.assign(new Error('A selected Worker is no longer available. Refresh the Worker list and try again.'), { status: 400 });
  const current = install.sources || [];
  const additions = sources.filter(source => !current.includes(source));
  const removals = current.filter(source => !sources.includes(source));
  for (const source of additions) {
    const route = `/workers/scripts/${encodeURIComponent(source)}/script-settings`;
    const settings = await cloudflareApi(token, install.accountId, route);
    const consumers = Array.isArray(settings.tail_consumers) ? settings.tail_consumers : [];
    if (!consumers.some(consumer => consumer.service === install.collector)) {
      await cloudflareApi(token, install.accountId, route, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tail_consumers: [...consumers, { service: install.collector }] })
      });
    }
    install.sources = [...(install.sources || []), source];
    install.attached = [...new Set([...(install.attached || []), source])];
    save();
  }
  for (const source of removals) {
    const route = `/workers/scripts/${encodeURIComponent(source)}/script-settings`;
    try {
      const settings = await cloudflareApi(token, install.accountId, route);
      const consumers = Array.isArray(settings.tail_consumers) ? settings.tail_consumers : [];
      if (consumers.some(consumer => consumer.service === install.collector)) {
        await cloudflareApi(token, install.accountId, route, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tail_consumers: consumers.filter(consumer => consumer.service !== install.collector) })
        });
      }
    } catch (error) { if (error.status !== 404) throw error; }
    install.sources = install.sources.filter(name => name !== source);
    install.attached = (install.attached || []).filter(name => name !== source);
    save();
  }
  install.sources = [...sources];
  install.attached = [...sources];
  save();
  return install;
}
