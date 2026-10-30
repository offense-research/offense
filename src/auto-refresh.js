// One request at a time, no hidden/offline polling, and bounded retry backoff.
export function createAutoRefresh(run, { interval = 15000, window: events = window,
  document: page = document, navigator: network = navigator, timers = globalThis } = {}) {
  let stopped = false, timer, active, failures = 0, resumeAfterAbort = false;
  const visible = () => !stopped && !page.hidden && network.onLine !== false;
  function schedule(delay) {
    timers.clearTimeout(timer);
    if (visible()) timer = timers.setTimeout(refresh, delay);
  }
  async function refresh() {
    if (!visible() || active) return;
    const controller = new AbortController(); active = controller;
    try { await run(controller.signal); failures = 0; }
    catch { if (!controller.signal.aborted) failures++; }
    finally {
      active = null;
      if (resumeAfterAbort) { resumeAfterAbort = false; schedule(0); }
      else schedule(Math.min(300000, interval * 2 ** Math.min(failures, 5)));
    }
  }
  function resume() {
    if (visible()) { if (active?.signal.aborted) resumeAfterAbort = true; else if (!active) schedule(0); }
    else { timers.clearTimeout(timer); active?.abort(); }
  }
  for (const event of ['focus', 'online', 'offline', 'purple:data-changed']) events.addEventListener(event, resume);
  page.addEventListener('visibilitychange', resume);
  schedule(0);
  return () => {
    stopped = true; timers.clearTimeout(timer); active?.abort();
    for (const event of ['focus', 'online', 'offline', 'purple:data-changed']) events.removeEventListener(event, resume);
    page.removeEventListener('visibilitychange', resume);
  };
}

export function notifyDataChanged() { window.dispatchEvent(new Event('purple:data-changed')); }

export function mergeDrafts(previous, oldSaved, newSaved) {
  const next = { ...newSaved };
  for (const [key, value] of Object.entries(previous)) if (value !== (oldSaved[key] || '')) next[key] = value;
  return next;
}
