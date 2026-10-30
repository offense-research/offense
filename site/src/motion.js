const mountedMotion = new WeakMap();

export function mountMotion(root = document, options = {}) {
  if (mountedMotion.has(root)) return mountedMotion.get(root);
  const scene = root.querySelector('.routing-view');
  const reveals = [...root.querySelectorAll('[data-reveal]')];
  if (!scene && !reveals.length) return;
  const doc = scene?.ownerDocument || root.ownerDocument || root;
  const view = doc.defaultView || globalThis;
  const Observer = options.IntersectionObserver ?? view.IntersectionObserver;
  const motion = options.motion || view.matchMedia?.('(prefers-reduced-motion: reduce)');
  const pointer = options.pointer || view.matchMedia?.('(hover: hover) and (pointer: fine)');
  const requestFrame = options.requestAnimationFrame || view.requestAnimationFrame?.bind(view);
  const cancelFrame = options.cancelAnimationFrame || view.cancelAnimationFrame?.bind(view);
  const tilt = scene?.querySelector('[data-core-tilt]');
  const toggle = scene?.querySelector('[data-motion-toggle]');
  const label = scene?.querySelector('[data-motion-label]');
  const listeners = [];
  let reduced = Boolean(motion?.matches);
  let fine = Boolean(pointer?.matches);
  let inView = false;
  let paused = false;
  let active = false;
  let frame = null;
  let point = null;
  let destroyed = false;

  const listen = (target, type, handler, settings) => {
    if (!target) return;
    target.addEventListener(type, handler, settings);
    listeners.push(() => target.removeEventListener(type, handler, settings));
  };
  function resetTilt() {
    if (frame !== null) cancelFrame?.(frame);
    frame = null;
    point = null;
    tilt?.style.setProperty('--core-rotate-x', '0deg');
    tilt?.style.setProperty('--core-rotate-y', '0deg');
  }
  function sync() {
    if (destroyed) return;
    active = Boolean(scene && Observer && inView && !doc.hidden && !reduced && !paused);
    scene?.classList.toggle('is-motion-active', active);
    scene?.classList.toggle('is-motion-paused', !active);
    if (!active || !fine) resetTilt();
    const text = paused || reduced ? 'Play motion' : 'Pause motion';
    if (label) label.textContent = text;
    if (toggle) {
      toggle.hidden = reduced || !Observer;
      toggle.setAttribute('aria-label', text);
      toggle.setAttribute('aria-pressed', String(paused));
    }
  }
  const showAll = () => {
    for (const element of reveals) {
      element.classList.add('is-revealed');
      if (element !== scene) observer?.unobserve(element);
    }
  };

  const observer = Observer ? new Observer(entries => {
    if (destroyed) return;
    for (const entry of entries) {
      const visible = entry.isIntersecting && entry.intersectionRatio >= .1;
      if (entry.target === scene) {
        inView = visible;
        sync();
      }
      if (visible && reveals.includes(entry.target)) {
        entry.target.classList.add('is-revealed');
        if (entry.target !== scene) observer.unobserve(entry.target);
      }
    }
  }, { threshold: .1 }) : null;

  listen(toggle, 'click', () => { paused = !paused; sync(); });
  listen(doc, 'visibilitychange', sync);
  listen(motion, 'change', event => {
    reduced = event.matches;
    if (reduced) showAll();
    sync();
  });
  listen(pointer, 'change', event => { fine = event.matches; sync(); });
  listen(scene, 'pointerleave', resetTilt);
  listen(scene, 'pointermove', event => {
    if (!active || !fine || !tilt || !requestFrame || event.pointerType === 'touch') return;
    point = { x: event.clientX, y: event.clientY };
    if (frame !== null) return;
    frame = requestFrame(() => {
      frame = null;
      if (destroyed || !active || !fine || !point) return;
      const { left, top, width, height } = scene.getBoundingClientRect();
      if (!width || !height) return resetTilt();
      const x = Math.max(-1, Math.min(1, (point.x - left) / width * 2 - 1));
      const y = Math.max(-1, Math.min(1, (point.y - top) / height * 2 - 1));
      point = null;
      tilt.style.setProperty('--core-rotate-x', `${(-y * 4).toFixed(2)}deg`);
      tilt.style.setProperty('--core-rotate-y', `${(x * 6).toFixed(2)}deg`);
    });
  }, { passive: true });

  if (scene && observer) {
    scene.classList.add('motion-ready');
    observer.observe(scene);
  }
  for (const element of reveals) {
    if (observer && !reduced) {
      element.classList.add('reveal-ready');
      observer.observe(element);
    } else element.classList.add('is-revealed');
  }
  sync();

  const controller = { destroy() {
    destroyed = true;
    resetTilt();
    observer?.disconnect();
    for (const remove of listeners) remove();
    scene?.classList.remove('motion-ready', 'is-motion-active', 'is-motion-paused');
    tilt?.style.removeProperty('--core-rotate-x');
    tilt?.style.removeProperty('--core-rotate-y');
    for (const element of reveals) element.classList.remove('reveal-ready', 'is-revealed');
    mountedMotion.delete(root);
  } };
  mountedMotion.set(root, controller);
  return controller;
}
