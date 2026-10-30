const mountedExamples = new WeakMap();
const interactive = 'a, button, input, textarea, select, summary, [contenteditable], [role="button"], [role="link"]';

export function mountExamples(root = document, options = {}) {
  const carousel = root.querySelector('.example-carousel');
  if (!carousel) return;
  if (mountedExamples.has(carousel)) return mountedExamples.get(carousel);
  const slides = [...carousel.querySelectorAll('.example-slide')];
  if (!slides.length) return;

  const doc = carousel.ownerDocument;
  const view = doc.defaultView || globalThis;
  const interval = options.interval ?? 8000;
  const schedule = options.setTimeout || view.setTimeout.bind(view);
  const cancel = options.clearTimeout || view.clearTimeout.bind(view);
  const motion = options.motion || view.matchMedia?.('(prefers-reduced-motion: reduce)');
  const Observer = options.IntersectionObserver ?? view.IntersectionObserver;
  const buttons = [...carousel.querySelectorAll('[data-example-go]')];
  const toggle = carousel.querySelector('[data-example-toggle]');
  const toggleLabel = carousel.querySelector('[data-example-toggle-label]');
  const current = carousel.querySelector('[data-example-current]');
  const total = carousel.querySelector('[data-example-total]');
  const status = carousel.querySelector('[data-example-status]');
  const slideArea = carousel.querySelector('[data-example-slides]');
  const listeners = [];
  let active = -1;
  let timer = null;
  let transitionTimer = null;
  let inView = false;
  let hovering = false;
  let paused = false;
  let reduced = Boolean(motion?.matches);
  let pointerToggleIntent = null;
  let touchStart = null;

  const listen = (target, type, handler, settings) => {
    if (!target) return;
    target.addEventListener(type, handler, settings);
    listeners.push(() => target.removeEventListener(type, handler, settings));
  };
  const stopTimer = () => {
    if (timer !== null) cancel(timer);
    timer = null;
  };
  function syncPlayback() {
    stopTimer();
    if (slides.length > 1 && !paused && !reduced && !hovering && inView && !doc.hidden) {
      timer = schedule(() => { timer = null; select(active + 1); }, interval);
    }
    carousel.classList.toggle('is-playing', timer !== null);
    carousel.classList.toggle('is-paused', paused);
    const label = paused || reduced ? 'Play examples' : 'Pause examples';
    if (toggleLabel) toggleLabel.textContent = label;
    if (toggle) {
      toggle.setAttribute('aria-label', label);
      toggle.disabled = reduced || slides.length < 2;
      toggle.hidden = reduced || slides.length < 2;
    }
  }
  function select(index, manual = false) {
    const next = ((index % slides.length) + slides.length) % slides.length;
    const previous = active;
    if (manual) paused = true;
    if (transitionTimer !== null) cancel(transitionTimer);
    transitionTimer = null;
    for (const [position, slide] of slides.entries()) {
      slide.classList.toggle('is-active', position === next);
      slide.classList.toggle('is-leaving', !reduced && previous !== next && position === previous);
      slide.inert = position !== next;
      slide.setAttribute('aria-hidden', String(position !== next));
    }
    if (!reduced && previous >= 0 && previous !== next) {
      transitionTimer = schedule(() => {
        slides[previous].classList.remove('is-leaving');
        transitionTimer = null;
      }, 560);
    }
    active = next;
    for (const button of buttons) {
      const selected = Number(button.dataset.exampleGo) === active;
      button.classList.toggle('is-active', selected);
      button.setAttribute('aria-pressed', String(selected));
    }
    if (current) current.textContent = String(active + 1).padStart(2, '0');
    if (total) total.textContent = String(slides.length).padStart(2, '0');
    if (manual && status) {
      status.textContent = `${slides[active].dataset.exampleName || 'Example'}, ${active + 1} of ${slides.length}.`;
    }
    syncPlayback();
  }
  const pause = () => { paused = true; syncPlayback(); };

  for (const button of buttons) listen(button, 'click', () => {
    const index = Number(button.dataset.exampleGo);
    if (Number.isInteger(index)) select(index, true);
  });
  listen(carousel.querySelector('[data-example-prev]'), 'click', () => select(active - 1, true));
  listen(carousel.querySelector('[data-example-next]'), 'click', () => select(active + 1, true));
  // Preserve pointer intent if focusing the rotation control pauses it first.
  listen(toggle, 'pointerdown', () => { pointerToggleIntent = !paused; });
  listen(toggle, 'pointercancel', () => { pointerToggleIntent = null; });
  listen(toggle, 'click', event => {
    if (reduced) return;
    const shouldPause = event.detail > 0 && pointerToggleIntent !== null ? pointerToggleIntent : !paused;
    pointerToggleIntent = null;
    paused = shouldPause;
    syncPlayback();
  });
  listen(carousel, 'mouseenter', () => { hovering = true; syncPlayback(); });
  listen(carousel, 'mouseleave', () => { hovering = false; syncPlayback(); });
  listen(carousel, 'focusin', pause);
  listen(doc, 'visibilitychange', syncPlayback);
  listen(motion, 'change', event => {
    reduced = event.matches;
    paused = true;
    if (reduced) {
      if (transitionTimer !== null) cancel(transitionTimer);
      transitionTimer = null;
      for (const slide of slides) slide.classList.remove('is-leaving');
    }
    syncPlayback();
  });
  listen(slideArea, 'touchstart', event => {
    pause();
    touchStart = null;
    if (event.touches.length !== 1 || event.target.closest?.(interactive)) return;
    const touch = event.touches[0];
    touchStart = { x: touch.clientX, y: touch.clientY, id: touch.identifier };
  }, { passive: true });
  listen(slideArea, 'touchend', event => {
    if (!touchStart) return;
    const start = touchStart;
    touchStart = null;
    const touch = [...event.changedTouches].find(candidate => candidate.identifier === start.id);
    if (!touch) return;
    const x = touch.clientX - start.x;
    const y = touch.clientY - start.y;
    if (Math.abs(x) >= 45 && Math.abs(x) > Math.abs(y) * 1.3) select(active + (x < 0 ? 1 : -1), true);
  }, { passive: true });
  listen(slideArea, 'touchcancel', () => { touchStart = null; }, { passive: true });

  carousel.style.setProperty('--example-duration', `${interval}ms`);
  select(0);
  carousel.classList.add('examples-ready');
  const observer = Observer ? new Observer(entries => {
    for (const entry of entries) if (entry.target === carousel) {
      inView = entry.isIntersecting && entry.intersectionRatio >= .2;
      syncPlayback();
    }
  }, { threshold: .2 }) : null;
  observer?.observe(carousel);

  const controller = { destroy() {
    stopTimer();
    if (transitionTimer !== null) cancel(transitionTimer);
    observer?.disconnect();
    for (const remove of listeners) remove();
    carousel.classList.remove('examples-ready', 'is-playing', 'is-paused');
    carousel.style.removeProperty('--example-duration');
    for (const slide of slides) {
      slide.classList.remove('is-active', 'is-leaving');
      slide.inert = false;
      slide.removeAttribute('aria-hidden');
    }
    mountedExamples.delete(carousel);
  } };
  mountedExamples.set(carousel, controller);
  return controller;
}
