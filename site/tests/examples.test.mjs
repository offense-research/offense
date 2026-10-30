import assert from 'node:assert/strict';
import test from 'node:test';
import { mountExamples } from '../src/examples.js';

class Element extends EventTarget {
  constructor(dataset = {}) {
    super();
    this.dataset = dataset;
    this.hidden = false;
    this.inert = false;
    this.textContent = '';
    this.attributes = new Map();
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, active) => active ? classes.add(name) : classes.delete(name),
      contains: name => classes.has(name),
    };
    this.style = {
      setProperty: (name, value) => this.attributes.set(`style:${name}`, value),
      removeProperty: name => this.attributes.delete(`style:${name}`),
    };
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return this.attributes.get(name); }
  removeAttribute(name) { this.attributes.delete(name); }
  closest() { return this.interactive ? this : null; }
  emit(type, values = {}) {
    const event = new Event(type, { cancelable: true });
    for (const [name, value] of Object.entries(values)) Object.defineProperty(event, name, { value });
    this.dispatchEvent(event);
    return event;
  }
  click(detail = 0) { this.emit('click', { detail }); }
}

function clock() {
  let now = 0;
  let nextId = 0;
  const tasks = new Map();
  return {
    setTimeout(callback, delay) {
      const id = ++nextId;
      tasks.set(id, { callback, at: now + delay });
      return id;
    },
    clearTimeout(id) { tasks.delete(id); },
    tick(milliseconds) {
      const end = now + milliseconds;
      for (;;) {
        const pending = [...tasks].filter(([, task]) => task.at <= end).sort((a, b) => a[1].at - b[1].at);
        if (!pending.length) break;
        const [id, task] = pending[0];
        now = task.at;
        tasks.delete(id);
        task.callback();
      }
      now = end;
    },
  };
}

function fixture({ reduced = false, observer = true } = {}) {
  const doc = Object.assign(new Element(), { hidden: false, defaultView: {} });
  const carousel = Object.assign(new Element(), { ownerDocument: doc });
  const slides = ['Dependencies', 'Secrets', 'Source code', 'GitHub Actions'].map(exampleName => new Element({ exampleName }));
  const dots = slides.map((_, index) => new Element({ exampleGo: String(index) }));
  const controls = Object.fromEntries(['prev', 'next', 'toggle', 'toggle-label', 'current', 'total', 'status', 'slides']
    .map(name => [name, new Element()]));
  const time = clock();
  const motion = Object.assign(new Element(), { matches: reduced });
  motion.change = matches => { motion.matches = matches; motion.emit('change', { matches }); };
  let intersection;
  class Observer {
    constructor(callback) { this.callback = callback; intersection = this; }
    observe(target) { this.target = target; }
    disconnect() { this.target = null; }
    show(visible) {
      this.callback([{ target: this.target, isIntersecting: visible, intersectionRatio: visible ? 1 : 0 }]);
    }
  }
  carousel.querySelectorAll = selector => selector === '.example-slide' ? slides : selector === '[data-example-go]' ? dots : [];
  carousel.querySelector = selector => controls[selector.slice('[data-example-'.length, -1)] || null;
  const root = { querySelector: selector => selector === '.example-carousel' ? carousel : null };
  const options = { motion, IntersectionObserver: observer ? Observer : false, setTimeout: time.setTimeout, clearTimeout: time.clearTimeout };
  const controller = mountExamples(root, options);
  return {
    root, options, controller, carousel, slides, dots, controls, motion, time, doc,
    active: () => slides.findIndex(slide => slide.classList.contains('is-active')),
    inView: visible => intersection.show(visible),
  };
}

test('one accessible slide is active; autoplay waits for viewport entry and never announces itself', () => {
  const example = fixture();
  assert.equal(example.active(), 0);
  assert.equal(example.controls.current.textContent, '01');
  assert.equal(example.controls.total.textContent, '04');
  assert.ok(example.slides.every((slide, index) => slide.inert === (index !== 0)));
  assert.ok(example.slides.every(slide => !slide.hidden));
  example.time.tick(20000);
  assert.equal(example.active(), 0);
  example.inView(true);
  assert.ok(example.carousel.classList.contains('is-playing'));
  example.time.tick(7999);
  assert.equal(example.active(), 0);
  example.time.tick(1);
  assert.equal(example.active(), 1);
  assert.equal(example.controls.status.textContent, '');
  assert.equal(example.slides[0].getAttribute('aria-hidden'), 'true');
  assert.ok(example.slides[0].classList.contains('is-leaving'));
  example.time.tick(560);
  assert.equal(example.slides[0].classList.contains('is-leaving'), false);
  example.controller.destroy();
});

test('manual controls wrap, announce the selection, and stop automatic rotation', () => {
  const example = fixture();
  example.inView(true);
  example.controls.prev.click();
  assert.equal(example.active(), 3);
  assert.equal(example.controls.current.textContent, '04');
  example.controls.next.click();
  assert.equal(example.active(), 0);
  example.dots[2].click();
  assert.equal(example.active(), 2);
  assert.equal(example.controls.status.textContent, 'Source code, 3 of 4.');
  assert.ok(example.dots.every((button, index) => button.getAttribute('aria-pressed') === String(index === 2)));
  assert.ok(example.carousel.classList.contains('is-paused'));
  example.time.tick(32000);
  assert.equal(example.active(), 2);
  example.controller.destroy();
});

test('hover, page visibility, and viewport suspension each restart a complete interval', () => {
  const example = fixture();
  example.inView(true);
  example.time.tick(3000);
  example.carousel.emit('mouseenter');
  assert.equal(example.carousel.classList.contains('is-playing'), false);
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  example.carousel.emit('mouseleave');
  example.time.tick(7999);
  assert.equal(example.active(), 0);
  example.time.tick(1);
  assert.equal(example.active(), 1);

  example.doc.hidden = true;
  example.doc.emit('visibilitychange');
  example.time.tick(16000);
  assert.equal(example.active(), 1);
  example.doc.hidden = false;
  example.doc.emit('visibilitychange');
  example.time.tick(7999);
  assert.equal(example.active(), 1);
  example.time.tick(1);
  assert.equal(example.active(), 2);

  example.inView(false);
  example.time.tick(16000);
  assert.equal(example.active(), 2);
  example.inView(true);
  example.time.tick(7999);
  assert.equal(example.active(), 2);
  example.time.tick(1);
  assert.equal(example.active(), 3);
  example.controller.destroy();
});

test('focus pauses until Play; focusing the rotation control cannot reverse pointer intent', () => {
  const example = fixture();
  example.inView(true);
  example.carousel.emit('focusin');
  assert.equal(example.controls['toggle-label'].textContent, 'Play examples');
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  example.controls.toggle.click();
  example.time.tick(8000);
  assert.equal(example.active(), 1, 'Explicit Play works while its control retains focus.');

  example.controls.toggle.emit('pointerdown');
  example.carousel.emit('focusin');
  example.controls.toggle.click(1);
  example.time.tick(16000);
  assert.equal(example.active(), 1, 'Pointer action on Pause must remain Pause after focusin.');
  example.controls.toggle.emit('pointerdown');
  example.carousel.emit('focusin');
  example.controls.toggle.click(1);
  example.time.tick(8000);
  assert.equal(example.active(), 2);
  example.controller.destroy();
});

test('reduced motion keeps manual navigation and never resumes automatically after preference changes', () => {
  const example = fixture({ reduced: true });
  example.inView(true);
  assert.equal(example.controls.toggle.disabled, true);
  assert.equal(example.controls.toggle.hidden, true);
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  example.dots[2].click();
  assert.equal(example.active(), 2);
  assert.ok(example.slides.every(slide => !slide.classList.contains('is-leaving')));
  example.controls.toggle.click();
  example.time.tick(16000);
  assert.equal(example.active(), 2);

  example.motion.change(false);
  assert.equal(example.controls.toggle.disabled, false);
  assert.equal(example.controls.toggle.hidden, false);
  example.time.tick(16000);
  assert.equal(example.active(), 2);
  example.controls.toggle.click();
  example.time.tick(8000);
  assert.equal(example.active(), 3);
  example.motion.change(true);
  example.time.tick(16000);
  assert.equal(example.active(), 3);
  example.motion.change(false);
  example.time.tick(16000);
  assert.equal(example.active(), 3);
  example.controls.toggle.click();
  example.time.tick(8000);
  assert.equal(example.active(), 0);
  example.controller.destroy();
});

test('touching to read or scroll pauses rotation without selecting a different example', () => {
  const example = fixture();
  example.inView(true);
  example.time.tick(5000);
  const start = example.controls.slides.emit('touchstart', {
    touches: [{ identifier: 1, clientX: 100, clientY: 100 }],
  });
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  assert.equal(example.controls['toggle-label'].textContent, 'Play examples');
  const end = example.controls.slides.emit('touchend', {
    changedTouches: [{ identifier: 1, clientX: 110, clientY: 200 }],
  });
  assert.equal(start.defaultPrevented || end.defaultPrevented, false);
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  example.controls.toggle.click();
  example.time.tick(8000);
  assert.equal(example.active(), 1);
  example.controller.destroy();
});

test('horizontal swipes navigate; vertical gestures, short gestures, and interactive targets do not', () => {
  const example = fixture();
  const area = example.controls.slides;
  const swipe = (x, y, target = area) => {
    const start = area.emit('touchstart', { target, touches: [{ identifier: 1, clientX: 100, clientY: 100 }] });
    const end = area.emit('touchend', { changedTouches: [{ identifier: 1, clientX: 100 + x, clientY: 100 + y }] });
    assert.equal(start.defaultPrevented || end.defaultPrevented, false);
  };
  swipe(-40, 2);
  swipe(-80, 80);
  assert.equal(example.active(), 0);
  swipe(-60, 8);
  assert.equal(example.active(), 1);
  swipe(60, 8);
  assert.equal(example.active(), 0);
  swipe(-80, 0, Object.assign(new Element(), { interactive: true }));
  assert.equal(example.active(), 0);
  assert.ok(example.carousel.classList.contains('is-paused'));
  example.controller.destroy();
});

test('initialization is idempotent and cleanup cancels timers and releases inactive content', () => {
  const example = fixture();
  assert.equal(mountExamples(example.root, example.options), example.controller);
  example.controls.next.click();
  assert.equal(example.active(), 1);
  example.controller.destroy();
  example.time.tick(16000);
  assert.equal(example.active(), -1);
  assert.ok(example.slides.every(slide => !slide.inert && !slide.attributes.has('aria-hidden')));
  example.controls.next.click();
  assert.equal(example.active(), -1);
  assert.equal(example.carousel.classList.contains('examples-ready'), false);
});

test('without IntersectionObserver the carousel remains available for manual navigation only', () => {
  const example = fixture({ observer: false });
  example.time.tick(16000);
  assert.equal(example.active(), 0);
  example.controls.next.click();
  assert.equal(example.active(), 1);
  example.controller.destroy();
  assert.doesNotThrow(() => mountExamples({ querySelector: () => null }));
});
