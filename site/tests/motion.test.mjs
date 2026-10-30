import assert from 'node:assert/strict';
import test from 'node:test';
import { mountMotion } from '../src/motion.js';

class Element extends EventTarget {
  constructor() {
    super();
    this.hidden = false;
    this.textContent = '';
    this.attributes = new Map();
    this.styles = new Map();
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, active) => active ? classes.add(name) : classes.delete(name),
      contains: name => classes.has(name),
    };
    this.style = {
      setProperty: (name, value) => this.styles.set(name, value),
      removeProperty: name => this.styles.delete(name),
    };
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return this.attributes.get(name); }
  emit(type, values = {}) {
    const event = new Event(type, { cancelable: true });
    for (const [name, value] of Object.entries(values)) Object.defineProperty(event, name, { value });
    this.dispatchEvent(event);
    return event;
  }
  click() { this.emit('click'); }
}

function fixture({ reduced = false, fine = true, observer = true, revealScene = false } = {}) {
  const doc = Object.assign(new Element(), { hidden: false, defaultView: {} });
  const scene = Object.assign(new Element(), { ownerDocument: doc });
  const tilt = new Element();
  const toggle = new Element();
  const label = new Element();
  const reveals = [new Element(), new Element(), ...(revealScene ? [scene] : [])];
  const motion = Object.assign(new Element(), { matches: reduced });
  const pointer = Object.assign(new Element(), { matches: fine });
  for (const media of [motion, pointer]) media.change = matches => {
    media.matches = matches;
    media.emit('change', { matches });
  };
  let geometryReads = 0;
  scene.getBoundingClientRect = () => {
    geometryReads += 1;
    return { left: 100, top: 50, width: 200, height: 100 };
  };
  scene.querySelector = selector => ({
    '[data-core-tilt]': tilt,
    '[data-motion-toggle]': toggle,
    '[data-motion-label]': label,
  })[selector] || null;
  const root = {
    querySelector: selector => selector === '.routing-view' ? scene : null,
    querySelectorAll: selector => selector === '[data-reveal]' ? reveals : [],
  };
  const observers = [];
  class Observer {
    constructor(callback, options) {
      this.callback = callback;
      this.options = options;
      this.targets = new Set();
      observers.push(this);
    }
    observe(target) { this.targets.add(target); }
    unobserve(target) { this.targets.delete(target); }
    disconnect() { this.targets.clear(); }
    emit(target, visible, ratio = visible ? 1 : 0) {
      if (this.targets.has(target)) this.callback([{ target, isIntersecting: visible, intersectionRatio: ratio }]);
    }
  }
  let nextFrame = 0;
  const pendingFrames = new Map();
  const frames = {
    request(callback) { const id = ++nextFrame; pendingFrames.set(id, callback); return id; },
    cancel(id) { pendingFrames.delete(id); },
    flush() {
      const callbacks = [...pendingFrames.values()];
      pendingFrames.clear();
      for (const callback of callbacks) callback();
    },
    get pending() { return pendingFrames.size; },
  };
  const options = { motion, pointer, IntersectionObserver: observer ? Observer : false,
    requestAnimationFrame: frames.request, cancelAnimationFrame: frames.cancel };
  const controller = mountMotion(root, options);
  return {
    root, scene, doc, tilt, toggle, label, reveals, motion, pointer, observers, options, controller, frames,
    inView: (visible, ratio) => observers[0].emit(scene, visible, ratio),
    move: (x, y, pointerType = 'mouse') => scene.emit('pointermove', { clientX: x, clientY: y, pointerType }),
    geometryReads: () => geometryReads,
    active: () => scene.classList.contains('is-motion-active'),
  };
}

test('decorative motion requires visibility and preserves the user pause choice across interruptions', () => {
  const state = fixture();
  assert.ok(state.scene.classList.contains('motion-ready'));
  assert.equal(state.active(), false);
  assert.equal(state.toggle.hidden, false);
  assert.equal(state.toggle.getAttribute('aria-pressed'), 'false');
  state.inView(true, .09);
  assert.equal(state.active(), false);
  state.inView(true, .1);
  assert.equal(state.active(), true);
  state.doc.hidden = true;
  state.doc.emit('visibilitychange');
  assert.equal(state.active(), false);
  state.doc.hidden = false;
  state.doc.emit('visibilitychange');
  assert.equal(state.active(), true);
  state.toggle.click();
  assert.equal(state.active(), false);
  assert.equal(state.toggle.getAttribute('aria-pressed'), 'true');
  assert.equal(state.label.textContent, 'Play motion');
  state.inView(false);
  state.inView(true);
  state.motion.change(true);
  state.motion.change(false);
  assert.equal(state.active(), false);
  state.toggle.click();
  assert.equal(state.active(), true);
  assert.equal(state.label.textContent, 'Pause motion');
  state.controller.destroy();
});

test('pointer bursts produce one bounded frame using the latest point and never create an idle loop', () => {
  const state = fixture();
  state.move(300, 150);
  assert.equal(state.frames.pending, 0);
  state.inView(true);
  for (let index = 0; index < 100; index++) state.move(100 + index, 100);
  state.move(1000, -1000);
  assert.equal(state.frames.pending, 1);
  assert.equal(state.geometryReads(), 0);
  state.frames.flush();
  assert.equal(state.geometryReads(), 1);
  assert.equal(state.tilt.styles.get('--core-rotate-x'), '4.00deg');
  assert.equal(state.tilt.styles.get('--core-rotate-y'), '6.00deg');
  assert.equal(state.frames.pending, 0);
  state.frames.flush();
  assert.equal(state.geometryReads(), 1);
  assert.equal(state.scene.styles.size, 0, 'Only the decorative wrapper receives transforms.');
  assert.ok(state.reveals.every(element => element.styles.size === 0));
  state.controller.destroy();
});

test('leaving, hiding, pausing, or losing fine-pointer support cancels pending movement and resets the pose', () => {
  const state = fixture();
  state.inView(true);
  state.move(300, 150);
  state.frames.flush();
  state.move(250, 125);
  state.scene.emit('pointerleave');
  assert.equal(state.frames.pending, 0);
  assert.equal(state.tilt.styles.get('--core-rotate-x'), '0deg');
  assert.equal(state.tilt.styles.get('--core-rotate-y'), '0deg');
  state.move(300, 150);
  state.inView(false);
  assert.equal(state.frames.pending, 0);
  state.inView(true);
  state.move(300, 150);
  state.doc.hidden = true;
  state.doc.emit('visibilitychange');
  assert.equal(state.frames.pending, 0);
  state.doc.hidden = false;
  state.doc.emit('visibilitychange');
  state.move(300, 150);
  state.toggle.click();
  assert.equal(state.frames.pending, 0);
  state.toggle.click();
  state.move(300, 150);
  state.pointer.change(false);
  assert.equal(state.frames.pending, 0);
  state.move(300, 150);
  assert.equal(state.frames.pending, 0);
  assert.equal(state.tilt.styles.get('--core-rotate-y'), '0deg');
  state.controller.destroy();
});

test('coarse pointers and touch events do not tilt or prevent normal gestures', () => {
  const state = fixture({ fine: false });
  state.inView(true);
  state.move(300, 150);
  assert.equal(state.frames.pending, 0);
  state.pointer.change(true);
  const event = state.move(300, 150, 'touch');
  assert.equal(event.defaultPrevented, false);
  assert.equal(state.frames.pending, 0);
  state.move(300, 150);
  assert.equal(state.frames.pending, 1);
  state.controller.destroy();
});

test('reduced motion exposes content immediately and stops pending work when changed at runtime', () => {
  const initial = fixture({ reduced: true });
  initial.inView(true);
  assert.equal(initial.active(), false);
  assert.equal(initial.toggle.hidden, true);
  assert.ok(initial.reveals.every(element => element.classList.contains('is-revealed')));
  assert.ok(initial.reveals.every(element => !element.classList.contains('reveal-ready')));
  initial.move(300, 150);
  assert.equal(initial.frames.pending, 0);
  initial.controller.destroy();

  const runtime = fixture();
  runtime.inView(true);
  runtime.move(300, 150);
  assert.equal(runtime.frames.pending, 1);
  runtime.motion.change(true);
  assert.equal(runtime.frames.pending, 0);
  assert.equal(runtime.active(), false);
  assert.equal(runtime.toggle.hidden, true);
  assert.equal(runtime.tilt.styles.get('--core-rotate-y'), '0deg');
  assert.ok(runtime.reveals.every(element => element.classList.contains('is-revealed')));
  runtime.motion.change(false);
  assert.equal(runtime.toggle.hidden, false);
  assert.ok(runtime.reveals.every(element => element.classList.contains('is-revealed')));
  runtime.controller.destroy();
});

test('sections reveal once without being hidden again when scrolled out', () => {
  const state = fixture();
  const section = state.reveals[0];
  assert.ok(section.classList.contains('reveal-ready'));
  assert.equal(section.classList.contains('is-revealed'), false);
  state.observers[0].emit(section, true);
  assert.ok(section.classList.contains('is-revealed'));
  assert.equal(state.observers[0].targets.has(section), false);
  state.observers[0].emit(section, false);
  assert.ok(section.classList.contains('is-revealed'));
  state.controller.destroy();
});

test('without IntersectionObserver all content stays exposed and the unavailable motion control is hidden', () => {
  const state = fixture({ observer: false });
  assert.equal(state.scene.classList.contains('motion-ready'), false);
  assert.equal(state.active(), false);
  assert.equal(state.toggle.hidden, true);
  assert.ok(state.reveals.every(element => element.classList.contains('is-revealed')));
  assert.ok(state.reveals.every(element => !element.classList.contains('reveal-ready')));
  state.move(300, 150);
  assert.equal(state.frames.pending, 0);
  state.controller.destroy();
});

test('revealing the scene itself keeps observing it so offscreen motion still stops', () => {
  const state = fixture({ revealScene: true });
  state.inView(true);
  assert.ok(state.scene.classList.contains('is-revealed'));
  assert.equal(state.active(), true);
  assert.ok(state.observers[0].targets.has(state.scene));
  state.motion.change(true);
  state.motion.change(false);
  state.inView(false);
  assert.equal(state.active(), false);
  state.controller.destroy();
});

test('mounting is idempotent and cleanup releases observers, listeners, frames, and enhancement styles', () => {
  const state = fixture();
  assert.equal(mountMotion(state.root, state.options), state.controller);
  assert.equal(state.observers.length, 1);
  state.inView(true);
  state.move(300, 150);
  state.controller.destroy();
  assert.equal(state.frames.pending, 0);
  assert.equal(state.observers[0].targets.size, 0);
  assert.equal(state.scene.classList.contains('motion-ready'), false);
  assert.equal(state.active(), false);
  assert.equal(state.tilt.styles.size, 0);
  assert.ok(state.reveals.every(element => !element.classList.contains('reveal-ready')));
  state.toggle.click();
  state.move(300, 150);
  state.doc.emit('visibilitychange');
  assert.equal(state.frames.pending, 0);
  assert.equal(state.active(), false);
  assert.doesNotThrow(() => mountMotion({ querySelector: () => null, querySelectorAll: () => [] }));
});
