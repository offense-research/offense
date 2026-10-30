import assert from 'node:assert/strict';
import test from 'node:test';
import { landingCatalog } from '../scripts/catalog.mjs';
import { mountToolkit } from '../src/toolkit.js';
const toolDetails = landingCatalog();

// A small event-capable DOM adapter keeps these interaction tests dependency-free.
function element(dataset = {}) {
  const target = new EventTarget();
  const attributes = new Map();
  const classes = new Set();
  return Object.assign(target, {
    dataset,
    hidden: false,
    textContent: '',
    classList: {
      toggle(name, active) { active ? classes.add(name) : classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(name, value) { attributes.set(name, value); },
    getAttribute(name) { return attributes.get(name); },
    click() { this.dispatchEvent(new Event('click')); },
  });
}

function fixture(extraFilters = []) {
  const rows = Object.entries(toolDetails).map(([tool, detail]) => element({ tool, category: detail.category }));
  const filters = new Map(['all', 'source', 'dependencies', 'infrastructure', 'web', 'mobile', ...extraFilters]
    .map(filter => [filter, element({ filter })]));
  const featured = ['trivy-vuln', 'opengrep', 'zizmor'].map(tool => element({ tool }));
  const count = element();
  const empty = Object.assign(element(), { hidden: true });
  const browser = {
    open: false,
    querySelectorAll(selector) {
      if (selector === '[data-filter]') return filters.values();
      if (selector === '.tool-row[data-category]') return rows;
      throw new Error(`Unexpected toolkit query: ${selector}`);
    },
    querySelector(selector) {
      return selector === '#catalog-count' ? count : selector === '.catalog-empty' ? empty : null;
    },
  };
  const root = {
    querySelector(selector) { return selector === '#all-tools' ? browser : null; },
    querySelectorAll() { throw new Error('Catalog filtering must stay inside #all-tools.'); },
  };
  return {
    root, browser, rows, featured, filters, count, empty,
    visible: () => rows.filter(row => !row.hidden).map(row => row.dataset.tool),
  };
}

test('the real catalog remains complete until an intentional filter, while featured cards stay visible', () => {
  const catalog = fixture();
  const ids = Object.keys(toolDetails);
  assert.deepEqual(catalog.visible(), ids);
  mountToolkit(catalog.root);
  assert.deepEqual(catalog.visible(), ids);
  assert.equal(catalog.count.textContent, '29 tools');

  catalog.browser.open = true;
  catalog.filters.get('web').click();
  assert.deepEqual(catalog.visible(), ['zap-passive-har', 'nuclei', 'schemathesis', 'zap-api', 'sslyze', 'katana', 'httpx']);
  assert.equal(catalog.count.textContent, '7 tools');
  assert.equal(catalog.browser.open, true);
  assert.ok(catalog.featured.every(card => !card.hidden));

  catalog.filters.get('all').click();
  assert.deepEqual(catalog.visible(), ids);
  assert.equal(catalog.count.textContent, '29 tools');
  assert.equal(catalog.browser.open, true);
});

test('category switches produce the expected coverage and accessible selected state', () => {
  const catalog = fixture();
  mountToolkit(catalog.root);
  for (const [filter, expected] of [['source', 7], ['dependencies', 7], ['infrastructure', 7], ['web', 7], ['mobile', 1]]) {
    catalog.filters.get(filter).click();
    assert.equal(catalog.visible().length, expected, filter);
    assert.ok(catalog.visible().every(id => toolDetails[id].category === filter));
    for (const [name, button] of catalog.filters) {
      assert.equal(button.getAttribute('aria-pressed'), String(name === filter));
      assert.equal(button.classList.contains('is-active'), name === filter);
    }
    assert.equal(catalog.empty.hidden, true);
  }
});

test('an empty category shows a recovery message and All restores the catalog', () => {
  const catalog = fixture(['future']);
  mountToolkit(catalog.root);
  catalog.filters.get('future').click();
  assert.deepEqual(catalog.visible(), []);
  assert.equal(catalog.count.textContent, '0 tools');
  assert.equal(catalog.empty.hidden, false);
  catalog.filters.get('all').click();
  assert.equal(catalog.visible().length, 29);
  assert.equal(catalog.empty.hidden, true);
});

test('pages without the optional browser can initialize the rest of their interface', () => {
  assert.doesNotThrow(() => mountToolkit({ querySelector: () => null }));
});
