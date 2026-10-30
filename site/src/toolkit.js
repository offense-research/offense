const mountedToolkits = new WeakSet();

export function mountToolkit(root = document) {
  const browser = root.querySelector('#all-tools');
  if (!browser || mountedToolkits.has(browser)) return;

  const filters = [...browser.querySelectorAll('[data-filter]')];
  const rows = [...browser.querySelectorAll('.tool-row[data-category]')];
  const count = browser.querySelector('#catalog-count');
  const empty = browser.querySelector('.catalog-empty');

  function applyFilter(selected) {
    let visible = 0;
    for (const row of rows) {
      row.hidden = selected.dataset.filter !== 'all'
        && row.dataset.category !== selected.dataset.filter;
      if (!row.hidden) visible += 1;
    }
    for (const button of filters) {
      const active = button === selected;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    }
    if (count) count.textContent = `${visible} ${visible === 1 ? 'tool' : 'tools'}`;
    if (empty) empty.hidden = visible !== 0;
  }

  for (const button of filters) {
    button.addEventListener('click', () => applyFilter(button));
  }
  const all = filters.find(button => button.dataset.filter === 'all');
  if (all) applyFilter(all);
  mountedToolkits.add(browser);
}
