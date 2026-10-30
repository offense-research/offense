// All content and links are static HTML. Filtering and copying are optional.
export function mountDirectory(root = document) {
  const browser = root.querySelector('[data-directory]');
  if (browser) {
    const form = browser.querySelector('form');
    const input = browser.querySelector('input');
    const filters = [...browser.querySelectorAll('[data-category-filter]')];
    const cards = [...browser.querySelectorAll('[data-directory-tool]')];
    const count = browser.querySelector('#directory-count');
    const empty = browser.querySelector('.directory-empty');
    const params = new URLSearchParams(window.location.search);
    let category = filters.some(button => button.dataset.categoryFilter === params.get('category')) ? params.get('category') : 'all';
    input.value = (params.get('q') || '').slice(0, input.maxLength);

    function filter() {
      const words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      let visible = 0;
      for (const card of cards) {
        card.hidden = (category !== 'all' && card.dataset.category !== category)
          || !words.every(word => card.dataset.search.includes(word));
        if (!card.hidden) visible++;
      }
      for (const button of filters) button.setAttribute('aria-pressed', String(button.dataset.categoryFilter === category));
      count.textContent = `${visible} ${visible === 1 ? 'tool' : 'tools'}${visible !== cards.length ? ` of ${cards.length}` : ''}`;
      empty.hidden = visible !== 0;
      const url = new URL(window.location.href);
      if (input.value.trim()) url.searchParams.set('q', input.value.trim()); else url.searchParams.delete('q');
      if (category !== 'all') url.searchParams.set('category', category); else url.searchParams.delete('category');
      window.history.replaceState(null, '', url);
    }
    function reset() {
      input.value = '';
      category = 'all';
      filter();
      input.focus();
    }
    form.addEventListener('submit', event => { event.preventDefault(); filter(); });
    form.addEventListener('reset', event => { event.preventDefault(); reset(); });
    input.addEventListener('input', filter);
    for (const button of filters) button.addEventListener('click', () => { category = button.dataset.categoryFilter; filter(); });
    browser.querySelector('[data-directory-reset]').addEventListener('click', reset);
    form.hidden = false;
    browser.querySelector('.directory-filters').hidden = false;
    filter();
  }

  for (const button of root.querySelectorAll('[data-directory-copy]')) {
    button.hidden = false;
    button.addEventListener('click', async () => {
      const code = root.getElementById(button.dataset.directoryCopy);
      const status = button.closest('.directory-code').querySelector('[role="status"]');
      try {
        await navigator.clipboard.writeText(code.textContent);
        status.textContent = 'Command copied. Review it before running.';
      } catch {
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        status.textContent = 'Copy the selected command with your keyboard or browser menu.';
      }
    });
  }
}

if (typeof document !== 'undefined') mountDirectory();
