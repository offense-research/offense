import { toolDetails, scannerToolCount } from './catalog.js?v=4';
import { localToolDetails } from './local-tools.js?v=1';
import { createIcon } from './icons.js';
import { mountToolkit } from './toolkit.js?v=1';
import { mountExamples } from './examples.js?v=1';
import { mountMotion } from './motion.js?v=1';

document.documentElement.classList.add('js');
mountToolkit();
mountExamples();
mountMotion();
for (const element of document.querySelectorAll('[data-scanner-count]')) element.textContent = scannerToolCount;

const dialog = document.querySelector('#tool-dialog');
for (const button of document.querySelectorAll('[data-details]')) {
  button.addEventListener('click', () => {
    const detail = toolDetails[button.dataset.details] || localToolDetails[button.dataset.details];
    if (!detail) return;
    document.querySelector('#dialog-provider').textContent = detail.provider;
    document.querySelector('#dialog-status').textContent = detail.status;
    document.querySelector('#dialog-title').textContent = detail.title;
    document.querySelector('#dialog-description').textContent = detail.description;
    document.querySelector('#dialog-points').replaceChildren(...detail.points.map(point => {
      const item = document.createElement('li');
      item.textContent = point;
      return item;
    }));
    const link = document.querySelector('#dialog-link');
    link.href = detail.url;
    link.replaceChildren(document.createTextNode(`${detail.action} `));
    link.append(createIcon('arrow-up-right'));
    dialog.showModal();
    dialog.scrollTop = 0;
  });
}

for (const button of dialog.querySelectorAll('.dialog-close')) {
  button.addEventListener('click', () => dialog.close());
}
dialog.addEventListener('click', event => {
  const bounds = dialog.getBoundingClientRect();
  const outside = event.clientX < bounds.left || event.clientX > bounds.right
    || event.clientY < bounds.top || event.clientY > bounds.bottom;
  if (event.target === dialog && outside) dialog.close();
});

const menuToggle = document.querySelector('.menu-toggle');
const navigation = document.querySelector('#main-nav');
function closeMenu() {
  navigation.classList.remove('is-open');
  menuToggle.setAttribute('aria-expanded', 'false');
  menuToggle.setAttribute('aria-label', 'Open navigation');
}
menuToggle.addEventListener('click', () => {
  const expanded = menuToggle.getAttribute('aria-expanded') === 'true';
  navigation.classList.toggle('is-open', !expanded);
  menuToggle.setAttribute('aria-expanded', String(!expanded));
  menuToggle.setAttribute('aria-label', expanded ? 'Open navigation' : 'Close navigation');
});
navigation.addEventListener('click', event => {
  if (event.target.closest('a')) closeMenu();
});
document.addEventListener('click', event => {
  if (!event.target.closest('.site-header')) closeMenu();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menuToggle.getAttribute('aria-expanded') === 'true') {
    closeMenu();
    menuToggle.focus();
  }
});
matchMedia('(min-width: 761px)').addEventListener('change', closeMenu);

const toast = document.querySelector('#toast');
let toastTimer;
function notify(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add('is-visible');
  toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 4500);
}

const copyFeedback = new WeakMap();
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const source = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      const label = button.querySelector('span');
      const previous = copyFeedback.get(button);
      if (previous) clearTimeout(previous.timer);
      const original = previous?.original || label?.textContent;
      if (label) label.textContent = 'Copied';
      button.classList.add('is-copied');
      const timer = setTimeout(() => {
        if (label) label.textContent = original;
        button.classList.remove('is-copied');
        copyFeedback.delete(button);
      }, 2200);
      copyFeedback.set(button, { original, timer });
      notify(source.id === 'cli-install-command' ? 'CLI install command copied. Run it in your terminal.' : 'Setup prompt copied. Paste it into your coding agent.');
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
      notify(source.id === 'cli-install-command' ? 'Select and copy the highlighted CLI install command.' : 'Select and copy the highlighted setup prompt.');
    }
  });
}

document.querySelector('#current-year').textContent = new Date().getFullYear();
