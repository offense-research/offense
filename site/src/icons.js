const namespace = 'http://www.w3.org/2000/svg';

export function createIcon(name) {
  const icon = document.createElementNS(namespace, 'svg');
  icon.classList.add('ui-icon');
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('focusable', 'false');
  const use = document.createElementNS(namespace, 'use');
  use.setAttribute('href', `/icons.svg#${name}`);
  icon.append(use);
  return icon;
}
