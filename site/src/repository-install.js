// Repository PR installer; separate from the homepage's CLI installer module.
export function installationUrl(repository, branch, workflow) {
  let value = repository.trim().replace(/\/$/, '');
  if (value.startsWith('https://github.com/')) value = value.slice('https://github.com/'.length);
  value = value.replace(/\.git$/, '');
  const parts = value.split('/');
  if (parts.length !== 2 || !/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(parts[0]) ||
      !/^[\w.-]{1,100}$/.test(parts[1]) || ['.', '..'].includes(parts[1])) {
    throw Error('Enter owner/repository or its https://github.com/owner/repository URL.');
  }
  branch = branch.trim();
  // Accept slash-separated Git refs, but not revision expressions or URL syntax.
  if (!branch || branch.length > 255 || /[\s~^:?*\[\\\x00-\x1f\x7f]/.test(branch) ||
      branch.includes('..') || branch.includes('@{') || branch === '@' || branch.startsWith('-') ||
      branch.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.') || part.endsWith('.lock'))) {
    throw Error('Enter an existing base branch, such as main, master or release/1.x.');
  }
  const url = new URL(`https://github.com/${value}/new/${branch.split('/').map(encodeURIComponent).join('/')}`);
  url.searchParams.set('filename', '.github/workflows/offense.yml');
  url.searchParams.set('value', workflow);
  return url.href;
}

if (typeof document !== 'undefined') {
  const form = document.querySelector('#install-form');
  const repository = document.querySelector('#repository');
  const branch = document.querySelector('#branch');
  const error = document.querySelector('#install-error');
  const ready = document.querySelector('#install-ready');
  const link = document.querySelector('#github-install');
  const button = form.querySelector('button');
  let workflow;
  async function loadTemplate() {
    const response = await fetch('/templates/offense.yml');
    if (!response.ok) throw Error('The template could not load. Try again, or use the manual instructions below.');
    const text = await response.text();
    if (!text.startsWith('# Offense dependency audit:')) throw Error('Invalid template response. Use the manual instructions below.');
    return text;
  }
  form.addEventListener('input', () => {
    ready.hidden = true;
    link.removeAttribute('href');
    error.textContent = '';
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    error.textContent = '';
    ready.hidden = true;
    link.removeAttribute('href');
    button.disabled = true;
    button.textContent = 'Preparing…';
    try {
      // Validate before fetching; the repository stays in this tab until handoff.
      installationUrl(repository.value, branch.value, '');
      workflow ||= await loadTemplate();
      link.href = installationUrl(repository.value, branch.value, workflow);
      document.querySelector('#ready-repository').textContent = new URL(link.href).pathname.split('/').slice(1, 3).join('/');
      ready.hidden = false;
      link.focus();
    } catch (problem) {
      error.textContent = problem.message;
    } finally {
      button.disabled = false;
      button.textContent = 'Prepare installation PR →';
    }
  });
  // Do not submit repository names to this site's URL if JavaScript fails to load.
  button.disabled = false;
}
