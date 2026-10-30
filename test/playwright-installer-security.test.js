import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const installers = ['chrome_beta', 'chrome_stable', 'msedge_beta', 'msedge_dev', 'msedge_stable'];

// Inspect every installed copy recorded in the lock, including nested copies.
// Never execute these destructive installers (they remove apps and install packages).
const cores = Object.keys(lock.packages).filter(name => name.endsWith('node_modules/playwright-core'));
assert.ok(cores.length, 'expected Playwright installer coverage');
for (const location of cores) {
  for (const installer of installers) {
    test(`${location}: ${installer} download verifies TLS certificates`, () => {
      const source = readFileSync(path.join(root, location, 'bin', `reinstall_${installer}_mac.sh`), 'utf8');
      const downloads = source.split('\n').filter(line => /^\s*curl\s/.test(line));
      assert.ok(downloads.length, 'expected a browser download command');
      for (const command of downloads) {
        assert.doesNotMatch(command, /(?:^|\s)(?:--insecure(?:[=\s]|$)|-[a-zA-Z]*k[a-zA-Z]*(?:\s|$))/,
          'browser installer must not bypass certificate verification (CVE-2025-59288)');
      }
    });
  }
}

test('BugPatrol resolves the patched Playwright pair', () => {
  const require = createRequire(path.join(root, 'node_modules/bugpatrol/package.json'));
  const playwright = require('playwright/package.json');
  const core = createRequire(require.resolve('playwright/package.json'))('playwright-core/package.json');
  assert.equal(playwright.version, '1.55.1');
  assert.equal(core.version, playwright.version);
});
