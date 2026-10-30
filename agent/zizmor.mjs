import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const ZIZMOR_VERSION = '1.31.1';
export const ZIZMOR_RELEASE_SHA256 = 'd185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99';
const MAX_OUTPUT = 8 * 1024 * 1024;
const MAX_FINDINGS = 500;
const RULES = new Set([
  'adhoc-packages', 'anonymous-definition', 'archived-uses', 'artipacked', 'bot-conditions',
  'cache-poisoning', 'concurrency-limits', 'dangerous-triggers', 'dependabot-cooldown',
  'dependabot-execution', 'excessive-permissions', 'forbidden-uses', 'github-app', 'github-env',
  'hardcoded-container-credentials', 'impostor-commit', 'insecure-commands', 'insecure-url-scheme',
  'known-vulnerable-actions', 'misfeature', 'obfuscation', 'overprovisioned-secrets', 'ref-confusion',
  'ref-version-mismatch', 'secrets-inherit', 'secrets-outside-env', 'self-hosted-runner',
  'self-repository', 'stale-action-refs', 'superfluous-actions', 'template-injection', 'typosquat-uses',
  'undocumented-permissions', 'unpinned-images', 'unpinned-tools', 'unpinned-uses', 'unredacted-secrets',
  'unsound-condition', 'unsound-contains', 'unsound-ternary', 'use-trusted-publishing'
]);
const REMEDIATION = Object.freeze({
  'template-injection': 'Pass untrusted GitHub expressions through step environment variables and quote shell variables. Avoid interpolating expressions directly into executable scripts; verify the workflow still behaves correctly.',
  'dangerous-triggers': 'Separate untrusted pull-request code from privileged workflows. Do not check out or execute attacker-controlled code while secrets or write permissions are available.',
  'excessive-permissions': 'Declare the minimum GitHub token permissions required for each job. Verify legitimate checkout, reporting and release operations after reducing permissions.',
  'unpinned-uses': 'Pin this action to a reviewed full commit SHA and retain its release version in a comment. Verify the selected action revision and configure reviewed updates.',
  'unpinned-images': 'Pin the container image to a reviewed immutable digest and verify its intended publisher and upgrade process.',
  artipacked: 'Disable persisted checkout credentials when they are not needed and exclude credentials from artifacts. Review whether untrusted code or uploaded artifacts can expose the token.',
  'cache-poisoning': 'Separate cache writes across trust boundaries. Ensure untrusted workflows cannot populate a cache later consumed by privileged builds or releases.',
  'github-env': 'Do not write untrusted multiline data directly to GitHub environment or path command files. Use a safe delimiter or an alternative data channel and verify downstream behavior.',
  'hardcoded-container-credentials': 'Remove the embedded registry credential, revoke and rotate it, and use a scoped secret reference. Inspect previous workflow runs for exposure.',
  'unredacted-secrets': 'Prevent secret-derived values from reaching workflow logs or outputs. Revoke and rotate any credential that was already exposed.',
  'secrets-inherit': 'Pass only the explicitly required secrets to the reusable workflow and verify its callers and trust boundary.',
  'self-hosted-runner': 'Restrict untrusted code from persistent self-hosted runners. Review runner isolation, job permissions and credential lifetime.',
  'use-trusted-publishing': 'Use the package registry trusted-publishing flow where supported and grant identity-token permission only to the required release job.'
});
const TITLE = Object.freeze({
  'template-injection': 'Potential script injection in GitHub Actions',
  'dangerous-triggers': 'Untrusted code can cross a privileged workflow boundary',
  'excessive-permissions': 'GitHub Actions token permissions exceed the declared need',
  'unpinned-uses': 'GitHub Action is referenced by a mutable version',
  'cache-poisoning': 'Workflow cache may cross a trust boundary',
  artipacked: 'Checkout credentials may be exposed by workflow artifacts'
});
const SEVERITY = Object.freeze({ High: 'HIGH', Medium: 'MEDIUM', Low: 'LOW', Informational: 'LOW' });
const CONFIDENCE = new Set(['High', 'Medium', 'Low']);

function validRelative(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 500 &&
    !value.includes('\\') && !/[\u0000-\u001f\u007f]/u.test(value) && !path.posix.isAbsolute(value) &&
    !value.split('/').some(part => !part || part === '.' || part === '..');
}

/** GitHub loads workflows from the root workflows directory, and actions from action.yml/yaml. */
export function isZizmorInput(value) {
  return validRelative(value) && (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(value) ||
    /(?:^|\/)action\.ya?ml$/.test(value));
}

function localLocation(location, root, allowed) {
  const value = location?.symbolic?.key?.Local?.verbatim_path;
  if (typeof value !== 'string' || value.length > root.length + 501) return null;
  const relative = path.isAbsolute(value) ? path.relative(root, value) : value.replace(/^\.\//, '');
  if (!validRelative(relative) || !allowed.has(relative)) return null;
  const row = location?.concrete?.location?.start_point?.row;
  return { file: relative, line: Number.isInteger(row) && row >= 0 && row < 1_000_000 ? row + 1 : null };
}

function normalized(raw, root, allowed) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !RULES.has(raw.ident) ||
      !Array.isArray(raw.locations)) return null;
  const locations = [...raw.locations].sort((a, b) =>
    Number(b?.symbolic?.kind === 'Primary') - Number(a?.symbolic?.kind === 'Primary'));
  const position = locations.map(location => localLocation(location, root, allowed)).find(Boolean);
  if (!position) return null;
  const ruleId = raw.ident;
  const result = {
    tool: 'zizmor', ruleId, ...position,
    severity: SEVERITY[raw.determinations?.severity] || 'UNKNOWN',
    confidence: CONFIDENCE.has(raw.determinations?.confidence) ? raw.determinations.confidence.toLowerCase() : 'unknown',
    title: TITLE[ruleId] || `GitHub Actions security finding (${ruleId})`,
    remediation: REMEDIATION[ruleId] || 'Review this workflow or action against the rule documentation, make a scoped change, and verify intended workflow behavior.',
    documentationUrl: `https://docs.zizmor.sh/audits/#${ruleId}`,
    verification: 'scanner_finding'
  };
  result.id = createHash('sha256').update(JSON.stringify([result.tool, ruleId, position.file, position.line])).digest('hex').slice(0, 32);
  return result;
}

async function persist(reportPath, result) {
  if (reportPath) await writeFile(reportPath, JSON.stringify(result), { mode: 0o600 });
  return result;
}

/**
 * Audit explicit, already staged local workflow/action files. The pinned scanner
 * sees no credentials, project configuration, ignore rules, remote inputs or fix flag.
 * Its source-bearing JSON/stdout/stderr stay in memory; only constructed findings persist.
 */
export async function runZizmor({ root, files, reportPath, execute = spawnSync,
  executable = '/usr/local/bin/zizmor', timeoutMs = 120000 } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || !Array.isArray(files) || files.length > 500 ||
      files.some(file => !validRelative(file)) || new Set(files).size !== files.length ||
      reportPath !== undefined && (typeof reportPath !== 'string' || !path.isAbsolute(reportPath)) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000)
    throw new Error('Zizmor requires a staged absolute root and bounded relative file paths.');
  const selected = files.filter(isZizmorInput);
  const coverage = { eligibleFiles: selected.length, offlineAuditsOnly: true,
    scope: 'Supplied GitHub Actions workflows and action definitions only. Online action metadata, remote repository state and exploit verification are not assessed.' };
  const result = (status, findings, error) => ({ status, version: ZIZMOR_VERSION, findings, coverage, ...(error ? { error } : {}) });
  if (!selected.length) return persist(reportPath, result('partial', [], 'No GitHub Actions workflow or action definition was detected.'));
  let actualRoot;
  try {
    actualRoot = await realpath(root);
    for (const relative of selected) {
      const target = path.join(actualRoot, relative);
      const metadata = await lstat(target);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 256 * 1024 ||
          await realpath(target) !== target) throw new Error('Unstaged input');
    }
  } catch { return persist(reportPath, result('failed', [], 'Workflow inputs must be regular staged files within the scan root.')); }
  const work = await mkdtemp(path.join(os.tmpdir(), 'purple-zizmor-'));
  try {
    let completed;
    try {
      completed = execute(executable, ['--offline', '--no-config', '--no-ignores', '--strict-collection',
        '--format=json-v1', '--persona=regular', '--no-progress', '--color=never', '--no-exit-codes', '--quiet',
        '--cache-dir', path.join(work, 'cache'), '--', ...selected.map(relative => path.join(actualRoot, relative))], {
        cwd: work, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: work, TMPDIR: work,
          XDG_CONFIG_HOME: work, XDG_CACHE_HOME: work, ZIZMOR_OFFLINE: '1', NO_COLOR: '1' },
        encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { return persist(reportPath, result('failed', [], 'GitHub Actions scanner failed or timed out.')); }
    if (!completed || completed.error || completed.signal || ![0, 1, 3].includes(completed.status))
      return persist(reportPath, result('failed', [], 'GitHub Actions scanner failed or timed out.'));
    if (completed.status === 3) return persist(reportPath, result('partial', [], 'GitHub Actions scanner could not collect the selected inputs.'));
    let raw;
    try {
      if (typeof completed.stdout !== 'string' || Buffer.byteLength(completed.stdout) > MAX_OUTPUT) throw new Error('Report bounds');
      raw = JSON.parse(completed.stdout);
      if (!Array.isArray(raw) || raw.length > 5000) throw new Error('Report shape');
    } catch { return persist(reportPath, result(completed.status === 1 ? 'partial' : 'failed', [],
      completed.status === 1 ? 'GitHub Actions inputs could not be fully parsed or audited.' : 'GitHub Actions scanner returned an invalid report.')); }
    const allowed = new Set(selected);
    const findings = raw.map(item => normalized(item, actualRoot, allowed)).filter(Boolean);
    const unique = [...new Map(findings.map(item => [item.id, item])).values()];
    const incomplete = completed.status !== 0 || findings.length !== raw.length ||
      findings.some(item => item.severity === 'UNKNOWN' || item.confidence === 'unknown') || unique.length > MAX_FINDINGS;
    return persist(reportPath, result(incomplete ? 'partial' : 'complete', unique.slice(0, MAX_FINDINGS),
      incomplete ? 'GitHub Actions findings or input coverage were incomplete. Narrow the scan and review omitted inputs or findings.' : undefined));
  } finally { await rm(work, { recursive: true, force: true }); }
}
