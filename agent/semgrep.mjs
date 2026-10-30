import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { adapterLocation, persistAdapterResult, stageAdapterFiles, validateAdapterOptions } from './scan-adapter-files.mjs';

export const SEMGREP_VERSION = '1.182.1';
export const SEMGREP_WHEEL_SHA256 = 'bba25e5a38db5061d725c0920699ecee3e8137026427e722a271bd9bb8d25a40';
const MAX_OUTPUT = 8 * 1024 * 1024;
const RULES = Object.freeze({
  'offense.js.jwt-signature-disabled': ['HIGH', 'JWT verification permits unsigned tokens', 'Require an explicitly approved signed JWT algorithm and validate issuer, audience and expiry. Add unsigned-token rejection and valid-token regression tests.'],
  'offense.js.cookie-httponly-disabled': ['MEDIUM', 'Response cookie disables HttpOnly', 'For authentication or sensitive cookies, enable HttpOnly and review Secure and SameSite settings. Verify legitimate client behavior and test cookie attributes.'],
  'offense.python.flask-debug-enabled': ['MEDIUM', 'Application startup enables debug mode', 'Disable debug mode on deployed services. Review whether the debugger is exposed and verify normal startup and error handling.'],
  'offense.python.jinja-autoescape-disabled': ['MEDIUM', 'Template environment disables escaping', 'Enable appropriate autoescaping for HTML templates and review explicit trusted markup. Test an untrusted HTML value and normal rendering.'],
  'offense.python.requests-tls-verification-disabled': ['HIGH', 'HTTP client disables TLS verification', 'Enable certificate verification and configure the intended CA bundle. Test a valid endpoint and rejection of an invalid certificate.'],
  'offense.python.xml-external-entities-enabled': ['MEDIUM', 'XML parser enables entity resolution', 'Disable external entity resolution and network access when parsing untrusted XML. Add external-entity rejection and normal XML regression tests.']
});
export const isSemgrepInput = value => /\.(?:[cm]?jsx?|tsx?|py)$/i.test(value);

export async function runSemgrep({ root, files, reportPath, execute = spawnSync, timeoutMs = 120000,
  executable = '/opt/purple/semgrep/bin/semgrep', rulesetPath = '/opt/purple/agent/semgrep-rules.yml' } = {}) {
  validateAdapterOptions({ root, files, reportPath, timeoutMs });
  const selected = files.filter(isSemgrepInput), coverage = { eligibleFiles: selected.length, rules: Object.keys(RULES).length,
    profile: 'offense-additional-sast-v1', engine: 'community', offline: true,
    scope: 'Six reviewed JavaScript, TypeScript and Python patterns. No Semgrep Pro, registry rules, cross-file reachability or exploit confirmation.' };
  const result = (status, findings, error) => persistAdapterResult(reportPath,
    { status, version: SEMGREP_VERSION, findings, coverage, ...(error ? { error } : {}) });
  if (!selected.length) return result('partial', [], 'No supported JavaScript, TypeScript or Python files were supplied.');
  let staged;
  try { staged = await stageAdapterFiles(root, selected); }
  catch { return result('failed', [], 'Source inputs must be regular bounded staged files.'); }
  try {
    let completed;
    try {
      completed = execute(executable, ['scan', '--oss-only', '--config', rulesetPath, '--json', '--quiet',
        '--metrics=off', '--disable-version-check', '--disable-nosem', '--no-git-ignore', '--x-ignore-semgrepignore-files',
        '--jobs', '2', '--timeout', '10', '--max-memory', '512', '--max-target-bytes', '262144',
        '--project-root', staged.source, '--', ...selected.map(file => path.join(staged.source, file))], {
        cwd: staged.directory, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: staged.directory, TMPDIR: staged.directory,
          SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', SEMGREP_SETTINGS_FILE: path.join(staged.directory, 'settings.yml'),
          OTEL_SDK_DISABLED: 'true', NO_COLOR: '1' }, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL',
        maxBuffer: MAX_OUTPUT, stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { return result('failed', [], 'Semgrep failed or timed out.'); }
    if (!completed || completed.error || completed.signal || ![0, 1, 3].includes(completed.status))
      return result('failed', [], 'Semgrep failed or timed out.');
    let raw;
    try {
      if (typeof completed.stdout !== 'string' || Buffer.byteLength(completed.stdout) > MAX_OUTPUT) throw new Error('Bounds');
      raw = JSON.parse(completed.stdout);
      if (!Array.isArray(raw.results) || raw.results.length > 5000 || !Array.isArray(raw.errors)) throw new Error('Shape');
    } catch { return result('failed', [], 'Semgrep returned an invalid bounded report.'); }
    const allowed = new Set(selected), findings = []; let omitted = 0;
    for (const item of raw.results) {
      const ruleId = typeof item?.check_id === 'string' ? item.check_id.match(/(?:^|\.)(offense\.(?:js|python)\.[a-z0-9-]+)$/)?.[1] : null;
      const rule = RULES[ruleId], file = adapterLocation(item?.path, staged.source, allowed);
      if (!rule || !file) { omitted++; continue; }
      const line = Number.isInteger(item.start?.line) && item.start.line > 0 ? item.start.line : null;
      findings.push({ id: createHash('sha256').update(JSON.stringify(['semgrep', ruleId, file, line])).digest('hex').slice(0, 32),
        tool: 'semgrep', ruleId, file, line, severity: rule[0], title: rule[1], remediation: rule[2], verification: 'scanner_finding' });
    }
    const unique = [...new Map(findings.map(item => [item.id, item])).values()];
    const incomplete = completed.status !== 0 || raw.errors.length || omitted || unique.length > 500;
    return result(incomplete ? 'partial' : 'complete', unique.slice(0, 500), incomplete ? 'Semgrep reported incomplete parsing, execution or finding coverage.' : undefined);
  } finally { await staged.cleanup(); }
}
