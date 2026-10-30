import { execFileSync, spawnSync } from 'node:child_process';
import { lstat, readFile, mkdtemp, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { runZizmor } from '../agent/zizmor.mjs';
import { normalizeFindings } from '../agent/scan-findings.mjs';
import { updateBeforeRun } from './skill-updater.mjs';

const VERSIONS = { opengrep: '1.32.0', zizmor: '1.31.1' };
const SKIP = new Set(['node_modules', '.git', '.agents', '.codex', '.claude', '.pi', 'dist', 'build', 'coverage', '.next', '.venv', 'venv']);
const environment = root => ({ PATH: '/usr/local/bin:/usr/bin:/bin', HOME: root, TMPDIR: root,
  SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', NO_COLOR: '1',
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' });
const selected = tools => {
  const value = tools ?? ['opengrep', 'zizmor'];
  if (!Array.isArray(value) || !value.length || new Set(value).size !== value.length || value.some(tool => !Object.hasOwn(VERSIONS, tool)))
    throw Error('Select opengrep or zizmor with --tool.');
  return value;
};
const relevant = (name, tools) => tools.includes('opengrep') && /\.(?:[cm]?jsx?|tsx?|py)$/i.test(name) ||
  tools.includes('zizmor') && (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(name) || /(?:^|\/)action\.ya?ml$/i.test(name));

export async function collectLocalSource(directory, tools = ['opengrep', 'zizmor']) {
  const root = await noSymlinkDirectory(path.resolve(directory));
  let names;
  try {
    names = execFileSync('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
      'ls-files', '--cached', '-z', '--', '.'], { cwd: root, env: environment(os.tmpdir()), maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 }).toString('utf8').split('\0').filter(Boolean);
  } catch { throw Error('A local Git checkout and Git CLI are required. No source was sent.'); }
  const files = [], omitted = []; let bytes = 0;
  for (const name of [...new Set(names)]) {
    if (name.startsWith('/') || name.includes('\\') || name.split('/').some(part => !part || part === '.' || part === '..'))
      throw Error('A tracked path is unsafe.');
    if (name.split('/').some(part => SKIP.has(part)) || !relevant(name, tools)) { omitted.push({ path: name, reason: 'outside_supported_source_scope' }); continue; }
    const target = path.join(root, name);
    let current = root, info;
    for (const part of name.split('/')) {
      current = path.join(current, part); info = await lstat(current).catch(() => null);
      if (!info || info.isSymbolicLink()) { info = null; break; }
    }
    if (!info?.isFile()) { omitted.push({ path: name, reason: 'missing_symlink_or_non_file' }); continue; }
    if (info.size > 256 * 1024 || files.length >= 500) throw Error('Local scan exceeds the file budget. Narrow the scan directory.');
    const buffer = await readFile(target);
    if (buffer.length > 256 * 1024 || (bytes += buffer.length) > 4 * 1024 * 1024) throw Error('Local scan exceeds the source byte budget.');
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(buffer); } catch { omitted.push({ path: name, reason: 'non_utf8' }); continue; }
    if (content.includes('\0')) { omitted.push({ path: name, reason: 'binary' }); continue; }
    files.push({ path: name, content });
  }
  return { files, omitted, bytes, scope: 'Tracked supported files at their current working versions. Untracked files, generated output and dependency/agent directories are excluded.' };
}

async function noSymlinkDirectory(directory, { create = false } = {}) {
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (create) await mkdir(current, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(current);
    if (info.isSymbolicLink() || !info.isDirectory()) throw Error('Scan directories must not contain symlinks or non-directories.');
  }
  return directory;
}

async function savePrivate(directory, filename, content) {
  const target = path.join(directory, filename), info = await lstat(target).catch(() => null);
  if (info && (info.isSymbolicLink() || !info.isFile())) throw Error('A report target is not a regular file.');
  const temporary = path.join(directory, `.${filename}-${process.pid}-${Date.now()}`);
  try { await writeFile(temporary, content, { mode: 0o600, flag: 'wx' }); await rename(temporary, target); }
  finally { await rm(temporary, { force: true }); }
}

export async function localSourceScan(directory, { tools, output, preview = false, execute = spawnSync,
  collect = collectLocalSource, opengrep = 'opengrep', zizmor = 'zizmor',
  rulesPath } = {}) {
  const chosen = selected(tools), source = await collect(path.resolve(directory), chosen);
  if (preview) return { tools: chosen, files: source.files.map(file => file.path), omitted: source.omitted,
    sourceBytes: source.bytes, sourceUpload: false, executesApplication: false };
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'purple-source-'));
  const root = path.join(temporary, 'source'); await mkdir(root, { mode: 0o700 });
  const results = [], findings = [];
  try {
    if (!rulesPath) {
      rulesPath = path.join(temporary, 'operator-rules.yml');
      const rules = typeof PURPLE_SOURCE_RULES === 'string' ? PURPLE_SOURCE_RULES : await readFile(new URL('../agent/scan-rules.yml', import.meta.url), 'utf8');
      await writeFile(rulesPath, rules, { mode: 0o600, flag: 'wx' });
    }
    for (const file of source.files) {
      if (file.path.startsWith('/') || file.path.split('/').some(part => !part || part === '.' || part === '..') || file.path.includes('\\')) throw Error('Unsafe source path.');
      const target = path.join(root, file.path); await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, file.content, { mode: 0o600, flag: 'wx' });
    }
    for (const tool of chosen) {
      const executable = tool === 'opengrep' ? opengrep : zizmor, started = Date.now();
      const probe = execute(executable, ['--version'], { cwd: temporary, env: environment(temporary), timeout: 10000, maxBuffer: 64000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const versionPattern = new RegExp(`(?:^|\\s)${VERSIONS[tool].replaceAll('.', '\\.')}($|\\s)`);
      if (probe.error || probe.status !== 0 || !versionPattern.test(String(probe.stdout || ''))) {
        results.push({ name: tool, version: VERSIONS[tool], status: 'failed', error: 'pinned_tool_unavailable', findings: 0 }); continue;
      }
      if (tool === 'zizmor') {
        const result = await runZizmor({ root, files: source.files.map(file => file.path), executable, execute,
          reportPath: path.join(temporary, 'zizmor.json'), timeoutMs: 120000 });
        findings.push(...(result.findings || []));
        results.push({ name: tool, version: result.version, status: result.status, durationMs: Date.now() - started,
          findings: result.findings?.length || 0, coverage: result.coverage, ...(result.error ? { error: 'workflow_scan_incomplete' } : {}) });
      } else {
        if (!source.files.some(file => /\.(?:[cm]?jsx?|tsx?|py)$/i.test(file.path))) {
          results.push({ name: tool, version: VERSIONS[tool], status: 'partial', findings: 0, error: 'no_supported_source' }); continue;
        }
        const destination = path.join(temporary, 'opengrep.json');
        const run = execute(executable, ['scan', '--config', rulesPath, '--taint-intrafile', '--json', '--output', destination,
          '--disable-version-check', '--no-git-ignore', '--x-ignore-semgrepignore-files', '--disable-nosem', '--jobs', '2',
          '--timeout', '10', '--max-memory', '512', root], { cwd: temporary, env: environment(temporary), timeout: 180000,
          killSignal: 'SIGKILL', maxBuffer: 1024 * 1024, stdio: ['ignore', 'ignore', 'ignore'] });
        let data;
        try { if ((await lstat(destination)).size > 8 * 1024 * 1024) throw Error(); data = JSON.parse(await readFile(destination, 'utf8')); if (!Array.isArray(data.results)) throw Error(); }
        catch { results.push({ name: tool, version: VERSIONS[tool], status: 'failed', findings: 0, error: 'invalid_scanner_report' }); continue; }
        const allowed = new Set(source.files.map(file => file.path));
        const normalized = normalizeFindings(tool, data, root).filter(finding => allowed.has(finding.file));
        const incomplete = run.error || run.status !== 0 || data.errors?.length;
        findings.push(...normalized); results.push({ name: tool, version: VERSIONS[tool], status: incomplete ? 'partial' : 'complete',
          durationMs: Date.now() - started, findings: normalized.length, ...(incomplete ? { error: 'source_scan_incomplete' } : {}) });
      }
    }
    const truncated = findings.length > 500;
    const incompleteSource = source.omitted.some(file => file.reason !== 'outside_supported_source_scope');
    const report = { schemaVersion: 'purple.source-scan.v1', status: !truncated && !incompleteSource && results.every(tool => tool.status === 'complete') ? 'completed' :
      results.every(tool => tool.status === 'failed') ? 'failed' : 'partial', tools: results, findings: findings.slice(0, 500),
      confirmedVulnerabilities: 0, sourceUpload: false, executesApplication: false,
      coverage: { sourceFiles: source.files.length, sourceBytes: source.bytes, omitted: source.omitted,
        scope: source.scope, analysis: 'Operator rules and supported within-file input flow only. Scanner findings require source review and security regression evidence; no exploit or cross-file proof.', truncated, incompleteSource } };
    const requested = output && path.resolve(output);
    if (requested && (requested === path.resolve(directory) || requested.startsWith(path.resolve(directory) + path.sep))) throw Error('Choose a report directory outside the scanned checkout.');
    const target = requested ? await noSymlinkDirectory(requested, { create: true }) : await mkdtemp(path.join(os.tmpdir(), 'purple-source-report-'));
    await savePrivate(target, 'scan.json', JSON.stringify(report, null, 2) + '\n');
    await savePrivate(target, 'scan.md', `# Purple local source scan\n\nStatus: ${report.status}\nSource uploaded: no\nConfirmed vulnerabilities: 0\n\n${report.tools.map(tool => `${tool.name} ${tool.version}: ${tool.status}${tool.error ? ` (${tool.error})` : ''}`).join('\n\n')}\n\n${report.findings.map(finding => `- **${finding.severity}** ${finding.title} — ${finding.file}:${finding.line || '?'}\n  ${finding.remediation}`).join('\n')}\n\n${report.coverage.analysis}\n`);
    return { status: report.status, findings: report.findings.length, confirmedVulnerabilities: 0, sourceUpload: false,
      report: path.join(target, 'scan.md'), json: path.join(target, 'scan.json') };
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help')) { console.log('Usage: node source-scan.mjs [checkout] [--tool opengrep|zizmor ...] [--preview] [--output directory] [--opengrep /path/to/binary] [--zizmor /path/to/binary]\nPinned tools: Opengrep 1.32.0, Zizmor 1.31.1. Install with your existing tool manager; no automatic installs, source uploads or application execution. Reports stay local.'); return; }
  const directory = args[0] && !args[0].startsWith('--') ? args.shift() : process.cwd(), options = {};
  while (args.length) {
    const option = args.shift();
    if (option === '--preview') options.preview = true;
    else if (['--tool', '--output', '--opengrep', '--zizmor'].includes(option) && args[0] && !args[0].startsWith('--')) {
      const value = args.shift(); if (option === '--tool') (options.tools ||= []).push(value); else options[option.slice(2)] = value;
    } else throw Error('Unknown or incomplete source scan option.');
  }
  const update = await updateBeforeRun('purple', import.meta.url, { preview: options.preview }); if (update.stop) return;
  const result = await localSourceScan(directory, options); console.log(JSON.stringify(result, null, 2));
  if (!options.preview && result.status !== 'completed') process.exitCode = 2;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(() => {
  console.error('Local source scan failed. Check checkout, pinned tools, budgets and report directory; no clean scan is implied. No source was uploaded.'); process.exitCode = 1;
});
