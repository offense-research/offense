#!/usr/bin/env node
import { readdir, readFile, lstat, realpath, mkdtemp, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { updateBeforeRun, updaterMain } from './skill-updater.mjs';
import { collectLocalEvidence, loadReviewedEvidence } from './offense-local-evidence.mjs';
import { mergeAuditContinuation } from '../shared/offense-planning.js';
import { mergeAuditScanPage, validateScanPage } from '../shared/offense-scanning.js';
import { createOffenseTrace, classifyTraceError, serializeOffenseTrace } from '../shared/offense-trace.js';

const excluded = new Set(['node_modules', 'vendor', 'dist', 'build', 'coverage']);
const unsupported = new Set(['yarn.lock', 'bun.lock', 'bun.lockb', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'go.sum', 'Gemfile.lock', 'composer.lock']);
const supported = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml']);
const CLIENT_VERSION = '0.5.0';
const TOOL_NAME = 'offense.audit_dependencies';

function serviceBase(endpoint) {
  const base = new URL(endpoint);
  if (base.username || base.password || base.search || base.hash || (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)))) throw Error('Offense requires an HTTPS endpoint without credentials, query or fragment.');
  return base;
}

async function boundedText(response, maximum) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum) { await response.body?.cancel(); throw Error('Offense response exceeds the client byte limit.'); }
  if (!response.body) return '';
  const reader = response.body.getReader(), chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw Error('Offense response exceeds the client byte limit.');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

function diagnosticHeaders(response) {
  const safe = name => response.headers.get(name)?.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160) || null;
  return { httpStatus: response.status, requestId: safe('x-offense-request-id') || safe('x-request-id'),
    edgeRequestId: safe('cf-ray'), contentType: safe('content-type'), retryAfter: safe('retry-after') };
}

function requestError(response, body) {
  const diagnostics = diagnosticHeaders(response);
  const detail = typeof body?.error === 'string' ? body.error : body?.error?.message;
  const explanation = typeof detail === 'string' ? detail.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500) : 'The endpoint did not return a completed JSON result.';
  const error = new Error(`Offense returned HTTP ${response.status}: ${explanation}${response.status === 403 ? ' Check endpoint/edge policy; this public capability does not require credentials.' : ''}`);
  error.status = response.status;
  error.code = classifyTraceError({ code: body?.error?.code, status: response.status });
  error.diagnostics = { ...diagnostics, code: typeof body?.error?.code === 'string' ? body.error.code.slice(0, 100) : 'http_error' };
  return error;
}

async function postJson(url, payload, { fetchImpl = fetch, signal, headers = {}, maximum = 8_000_000 } = {}) {
  let response;
  try {
    response = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json',
      'user-agent': `Purple-Offense-CLI/${CLIENT_VERSION}`, ...headers }, body: JSON.stringify(payload), signal, redirect: 'error', credentials: 'omit' });
  } catch (cause) {
    const error = new Error('Offense could not reach the endpoint. Check network access and retry; no completed result is implied.');
    error.code = signal?.aborted ? 'timeout' : 'network_failure';
    error.diagnostics = { code: signal?.aborted ? 'request_timeout' : 'network_error' };
    throw error;
  }
  let text;
  try { text = await boundedText(response, maximum); }
  catch (cause) {
    if (!signal?.aborted) throw cause;
    const error = new Error('Offense response timed out before completion. No completed result is implied.');
    error.code = 'timeout'; error.diagnostics = { code: 'request_timeout' };
    throw error;
  }
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (!response.ok) throw requestError(response, body);
  return { response, text, body };
}

async function fileObservation(filename, maximum = 256_000, within) {
  try {
    if (within) {
      const resolved = await realpath(filename);
      if (resolved !== within && !resolved.startsWith(within + path.sep)) return { status: 'not_read', reason: 'File resolves outside this project checkout.' };
    }
    const info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink()) return { status: 'not_read', reason: 'Not a regular file; symlinks are not followed.' };
    if (info.size > maximum) return { status: 'not_read', reason: 'File exceeds the bounded inspection size.' };
    return { status: 'present', text: await readFile(filename, 'utf8') };
  } catch (error) {
    if (error.code === 'ENOENT') return { status: 'absent' };
    return { status: 'not_read', reason: 'File cannot be inspected.' };
  }
}

async function reportDestination(filename) {
  try {
    const info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink()) throw Error('Report files must be regular files; report symlinks are not followed.');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

async function writeReport(filename, content) {
  await reportDestination(filename);
  const temporary = path.join(path.dirname(filename), `.offense-report-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, content, { mode: 0o600, flag: 'wx' });
    await rename(temporary, filename);
  } finally { await rm(temporary, { force: true }); }
}

async function checkReportAncestors(root, target) {
  let existing = target;
  while (true) {
    try {
      const resolved = await realpath(existing);
      if (resolved === root || resolved.startsWith(root + path.sep)) throw Error('The report directory resolves inside the source checkout.');
      return;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.dirname(existing);
      if (parent === existing) throw error;
      existing = parent;
    }
  }
}

// This probe observes public protocol responses and local file presence. Only
// the host agent can establish that its current tool list actually contains MCP.
export async function doctor(directory, { endpoint = 'https://app.purpleteam.sh', preview = false, fetchImpl = fetch, scriptUrl = import.meta.url } = {}) {
  const root = await realpath(directory), base = serviceBase(endpoint);
  const skillRoot = path.resolve(path.dirname(fileURLToPath(scriptUrl)), '..');
  const skill = await fileObservation(path.join(skillRoot, 'SKILL.md'));
  const installedHelper = await fileObservation(path.join(skillRoot, 'scripts/offense.mjs'), 2_000_000);
  const configurations = [];
  for (const relative of ['.codex/config.toml', '.mcp.json', '.cursor/mcp.json']) {
    const observed = await fileObservation(path.join(root, relative), 256_000, root);
    configurations.push({ path: relative, status: observed.status,
      ...(observed.status === 'present' ? { endpointMentioned: observed.text.includes(new URL('/mcp', base).href), verification: 'Use the client\'s own MCP settings/list command to verify the merged entry.' } : {}),
      ...(observed.reason ? { reason: observed.reason } : {}) });
  }
  const result = { schemaVersion: 'offense.doctor.v1', product: 'Purple', server: 'offense', tool: TOOL_NAME,
    installation: { status: skill.status === 'present' && installedHelper.status === 'present' ? 'files_present' : 'not_installed_here',
      version: skill.text?.match(/\n\s+version:\s*["']?([\w.+-]+)/)?.[1] || null,
      scope: skillRoot === root || skillRoot.startsWith(root + path.sep) ? 'this project checkout' : 'outside_selected_project',
      note: 'File presence is separate from client discovery; another checkout may have different project configuration.' },
    projectConfiguration: { status: configurations.some(item => item.status === 'present') ? 'requires_client_verification' : 'not_observed', files: configurations },
    endpoint: { status: 'not_checked', toolAdvertised: false },
    activeSession: { status: 'not_observable_from_helper', requiredTool: TOOL_NAME,
      nextStep: 'Check this agent\'s actual callable tool list. If absent, use the HTTPS audit helper and report that transport.' },
    newSessionInstruction: 'After installing or updating, start a new coding-agent session in this same project to load the skill and MCP configuration.' };
  if (preview) return result;
  try {
    const signal = AbortSignal.timeout(30_000), url = new URL('/mcp', base);
    const initialized = await postJson(url, { jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'purple-offense-doctor', version: CLIENT_VERSION } } },
    { fetchImpl, signal, headers: { accept: 'application/json, text/event-stream' }, maximum: 256_000 });
    const decode = response => {
      if (response.body) return response.body;
      const records = response.text.split(/\r?\n/).filter(line => line.startsWith('data: ')).map(line => line.slice(6)).filter(value => value !== '[DONE]');
      return records.length ? JSON.parse(records.at(-1)) : null;
    };
    const initialization = decode(initialized);
    if (initialization?.id !== 1 || initialization.error || typeof initialization.result?.protocolVersion !== 'string' || initialization.result.protocolVersion.length > 80) throw Error('MCP initialization returned an invalid result.');
    const session = initialized.response.headers.get('mcp-session-id');
    if (session && (session.length > 256 || /[\r\n]/.test(session))) throw Error('MCP returned an invalid session identifier.');
    const headers = { accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': initialization.result.protocolVersion,
      ...(session ? { 'Mcp-Session-Id': session } : {}) };
    const notified = await postJson(url, { jsonrpc: '2.0', method: 'notifications/initialized' }, { fetchImpl, signal, headers, maximum: 256_000 });
    if (notified.body?.error) throw Error('MCP rejected the initialization notification.');
    let cursor, advertised = false, listed, pages = 0;
    const cursors = new Set();
    do {
      const id = 2 + pages;
      listed = await postJson(url, { jsonrpc: '2.0', id, method: 'tools/list', params: cursor ? { cursor } : {} }, { fetchImpl, signal, headers, maximum: 256_000 });
      const discovery = decode(listed);
      if (discovery?.id !== id || discovery.error || !Array.isArray(discovery.result?.tools)) throw Error('MCP discovery returned an invalid result.');
      advertised = discovery.result.tools.some(tool => tool?.name === TOOL_NAME);
      cursor = discovery.result.nextCursor;
      if (cursor !== undefined && (typeof cursor !== 'string' || !cursor || cursor.length > 1000 || cursors.has(cursor))) throw Error('MCP discovery returned an invalid or repeated page cursor.');
      if (cursor) cursors.add(cursor);
      pages++;
    } while (!advertised && cursor && pages < 5);
    result.endpoint = { status: advertised ? 'verified' : cursor ? 'discovery_incomplete' : 'expected_tool_missing', protocolVersion: initialization.result.protocolVersion,
      toolAdvertised: advertised, discoveryPages: pages, diagnostics: diagnosticHeaders(listed.response) };
  } catch (error) {
    result.endpoint = { status: 'failed', toolAdvertised: false, message: error.message,
      diagnostics: error.diagnostics || { code: 'protocol_error' } };
  }
  return result;
}

export async function prepareAudit(directory, { planLimit = 3 } = {}) {
  if (!Number.isInteger(planLimit) || planLimit < 0 || planLimit > 10) throw Error('Plan limit must be an integer from 0 to 10.');
  const root = await realpath(directory), files = [], manifests = [], warnings = [], fingerprint = createHash('sha256');
  let entries = 0;
  async function walk(folder, depth = 0) {
    if (depth > 12) { warnings.push(`${path.relative(root, folder)}: directory depth limit reached.`); return; }
    const listing = await readdir(folder, { withFileTypes: true });
    const shrinkwrap = listing.some(entry => entry.isFile() && entry.name === 'npm-shrinkwrap.json');
    for (const entry of listing) {
      if (++entries > 30000) throw Error('Repository exceeds the bounded file search. Select a project subdirectory.');
      const target = path.join(folder, entry.name), relative = path.relative(root, target).split(path.sep).join('/');
      if (entry.isSymbolicLink()) { warnings.push(`${relative}: symlink not followed.`); continue; }
      if (entry.isDirectory()) { if (!entry.name.startsWith('.') && !excluded.has(entry.name)) await walk(target, depth + 1); continue; }
      if (!entry.isFile()) continue;
      if (entry.name === 'package.json') manifests.push(relative);
      if (unsupported.has(entry.name)) warnings.push(`${relative}: unsupported lockfile; not scanned.`);
      if (!supported.has(entry.name) || (shrinkwrap && entry.name === 'package-lock.json')) continue;
      const info = await lstat(target);
      if (info.isSymbolicLink() || !info.isFile()) throw Error('A dependency file changed during collection. Retry.');
      if (info.size > 12_000_000) throw Error(`${relative}: lockfile exceeds 12 MB. Select a smaller project.`);
      const content = await readFile(target, 'utf8');
      files.push({ path: relative, content });
      if (files.length > 20) throw Error('More than 20 supported lockfiles. Select a project subdirectory.');
      fingerprint.update(relative).update('\0').update(content).update('\0');
    }
  }
  await walk(root);
  if (!files.length) throw Error('No supported npm v2/v3 or pnpm v6/v9 lockfile. Exact dependency versions are unknown; generate and review a lockfile before auditing.');
  const clean = sanitizeLockfiles(files);
  const covered = new Set();
  for (const file of clean.files) {
    const base = path.posix.dirname(file.path), lock = JSON.parse(file.content);
    if (file.path.endsWith('pnpm-lock.yaml')) for (const importer of Object.keys(lock.importers || {})) covered.add(path.posix.join(base, importer, 'package.json'));
    else covered.add(path.posix.join(base, 'package.json'));
  }
  for (const manifest of manifests) if (!covered.has(manifest)) warnings.push(`${manifest}: no covering lockfile importer; dependency coverage is incomplete.`);
  const metadataFingerprint = createHash('sha256').update(JSON.stringify(clean.files.slice().sort((a, b) => a.path.localeCompare(b.path)))).digest('hex');
  const evidence = await collectLocalEvidence(root, { coveredManifests: [...covered], supportedLockfiles: clean.files.map(file => file.path) });
  return { request: { files: clean.files, planLimit }, local: { fingerprint: fingerprint.digest('hex'), metadataFingerprint,
    warnings: [...new Set([...warnings, ...clean.warnings, ...evidence.coverage.warnings])], evidence } };
}

export async function auditDependencies(directory, options = {}) {
  if (options.preview) return runAudit(directory, options);
  const enabled = options.trace !== false, startedAt = performance.now();
  let recorder, traceFile, traceWritten = false;
  try { if (enabled) recorder = createOffenseTrace({ origin: 'helper', transport: 'https_helper' }); } catch {}
  const observer = {
    record(...args) { try { recorder?.record(...args); } catch {} },
    output(directory) { traceFile = path.join(directory, 'trace.json'); },
    async flush() {
      if (!recorder || !traceFile) return;
      try { await writeReport(traceFile, serializeOffenseTrace(recorder) + '\n'); traceWritten = true; }
      catch { traceWritten = false; }
    }
  };
  observer.record('discovery', 'started');
  try {
    const result = await runAudit(directory, options, observer);
    observer.record('response', result.status === 'complete' ? 'completed' : 'partial', { durationMs: performance.now() - startedAt, counts: {
      advisoryMatches: result.advisoryMatches, upgradePlans: result.upgradePlans, blockers: result.blockers,
      planningPages: result.planningPages, remainingPlanningTargets: result.remainingPlanningTargets,
      coverageWarnings: result.localCoverageWarnings
    } });
    await observer.flush();
    return { ...result, trace: traceWritten ? traceFile : null, traceStatus: !enabled ? 'disabled' : traceWritten ? 'saved' : 'unavailable' };
  } catch (error) {
    observer.record('response', 'failed', { durationMs: performance.now() - startedAt, errorCode: classifyTraceError(error) });
    await observer.flush();
    if (traceWritten && error && typeof error === 'object') { try { error.traceFile = traceFile; } catch {} }
    throw error;
  }
}

async function runAudit(directory, { endpoint = 'https://app.purpleteam.sh', output, planLimit = 3, maxPages = 10,
  evidence, resume, preview = false, fetchImpl = fetch } = {}, observer = { record() {}, output() {}, async flush() {} }) {
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 10) throw Error('Scan and planning pages must be an integer from 1 to 10.');
  if (preview) return prepareAudit(directory, { planLimit });
  const base = serviceBase(endpoint);
  const root = await realpath(directory), target = output ? path.resolve(output) : await mkdtemp(path.join(os.tmpdir(), 'offense-audit-'));
  if (target === root || target.startsWith(root + path.sep)) throw Error('Choose a report directory outside the source checkout.');
  await checkReportAncestors(root, target);
  await mkdir(target, { recursive: true, mode: 0o700 });
  const resolvedTarget = await realpath(target);
  if (resolvedTarget === root || resolvedTarget.startsWith(root + path.sep)) throw Error('The report directory resolves inside the source checkout.');
  const validFinding = finding => finding && typeof finding.id === 'string' && finding.id && typeof finding.advisoryId === 'string' && finding.advisoryId &&
    finding.package?.ecosystem === 'npm' && typeof finding.package.name === 'string' && finding.package.name &&
    typeof finding.package.installedVersion === 'string' && finding.package.installedVersion && Array.isArray(finding.package.lockfiles) &&
    typeof finding.verification?.status === 'string' && typeof finding.verification.confirmed === 'boolean';
  const json = path.join(resolvedTarget, 'audit.json'), prompt = path.join(resolvedTarget, 'remediation.md');
  await reportDestination(json); await reportDestination(prompt);
  observer.output(resolvedTarget);
  const collectedAt = performance.now();
  const prepared = await prepareAudit(directory, { planLimit });
  observer.record('discovery', 'completed', { durationMs: performance.now() - collectedAt, counts: { lockfiles: prepared.request.files.length } });
  observer.record('local_coverage', prepared.local.warnings.length ? 'partial' : 'completed', { counts: {
    coverageWarnings: prepared.local.warnings.length, uncoveredManifests: prepared.local.evidence.coverage.uncoveredManifests.length,
    unsupportedFiles: prepared.local.evidence.coverage.unsupportedFiles.length, patches: prepared.local.evidence.patches.length
  } });
  await observer.flush();
  const deadline = AbortSignal.timeout(180_000);
  async function request(payload) {
    const stage = payload.planning ? 'upgrade_planning' : 'advisory_scan', startedAt = performance.now();
    observer.record(stage, 'started');
    try {
      const { body: report } = await postJson(new URL('/api/offense/audit', base), payload,
        { fetchImpl, signal: AbortSignal.any([deadline, AbortSignal.timeout(120_000)]) });
      if (report?.schemaVersion !== 'offense.audit.v1' || report.capability !== 'audit_dependencies' || !['complete', 'partial'].includes(report.status) || !Array.isArray(report.findings) || !report.findings.every(validFinding) || !report.coverage || !report.remediation || !Array.isArray(report.remediation.plans) || !Array.isArray(report.remediation.blockers)) {
        observer.record('validation', 'rejected', { errorCode: 'response_invalid' });
        throw Error('Unsupported or incomplete Offense response. Update the skill; no clean result is implied.');
      }
      if (report.metadataFingerprint !== prepared.local.metadataFingerprint) {
        observer.record('validation', 'rejected', { errorCode: 'metadata_changed' });
        throw Error('Offense response does not match the normalized dependency metadata sent. The report was not saved; audit again with current files.');
      }
      observer.record(stage, report.status === 'complete' ? 'completed' : 'partial', { durationMs: performance.now() - startedAt, counts: {
        checkedPackages: report.coverage.checkedPackages, advisoryMatches: report.findings.length,
        upgradePlans: report.remediation.plans.length, blockers: report.remediation.blockers.length
      } });
      return report;
    } catch (error) {
      observer.record(stage, 'failed', { durationMs: performance.now() - startedAt, errorCode: classifyTraceError(error) });
      throw error;
    }
  }
  let report;
  if (resume) {
    const filename = path.resolve(resume), info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 24_000_000) throw Error('Resume requires a regular saved audit.json of at most 24 MB.');
    report = JSON.parse(await readFile(filename, 'utf8'));
    if (report.schemaVersion !== 'offense.audit.v1' || report.capability !== 'audit_dependencies' || report.metadataFingerprint !== prepared.local.metadataFingerprint ||
      report.status !== 'partial' || !Array.isArray(report.findings) || !report.findings.every(validFinding) || !report.scanning?.next ||
      !Number.isInteger(report.scanning.completedPages) || report.scanning.completedPages < 1 ||
      !Array.isArray(report.remediation?.plans) || report.remediation.plans.length || !Array.isArray(report.remediation.blockers)) {
      throw Error('Resume requires an unfinished advisory scan matching the current dependency metadata.');
    }
    // Local evidence is recollected; never carry a previous reviewed assessment
    // into a resumed scan without the explicit --evidence path.
    delete report.localVerification;
  } else report = await request(prepared.request);
  let pages = report.scanning?.next ? 0 : 1, planningError = null, scanningError = null;
  let scanPages = report.scanning?.completedPages || 1, scanRequests = resume ? 0 : 1;
  if (report.coverage.planningOnly || (report.remediation.planning && report.remediation.planning.scope !== 'full_audit')) throw Error('Expected a full advisory audit before planning continuations. No complete scan was established.');
  if (report.scanning) {
    validateScanPage(report);
    if (report.scanning.start !== null) throw Error('Expected the first advisory scan page.');
  }
  let localVerification = null;
  let saved;
  async function persist() {
    const startedAt = performance.now();
    const pending = !!report.remediation.planning?.hasMore;
    saved = { ...report, ...(prepared.local.warnings.length || scanningError || report.scanning?.next || planningError || (planLimit > 0 && pending) ? { status: 'partial', serverStatus: report.status } : {}),
      clientCoverage: prepared.local, clientScanning: { completedPages: scanPages, maxPages,
        stopReason: scanningError ? 'request_failed' : report.scanning?.next ? 'client_page_limit' : 'finished',
        ...(scanningError ? { error: scanningError } : {}) }, clientPlanning: { completedPages: pages, maxPages,
        stopReason: planningError ? 'request_failed' : pending ? 'client_page_limit' : planLimit ? 'finished' : 'not_requested',
        ...(planningError ? { error: planningError } : {}) }, ...(localVerification ? { localVerification } : {}) };
    await writeReport(json, JSON.stringify(saved, null, 2) + '\n');
    const coverage = prepared.local.warnings.length ? `\n\nLocal coverage warnings:\n${prepared.local.warnings.map(warning => `- ${warning}`).join('\n')}` : '';
    const tasks = prepared.local.evidence.coverage.tasks.length ? `\n\nAgent-owned coverage follow-up (local inventory; not uploaded):\n${JSON.stringify(prepared.local.evidence.coverage.tasks, null, 2)}` : '';
    const patches = prepared.local.evidence.patches.length ? '\n\nLocal dependency patches were found. Keep advisory matches visible until patch application, content guards, focused security regressions, and normal behavior are verified at this revision.' : '';
    const verification = localVerification ? `\n\nLocal verification assessment (reviewer-supplied evidence, not an independent hosted confirmation):\n${JSON.stringify(localVerification, null, 2)}` : '';
    const continuation = pending ? `\n\nPlanning is unfinished. The saved audit.json retains remediation.planning.next with remaining stable target IDs. Continue via offense.audit_dependencies using the same sanitized files, planLimit, and planning: remediation.planning.next; preserve this original full scan and merge pages by targetId. A planning-only response is not a new full audit.${planningError ? ` Last request: ${planningError.message}` : ''}` : '';
    const scanning = report.scanning?.next ? `\n\nAdvisory scanning is unfinished. Retain all findings and scanning.next in audit.json. Continue with the same complete sanitized files and scanning: scanning.next; merge contiguous pages before claiming full coverage or planning upgrades.${scanningError ? ` Last request: ${scanningError.message}` : ''}` : '';
    await writeReport(prompt, `${report.remediation.agentPrompt || 'No prepared remediation prompt was returned. Review audit.json and all blockers.'}${coverage}${tasks}${patches}${verification}${scanning}${continuation}\n`);
    observer.record('report', 'completed', { durationMs: performance.now() - startedAt, counts: { planningPages: pages } });
    await observer.flush();
  }
  await persist();
  while (report.scanning?.next && scanRequests < maxPages) {
    try {
      scanRequests++;
      const page = await request({ ...prepared.request, scanning: report.scanning.next });
      report = mergeAuditScanPage(report, page, planLimit); scanPages++;
      pages = 0;
    } catch (error) {
      scanningError = { message: error.message, ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}) };
      await persist(); break;
    }
    await persist();
  }
  const verificationStartedAt = performance.now();
  if (evidence && !report.scanning?.next) {
    observer.record('local_verification', 'started', { evidenceSource: 'reviewed_artifact' });
    try {
      localVerification = await loadReviewedEvidence(root, path.resolve(evidence), {
        metadataFingerprint: prepared.local.metadataFingerprint, findings: report.findings, localEvidence: prepared.local.evidence
      });
    } catch (error) {
      observer.record('local_verification', 'failed', { durationMs: performance.now() - verificationStartedAt,
        errorCode: classifyTraceError(error), evidenceSource: 'reviewed_artifact' });
      throw error;
    }
  }
  observer.record('local_verification', localVerification ? localVerification.status === 'reviewed' ? 'completed' : 'partial' : 'skipped', {
    durationMs: performance.now() - verificationStartedAt, evidenceSource: localVerification ? 'reviewed_artifact' : 'unknown',
    ...(localVerification ? { counts: { compatibilityVerified: localVerification.counts.compatibility_verified,
      mitigationsVerified: localVerification.counts.mitigation_verified, securityRegressionsVerified: localVerification.counts.security_regression_verified } } : {})
  });
  await persist();
  while (!report.scanning?.next && planLimit > 0 && report.remediation.planning?.hasMore && pages < maxPages) {
    const startedAt = performance.now();
    observer.record('continuation', 'started');
    try {
      const next = report.remediation.planning.next;
      if (!next || next.metadataFingerprint !== prepared.local.metadataFingerprint || !Array.isArray(next.pendingTargetIds) || !next.pendingTargetIds.length || next.pendingTargetIds.length > 5000) throw Error('The server returned an invalid planning continuation. Retain the saved original scan.');
      const page = await request({ ...prepared.request, planning: next });
      report = mergeAuditContinuation(report, page); pages++;
      observer.record('continuation', 'completed', { durationMs: performance.now() - startedAt, counts: {
        planningPages: pages, remainingPlanningTargets: report.remediation.planning.remainingTargetIds.length
      } });
    } catch (error) {
      observer.record('continuation', 'failed', { durationMs: performance.now() - startedAt, errorCode: classifyTraceError(error) });
      planningError = { message: error.message, ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}) };
      await persist(); break;
    }
    await persist();
  }
  return { status: saved.status, advisoryMatches: report.findings.length, confirmedVulnerabilities: 0,
    upgradePlans: report.remediation.plans.length, blockers: report.remediation.blockers.length,
    scanningPages: scanPages, remainingScanning: !!report.scanning?.next,
    planningPages: pages, remainingPlanningTargets: report.remediation.planning?.remainingTargetIds?.length || 0,
    localCoverageWarnings: prepared.local.warnings.length,
    ...(localVerification ? { verification: localVerification.counts } : {}), json, prompt };
}

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length || argv.includes('--help')) { console.log('Usage: node offense.mjs metadata [directory] [--plan-limit 0..10]\n       node offense.mjs audit [directory] [--plan-limit 0..10] [--max-pages 1..10] [--resume audit.json] [--evidence file] [--output directory] [--preview] [--no-trace]\n       node offense.mjs doctor [directory]\n       node offense.mjs update [--check | --accept-local]\nNode 20+. Purple uses the offense server/tool. Sanitized npm/pnpm dependency metadata only; local evidence stays local. Audit automatically continues advisory scanning before planning, retaining complete lockfiles. --max-pages bounds each phase per invocation (default 10) within a shared 180-second budget. --resume continues unfinished advisory scanning from a trusted saved audit.json with unchanged metadata; retained evidence is not freshly rechecked. Partial reports retain scanning.next or unfinished planning target IDs. A minimized trace.json records observed helper stages/counts locally; it is never uploaded automatically. Share only trace.json, not the full audit report. --no-trace disables this export. Doctor verifies the endpoint without auditing; it cannot observe this agent session\'s tools. Installed skills check for updates on every run; help and previews stay offline. Exit 4 means start a new session.'); return; }
  const action = argv.shift();
  if (action === 'update') return updaterMain(['--skill', 'offense', ...argv], import.meta.url);
  if (!['metadata', 'audit', 'doctor'].includes(action)) throw Error('Expected metadata, audit or doctor.');
  const directory = argv[0] && !argv[0].startsWith('--') ? argv.shift() : process.cwd();
  const options = { endpoint: process.env.OFFENSE_API_URL };
  while (argv.length) {
    const key = argv.shift();
    if (key === '--plan-limit' && /^\d+$/.test(argv[0] || '')) options.planLimit = Number(argv.shift());
    else if (key === '--max-pages' && /^\d+$/.test(argv[0] || '')) options.maxPages = Number(argv.shift());
    else if (key === '--evidence' && argv[0] && !argv[0].startsWith('--')) options.evidence = argv.shift();
    else if (key === '--resume' && argv[0] && !argv[0].startsWith('--')) options.resume = argv.shift();
    else if (key === '--output' && argv[0] && !argv[0].startsWith('--')) options.output = argv.shift();
    else if (key === '--preview') options.preview = true;
    else if (key === '--no-trace') options.trace = false;
    else throw Error(`Unknown or incomplete option: ${key}`);
  }
  const update = await updateBeforeRun('offense', import.meta.url, { preview: options.preview });
  if (update.stop) return;
  if (action === 'doctor') {
    const result = await doctor(directory, options); console.log(JSON.stringify(result, null, 2));
    if (!options.preview && result.endpoint.status !== 'verified') process.exitCode = 2;
  } else if (action === 'metadata') {
    const result = await prepareAudit(directory, options);
    for (const warning of result.local.warnings) console.error(`Coverage: ${warning}`);
    console.log(JSON.stringify(result.request, null, 2));
  } else {
    const result = await auditDependencies(directory, options); console.log(JSON.stringify(result, null, 2));
    if (!options.preview && (result.status !== 'complete' || result.localCoverageWarnings > 0)) process.exitCode = 2;
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => {
  console.error(`Offense: ${error.message}`);
  if (error.diagnostics) console.error(JSON.stringify(error.diagnostics));
  if (error.traceFile) console.error(`Local minimized trace: ${error.traceFile}`);
  process.exitCode = 1;
});
