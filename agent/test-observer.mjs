// Trusted coordinator. Repository stdout/stderr are test events, never verdicts.
import { run } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const files = JSON.parse(process.argv[2]);
if (!Array.isArray(files) || !files.length || files.length > 200) throw new Error('Invalid test scope.');
const root = process.cwd(), tests = [], infrastructureErrors = [];
let summary, events = 0;
const isolated = process.env.PURPLE_FIX_OBSERVER_ISOLATION === '1';
if (isolated && (process.platform !== 'linux' || process.getuid?.() !== 0)) throw new Error('Isolated observer must use the trusted controller identity.');
const execArgv = isolated ? ['--disable-sigusr1', '--import', fileURLToPath(new URL('./drop-repository-privileges.mjs', import.meta.url))] : [];
for await (const event of run({ files: files.map(file => path.join(root, file)), concurrency: false, timeout: 120000, execArgv })) {
  if (++events > 30000) throw new Error('Test event budget exceeded.');
  const data = event.data;
  if (event.type === 'test:summary' && !data.file) summary = data.counts;
  if (!['test:pass', 'test:fail'].includes(event.type)) continue;
  const error = data.details?.error;
  if (data.details?.type === 'suite' || error?.failureType === 'subtestsFailed') continue;
  const file = data.file ? path.relative(root, data.file).split(path.sep).join('/') : null;
  // Node also emits a successful file wrapper when a file defines zero tests.
  if (!file || !files.includes(file) || data.name === data.file || data.name === file) {
    infrastructureErrors.push({ kind: 'test_file_or_scope_error', file }); continue;
  }
  const cause = error?.cause;
  const assertion = event.type === 'test:fail' && cause?.code === 'ERR_ASSERTION' ? {
    code: cause.code, failureType: error.failureType, operator: cause.operator,
    actual: cause.actual, expected: cause.expected
  } : null;
  if (event.type === 'test:fail' && !assertion) infrastructureErrors.push({ kind: error?.failureType || 'test_runtime_error', file, name: data.name });
  tests.push({ file, line: data.line, name: data.name, status: event.type === 'test:pass' ? 'passed' : 'failed',
    skip: Boolean(data.skip), todo: Boolean(data.todo), ...(assertion ? { assertion } : {}) });
  if (tests.length > 2000) throw new Error('Test count exceeds 2,000.');
}
const report = { protocolVersion: 2, complete: Boolean(summary), summary, tests, infrastructureErrors };
const output = JSON.stringify(report);
if (output.length > 128000) throw new Error('Structured test report exceeds 128 KB.');
process.stdout.write(output);
