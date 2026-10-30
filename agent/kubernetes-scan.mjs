import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { LineCounter, parseAllDocuments } from 'yaml';
import { KUBERNETES_SCAN_TOOLS, kubernetesScanVersion } from '../shared/kubernetes-scan.js';
import { stageAdapterFiles, validateAdapterOptions } from './scan-adapter-files.mjs';

const VERSIONS = { 'k8s-deprecations': '5.24.4', 'k8s-manifest-validate': '0.8.0' };
const MAX_OUTPUT = 8 * 1024 * 1024;
const MAX_RESOURCES = 2000;
export const KUBERNETES_SCHEMA_REVISION = '89a35a5e9a1412a692a2603d79c3786f602238a4';
const signature = resource => resource && typeof resource === 'object' && !Array.isArray(resource) &&
  typeof resource.kind === 'string' && /^[A-Za-z][A-Za-z0-9]{0,99}$/.test(resource.kind) &&
  typeof resource.apiVersion === 'string' && /^(?:[a-z0-9][a-z0-9.-]{0,199}\/)?v[0-9]+(?:(?:alpha|beta)[0-9]+)?$/.test(resource.apiVersion);

// Parse before invoking Pluto: its detect-files command silently skips malformed
// YAML. Each resource gets its own JSON file so duplicate names and multi-document
// manifests retain distinct, source-mapped findings without persisting raw output.
export async function runKubernetesScan({ tool, root, files, kubernetesVersion,
  execute = spawnSync, timeoutMs = 120000, schemaRoot = '/opt/purple/kubernetes-schemas' }) {
  validateAdapterOptions({ root, files, timeoutMs });
  if (!KUBERNETES_SCAN_TOOLS.includes(tool)) throw new Error('Unknown Kubernetes scanner.');
  kubernetesScanVersion({ tools: [tool], kubernetesVersion });
  const pluto = tool === 'k8s-deprecations';
  const selected = files.filter(file => /\.(json|ya?ml)$/i.test(file));
  const coverage = { kubernetesVersion, eligibleFiles: selected.length, excludedFiles: files.length - selected.length,
    resources: 0, rejectedDocuments: 0, offline: true,
    ...(pluto ? {} : { schemaRevision: KUBERNETES_SCHEMA_REVISION }),
    scope: pluto ? 'Submitted rendered manifests against bundled Kubernetes API lifecycle rules only. Unlisted APIs are not assessed. No live cluster, Helm rendering or GPU upgrade compatibility checks.' :
      'Submitted rendered manifests against bundled strict Kubernetes schemas only. Missing schemas, including custom resources, are coverage gaps. No admission, runtime or GPU upgrade compatibility checks.' };
  const result = (status, findings = [], error) => ({ status, version: VERSIONS[tool], findings, coverage, ...(error ? { error } : {}) });
  if (!selected.length) return result('partial', [], 'No YAML or JSON manifests were supplied.');
  const staged = await stageAdapterFiles(root, selected);
  try {
    const manifests = path.join(staged.directory, 'manifests');
    await mkdir(manifests, { mode: 0o700 });
    const locations = new Map();
    for (const file of selected) {
      const content = await readFile(path.join(staged.source, file), 'utf8');
      const lineCounter = new LineCounter();
      let documents;
      // Kubernetes' YAML-to-JSON conversion uses YAML 1.1 scalar semantics:
      // unquoted yes/no and octal values must not silently change during staging.
      try { documents = parseAllDocuments(content, { lineCounter, version: '1.1', schema: 'yaml-1.1', merge: false, strict: true, uniqueKeys: true }); }
      catch { coverage.rejectedDocuments++; continue; }
      for (const [documentIndex, document] of documents.entries()) {
        let value;
        try {
          if (document.errors.length || document.warnings.length) throw new Error('Invalid YAML');
          value = document.toJS({ maxAliasCount: 0 });
        } catch { coverage.rejectedDocuments++; continue; }
        if (value === null) continue;
        const resources = value?.kind === 'List' && value.apiVersion === 'v1' && Array.isArray(value.items) ? value.items : [value];
        if (!resources.length) coverage.rejectedDocuments++;
        for (const [itemIndex, resource] of resources.entries()) {
          if (!signature(resource) || resource.kind === 'List') { coverage.rejectedDocuments++; continue; }
          if (locations.size >= MAX_RESOURCES) return result('partial', [], 'More than 2000 resources were supplied. Narrow the scan.');
          let serialized;
          try {
            serialized = JSON.stringify(resource, (_key, value) => {
              if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Non-JSON numeric value');
              return value;
            });
          } catch { coverage.rejectedDocuments++; continue; }
          const filename = path.join(manifests, `${locations.size}.json`);
          locations.set(filename, { file, line: lineCounter.linePos(document.range?.[0] || 0).line,
            document: documentIndex + 1, item: itemIndex + 1, kind: resource.kind, apiVersion: resource.apiVersion });
          // Pluto only needs the API identity. Invalid metadata or arbitrary
          // spec.items must not make its typed stub parser silently omit an API.
          const input = pluto ? JSON.stringify({ apiVersion: resource.apiVersion, kind: resource.kind }) : serialized;
          await writeFile(filename, input, { mode: 0o600, flag: 'wx' });
        }
      }
    }
    coverage.resources = locations.size;
    if (!locations.size) return result('partial', [], 'No parseable Kubernetes resources were supplied. Render templates and check YAML/JSON syntax.');
    const args = pluto ? ['detect-files', '--directory', 'manifests', '--output', 'json', '--components', 'k8s',
      '--target-versions', `k8s=v${kubernetesVersion}`] :
      ['-strict', '-summary', '-verbose', '-output', 'json', '-n', '2', '-kubernetes-version', kubernetesVersion,
        '-schema-location', schemaRoot, 'manifests'];
    let completed;
    try {
      completed = execute(pluto ? '/usr/local/bin/pluto' : '/usr/local/bin/kubeconform', args, {
        cwd: staged.directory, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: staged.directory, TMPDIR: staged.directory, NO_COLOR: '1' },
        encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT, stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { return result('failed', [], 'Kubernetes scanner failed or timed out.'); }
    if (!completed || completed.error || completed.signal || !(pluto ? [0, 2, 3, 4] : [0, 1]).includes(completed.status))
      return result('failed', [], 'Kubernetes scanner failed or timed out.');
    let raw;
    try {
      if (typeof completed.stdout !== 'string' || Buffer.byteLength(completed.stdout) > MAX_OUTPUT) throw new Error('Report bounds');
      raw = JSON.parse(completed.stdout);
      if (pluto ? raw?.['target-versions']?.k8s !== `v${kubernetesVersion}` ||
          raw.items !== undefined && !Array.isArray(raw.items) : !Array.isArray(raw?.resources)) throw new Error('Report shape');
    } catch { return result('failed', [], 'Kubernetes scanner returned an invalid report.'); }
    const findings = [], seen = new Set();
    let incomplete = coverage.rejectedDocuments > 0;
    const add = (location, ruleId, severity, title, remediation) => {
      const finding = { tool, ruleId, ...location, severity, title, remediation, kubernetesVersion,
        verification: 'scanner_finding', documentationUrl: pluto ? 'https://kubernetes.io/docs/reference/using-api/deprecation-guide/' : 'https://kubernetes.io/docs/reference/kubernetes-api/' };
      finding.id = createHash('sha256').update(JSON.stringify([tool, location.file, location.document, location.item, ruleId, kubernetesVersion])).digest('hex').slice(0, 32);
      findings.push(finding);
    };
    for (const entry of (pluto ? raw.items || [] : raw.resources)) {
      const filename = pluto ? entry?.filePath : entry?.filename;
      const location = typeof filename === 'string' ? locations.get(path.resolve(staged.directory, filename)) : null;
      if (!location || seen.has(filename)) { incomplete = true; continue; }
      seen.add(filename);
      if (pluto) {
        if (entry.api?.kind !== location.kind || entry.api?.version !== location.apiVersion ||
            typeof entry.removed !== 'boolean' || typeof entry.deprecated !== 'boolean') { incomplete = true; continue; }
        if (!entry.removed && !entry.deprecated) continue;
        const replacement = entry.api['replacement-api'];
        add(location, entry.removed ? 'k8s-api-removed' : 'k8s-api-deprecated', entry.removed ? 'HIGH' : 'MEDIUM',
          `${location.kind} ${location.apiVersion} is ${entry.removed ? 'removed' : 'deprecated'} in Kubernetes ${kubernetesVersion}`,
          typeof replacement === 'string' && /^[a-zA-Z0-9./-]{1,200}$/.test(replacement) && entry.replacementAvailable === true ?
            `Migrate to ${replacement} using the Kubernetes migration guide, including required field changes. Validate and test before upgrading.` :
            'Review the Kubernetes migration guide for this API. No available replacement is established by this report.');
      } else {
        if (entry.status === 'statusInvalid') add(location, 'k8s-schema-invalid', 'HIGH',
          `${location.kind} does not match the Kubernetes ${kubernetesVersion} schema`,
          'Review this document against the target Kubernetes API schema, including field types, required fields and unknown properties. Validate the corrected manifest again.');
        else if (entry.status !== 'statusValid') incomplete = true;
      }
    }
    if (!pluto) {
      const summary = raw.summary;
      if (!summary || ['valid', 'invalid', 'errors', 'skipped'].some(key => !Number.isSafeInteger(summary[key]) || summary[key] < 0) ||
          summary.valid + summary.invalid + summary.errors + summary.skipped !== locations.size || seen.size !== locations.size ||
          summary.errors || summary.skipped || completed.status !== (summary.invalid || summary.errors ? 1 : 0)) incomplete = true;
      coverage.validResources = summary?.valid || 0;
      coverage.invalidResources = summary?.invalid || 0;
      coverage.unvalidatedResources = (summary?.errors || 0) + (summary?.skipped || 0);
    } else if (completed.status !== 0 && !findings.length) incomplete = true;
    if (findings.length > 500) incomplete = true;
    return result(incomplete ? 'partial' : 'complete', findings.slice(0, 500), incomplete ?
      'Some resources could not be parsed or validated, schemas were missing, or findings exceeded the limit. Narrow the scan and review coverage; this is not a clean result.' : undefined);
  } finally { await staged.cleanup(); }
}
