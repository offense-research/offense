import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, mkdtemp, rm, lstat, realpath, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { verificationQualified } from './verification-gate.mjs';

const exec = promisify(execFile);
const hash = value => createHash('sha256').update(value).digest('hex');
const revisionPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const generated = file => file.split('/').some(part => ['node_modules', '.pnpm-store'].includes(part));
const fail = message => Object.assign(new Error(message), { code: 'invalid_fix_evidence' });
const safePath = file => typeof file === 'string' && file.length <= 500 && !file.startsWith('/') &&
  !file.includes('\\') && file.split('/').every(part => part && part !== '.' && part !== '..' && part.toLowerCase() !== '.git' && !/[\x00-\x1f\x7f]/.test(part));
const text = value => String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/[<>]/g, '').slice(0, 2000);
const cell = value => text(value).replace(/[\\`*_[\]~]/g, '\\$&').replaceAll('|', '\\|');

function gitEnvironment() {
  return { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0',
    GIT_ATTR_NOSYSTEM: '1', GIT_OPTIONAL_LOCKS: '0' };
}
async function git(directory, args) {
  return (await exec('git', ['-c', `safe.directory=${path.resolve(directory)}`, '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'diff.external=', ...args],
    { cwd: directory, env: gitEnvironment(), timeout: 15000, maxBuffer: 8 * 1024 * 1024 })).stdout;
}
async function regular(root, relative) {
  if (!safePath(relative)) throw fail('Unsafe file path in fix evidence.');
  let current = root;
  for (const segment of relative.split('/')) {
    current = path.join(current, segment);
    if ((await lstat(current)).isSymbolicLink()) throw fail(`Symlinked fix evidence is unsupported: ${text(relative)}`);
  }
  const stat = await lstat(current);
  if (!stat.isFile() || stat.size > 8 * 1024 * 1024) throw fail('Fix evidence files must be regular files no larger than 8 MiB.');
  return { file: current, mode: stat.mode & 0o111 ? '100755' : '100644', bytes: await readFile(current) };
}
async function artifactDirectory(directory, create = false) {
  const absolute = path.resolve(directory);
  let current = path.parse(absolute).root;
  for (const part of path.relative(current, absolute).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('Symlinked or non-directory fix artifact paths are unsupported.');
    } catch (error) {
      if (error.code !== 'ENOENT' || !create) throw error;
      await mkdir(current, { mode: 0o700 });
    }
  }
  if (await realpath(absolute) !== absolute) throw fail('Fix artifact directory changed during validation.');
  return absolute;
}
async function artifactTarget(file) {
  const directory = await artifactDirectory(path.dirname(path.resolve(file)), true), basename = path.basename(file);
  if (!safePath(basename)) throw fail('Unsafe fix artifact filename.');
  const target = path.join(directory, basename);
  try { const stat = await lstat(target); if (!stat.isFile() || stat.isSymbolicLink()) throw fail('Refusing to replace a symlinked or non-regular fix artifact.'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return { directory, target };
}
async function writeArtifact(file, bytes) {
  const { directory, target } = await artifactTarget(file), parentStat = await lstat(directory);
  const temporary = await mkdtemp(path.join(directory, '.purple-artifact-'));
  try {
    const next = path.join(temporary, 'next'); await writeFile(next, bytes, { mode: 0o600, flag: 'wx' });
    await artifactDirectory(directory);
    const current = await lstat(directory);
    if (current.dev !== parentStat.dev || current.ino !== parentStat.ino) throw fail('Fix artifact directory changed while writing.');
    await artifactTarget(file);
    // Rename replaces the destination entry rather than following its target.
    await rename(next, target);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}
async function document(file, maximum = 2 * 1024 * 1024) {
  const absolute = path.resolve(file), parent = await artifactDirectory(path.dirname(absolute));
  const record = await regular(parent, path.basename(absolute));
  if (record.bytes.length > maximum) throw fail('Fix artifact exceeds its size limit.');
  return record.bytes;
}
async function checkoutFiles(directory) {
  const tracked = (await git(directory, ['ls-files', '-z'])).split('\0').filter(Boolean);
  const other = (await git(directory, ['ls-files', '--others', '--exclude-standard', '-z'])).split('\0').filter(Boolean).filter(file => !generated(file));
  const files = [...new Set([...tracked, ...other])].sort();
  if (files.length > 20000) throw fail('Checkout exceeds the 20,000-file evidence limit.');
  return files;
}

// Shared with the orchestrator: no repository programs are run by this observer.
export async function fingerprintCheckout(directory) {
  const root = await artifactDirectory(directory), digest = createHash('sha256');
  let bytes = 0;
  for (const file of await checkoutFiles(root)) {
    try {
      const record = await regular(root, file); bytes += record.bytes.length;
      if (bytes > 64 * 1024 * 1024) throw fail('Checkout exceeds the 64 MiB evidence limit.');
      digest.update(file).update('\0').update(record.mode).update('\0').update(record.bytes).update('\0');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      // A tracked deletion is part of candidate evidence too.
      digest.update(file).update('\0deleted\0');
    }
  }
  return digest.digest('hex');
}

function checksPassed(section) {
  return section?.integrity === true && Array.isArray(section.setup) && section.setup.length > 0 && section.setup.every(item => item.passed === true) &&
    Array.isArray(section.checks) && section.checks.length > 0 && section.checks.every(item => item.passed === true);
}
function checkIdentities(checks) {
  return checks.map(item => JSON.stringify([item.directory || '.', item.command])).sort();
}
function eligible(report) {
  if (!report || report.schemaVersion !== 1 || report.status !== 'ready_for_review' || !revisionPattern.test(report.revision || '')) throw fail('Only a current ready_for_review dependency-fix report can be published.');
  if (!Number.isFinite(report.finishedAt) || Date.now()-report.finishedAt>24*3600_000 || report.finishedAt>Date.now()+300_000) throw fail('Fix verification is older than 24 hours or has no valid completion time. Rescan before publishing.');
  if (!checksPassed(report.baseline) || !checksPassed(report.candidate) ||
      JSON.stringify(checkIdentities(report.baseline.checks)) !== JSON.stringify(checkIdentities(report.candidate.checks))) throw fail('Original baseline and matching candidate checks must pass with unchanged evidence.');
  if (!Array.isArray(report.checklist) || !report.checklist.length || report.checklist.some(row => typeof row.id !== 'string' || !row.id || typeof row.targeted !== 'boolean') ||
      !report.checklist.some(row => row.targeted) || report.checklist.some(row => row.targeted && !['remediated', 'resolved'].includes(row.status))) throw fail('Every targeted advisory needs an explicit successful remediation outcome.');
  if (!Array.isArray(report.remainingAdvisories) || !Array.isArray(report.newAdvisories) || report.newAdvisories.length) throw fail('Remaining and new advisory results must be explicit; new advisories block publication.');
  const final = report.finalScan || report.rescan;
  if (final?.status !== 'complete' && final?.vulnerabilityCheck?.status !== 'complete') throw fail('A completed independent advisory rescan is required.');
  if(typeof final.json!=='string'||!digestPattern.test(final.fingerprint||'')||!Number.isFinite(final.checkedAt)||!Number.isFinite(report.startedAt))throw fail('The independent rescan needs its persisted artifact, fingerprint and checked time.');
  if (!digestPattern.test(report.patch?.sha256 || '') || !digestPattern.test(report.evidence?.sourceFingerprint || '') || !digestPattern.test(report.evidence?.candidateFingerprint || '')) throw fail('Patch and checkout evidence digests are required.');
  if (typeof report.sourceDirectory !== 'string' || typeof report.candidateDirectory !== 'string') throw fail('Pinned source and candidate checkout paths are required.');
}

function advisoryRows(items) {
  return items.map(item => `| ${cell(item.id || item.advisory)} | ${cell(item.package)}@${cell(item.version)} | ${cell(item.severity || 'unknown')} | ${item.targeted ? 'Yes' : 'No'} | ${cell(item.status || 'unassessed')} | ${cell(item.reason || '')} |`);
}
function commandRows(label, section) {
  return [...(section?.setup || []), ...(section?.checks || [])].map(item => `- ${label}: \`${cell((item.command || []).join(' '))}\` (${cell(item.directory || '.')}) — ${item.passed === true ? 'passed' : 'blocked/failed'}`);
}
function maintenanceReview(report) {
  const reviewWarnings = Array.isArray(report.reviewWarnings) ? report.reviewWarnings : [];
  return { needsMaintainerReview: report.needsMaintainerReview === true || reviewWarnings.length > 0, reviewWarnings };
}
export async function createDependencyPrHandoff({ report, patchPath = report?.patch?.path, outputDirectory, repository = report?.repository }) {
  const ready = report?.status === 'ready_for_review';
  if (!report || !outputDirectory || (ready && (!revisionPattern.test(report.revision || '') || !patchPath))) throw fail('A pinned report, patch and output directory are required for a publishable handoff.');
  for (const checkout of [report.sourceDirectory, report.candidateDirectory].filter(Boolean)) {
    const relative = path.relative(path.resolve(checkout), path.resolve(outputDirectory));
    if (!relative || (!relative.startsWith('..'+path.sep) && relative !== '..' && !path.isAbsolute(relative))) throw fail('PR handoff artifacts must be outside the source and candidate checkouts.');
  }
  if (repository && !repositoryPattern.test(repository)) throw fail('Expected a GitHub owner/repository.');
  const patchBytes = patchPath ? await document(patchPath) : null, patchSha256 = patchBytes ? hash(patchBytes) : null, reportSha256 = hash(JSON.stringify(report));
  if (patchBytes && report.patch?.sha256 !== patchSha256) throw fail('Patch bytes no longer match the reviewed fix report.');
  const title = 'fix: remediate vulnerable dependencies';
  const branch = ready ? `codex/dependency-fix-${report.revision.slice(0, 12)}-${patchSha256.slice(0, 10)}` : null;
  const marker = `<!-- purple-dependency-fix report=${reportSha256} patch=${patchSha256} revision=${report.revision || 'unavailable'} -->`;
  const security = verificationQualified(report.securityVerification);
  const maintenance = maintenanceReview(report);
  const lines = [
    ready ? 'This patch applies coordinated dependency upgrades and any recorded compatibility repairs.' : 'This dependency-fix run has no publishable patch. Review its outcomes and blockers below.',
    `Pinned base: \`${report.revision || 'unavailable'}\`. Report status: **${text(report.status)}**.`,
    ...(maintenance.needsMaintainerReview ? ['', '### Maintainer review required', '',
      'The recorded advisory and compatibility results do not establish that the selected version is recommended by its maintainer. Review these package maintenance warnings before accepting the upgrade:',
      ...maintenance.reviewWarnings.map(warning => `- **${cell(warning.type || 'Maintenance warning')}** — ${cell(warning.package)}@${cell(warning.version)} (${cell(warning.source || 'dependency')}): ${cell(warning.message)}`),
      '- This remains a draft for human review. No upstream recommendation or automatic merge is implied.'] : []),
    '', '### Advisory checklist', '', '| Advisory | Package | Severity | Targeted | Outcome | Evidence / blocker |', '| --- | --- | --- | --- | --- | --- |',
    ...advisoryRows(report.checklist || []),
    '', '### Validation', '', ...commandRows('Baseline', report.baseline), ...commandRows('Candidate', report.candidate),
    `- Remaining advisory matches in the full supported dependency rescan: ${report.remainingAdvisories?.length ?? 'not checked'}.`,
    `- New advisory matches: ${report.newAdvisories?.length ?? 'not checked'}.`,
    security ? '- A separate security regression passed Purple’s structured reproduction-and-fix gate; inspect its recorded invariant and evidence.' :
      '- Verification covers dependency advisory removal and recorded compatibility checks. Exploit reproduction is not established by these checks.',
    '', '### Remaining scope and review', '',
    ...(report.remainingAdvisories || []).map(item => `- Remaining: ${cell(item.id)} — ${cell(item.package)}@${cell(item.version)}.`),
    ...(report.blockers || []).map(item => `- Blocker: ${cell(item)}`),
    ...(report.limitations || []).map(item => `- ${cell(item)}`),
    '- Applicability and reachability remain unassessed unless the report provides explicit evidence; missing paths do not prove safety.',
    '- CI on this pull request has not been established as passing by the local fix run.',
    '- Review the patch and any deferred findings before merging. This workflow never merges automatically.',
    '', '### Artifact integrity', '', `Report SHA-256: \`${reportSha256}\``, `Patch SHA-256: \`${patchSha256 || 'no patch produced'}\``, '', marker, ''
  ];
  await artifactDirectory(outputDirectory, true);
  const bodyPath = path.join(outputDirectory, 'pr-body.md'), manifestPath = path.join(outputDirectory, 'pr-handoff.json');
  const manifest = { schemaVersion: 1, repository: repository || null, revision: report.revision, title, branch,
    reportSha256, patchSha256, patchPath: patchPath ? path.resolve(patchPath) : null, bodyPath: path.resolve(bodyPath), publishable: report.status === 'ready_for_review', ...maintenance };
  await writeArtifact(bodyPath, lines.join('\n'));
  manifest.bodySha256 = hash(await readFile(bodyPath));
  await writeArtifact(manifestPath, JSON.stringify(manifest, null, 2)+'\n');
  return { bodyPath, manifestPath, title, branch, reportSha256, patchSha256 };
}

function githubEnvironment() {
  const env = {};
  // Only the trusted publisher sees the selected existing GitHub login.
  for (const key of ['PATH', 'HOME', 'XDG_CONFIG_HOME', 'GH_CONFIG_DIR', 'GH_TOKEN', 'GITHUB_TOKEN', 'SSL_CERT_FILE', 'SSL_CERT_DIR']) if (process.env[key]) env[key] = process.env[key];
  env.GH_PROMPT_DISABLED = '1'; env.GIT_TERMINAL_PROMPT = '0';
  return env;
}
export function githubCliTransport() {
  return { async request(method, endpoint, body) {
    const directory = await mkdtemp(path.join(tmpdir(), 'purple-pr-publish-'));
    try {
      const args = ['api', '--hostname', 'github.com', '--method', method, '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', endpoint];
      if (body !== undefined) {
        const file = path.join(directory,'request.json'); await writeFile(file, JSON.stringify(body), {mode:0o600});
        args.push('--input', file);
      }
      const {stdout} = await exec('gh', args, {cwd:directory,env:githubEnvironment(),timeout:30000,maxBuffer:4*1024*1024});
      return stdout.trim() ? JSON.parse(stdout) : null;
    } catch (error) {
      const status = /HTTP (\d{3})/.exec(error.stderr || '')?.[1];
      if (status === '404') return null;
      throw Object.assign(new Error(error.code === 'ENOENT' ? 'The existing GitHub CLI connection is unavailable.' : `GitHub request was rejected${status ? ` (HTTP ${status})` : ''}.`),
        {code:'github_connection_unavailable',status:status?Number(status):null});
    } finally {await rm(directory,{recursive:true,force:true});}
  }};
}
async function changesFor(candidate) {
  const raw = (await git(candidate,['diff','--name-status','--no-renames','-z','HEAD'])).split('\0').filter(Boolean), changes=[];
  if (!raw.length || raw.length%2 || raw.length>200) throw fail('Publication requires 1–100 reviewable changed files.');
  for(let index=0;index<raw.length;index+=2) {
    const [status,file]=[raw[index],raw[index+1]];
    if(!['A','M','D'].includes(status)||!safePath(file)||generated(file))throw fail('Unsupported patch path or change type.');
    // Workflow edits need a deliberately separate capability, never implicit escalation.
    if(file.startsWith('.github/workflows/')||['.gitmodules','.gitattributes','.lfsconfig'].includes(file)) throw fail('This publisher does not authorize workflow, submodule or Git filter configuration changes.');
    const basename=path.posix.basename(file);
    if((/^\.env(?:\.|$)/.test(basename)&&!['.env.example','.env.sample','.env.template'].includes(basename))||['.npmrc','.pypirc','id_rsa','id_ed25519'].includes(basename)||file.split('/').some(part=>['.aws','.ssh'].includes(part)))throw fail('Credential and secret configuration files cannot be published by this workflow.');
    if(status==='D') changes.push({path:file,mode:'100644',type:'blob',sha:null,status});
    else {
      const record=await regular(candidate,file);
      const sha=createHash('sha1').update(`blob ${record.bytes.length}\0`).update(record.bytes).digest('hex');
      changes.push({path:file,mode:record.mode,type:'blob',sha,status,content:record.bytes.toString('base64')});
    }
  }
  return changes;
}
export async function validateArtifacts(reportFile, manifestPath) {
  const report=JSON.parse((await document(reportFile)).toString('utf8')); eligible(report);
  await artifactTarget(path.join(path.dirname(path.resolve(reportFile)), 'pr-published.json'));
  const manifest=JSON.parse((await document(manifestPath)).toString('utf8'));
  if(manifest.schemaVersion!==1||manifest.reportSha256!==hash(JSON.stringify(report))||manifest.revision!==report.revision||manifest.publishable!==true)throw fail('The report changed after its PR handoff was prepared.');
  const maintenance=maintenanceReview(report);
  if(manifest.needsMaintainerReview!==maintenance.needsMaintainerReview||JSON.stringify(manifest.reviewWarnings)!==JSON.stringify(maintenance.reviewWarnings))throw fail('Package maintenance warnings differ from the reviewed report.');
  const patchPath=report.patch.path, patch=await document(patchPath);
  if(!patch.length||hash(patch)!==report.patch.sha256||manifest.patchSha256!==report.patch.sha256||manifest.patchPath!==path.resolve(patchPath))throw fail('Patch integrity no longer matches the handoff.');
  const body=await document(manifest.bodyPath);
  if(hash(body)!==manifest.bodySha256)throw fail('PR text changed after the handoff was prepared.');
  const final=report.finalScan||report.rescan,scan=JSON.parse((await document(final.json)).toString('utf8'));
  const results=scan.vulnerabilityCheck;
  if(hash(JSON.stringify(scan))!==final.fingerprint||results?.status!=='complete'||!Array.isArray(results.findings)||scan.warnings?.length||
    results.checkedAt!==final.checkedAt||final.checkedAt<report.startedAt-5000||final.checkedAt>report.finishedAt+5000||final.checkedAt>Date.now()+300000||
    JSON.stringify(results.findings)!==JSON.stringify(report.remainingAdvisories))throw fail('The persisted final advisory scan changed or does not match the reported results.');
  const original=new Set(report.checklist.map(row=>`${row.package}:${row.id}`));
  if(JSON.stringify(results.findings.filter(row=>!original.has(`${row.package}:${row.id}`)))!==JSON.stringify(report.newAdvisories)||
    report.checklist.some(row=>row.targeted&&results.findings.some(finding=>finding.package===row.package&&finding.id===row.id)))throw fail('Final advisory evidence contradicts the remediation checklist.');
  if((await git(report.sourceDirectory,['rev-parse','HEAD'])).trim()!==report.revision || (await git(report.candidateDirectory,['rev-parse','HEAD'])).trim()!==report.revision)throw fail('The source or candidate revision changed.');
  if(await fingerprintCheckout(report.sourceDirectory)!==report.evidence.sourceFingerprint||await fingerprintCheckout(report.candidateDirectory)!==report.evidence.candidateFingerprint)throw fail('Source or candidate files changed after verification.');
  const sourceStatus=(await git(report.sourceDirectory,['status','--porcelain','--untracked-files=all'])).split('\n').filter(Boolean).filter(line=>!generated(line.slice(3)));
  if(sourceStatus.length)throw fail('The pinned source checkout is no longer clean.');
  const actual=await git(report.candidateDirectory,['diff','--binary','--no-ext-diff','--no-textconv','HEAD']);
  if(hash(Buffer.from(actual))!==report.patch.sha256)throw fail('The current candidate diff differs from the reviewed patch.');
  const changes=await changesFor(report.candidateDirectory);
  // Bind bytes read for publication to the same candidate observation.
  if(await fingerprintCheckout(report.candidateDirectory)!==report.evidence.candidateFingerprint)throw fail('Candidate changed while preparing publication.');
  return {report,manifest,body:body.toString('utf8'),changes};
}
const component = value => encodeURIComponent(value);
function branchValid(branch) {
  return typeof branch==='string'&&branch.length<=180&&/^[A-Za-z0-9][A-Za-z0-9._/-]+$/.test(branch)&&!branch.includes('..')&&!branch.includes('//')&&
    branch.split('/').every(part=>part&&!part.startsWith('.')&&!part.endsWith('.')&&!part.endsWith('.lock'));
}
export async function matchesPublishedCommit(transport, prefix, revision, head, changes) {
  const compare=await transport.request('GET',`${prefix}/compare/${revision}...${head}`);
  if(!compare||compare.total_commits!==1||!Array.isArray(compare.files)||compare.files.length!==changes.length)return false;
  if(!changes.every(change=>compare.files.some(file=>file.filename===change.path && file.status===({A:'added',M:'modified',D:'removed'})[change.status] && (change.status==='D'||file.sha===change.sha))))return false;
  const commit=await transport.request('GET',`${prefix}/git/commits/${head}`);
  if(!revisionPattern.test(commit?.tree?.sha||'')||commit.parents?.length!==1||commit.parents[0].sha!==revision)return false;
  const tree=await transport.request('GET',`${prefix}/git/trees/${commit.tree.sha}?recursive=1`);
  if(!tree||tree.truncated!==false||!Array.isArray(tree.tree))return false;
  return changes.every(change=>change.status==='D'?!tree.tree.some(entry=>entry.path===change.path):
    tree.tree.some(entry=>entry.path===change.path&&entry.type==='blob'&&entry.mode===change.mode&&entry.sha===change.sha));
}

export async function dependencyPrChecks({repository,headSha}, {transport=githubCliTransport()}={}) {
  if(!repositoryPattern.test(repository||'')||!revisionPattern.test(headSha||''))throw fail('A GitHub repository and commit SHA are required.');
  const prefix=`repos/${repository}`;
  try {
    const checks=await transport.request('GET',`${prefix}/commits/${headSha}/check-runs?per_page=100`);
    const statuses=await transport.request('GET',`${prefix}/commits/${headSha}/status?per_page=100`);
    const runs=checks?.check_runs||[],states=statuses?.statuses||[];
    if ((Number.isInteger(checks?.total_count)&&checks.total_count>runs.length)||(Number.isInteger(statuses?.total_count)&&statuses.total_count>states.length)) return {status:'incomplete',count:runs.length+states.length};
    if(!runs.length&&!states.length)return {status:'not_reported',count:0};
    const failed=runs.some(x=>x.status==='completed'&&['failure','cancelled','timed_out','action_required','startup_failure'].includes(x.conclusion))||states.some(x=>['error','failure'].includes(x.state));
    const pending=runs.some(x=>x.status!=='completed')||states.some(x=>x.state==='pending');
    const passed=!failed&&!pending&&runs.every(x=>x.conclusion==='success')&&states.every(x=>x.state==='success');
    return {status:failed?'failed':pending?'pending':passed?'passed':'needs_review',count:runs.length+states.length};
  }catch{return {status:'unavailable',count:null};}
}

export async function publishDependencyFix({reportFile,repository,branch,base,authorizePublish=false,manifestPath=path.join(path.dirname(path.resolve(reportFile||'.')),'pr-handoff.json'),draft=true},
  {transport=githubCliTransport()}={}) {
  if(authorizePublish!==true)throw fail('Explicit authorization is required to publish a dependency-fix branch and pull request.');
  if(!reportFile||!repositoryPattern.test(repository||''))throw fail('A report and explicit GitHub owner/repository are required.');
  const {report,manifest,body,changes}=await validateArtifacts(reportFile,manifestPath);
  const maintenance=maintenanceReview(report);
  if(maintenance.needsMaintainerReview&&draft!==true)throw fail('Package maintenance warnings require a draft pull request for maintainer review.');
  if((report.repository&&report.repository.toLowerCase()!==repository.toLowerCase())||(manifest.repository&&manifest.repository.toLowerCase()!==repository.toLowerCase()))throw fail('The selected GitHub repository differs from the reviewed report.');
  branch ||= manifest.branch;
  if(!branchValid(branch))throw fail('Invalid publication branch.');
  const prefix=`repos/${repository}`;
  let published=null;
  try {
    const repo=await transport.request('GET',prefix);
    if(!repo||repo.permissions?.push===false)return {status:'blocked',reason:'The existing GitHub connection has no write access to this repository.'};
    base ||= repo.default_branch;
    if(!branchValid(base)||base===branch)throw fail('A distinct valid base branch is required.');
    const baseRef=await transport.request('GET',`${prefix}/git/ref/heads/${component(base)}`);
    if(baseRef?.object?.sha!==report.revision)throw fail('The GitHub base branch moved since verification. Rescan and verify the new base.');
    const headRef=await transport.request('GET',`${prefix}/git/ref/heads/${component(branch)}`);
    let head=headRef?.object?.sha;
    if(head&&!await matchesPublishedCommit(transport,prefix,report.revision,head,changes))throw fail('The requested branch already contains a different patch; it will not be overwritten.');
    const prs=await transport.request('GET',`${prefix}/pulls?state=all&head=${component(repository.split('/')[0]+':'+branch)}&base=${component(base)}&per_page=100`);
    const marker=`<!-- purple-dependency-fix report=${manifest.reportSha256} patch=${manifest.patchSha256} revision=${report.revision || 'unavailable'} -->`;
    const existing=Array.isArray(prs)?prs.find(pr=>pr.head?.ref===branch&&pr.base?.ref===base):null;
    if(existing) {
      if(!head||!existing.body?.includes(marker)||existing.head?.sha!==head)throw fail('An existing pull request has different review evidence.');
      published={status:'published',url:existing.html_url,number:existing.number,headSha:head,repository,branch,base,reused:true};
    }else {
      if(!head) {
        const commit=await transport.request('GET',`${prefix}/git/commits/${report.revision}`);
        if(!revisionPattern.test(commit?.tree?.sha||''))throw fail('GitHub did not return the verified base tree.');
        const entries=[];
        for(const change of changes) {
          if(change.sha) {
            const blob=await transport.request('POST',`${prefix}/git/blobs`,{content:change.content,encoding:'base64'});
            if(blob?.sha!==change.sha)throw fail('GitHub stored unexpected patch content.');
          }
          entries.push({path:change.path,mode:change.mode,type:'blob',sha:change.sha});
        }
        const tree=await transport.request('POST',`${prefix}/git/trees`,{base_tree:commit.tree.sha,tree:entries});
        if(!revisionPattern.test(tree?.sha||''))throw fail('GitHub did not return the candidate tree.');
        const made=await transport.request('POST',`${prefix}/git/commits`,{message:manifest.title,tree:tree.sha,parents:[report.revision]});
        if(!revisionPattern.test(made?.sha||''))throw fail('GitHub did not return the candidate commit.');
        head=made.sha;
        const latest=await transport.request('GET',`${prefix}/git/ref/heads/${component(base)}`);
        if(latest?.object?.sha!==report.revision)throw fail('The base branch changed during publication; no fix branch was created.');
        await transport.request('POST',`${prefix}/git/refs`,{ref:`refs/heads/${branch}`,sha:head});
      }
      const pr=await transport.request('POST',`${prefix}/pulls`,{title:manifest.title,head:branch,base,body,draft:!!draft});
      const expectedUrl = `https://github.com/${repository}/pull/${pr?.number}`;
      if(typeof pr?.html_url !== 'string' || pr.html_url.toLowerCase() !== expectedUrl.toLowerCase() || !Number.isSafeInteger(pr.number) || pr.number < 1)throw fail('GitHub did not return the created pull request.');
      published={status:'published',url:pr.html_url,number:pr.number,headSha:head,repository,branch,base,reused:false};
    }
    Object.assign(published,maintenance);
    published.ci=await dependencyPrChecks({repository,headSha:published.headSha},{transport});
    await writeArtifact(path.join(path.dirname(path.resolve(reportFile)),'pr-published.json'),JSON.stringify({...published,reportSha256:manifest.reportSha256,patchSha256:manifest.patchSha256},null,2)+'\n');
    return published;
  }catch(error) {
    if(error.code==='github_connection_unavailable')return {status:'blocked',repository,branch,reason:error.message,publicationMayHaveStarted:true};
    throw error;
  }
}
