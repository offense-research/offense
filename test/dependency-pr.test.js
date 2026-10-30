import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fingerprintCheckout, createDependencyPrHandoff, publishDependencyFix, dependencyPrChecks } from '../agent/pr-handoff.mjs';

const sha256=value=>createHash('sha256').update(value).digest('hex');
const run=(directory,args)=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:directory,env:{PATH:process.env.PATH,GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_NOSYSTEM:'1'},encoding:'utf8',stdio:['ignore','pipe','pipe']});
async function fixture() {
  const root=await mkdtemp(path.join(os.tmpdir(),'purple-pr-test-')),source=path.join(root,'source'),candidate=path.join(root,'candidate'),output=path.join(root,'output');
  await mkdir(source);await mkdir(output);
  await writeFile(path.join(source,'.gitignore'),'node_modules/\n');
  await writeFile(path.join(source,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0',scripts:{test:'node --test'}})+'\n');
  await writeFile(path.join(source,'app.js'),'export const dependencyVersion = "old";\n');
  run(source,['init','--quiet']);run(source,['add','.']);run(source,['-c','user.name=Fixture','-c','user.email=fixture@example.com','commit','--quiet','-m','baseline']);
  const revision=run(source,['rev-parse','HEAD']).trim();run(root,['clone','--quiet','--no-hardlinks',source,candidate]);
  await writeFile(path.join(candidate,'app.js'),'export const dependencyVersion = "new";\n');
  const patchPath=path.join(output,'upgrade.patch'),patch=run(candidate,['diff','--binary','--no-ext-diff','--no-textconv','HEAD']);await writeFile(patchPath,patch);
  const section=()=>({integrity:true,setup:[{command:['npm','ci'],directory:'.',passed:true}],checks:[{command:['npm','test'],directory:'.',passed:true}]});
  const scanFile=path.join(output,'final-scan.json'),checkedAt=Date.now(),remaining=[{id:'GHSA-low',package:'other',version:'2.0.0'}];
  const scan={vulnerabilityCheck:{status:'complete',checkedAt,findings:remaining},warnings:[],metadataFingerprint:sha256('fixture metadata')};
  await writeFile(scanFile,JSON.stringify(scan));
  const report={schemaVersion:1,startedAt:checkedAt-100,finishedAt:Date.now(),status:'ready_for_review',repository:'owner/repo',revision,sourceDirectory:source,candidateDirectory:candidate,patch:{path:patchPath,sha256:sha256(patch)},
    evidence:{sourceFingerprint:await fingerprintCheckout(source),candidateFingerprint:await fingerprintCheckout(candidate)},baseline:section(),candidate:section(),
    checklist:[{id:'GHSA-critical',package:'example',version:'1.0.0',severity:'HIGH',targeted:true,status:'remediated',reason:'Target no longer present in the resolved dependency graph.'},
      {id:'GHSA-low',package:'other',version:'2.0.0',severity:'LOW',targeted:false,status:'deferred',reason:'Outside selected high/critical scope.'}],
    finalScan:{status:'complete',json:scanFile,checkedAt,fingerprint:sha256(JSON.stringify(scan))},remainingAdvisories:remaining,newAdvisories:[],verification:'compatibility_and_advisory_checks',limitations:['Applicability has not been established.']};
  const reportFile=path.join(output,'fix.json');
  const save=async()=>{await writeFile(reportFile,JSON.stringify(report,null,2));return createDependencyPrHandoff({report,patchPath,outputDirectory:output});};
  const handoff=await save();
  return {root,source,candidate,output,report,reportFile,patchPath,handoff,scanFile,save,close:()=>rm(root,{recursive:true,force:true})};
}
function transportFor(f) {
  const calls=[],state={head:null,prs:[],tree:[],base:f.report.revision,baseReads:0,failedChecks:false};
  const request=async(method,endpoint,body)=>{
    calls.push({method,endpoint,body:structuredClone(body)});
    if(method==='GET'&&endpoint==='repos/owner/repo')return {default_branch:'main',permissions:{push:true}};
    if(method==='GET'&&endpoint==='repos/owner/repo/git/ref/heads/main'){state.baseReads++;return {object:{sha:state.base}};}
    if(method==='GET'&&endpoint.startsWith('repos/owner/repo/git/ref/heads/'))return state.head?{object:{sha:state.head}}:null;
    if(method==='GET'&&endpoint.includes('/pulls?'))return state.prs;
    if(method==='GET'&&endpoint===`repos/owner/repo/git/commits/${f.report.revision}`)return {tree:{sha:'b'.repeat(40)}};
    if(method==='GET'&&endpoint==='repos/owner/repo/git/commits/'+state.head)return {tree:{sha:'c'.repeat(40)},parents:[{sha:f.report.revision}]};
    if(method==='GET'&&endpoint==='repos/owner/repo/git/trees/'+('c'.repeat(40))+'?recursive=1')return {truncated:false,tree:state.tree.filter(x=>x.sha).map(x=>({...x,mode:state.wrongMode?'100755':x.mode}))};
    if(method==='POST'&&endpoint.endsWith('/git/blobs')){const bytes=Buffer.from(body.content,'base64');return {sha:createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')};}
    if(method==='POST'&&endpoint.endsWith('/git/trees')){state.tree=body.tree;return {sha:'c'.repeat(40)};}
    if(method==='POST'&&endpoint.endsWith('/git/commits'))return {sha:'d'.repeat(40)};
    if(method==='POST'&&endpoint.endsWith('/git/refs')){state.head=body.sha;return {object:{sha:state.head}};}
    if(method==='POST'&&endpoint.endsWith('/pulls')){const pr={number:7,html_url:'https://github.com/owner/repo/pull/7',body:body.body,head:{ref:body.head,sha:state.head},base:{ref:body.base}};state.prs.push(pr);return pr;}
    if(method==='GET'&&endpoint.includes('/compare/'))return {total_commits:1,files:state.tree.map(x=>({filename:x.path,sha:x.sha,status:x.sha?'modified':'removed'}))};
    if(method==='GET'&&endpoint.includes('/check-runs'))return {check_runs:[{name:'test',status:'completed',conclusion:state.failedChecks?'failure':'success'}]};
    if(method==='GET'&&endpoint.includes('/status'))return {statuses:[]};
    throw Error(`Unexpected request ${method} ${endpoint}`);
  };
  return {calls,state,request};
}

test('handoff covers every advisory, deferred risk and actual verification limits, with immutable digests',async()=>{
  const f=await fixture();try{
    const body=await readFile(f.handoff.bodyPath,'utf8'),manifest=JSON.parse(await readFile(f.handoff.manifestPath,'utf8'));
    assert.match(body,/GHSA-critical/);assert.match(body,/GHSA-low/);assert.match(body,/deferred/);
    assert.match(body,/Exploit reproduction is not established/);assert.match(body,/CI on this pull request has not been established/);
    assert.equal(manifest.reportSha256,sha256(JSON.stringify(f.report)));assert.equal(manifest.patchSha256,f.report.patch.sha256);assert.equal(manifest.bodySha256,sha256(body));
    assert.ok(f.handoff.branch.startsWith('codex/dependency-fix-'));
  }finally{await f.close();}
});

test('deprecated targets remain prominent maintenance warnings in hashed draft handoff and publication output',async()=>{
  const f=await fixture(),transport=transportFor(f);try{
    const warning={type:'deprecated_target',package:'lodash',version:'4.18.0',source:'dependency',message:'Bad release: use 4.17.21.'};
    f.report.reviewWarnings=[warning];f.report.needsMaintainerReview=true;await f.save();
    const body=await readFile(f.handoff.bodyPath,'utf8'),manifest=JSON.parse(await readFile(f.handoff.manifestPath,'utf8'));
    assert.ok(body.indexOf('Maintainer review required')<body.indexOf('Advisory checklist'));assert.match(body,/lodash@4\.18\.0/);assert.match(body,/Bad release: use 4\.17\.21/);assert.match(body,/No upstream recommendation/);
    assert.equal(manifest.needsMaintainerReview,true);assert.deepEqual(manifest.reviewWarnings,[warning]);assert.equal(manifest.reportSha256,sha256(JSON.stringify(f.report)));assert.equal(manifest.bodySha256,sha256(body));
    await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true,draft:false},{transport}),/draft pull request/);assert.equal(transport.calls.length,0);
    const result=await publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport});
    assert.equal(result.needsMaintainerReview,true);assert.deepEqual(result.reviewWarnings,[warning]);assert.equal(transport.calls.find(call=>call.method==='POST'&&call.endpoint.endsWith('/pulls')).body.draft,true);
    const callCount=transport.calls.length;manifest.reviewWarnings=[];await writeFile(f.handoff.manifestPath,JSON.stringify(manifest));
    await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),/maintenance warnings/);assert.equal(transport.calls.length,callCount);
  }finally{await f.close();}
});

test('publisher requires explicit authorization and refuses blocked or incomplete results before accessing GitHub',async()=>{
  const f=await fixture(),transport=transportFor(f);try{
    await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo'},{transport}),/Explicit authorization/);
    for(const patch of [{status:'blocked'},{finishedAt:Date.now()-25*3600_000},{candidate:{...f.report.candidate,checks:[]}},{newAdvisories:[{id:'new'}]},{finalScan:{status:'failed'}},{checklist:[{...f.report.checklist[0],status:'blocked'}]}]){
      const initial=structuredClone(f.report);Object.assign(f.report,patch);await f.save();
      await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}));
      for(const k of Object.keys(f.report))delete f.report[k];Object.assign(f.report,initial);
    }
    assert.equal(transport.calls.length,0);
  }finally{await f.close();}
});

test('changed report, PR text, patch, candidate or source are rejected before publication',async()=>{
  for(const kind of ['report','body','patch','candidate','source','scan']){
    const f=await fixture(),transport=transportFor(f);try{
      if(kind==='report'){f.report.checklist[0].reason='edited after review';await writeFile(f.reportFile,JSON.stringify(f.report));}
      if(kind==='body')await writeFile(f.handoff.bodyPath,'Unreviewed PR body');
      if(kind==='patch')await writeFile(f.patchPath,(await readFile(f.patchPath,'utf8'))+'\n');
      if(kind==='candidate')await writeFile(path.join(f.candidate,'app.js'),'unreviewed change');
      if(kind==='source')await writeFile(path.join(f.source,'app.js'),'changed baseline');
      if(kind==='scan')await writeFile(f.scanFile,JSON.stringify({vulnerabilityCheck:{status:'complete',checkedAt:Date.now(),findings:[]}}));
      await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}));assert.equal(transport.calls.length,0);
    }finally{await f.close();}
  }
});

test('publisher creates an exact draft patch PR using controller requests and reuses it without repeated writes',async()=>{
  const f=await fixture(),transport=transportFor(f);try{
    const result=await publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport});
    assert.equal(result.status,'published');assert.equal(result.url,'https://github.com/owner/repo/pull/7');assert.equal(result.ci.status,'passed');
    const create=transport.calls.find(x=>x.method==='POST'&&x.endpoint.endsWith('/pulls'));assert.equal(create.body.draft,true);assert.equal(create.body.base,'main');
    assert.ok(transport.calls.every(x=>!x.endpoint.includes('/merge')));
    const writes=transport.calls.filter(x=>x.method==='POST').length;
    const again=await publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport});
    assert.equal(again.reused,true);assert.equal(transport.calls.filter(x=>x.method==='POST').length,writes);
    assert.equal(JSON.parse(await readFile(path.join(f.output,'pr-published.json'),'utf8')).patchSha256,f.report.patch.sha256);
  }finally{await f.close();}
});

test('moved base or unrelated existing branch blocks publication without overwriting a branch',async()=>{
  for(const existing of [false,true]){
    const f=await fixture(),transport=transportFor(f);try{
      if(existing)transport.state.head='f'.repeat(40);else transport.state.base='e'.repeat(40);
      await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),existing?/different patch/:/base branch moved/);
      assert.ok(!transport.calls.some(x=>x.method==='POST'));
    }finally{await f.close();}
  }
});

test('publication retries reject remote file-mode changes even when every blob SHA still matches',async()=>{
  const f=await fixture(),transport=transportFor(f);try{
    await publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport});
    const writes=transport.calls.filter(call=>call.method==='POST').length;transport.state.wrongMode=true;
    await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),/different patch/);
    assert.equal(transport.calls.filter(call=>call.method==='POST').length,writes);
  }finally{await f.close();}
});

test('publisher checks persisted rescan time and findings independently of a successful checklist label',async()=>{
  for(const kind of ['stale','contradiction']){
    const f=await fixture(),transport=transportFor(f);try{
      const scan=JSON.parse(await readFile(f.scanFile,'utf8'));
      if(kind==='stale')scan.vulnerabilityCheck.checkedAt=f.report.startedAt-60000;
      else{scan.vulnerabilityCheck.findings.push({id:'GHSA-critical',package:'example',version:'1.0.0'});f.report.remainingAdvisories=scan.vulnerabilityCheck.findings;}
      await writeFile(f.scanFile,JSON.stringify(scan));f.report.finalScan.checkedAt=scan.vulnerabilityCheck.checkedAt;f.report.finalScan.fingerprint=sha256(JSON.stringify(scan));await f.save();
      await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),/scan|checklist/);
      assert.equal(transport.calls.length,0);
    }finally{await f.close();}
  }
});

test('existing GitHub connection failures are explicit blockers and do not start repository programs',async()=>{
  const f=await fixture();try{
    const result=await publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport:{request:async()=>{throw Object.assign(Error('No connection'),{code:'github_connection_unavailable'});}}});
    assert.equal(result.status,'blocked');assert.match(result.reason,/No connection/);
  }finally{await f.close();}
});

test('CI absence, pending checks and failures are never reported as a passing CI run',async()=>{
  const options={repository:'owner/repo',headSha:'a'.repeat(40)};
  const transport=checks=>({request:async(_method,endpoint)=>endpoint.includes('/check-runs')?{check_runs:checks}:{statuses:[]}});
  assert.equal((await dependencyPrChecks(options,{transport:transport([])})).status,'not_reported');
  assert.equal((await dependencyPrChecks(options,{transport:{request:async(_m,url)=>url.includes('/check-runs')?{total_count:101,check_runs:[{status:'completed',conclusion:'success'}]}:{statuses:[]}}})).status,'incomplete');
  assert.equal((await dependencyPrChecks(options,{transport:transport([{status:'in_progress'}])})).status,'pending');
  assert.equal((await dependencyPrChecks(options,{transport:transport([{status:'completed',conclusion:'failure'}])})).status,'failed');
  assert.equal((await dependencyPrChecks(options,{transport:transport([{status:'completed',conclusion:'skipped'}])})).status,'needs_review');
});

test('blocked and no-change runs still produce complete handoffs without inventing a patch or revision',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'purple-pr-blocked-'));
  try{
    for(const status of ['blocked','no_changes']){
      const report={schemaVersion:1,status,revision:null,checklist:[{id:'GHSA-one',package:'one',version:'1',severity:'HIGH',targeted:true,status:'blocked',reason:'No fixed target is available.'}],remainingAdvisories:[],newAdvisories:[]};
      const result=await createDependencyPrHandoff({report,outputDirectory:directory});
      const manifest=JSON.parse(await readFile(result.manifestPath,'utf8')),body=await readFile(result.bodyPath,'utf8');
      assert.equal(manifest.publishable,false);assert.equal(manifest.patchPath,null);assert.equal(manifest.branch,null);assert.match(body,/GHSA-one/);assert.match(body,/No fixed target/);assert.match(body,/no publishable patch/);
    }
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('credential files and workflow edits cannot be published even when hashes and compatibility checks pass',async()=>{
  for(const file of ['.env','.npmrc','.github/workflows/publish.yml']){
    const f=await fixture(),transport=transportFor(f);try{
      await mkdir(path.dirname(path.join(f.candidate,file)),{recursive:true});await writeFile(path.join(f.candidate,file),'sensitive-or-executable-config\n');
      run(f.candidate,['add','-N','--all']);
      const patch=run(f.candidate,['diff','--binary','--no-ext-diff','--no-textconv','HEAD']);await writeFile(f.patchPath,patch);
      f.report.patch.sha256=sha256(patch);f.report.evidence.candidateFingerprint=await fingerprintCheckout(f.candidate);await f.save();
      await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),/Credential|authorize workflow/);
      assert.equal(transport.calls.length,0);
    }finally{await f.close();}
  }
});

test('symlinked publication destinations and artifact parents are refused without following host paths',async()=>{
  for(const kind of ['publication','body','parent','checkout']){
    const f=await fixture(),transport=transportFor(f);try{
      const canary=path.join(f.root,'outside-canary');await writeFile(canary,'preserve host contents\n');
      if(kind==='publication')await symlink(canary,path.join(f.output,'pr-published.json'));
      if(kind==='body'){
        await rm(f.handoff.bodyPath);await symlink(canary,f.handoff.bodyPath);
        await assert.rejects(f.save(),/symlinked/);
      }else if(kind==='parent'){
        await symlink(f.output,path.join(f.root,'artifact-alias'));
        await assert.rejects(publishDependencyFix({reportFile:path.join(f.root,'artifact-alias','fix.json'),repository:'owner/repo',authorizePublish:true},{transport}),/Symlinked/);
      }else if(kind==='checkout'){
        await symlink(f.candidate,path.join(f.root,'candidate-alias'));
        await assert.rejects(fingerprintCheckout(path.join(f.root,'candidate-alias')),/Symlinked/);
      }else await assert.rejects(publishDependencyFix({reportFile:f.reportFile,repository:'owner/repo',authorizePublish:true},{transport}),/symlinked/);
      assert.equal(transport.calls.length,0);assert.equal(await readFile(canary,'utf8'),'preserve host contents\n');
    }finally{await f.close();}
  }
});
