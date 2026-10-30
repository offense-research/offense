import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rm, mkdir, symlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { parseArguments, prepareSnapshot, prepareVerification, dockerArguments, MANAGED_JOB_FILE } from '../scripts/offense.mjs';

test('dependency-fix CLI bounds attempts and never implicitly authorizes publishing', () => {
  const options=parseArguments(['dependencies','fix','.','--repository','org/repo','--max-attempts','2']);
  assert.equal(options.authorizePublish,undefined);assert.equal(options.maxAttempts,2);assert.equal(options.maxTurns,12);
  for(const args of [['--max-attempts','4'],['--max-turns','0'],['--image','--privileged'],['--repository','org/repo;bad']]) {
    assert.throws(()=>parseArguments(['dependencies','fix',...args]));
  }
  assert.equal(parseArguments(['dependencies','publish','--authorize-publish']).authorizePublish,true);
});

test('Docker controller uses limited ownership capabilities, isolated repository UID and no credential argv', () => {
  const args=dockerArguments({directory:'/tmp/job/input',output:'/tmp/job',image:'purple-hermes:local',uid:1000,gid:1000,name:'purple-fix-'+'a'.repeat(24)});
  assert.equal(args[args.indexOf('--network')+1],'purple-fix-'+'a'.repeat(24)+'-network');
  assert.ok(args.includes('--read-only'));assert.ok(args.includes('--cap-drop=ALL'));assert.ok(args.includes('--security-opt=no-new-privileges'));
  assert.equal(args[args.indexOf('--user')+1],'0:0');assert.ok(args.some(x=>x.endsWith('target=/tmp/job/input,readonly')));
  for(const capability of ['SETUID','SETGID','CHOWN','KILL','FOWNER','DAC_OVERRIDE'])assert.ok(args.includes('--cap-add='+capability));
  assert.ok(args.includes('PURPLE_FIX_ISOLATE_COMMANDS=1'));assert.ok(args.includes('--disable-sigusr1'));
  assert.ok(args.some(x=>x.endsWith('target=/tmp/job/'+MANAGED_JOB_FILE+',readonly')));
  assert.ok(!args.some(x=>/OPENROUTER|apiKey|--privileged|docker.sock|\.env/.test(x)));
  assert.throws(()=>dockerArguments({directory:'/tmp/input,src=/',output:'/tmp/out',image:'image',uid:1,gid:1,name:'purple-fix-'+'a'.repeat(24)}),/mount paths/);
});

async function managedFixture() {
  const root=await mkdtemp(path.join(tmpdir(),'purple-verify-cli-')),source=path.join(root,'source'),output=path.join(root,'job');
  await mkdir(source);await writeFile(path.join(source,'package.json'),'{}\n');
  const git=args=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:source,stdio:'pipe'}).toString();
  git(['init']);git(['add','.']);git(['-c','user.name=Fixture','-c','user.email=fixture@example.com','commit','-m','initial']);
  const snapshot=await prepareSnapshot(source,output),reportFile=path.join(output,'fix.json');
  await mkdir(path.join(output,'work','source'),{recursive:true});await mkdir(path.join(output,'work','candidate-0'));
  const report={revision:snapshot.revision,sourceDirectory:path.join(output,'work','source'),candidateDirectory:path.join(output,'work','candidate-0')};
  await writeFile(reportFile,JSON.stringify(report));
  return {root,output,snapshot,reportFile,report,close:()=>rm(root,{recursive:true,force:true})};
}

test('verification derives a narrow mount from the host marker and canonical managed paths',async()=>{
  const f=await managedFixture();try{
    const prepared=await prepareVerification(f.reportFile,path.join(f.output,'verification-repeat'));
    assert.equal(prepared.output,f.output);assert.equal(prepared.pinned.directory,f.snapshot.directory);assert.equal(prepared.pinned.revision,f.snapshot.revision);
    assert.equal(prepared.input.verificationOutput,path.join(f.output,'verification-repeat'));
    const marker=JSON.parse(await readFile(path.join(f.output,MANAGED_JOB_FILE),'utf8'));assert.equal(marker.outputDirectory,f.output);assert.equal(marker.revision,f.snapshot.revision);
    await assert.rejects(prepareVerification(f.reportFile,path.join(f.root,'outside')),/verification-/);
    await assert.rejects(prepareVerification(f.reportFile,path.join(f.output,'work','source','nested')),/verification-/);
  }finally{await f.close();}
});

test('untrusted report paths and revisions never broaden the writable job mount',async()=>{
  for(const attack of [report=>({...report,sourceDirectory:'/home/ronny/work/source',candidateDirectory:'/home/ronny/anything'}),
    report=>({...report,sourceDirectory:'/tmp/another-job/work/source'}),
    report=>({...report,candidateDirectory:report.candidateDirectory+'/../../outside'}),report=>({...report,revision:'f'.repeat(40)})]){
    const f=await managedFixture();try{
      await writeFile(f.reportFile,JSON.stringify(attack(f.report)));
      await assert.rejects(prepareVerification(f.reportFile),/paths or revision/);
    }finally{await f.close();}
  }
});

test('verification refuses symlinked report, directory, candidate and output paths',async()=>{
  for(const attack of ['report','parent','candidate','output']){
    const f=await managedFixture();try{
      let selected=f.reportFile,destination;
      if(attack==='report'){const bytes=await readFile(f.reportFile);await rm(f.reportFile);await writeFile(path.join(f.root,'untrusted.json'),bytes);await symlink(path.join(f.root,'untrusted.json'),f.reportFile);}
      if(attack==='parent'){await symlink(f.output,path.join(f.root,'alias'));selected=path.join(f.root,'alias','fix.json');}
      if(attack==='candidate'){await rm(f.report.candidateDirectory,{recursive:true});await symlink(f.root,f.report.candidateDirectory);}
      if(attack==='output'){destination=path.join(f.output,'verification-alias');await symlink(f.root,destination);}
      await assert.rejects(prepareVerification(selected,destination),/Symlinked/);
    }finally{await f.close();}
  }
});

test('a fabricated broad report without a host-managed marker is refused before Docker',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'purple-fake-report-'));
  try{
    await mkdir(path.join(root,'work','source'),{recursive:true});await writeFile(path.join(root,'fix.json'),JSON.stringify({sourceDirectory:path.join(root,'work','source'),candidateDirectory:path.join(root,'other'),revision:'a'.repeat(40)}));
    await assert.rejects(prepareVerification(path.join(root,'fix.json')),/managed|root/);
  }finally{await rm(root,{recursive:true,force:true});}
});

test('fix snapshots pin committed files without mounting ignored production secrets, and preserve dirty work', async () => {
  const root=await mkdtemp(path.join(tmpdir(),'purple-fix-cli-')),source=path.join(root,'source'),output=path.join(root,'report');
  try {
    await mkdir(source);const git=args=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:source,stdio:'pipe'}).toString();
    await writeFile(path.join(source,'.gitignore'),'.env\nnode_modules/\n');await writeFile(path.join(source,'package.json'),'{}\n');
    git(['init']);git(['add','.']);git(['-c','user.name=Fixture','-c','user.email=fixture@example.com','commit','-m','initial']);
    await writeFile(path.join(source,'.env'),'OPENROUTER_API_KEY=untracked-production-canary\n');
    const snapshot=await prepareSnapshot(source,output);
    assert.equal(snapshot.revision,git(['rev-parse','HEAD']).trim());assert.ok(!(await readdir(snapshot.directory)).includes('.env'));
    assert.equal(await readFile(path.join(source,'.env'),'utf8'),'OPENROUTER_API_KEY=untracked-production-canary\n');
    assert.equal(git(['status','--porcelain']).trim(),'');
    await writeFile(path.join(source,'package.json'),'{"changed":true}\n');
    await assert.rejects(prepareSnapshot(source,path.join(root,'dirty-output')),/clean checkout/);
    assert.equal(await readFile(path.join(source,'package.json'),'utf8'),'{"changed":true}\n');
    await assert.rejects(prepareSnapshot(source,path.join(source,'report')),/outside/);
    await symlink(source,path.join(root,'alias'));
    await assert.rejects(prepareSnapshot(source,path.join(root,'alias','new-output')),/outside/);
  } finally {await rm(root,{recursive:true,force:true});}
});
