import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runHermesTask, preflightHermes, HERMES_REVISION } from '../agent/hermes-runtime.mjs';

async function fixture(action) {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-hermes-test-'));
  await mkdir(root+'/candidate'); await mkdir(root+'/output');
  try { return await action(root); } finally { await rm(root,{recursive:true,force:true}); }
}
function childStub(result, inspect) {
  return (executable, args, options) => {
    const child = new EventEmitter(); child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{};
    let raw=''; child.stdin.on('data', chunk=>{raw+=chunk;});child.stdin.on('finish',()=>queueMicrotask(()=>{
      inspect?.({executable,args,options,input:JSON.parse(raw)});
      child.stdout.write(typeof result === 'string'?result:JSON.stringify(result));child.emit('close',0);
    }));return child;
  };
}
const answer={protocolVersion:1,status:'completed',summary:'Reviewable changes',runtime:{name:'hermes',revision:HERMES_REVISION},usage:{costUsd:null,costKind:'unverified',billingEligible:false}};

test('Hermes uses stdin credentials, an isolated job home and no inherited platform or preload settings', async()=>fixture(async root=>{
  const old=process.env.WHOP_API_KEY;process.env.WHOP_API_KEY='billing-canary';let firstHome;
  try {
    for(let n=0;n<2;n++) await runHermesTask({candidateDirectory:root+'/candidate',outputDirectory:root+'/output',task:{findings:[]},model:'fixture/model',apiKey:'model-canary'},
      {hermesPath:root,python:'python-test',spawnImpl:childStub(answer,({args,options,input})=>{
        assert.ok(!JSON.stringify(args).includes('model-canary'));assert.equal(input.apiKey,'model-canary');
        assert.equal(options.env.WHOP_API_KEY,undefined);assert.equal(options.env.OPENROUTER_API_KEY,undefined);assert.equal(options.env.NODE_OPTIONS,undefined);
        assert.equal(options.env.HERMES_HOME,options.env.HOME);assert.ok(!options.env.HERMES_HOME.startsWith(root+'/candidate'));
        if(firstHome)assert.notEqual(options.env.HERMES_HOME,firstHome);firstHome=options.env.HERMES_HOME;
        assert.equal(input.revision,HERMES_REVISION);assert.deepEqual(args.slice(0,1),['-I']);
      })});
  } finally {if(old===undefined)delete process.env.WHOP_API_KEY;else process.env.WHOP_API_KEY=old;}
}));

test('Hermes rejects overlapping roots, invalid model endpoints, oversized input and invalid runtime output',async()=>fixture(async root=>{
  const common={candidateDirectory:root+'/candidate',outputDirectory:root+'/output',task:{},model:'fixture',apiKey:'test-model-key'};
  await assert.rejects(runHermesTask({...common,outputDirectory:root+'/candidate'}),/separate/);
  await assert.rejects(runHermesTask({...common,endpoint:'http://outside.example/v1'}),/HTTPS/);
  await assert.rejects(runHermesTask({...common,endpoint:'https://user:password@outside.example/v1'}),/HTTPS/);
  await assert.rejects(runHermesTask({...common,maxTurns:100}),/turn budget/);
  await assert.rejects(runHermesTask({...common,task:{source:'x'.repeat(600000)}},{hermesPath:root,spawnImpl:childStub(answer)}),/512 KiB/);
  await assert.rejects(runHermesTask(common,{hermesPath:root,spawnImpl:childStub('not-json')}),/invalid runtime/);
}));

test('Hermes preflight needs no model key and model estimates are never eligible customer billing evidence', async()=>fixture(async root=>{
  const value=await preflightHermes({hermesPath:root,spawnImpl:childStub({...answer,status:'ready'},({input})=>{assert.equal(input.preflight,true);assert.equal(input.apiKey,undefined);})});
  assert.equal(value.status,'ready');assert.equal(value.usage.billingEligible,false);assert.equal(value.usage.costUsd,null);
}));

test('Hermes forwards credential-free controller proxy settings and redacts model keys from all returned text', async()=>fixture(async root=>{
  const previous=Object.fromEntries(['HTTP_PROXY','HTTPS_PROXY','NO_PROXY'].map(name=>[name,process.env[name]]));
  try {
    process.env.HTTP_PROXY='http://purple-egress:8080';process.env.HTTPS_PROXY='http://purple-egress:8080';process.env.NO_PROXY='127.0.0.1,localhost';
    const value=await runHermesTask({candidateDirectory:root+'/candidate',outputDirectory:root+'/output',task:{},model:'fixture',apiKey:'model-canary'},
      {hermesPath:root,spawnImpl:childStub({...answer,plan:{notes:['model-canary']}},({options})=>{
        assert.equal(options.env.HTTP_PROXY,'http://purple-egress:8080/');assert.equal(options.env.HTTPS_PROXY,'http://purple-egress:8080/');assert.equal(options.env.NO_PROXY,'127.0.0.1,localhost');
      })});
    assert.deepEqual(value.plan.notes,['[REDACTED]']);
    process.env.HTTPS_PROXY='http://user:secret@purple-egress:8080';
    await assert.rejects(preflightHermes({hermesPath:root,spawnImpl:childStub(answer)}),/without credentials/);
  } finally {for(const [name,value] of Object.entries(previous))if(value===undefined)delete process.env[name];else process.env[name]=value;}
}));

test('scoped Python tools block traversal, symlinks, hardlinks, credentials and protected tests while permitting source and new plan edits', async()=>fixture(async root=>{
  const script=fileURLToPath(new URL('../agent/hermes-task.py',import.meta.url));
  const program=`import importlib.util,json,os,pathlib,sys\nspec=importlib.util.spec_from_file_location('purple_hermes',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\nassert m.completed_result({'completed':True})\nfor envelope in [{}, {'completed':False}, {'completed':False,'final_response':'plausible summary'}, {'completed':True,'partial':True}, {'completed':True,'interrupted':True}, {'completed':True,'failed':True}]:assert not m.completed_result(envelope)\nr=pathlib.Path(sys.argv[2]);c=r/'candidate';o=r/'output';(c/'source.js').write_text('export const value = 1;')\n(c/'tests').mkdir();(c/'tests/normal.test.js').write_text('normal');(c/'.env').write_text('secret');(r/'outside').write_text('outside')\nos.symlink(r/'outside',c/'linked');os.link(r/'outside',c/'hardlinked')\nf=m.ScopedFiles(c,o,['tests/normal.test.js'])\nfor name in ['../outside','/etc/passwd','.env','.git/config','linked','hardlinked','@output/../outside']:\n try:f.read({'path':name});raise AssertionError('unsafe read succeeded: '+name)\n except (ValueError,FileNotFoundError):pass\nfor name in ['tests/normal.test.js','./tests/normal.test.js','../outside','.npmrc']:\n try:f.write({'path':name,'content':'bad'});raise AssertionError('unsafe write succeeded: '+name)\n except ValueError:pass\nf.patch({'path':'source.js','oldText':'value = 1','newText':'value = 2'});assert 'value = 2' in (c/'source.js').read_text()\nf.write({'path':'@output/plan.json','content':'{"summary":"changed"}'});assert json.loads((o/'plan.json').read_text())['summary']=='changed'\nassert (r/'outside').read_text()=='outside';assert (c/'tests/normal.test.js').read_text()=='normal'\nprint('scoped-files-pass')`;
  assert.match(execFileSync('python3',['-I','-B','-c',program,script,root],{encoding:'utf8'}),/scoped-files-pass/);
}));
