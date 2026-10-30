import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { createIssueTrackers, issueDraft } from '../server/issue-trackers.js';
import { registerDependencyRoutes } from '../server/dependency-routes.js';
import { once } from 'node:events';
const identity = {workspace:'workspace-a',user:'user-a',browser:'browser-a'};
const evidence = () => ({repository:'customer/repo',snapshot:{revision:'a'.repeat(40),vulnerabilityCheck:{checkedAt:Date.now()}},finding:{id:'GHSA-test',package:'example',version:'1.0.0',severity:'CRITICAL',summary:'Example issue',cves:['CVE-2099-0001']},prompt:'Upgrade parent 1 → 2, then dependency 1 → 3. Run baseline, regression, normal tests, and rescan.'});
function fixture(handler) {
  const db = new DatabaseSync(':memory:'), key = randomBytes(32), calls=[];
  const encrypt = value => {const iv=randomBytes(12), cipher=createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(value),cipher.final(),cipher.getAuthTag()]).toString('base64');};
  const decrypt = value => {const b=Buffer.from(value,'base64'), d=createDecipheriv('aes-256-gcm',key,b.subarray(0,12));d.setAuthTag(b.subarray(-16));return Buffer.concat([d.update(b.subarray(12,-16)),d.final()]).toString();};
  let clock=Date.now();
  const env={PUBLIC_URL:'https://purple.example',LINEAR_CLIENT_ID:'linear-client',LINEAR_CLIENT_SECRET:'linear-secret',JIRA_CLIENT_ID:'jira-client',JIRA_CLIENT_SECRET:'jira-secret'};
  const trackers=createIssueTrackers(db,{env,encrypt,decrypt,now:()=>clock,fetchImpl:async(url,options)=>{
    calls.push({url,options});if(handler){const result=await handler(url,options);if(result)return result;}
    if(url.endsWith('/oauth/token'))return Response.json({access_token:'access-canary',refresh_token:'refresh-canary',expires_in:3600});
    if(url==='https://api.linear.app/graphql'){const body=JSON.parse(options.body);if(body.query.includes('PurpleTeams'))return Response.json({data:{teams:{nodes:[{id:'team-a',name:'Security'}],pageInfo:{hasNextPage:false}}}});if(body.query.includes('PurpleIssue'))return Response.json({data:{issueCreate:{success:true,issue:{identifier:'SEC-1',url:'https://linear.app/example/issue/SEC-1'}}}});}
    if(url.endsWith('/accessible-resources'))return Response.json([{id:'site-a',name:'Customer',url:'https://customer.atlassian.net'}]);
    if(url.includes('/project/search'))return Response.json({isLast:true,values:[{id:'100',name:'Product',key:'PROD'}]});
    if(url.includes('/issuetypes?'))return Response.json({total:2,issueTypes:[{id:'1',name:'Bug',subtask:false},{id:'2',name:'Subtask',subtask:true}]});
    if(url.endsWith('/issue'))return Response.json({key:'PROD-1'});
    throw Error('Unexpected request');
  }});
  async function connect(provider='linear') {const url=new URL(trackers.start(provider,identity));await trackers.finish(provider,identity,{state:url.searchParams.get('state'),code:'test-code'});return url;}
  return {db,trackers,calls,connect,advance:ms=>clock+=ms};
}
test('OAuth binds single-use state to provider, browser, user, workspace, expiry and uses PKCE',async()=>{
  const f=fixture();try{
    const url=new URL(f.trackers.start('linear',identity)),state=url.searchParams.get('state');assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.equal(url.searchParams.get('scope'),'read,issues:create');
    for(const modified of [{...identity,workspace:'other'},{...identity,user:'other'},{...identity,browser:'other'}])await assert.rejects(()=>f.trackers.finish('linear',modified,{state,code:'test'}),/different session/);
    await assert.rejects(()=>f.trackers.finish('jira',identity,{state,code:'test'}),/different session/);
    await f.trackers.finish('linear',identity,{state,code:'test'});await assert.rejects(()=>f.trackers.finish('linear',identity,{state,code:'test'}),/expired/);
    const exchange=new URLSearchParams(f.calls[0].options.body);assert.ok(exchange.get('code_verifier'));assert.equal(exchange.get('redirect_uri'),'https://purple.example/api/issue-trackers/linear/callback');
    const expired=new URL(f.trackers.start('jira',identity));f.advance(600001);await assert.rejects(()=>f.trackers.finish('jira',identity,{state:expired.searchParams.get('state'),code:'test'}),/expired/);
    assert.ok(!JSON.stringify(f.trackers.status(identity.workspace)).includes('canary'));const row=f.db.prepare('SELECT secret FROM issue_tracker_connections').get();assert.ok(!row.secret.includes('canary'));
  }finally{f.db.close();}
});
test('Linear creates evidence and checked remediation once, scopes links by workspace, and reuses across package versions',async()=>{
  const f=fixture();try{await f.connect();await f.trackers.choose(identity.workspace,'linear',{teamId:'team-a'});
    const [first,second]=await Promise.allSettled([f.trackers.create(identity.workspace,'linear',evidence()),f.trackers.create(identity.workspace,'linear',evidence())]);assert.equal(first.status,'fulfilled');assert.equal(second.status,'rejected');
    const again=await f.trackers.create(identity.workspace,'linear',{...evidence(),finding:{...evidence().finding,version:'1.0.1'}});assert.equal(again.existing,true);
    assert.equal(f.calls.filter(c=>c.options.body?.includes('mutation PurpleIssue')).length,1);const body=JSON.parse(f.calls.find(c=>c.options.body?.includes('mutation PurpleIssue')).options.body);assert.match(body.variables.input.description,/NOT been confirmed/);assert.match(body.variables.input.description,/Upgrade parent/);assert.equal(body.variables.input.priority,1);
    assert.equal(f.trackers.links('other-workspace').length,0);await assert.rejects(()=>f.trackers.create('other-workspace','linear',evidence()),/destination/);
  }finally{f.db.close();}
});
test('Jira validates accessible sites/projects/types and sends ADF to the fixed API gateway',async()=>{
  const f=fixture();try{const url=await f.connect('jira');assert.equal(url.origin,'https://auth.atlassian.com');assert.match(url.searchParams.get('scope'),/offline_access/);
    await assert.rejects(()=>f.trackers.choose(identity.workspace,'jira',{siteId:'http://localhost'}),/authorized/);
    await assert.rejects(()=>f.trackers.choose(identity.workspace,'jira',{siteId:'site-a',projectId:'100',issueTypeId:'2'}),/issue type/);
    await f.trackers.choose(identity.workspace,'jira',{siteId:'site-a',projectId:'100',issueTypeId:'1'});const issue=await f.trackers.create(identity.workspace,'jira',evidence());assert.equal(issue.url,'https://customer.atlassian.net/browse/PROD-1');
    const post=f.calls.find(c=>c.url.endsWith('/issue')),fields=JSON.parse(post.options.body).fields;assert.equal(fields.description.type,'doc');assert.equal(fields.issuetype.id,'1');assert.equal(post.options.redirect,'error');assert.match(JSON.stringify(fields.description),/NOT been confirmed/);
  }finally{f.db.close();}
});
test('uncertain sends survive restarts without blind retries; explicit rejection can be retried',async()=>{
  let mode='timeout';const f=fixture((url,options)=>{if(options.body?.includes('mutation PurpleIssue')){if(mode==='timeout')throw Error('secret-canary');if(mode==='rejected')return new Response('',{status:403});}});
  try{await f.connect();await f.trackers.choose(identity.workspace,'linear',{teamId:'team-a'});await assert.rejects(()=>f.trackers.create(identity.workspace,'linear',evidence()),/did not confirm/);
    await assert.rejects(()=>f.trackers.create(identity.workspace,'linear',evidence()),/unconfirmed/);assert.equal(f.trackers.links(identity.workspace)[0].status,'uncertain');
    const other={...evidence(),finding:{...evidence().finding,id:'GHSA-second'}};mode='rejected';await assert.rejects(()=>f.trackers.create(identity.workspace,'linear',other),/403/);mode='success';assert.equal((await f.trackers.create(identity.workspace,'linear',other)).issueKey,'SEC-1');
  }finally{f.db.close();}
});
test('rotating refresh tokens are serialized and disconnect never resurrects credentials',async()=>{
  const f=fixture();try{await f.connect();f.advance(3600000);await Promise.all([f.trackers.destinations(identity.workspace,'linear'),f.trackers.destinations(identity.workspace,'linear')]);assert.equal(f.calls.filter(c=>c.options.body?.includes('grant_type=refresh_token')).length,1);f.trackers.disconnect(identity.workspace,'linear');assert.equal(f.trackers.status(identity.workspace)[0].connected,false);await assert.rejects(()=>f.trackers.destinations(identity.workspace,'linear'),/Connect/);
  }finally{f.db.close();}
});
test('issue draft labels declared versions as uncertain and never invents an upgrade',()=>{const e=evidence();e.finding.resolved=false;delete e.prompt;const text=issueDraft(e).description;assert.match(text,/Installed version is unknown/);assert.match(text,/No checked upgrade path/);});

test('finding export authorizes current repository access and rejects stale or forged scan evidence',async()=>{
  const handlers=new Map(),app={get(){},delete(){},post:(route,handler)=>handlers.set(route,handler)};
  const e=evidence();let accessible=true,created=0;
  const snapshot={...e.snapshot,repository:e.repository,installationId:10,vulnerabilityCheck:{checkedAt:Date.now(),status:'complete',findings:[e.finding]}};
  registerDependencyRoutes(app,{trackers:{create:async(workspace,provider,value)=>{created++;assert.equal(workspace,'ws');assert.equal(value.finding.summary,e.finding.summary);return{issueKey:'SEC-1'};}},
    github:{repositories:async()=>accessible?[{fullName:e.repository}]:[]},mapper:{snapshots:()=>[snapshot],upgradePlan:async()=>{throw Error('no target');}},
    runner:{mappings:()=>[]},syncGitHubAccess:async()=>{},autoLinkWorkers:async()=>{}});
  const run=async override=>{let code=200,data;const req={sessionId:'ws',session:{github:{installationId:10,account:'customer'},dependencyRepositories:{'10:customer/repo':{repository:e.repository,installationId:10}}},
    body:{repository:e.repository,installationId:10,provider:'linear',revision:e.snapshot.revision,advisoryId:e.finding.id,package:e.finding.package,version:e.finding.version,...override}};
    const res={status(value){code=value;return this;},json(value){data=value;return this;}};
    try{await handlers.get('/api/dependencies/issue')(req,res);}catch(error){code=error.status||500;}
    return{code,data};};
  assert.equal((await run({repository:'other/private'})).code,403);assert.equal((await run({package:'forged'})).code,409);assert.equal((await run({revision:'outdated'})).code,409);assert.equal(created,0);
  assert.equal((await run({prompt:'untrusted client text'})).code,200);assert.equal(created,1);accessible=false;assert.equal((await run({})).code,403);assert.equal(created,1);
});

test('disconnect during OAuth exchange cancels the callback instead of restoring credentials',async()=>{
  let release,notify;const started=new Promise(resolve=>notify=resolve);
  const f=fixture(async(url)=>{if(url.endsWith('/oauth/token')){notify();await new Promise(resolve=>release=resolve);return Response.json({access_token:'access-canary',refresh_token:'refresh-canary',expires_in:3600});}});
  try{const url=new URL(f.trackers.start('linear',identity));const completion=f.trackers.finish('linear',identity,{state:url.searchParams.get('state'),code:'test'});await started;f.trackers.disconnect(identity.workspace,'linear');release();await assert.rejects(()=>completion,/cancelled/);assert.equal(f.trackers.status(identity.workspace)[0].connected,false);}finally{f.db.close();}
});
test('disconnect during token refresh cannot restore a connection',async()=>{
  let release,notify;const started=new Promise(resolve=>notify=resolve);
  const f=fixture(async(url,options)=>{if(options.body?.includes('grant_type=refresh_token')){notify();await new Promise(resolve=>release=resolve);return Response.json({access_token:'new-canary',refresh_token:'new-refresh',expires_in:3600});}});
  try{await f.connect();f.advance(3600000);const request=f.trackers.destinations(identity.workspace,'linear');await started;f.trackers.disconnect(identity.workspace,'linear');release();await assert.rejects(()=>request,/connection changed/);assert.equal(f.trackers.status(identity.workspace)[0].connected,false);}finally{f.db.close();}
});

test('actual Worker routes require login, enforce origin, and never share connections across workspaces',async()=>{
  const {createWorkerApp}=await import('../workers/app-api.js'),{createAccounts}=await import('../server/accounts.js');
  const db=new DatabaseSync(':memory:');let server;
  try{const {app}=createWorkerApp({db,env:{PUBLIC_URL:'https://purple.test'},schedule:()=>{}}),accounts=createAccounts(db);
    const alice=accounts.upsertUser(100,'alice'),bob=accounts.upsertUser(101,'bob'),workspace=accounts.ensureWorkspace(alice.id);
    const a='a'.repeat(64),b='b'.repeat(64);db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(a,JSON.stringify({userId:alice.id}),Date.now());db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(b,JSON.stringify({userId:bob.id}),Date.now());
    db.prepare('INSERT INTO issue_tracker_connections VALUES (?,?,?,?,?)').run(workspace.id,'linear','encrypted-secret-canary',JSON.stringify({teamId:'private-team',name:'Private team'}),Date.now());
    server=app.listen(0,'127.0.0.1');await once(server,'listening');const base=`http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(base+'/api/issue-trackers')).status,401);
    const own=await fetch(base+'/api/issue-trackers',{headers:{cookie:'purple_session='+a}}).then(r=>r.json());assert.equal(own.integrations[0].connected,true);assert.ok(!JSON.stringify(own).includes('secret-canary'));
    const other=await fetch(base+'/api/issue-trackers',{headers:{cookie:'purple_session='+b}}).then(r=>r.json());assert.equal(other.integrations[0].connected,false);assert.ok(!JSON.stringify(other).includes('Private team'));
    assert.equal((await fetch(base+'/api/issue-trackers/linear',{method:'DELETE',headers:{cookie:'purple_session='+a,origin:'https://evil.test'}})).status,403);assert.equal(db.prepare('SELECT COUNT(*) AS n FROM issue_tracker_connections').get().n,1);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));db.close();}
});
