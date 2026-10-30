import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { infisicalInvocation } from '../scripts/with-infisical.mjs';
import { deploymentSecrets, mergeDeploymentBindings } from '../scripts/deployment-secrets.mjs';

function temporary(action) {
  const cwd = mkdtempSync(path.join(tmpdir(), 'purple-infisical-'));
  try { return action(cwd); } finally { rmSync(cwd, {recursive:true,force:true}); }
}

test('Infisical selects explicit project/environment and removes ambient credentials and subprocess injection settings', () => temporary(cwd => {
  writeFileSync(path.join(cwd,'.infisical.yaml'), 'version: 1\nsecrets-management:\n  project-id: purple-project-id\n  environment: prod\n');
  const invocation=infisicalInvocation('dev','node',['server/index.js'],{cwd,home:cwd,env:{PATH:'/usr/bin',HOME:cwd,WHOP_API_KEY:'production-canary',STAGING_WHOP_API_KEY:'staging-canary',ENCRYPTION_KEY:'do-not-inherit',NODE_OPTIONS:'--require /bad.js',BASH_ENV:'/bad.sh',INFISICAL_TOKEN:'machine-canary'}});
  assert.ok(invocation.args.includes('--env=dev')); assert.ok(invocation.args.includes('--projectId=purple-project-id'));
  assert.deepEqual(invocation.args.slice(-3), ['--','node','server/index.js']);
  assert.equal(invocation.env.INFISICAL_TOKEN,'machine-canary'); assert.equal(invocation.env.PURPLE_SECRETS_ENVIRONMENT,'dev');
  assert.equal(invocation.env.WHOP_API_KEY,undefined); assert.equal(invocation.env.STAGING_WHOP_API_KEY,undefined);
  assert.equal(invocation.env.ENCRYPTION_KEY,undefined); assert.equal(invocation.env.NODE_OPTIONS,undefined); assert.equal(invocation.env.BASH_ENV,undefined);
  assert.ok(!JSON.stringify(invocation.args).includes('machine-canary')); assert.ok(!invocation.args.some(x=>x.includes('env-file')));
}));

test('Infisical fails without project configuration and rejects unsupported environments or credential-bearing endpoints', () => temporary(cwd => {
  assert.throws(()=>infisicalInvocation('prod','node',[],{cwd,env:{},home:cwd}),/Link Purple first/);
  assert.throws(()=>infisicalInvocation('production','node',[],{cwd,env:{},home:cwd}),/explicit/);
  for(const domain of ['http://localhost:8080','https://user:secret@vault.example','https://vault.example?token=value']) {
    assert.throws(()=>infisicalInvocation('dev','node',[],{cwd,home:cwd,env:{INFISICAL_PROJECT_ID:'project-example',INFISICAL_DOMAIN:domain}}),/HTTPS/);
  }
  const login=infisicalInvocation('prod','node',[],{cwd,home:cwd,env:{INFISICAL_PROJECT_ID:'project-example',INFISICAL_DOMAIN:'https://eu.infisical.com'}});
  assert.equal(login.env.INFISICAL_PROFILE,'purple');assert.ok(login.args.includes('--domain=https://eu.infisical.com'));
}));

test('staging Infisical deployments use only staging environment values and never fall back to production files', () => {
  const env={PURPLE_SECRETS_SOURCE:'infisical',PURPLE_SECRETS_ENVIRONMENT:'staging',WHOP_API_KEY:'staging-only',STAGING_WHOP_API_KEY:'legacy-ignore'};
  const secrets=deploymentSecrets(env,'staging',{read:()=>{throw Error('Disk secrets must not be loaded');}});
  assert.equal(secrets.valueFor('WHOP_API_KEY'),'staging-only'); assert.equal(secrets.valueFor('CLICKHOUSE_PASSWORD'),undefined);
  assert.throws(()=>secrets.privateKey(),/GITHUB_APP_PRIVATE_KEY/); assert.throws(()=>secrets.agent('/production-agent-key'),/PURPLE_AGENT_SHARED_KEY/);
  assert.throws(()=>deploymentSecrets(env,'production'),/does not match/);
  const ready=deploymentSecrets({...env,GITHUB_APP_PRIVATE_KEY:'staging-pem',PURPLE_AGENT_SHARED_KEY:'staging-agent',PURPLE_AGENT_URL:'https://agent-staging.example'},'staging');
  assert.equal(ready.privateKey(),'staging-pem');assert.deepEqual(ready.agent(),{key:'staging-agent',url:'https://agent-staging.example'});
});

test('existing file-based deployments retain staging prefixes, scoped agent URL and explicit key-file behavior', () => {
  const env={WHOP_API_KEY:'production',STAGING_WHOP_API_KEY:'staging',OPENROUTER_API_KEY:'prod-model',PURPLE_AGENT_URL:'https://production-agent.example'};
  const secrets=deploymentSecrets(env,'staging',{read:file=>file.endsWith('.pem')?'legacy-pem':'legacy-agent\n'});
  assert.equal(secrets.valueFor('WHOP_API_KEY'),'staging');assert.equal(secrets.valueFor('OPENROUTER_API_KEY'),undefined);
  assert.equal(secrets.privateKey(),'legacy-pem');assert.equal(secrets.agent(),null);
  assert.deepEqual(secrets.agent('/explicit/staging-agent-key'),{key:'legacy-agent',url:'https://agent-staging.example.invalid'});
  assert.equal(deploymentSecrets(env,'production').valueFor('WHOP_API_KEY'),'production');
});

test('partial vaults cannot delete runtime secrets and existing resource bindings survive deployment', () => {
  const existing = [{name:'ENCRYPTION_KEY',type:'secret_text'}, {name:'OPENROUTER_API_KEY',type:'secret_text'},
    {name:'STATE',type:'durable_object_namespace'}, {name:'PUBLIC_URL',type:'plain_text',text:'https://app.example'}];
  const supplied = [{name:'ENCRYPTION_KEY',type:'secret_text',text:'same-key'}];
  assert.throws(() => mergeDeploymentBindings(existing,supplied), /OPENROUTER_API_KEY/);
  const bindings = mergeDeploymentBindings(existing,supplied,{preserveMissing:['OPENROUTER_API_KEY']});
  assert.deepEqual(bindings, [supplied[0], {name:'OPENROUTER_API_KEY',type:'inherit'},
    {name:'STATE',type:'inherit'}, {name:'PUBLIC_URL',type:'inherit'}]);
  assert.equal(existing[0].type,'secret_text');
  assert.deepEqual(mergeDeploymentBindings([],supplied),supplied);
});
