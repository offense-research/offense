#!/usr/bin/env node
// Full acceptance uses real package/advisory services and a synthetic model.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

const image = process.env.PURPLE_HERMES_IMAGE || 'purple-hermes:local';
const output = await mkdtemp(path.join(tmpdir(), 'purple-hermes-acceptance-'));
const name = `purple-fix-${randomBytes(12).toString('hex')}`;
const env = { PATH: process.env.PATH };
let completed=false;
const cleanup = () => {
  for (const args of [['rm','--force',name],['rm','--force',`${name}-proxy`],['network','rm',`${name}-network`]]) {
    spawnSync('docker',args,{env,stdio:'ignore',timeout:15000});
  }
};
const interrupt = () => { cleanup(); process.exit(130); };
process.once('SIGINT',interrupt); process.once('SIGTERM',interrupt);
async function docker(args, timeout = 60000) {
  return new Promise((resolve,reject) => {
    const child = spawn('docker',args,{env,stdio:'inherit'});
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.on('error',error => { clearTimeout(timer); reject(error); });
    child.on('close',(code,signal) => { clearTimeout(timer); code === 0 ? resolve() : reject(Error(`Container acceptance failed (${signal || code}); artifacts: ${output}`)); });
  });
}
try {
  await docker(['image','inspect','--format','{{.Id}}',image]);
  await docker(['network','create','--internal',`${name}-network`]);
  await docker(['run','--rm','--detach','--name',`${name}-proxy`,'--init','--read-only',
    '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=128m','--cpus=0.5',
    '--user','1000:1000','--entrypoint','node',image,'--disable-sigusr1','/opt/purple/agent/fix-egress-proxy.mjs']);
  await docker(['network','connect','--alias','purple-egress',`${name}-network`,`${name}-proxy`]);
  await docker(['run','--rm','--name',name,'--init','--read-only','--cap-drop=ALL',
    '--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--cap-add=KILL',
    '--cap-add=DAC_OVERRIDE','--cap-add=FOWNER','--security-opt=no-new-privileges',
    '--network',`${name}-network`,'--env','PURPLE_FIX_EGRESS_PROXY=http://purple-egress:8080',
    '--env','HTTP_PROXY=http://purple-egress:8080','--env','HTTPS_PROXY=http://purple-egress:8080',
    '--env','NO_PROXY=127.0.0.1,localhost','--env','NODE_USE_ENV_PROXY=1',
    '--env','PURPLE_FIX_ISOLATE_COMMANDS=1','--env',`PURPLE_FIX_OUTPUT_UID=${process.getuid()}`,
    '--env',`PURPLE_FIX_OUTPUT_GID=${process.getgid()}`,'--env',`PURPLE_FIX_E2E_OUTPUT=${output}`,
    '--pids-limit=256','--memory=3g','--cpus=2','--user','0:0',
    '--tmpfs','/tmp:rw,nosuid,nodev,size=2g','--mount',`type=bind,source=${output},target=${output}`,
    '--workdir','/tmp','--entrypoint','node',image,'--disable-sigusr1','/opt/purple/scripts/e2e-dependency-fix.mjs'],20*60000);
  const result = JSON.parse(await readFile(path.join(output,'acceptance.json'),'utf8'));
  if (!result.passed) throw Error('Acceptance did not produce a passing result.');
  for (const file of [output,path.join(output,'acceptance.json'),result.reportFile,path.join(output,'source/app.cjs')]) {
    const owner=await stat(file);assert.equal(owner.uid,process.getuid(),'artifacts must return to the host owner');
    assert.equal(owner.gid,process.getgid(),'artifacts must return to the host group');
  }
  completed=true;
  console.log(`Full acceptance passed. Review artifacts: ${output}`);
} finally {
  cleanup(); process.removeListener('SIGINT',interrupt); process.removeListener('SIGTERM',interrupt);
  if(!completed){
    const recovery=`import {restoreArtifactOwnership} from '/opt/purple/agent/artifact-ownership.mjs';await restoreArtifactOwnership(${JSON.stringify({output,uid:process.getuid(),gid:process.getgid()})});`;
    await docker(['run','--rm','--init','--read-only','--network=none','--cap-drop=ALL',
      '--cap-add=CHOWN','--cap-add=FOWNER','--cap-add=DAC_OVERRIDE','--security-opt=no-new-privileges',
      '--user','0:0','--pids-limit=64','--memory=256m','--mount',`type=bind,source=${output},target=${output}`,
      '--entrypoint','node',image,'--disable-sigusr1','--input-type=module','-e',recovery]);
  }
}
