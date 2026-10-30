import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, chmod, lstat, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { restoreArtifactOwnership } from '../agent/artifact-ownership.mjs';

test('artifact ownership restoration bounds itself to the job and never follows repository symlinks',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'purple-artifact-owner-')),output=path.join(root,'job'),outside=path.join(root,'outside');
  try{
    await mkdir(output);await mkdir(outside);await chmod(outside,0o711);await writeFile(path.join(outside,'canary'),'host file\n',{mode:0o600});
    await mkdir(path.join(output,'work'));await chmod(path.join(output,'work'),0o1777);await writeFile(path.join(output,'work','report'),'evidence\n');
    await mkdir(path.join(output,'input-repository'));await chmod(path.join(output,'input-repository'),0o700);
    await symlink(outside,path.join(output,'escape'));
    execFileSync('mkfifo',[path.join(output,'test-fifo')]);
    await restoreArtifactOwnership({output,uid:process.getuid(),gid:process.getgid()});
    assert.equal((await lstat(output)).mode&0o7777,0o700);assert.equal((await lstat(path.join(output,'work'))).mode&0o7777,0o755);
    assert.equal((await lstat(path.join(output,'input-repository'))).mode&0o7777,0o700);
    assert.equal((await lstat(outside)).mode&0o7777,0o711);assert.equal(await readFile(path.join(outside,'canary'),'utf8'),'host file\n');
    assert.equal((await lstat(path.join(output,'escape'))).isSymbolicLink(),true);
    assert.equal((await lstat(path.join(output,'test-fifo'))).isFIFO(),true);
    await assert.rejects(restoreArtifactOwnership({output:path.join(output,'escape'),uid:process.getuid(),gid:process.getgid()}),/symlinked/);
    await assert.rejects(restoreArtifactOwnership({output,uid:-1,gid:0}),/identity/);
  }finally{await rm(root,{recursive:true,force:true});}
});

test('ownership traversal bounds still leave the top-level job owned and accessible to its host user',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'purple-artifact-bounds-')),output=path.join(root,'job');
  try{
    await mkdir(path.join(output,...Array(102).fill('deep')),{recursive:true});
    await assert.rejects(restoreArtifactOwnership({output,uid:process.getuid(),gid:process.getgid()}),/bounds/);
    const stat=await lstat(output);assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o777,0o700);
  }finally{await rm(root,{recursive:true,force:true});}
});
