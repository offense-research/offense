import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { startFixEgressProxy, permittedAuthority, publicAddress, clientHelloServerName } from '../agent/fix-egress-proxy.mjs';

function clientHello(hostname, encrypted=false) {
  const name=Buffer.from(hostname),entry=Buffer.alloc(3+name.length);entry[0]=0;entry.writeUInt16BE(name.length,1);name.copy(entry,3);
  const list=Buffer.alloc(2+entry.length);list.writeUInt16BE(entry.length,0);entry.copy(list,2);
  const extension=Buffer.alloc(4+list.length);extension.writeUInt16BE(encrypted?0xfe0d:0,0);extension.writeUInt16BE(list.length,2);list.copy(extension,4);
  const body=Buffer.concat([Buffer.from([3,3]),Buffer.alloc(32),Buffer.from([0,0,2,0x13,1,1,0]),Buffer.from([extension.length>>8,extension.length&255]),extension]);
  const handshake=Buffer.alloc(4+body.length);handshake[0]=1;handshake.writeUIntBE(body.length,1,3);body.copy(handshake,4);
  const record=Buffer.alloc(5+handshake.length);record[0]=22;record[1]=3;record[2]=1;record.writeUInt16BE(handshake.length,3);handshake.copy(record,5);return record;
}
function upstreamFactory(sent, connected) {
  return options=>{
    connected.push(options);
    const stream=new Duplex({read(){},write(chunk,_encoding,callback){sent.push(chunk.toString());callback();}});
    queueMicrotask(()=>stream.emit('connect'));stream.setTimeout=()=>{};
    return stream;
  };
}
async function conversation(proxy,request,afterReady) {
  const socket=net.createConnection({host:'127.0.0.1',port:proxy.port});
  let result='';
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{socket.destroy();reject(Error('Test proxy socket timed out'));},2000);
    socket.on('error',error=>{clearTimeout(timer);reject(error);});
    socket.on('data',chunk=>{
      result+=chunk;
      if(result.includes('\r\n\r\n')){
        if(afterReady){const callback=afterReady;afterReady=null;callback(socket,result);}
        else {socket.destroy();clearTimeout(timer);resolve(result);}
      }
    });
    socket.on('close',()=>{clearTimeout(timer);resolve(result);});
    socket.on('connect',()=>socket.write(request));
  });
}
const lookup=async()=>[{address:'8.8.8.8',family:4}];

test('CONNECT authority permits only exact HTTPS service names and blocks IPs, suffixes and alternate ports',()=>{
  for(const name of ['registry.npmjs.org','app.purpleteam.sh','api.osv.dev','openrouter.ai'])assert.equal(permittedAuthority(name+':443'),name);
  for(const target of ['127.0.0.1:443','169.254.169.254:443','[::1]:443','openrouter.ai:80','openrouter.ai:0443','openrouter.ai.evil.test:443','user@openrouter.ai:443','openrouter.ai.:443','openrouter.ai:443\r\nHost: evil','https://openrouter.ai:443'])assert.equal(permittedAuthority(target),null);
  for(const ip of ['0.0.0.0','10.1.2.3','100.64.1.1','127.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','198.18.0.1','198.51.100.1','203.0.113.9','224.0.0.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);
  assert.equal(publicAddress('8.8.8.8'),true);assert.equal(publicAddress('2606:4700:4700::1111'),true);
});

test('valid TLS tunnels connect only to pinned public DNS addresses and do not forward proxy headers',async()=>{
  const sent=[],connected=[];
  const proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',resolve:lookup,connect:upstreamFactory(sent,connected)});
  try{
    const result=await conversation(proxy,'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: openrouter.ai:443\r\nProxy-Authorization: secret-never-forwarded\r\n\r\n',(socket)=>{socket.write(clientHello('openrouter.ai'));setTimeout(()=>socket.destroy(),20);});
    assert.match(result,/200 Connection Established/);assert.deepEqual(connected,[{host:'8.8.8.8',port:443,family:4}]);
    assert.equal(sent.join(''),clientHello('openrouter.ai').toString());assert.equal(proxy.stats.accepted,1);
  }finally{await proxy.close();}
});

test('raw HTTP, disallowed targets, mismatched Host and private DNS never open an upstream connection',async()=>{
  for(const request of ['GET http://openrouter.ai/ HTTP/1.1\r\nHost: openrouter.ai\r\n\r\n',
    'CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n',
    'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: api.osv.dev:443\r\n\r\n',
    'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: openrouter.ai:443\r\nContent-Length: 10\r\n\r\n']){
    const calls=[],proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',resolve:lookup,connect:upstreamFactory([],calls)});
    try{assert.match(await conversation(proxy,request),/403/);assert.equal(calls.length,0);}finally{await proxy.close();}
  }
  const calls=[],proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',resolve:async()=>[{address:'127.0.0.1',family:4}],connect:upstreamFactory([],calls)});
  try{assert.match(await conversation(proxy,'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: openrouter.ai:443\r\n\r\n'),/502/);assert.equal(calls.length,0);}finally{await proxy.close();}
});

test('Node HTTPS proxy default-port Host form still requires the exact CONNECT hostname and TLS SNI',async()=>{
  const sent=[],proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',resolve:lookup,connect:upstreamFactory(sent,[])});
  try{
    const response=await conversation(proxy,'CONNECT app.purpleteam.sh:443 HTTP/1.1\r\nHost: app.purpleteam.sh\r\n\r\n',socket=>{socket.write(clientHello('app.purpleteam.sh'));setTimeout(()=>socket.destroy(),10);});
    assert.match(response,/200 Connection Established/);assert.equal(proxy.stats.accepted,1);assert.equal(sent.join(''),clientHello('app.purpleteam.sh').toString());
  }finally{await proxy.close();}
});

test('Python HTTP/1.0 CONNECT is supported and byte budgets terminate tunnels before excess bytes are forwarded',async()=>{
  const sent=[],proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',maxBytes:4,resolve:lookup,connect:upstreamFactory(sent,[])});
  try{
    const result=await conversation(proxy,'CONNECT api.osv.dev:443 HTTP/1.0\r\n\r\n',(socket)=>socket.write('exceeds-limit'));
    assert.match(result,/200 Connection Established/);assert.equal(sent.length,0);assert.equal(proxy.stats.bytes,0);assert.ok(proxy.stats.rejected>0);
  }finally{await proxy.close();}
});

test('connection timeout and absolute tunnel lifetime close hanging peers',async()=>{
  let stalledDials=0;
  const stalled=await startFixEgressProxy({port:0,host:'127.0.0.1',connectTimeoutMs:30,resolve:()=>new Promise(()=>{}),
    connect:()=>{stalledDials++;throw new Error('Unresolved DNS must not open an upstream connection.');}});
  // Either deadline may close this socket first; verify the security outcome
  // without depending on which timer updates its diagnostic counter.
  try{assert.equal(await conversation(stalled,'CONNECT api.osv.dev:443 HTTP/1.0\r\n\r\n'),'');
    assert.equal(stalledDials,0);assert.equal(stalled.stats.accepted,0);assert.equal(stalled.stats.active,0);}finally{await stalled.close();}
  const proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',maxTunnelMs:30,resolve:lookup,connect:upstreamFactory([],[])});
  try{const response=await conversation(proxy,'CONNECT api.osv.dev:443 HTTP/1.0\r\n\r\n',socket=>socket.write(clientHello('api.osv.dev')));assert.match(response,/200/);assert.equal(proxy.stats.active,0);}finally{await proxy.close();}
});


test('TLS SNI must exactly match the CONNECT host, and ambiguous/ECH/unparseable handshakes never reach upstream',async()=>{
  assert.deepEqual(clientHelloServerName(clientHello('openrouter.ai')),{status:'valid',hostname:'openrouter.ai'});
  assert.equal(clientHelloServerName(clientHello('openrouter.ai').subarray(0,8)).status,'need_more');
  assert.equal(clientHelloServerName(clientHello('openrouter.ai',true)).status,'invalid');
  for(const data of [clientHello('evil.test'),clientHello('api.osv.dev'),clientHello('openrouter.ai',true),Buffer.from('plain HTTP bytes not TLS')]){
    const sent=[],proxy=await startFixEgressProxy({port:0,host:'127.0.0.1',resolve:lookup,connect:upstreamFactory(sent,[])});
    try{const response=await conversation(proxy,'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: openrouter.ai:443\r\n\r\n',socket=>socket.write(data));assert.match(response,/200/);assert.equal(sent.length,0);assert.equal(proxy.stats.accepted,0);assert.ok(proxy.stats.rejected>0);}finally{await proxy.close();}
  }
});
