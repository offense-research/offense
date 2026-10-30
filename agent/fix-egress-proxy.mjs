import http from 'node:http';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { Transform } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const FIX_EGRESS_HOSTS = Object.freeze(['registry.npmjs.org', 'app.purpleteam.sh', 'api.osv.dev', 'openrouter.ai']);
const allowed = new Set(FIX_EGRESS_HOSTS);
export function permittedAuthority(value) {
  if (typeof value !== 'string' || value.length > 150 || !/^[a-z0-9.-]+:443$/i.test(value)) return null;
  const hostname = value.slice(0, -4).toLowerCase();
  return allowed.has(hostname) ? hostname : null;
}
export function publicAddress(address) {
  if (net.isIP(address) === 4) {
    const [a,b,c]=address.split('.').map(Number);
    return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||
      (a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===192&&b===0)||(a===192&&b===88&&c===99)||
      (a===198&&(b===18||b===19))||(a===198&&b===51&&c===100)||(a===203&&b===0&&c===113));
  }
  if (net.isIP(address) === 6) return /^[23][a-f0-9]{0,3}:/i.test(address) && !/^2001:(?:db8|0?0?1[0-9a-f]|0?0?2[0-9a-f]):/i.test(address);
  return false;
}
// Peek only at the unencrypted first ClientHello. TLS payloads stay encrypted.
export function clientHelloServerName(buffer) {
  const invalid = { status: 'invalid' };
  if (buffer.length < 5) return { status: 'need_more' };
  if (buffer[0] !== 22 || buffer[1] !== 3 || buffer[2] > 3) return invalid;
  const recordLength = buffer.readUInt16BE(3);
  if (recordLength < 42 || recordLength > 16384) return invalid;
  if (buffer.length < recordLength + 5) return { status: 'need_more' };
  const record = buffer.subarray(5, recordLength + 5);
  if (record[0] !== 1 || record.readUIntBE(1, 3) + 4 !== record.length) return invalid;
  let cursor = 4 + 2 + 32;
  const skip = size => { cursor += size; return cursor <= record.length; };
  if (cursor >= record.length || !skip(1 + record[cursor])) return invalid;
  if (cursor + 2 > record.length) return invalid;
  const ciphers = record.readUInt16BE(cursor);
  if (ciphers < 2 || ciphers % 2 || !skip(2 + ciphers)) return invalid;
  if (cursor >= record.length || !record[cursor] || !skip(1 + record[cursor])) return invalid;
  if (cursor + 2 > record.length) return invalid;
  const extensions = record.readUInt16BE(cursor); cursor += 2;
  if (cursor + extensions !== record.length) return invalid;
  const names = [];
  while (cursor < record.length) {
    if (cursor + 4 > record.length) return invalid;
    const type = record.readUInt16BE(cursor), size = record.readUInt16BE(cursor + 2); cursor += 4;
    if (cursor + size > record.length || type === 0xfe0d) return invalid; // ECH hides the actual name.
    if (type === 0) {
      if (size < 5 || record.readUInt16BE(cursor) !== size - 2) return invalid;
      let offset = cursor + 2;
      while (offset < cursor + size) {
        if (offset + 3 > cursor + size || record[offset] !== 0) return invalid;
        const length = record.readUInt16BE(offset + 1); offset += 3;
        if (!length || length > 253 || offset + length > cursor + size) return invalid;
        const value = record.subarray(offset, offset + length);
        if ([...value].some(byte => byte > 127)) return invalid;
        const hostname = value.toString('ascii').toLowerCase();
        if (!/^[a-z0-9.-]+$/.test(hostname)) return invalid;
        names.push(hostname); offset += length;
      }
    }
    cursor += size;
  }
  return names.length === 1 ? { status: 'valid', hostname: names[0] } : invalid;
}
const bounded = (value,min,max,name) => {if(!Number.isSafeInteger(value)||value<min||value>max)throw new Error(`Invalid ${name}.`);return value;};

// Only the proxy has an external network interface. The job container must be
// attached exclusively to its own Docker --internal network; env proxy settings
// alone are not an egress boundary. TLS remains end-to-end with the destination.
export async function startFixEgressProxy({port=8080,host='0.0.0.0',maxSockets=32,connectTimeoutMs=10000,idleTimeoutMs=60000,
  maxTunnelMs=20*60000,maxBytes=64*1024*1024,maxTotalBytes=256*1024*1024,
  resolve=(hostname)=>lookup(hostname,{all:true,verbatim:true}),connect=options=>net.connect(options)}={}) {
  bounded(port,0,65535,'proxy port');bounded(maxSockets,1,64,'socket limit');
  bounded(connectTimeoutMs,1,60000,'connect timeout');bounded(idleTimeoutMs,1,120000,'idle timeout');
  bounded(maxTunnelMs,1,30*60000,'tunnel lifetime');bounded(maxBytes,1,256*1024*1024,'tunnel byte limit');bounded(maxTotalBytes,1,1024*1024*1024,'total byte limit');
  const sockets=new Set(),upstreams=new Set(),stats={accepted:0,rejected:0,bytes:0,active:0};
  const server=http.createServer({maxHeaderSize:8192,requestTimeout:connectTimeoutMs,headersTimeout:connectTimeoutMs},(_req,res)=>{
    stats.rejected++;res.writeHead(403,{'connection':'close','content-type':'text/plain'});res.end('HTTPS CONNECT required.\n');
  });
  server.maxConnections=maxSockets;
  server.on('connection',socket=>{
    sockets.add(socket);socket.setTimeout(connectTimeoutMs,()=>socket.destroy());
    socket.on('error',()=>{});socket.once('close',()=>sockets.delete(socket));
  });
  server.on('clientError',(_error,socket)=>{stats.rejected++;if(!socket.destroyed)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');});
  server.on('connect',(req,client,head)=>{
    const hostname=permittedAuthority(req.url),hostHeaders=[];
    for(let i=0;i<req.rawHeaders.length;i+=2)if(req.rawHeaders[i].toLowerCase()==='host')hostHeaders.push(req.rawHeaders[i+1]);
    // Node's built-in HTTPS proxy omits the default port in Host while its
    // CONNECT authority still includes :443. Both forms name the same service.
    const validHost=hostHeaders.length===1&&(permittedAuthority(hostHeaders[0])===hostname||hostHeaders[0].toLowerCase()===hostname);
    const oldClient=req.httpVersion==='1.0'&&hostHeaders.length===0;
    if(!hostname||(!validHost&&!oldClient)||req.headers['transfer-encoding']||req.headers['content-length']||stats.bytes>=maxTotalBytes){
      stats.rejected++;client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;
    }
    client.pause();let upstream,closed=false,connected=false,tunnelBytes=0;
    const timers=[];
    const finish=()=>{if(closed)return;closed=true;for(const timer of timers)clearTimeout(timer);upstream?.destroy();client.destroy();if(connected)stats.active--;};
    const reject=()=>{if(closed)return;stats.rejected++;client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');upstream?.destroy();};
    client.once('error',finish);client.once('close',finish);
    timers.push(setTimeout(()=>{stats.rejected++;finish();},connectTimeoutMs));
    const consume=size=>{
      if(tunnelBytes+size>maxBytes||stats.bytes+size>maxTotalBytes)return false;
      tunnelBytes+=size;stats.bytes+=size;return true;
    };
    const limiter=()=>new Transform({transform(chunk,_encoding,callback){
      if(!consume(chunk.length)){stats.rejected++;callback(new Error('Proxy byte limit reached.'));finish();return;}
      callback(null,chunk);
    }}).on('error',finish);
    void (async()=>{
      try {
        const addresses=await resolve(hostname);
        if(closed)return;
        if(!Array.isArray(addresses)||!addresses.length||addresses.some(record=>!publicAddress(record.address)))return reject();
        const address=addresses.find(record=>net.isIP(record.address)===4)||addresses[0];
        // Connect to the approved resolved address, never re-resolve the name.
        upstream=connect({host:address.address,port:443,family:net.isIP(address.address)});
        if(!upstream||typeof upstream.pipe!=='function')throw new Error('Invalid upstream socket.');
        upstreams.add(upstream);upstream.once('close',()=>upstreams.delete(upstream));
        upstream.once('error',()=>{if(connected)finish();else reject();});
        upstream.once('end',()=>client.end());
        upstream.once('connect',()=>{
          if(closed)return upstream.destroy();
          connected=true;stats.active++;
          for(const timer of timers)clearTimeout(timer);timers.length=0;
          timers.push(setTimeout(finish,maxTunnelMs));
          client.setTimeout(idleTimeoutMs,finish);
          upstream.setTimeout?.(idleTimeoutMs,finish);
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          let hello = Buffer.alloc(0);
          const helloTimer = setTimeout(()=>{stats.rejected++;finish();},connectTimeoutMs); timers.push(helloTimer);
          const inspect = chunk => {
            if (closed) return;
            if (!consume(chunk.length) || hello.length + chunk.length > 65536) { stats.rejected++; return finish(); }
            hello = Buffer.concat([hello, chunk]);
            const result = clientHelloServerName(hello);
            if (result.status === 'need_more') return;
            if (result.status !== 'valid' || result.hostname !== hostname) { stats.rejected++; return finish(); }
            clearTimeout(helloTimer); client.removeListener('data', inspect); stats.accepted++;
            // Only an exact, visible SNI match can release the handshake bytes.
            upstream.write(hello); hello = null;
            client.pipe(limiter()).pipe(upstream); upstream.pipe(limiter()).pipe(client);
          };
          client.on('data',inspect);
          if(head.length)inspect(head);
          if(!closed)client.resume();
        });
      }catch{reject();}
    })();
  });
  await new Promise((resolveReady,reject)=>{server.once('error',reject);server.listen(port,host,resolveReady);});
  const address=server.address();
  return {server,address,port:address.port,stats,close:async()=>{
    for(const socket of sockets)socket.destroy();for(const socket of upstreams)socket.destroy();
    await new Promise(resolveClosed=>server.close(resolveClosed));
  }};
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const proxy=await startFixEgressProxy({port:Number(process.env.PURPLE_FIX_EGRESS_PORT||8080)});
  process.stdout.write(`Purple dependency-fix HTTPS egress proxy listening on ${proxy.port}.\n`);
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{void proxy.close().then(()=>{process.exitCode=0;});});
}
