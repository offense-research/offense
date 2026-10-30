import { readRehearsal, finishRehearsal, rehearsalOutboundAllowed } from './rehearsal-lifecycle.js';
import { scanController, scanService } from './scan-container.js';
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { timingSafeEqual } from 'node:crypto';
import { rehearsalProgram } from '../agent/upgrade-rehearsal.js';
import { connect } from 'cloudflare:sockets';
import { ASSESSMENT_GATEWAY, assessmentDestination, assessmentTunnel, assessmentFailureReason } from './assessment-egress.js';
import { assessmentGatewayStream } from './assessment-egress-client.js';
import { recordAssessmentFailure } from './assessment-failure-metrics.js';

function equal(a, b) {
  if (!a || !b) return false;
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export class AgentOutbound extends WorkerEntrypoint {
  fetch(request) {
    const url = new URL(request.url);
    const allowed = new Set(['github.com', 'codeload.github.com', 'api.github.com', 'openrouter.ai',
      'registry.npmjs.org', 'registry.yarnpkg.com']);
    if (url.protocol !== 'https:' || !allowed.has(url.hostname)) return new Response('Outbound host blocked', { status: 403 });
    return fetch(request);
  }
}

export class RehearsalOutbound extends WorkerEntrypoint {
  fetch(request) {
    if (!rehearsalOutboundAllowed(request.url)) return new Response('Simulation network access blocked', { status: 403 });
    return fetch(request);
  }
}

export class AssessmentOutbound extends WorkerEntrypoint {
  async fetch(request) {
    const url = new URL(request.url), scanId = this.ctx.props.scanId;
    if (!/^[a-f0-9]{32}$/.test(scanId || '')) return new Response('Invalid assessment', { status: 403 });
    const controller = this.env.AGENT.getByName(`scan-${scanId}`);
    if (url.protocol !== 'http:' || url.hostname !== ASSESSMENT_GATEWAY || url.pathname !== '/tunnel' || request.method !== 'POST') {
      await controller.assessmentNetworkFailed('scope_denied', 0);
      return new Response('Assessment network access denied', { status: 403 });
    }
    let socket, connectionTicket, failurePhase = 'destination_denied';
    const tunnel = assessmentTunnel({ onFailure: (reason, metrics) => controller.assessmentNetworkFailed(reason, metrics?.durationMs),
      onClose: async () => { if (socket) await socket.close(); } });
    this.ctx.waitUntil(tunnel.finished.then(async result => {
      if (result.failed && !result.failureRecorded) throw new Error('Assessment network failure could not be recorded.');
      if (connectionTicket) await controller.assessmentConnectionFinished(connectionTicket);
    }));
    try {
      const host = request.headers.get('x-purple-target-host');
      const authorized = await controller.authorizeAssessmentConnection(host);
      const address = authorized.address;
      connectionTicket = authorized.ticket;
      if (tunnel.signal.aborted) {
        // The lifecycle may have ended while authorization was in flight.
        const outcome = await tunnel.finished;
        if (!outcome.failed || outcome.failureRecorded) await controller.assessmentConnectionFinished(connectionTicket);
        throw new Error('Assessment connection authorization timed out.');
      }
      if (authorized.denied) throw new Error('Assessment destination could not be authorized.');
      if (this.env.ASSESSMENT_EGRESS_URL) {
        failurePhase = 'gateway_unavailable';
        const body = await assessmentGatewayStream({ gatewayURL: this.env.ASSESSMENT_EGRESS_URL,
          key: this.env.ASSESSMENT_EGRESS_KEY, host, address, body: request.body, tunnel,
          waitUntil: promise => this.ctx.waitUntil(promise) });
        return new Response(body, { headers: { 'content-type': 'application/octet-stream' } });
      }
      failurePhase = 'socket_open';
      socket = connect({ hostname: address, port: 443 }, { secureTransport: 'off', allowHalfOpen: true });
      this.ctx.waitUntil(socket.closed.catch(() => tunnel.fail('socket_open')));
      await socket.opened;
      this.ctx.waitUntil(tunnel.wrap(request.body, 'request').pipeTo(socket.writable).catch(() => tunnel.fail('socket_upload')));
      return new Response(tunnel.wrap(socket.readable, 'response'), { headers: { 'content-type': 'application/octet-stream' } });
    } catch (error) {
      const reason = assessmentFailureReason(error?.reason);
      await tunnel.fail(reason === 'unknown' ? failurePhase : reason);
      return new Response('Assessment connection unavailable', { status: 502 });
    }
  }
}

export class PurpleAgentContainer extends DurableObject {
  async authorizeAssessmentConnection(host) {
    const policy = this.ctx.storage.kv.get('assessment-policy');
    const connections = this.ctx.storage.kv.get('assessment-connections') || 0;
    if (!policy || connections >= policy.maxConnections) throw new Error('Assessment connection budget exceeded.');
    // Reserve before resolving DNS, so concurrent sockets cannot overspend.
    this.ctx.storage.kv.put('assessment-connections', connections + 1);
    const ticket = crypto.randomUUID();
    this.ctx.storage.kv.put(`assessment-active:${ticket}`, true);
    this.ctx.storage.kv.put('assessment-active-count', (this.ctx.storage.kv.get('assessment-active-count') || 0) + 1);
    try { return { address: await assessmentDestination(policy, host), ticket }; }
    catch {
      // Keep the receipt pending until the tunnel records its one failure and
      // finishes cleanup. Recording here as well would double-count a denial.
      return { denied: true, ticket };
    }
  }
  async assessmentConnectionFinished(ticket) {
    if (typeof ticket !== 'string' || !/^[a-f0-9-]{36}$/.test(ticket) || !this.ctx.storage.kv.get(`assessment-active:${ticket}`)) return;
    this.ctx.storage.kv.delete(`assessment-active:${ticket}`);
    this.ctx.storage.kv.put('assessment-active-count', Math.max(0, (this.ctx.storage.kv.get('assessment-active-count') || 0) - 1));
  }
  async assessmentNetworkFailed(reason, durationMs) {
    recordAssessmentFailure(this.ctx.storage.kv, reason, durationMs);
  }
  async startScan(input) { return scanController(this.ctx, this.env).start(input); }
  async readScan() { return scanController(this.ctx, this.env).get(); }
  async destroyScan() { return scanController(this.ctx, this.env).destroy(); }

  async startRehearsal(input) {
    const previous = this.ctx.storage.kv.get('rehearsal');
    if (previous) return previous;
    const container = await this.start();
    this.ctx.storage.kv.put('rehearsal', { status: 'running', startedAt: Date.now() });
    await this.ctx.storage.setAlarm(Date.now() + 14 * 60_000);
    try {
      // Credentials are confined to this checkout process, which exits before
      // any repository install/test/build command starts. No model key is sent.
      const clone = `const {spawnSync}=await import('node:child_process');const {mkdir}=await import('node:fs/promises');let text='';for await(const chunk of process.stdin)text+=chunk;const input=JSON.parse(text);await mkdir('/tmp/purple-rehearsal',{recursive:true});const cwd='/tmp/purple-rehearsal/source';const env={PATH:process.env.PATH,HOME:process.env.HOME,GIT_TERMINAL_PROMPT:'0',GIT_SSL_CAINFO:'/etc/cloudflare/certs/cloudflare-containers-ca.crt'};const header='AUTHORIZATION: basic '+Buffer.from('x-access-token:'+input.githubToken).toString('base64');for(const argv of [['clone','--no-checkout','--depth','1','https://github.com/'+input.repository+'.git',cwd],['-C',cwd,'fetch','--depth','1','origin',input.revision],['-C',cwd,'checkout','--detach',input.revision]]){const r=spawnSync('git',['-c','http.https://github.com/.extraheader='+header,...argv],{env,timeout:90000,stdio:'ignore'});if(r.status!==0)throw new Error('Pinned GitHub checkout failed');}`;
      const stream = value => new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(JSON.stringify(value))); controller.close(); } });
      const checkout = await container.exec(['timeout', '120', 'node', '--input-type=module', '-e', clone], { stdin: stream(input) });
      const checkoutOutput = await checkout.output();
      if (checkoutOutput.exitCode !== 0) {
        const diagnostic = new TextDecoder().decode(checkoutOutput.stderr).split(input.githubToken).join('[REDACTED]').slice(-1000);
        console.error('Rehearsal checkout failed', diagnostic);
        throw new Error('Could not check out the pinned GitHub revision.');
      }
      // After checkout, repository commands may fetch public packages only.
      await container.interceptAllOutboundHttp(this.ctx.exports.RehearsalOutbound);
      await container.interceptOutboundHttps('*', this.ctx.exports.RehearsalOutbound);
      await container.exec(['timeout', '--kill-after=5', '720', 'node', '--input-type=module', '-e', rehearsalProgram()], {
        stdin: stream({ root: '/tmp/purple-rehearsal', revision: input.revision, scenarios: input.scenarios }), stdout: 'ignore', stderr: 'ignore'
      });
      const job = { status: 'running', startedAt: Date.now() };
      this.ctx.storage.kv.put('rehearsal', job);
      return job;
    } catch (error) {
      await finishRehearsal(this.ctx, { status: 'failed', error: 'Could not start the simulation sandbox.' });
      throw error;
    }
  }

  async readRehearsal() {
    return readRehearsal(this.ctx);
  }

  async start() {
    const container = this.ctx.container;
    if (!container) throw new Error('Container binding is unavailable.');
    if (!container.running) container.start({
      image: container.images.agent,
      entrypoint: ['sleep', 'infinity'],
      enableInternet: false,
      instance: 'standard-2'
    });
    await container.interceptAllOutboundHttp(this.ctx.exports.AgentOutbound);
    await container.interceptOutboundHttps('*', this.ctx.exports.AgentOutbound);
    await container.setInactivityTimeout(15 * 60_000);
    return container;
  }

  async probe() {
    const container = await this.start();
    const process = await container.exec(['pi', '--version']);
    const output = await process.output();
    return { exitCode: output.exitCode, version: new TextDecoder().decode(output.stdout).trim().slice(0, 100) };
  }

  async verifyFixture() {
    const container = await this.start();
    try {
      const process = await container.exec(['timeout', '--kill-after=5', '90', 'node', '/opt/purple/verification-self-test.mjs']);
      const output = await process.output();
      if (output.exitCode !== 0 || output.stdout.byteLength > 20000) throw new Error('Verification fixture failed.');
      return JSON.parse(new TextDecoder().decode(output.stdout));
    } finally { await this.ctx.container?.destroy(); }
  }

  async probeModel(key, kind) {
    if (typeof key !== 'string' || key.length < 20 || key.length > 500) throw new Error('Invalid model credentials.');
    const container = await this.start();
    const script = `try { const r = await fetch('https://openrouter.ai/api/v1/chat/completions', { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.OPENROUTER_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ model: 'deepseek/deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Reply with OK.' }], max_tokens: 32, reasoning: { effort: 'none' } }), signal: AbortSignal.timeout(30000) }); const d = await r.json(); console.log(JSON.stringify({ status: r.status, reply: d.choices?.[0]?.message?.content, error: d.error })); } catch (e) { console.error(e.message, e.cause?.message || ''); process.exitCode = 1; }`;
    const argv = kind === 'http' ? ['timeout', '40', 'node', '--input-type=module', '-e', script] :
      ['timeout', '40', 'pi', '-p', '--no-session', '--no-context-files', '--no-skills', '--no-extensions', '--no-mcp', '--no-approve',
        '--provider', 'openrouter', '--model', 'deepseek/deepseek-v4.1-flash', '--no-tools', 'Reply with OK.'];
    const process = await container.exec(argv, { env: { OPENROUTER_API_KEY: key, PI_CODING_AGENT_DIR: '/tmp/pi-probe',
      GIT_SSL_CAINFO: '/etc/cloudflare/certs/cloudflare-containers-ca.crt', NODE_EXTRA_CA_CERTS: '/etc/cloudflare/certs/cloudflare-containers-ca.crt' } });
    const result = await process.output();
    const clean = bytes => new TextDecoder().decode(bytes).split(key).join('[REDACTED]').slice(-2000);
    return { exitCode: result.exitCode, stdout: clean(result.stdout), stderr: clean(result.stderr) };
  }

  async startInvestigation(input) {
    const existing = this.ctx.storage.kv.get('job');
    if (existing) return existing;
    const json = JSON.stringify(input);
    if (json.length > 200000) throw new Error('Investigation evidence is too large.');
    const container = await this.start();
    const stdin = new ReadableStream({ start(controller) {
      controller.enqueue(new TextEncoder().encode(json));
      controller.close();
    } });
    await container.exec(['timeout', '--kill-after=5', '900', 'node', '/opt/purple/cloudflare-run.mjs'], {
      stdin, stdout: 'ignore', stderr: 'ignore', env: { PURPLE_RESULT_PATH: '/tmp/purple-result.json' }
    });
    this.ctx.storage.kv.put('job', { status: 'running', startedAt: Date.now() });
    await this.ctx.storage.setAlarm(Date.now() + 15000);
    return { status: 'running' };
  }

  async readInvestigation() {
    const job = this.ctx.storage.kv.get('job');
    if (!job) return { status: 'missing' };
    if (job.status !== 'running') return job;
    if (!this.ctx.container?.running) {
      const failed = { status: 'failed', error: 'Pi container stopped before returning a result.' };
      this.ctx.storage.kv.put('job', failed);
      return failed;
    }
    const process = await this.ctx.container.exec(['cat', '/tmp/purple-result.json']);
    const output = await process.output();
    if (output.exitCode === 0) {
      const text = new TextDecoder().decode(output.stdout);
      if (text.length > 500000) throw new Error('Pi result is too large.');
      const result = JSON.parse(text);
      this.ctx.storage.kv.put('job', result);
      return result;
    }
    if (Date.now() - job.startedAt > 15 * 60_000) {
      const failed = { status: 'failed', error: 'Pi analysis timed out.' };
      this.ctx.storage.kv.put('job', failed);
      return failed;
    }
    return { status: 'running' };
  }

  async alarm() {
    if (this.ctx.storage.kv.get('rehearsal')) {
      await finishRehearsal(this.ctx, this.ctx.storage.kv.get('rehearsal').status === 'running'
        ? { status: 'failed', error: 'Simulation retention deadline reached.' } : this.ctx.storage.kv.get('rehearsal'));
      return;
    }
    if (this.ctx.storage.kv.get('scan')) { await this.destroyScan(); return; }
    try {
      if ((await this.readInvestigation()).status === 'running') await this.ctx.storage.setAlarm(Date.now() + 15000);
    } catch (error) {
      console.error('Pi result check failed', error);
      await this.ctx.storage.setAlarm(Date.now() + 15000);
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/scans' || url.pathname.startsWith('/scans/')) {
      if (!equal(request.headers.get('authorization')?.replace(/^Bearer /, ''), env.AGENT_SHARED_KEY)) return new Response('Unauthorized', { status: 401 });
      try { return await scanService(request, env); }
      catch { return Response.json({ error: 'Scanner service could not process this request.' }, { status: 502 }); }
    }
    const rehearsalMatch = /^\/rehearsals\/([a-f0-9]{32})$/.exec(url.pathname);
    if ((url.pathname === '/rehearsals' && request.method === 'POST') || (rehearsalMatch && request.method === 'GET')) {
      if (!equal(request.headers.get('authorization')?.replace(/^Bearer /, ''), env.AGENT_SHARED_KEY)) return new Response('Unauthorized', { status: 401 });
      try {
        if (rehearsalMatch) return Response.json(await env.AGENT.getByName(`rehearsal-${rehearsalMatch[1]}`).readRehearsal());
        const text = await request.text();
        if (text.length > 180000) return new Response('Request too large', { status: 413 });
        const input = JSON.parse(text);
        if (!/^[a-f0-9]{32}$/.test(input.id || '') || !/^[a-f0-9]{40}$/.test(input.revision || '') ||
          !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(input.repository || '') || typeof input.githubToken !== 'string' ||
          !Array.isArray(input.scenarios) || !input.scenarios.length || input.scenarios.length > 2) return new Response('Invalid rehearsal input', { status: 400 });
        return Response.json(await env.AGENT.getByName(`rehearsal-${input.id}`).startRehearsal(input), { status: 202 });
      } catch (error) {
        console.error('Rehearsal sandbox failed', String(error.message).slice(0, 500));
        return Response.json({ error: 'Could not start or read the upgrade rehearsal sandbox.' }, { status: 502 });
      }
    }
    const runMatch = /^\/runs\/(\d+)$/.exec(url.pathname);
    if ((url.pathname === '/run' && request.method === 'POST') || (runMatch && request.method === 'GET')) {
      if (!equal(request.headers.get('authorization')?.replace(/^Bearer /, ''), env.AGENT_SHARED_KEY)) {
        return new Response('Unauthorized', { status: 401 });
      }
      if (runMatch) {
        const attemptId = url.searchParams.get('attempt') || '';
        if (attemptId && !/^[a-f0-9]{32}$/.test(attemptId)) return new Response('Invalid attempt ID', { status: 400 });
        try { return Response.json(await env.AGENT.getByName(`run-${runMatch[1]}${attemptId ? `-${attemptId}` : ''}`).readInvestigation()); }
        catch (error) { return Response.json({ error: String(error.message || error).slice(0, 300) }, { status: 502 }); }
      }
    }
    if (url.pathname === '/run' && request.method === 'POST') {
      if (Number(request.headers.get('content-length')) > 200000) return new Response('Request too large', { status: 413 });
      try {
        const text = await request.text();
        if (text.length > 200000) return new Response('Request too large', { status: 413 });
        const input = JSON.parse(text);
        if (!Number.isSafeInteger(input.runId) || input.runId < 1) return new Response('Invalid run ID', { status: 400 });
        if (input.attemptId && !/^[a-f0-9]{32}$/.test(input.attemptId)) return new Response('Invalid attempt ID', { status: 400 });
        const result = await env.AGENT.getByName(`run-${input.runId}${input.attemptId ? `-${input.attemptId}` : ''}`).startInvestigation(input);
        return Response.json(result, { status: 202 });
      } catch (error) {
        console.error('Agent run failed', error);
        return Response.json({ error: String(error.message || error).slice(0, 500) }, { status: 502 });
      }
    }
    if (url.pathname === '/diagnostics/verification' && request.method === 'POST') {
      if (!equal(request.headers.get('authorization')?.replace(/^Bearer /, ''), env.AGENT_SHARED_KEY)) return new Response('Unauthorized', { status: 401 });
      try { return Response.json(await env.AGENT.getByName('verification-gate-v2-fixture').verifyFixture()); }
      catch { return Response.json({ error: 'Verification fixture failed.' }, { status: 502 }); }
    }
    if (url.pathname === '/diagnostics/model' && request.method === 'POST') {
      if (!equal(request.headers.get('authorization')?.replace(/^Bearer /, ''), env.AGENT_SHARED_KEY)) return new Response('Unauthorized', { status: 401 });
      try {
        const text = await request.text();
        if (text.length > 1000) return new Response('Request too large', { status: 413 });
        const input = JSON.parse(text);
        if (!['http', 'pi'].includes(input.kind)) return new Response('Invalid probe', { status: 400 });
        return Response.json(await env.AGENT.getByName('model-diagnostics').probeModel(input.key, input.kind));
      } catch (error) { return Response.json({ error: String(error.message).slice(0, 300) }, { status: 502 }); }
    }
    if (url.pathname !== '/health' || request.method !== 'GET') return new Response('Not found', { status: 404 });
    try {
      const result = await env.AGENT.getByName('probe').probe();
      return Response.json({ status: result.exitCode === 0 ? 'ok' : 'error', ...result, upgradeRehearsals: true }, { status: result.exitCode === 0 ? 200 : 503 });
    } catch (error) {
      console.error('Agent container probe failed', error);
      return Response.json({ status: 'error', message: String(error.message || error).slice(0, 200) }, { status: 503 });
    }
  }
};
