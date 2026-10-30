import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createSimulationBilling, createWhopProvider, verifyWhopWebhook } from '../server/whop-billing.js';
import { markedUpMicros, RUN_RESERVE_MICROS } from '../server/simulation-wallet.js';
import { createUpgradeRehearsals, proposeTrialRehearsal } from '../server/upgrade-rehearsal.js';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

const secret = 'ws_test-only-signing-secret', product = 'hosted-model-balance-v2';
let message = 0;
function signed(data, id = `msg_${++message}`, timestamp = Math.floor(Date.now() / 1000)) {
  const raw = Buffer.from(JSON.stringify(data));
  return [raw, { 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': 'v1,' + createHmac('sha256', secret).update(`${id}.${timestamp}.`).update(raw).digest('base64') }];
}
function fixture(extra = {}) {
  const db = new DatabaseSync(':memory:'); let payment = {}, setup = {}, checkouts = 0, topups = 0, failTopup = false, topupState = 'paid';
  const provider = {
    checkout: async (id, url, kind) => { checkouts++; return { id: `ch_${checkouts}`, account_id: 'biz_test', purchase_url: `https://whop.com/checkout/${checkouts}`,
      mode: kind === 'setup' ? 'setup' : 'payment', plan: kind === 'setup' ? null : { plan_type: 'one_time', currency: 'usd', initial_price: 5 } }; },
    payment: async () => payment,
    setupIntent: async () => setup,
    topUp: async (id, preferences) => { topups++; if (failTopup) throw new Error('Ambiguous network timeout');
      payment = { id: `pay_topup${topups}`, account_id: preferences.account_id, member_id: preferences.member_id, status: topupState,
        currency: 'usd', total: { amount: '5.00', currency: 'usd' }, metadata: { purple_order_id: id, purple_product: product } };
      return { id: payment.id }; }
  };
  const billing = createSimulationBilling(db, { apiKey: 'private-api-key', webhookSecret: secret, enabled: true, publicUrl: 'https://purple.test', provider, ...extra });
  async function buy() {
    const order = await billing.checkout('workspace', 'user');
    payment = { id: 'pay_test', account_id: 'biz_test', checkout_configuration_id: `ch_${checkouts}`, status: 'paid', currency: 'usd', total: { amount: '5.00', currency: 'usd' },
      refunded_amount: { amount: '0.00', currency: 'usd' }, metadata: { purple_order_id: order.orderId, purple_product: product } };
    return order;
  }
  const deliver = (type = 'payment.succeeded', id = payment.id) => billing.webhook(...signed({ type, data: { id } }));
  async function enable() {
    const order = await billing.checkout('workspace', 'user', 'setup');
    setup = { id: 'sint_test', account_id: 'biz_test', checkout_configuration_id: `ch_${checkouts}`, status: 'succeeded', member_id: 'mber_test', payment_method_id: 'payt_test', metadata: { purple_order_id: order.orderId, purple_product: product } };
    await deliver('setup_intent.succeeded', 'sint_test'); return order;
  }
  return { db, billing, buy, enable, deliver, provider, get payment() { return payment; }, get setup() { return setup; }, get checkouts() { return checkouts; }, get topups() { return topups; },
    set failTopup(v) { failTopup = v; }, set topupState(v) { topupState = v; } };
}

test('Whop signatures cover original bytes, timestamp, ID and literal secret', () => {
  const [raw, headers] = signed({ type: 'payment.succeeded', data: { id: 'pay_test' } });
  assert.equal(verifyWhopWebhook(raw, headers, secret).event.type, 'payment.succeeded');
  assert.throws(() => verifyWhopWebhook(Buffer.from(raw.toString()+' '), headers, secret), error => error.status === 401);
  assert.throws(() => verifyWhopWebhook(raw, { ...headers, 'webhook-id': 'different' }, secret), error => error.status === 401);
  assert.throws(() => verifyWhopWebhook(raw, headers, 'wrong-secret'), error => error.status === 401);
  assert.throws(() => verifyWhopWebhook(...signed({}, 'msg_expired', Math.floor(Date.now()/1000) - 301), secret), error => error.status === 401);
});

test('usage markup retains fractional cents, uses actual cost and rejects missing or nonfinite costs', () => {
  assert.equal(markedUpMicros(1), 1_300_000);
  assert.equal(markedUpMicros(0.01), 13000);
  assert.equal(markedUpMicros(0.000001), 2);
  assert.equal(markedUpMicros(0), 0);
  assert.equal(markedUpMicros(0.023456), 30493);
  for (const value of [undefined, null, NaN, Infinity, -1, '0.01']) assert.throws(() => markedUpMicros(value));
});

test('one verified $5 purchase adds $5 once despite repeated delivery; reservation and release are isolated', async () => {
  const f = fixture();
  try {
    const order = await f.buy(); assert.deepEqual(await f.billing.checkout('workspace', 'user'), order); assert.equal(f.checkouts, 1);
    assert.equal(f.billing.status('workspace').balanceMicros, 0);
    const event = signed({ type: 'payment.succeeded', data: { id: 'pay_test' } });
    await f.billing.webhook(...event); await f.billing.webhook(...event); await f.deliver();
    assert.equal(f.billing.status('workspace').balanceMicros, 5_000_000);
    assert.equal(f.billing.status('another-workspace').balanceMicros, 0);
    assert.throws(() => f.billing.reserve('another-workspace', 'job'), error => error.status === 402);
    f.billing.reserve('workspace', 'job');
    assert.equal(f.billing.status('workspace').availableMicros, 5_000_000 - RUN_RESERVE_MICROS);
    const charge = f.billing.settle('job', { costUsd: 0.01, generationId: 'gen_test' });
    assert.equal(charge.chargedMicros, 13000); f.billing.settle('job', { costUsd: 1 });
    assert.equal(f.billing.status('workspace').balanceMicros, 4_987_000);
    f.billing.release('job'); f.billing.release('job'); assert.equal(f.billing.status('workspace').balanceMicros, 5_000_000);
    assert.ok(!JSON.stringify(f.billing.status('workspace')).includes('private-api-key'));
  } finally { f.db.close(); }
});

test('zero-cost planning is not billed, unknown or excessive costs are never guessed or allowed to overdraw', async () => {
  const f = fixture();
  try {
    await f.buy(); await f.deliver();
    f.billing.reserve('workspace','free'); f.billing.settle('free',{costUsd:0}); assert.equal(f.billing.status('workspace').balanceMicros,5_000_000);
    f.billing.reserve('workspace','unknown'); assert.throws(() => f.billing.settle('unknown', {}));
    assert.throws(() => f.billing.settle('unknown', {costUsd: 1}));
    assert.equal(f.billing.status('workspace').reservedMicros, RUN_RESERVE_MICROS);
    f.billing.release('unknown'); assert.equal(f.billing.status('workspace').balanceMicros, 5_000_000);
    for (let n=0;n<50;n++) f.billing.reserve('workspace',`reservation${n}`);
    assert.throws(() => f.billing.reserve('workspace','overdraw'), error => error.status === 402);
  } finally { f.db.close(); }
});

test('wrong amount, checkout, account, currency, product, unpaid or refunded payments cannot fund balances', async () => {
  for (const patch of [{ total: { amount: '4.99', currency: 'usd' } }, { checkout_configuration_id: 'ch_other' }, { account_id: 'biz_other' },
    { currency: 'eur' }, { total: { amount: '5.00', currency: 'eur' } }, { status: 'pending' }, { auto_refunded: true },
    { refunded_amount: { amount: '0.50', currency: 'usd' } }, { refunded_amount: { amount: 'invalid' } }, { metadata: {purple_product:'other'} }]) {
    const f = fixture(); try {
      const order = await f.buy(); if (patch.metadata) patch.metadata.purple_order_id = order.orderId;
      Object.assign(f.payment, patch); await assert.rejects(f.deliver(), error => error.status === 409);
      assert.equal(f.billing.status('workspace').balanceMicros, 0);
    } finally { f.db.close(); }
  }
});

test('refunds and disputes freeze spending and auto top-up even when delivery precedes payment success', async () => {
  for (const before of [true,false]) {
    const f = fixture(); try {
      await f.buy(); if (!before) await f.deliver();
      await f.billing.webhook(...signed({ type: 'dispute.created', data: { payment_id: 'pay_test' } }));
      if (before) await f.deliver();
      assert.equal(f.billing.status('workspace').blocked, true); assert.equal(f.billing.status('workspace').canRun, false);
      assert.throws(() => f.billing.reserve('workspace','job'), error => error.status === 409);
      await assert.rejects(f.billing.checkout('workspace','user'), error => error.status === 409);
      await f.billing.dispatch(); assert.equal(f.topups,0);
    } finally { f.db.close(); }
  }
});

test('auto top-up requires verified saved-method setup and never enables from an unverified or canceled setup', async () => {
  const f = fixture(); try {
    assert.equal(f.billing.status('workspace').autoTopUp.enabled, false);
    const order = await f.billing.checkout('workspace','user','setup');
    assert.equal(f.billing.status('workspace').autoTopUp.pending,true);
    Object.assign(f.setup,{ id:'sint_test',status:'processing',metadata:{purple_order_id:order.orderId,purple_product:product} });
    await assert.rejects(f.deliver('setup_intent.succeeded','sint_test'));
    await f.enable(); assert.equal(f.billing.status('workspace').autoTopUp.enabled,true);
    f.billing.disableAuto('workspace');
    await f.deliver('setup_intent.succeeded','sint_test');
    await f.billing.dispatch(); assert.equal(f.topups,0); assert.equal(f.billing.status('workspace').autoTopUp.enabled,false);
  } finally { f.db.close(); }
});

test('opt-in top-up adds $5 below $1 once under concurrent dispatch, retains saved identity, and respects daily cap', async () => {
  const f = fixture(); try {
    await f.enable(); await Promise.all([f.billing.dispatch(),f.billing.dispatch()]);
    assert.equal(f.topups,1); assert.equal(f.billing.status('workspace').balanceMicros,5_000_000);
    await f.billing.dispatch(); assert.equal(f.topups,1);
    for(let n=0;n<3;n++) {
      f.db.prepare("INSERT INTO wallet_entries VALUES (?, 'workspace', -5000000, 'test-usage', ?)").run(`spend${n}`,Date.now());
      await f.billing.dispatch();
    }
    assert.equal(f.topups,4);
    f.db.prepare("INSERT INTO wallet_entries VALUES ('final-spend', 'workspace', -5000000, 'test-usage', ?)").run(Date.now());
    await f.billing.dispatch(); assert.equal(f.topups,4);
    assert.match(f.billing.status('workspace').autoTopUp.error,/daily/);
    assert.equal(f.billing.status('workspace').autoTopUp.amountCents,500);
  } finally { f.db.close(); }
});

test('ambiguous and authentication-required top-ups pause charging without granting funds or retrying', async () => {
  for(const timeout of [true,false]) {
    const f=fixture(); try {
      await f.enable(); f.failTopup=timeout; f.topupState='requires_action';
      await f.billing.dispatch(); await f.billing.dispatch();
      assert.equal(f.topups,1); assert.equal(f.billing.status('workspace').balanceMicros,0);
      assert.equal(f.billing.status('workspace').autoTopUp.enabled,false);
      assert.match(f.billing.status('workspace').autoTopUp.error,/attention/);
    } finally { f.db.close(); }
  }
});

test('a delayed successful top-up funds the balance once after authentication failure, without restoring automatic consent', async () => {
  const f=fixture(); try {
    await f.enable(); f.topupState='requires_action'; await f.billing.dispatch();
    await f.deliver('payment.requires_action');
    assert.equal(f.billing.status('workspace').balanceMicros,0);
    f.payment.status='paid'; await f.deliver(); await f.deliver();
    assert.equal(f.billing.status('workspace').balanceMicros,5_000_000);
    assert.equal(f.billing.status('workspace').autoTopUp.enabled,false);
    await f.billing.dispatch(); assert.equal(f.topups,1);
  } finally { f.db.close(); }
});

test('canceling pending saved-method setup permits a fresh opt-in and rejects late setup events', async () => {
  const f=fixture(); try {
    const old=await f.billing.checkout('workspace','user','setup'); f.billing.disableAuto('workspace');
    const fresh=await f.billing.checkout('workspace','user','setup'); assert.notEqual(fresh.orderId,old.orderId);
    Object.assign(f.setup,{id:'sint_old',status:'succeeded',account_id:'biz_test',checkout_configuration_id:'ch_1',member_id:'mber_old',payment_method_id:'payt_old',metadata:{purple_order_id:old.orderId,purple_product:product}});
    await f.deliver('setup_intent.succeeded','sint_old'); assert.equal(f.billing.status('workspace').autoTopUp.enabled,false);
  } finally { f.db.close(); }
});

test('in-flight top-up may complete after consent is disabled but never starts another charge', async () => {
  const f=fixture(); try {
    await f.enable(); let finish;
    const original=f.provider.topUp;
    f.provider.topUp=async(...args) => { const result=await original(...args); await new Promise(resolve => { finish=resolve; }); return result; };
    const pending=f.billing.dispatch(); await new Promise(resolve=>setImmediate(resolve));
    f.billing.disableAuto('workspace'); finish(); await pending;
    assert.equal(f.billing.status('workspace').balanceMicros,5_000_000);
    await f.billing.dispatch(); assert.equal(f.topups,1);
  } finally { f.db.close(); }
});

test('billing disabled prevents purchases, usage reservations and automatic charges', async () => {
  const f=fixture({enabled:false}); try {
    assert.equal(f.billing.status('workspace').enabled,false);
    await assert.rejects(f.buy(),error=>error.status===503);
    assert.throws(()=>f.billing.reserve('workspace','job'),error=>error.status===402);
    await f.billing.dispatch(); assert.equal(f.topups,0);
  } finally { f.db.close(); }
});

test('provider fixes $5, metadata and idempotency, supports setup and off-session tokens, and redacts failures', async () => {
  let request;
  const provider=createWhopProvider({apiKey:'private-provider-key',fetchImpl:async(url,options)=>{request={url,options};return Response.json({id:'ch_test'});}});
  await provider.checkout('server-order','https://purple.test/'); let body=JSON.parse(request.options.body);
  assert.equal(body.plan.initial_price,5);assert.equal(body.plan.plan_type,'one_time');assert.equal(body.plan.stock,1);
  assert.equal(body.metadata.purple_order_id,'server-order');assert.equal(request.options.headers['Idempotency-Key'],'purple-checkout-server-order');
  await provider.checkout('setup-order','https://purple.test/','setup');body=JSON.parse(request.options.body);assert.equal(body.mode,'setup');assert.equal(body.plan,undefined);
  await provider.topUp('auto-order',{account_id:'biz_test',member_id:'mber_test',payment_method_id:'payt_test'});body=JSON.parse(request.options.body);
  assert.equal(body.off_session,true);assert.equal(body.plan.initial_price,5);assert.equal(body.payment_method_id,'payt_test');assert.equal(request.options.headers['Idempotency-Key'],'purple-topup-auto-order');
  assert.ok(!request.options.body.includes('private-provider-key'));
  const broken=createWhopProvider({apiKey:'secret',fetchImpl:async()=>Response.json({error:'secret'},{status:403})});
  await assert.rejects(broken.payment('pay_test'),error=>!error.message.includes('secret')&&error.status===502);
});

test('paid hosted simulations meter actual model cost, survive restarts, reuse results and refund infrastructure failures',async()=>{
  const f=fixture();try {
    await f.buy();await f.deliver();f.db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY,data TEXT)');
    const session={github:{account:'org',installationId:1}};
    f.db.prepare('INSERT INTO workspaces VALUES (?,?)').run('workspace',JSON.stringify(session));
    const snapshot={repository:'org/repo',installationId:1,revision:'rev',scannedAt:1,graph:{nodes:[{}]},files:['package-lock.json'],vulnerabilityCheck:{status:'complete',checkedAt:2,findings:[{id:'x',package:'leaf',version:'1.0.0'}]}};
    let failStart=true,calls=0;
    const options={mapper:{snapshots:()=>[snapshot],upgradePlan:async()=>({name:'leaf',currentVersion:'1.0.0',targetVersion:'1.0.1'})},
      billing:f.billing,platformModelKey:'platform-key',github:{repositories:async()=>[{fullName:'org/repo'}],installationToken:async()=>'checkout-key'},
      decrypt:()=>{throw new Error('Hosted runs must not decrypt a user key');},propose:async(_snapshot,plans,key)=>{assert.equal(key,'platform-key');calls++;return {...proposeTrialRehearsal(plans),usage:{costUsd:0.01,generationId:'gen_test'}};},
      sandbox:{start:async input=>{assert.ok(!JSON.stringify(input).includes('platform-key'));if(failStart)throw new Error('Container unavailable');return{status:'running'};},get:async()=>({status:'completed',revision:'rev',baseline:{checks:[{passed:false}]},scenarios:[]})}};
    let service=createUpgradeRehearsals(f.db,options);f.db.prepare('INSERT INTO rehearsal_trials VALUES (?,?,?)').run('workspace','previous-trial',Date.now());
    const first=service.start('workspace','org/repo',1,session);assert.ok(first.walletJobId);assert.equal(service.start('workspace','org/repo',1,session).id,first.id);
    await service.dispatch();assert.equal(f.billing.status('workspace').balanceMicros,5_000_000);
    assert.equal(service.latest('workspace','org/repo',1).billing.refunded,true);
    failStart=false;service=createUpgradeRehearsals(f.db,options);const second=service.start('workspace','org/repo',1,session);
    await service.dispatch();await service.dispatch();assert.equal(service.latest('workspace','org/repo',1).status,'completed');
    assert.equal(f.billing.status('workspace').balanceMicros,4_987_000);assert.equal(calls,2);
    assert.equal(service.start('workspace','org/repo',1,session).id,second.id);assert.equal(calls,2);
    snapshot.revision = 'byok-revision';
    const byok = { ...session, openrouter: { secret: 'encrypted-own-key' } };
    f.db.prepare('UPDATE workspaces SET data = ? WHERE id = ?').run(JSON.stringify(byok),'workspace');
    service = createUpgradeRehearsals(f.db, { ...options, decrypt: () => 'own-key', propose: async (_s,plans,key) => { assert.equal(key,'own-key'); return {...proposeTrialRehearsal(plans),usage:{costUsd:0.01}}; } });
    const own = service.start('workspace','org/repo',1,byok); assert.equal(own.walletJobId,undefined);
    await service.dispatch(); await service.dispatch(); assert.equal(f.billing.status('workspace').balanceMicros,4_987_000);
  }finally{f.db.close();}
});

test('real app accepts raw signed webhooks, isolates workspace funds and requires authenticated same-origin consent',async()=>{
  const original=globalThis.fetch,db=new DatabaseSync(':memory:');let server;
  try {
    let orderId;
    globalThis.fetch=async(url,options)=>{
      if(String(url).startsWith('https://api.whop.com/api/v1/checkout_configurations')) {orderId=JSON.parse(options.body).metadata.purple_order_id;return Response.json({id:'ch_app',account_id:'biz_app',purchase_url:'https://whop.com/checkout/app',plan:{plan_type:'one_time',currency:'usd',initial_price:5}});}
      if(String(url).startsWith('https://api.whop.com/api/v1/payments/pay_app'))return Response.json({id:'pay_app',status:'paid',account_id:'biz_app',checkout_configuration_id:'ch_app',currency:'usd',total:{amount:'5.00',currency:'usd'},metadata:{purple_order_id:orderId,purple_product:product}});
      return original(url,options);
    };
    const {app}=createWorkerApp({db,env:{PUBLIC_URL:'https://purple.test',WHOP_API_KEY:'test-key',WHOP_WEBHOOK_SECRET:secret,WHOP_BILLING_ENABLED:'true',OPENROUTER_API_KEY:'platform-test'},schedule:()=>{}});
    const accounts=createAccounts(db),user=accounts.upsertUser(777,'payer'),cookie='c'.repeat(64);
    db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(cookie,JSON.stringify({userId:user.id}),Date.now());
    server=app.listen(0,'127.0.0.1');await once(server,'listening');const address=`http://127.0.0.1:${server.address().port}`;
    assert.equal((await original(address+'/api/billing/checkout',{method:'POST'})).status,401);
    assert.equal((await original(address+'/api/billing/checkout',{method:'POST',headers:{cookie:`purple_session=${cookie}`,origin:'https://evil.test'}})).status,403);
    assert.equal((await original(address+'/api/billing/auto-top-up',{method:'POST',headers:{cookie:`purple_session=${cookie}`}})).status,400);
    const checkout=await original(address+'/api/billing/checkout',{method:'POST',headers:{cookie:`purple_session=${cookie}`,'content-type':'application/json'},body:JSON.stringify({amount:0,workspace:'someone-else'})});assert.equal(checkout.status,200);
    const [raw,headers]=signed({type:'payment.succeeded',data:{id:'pay_app'}});
    assert.equal((await original(address+'/api/billing/whop/webhook',{method:'POST',headers:{...headers,'content-type':'application/json'},body:raw})).status,200);
    const state=await original(address+'/api/billing',{headers:{cookie:`purple_session=${cookie}`}}).then(r=>r.json());assert.equal(state.billing.balanceMicros,5_000_000);
    assert.equal((await original(address+'/api/billing/whop/webhook',{method:'POST',headers:{...headers,'content-type':'application/json'},body:Buffer.from('{}')})).status,401);
  }finally{globalThis.fetch=original;if(server)await new Promise(resolve=>server.close(resolve));db.close();}
});
