import React, { useEffect, useRef, useState } from 'react';
import { useAutoRefresh } from './useAutoRefresh.js';
import UsageMetrics from './UsageMetrics.jsx';
import ApiKeysPanel from './ApiKeysPanel.jsx';
import AutoTopUp from './AutoTopUp.jsx';
import { Gift } from 'lucide-react';

const usd = micros => Number.isSafeInteger(micros) && micros >= 0
  ? new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2,
    maximumFractionDigits: 6 }).format(micros / 1_000_000) : '—';
const dollars = cents => Number.isSafeInteger(cents) && cents > 0 ? usd(cents * 10_000) : 'credit';

export default function ScanKeys({ scannerPaymentReturned = false, expanded = false, mode = 'all', heading }) {
  const selectedMode = ['keys', 'billing'].includes(mode) ? mode : 'all';
  const showKeys = selectedMode !== 'billing', showBilling = selectedMode !== 'keys';
  const [keys, setKeys] = useState(null), [token, setToken] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [billing, setBilling] = useState(null), [billingBusy, setBillingBusy] = useState(false);
  const [billingError, setBillingError] = useState(''), [buyingCredit, setBuyingCredit] = useState(false);
  const [panelOpen, setPanelOpen] = useState(expanded || scannerPaymentReturned);
  const loadingKeys = useRef(false), loadingBilling = useRef(false), billingRevision = useRef(0);
  const currentMode = useRef(selectedMode); currentMode.current = selectedMode;
  useEffect(() => { setToken(''); setError(''); }, [selectedMode]);
  const atCreditLimit = billing && Number.isSafeInteger(billing.maxBalanceMicros) &&
    Number.isSafeInteger(billing.purchaseCents) &&
    billing.balanceMicros + billing.purchaseCents * 10_000 > billing.maxBalanceMicros;

  async function request(method = 'GET', id = '', signal) {
    if (loadingKeys.current) return;
    loadingKeys.current = true; setBusy(true); setError('');
    let mutationCompleted = false;
    try {
      if (method !== 'GET') {
        const response = await fetch(`/api/scan-keys${id ? `/${encodeURIComponent(id)}` : ''}`, {
          method, credentials: 'same-origin', headers: { 'content-type': 'application/json' }, signal
        });
        const data = response.status === 204 ? {} : await response.json();
        if (!response.ok) {
          if ([401, 403].includes(response.status)) { setToken(''); setKeys(null); }
          throw new Error(data.error || 'API keys unavailable.');
        }
        mutationCompleted = true;
        if (data.token && currentMode.current !== 'billing' && !signal?.aborted) setToken(data.token);
        if (method === 'DELETE') { setToken(''); setKeys(previous => previous?.filter(key => key.id !== id) ?? null); }
      }
      const list = await fetch('/api/scan-keys', { credentials: 'same-origin', cache: 'no-store', signal });
      if (!list.ok) { if ([401, 403].includes(list.status)) { setToken(''); setKeys(null); } throw new Error('Could not refresh API keys.'); }
      const nextKeys = (await list.json()).keys;
      if (!signal?.aborted) setKeys(nextKeys);
      return true;
    } catch (cause) { if (!signal?.aborted) setError(cause.message); return mutationCompleted; }
    finally { loadingKeys.current = false; setBusy(false); }
  }

  async function refreshBilling(signal) {
    if (loadingBilling.current) return;
    loadingBilling.current = true; setBillingBusy(true); setBillingError('');
    const revision = billingRevision.current;
    try {
      const response = await fetch('/api/scanner-billing', { credentials: 'same-origin', cache: 'no-store', signal });
      const data = await response.json();
      if (!response.ok || !data.billing) throw new Error(data.error || 'Tool balance is unavailable.');
      if (!signal?.aborted && revision === billingRevision.current) setBilling(data.billing);
    } catch (cause) { if (!signal?.aborted) setBillingError(cause.message); }
    finally { loadingBilling.current = false; setBillingBusy(false); }
  }

  function billingChanged(next) {
    billingRevision.current++;
    setBilling(next);
  }

  async function buyCredit() {
    setBuyingCredit(true); setBillingError('');
    try {
      const response = await fetch('/api/scanner-billing/checkout', {
        method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not open tool credit checkout.');
      const url = new URL(data.url);
      if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname) ||
          url.username || url.password) throw new Error('Unexpected tool credit checkout URL.');
      location.assign(url.href);
    } catch (cause) { setBillingError(cause.message); setBuyingCredit(false); }
  }

  useAutoRefresh(async signal => {
    await Promise.all([
      ...(showKeys ? [request('GET', '', signal)] : []),
      ...(showBilling ? [refreshBilling(signal)] : [])
    ]);
  }, { enabled: expanded || panelOpen, interval: showBilling && (scannerPaymentReturned || billing?.pendingPayments > 0 || billing?.autoTopUp?.pendingSetup || billing?.autoTopUp?.pending) ? 3000 : 15000,
    dependencies: [selectedMode] });

  const Container = expanded ? 'section' : 'details';
  const label = selectedMode === 'keys' ? 'Offense API keys' : selectedMode === 'billing' ? 'Offense tool credit' : 'Offense account, tool credit and API keys';
  return <Container className={`dashboard-panel scan-keys scan-keys-${selectedMode}${expanded ? ' scan-keys-expanded' : ''}${selectedMode === 'keys' && expanded ? ' scan-keys-table-layout' : ''}`} {...(expanded ? { 'aria-label': label } : {
    defaultOpen: scannerPaymentReturned,
    onToggle: event => { if (event.target === event.currentTarget) { setPanelOpen(event.currentTarget.open); } }
  })}>
    {!expanded && <summary>{selectedMode === 'keys' ? 'API keys' : selectedMode === 'billing' ? 'Tool credit' : 'Tool credit & API keys'}</summary>}
    {selectedMode === 'all' && <><p className="dashboard-muted">One API key across Offense security tools. Sign in through the CLI or create a key here.</p><p><a className="text-link" href="/skill">Set up your coding agent →</a></p></>}

    {showBilling && <section className="scan-wallet" aria-label="Tool credit">
      <div className="scan-wallet-heading"><h3>Tool credit</h3><span className="dashboard-muted">Updates automatically</span></div>
      {scannerPaymentReturned && <p role="status">Returned from Whop. Your balance updates automatically after payment verification.</p>}
      {billing ? <>
        <dl className="scan-wallet-balances">
          <div><dt>Balance</dt><dd>{usd(billing.balanceMicros)}</dd></div>
          <div><dt>Reserved for active runs</dt><dd>{usd(billing.reservedMicros)}</dd></div>
          <div><dt>Available</dt><dd>{usd(billing.availableMicros)}</dd></div>
        </dl>
        {billing.welcomeCreditMicros > 0 && <p className="scan-wallet-welcome"><Gift size={16}/>{usd(billing.welcomeCreditMicros)} in welcome credit included</p>}
        {billing.enabled ? <>
          <p className="dashboard-muted">Pay per security tool call. Your agent gets a maximum-price quote first. Partial or failed jobs release their reservation.</p>
          {billing.blocked && <p role="alert">Tool credit is under payment review. New paid calls and top-ups are paused.</p>}
          {billing.pendingPayments > 0 && <p role="status">A payment is being verified. Your balance will update here automatically.</p>}
          {billing.pendingPurchases > 0 && !billing.pendingPayments && <p className="dashboard-muted">A tool credit checkout is open for this workspace.</p>}
          {billing.reviewPurchases > 0 && !billing.blocked && <p role="alert">A payment needs review before its credit can be used.</p>}
          {atCreditLimit && <p className="dashboard-muted">Top-ups have a {usd(billing.maxBalanceMicros)} balance limit. Use some credit before loading more.</p>}
          {billing.checkoutEnabled && !billing.blocked && !atCreditLimit ? <button className="secondary-button" disabled={buyingCredit}
            onClick={() => { void buyCredit(); }}>{buyingCredit ? 'Opening Whop…' : `Add ${dollars(billing.purchaseCents)} via Whop`}</button>
            : !billing.blocked && !atCreditLimit && <p className="dashboard-muted">Tool credit top-up is temporarily unavailable.</p>}
          {Array.isArray(billing.prices) && billing.prices.length > 0 && <details className="scan-wallet-prices">
            <summary>Prices per tool</summary>
            <p className="dashboard-muted">Prices depend on the tool and its input. Your agent requests a maximum-price quote before submitting a paid scan.</p>
            <ul>{billing.prices.map(price => <li key={price.id}>
              <span>{price.name || price.id}</span>
              <span>{['bounded_assessment', 'bounded_job', 'assessment'].includes(price.unit) ? `${usd(price.basePriceMicros)} per bounded assessment` : price.additionalMiBPriceMicros === 0 ? `${usd(price.basePriceMicros)} per scan` : `${usd(price.basePriceMicros)} first MiB + ${usd(price.additionalMiBPriceMicros)} each extra MiB`}</span>
            </li>)}</ul>
          </details>}
        </> : <p className="dashboard-muted">Paid tools are temporarily unavailable. Free dependency advisory checks still work.</p>}
        <p className="dashboard-muted">Limit: 10 hosted runs per workspace in a rolling 24 hours, subject to shared capacity.</p>
      </> : !billingBusy && !billingError && <p className="dashboard-muted">Loading your tool balance…</p>}
      {billingError && <p className="key-error" role="alert">{billingError}</p>}
      {billing?.autoTopUp && <AutoTopUp settings={billing.autoTopUp} onChanged={billingChanged}/>}
    </section>}

    {showKeys && <ApiKeysPanel keys={keys} token={token} busy={busy} error={error} heading={heading}
      onCreate={() => request('POST')} onRevoke={id => request('DELETE', id)} onClearToken={() => setToken('')} onCopyError={setError}/>}
    {selectedMode === 'all' && <details><summary>Data and balances</summary><p className="dashboard-muted">Hosted source and artifact tools upload the inputs you select. Review them for private data before submitting. Jobs run in isolated containers and reports are kept for 30 days. Tool credit is separate from any existing hosted model balance.</p></details>}
    {selectedMode === 'all' && (expanded || panelOpen) && <UsageMetrics/>}
  </Container>;
}
