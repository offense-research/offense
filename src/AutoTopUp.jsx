import React, { useState } from 'react';
import { ArrowUpRight, RefreshCw } from 'lucide-react';
import './auto-top-up.css';

const usd = micros => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 }).format(micros / 1_000_000);

export default function AutoTopUp({ settings, onChanged }) {
  const [accepted, setAccepted] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  if (!settings) return null;
  const validPolicy = Number.isSafeInteger(settings.amountCents) && settings.amountCents > 0 &&
    Number.isSafeInteger(settings.thresholdMicros) && settings.thresholdMicros > 0 &&
    Number.isSafeInteger(settings.dailyLimitCents) && settings.dailyLimitCents >= settings.amountCents &&
    typeof settings.consentVersion === 'string' && settings.consentVersion.length > 0;
  const amount = validPolicy ? usd(settings.amountCents * 10_000) : '—';
  const threshold = validPolicy ? usd(settings.thresholdMicros) : '—';
  const maximum = validPolicy ? Math.floor(settings.dailyLimitCents / settings.amountCents) : 0;

  async function update(enabled) {
    if (busy || !settings.canManage || enabled && (!accepted || !validPolicy)) return;
    setBusy(true); setError('');
    try {
      const response = await fetch('/api/scanner-billing/auto-top-up', {
        method: enabled ? 'POST' : 'DELETE', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        ...(enabled ? { body: JSON.stringify({ enabled: true, consentVersion: settings.consentVersion }) } : {})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not update automatic top-up.');
      if (enabled) {
        const url = new URL(data.url);
        if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname) || url.username || url.password)
          throw new Error('Unexpected payment-method setup URL.');
        location.assign(url.href);
      } else {
        if (!data.billing?.autoTopUp || data.billing.autoTopUp.enabled || data.billing.autoTopUp.pendingSetup)
          throw new Error('Could not confirm automatic top-up is off.');
        onChanged(data.billing); setAccepted(false); setBusy(false);
      }
    } catch (cause) { setError(cause.message); setBusy(false); }
  }

  return <section className="scan-auto-topup" aria-labelledby="auto-topup-heading">
    <div className="scan-auto-heading"><h3 id="auto-topup-heading"><RefreshCw size={16}/> Automatic top-up</h3>
      <span className={settings.enabled && settings.available ? 'scan-auto-state is-enabled' : 'scan-auto-state'}>{settings.enabled ? settings.available ? 'On' : 'Paused' : settings.pendingSetup ? 'Setup pending' : 'Off'}</span></div>
    <p className="scan-auto-summary">Add {amount} in credit when your balance falls below {threshold}. Up to {maximum} automatic refills per 24 hours.</p>
    {settings.pending && <p className="scan-auto-message" role="status">A refill is being verified. Your balance updates automatically.</p>}
    {settings.pendingSetup && <p className="scan-auto-message" role="status">Complete payment-method setup on Whop. This page updates automatically.</p>}
    {settings.canManage ? settings.enabled ? <button type="button" className="secondary-button" disabled={busy} onClick={() => { void update(false); }}>{busy ? 'Turning off…' : 'Turn off automatic top-up'}</button> : <>
      {settings.available && validPolicy ? <>
        <label className="scan-auto-consent"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)} disabled={busy}/>
          <span>I authorize {amount} credit purchases below a {threshold} balance, up to {maximum} times per 24 hours. Whop fees and taxes may apply.</span></label>
        <div className="scan-auto-actions"><button type="button" className="secondary-button" disabled={!accepted || busy} onClick={() => { void update(true); }}>{busy ? 'Opening Whop…' : settings.pendingSetup ? 'Continue setup on Whop' : 'Set up automatic top-up'} <ArrowUpRight size={14}/></button>
          {settings.pendingSetup && <button type="button" className="scan-auto-cancel" disabled={busy} onClick={() => { void update(false); }}>Cancel setup</button>}</div>
        <p className="scan-auto-note">Whop securely saves your payment method. Refills start after setup is confirmed.</p>
      </> : <p className="scan-auto-message">Automatic top-up is temporarily unavailable.</p>}
    </> : <p className="scan-auto-message">Only workspace owners can manage automatic top-up.</p>}
    {(error || settings.error) && <p className="key-error" role="alert">{error || settings.error}</p>}
  </section>;
}
