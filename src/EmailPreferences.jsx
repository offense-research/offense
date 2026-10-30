import React, { useEffect, useId, useState } from 'react';

export default function EmailPreferences({ contact, compact = false, onSaved }) {
  const emailId = useId(), updatesId = useId();
  const [email, setEmail] = useState(contact?.email || contact?.suggestedEmail || '');
  const [productUpdates, setProductUpdates] = useState(contact?.productUpdates === true);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  useEffect(() => {
    setEmail(contact?.email || contact?.suggestedEmail || '');
    setProductUpdates(contact?.productUpdates === true);
  }, [contact?.email, contact?.suggestedEmail, contact?.productUpdates, contact?.updatedAt]);
  async function request(action, event) {
    event?.preventDefault();
    setBusy(true); setError('');
    try {
      const response = await fetch(`/api/account/email${action === 'dismiss' ? '/dismiss' : ''}`, {
        method: action === 'remove' ? 'DELETE' : 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        ...(action === 'save' ? { body: JSON.stringify({ email, productUpdates }) } : {})
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save email preferences.');
      onSaved(result.contact, action);
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  }
  return <section className={`email-preferences ${compact ? 'compact' : ''}`} aria-label="Email preferences">
    <div><h3>{compact ? 'Add a contact email' : 'Email & notifications'}</h3><p>Save an email for account and scan updates. Product emails are optional.</p></div>
    <form onSubmit={event => request('save', event)}>
      <label htmlFor={emailId}>Email address</label>
      <div className="email-address-row"><input id={emailId} type="email" inputMode="email" autoComplete="email" value={email} maxLength={254} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" required disabled={busy}/><button className="primary-button" disabled={busy}>{busy ? 'Saving…' : 'Save email'}</button>{compact && <button type="button" className="secondary-button" disabled={busy} onClick={() => request('dismiss')}>Not now</button>}</div>
      {!contact?.email && contact?.suggestedEmail && <p className="email-suggestion">Suggested from your GitHub profile. Confirm or change it before saving.</p>}
      <label className="email-opt-in" htmlFor={updatesId}><input id={updatesId} type="checkbox" checked={productUpdates} onChange={e => setProductUpdates(e.target.checked)} disabled={busy}/>Also email me occasional Offense product updates.</label>
      {contact?.email && <button type="button" className="text-link" disabled={busy} onClick={() => request('remove')}>Remove saved email</button>}
      {error && <p className="key-error" role="alert">{error}</p>}
    </form>
  </section>;
}
