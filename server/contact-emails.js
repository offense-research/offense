export function normalizeContactEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim();
  if (email.length > 254 || /[\r\n\s]/.test(email)) return null;
  const parts = email.split('@');
  if (parts.length !== 2) return null;
  const [local, domain] = parts;
  if (!local || local.length > 64 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local) || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) || labels.at(-1).length < 2) return null;
  return `${local}@${domain.toLowerCase()}`;
}

export function createContactEmails(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS user_contacts (
    user_id TEXT PRIMARY KEY REFERENCES users(id), email TEXT NOT NULL DEFAULT '', suggested_email TEXT NOT NULL DEFAULT '',
    product_updates INTEGER NOT NULL DEFAULT 0, consent_updated_at INTEGER, consent_version TEXT,
    updated_at INTEGER NOT NULL, dismissed_at INTEGER
  )`);
  function get(userId) {
    const row = db.prepare('SELECT * FROM user_contacts WHERE user_id = ?').get(userId);
    return { email: row?.email || '', suggestedEmail: row?.suggested_email || '', productUpdates: row?.product_updates === 1,
      consentUpdatedAt: row?.consent_updated_at || null, updatedAt: row?.updated_at || null,
      dismissedAt: row?.dismissed_at || null, verified: false };
  }
  function suggestFromGitHub(userId, value) {
    const email = normalizeContactEmail(value);
    if (!email || /(?:^|\.)noreply\.github\.com$/i.test(email.split('@')[1])) return;
    db.prepare(`INSERT INTO user_contacts (user_id, suggested_email, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET suggested_email = excluded.suggested_email
      WHERE user_contacts.email = '' AND user_contacts.dismissed_at IS NULL`).run(userId, email, Date.now());
  }
  function save(userId, input) {
    const email = normalizeContactEmail(input?.email);
    if (!email) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
    if (typeof input.productUpdates !== 'boolean') throw Object.assign(new Error('Choose whether to receive product updates.'), { status: 400 });
    const now = Date.now();
    db.prepare(`INSERT INTO user_contacts
      (user_id, email, product_updates, consent_updated_at, consent_version, updated_at)
      VALUES (?, ?, ?, ?, 'product-updates-v1', ?)
      ON CONFLICT(user_id) DO UPDATE SET email = excluded.email, suggested_email = '', product_updates = excluded.product_updates,
        consent_updated_at = excluded.consent_updated_at, consent_version = excluded.consent_version,
        updated_at = excluded.updated_at, dismissed_at = NULL`)
      .run(userId, email, input.productUpdates ? 1 : 0, now, now);
    return get(userId);
  }
  function dismiss(userId) {
    db.prepare(`INSERT INTO user_contacts (user_id, updated_at, dismissed_at) VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET dismissed_at = excluded.dismissed_at`).run(userId, Date.now(), Date.now());
    return get(userId);
  }
  function remove(userId) {
    const now = Date.now();
    db.prepare(`INSERT INTO user_contacts (user_id, updated_at, dismissed_at) VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET email = '', suggested_email = '', product_updates = 0,
        consent_updated_at = excluded.updated_at, consent_version = 'product-updates-v1',
        updated_at = excluded.updated_at, dismissed_at = excluded.dismissed_at`).run(userId, now, now);
    return get(userId);
  }
  return { get, suggestFromGitHub, save, dismiss, remove };
}

// Register after the app's session, authentication and request-origin middleware.
export function registerContactEmailRoutes(app, contacts) {
  app.post('/api/account/email', (req, res) => res.json({ contact: contacts.save(req.authUser.id, req.body) }));
  app.post('/api/account/email/dismiss', (req, res) => res.json({ contact: contacts.dismiss(req.authUser.id) }));
  app.delete('/api/account/email', (req, res) => res.json({ contact: contacts.remove(req.authUser.id) }));
}
