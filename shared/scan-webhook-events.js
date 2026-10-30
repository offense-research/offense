// Scanner credit purchases, saved-method setup and automatic refills share
// the existing scanner webhook. Keep its subscriptions together.
export const SCAN_WHOP_WEBHOOK_EVENTS = Object.freeze([
  'payment.succeeded',
  'refund.created',
  'refund.updated',
  'dispute.created',
  'dispute.updated',
  'payment.failed',
  'payment.requires_action',
  'payment.canceled',
  'setup_intent.succeeded',
  'setup_intent.requires_action',
  'setup_intent.canceled'
]);
