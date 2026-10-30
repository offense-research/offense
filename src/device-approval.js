export const DEVICE_PERMISSION_LABELS = Object.freeze({
  'tools:call': 'Run security tools using your prepaid credit',
  'account:read': 'Read this account’s balance and tool usage',
  'billing:checkout': 'Open a Whop checkout for you to review'
});

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const invalidRequest = () => failure('invalid_request', 'Could not verify this login request. Start login again in your terminal.');
function failure(code, message) {
  return Object.assign(new Error(message), { code });
}

// An inspect response uses HTTP 200 even when a known request has expired.
// Check that state before the permission gate, while keeping every invalid
// response out of the consent UI.
export function validateDeviceApprovalRequest(data, expectedCode, now = Date.now()) {
  if (!object(data)) throw invalidRequest();
  if (data.user_code !== expectedCode) {
    throw failure('request_mismatch', 'This request does not match the code you entered. Check the code shown in your terminal.');
  }
  if (!Number.isSafeInteger(data.expiresAt) || data.expiresAt < 0) throw invalidRequest();
  if (data.status === 'expired' || data.expiresAt <= now) {
    throw failure('expired_token', 'This request expired. Run offense login again in your terminal.');
  }
  if (!['pending', 'approved', 'denied'].includes(data.status) ||
      !object(data.workspace) || typeof data.workspace.id !== 'string' || !data.workspace.id ||
      typeof data.workspace.name !== 'string') throw invalidRequest();
  if (!Array.isArray(data.scopes) || data.scopes.length !== Object.keys(DEVICE_PERMISSION_LABELS).length ||
      new Set(data.scopes).size !== data.scopes.length ||
      data.scopes.some(scope => typeof scope !== 'string' || !Object.hasOwn(DEVICE_PERMISSION_LABELS, scope))) {
    throw failure('unsupported_permissions', 'This request has unsupported permissions. Start a new login from the current Offense CLI.');
  }
  return data;
}
