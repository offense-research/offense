export const cloneJson = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export class WorkspaceConflictError extends Error {
  constructor() { super('Workspace changed in another request. Refresh and try again.'); this.status = 409; }
}

// Apply only this request's changes. Concurrent edits of the same value must retry.
export function mergeJsonDraft(base, draft, latest) {
  if (same(base, draft)) return cloneJson(latest);
  if (same(base, latest) || same(draft, latest)) return cloneJson(draft);
  if (!object(base) || !object(draft) || !object(latest)) throw new WorkspaceConflictError();
  const result = {};
  for (const key of new Set([...Object.keys(base), ...Object.keys(draft), ...Object.keys(latest)])) {
    const value = mergeJsonDraft(base[key], draft[key], latest[key]);
    if (value !== undefined) Object.defineProperty(result, key, { value, writable: true, configurable: true, enumerable: true });
  }
  return result;
}

function syncObject(target, latest) {
  for (const key of Object.keys(target)) if (!Object.hasOwn(latest, key)) delete target[key];
  for (const [key, value] of Object.entries(latest)) {
    if (object(value) && object(target[key])) syncObject(target[key], value);
    else Object.defineProperty(target, key, { value: cloneJson(value), writable: true, configurable: true, enumerable: true });
  }
}

export function createJsonDraft(source, commit) {
  const value = cloneJson(source);
  let baseline = cloneJson(source);
  return { value, save() {
    const latest = commit(value, baseline);
    // Preserve references used by long-running installer and refresh callbacks.
    syncObject(value, latest);
    baseline = cloneJson(latest);
    return value;
  } };
}
