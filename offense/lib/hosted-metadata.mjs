// Reuse the local sanitized collector without importing a hosted automation SDK.
import { collectMetadata } from './metadata.mjs';
export async function collectDependencyMetadata(directory) {
  const metadata = await collectMetadata(directory);
  return { ...metadata, inspectedLockfiles: metadata.files.length };
}
