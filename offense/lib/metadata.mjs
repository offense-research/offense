export { collectMetadata } from '../tools/purple.mjs';
import { collectMetadata } from '../tools/purple.mjs';
export async function prepareAudit(directory) { const metadata = await collectMetadata(directory); return { ...metadata, payload: { files: metadata.files } }; }
