import { createDependencyIntelligence } from '../server/dependency-intelligence.js';

export function createLocalIntelligence(options = {}) { return createDependencyIntelligence(options); }
export async function auditMetadata(input, options = {}) { return createLocalIntelligence(options).audit(input); }
