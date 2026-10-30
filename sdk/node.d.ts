import type { AutomationPolicy, PolicyInput, SecurityEvent, OffenseClient, DependencyFile, CheckResult } from './index.js';
export { assertSecurityDecision, SecurityGateError } from './index.js';
export function collectDependencyMetadata(directory: string): Promise<{ files: DependencyFile[]; warnings: string[]; inspectedLockfiles: number }>;
export function checkRepository(options: { directory: string; event?: SecurityEvent; policy?: PolicyInput; client?: OffenseClient;
  signal?: AbortSignal }): Promise<CheckResult & { localCoverage: { status: 'not_checked' | 'complete' | 'incomplete'; warnings: string[]; inspectedLockfiles?: number } }>;
