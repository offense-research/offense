export type SecurityEvent = 'manual' | 'dependency_change' | 'scheduled' | 'pre_deploy' | 'post_deploy' | 'agent_run';
export interface AutomationPolicy {
  schemaVersion: 'offense.automation.v1'; enabled: boolean; onChange: boolean; schedule: 'daily' | 'weekly' | 'off';
  preDeploy: boolean; postDeploy: boolean; agentRun: boolean;
  gate: { mode: 'report' | 'block'; minimumSeverity: 'high' | 'critical'; onIncomplete: 'block' | 'report' };
}
export type PolicyInput = Partial<Omit<AutomationPolicy, 'gate'>> & { gate?: Partial<AutomationPolicy['gate']> };
export interface DependencyFile { path: string; content: string | Record<string, unknown> }
export interface SecurityDecision {
  schemaVersion: 'offense.decision.v1'; event: SecurityEvent; enabled: boolean;
  action: 'allow' | 'block' | 'report' | 'skip'; passed: boolean | null; reason: string;
  counts: { total: number; critical: number; high: number; medium: number; low: number; unknown: number;
    atOrAboveThreshold: number; checkedPackages: number; skippedPackages: number };
  limitations: string[];
}
export interface AuditFinding {
  id: string; advisoryId: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  package: { name: string; installedVersion: string; lockfiles: string[]; [key: string]: unknown };
  verification: { status: 'advisory_match'; confirmed: false }; [key: string]: unknown;
}
export interface AuditReport {
  schemaVersion: 'offense.audit.v1'; capability: 'audit_dependencies'; status: 'complete' | 'partial'; scannedAt: number;
  metadataFingerprint: string; findings: AuditFinding[];
  coverage: { status: 'complete' | 'partial'; checkedPackages: number; skippedPackages: number; warnings: string[]; [key: string]: unknown };
  summary: { advisoryMatches: number; confirmedVulnerabilities: 0; [key: string]: unknown };
  remediation: { plans: unknown[]; blockers: unknown[]; [key: string]: unknown }; providers: unknown[]; [key: string]: unknown;
}
export interface CheckResult {
  report: AuditReport | null; decision: SecurityDecision; durationMs: number;
  error?: { code: string; status?: number };
}
export interface ClientEvent { event: SecurityEvent; stage: 'audit'; outcome: string; durationMs?: number; advisoryMatches?: number; errorCode?: string }
export interface OffenseClient {
  audit(input: { files: DependencyFile[]; signal?: AbortSignal }): Promise<AuditReport>;
  check(input: { files: DependencyFile[]; event?: SecurityEvent; policy?: PolicyInput; signal?: AbortSignal }): Promise<CheckResult>;
}
export function defaultAutomationPolicy(): AutomationPolicy;
export function normalizeAutomationPolicy(input?: PolicyInput): AutomationPolicy;
export function evaluateSecurityPolicy(report: AuditReport | null, policy?: PolicyInput, event?: SecurityEvent, options?: { now?: number }): SecurityDecision;
export const OFFENSE_SDK_VERSION: '0.1.1';
export const OFFENSE_API_URL: 'https://offense.sh';
export function dependencyMetadataFingerprint(files: DependencyFile[]): Promise<string>;
export function createOffenseClient(options?: { baseUrl?: string; fetchImpl?: typeof fetch; timeoutMs?: number;
  maximumResponseBytes?: number; onEvent?: (event: Readonly<ClientEvent>) => void }): OffenseClient;
export class SecurityGateError extends Error { decision: SecurityDecision; constructor(decision: SecurityDecision) }
export function assertSecurityDecision(decision: SecurityDecision, options?: { requirePassed?: boolean }): SecurityDecision;
export function createAuditTool(options?: { client?: OffenseClient; policy?: PolicyInput; event?: SecurityEvent }): {
  readonly name: 'offense_audit_dependencies'; readonly description: string; readonly inputSchema: Record<string, unknown>;
  execute(input: { files: DependencyFile[] }): Promise<CheckResult>;
};
export function claudeMcpOptions(options?: { baseUrl?: string }): {
  mcpServers: { offense: { type: 'http'; url: string } }; allowedTools: string[];
};
export function opencodeMcpConfig(options?: { baseUrl?: string }): {
  mcp: { offense: { type: 'remote'; url: string; enabled: true; oauth: false; timeout: number } };
};
export interface HostedScanQuote {
  readonly currency: 'usd'; readonly billable: boolean; readonly toolIds: readonly string[];
  readonly inputBytes: number; readonly fileCount: number; readonly maximumMicros: number; [key: string]: unknown;
}
export interface HostedScanJob {
  id: string; status: 'queued' | 'starting' | 'running' | 'completed' | 'partial' | 'failed';
  reportExpired?: boolean; [key: string]: unknown;
}
export function createHostedScanClient(options: { apiKey: string; baseUrl?: string; fetchImpl?: typeof fetch; timeoutMs?: number }): {
  tools(options?: { signal?: AbortSignal }): Promise<{ tools: { id: string; [key: string]: unknown }[]; [key: string]: unknown }>;
  usage(options?: { signal?: AbortSignal }): Promise<Record<string, unknown>>;
  quote(input: { tools: string[]; inputBytes: number; fileCount: number; signal?: AbortSignal }): Promise<HostedScanQuote>;
  submit(input: { input: { tools: string[]; files?: { path: string; content: string }[]; [key: string]: unknown };
    quote: HostedScanQuote; maxChargeMicros: number; idempotencyKey: string; signal?: AbortSignal }): Promise<HostedScanJob>;
  get(scanId: string, options?: { signal?: AbortSignal }): Promise<HostedScanJob>;
};
