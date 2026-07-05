// API client + types. Field names mirror the Go JSON contract in
// internal/server/api.go exactly. Every string here (title, description, path,
// rationale) originates from scanned code or an LLM and is HOSTILE — it is only
// ever rendered as React text (auto-escaped), never as HTML.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Location {
  file?: string;
  startLine?: number;
  endLine?: number;
  url?: string;
}

export interface Triage {
  verdict: "true-positive" | "false-positive" | "uncertain";
  confidence?: number;
  rationale?: string;
  model?: string;
}

// Stage-2 context evidence behind riskScore (schema 1.3.0, risk v2).
// code/note are fixed strings from the reviewed signal tables in Go.
export interface RiskSignal {
  code: string;
  delta: number;
  note?: string;
}

export interface Finding {
  id: string;
  tool: string;
  tools?: string[];
  category: string;
  ruleId: string;
  title: string;
  description?: string;
  severity: Severity;
  rawSeverity?: string;
  confidence?: string;
  location: Location;
  package?: string;
  cwes?: string[];
  cve?: string;
  remediation?: string;
  complianceControls?: string[];
  triage?: Triage;
  riskScore?: number;
  riskSignals?: RiskSignal[];
}

export interface OwaspCategory {
  id: string;
  title: string;
}
export interface OwaspBucket {
  category: OwaspCategory;
  count: number;
}

export interface FrameworkSummary {
  id: string;
  version: string;
  violatedControls: number;
  cleanControls: number;
  notAssessable: number;
  unmappedFindings: number;
}

export interface GateInfo {
  threshold: string;
  failed: boolean;
}
export interface VerdictCounts {
  truePositive: number;
  falsePositive: number;
  uncertain: number;
  untriaged: number;
}
export interface RiskBands {
  low: number;
  medium: number;
  high: number;
  critical: number;
}
export interface DeltaCounts {
  new: number;
  resolved: number;
  unchanged: number;
  total: number;
}

export interface TrendPoint {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  riskAvg: number;
}

export interface SummaryResponse {
  runCount: number;
  latestId: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  owasp: OwaspBucket[];
  compliance: FrameworkSummary[];
  riskBands: RiskBands;
  gate: GateInfo;
  verdicts: VerdictCounts;
  trend: TrendPoint[];
}

export interface RunListItem {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  gate: GateInfo;
  delta: DeltaCounts;
  verdicts: VerdictCounts;
}
export interface RunsResponse {
  runs: RunListItem[];
}

export interface RunDetail {
  id: string;
  createdAt: string;
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  owasp: OwaspBucket[];
  compliance: FrameworkSummary[];
  gate: GateInfo;
  verdicts: VerdictCounts;
  delta: DeltaCounts;
  newIds: string[];
  resolvedIds: string[];
  findings: Finding[];
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path}: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  summary: () => getJSON<SummaryResponse>("api/summary"),
  runs: () => getJSON<RunsResponse>("api/runs"),
  run: (id: string) => getJSON<RunDetail>(`api/runs/${encodeURIComponent(id)}`),
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// --- Console-ops (auth, targets, scan jobs, audit) ---
// Field names mirror internal/server DTOs exactly; opsApi sends the
// session CSRF token on every non-GET request.

// --- New TypeScript types (exact JSON contract from the Go server) ---

export interface UserInfo { id: string; username: string; role: string; createdAt: string; }
export interface MeResponse { authRequired: boolean; authenticated: boolean; user?: UserInfo; csrfToken?: string; }
export interface LoginResponse { user: UserInfo; csrfToken: string; }
export interface Target { id: string; name: string; path: string; scanners?: string[]; profile?: string; createdAt: string; }
export interface TargetsResponse { targets: Target[]; }
export interface JobOptions { scanners?: string[]; profile?: string; triage?: boolean | null; }
export type JobStatus = "queued" | "running" | "done" | "failed";
export interface Job {
  id: string; targetId: string; targetName: string; launchedBy: string;
  options: JobOptions; status: JobStatus; queuedAt: string;
  startedAt?: string; finishedAt?: string; progress: string[];
  runId?: string; error?: string;
}
export interface JobsResponse { jobs: Job[]; }
export interface AuditEntry { time: string; event: string; actor?: string; details?: Record<string, string>; }
export interface AuditResponse { entries: AuditEntry[]; }

// --- ApiError class ---

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// --- Module-level CSRF state ---

let csrfToken: string | null = null;

export function setCsrfToken(t: string | null): void {
  csrfToken = t;
}

// --- send helper ---

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (!res.ok) {
    let errorMessage = `${path}: ${res.status} ${res.statusText}`;
    try {
      const errBody = await res.json();
      if (errBody && typeof errBody === "object" && "error" in errBody && typeof errBody.error === "string") {
        errorMessage = errBody.error;
      }
    } catch {
      // Ignore parse errors, use default message
    }
    throw new ApiError(res.status, errorMessage);
  }

  // Every success body in the contract is JSON; a non-JSON success is empty.
  const contentType = res.headers.get("content-type");
  if (!contentType || !contentType.includes("application/json")) {
    return undefined as unknown as T;
  }
  return (await res.json()) as T;
}

// --- Constants ---

export const KNOWN_SCANNERS = ["semgrep", "gitleaks", "trivy", "checkov"];
export const PROFILES = ["fast", "standard", "max"];

// --- opsApi implementation ---

export const opsApi = {
  me: (): Promise<MeResponse> => send<MeResponse>("GET", "api/auth/me"),
  
  login: (username: string, password: string): Promise<LoginResponse> => 
    send<LoginResponse>("POST", "api/auth/login", { username, password }),
  
  logout: (): Promise<void> => 
    send<void>("POST", "api/auth/logout"),
  
  users: (): Promise<{ users: UserInfo[] }> => 
    send<{ users: UserInfo[] }>("GET", "api/users"),
  
  createUser: (username: string, password: string, role: string): Promise<UserInfo> => 
    send<UserInfo>("POST", "api/users", { username, password, role }),
  
  updateUserRole: (id: string, role: string): Promise<UserInfo> => 
    send<UserInfo>("PATCH", `api/users/${encodeURIComponent(id)}`, { role }),
  
  updateUserPassword: (id: string, password: string): Promise<UserInfo> => 
    send<UserInfo>("PATCH", `api/users/${encodeURIComponent(id)}`, { password }),
  
  deleteUser: (id: string): Promise<void> => 
    send<void>("DELETE", `api/users/${encodeURIComponent(id)}`),
  
  targets: (): Promise<TargetsResponse> => 
    send<TargetsResponse>("GET", "api/targets"),
  
  createTarget: (t: { name: string; path: string; scanners?: string[]; profile?: string }): Promise<Target> => 
    send<Target>("POST", "api/targets", t),
  
  deleteTarget: (id: string): Promise<void> => 
    send<void>("DELETE", `api/targets/${encodeURIComponent(id)}`),
  
  jobs: (): Promise<JobsResponse> => 
    send<JobsResponse>("GET", "api/scans"),
  
  job: (id: string): Promise<Job> => 
    send<Job>(`GET`, `api/scans/${encodeURIComponent(id)}`),
  
  launchScan: (targetId: string, options: JobOptions): Promise<Job> => 
    send<Job>("POST", "api/scans", { targetId, options }),
  
  audit: (n = 200): Promise<AuditResponse> => 
    send<AuditResponse>(`GET`, `api/audit?n=${n}`),
};
