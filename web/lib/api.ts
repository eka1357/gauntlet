/**
 * Typed API client for Gauntlet Backend (FR-14).
 * Generated from live endpoint shapes:
 *   - /api/recorded/summary
 *   - /api/recorded/attacks
 *   - /api/policy/{v}
 *   - /api/attacks/{id}/trace
 */

export interface MetricDetail {
  count: number;
  rate: number;
  rate_pct: number;
  ci: [number, number];
  ci_pct: [number, number];
}

export interface ModeMetrics {
  n: number;
  m1: MetricDetail;
  m2: MetricDetail;
  m3: MetricDetail;
  m4: MetricDetail;
  unsafe: MetricDetail;
}

export interface StandardModeEval {
  n: number;
  description: string;
  unhardened: ModeMetrics;
  policy_v2: ModeMetrics;
}

export interface ProbeSetEval {
  n: number;
  description: string;
  unhardened: ModeMetrics;
  policy_v1: ModeMetrics;
  policy_v2: ModeMetrics;
}

export interface BenignRun {
  run: number;
  passed: number;
  total: number;
  pass_rate_pct: number;
}

export interface BenignConditionResult {
  runs: BenignRun[];
  pooled_passed: number;
  pooled_total: number;
  pooled_pass_rate_pct: number;
  ci: [number, number];
  ci_pct: [number, number];
}

export interface NegativeControlResult {
  condition: string;
  passed: number;
  total: number;
  pass_rate_pct: number;
  ci: [number, number];
  ci_pct: [number, number];
  status: string;
}

export interface BenignSuiteEval {
  repeats: number;
  tasks_per_repeat: number;
  total_evaluations_per_condition: number;
  unhardened: BenignConditionResult;
  policy_v2: BenignConditionResult;
  pooled_difference_percentage_points: number;
  negative_control: NegativeControlResult;
}

export interface PolicyHashes {
  v1: string;
  v2: string;
}

export interface RunCosts {
  policy_v1_run_usd: number;
  confirmation_set2_run_usd: number;
  benign_variance_naive_run_usd: number;
  total_usd: number;
}

export interface RecordedSummary {
  naive_mode: StandardModeEval;
  realistic_mode: StandardModeEval;
  probe_set: ProbeSetEval;
  benign_suite: BenignSuiteEval;
  policy_hashes: PolicyHashes;
  costs: RunCosts;
  limitations: string[];
  total_cost_usd: number;
  n_total: number;
  n_standard: number;
  n_probe: number;
  elapsed_sec: number;
  seed: number;
  evaluation_type?: string;
  frozen_policy_v1_sha256?: string;
  frozen_policy_v2_sha256?: string;
}

export interface AttackConditionRecord {
  outcome: "defended" | "breach";
  m1: boolean;
  m2: boolean;
  m3: boolean;
  m4: boolean;
  unsafe: boolean;
  policy_block_rule: string | null;
}

export interface AttackRecord {
  id: string;
  channel: "email" | "web_page" | "document" | string;
  category: string;
  strategy: string;
  is_probe: boolean;
  unhardened: AttackConditionRecord;
  v1: AttackConditionRecord;
  v2: AttackConditionRecord;
}

export interface RecordedAttacksResponse {
  total: number;
  page: number;
  limit: number;
  pages: number;
  attacks: AttackRecord[];
}

export interface PolicyResponse {
  version: number;
  sha256: string;
  yaml: string;
  policy: Record<string, unknown>;
  rationale: Record<string, string>;
}

export interface AttackTraceStep {
  type?: string;
  tool?: string;
  args?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  content?: string;
  result?: unknown;
  policy_block?: boolean;
  policy_rule?: string | null;
  policy_reason?: string | null;
  canary?: string | boolean;
  turn?: number;
  call_id?: string;
  timestamp?: number;
  [key: string]: unknown;
}

export interface AttackTraceResponse {
  id: string;
  condition: "unhardened" | "v1" | "v2";
  channel: string;
  category: string;
  strategy: string;
  payload: string;
  is_probe: boolean;
  outcome: "defended" | "breach";
  metrics: {
    m1?: boolean;
    m2?: boolean;
    m3?: boolean;
    m4?: boolean;
    unsafe?: boolean;
    [key: string]: unknown;
  };
  policy_block_rule: string | null;
  trace: AttackTraceStep[];
}

export class ApiError extends Error {
  status?: number;
  actionGuide?: string;

  constructor(message: string, status?: number, actionGuide?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.actionGuide = actionGuide;
  }
}

export function getApiBaseUrl(): string {
  if (typeof window !== "undefined" && process.env.NEXT_PUBLIC_API_BASE) {
    return process.env.NEXT_PUBLIC_API_BASE;
  }
  return process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const base = getApiBaseUrl();
  const url = `${base.replace(/\/$/, "")}${path}`;

  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options?.headers || {}),
      },
      // Avoid stale cache during local dev
      cache: "no-store",
    });

    if (!res.ok) {
      let detail = `Server returned HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body?.detail) {
          detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
        }
      } catch {
        // fallback to default text
      }

      let guide = "Check server logs or verify your request parameters.";
      if (res.status === 404) {
        guide = "The requested resource was not found. Check endpoint route and run fixtures.";
      } else if (res.status === 429) {
        guide = "Rate limit reached. Wait a short while or inspect spend limits in config.";
      } else if (res.status >= 500) {
        guide = "Backend crashed or had an unhandled error. Inspect uvicorn terminal output.";
      }

      throw new ApiError(detail, res.status, guide);
    }

    return (await res.json()) as T;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const message = err instanceof Error ? err.message : String(err);
    throw new ApiError(
      `Cannot connect to Gauntlet API at ${url} (${message})`,
      0,
      "Ensure backend is running: run 'py -m uvicorn backend.api:app --port 8000' in another terminal."
    );
  }
}

export async function getRecordedSummary(): Promise<RecordedSummary> {
  return request<RecordedSummary>("/api/recorded/summary");
}

export interface GetRecordedAttacksParams {
  page?: number;
  limit?: number;
  channel?: string;
  condition?: "unhardened" | "v1" | "v2";
  outcome?: "defended" | "breach";
  is_probe?: boolean;
}

export async function getRecordedAttacks(
  params: GetRecordedAttacksParams = {}
): Promise<RecordedAttacksResponse> {
  const query = new URLSearchParams();
  if (params.page !== undefined) query.set("page", String(params.page));
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.channel) query.set("channel", params.channel);
  if (params.condition) query.set("condition", params.condition);
  if (params.outcome) query.set("outcome", params.outcome);
  if (params.is_probe !== undefined) query.set("is_probe", String(params.is_probe));

  const qs = query.toString();
  return request<RecordedAttacksResponse>(`/api/recorded/attacks${qs ? `?${qs}` : ""}`);
}

export async function getPolicy(version: "v1" | "v2" | string = "v2"): Promise<PolicyResponse> {
  return request<PolicyResponse>(`/api/policy/${version}`);
}

export async function getAttackTrace(
  id: string,
  condition: "unhardened" | "v1" | "v2" = "unhardened"
): Promise<AttackTraceResponse> {
  return request<AttackTraceResponse>(`/api/attacks/${encodeURIComponent(id)}/trace?condition=${condition}`);
}
