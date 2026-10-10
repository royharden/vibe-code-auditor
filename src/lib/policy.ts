export type Severity = 0 | 1 | 2 | 3 | 4;

export const SEVERITY_LABELS = ["Info", "Low", "Medium", "High", "Critical"] as const;

export const SEVERITY_COLORS: Record<Severity, string> = {
  0: "#64748b",
  1: "#3b82f6",
  2: "#f59e0b",
  3: "#f97316",
  4: "#dc2626",
};

export const SEVERITY_PENALTIES: Record<Severity, number> = { 0: 0, 1: 3, 2: 8, 3: 20, 4: 40 };

export const EXPLOIT_WEIGHTS: Record<string, number> = {
  anyone_remote: 1.0,
  needs_user_action: 0.7,
  needs_account: 0.5,
  not_exploitable: 0.1,
  uncertain: 0.6,
};

export const AUDITORS = ["Secrets", "Headers", "Auth & RLS", "Accessibility", "SEO", "Performance"] as const;
export type AuditorName = (typeof AUDITORS)[number];

export interface JevUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface Triage {
  severity: Severity;
  severityConf: number;
  exploitability: string;
  exploitConf: number;
  placeholderP: number;
  fixRoute: string;
  fixRouteConf: number;
  model: string;
  latencyMs: number;
  usage: JevUsage;
  priority: number;
  llmFixEligible: boolean;
  needsHumanReview: boolean;
}

export interface FindingRow {
  id: string;
  scan_id: string;
  auditor: string;
  rule_id: string;
  title: string;
  location: string;
  evidence_masked: string;
  jev_request?: unknown;
  jev_response?: unknown;
  severity: number;
  severity_conf: number;
  exploitability: string;
  exploit_conf: number;
  placeholder_p: number;
  priority: number;
  fix_route: string | null;
  fix?: { why_it_matters: string; fix_steps: string[]; patch: string; verify_steps: string[] } | null;
  status: "open" | "ignored";
}

export interface FileMeta {
  path: string;
  kind: string;
  status: number;
  size: number;
  gzipSize: number | null;
  headers: Record<string, string>;
  error: string | null;
  secretBearing: boolean;
}

export interface ScanRow {
  id: string;
  slug: string;
  target: string;
  mode: string;
  status: string;
  file_meta: FileMeta[];
  scores: { categories: Array<{ auditor: string; score: number }>; overall: number; grade: string };
  grade: string;
  counts: Record<string, number>;
  jev_cost_usd: number;
  fixer_mode: string;
  created_at: string;
}

export interface FixPayload {
  why_it_matters: string;
  fix_steps: string[];
  patch: string;
  verify_steps: string[];
}

export const COST_CONSTANTS = {
  jevInputPerMillion: 0.042,
  llmInputPerMillion: 2.5,
  llmOutputPerMillion: 10,
  llmTokensPerFinding: 1200,
};

export function computePriority(severity: number, exploitability: string, placeholderP: number): number {
  const sev = Math.max(0, Math.min(4, Math.round(severity)));
  const w = EXPLOIT_WEIGHTS[exploitability] ?? 0.6;
  return sev * w * (1 - Math.max(0, Math.min(1, placeholderP)));
}

export function isLlmFixEligible(fixRoute: string, conf: number, severity: number, placeholderP: number): boolean {
  return fixRoute === "code_change" && conf >= 0.6 && severity >= 2 && placeholderP < 0.5;
}

export function gradeFor(overall: number): string {
  if (overall >= 90) return "A";
  if (overall >= 80) return "B";
  if (overall >= 70) return "C";
  if (overall >= 60) return "D";
  return "F";
}

export function computeScores(findings: Array<{ auditor: string; severity: number; placeholder_p: number }>): ScanRow["scores"] {
  const categories = AUDITORS.map((auditor) => {
    const rows = findings.filter((f) => f.auditor === auditor);
    const penalty = rows.reduce((sum, f) => {
      const sev = Math.max(0, Math.min(4, Math.round(f.severity))) as Severity;
      return sum + SEVERITY_PENALTIES[sev] * (1 - Math.max(0, Math.min(1, f.placeholder_p)));
    }, 0);
    return { auditor, score: Math.max(0, Math.min(100, Math.round(100 - penalty))) };
  });
  const overall = Math.round(categories.reduce((s, c) => s + c.score, 0) / categories.length);
  return { categories, overall, grade: gradeFor(overall) };
}

export function severityCounts(findings: Array<{ severity: number }>): Record<string, number> {
  const counts: Record<string, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
  for (const f of findings) {
    const sev = Math.max(0, Math.min(4, Math.round(f.severity))).toString();
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return counts;
}

export function estimateLlmTriageCost(findingCount: number): number {
  const t = findingCount * COST_CONSTANTS.llmTokensPerFinding;
  return (t / 1_000_000) * (COST_CONSTANTS.llmInputPerMillion + COST_CONSTANTS.llmOutputPerMillion / 5);
}

const FALLBACK_SEVERITY: Record<string, { severity: Severity; exploitability: string; fixRoute: string }> = {
  openai_key: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  anthropic_key: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  aws_key: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  stripe_live_key: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  github_token: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  google_api_key: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  slack_token: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  private_key: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  service_role_jwt: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  high_entropy_secret: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  committed_env_file: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  public_secret_var: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  csp_missing: { severity: 2, exploitability: "needs_user_action", fixRoute: "code_change" },
  csp_unsafe_inline: { severity: 2, exploitability: "needs_user_action", fixRoute: "code_change" },
  hsts_missing: { severity: 1, exploitability: "needs_user_action", fixRoute: "quick_tip" },
  xcto_missing: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  frame_ancestors_missing: { severity: 2, exploitability: "needs_user_action", fixRoute: "code_change" },
  referrer_policy_missing: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  permissions_policy_missing: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  cookie_flags: { severity: 2, exploitability: "needs_account", fixRoute: "code_change" },
  cors_wildcard: { severity: 1, exploitability: "uncertain", fixRoute: "quick_tip" },
  version_leak: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  rls_missing: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  rls_using_true_update: { severity: 3, exploitability: "needs_account", fixRoute: "code_change" },
  rls_using_true_delete: { severity: 3, exploitability: "needs_account", fixRoute: "code_change" },
  service_key_in_client: { severity: 4, exploitability: "anyone_remote", fixRoute: "code_change" },
  firebase_rules_open: { severity: 3, exploitability: "anyone_remote", fixRoute: "code_change" },
  admin_check_client_only: { severity: 3, exploitability: "needs_account", fixRoute: "code_change" },
  anon_key_public: { severity: 0, exploitability: "not_exploitable", fixRoute: "no_fix" },
  a11y_lang_missing: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  a11y_title_missing: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  a11y_img_no_alt: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  a11y_input_no_label: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  a11y_button_no_name: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  a11y_heading_skip: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  a11y_zoom_disabled: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  seo_title: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  seo_description: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  seo_canonical_missing: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  seo_og_missing: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  seo_noindex: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  seo_sitemap_missing: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  seo_h1_count: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  seo_empty_shell: { severity: 2, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  perf_js_size: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  perf_no_compression: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  perf_cache_control: { severity: 1, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  perf_blocking_script: { severity: 1, exploitability: "not_exploitable", fixRoute: "code_change" },
  perf_img_no_dimensions: { severity: 0, exploitability: "not_exploitable", fixRoute: "quick_tip" },
  perf_source_map_exposed: { severity: 2, exploitability: "anyone_remote", fixRoute: "code_change" },
};

export interface RawFindingInput {
  auditor: string;
  rule_id: string;
  title: string;
  location: string;
  evidence_masked: string;
  in_client_bundle?: boolean;
}

export function fallbackTriage(f: RawFindingInput): Triage {
  const fb = FALLBACK_SEVERITY[f.rule_id] ?? { severity: 1 as Severity, exploitability: "uncertain", fixRoute: "uncertain" };
  return {
    severity: fb.severity,
    severityConf: 0.3,
    exploitability: fb.exploitability,
    exploitConf: 0.3,
    placeholderP: 0,
    fixRoute: fb.fixRoute,
    fixRouteConf: 0.3,
    model: "Fallback (not Jev)",
    latencyMs: 0,
    usage: { input_tokens: 0, output_tokens: 0 },
    priority: computePriority(fb.severity, fb.exploitability, 0),
    llmFixEligible: fb.fixRoute === "code_change" && fb.severity >= 2,
    needsHumanReview: false,
  };
}
