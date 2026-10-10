import { supabase } from "./supabaseClient.ts";
import { FIXTURES, type FixtureFile } from "./fixtures.ts";
import {
  fallbackTriage,
  computePriority,
  computeScores,
  severityCounts,
  isLlmFixEligible,
  type FindingRow,
  type FileMeta,
  type RawFindingInput,
} from "./policy.ts";

export type ScanMode = "url" | "repo";
export type FixerMode = "llm" | "mock";
export type ScanPhase = "idle" | "fetching" | "auditing" | "triaging" | "fixing" | "scoring" | "done" | "error";

export interface ScanStats {
  files: number;
  bytes: number;
  requests: number;
  durationMs: number;
}

export interface ScanOutcome {
  scan: { slug: string; id: string };
  findings: FindingRow[];
  fileMeta: FileMeta[];
  stats: ScanStats;
  scores: ReturnType<typeof computeScores>;
  counts: Record<string, number>;
  jevCostUsd: number;
  jevMode: "live" | "fallback" | "replay";
  fixerMode: FixerMode;
}

export interface ScanOptions {
  mode: ScanMode;
  target: string;
  consent: boolean;
  fixerMode: FixerMode;
  offlineReplay: boolean;
  onPhase: (phase: ScanPhase, note: string, stats?: ScanStats) => void;
}

export const SAFETY_RULES = [
  "GET/HEAD requests only, for publicly served resources",
  "Max 30 requests, 2 MB per file, 6 MB total, 20 s timeout",
  "Never submits forms, logs in, guesses paths, or sends payloads",
  "Found secrets are masked (first 4 + last 4 chars) and hashed, never stored in full",
  "Blocks localhost, private IP ranges, cloud metadata IPs, and non-standard ports",
  "Redirects are followed manually (max 5) and re-checked at every hop",
];

function slugify(target: string): string {
  const cleaned = target
    .replace(/^https?:\/\//, "")
    .replace(/^github\.com\//, "")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase()
    .slice(0, 40);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${cleaned || "scan"}-${rand}`;
}

function invoke<T>(name: string, body: Record<string, unknown>): Promise<T> {
  return supabase.functions.invoke<T>(name, { body }).then((r) => {
    if (r.error) throw new Error(r.error.message || `Edge function ${name} failed`);
    return r.data as T;
  });
}

interface FetchedFilePayload {
  path: string;
  kind: string;
  status: number;
  size: number;
  gzipSize?: number | null;
  headers: Record<string, string>;
  text?: string;
  error?: string;
}

interface FetchResponse {
  mode: string;
  files: FetchedFilePayload[];
  file_meta: FileMeta[];
  requestsUsed: number;
  bytesTotal: number;
  durationMs: number;
}

interface AuditResponse {
  findings: AuditFinding[];
}

type AuditFinding = RawFindingInput & { evidence: string; context?: string };

interface TriageResponse {
  results: Array<{
    rule_id: string;
    triage?: {
      severity: number;
      severityConf: number;
      exploitability: string;
      exploitConf: number;
      placeholderP: number;
      fixRoute: string;
      fixRouteConf: number;
      model: string;
      latencyMs: number;
      usage: { input_tokens: number; output_tokens: number };
    };
    jev_request?: unknown;
    jev_response?: unknown;
    mode?: string;
  }>;
  mode: string;
  jev_cost_usd?: number;
}

interface FixResponse {
  fix?: { why_it_matters: string; fix_steps: string[]; patch: string; verify_steps: string[] };
  mode?: string;
  error?: string;
}

const STATIC_TIPS: Record<string, string> = {
  openai_key: "Rotate the key immediately and move it to a server-side environment variable.",
  anthropic_key: "Rotate the key immediately and move it to a server-side environment variable.",
  aws_key: "Deactivate the access key in IAM and rotate credentials.",
  stripe_live_key: "Roll the live secret key in the Stripe dashboard and keep it server-side.",
  rls_missing: "Enable Row Level Security on this table and add owner-scoped policies.",
  csp_missing: "Add a Content-Security-Policy header, starting in report-only mode.",
  perf_source_map_exposed: "Disable source maps in production builds or block *.map at the CDN.",
};

async function runLiveScan(opts: ScanOptions): Promise<ScanOutcome> {
  const fetchRes = await invoke<FetchResponse>("fetch-target", {
    mode: opts.mode,
    target: opts.target,
    consent: opts.consent,
  });
  if ((fetchRes.files || []).length === 0) throw new Error("Nothing could be fetched from that target");
  const pageFile = fetchRes.files.find((f) => f.kind === "page");
  if (pageFile && pageFile.error) throw new Error(pageFile.error);
  opts.onPhase("fetching", `${fetchRes.files.length} files, ${(fetchRes.bytesTotal / 1024).toFixed(0)} KB`, {
    files: fetchRes.files.length,
    bytes: fetchRes.bytesTotal,
    requests: fetchRes.requestsUsed,
    durationMs: fetchRes.durationMs,
  });

  const auditRes = await invoke<AuditResponse>("audit", { mode: fetchRes.mode, files: fetchRes.files });
  opts.onPhase("auditing", `${auditRes.findings.length} findings from 6 auditors`);

  const triageRes = await invoke<TriageResponse>("jev-triage", {
    findings: auditRes.findings.map((f) => ({
      auditor: f.auditor,
      rule_id: f.rule_id,
      title: f.title,
      location: f.location,
      evidence_masked: f.evidence,
      in_client_bundle: f.in_client_bundle === true,
    })),
    mode: fetchRes.mode,
  });
  opts.onPhase("triaging", triageRes.mode === "live" ? "Jev triaged every finding" : "Jev unreachable — fallback table used");

  const triageByRule = new Map<string, AuditResponse["findings"][number]>();
  for (const f of auditRes.findings) triageByRule.set(JSON.stringify([f.rule_id, f.location, f.evidence]), f);

  const rows: FindingRow[] = [];
  const fixCandidates: Array<{ index: number; finding: AuditFinding; ruleId: string }> = [];
  const jevCost = triageRes.jev_cost_usd ?? 0;

  auditRes.findings.forEach((f, i) => {
    const key = JSON.stringify([f.rule_id, f.location, f.evidence]);
    const tri = triageRes.results.find((r) => r.rule_id === f.rule_id && !!r.triage);
    const t = tri?.triage
      ? {
          ...tri.triage,
          severity: Math.max(0, Math.min(4, Math.round(tri.triage.severity))) as 0 | 1 | 2 | 3 | 4,
          placeholderP: tri.triage.placeholderP,
          priority: computePriority(tri.triage.severity, tri.triage.exploitability, tri.triage.placeholderP),
          llmFixEligible: isLlmFixEligible(tri.triage.fixRoute, tri.triage.fixRouteConf, tri.triage.severity, tri.triage.placeholderP),
          needsHumanReview: tri.triage.fixRouteConf < 0.6 || tri.triage.fixRoute === "uncertain",
        }
      : fallbackTriage({ auditor: f.auditor, rule_id: f.rule_id, title: f.title, location: f.location, evidence_masked: f.evidence });
    rows.push({
      id: `f${i}`,
      scan_id: "",
      auditor: f.auditor,
      rule_id: f.rule_id,
      title: f.title,
      location: f.location,
      evidence_masked: f.evidence,
      severity: t.severity as number,
      severity_conf: t.severityConf,
      exploitability: t.exploitability,
      exploit_conf: t.exploitConf,
      placeholder_p: t.placeholderP,
      priority: t.priority,
      fix_route: t.fixRoute,
      status: "open",
      jev_response: tri?.jev_response,
    });
    if (t.llmFixEligible) fixCandidates.push({ index: i, finding: f, ruleId: f.rule_id });
  });

  fixCandidates.sort((a, b) => (rows[b.index].priority ?? 0) - (rows[a.index].priority ?? 0));
  const top = fixCandidates.slice(0, 8);
  opts.onPhase("fixing", `${top.length} finding(s) routed to the fixer (top 8 by priority)`);

  const packageJson = fetchRes.files.find((f) => f.kind === "package")?.text;
  await Promise.all(
    top.map(async (c) => {
      try {
        const fixRes = await invoke<FixResponse>("write-fix", {
          finding: { rule_id: c.ruleId, title: c.finding.title, location: c.finding.location, evidence: c.finding.evidence },
          package_json: packageJson,
          mock: opts.fixerMode === "mock",
        });
        if (fixRes.fix) rows[c.index].fix = fixRes.fix;
        else if (c.ruleId in STATIC_TIPS) rows[c.index].fix = { why_it_matters: "", fix_steps: [STATIC_TIPS[c.ruleId]], patch: "", verify_steps: [] };
      } catch {
        if (c.ruleId in STATIC_TIPS) rows[c.index].fix = { why_it_matters: "", fix_steps: [STATIC_TIPS[c.ruleId]], patch: "", verify_steps: [] };
      }
    })
  );
  for (const row of rows) {
    if (!row.fix && row.fix_route === "quick_tip" && STATIC_TIPS[row.rule_id]) {
      row.fix = { why_it_matters: "", fix_steps: [STATIC_TIPS[row.rule_id]], patch: "", verify_steps: [] };
    }
    if (!row.fix && (row.fix_route === "uncertain" || (row.fix_route === "code_change" && (row.severity_conf ?? 1) < 0.6))) {
      row.fix = { why_it_matters: "", fix_steps: ["Needs human review — Jev was not confident enough to route this to the fixer."], patch: "", verify_steps: [] };
    }
  }

  opts.onPhase("scoring", "Computing category scores");
  const scores = computeScores(rows);
  const counts = severityCounts(rows);

  const slug = slugify(opts.target);
  const { data: scanRow, error: scanErr } = await supabase
    .from("scans")
    .insert({
      slug,
      target: opts.target,
      mode: opts.mode,
      status: "done",
      file_meta: fetchRes.file_meta,
      scores,
      grade: scores.grade,
      counts,
      jev_cost_usd: jevCost,
      fixer_mode: opts.fixerMode,
    })
    .select("id, slug")
    .single();
  if (scanErr) throw new Error(`Could not save the scan: ${scanErr.message}`);

  const toInsert = rows.map((r) => ({
    scan_id: scanRow.id,
    auditor: r.auditor,
    rule_id: r.rule_id,
    title: r.title,
    location: r.location,
    evidence_masked: r.evidence_masked,
    jev_response: r.jev_response ?? null,
    severity: r.severity,
    severity_conf: r.severity_conf,
    exploitability: r.exploitability,
    exploit_conf: r.exploit_conf,
    placeholder_p: r.placeholder_p,
    priority: r.priority,
    fix_route: r.fix_route,
    fix: r.fix ?? null,
    status: "open",
  }));
  const { data: inserted, error: findErr } = await supabase.from("findings").insert(toInsert).select();
  if (findErr) throw new Error(`Could not save findings: ${findErr.message}`);

  opts.onPhase("done", "Report ready");
  return {
    scan: { slug: scanRow.slug, id: scanRow.id },
    findings: (inserted || []).map((r: Record<string, unknown>, i: number) => ({ ...rows[i], id: r.id as string, scan_id: scanRow.id })),
    fileMeta: fetchRes.file_meta,
    stats: { files: fetchRes.files.length, bytes: fetchRes.bytesTotal, requests: fetchRes.requestsUsed, durationMs: fetchRes.durationMs },
    scores,
    counts,
    jevCostUsd: jevCost,
    jevMode: triageRes.mode === "live" ? "live" : "fallback",
    fixerMode: opts.fixerMode,
  };
}

async function runDemoScan(opts: ScanOptions, fixtureId: string): Promise<ScanOutcome> {
  const fixture = FIXTURES.find((f) => f.id === fixtureId);
  if (!fixture) throw new Error("Unknown demo fixture");
  const files: FetchedFilePayload[] = fixture.files;
  opts.onPhase("fetching", `${files.length} fixture files (offline)`, {
    files: files.length,
    bytes: files.reduce((s, f) => s + f.size, 0),
    requests: files.length,
    durationMs: 0,
  });

  const auditRes = await invoke<AuditResponse>("audit", { mode: fixture.mode, files });
  opts.onPhase("auditing", `${auditRes.findings.length} findings from 6 auditors`);

  let triageRes: TriageResponse | null = null;
  let jevMode: ScanOutcome["jevMode"] = "replay";
  if (opts.offlineReplay) {
    opts.onPhase("triaging", "Recorded Jev responses replayed (offline)");
  } else {
    try {
      triageRes = await invoke<TriageResponse>("jev-triage", {
        findings: auditRes.findings.map((f) => ({
          auditor: f.auditor,
          rule_id: f.rule_id,
          title: f.title,
          location: f.location,
          evidence_masked: f.evidence,
          in_client_bundle: f.in_client_bundle === true,
        })),
        mode: fixture.mode,
      });
      jevMode = triageRes.mode === "live" ? "live" : "fallback";
      opts.onPhase("triaging", jevMode === "live" ? "Jev triaged every finding" : "Jev unreachable — fallback table used");
    } catch {
      opts.onPhase("triaging", "Jev unreachable — fallback table used");
    }
  }

  const rows: FindingRow[] = [];
  const fixCandidates: Array<{ index: number; finding: AuditFinding; ruleId: string }> = [];
  const jevCost = triageRes?.jev_cost_usd ?? 0;

  auditRes.findings.forEach((f, i) => {
    const tri = triageRes?.results.find((r) => r.rule_id === f.rule_id && !!r.triage)?.triage;
    const t = tri
      ? {
          ...tri,
          severity: Math.max(0, Math.min(4, Math.round(tri.severity))) as 0 | 1 | 2 | 3 | 4,
          placeholderP: tri.placeholderP,
          priority: computePriority(tri.severity, tri.exploitability, tri.placeholderP),
          llmFixEligible: isLlmFixEligible(tri.fixRoute, tri.fixRouteConf, tri.severity, tri.placeholderP),
          needsHumanReview: tri.fixRouteConf < 0.6 || tri.fixRoute === "uncertain",
        }
      : fallbackTriage({ auditor: f.auditor, rule_id: f.rule_id, title: f.title, location: f.location, evidence_masked: f.evidence });
    rows.push({
      id: `f${i}`,
      scan_id: "",
      auditor: f.auditor,
      rule_id: f.rule_id,
      title: f.title,
      location: f.location,
      evidence_masked: f.evidence,
      severity: t.severity as number,
      severity_conf: t.severityConf,
      exploitability: t.exploitability,
      exploit_conf: t.exploitConf,
      placeholder_p: t.placeholderP,
      priority: t.priority,
      fix_route: t.fixRoute,
      status: "open",
    });
    if (t.llmFixEligible) fixCandidates.push({ index: i, finding: f, ruleId: f.rule_id });
  });

  fixCandidates.sort((a, b) => (rows[b.index].priority ?? 0) - (rows[a.index].priority ?? 0));
  const top = fixCandidates.slice(0, 8);
  opts.onPhase("fixing", `${top.length} finding(s) routed to the fixer (top 8 by priority)`);

  const packageJson = files.find((f) => f.kind === "package")?.text;
  await Promise.all(
    top.map(async (c) => {
      try {
        const fixRes = await invoke<FixResponse>("write-fix", {
          finding: { rule_id: c.ruleId, title: c.finding.title, location: c.finding.location, evidence: c.finding.evidence },
          package_json: packageJson,
          mock: opts.fixerMode === "mock",
        });
        if (fixRes.fix) rows[c.index].fix = fixRes.fix;
      } catch { /* keep default */ }
    })
  );

  opts.onPhase("scoring", "Computing category scores");
  const scores = computeScores(rows);
  const counts = severityCounts(rows);

  const slug = slugify(fixture.name);
  const { data: scanRow, error: scanErr } = await supabase
    .from("scans")
    .insert({
      slug,
      target: fixture.target,
      mode: "demo",
      status: "done",
      file_meta: fixture.files.map((f: FixtureFile) => ({
        path: f.path,
        kind: f.kind,
        status: f.status,
        size: f.size,
        gzipSize: f.gzipSize ?? null,
        headers: f.headers,
        error: null,
        secretBearing: false,
      })),
      scores,
      grade: scores.grade,
      counts,
      jev_cost_usd: jevCost,
      fixer_mode: opts.fixerMode,
    })
    .select("id, slug")
    .single();
  if (scanErr) throw new Error(`Could not save the scan: ${scanErr.message}`);

  const { data: inserted, error: findErr } = await supabase
    .from("findings")
    .insert(
      rows.map((r) => ({
        scan_id: scanRow.id,
        auditor: r.auditor,
        rule_id: r.rule_id,
        title: r.title,
        location: r.location,
        evidence_masked: r.evidence_masked,
        severity: r.severity,
        severity_conf: r.severity_conf,
        exploitability: r.exploitability,
        exploit_conf: r.exploit_conf,
        placeholder_p: r.placeholder_p,
        priority: r.priority,
        fix_route: r.fix_route,
        fix: r.fix ?? null,
        status: "open",
      }))
    )
    .select();
  if (findErr) throw new Error(`Could not save findings: ${findErr.message}`);

  opts.onPhase("done", "Report ready");
  return {
    scan: { slug: scanRow.slug, id: scanRow.id },
    findings: (inserted || []).map((r: Record<string, unknown>, i: number) => ({ ...rows[i], id: r.id as string, scan_id: scanRow.id })),
    fileMeta: (fixture.files as FixtureFile[]).map((f) => ({
      path: f.path,
      kind: f.kind,
      status: f.status,
      size: f.size,
      gzipSize: f.gzipSize ?? null,
      headers: f.headers,
      error: null,
      secretBearing: false,
    })),
    stats: { files: files.length, bytes: files.reduce((s, f) => s + f.size, 0), requests: files.length, durationMs: 0 },
    scores,
    counts,
    jevCostUsd: jevCost,
    jevMode,
    fixerMode: opts.fixerMode,
  };
}

export async function runScan(opts: ScanOptions & { demoFixtureId?: string }): Promise<ScanOutcome> {
  try {
    if (opts.demoFixtureId) return await runDemoScan(opts, opts.demoFixtureId);
    return await runLiveScan(opts);
  } catch (e) {
    opts.onPhase("error", (e as Error).message);
    throw e;
  }
}

export async function ignoreFinding(findingId: string, ignored: boolean): Promise<void> {
  const { data, error } = await supabase.functions.invoke("update-finding", {
    body: { finding_id: findingId, status: ignored ? "ignored" : "open" },
  });
  if (error) throw new Error(error.message || "Could not update finding");
  if (data?.error) throw new Error(data.error);
}

export async function loadReport(slug: string): Promise<{ scan: ScanRowOf; findings: FindingRow[] } | null> {
  const { data: scan, error } = await supabase.from("scans").select("*").eq("slug", slug).maybeSingle();
  if (error || !scan) return null;
  const { data: findings } = await supabase.from("findings").select("*").eq("scan_id", scan.id).order("priority", { ascending: false });
  return { scan: scan as ScanRowOf, findings: (findings || []) as FindingRow[] };
}

type ScanRowOf = {
  id: string;
  slug: string;
  target: string;
  mode: string;
  status: string;
  file_meta: FileMeta[];
  scores: ReturnType<typeof computeScores>;
  grade: string;
  counts: Record<string, number>;
  jev_cost_usd: number;
  fixer_mode: string;
  created_at: string;
};

export function findingsToMarkdown(scan: ScanRowOf, findings: FindingRow[]): string {
  const lines: string[] = [];
  lines.push(`# Vibe-Code Auditor report — ${scan.target}`);
  lines.push("");
  lines.push(`Grade **${scan.grade}** (overall ${scan.scores.overall}/100) · ${scan.mode} mode · ${new Date(scan.created_at).toLocaleString()}`);
  lines.push("");
  lines.push("| Category | Score |");
  lines.push("|---|---|");
  for (const c of scan.scores.categories) lines.push(`| ${c.auditor} | ${c.score} |`);
  lines.push("");
  lines.push(`**Findings (${findings.length})**`);
  lines.push("");
  for (const f of findings) {
    lines.push(`## [${f.severity}] ${f.title}`);
    lines.push(`- Auditor: ${f.auditor} (${f.rule_id})`);
    lines.push(`- Location: ${f.location || "n/a"}`);
    lines.push(`- Evidence: \`${f.evidence_masked || "n/a"}\``);
    lines.push(`- Jev: severity ${f.severity} (conf ${f.severity_conf}), exploitability ${f.exploitability} (${f.exploit_conf}), placeholder ${(f.placeholder_p * 100).toFixed(0)}%, priority ${f.priority.toFixed(2)}`);
    if (f.fix?.fix_steps?.length) {
      lines.push("- Fix steps:");
      for (const s of f.fix.fix_steps) lines.push(`  1. ${s}`);
    }
    if (f.fix?.patch) {
      lines.push("- Patch:");
      lines.push("  ```");
      lines.push(`  ${f.fix.patch}`);
      lines.push("  ```");
    }
    lines.push("");
  }
  return lines.join("\n");
}
