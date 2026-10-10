import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldCheck, Link2, Github, Play, CircleStop, FileCode2, FileJson,
  Zap, Download, ExternalLink, Printer, CheckCircle2, AlertTriangle, Loader2, Lock,
} from "lucide-react";
import { GradeRing, Gauge, SeverityChip } from "@/components/ScoreCard";
import { FindingsTable } from "@/components/FindingsTable";
import { FIXTURES } from "@/lib/fixtures";
import { runScan, SAFETY_RULES, findingsToMarkdown, type ScanOutcome, type ScanPhase, type ScanStats, type ScanMode, type FixerMode } from "@/lib/scanRunner";
import { COST_CONSTANTS, type FindingRow, type FileMeta } from "@/lib/policy";

const PHASES: Array<{ key: ScanPhase; label: string }> = [
  { key: "fetching", label: "Fetch target" },
  { key: "auditing", label: "Run auditors" },
  { key: "triaging", label: "Jev triage" },
  { key: "fixing", label: "Write fixes" },
  { key: "scoring", label: "Score" },
];

function detectMode(input: string): ScanMode {
  return /github\.com|^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(input.trim()) ? "repo" : "url";
}

export function Home() {
  const navigate = useNavigate();
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [liveMode, setLiveMode] = useState(true);
  const [mockFixer, setMockFixer] = useState(false);
  const [offlineReplay, setOfflineReplay] = useState(true);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [note, setNote] = useState("");
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [outcome, setOutcome] = useState<ScanOutcome | null>(null);
  const [error, setError] = useState("");

  const mode = detectMode(target);

  async function startScan(demoFixtureId?: string) {
    setError("");
    setOutcome(null);
    setPhase("fetching");
    setNote("Starting…");
    try {
      const result = await runScan({
        mode: demoFixtureId ? "url" : mode,
        target: demoFixtureId ? "" : target,
        consent,
        fixerMode: mockFixer ? "mock" : "llm",
        offlineReplay,
        demoFixtureId,
        onPhase: (p, n, s) => {
          setPhase(p);
          setNote(n);
          if (s) setStats(s);
        },
      });
      setOutcome(result);
      navigate(`/r/${result.scan.slug}`);
    } catch {
      /* error already surfaced via onPhase */
    }
  }

  const phaseIndex = PHASES.findIndex((p) => p.key === phase);
  const busy = !["idle", "done", "error"].includes(phase);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800/60">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            <span className="font-semibold tracking-tight">Vibe-Code Auditor</span>
          </div>
          <a
            href="#safety"
            className="inline-flex items-center gap-1.5 text-xs rounded-full px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors"
          >
            <Lock className="w-3.5 h-3.5" /> Read-only, passive scan
          </a>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 pb-20">
        <section className="pt-16 pb-10 text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
            Vibe-Code Auditor: <span className="text-emerald-400">ship fast, not leaky.</span>
          </h1>
          <p className="mt-4 text-slate-400 max-w-2xl mx-auto">
            Paste a deployed URL or a public GitHub repo. Deterministic auditors find issues, Jev triages each one
            by severity and false-positive odds, and an LLM writes the fixes. Rules find, Jev triages, code scores, the LLM writes fixes.
          </p>
        </section>

        <section className="max-w-3xl mx-auto">
          <div className="flex rounded-lg border border-slate-700 bg-slate-900 overflow-hidden focus-within:border-emerald-500/60 transition-colors">
            <div className="flex items-center pl-4 text-slate-500">
              {mode === "repo" ? <Github className="w-4 h-4" /> : <Link2 className="w-4 h-4" />}
            </div>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://your-app.com  ·  owner/repo"
              className="flex-1 bg-transparent px-3 py-3.5 text-sm outline-none placeholder:text-slate-600"
            />
            <span className="flex items-center pr-4 text-[11px] text-slate-500 uppercase tracking-wide">{mode} mode</span>
          </div>

          <label className="mt-3 flex items-start gap-2.5 text-sm text-slate-400 cursor-pointer select-none justify-center">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              className="mt-0.5 accent-emerald-500"
            />
            I own this app or have permission to audit it
          </label>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <button
              onClick={() => startScan()}
              disabled={!target.trim() || busy || (mode === "url" && !consent)}
              className="inline-flex items-center gap-2 rounded-lg px-6 py-2.5 text-sm font-semibold bg-emerald-500 text-slate-950 hover:bg-emerald-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run audit
            </button>
            {FIXTURES.map((fx) => (
              <button
                key={fx.id}
                onClick={() => startScan(fx.id)}
                disabled={busy}
                className="inline-flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm border border-slate-700 text-slate-300 hover:border-slate-500 hover:text-white transition-colors disabled:opacity-40"
              >
                <Zap className="w-4 h-4 text-amber-400" /> Load demo: {fx.name}
              </button>
            ))}
          </div>

          <div className="mt-5 flex flex-wrap items-center justify-center gap-2 text-xs">
            {[
              { label: "Live", on: liveMode, set: setLiveMode, desc: "live Jev triage" },
              { label: "Mock fixer", on: mockFixer, set: setMockFixer, desc: "static fix templates" },
              { label: "Offline replay", on: offlineReplay, set: setOfflineReplay, desc: "recorded Jev answers" },
            ].map((t) => (
              <button
                key={t.label}
                onClick={() => t.set(!t.on)}
                title={t.desc}
                className={`rounded-full px-3.5 py-1.5 border transition-colors ${t.on ? "bg-sky-500/15 text-sky-400 border-sky-500/40" : "bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300"}`}
              >
                {t.label}: {t.on ? "on" : "off"}
              </button>
            ))}
          </div>

          {error && (
            <div className="mt-6 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
            </div>
          )}
        </section>

        {phase !== "idle" && !outcome && (
          <section className="max-w-3xl mx-auto mt-10">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Scan progress</h2>
                {stats && (
                  <span className="text-xs text-slate-500">
                    {stats.files} files · {(stats.bytes / 1024).toFixed(0)} KB · {stats.requests}/{30} requests used
                  </span>
                )}
              </div>
              <div className="space-y-2.5">
                {PHASES.map((p, i) => {
                  const done = phaseIndex > i || phase === "done";
                  const active = phaseIndex === i;
                  return (
                    <div key={p.key} className="flex items-center gap-3">
                      {done ? <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        : active ? <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />
                        : <CircleStop className="w-4 h-4 text-slate-700" />}
                      <span className={`text-sm ${done ? "text-slate-300" : active ? "text-white" : "text-slate-600"}`}>{p.label}</span>
                      {active && note && <span className="text-xs text-slate-500 truncate">{note}</span>}
                    </div>
                  );
                })}
              </div>
              {phase === "error" && (
                <div className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">{note}</div>
              )}
            </div>
          </section>
        )}

        {outcome && (
          <>
            <section className="mt-12 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <div className="flex flex-col md:flex-row items-center gap-8">
                <GradeRing grade={outcome.scores.grade} overall={outcome.scores.overall} />
                <div className="flex-1 w-full">
                  <div className="flex items-center gap-3 mb-3">
                    <h2 className="text-lg font-semibold">Score card</h2>
                    <SeverityChip severity={0} />
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {outcome.scores.categories.map((c) => <Gauge key={c.auditor} label={c.auditor} score={c.score} />)}
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {([4, 3, 2, 1, 0] as const).map((s) => (
                      <span key={s} className="text-xs rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-slate-300">
                        {outcome.counts[s] || 0} × <SeverityChip severity={s} small />
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap items-center gap-3">
                <button
                  onClick={() => navigate(`/r/${outcome.scan.slug}`)}
                  className="inline-flex items-center gap-2 text-sm rounded-lg px-4 py-2 bg-slate-800 hover:bg-slate-700 transition-colors"
                >
                  <ExternalLink className="w-4 h-4" /> Open report page
                </button>
                <button
                  onClick={() => {
                    const blob = new Blob([findingsToMarkdownFromOutcome(outcome)], { type: "text/markdown" });
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = `${outcome.scan.slug}.md`;
                    a.click();
                  }}
                  className="inline-flex items-center gap-2 text-sm rounded-lg px-4 py-2 bg-slate-800 hover:bg-slate-700 transition-colors"
                >
                  <Download className="w-4 h-4" /> Export Markdown
                </button>
                <button
                  onClick={() => window.print()}
                  className="inline-flex items-center gap-2 text-sm rounded-lg px-4 py-2 bg-slate-800 hover:bg-slate-700 transition-colors"
                >
                  <Printer className="w-4 h-4" /> Print / PDF
                </button>
              </div>
            </section>

            <section className="mt-8">
              <h2 className="text-lg font-semibold mb-4">Findings</h2>
              <FindingsTable findings={outcome.findings} onChange={() => {}} />
            </section>

            <section className="mt-8">
              <h2 className="text-lg font-semibold mb-4">Fetched files</h2>
              <div className="overflow-x-auto rounded-xl border border-slate-800">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase tracking-wide text-slate-500 border-b border-slate-800 bg-slate-900/80">
                      <th className="px-4 py-2.5">Path</th>
                      <th className="px-4 py-2.5">Status</th>
                      <th className="px-4 py-2.5">Size</th>
                      <th className="px-4 py-2.5">Headers</th>
                    </tr>
                  </thead>
                  <tbody>
                    {outcome.fileMeta.map((f: FileMeta, i: number) => (
                      <tr key={i} className="border-b border-slate-800/60 last:border-0">
                        <td className="px-4 py-2.5 font-mono text-xs text-slate-300">
                          {f.path}
                          {f.secretBearing && (
                            <span className="ml-2 inline-flex items-center gap-1 text-[10px] text-red-400"><FileCode2 className="w-3 h-3" /> secret-bearing — body withheld</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={f.status >= 200 && f.status < 300 ? "text-emerald-400" : f.status === 0 ? "text-red-400" : "text-amber-400"}>
                            {f.status === 0 ? "err" : f.status}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-slate-400">{(f.size / 1024).toFixed(1)} KB{f.gzipSize != null && <span className="text-slate-600"> · gzip {(f.gzipSize / 1024).toFixed(1)} KB</span>}</td>
                        <td className="px-4 py-2.5 text-xs text-slate-500 max-w-[360px] truncate">{Object.entries(f.headers).slice(0, 3).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <h2 className="text-lg font-semibold mb-2">Triage economics</h2>
              <p className="text-sm text-slate-400">
                Jev triaged {outcome.findings.length} findings for <span className="text-emerald-400 font-semibold">${outcome.jevCostUsd.toFixed(5)}</span>
                {" "}(${COST_CONSTANTS.jevInputPerMillion}/1M input tokens, output free). An LLM doing the same triage would cost an estimated
                <span className="text-amber-400 font-semibold"> ${((outcome.findings.length * COST_CONSTANTS.llmTokensPerFinding * (COST_CONSTANTS.llmInputPerMillion + COST_CONSTANTS.llmOutputPerMillion)) / 1_000_000).toFixed(4)}</span>
                {" "}— edit these constants in the policy module.
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Jev mode: {outcome.jevMode === "live" ? "live" : outcome.jevMode === "replay" ? "recorded replay (offline)" : "fallback (not Jev)"} · fixer: {outcome.fixerMode === "mock" ? "mock templates" : "LLM"}
              </p>
            </section>
          </>
        )}

        <section id="safety" className="mt-14 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2"><ShieldCheck className="w-5 h-5 text-emerald-400" /> Safety &amp; scope</h2>
          <ul className="space-y-2 text-sm text-slate-400">
            {SAFETY_RULES.map((r, i) => (
              <li key={i} className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" /> {r}
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-slate-500">
            URL mode requires the consent checkbox. Demo fixtures run offline and need no consent.
          </p>
        </section>
      </main>
    </div>
  );
}

function findingsToMarkdownFromOutcome(outcome: ScanOutcome): string {
  const scan = {
    id: outcome.scan.id,
    slug: outcome.scan.slug,
    target: outcome.fileMeta[0]?.path || "demo",
    mode: "url",
    status: "done",
    file_meta: [],
    scores: outcome.scores,
    grade: outcome.scores.grade,
    counts: outcome.counts,
    jev_cost_usd: outcome.jevCostUsd,
    fixer_mode: outcome.fixerMode,
    created_at: new Date().toISOString(),
  };
  return findingsToMarkdown(scan as never, outcome.findings as FindingRow[]);
}
