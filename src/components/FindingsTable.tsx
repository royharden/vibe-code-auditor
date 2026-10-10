import { useMemo, useState } from "react";
import { ChevronDown, ChevronUp, Copy, EyeOff, RotateCcw } from "lucide-react";
import { SeverityChip, ProbabilityBar } from "./ScoreCard";
import { SEVERITY_COLORS, type FindingRow } from "@/lib/policy";
import { ignoreFinding } from "@/lib/scanRunner";

const EXPLOIT_LABELS: Record<string, string> = {
  anyone_remote: "Anyone, remotely",
  needs_user_action: "Needs user action",
  needs_account: "Needs an account",
  not_exploitable: "Not exploitable",
  uncertain: "Uncertain",
};

const FIX_ROUTE_LABELS: Record<string, string> = {
  code_change: "Code change",
  quick_tip: "Quick tip",
  no_fix: "Nothing to fix",
  uncertain: "Uncertain",
};

export function FindingsTable({ findings, onChange }: { findings: FindingRow[]; onChange: () => void }) {
  const [auditorFilter, setAuditorFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const auditors = useMemo(() => Array.from(new Set(findings.map((f) => f.auditor))), [findings]);
  const visible = useMemo(() => {
    return findings
      .filter((f) => (auditorFilter === "all" || f.auditor === auditorFilter))
      .filter((f) => (severityFilter === "all" || String(Math.round(f.severity)) === severityFilter))
      .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  }, [findings, auditorFilter, severityFilter]);

  async function toggleIgnore(f: FindingRow) {
    setBusy(f.id);
    try {
      await ignoreFinding(f.id, f.status !== "ignored");
      onChange();
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap gap-3 mb-4">
        <select
          value={auditorFilter}
          onChange={(e) => setAuditorFilter(e.target.value)}
          className="rounded-md bg-slate-900 border border-slate-700 text-sm text-slate-200 px-3 py-1.5"
        >
          <option value="all">All auditors</option>
          {auditors.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-md bg-slate-900 border border-slate-700 text-sm text-slate-200 px-3 py-1.5"
        >
          <option value="all">All severities</option>
          <option value="4">Critical</option>
          <option value="3">High</option>
          <option value="2">Medium</option>
          <option value="1">Low</option>
          <option value="0">Info</option>
        </select>
        <span className="text-sm text-slate-500 self-center">{visible.filter((f) => f.status === "open").length} open · sorted by priority</span>
      </div>

      <div className="space-y-2">
        {visible.map((f) => {
          const isOpen = expanded === f.id;
          const ignored = f.status === "ignored";
          return (
            <div
              key={f.id}
              className={`rounded-lg border transition-colors ${ignored ? "border-slate-800 bg-slate-900/30 opacity-60" : "border-slate-800 bg-slate-900/70 hover:border-slate-600"}`}
            >
              <button
                className="w-full text-left px-4 py-3 flex items-start gap-3"
                onClick={() => setExpanded(isOpen ? null : f.id)}
              >
                <div className="flex flex-col items-center gap-1 min-w-[72px]">
                  <SeverityChip severity={f.severity} />
                  <span className="text-[10px] text-slate-500">prio {f.priority?.toFixed(2)}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-sm font-medium ${ignored ? "line-through" : ""} text-slate-100`}>{f.title}</span>
                    {f.fix_route === "uncertain" && (
                      <span className="text-[10px] rounded px-1.5 py-0.5 bg-amber-500/15 text-amber-400 border border-amber-500/30">needs human review</span>
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-xs text-slate-500 flex-wrap">
                    <span>{f.auditor}</span>
                    {f.location && <span className="truncate max-w-[280px] font-mono">{f.location}</span>}
                    <span>{EXPLOIT_LABELS[f.exploitability] || f.exploitability}</span>
                    <span>placeholder {(f.placeholder_p * 100).toFixed(0)}%</span>
                  </div>
                  {f.evidence_masked && (
                    <code className="mt-1.5 block text-[11px] font-mono text-slate-400 bg-slate-950/70 rounded px-2 py-1 truncate">
                      {f.evidence_masked}
                    </code>
                  )}
                  <div className="mt-2 grid grid-cols-3 gap-3 max-w-md">
                    <div>
                      <div className="flex justify-between text-[10px] text-slate-500 mb-0.5"><span>severity conf</span><span>{(f.severity_conf * 100).toFixed(0)}%</span></div>
                      <ProbabilityBar value={f.severity_conf} color={SEVERITY_COLORS[Math.round(f.severity) as 0 | 1 | 2 | 3 | 4]} />
                    </div>
                    <div>
                      <div className="flex justify-between text-[10px] text-slate-500 mb-0.5"><span>exploit conf</span><span>{(f.exploit_conf * 100).toFixed(0)}%</span></div>
                      <ProbabilityBar value={f.exploit_conf} color="#38bdf8" />
                    </div>
                    <div>
                      <div className="flex justify-between text-[10px] text-slate-500 mb-0.5"><span>placeholder p</span><span>{(f.placeholder_p * 100).toFixed(0)}%</span></div>
                      <ProbabilityBar value={f.placeholder_p} color="#a78bfa" />
                    </div>
                  </div>
                </div>
                {isOpen ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0 mt-1" /> : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0 mt-1" />}
              </button>

              {isOpen && (
                <div className="px-4 pb-4 pt-1 border-t border-slate-800/70">
                  {f.fix && (f.fix.fix_steps?.length > 0 || f.fix.patch) ? (
                    <div className="space-y-3">
                      {f.fix.why_it_matters && (
                        <p className="text-sm text-slate-300">{f.fix.why_it_matters}</p>
                      )}
                      {f.fix.fix_steps?.length > 0 && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Fix steps</h4>
                            <CopyButton text={f.fix.fix_steps.map((s, i) => `${i + 1}. ${s}`).join("\n")} />
                          </div>
                          <ol className="list-decimal list-inside text-sm text-slate-300 space-y-1">
                            {f.fix.fix_steps.map((s, i) => <li key={i}>{s}</li>)}
                          </ol>
                        </div>
                      )}
                      {f.fix.patch && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Patch</h4>
                            <CopyButton text={f.fix.patch} />
                          </div>
                          <pre className="text-xs font-mono bg-slate-950 rounded-md p-3 overflow-x-auto text-emerald-300 whitespace-pre-wrap">{f.fix.patch}</pre>
                        </div>
                      )}
                      {f.fix.verify_steps?.length > 0 && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Verify</h4>
                            <CopyButton text={f.fix.verify_steps.map((s, i) => `${i + 1}. ${s}`).join("\n")} />
                          </div>
                          <ol className="list-decimal list-inside text-sm text-slate-400 space-y-1">
                            {f.fix.verify_steps.map((s, i) => <li key={i}>{s}</li>)}
                          </ol>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-500">
                      {f.fix_route === "no_fix"
                        ? "Nothing to fix — this is informational."
                        : "No automated fix for this finding. See the tip in the row details."}
                    </p>
                  )}
                  <div className="mt-3 flex items-center gap-2">
                    <button
                      onClick={() => toggleIgnore(f)}
                      disabled={busy === f.id}
                      className="inline-flex items-center gap-1.5 text-xs rounded-md px-2.5 py-1.5 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
                    >
                      {ignored ? <><RotateCcw className="w-3.5 h-3.5" /> Restore</> : <><EyeOff className="w-3.5 h-3.5" /> Ignore</>}
                    </button>
                    {f.fix_route && (
                      <span className="text-xs text-slate-600">routed: {FIX_ROUTE_LABELS[f.fix_route] || f.fix_route}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
        {visible.length === 0 && (
          <p className="text-sm text-slate-500 py-6 text-center">No findings match the current filters.</p>
        )}
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 transition-colors"
    >
      <Copy className="w-3 h-3" /> {copied ? "Copied" : "Copy"}
    </button>
  );
}
