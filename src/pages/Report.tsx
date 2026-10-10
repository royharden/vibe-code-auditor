import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ShieldCheck, Download, Printer, ArrowLeft, FileJson } from "lucide-react";
import { GradeRing, Gauge } from "@/components/ScoreCard";
import { FindingsTable } from "@/components/FindingsTable";
import { loadReport, findingsToMarkdown } from "@/lib/scanRunner";
import type { FindingRow } from "@/lib/policy";

interface ReportScan {
  id: string;
  slug: string;
  target: string;
  mode: string;
  status: string;
  file_meta: Array<{ path: string; kind: string; status: number; size: number; gzipSize: number | null; headers: Record<string, string>; error: string | null; secretBearing?: boolean }>;
  scores: { categories: Array<{ auditor: string; score: number }>; overall: number; grade: string };
  grade: string;
  counts: Record<string, number>;
  jev_cost_usd: number;
  fixer_mode: string;
  created_at: string;
}

export function Report() {
  const { slug } = useParams<{ slug: string }>();
  const [scan, setScan] = useState<ReportScan | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadReport(slug || "").then((r) => {
      if (r) {
        setScan(r.scan as unknown as ReportScan);
        setFindings(r.findings);
      }
      setLoading(false);
    });
  }, [slug]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
        <p className="text-slate-500">Loading report…</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center gap-4">
        <p className="text-slate-400">Report not found.</p>
        <Link to="/" className="text-emerald-400 hover:text-emerald-300 text-sm">← Back to the auditor</Link>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800/60 print:border-slate-300">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            <span className="font-semibold tracking-tight">Vibe-Code Auditor</span>
          </Link>
          <div className="flex items-center gap-2 print:hidden">
            <button
              onClick={() => {
                const blob = new Blob([findingsToMarkdown(scan as never, findings)], { type: "text/markdown" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `${scan.slug}.md`;
                a.click();
              }}
              className="inline-flex items-center gap-1.5 text-xs rounded-lg px-3 py-2 bg-slate-800 hover:bg-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Markdown
            </button>
            <button
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 text-xs rounded-lg px-3 py-2 bg-slate-800 hover:bg-slate-700 transition-colors"
            >
              <Printer className="w-3.5 h-3.5" /> Print / PDF
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-10">
        <Link to="/" className="text-xs text-slate-500 hover:text-slate-300 print:hidden"><ArrowLeft className="w-3 h-3 inline mr-1" />Back</Link>

        <div className="mt-4 flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">Read-only report · {scan.mode} mode</p>
            <h1 className="text-2xl font-bold mt-1 break-all">{scan.target}</h1>
            <p className="text-sm text-slate-500 mt-1">Scanned {new Date(scan.created_at).toLocaleString()} · slug /r/{scan.slug}</p>
          </div>
          <div className="flex gap-4 text-sm">
            <span className="rounded-md bg-slate-900 border border-slate-800 px-3 py-2">Jev cost: ${scan.jev_cost_usd?.toFixed(5) ?? "0"}</span>
            <span className="rounded-md bg-slate-900 border border-slate-800 px-3 py-2">Fixer: {scan.fixer_mode}</span>
          </div>
        </div>

        <section className="mt-8 rounded-xl border border-slate-800 bg-slate-900/60 p-6 print:bg-white print:border-slate-300">
          <div className="flex flex-col md:flex-row items-center gap-8">
            <GradeRing grade={scan.grade} overall={scan.scores.overall} />
            <div className="flex-1 w-full">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {scan.scores.categories.map((c) => <Gauge key={c.auditor} label={c.auditor} score={c.score} />)}
              </div>
            </div>
          </div>
        </section>

        <section className="mt-8">
          <h2 className="text-lg font-semibold mb-4">Findings</h2>
          <FindingsTable findings={findings} onChange={() => loadReport(slug || "").then((r) => r && setFindings(r.findings))} />
        </section>

        <section className="mt-8">
          <h2 className="text-lg font-semibold mb-4">Fetched files</h2>
          <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-slate-300">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-slate-500 border-b border-slate-800 bg-slate-900/80 print:bg-slate-100">
                  <th className="px-4 py-2.5">Path</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Size</th>
                  <th className="px-4 py-2.5">Headers</th>
                </tr>
              </thead>
              <tbody>
                {scan.file_meta.map((f, i) => (
                  <tr key={i} className="border-b border-slate-800/60 last:border-0">
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-300 break-all">
                      {f.path}
                      {f.secretBearing && <span className="ml-2 text-[10px] text-red-400 inline-flex items-center gap-1"><FileJson className="w-3 h-3" /> secret-bearing — body withheld</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={f.status >= 200 && f.status < 300 ? "text-emerald-400" : f.status === 0 ? "text-red-400" : "text-amber-400"}>{f.status === 0 ? "err" : f.status}</span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">{(f.size / 1024).toFixed(1)} KB{f.gzipSize != null && <span className="text-slate-600"> · gzip {(f.gzipSize / 1024).toFixed(1)} KB</span>}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-500 max-w-[360px] truncate">{Object.entries(f.headers || {}).slice(0, 3).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}
