import { SEVERITY_COLORS, type Severity } from "@/lib/policy";

export function GradeRing({ grade, overall }: { grade: string; overall: number }) {
  const angle = Math.round((overall / 100) * 360);
  const color = overall >= 90 ? "#10b981" : overall >= 80 ? "#3b82f6" : overall >= 70 ? "#f59e0b" : overall >= 60 ? "#f97316" : "#dc2626";
  return (
    <div className="relative w-40 h-40 shrink-0">
      <div
        className="w-full h-full rounded-full"
        style={{ background: `conic-gradient(${color} ${angle}deg, #1e293b ${angle}deg)` }}
      />
      <div className="absolute inset-[10px] rounded-full bg-slate-900 flex flex-col items-center justify-center">
        <span className="text-5xl font-bold" style={{ color }}>{grade}</span>
        <span className="text-xs text-slate-400 mt-1">{overall}/100</span>
      </div>
    </div>
  );
}

export function SeverityChip({ severity, small }: { severity: number; small?: boolean }) {
  const labels = ["Info", "Low", "Medium", "High", "Critical"];
  const sev = Math.max(0, Math.min(4, Math.round(severity))) as Severity;
  return (
    <span
      className={`inline-flex items-center rounded-full font-semibold ${small ? "text-[10px] px-2 py-0.5" : "text-xs px-2.5 py-1"}`}
      style={{ backgroundColor: `${SEVERITY_COLORS[sev]}22`, color: SEVERITY_COLORS[sev], border: `1px solid ${SEVERITY_COLORS[sev]}55` }}
    >
      {labels[sev]}
    </span>
  );
}

export function ProbabilityBar({ value, color }: { value: number; color: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

export function Gauge({ label, score }: { label: string; score: number }) {
  const color = score >= 90 ? "#10b981" : score >= 70 ? "#f59e0b" : score >= 50 ? "#f97316" : "#dc2626";
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-baseline justify-between mb-2">
        <span className="text-xs text-slate-400">{label}</span>
        <span className="text-lg font-bold" style={{ color }}>{score}</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${score}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
