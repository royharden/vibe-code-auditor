import type { FetchedFile } from "../fetch-target.ts";
import type { Finding } from "./secrets.ts";

export function auditPerformance(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  if (mode !== "url") return out;
  const page = files.find((f) => f.kind === "page");
  const html = page?.text || "";
  const add = (rule_id: string, title: string, evidence: string, context?: string) =>
    out.push({ auditor: "Performance", rule_id, title, location: page?.path || "", evidence, mode, context });

  const jsFiles = files.filter((f) => (f.kind === "asset" || f.kind === "cdn") && /\.(js|mjs)(\?|$)/i.test(f.path));
  const totalJs = jsFiles.reduce((s, f) => s + f.size, 0);
  if (totalJs > 500_000) {
    add("perf_js_size", `Total JavaScript is ${(totalJs / 1024).toFixed(0)} KB`, jsFiles.map((f) => `${f.path.split("/").pop()} ${(f.size / 1024).toFixed(0)}KB`).join(", "));
  }
  const largest = jsFiles.sort((a, b) => b.size - a.size)[0];
  if (largest && largest.size > 300_000) {
    add("perf_js_size", `Largest JS file is ${(largest.size / 1024).toFixed(0)} KB`, largest.path);
  }

  for (const f of jsFiles) {
    const enc = (f.headers["content-encoding"] || "").toLowerCase();
    if (!enc && f.size > 50_000) {
      out.push({
        auditor: "Performance",
        rule_id: "perf_no_compression",
        title: "No compression on a large JS asset",
        location: f.path,
        evidence: `content-encoding absent, ${(f.size / 1024).toFixed(0)} KB${f.gzipSize != null ? ` (gzip estimate: ${(f.gzipSize / 1024).toFixed(0)} KB)` : ""}`,
        mode,
      });
    }
    const cc = f.headers["cache-control"] || "";
    const isHashed = /-[0-9a-f]{8,}\.(js|mjs|css)/i.test(f.path);
    if (isHashed && !/max-age\s*=\s*[3-9]\d{6}|max-age\s*=\s*\d{8,}|immutable/i.test(cc)) {
      out.push({
        auditor: "Performance",
        rule_id: "perf_cache_control",
        title: "Weak Cache-Control on hashed asset",
        location: f.path,
        evidence: cc || "no cache-control header",
        mode,
      });
    }
    if (f.text && /\/\/[#@]\s*sourceMappingURL/.test(f.text)) {
      const sm = files.find((x) => x.kind === "sourcemap" && x.status === 200 && x.path && f.text!.includes(x.path.split("/").pop() || "__never__"));
      if (sm || /sourceMappingURL\s*=\s*https?:/.test(f.text)) {
        out.push({
          auditor: "Performance",
          rule_id: "perf_source_map_exposed",
          title: "Source map publicly exposed",
          location: f.path,
          evidence: "sourceMappingURL reachable in production",
          mode,
          context: "Source maps reveal original source code to anyone.",
        });
      }
    }
  }

  const head = html.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i)?.[1] || "";
  const blocking = [...head.matchAll(/<script\b([^>]*)>/gi)]
    .filter((m) => !/\b(async|defer|type\s*=\s*["']module)/i.test(m[1]))
    .filter((m) => /src\s*=\s*["']/i.test(m[1]));
  if (blocking.length > 0) {
    add("perf_blocking_script", `${blocking.length} blocking script(s) in <head>`, "scripts without async/defer");
  }

  const imgNoDim = [...html.matchAll(/<img\b([^>]*)>/gi)].filter((m) => {
    const a = m[1];
    return !/\bwidth\s*=/i.test(a) && !/\bheight\s*=/i.test(a) && !/\bloading\s*=\s*["']lazy/i.test(a);
  }).length;
  if (imgNoDim > 0) {
    add("perf_img_no_dimensions", `${imgNoDim} image(s) without width/height`, "causes layout shift");
  }
  return out;
}
