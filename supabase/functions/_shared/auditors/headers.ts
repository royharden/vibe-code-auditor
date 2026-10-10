import type { FetchedFile } from "../fetch-target.ts";
import type { Finding } from "./secrets.ts";

export function auditHeaders(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  const page = files.find((f) => f.kind === "page");
  if (!page || mode !== "url") return out;
  const h = page.headers;
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) lower[k.toLowerCase()] = v;
  const loc = page.path;

  const add = (rule_id: string, title: string, evidence: string, context?: string) =>
    out.push({ auditor: "Headers", rule_id, title, location: loc, evidence, mode, context });

  const csp = lower["content-security-policy"];
  if (!csp) {
    add("csp_missing", "Content-Security-Policy header missing", "No CSP header on the main document");
  } else if (csp.includes("unsafe-inline")) {
    add("csp_unsafe_inline", "CSP allows unsafe-inline", csp.slice(0, 200));
  }
  if (!lower["strict-transport-security"]) {
    add("hsts_missing", "Strict-Transport-Security header missing", "No HSTS header");
  }
  if (!lower["x-content-type-options"]) {
    add("xcto_missing", "X-Content-Type-Options header missing", "Nosniff not enforced");
  }
  const hasFrame = (csp && /frame-ancestors/i.test(csp)) || lower["x-frame-options"];
  if (!hasFrame) {
    add("frame_ancestors_missing", "No frame-ancestors / X-Frame-Options (clickjacking)", "Page can be framed by any site");
  }
  if (!lower["referrer-policy"]) {
    add("referrer_policy_missing", "Referrer-Policy header missing", "Full URLs may leak via Referer");
  }
  if (!lower["permissions-policy"]) {
    add("permissions_policy_missing", "Permissions-Policy header missing", "Browser features not restricted");
  }
  const setCookie = lower["set-cookie"];
  if (setCookie) {
    const flags: string[] = [];
    if (!/secure/i.test(setCookie)) flags.push("Secure");
    if (!/httponly/i.test(setCookie)) flags.push("HttpOnly");
    if (!/samesite/i.test(setCookie)) flags.push("SameSite");
    if (flags.length) add("cookie_flags", `Cookie missing flags: ${flags.join(", ")}`, setCookie.slice(0, 120));
  }
  const acao = lower["access-control-allow-origin"];
  if (acao === "*") {
    add("cors_wildcard", "Access-Control-Allow-Origin: *", "API responses readable by any origin");
  }
  if (lower["x-powered-by"] || /^[-\w.]+\/\d/.test(lower["server"] || "")) {
    add("version_leak", "Server version disclosure", `${lower["server"] || ""} ${lower["x-powered-by"] || ""}`.trim().slice(0, 80));
  }
  return out;
}
