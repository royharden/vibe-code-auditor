import type { FetchedFile } from "../fetch-target.ts";
import type { Finding } from "./secrets.ts";

export function auditSeo(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  if (mode !== "url") return out;
  const page = files.find((f) => f.kind === "page");
  const html = page?.text || "";
  if (!html) return out;
  const loc = page!.path;
  const add = (rule_id: string, title: string, evidence: string, context?: string) =>
    out.push({ auditor: "SEO", rule_id, title, location: loc, evidence, mode, context });

  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.trim() || "";
  if (!title) {
    add("seo_title", "Missing <title>", "no <title> tag");
  } else if (title.length < 15 || title.length > 65) {
    add("seo_title", `Title length ${title.length} (recommended 15–65)`, title.slice(0, 80));
  }

  const desc = /<meta[^>]*name\s*=\s*["']description["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html)?.[1]?.trim() || "";
  if (!desc) {
    add("seo_description", "Missing meta description", "no description meta tag");
  } else if (desc.length < 50 || desc.length > 160) {
    add("seo_description", `Meta description length ${desc.length} (recommended 50–160)`, desc.slice(0, 80));
  }

  if (!/<link[^>]*rel\s*=\s*["']canonical["']/i.test(html)) {
    add("seo_canonical_missing", "No canonical link", "missing rel=canonical");
  }

  const ogTags = ["og:title", "og:description", "og:image"].filter(
    (p) => new RegExp(`property\\s*=\\s*["']${p}["']`, "i").test(html)
  );
  if (ogTags.length < 3) {
    add("seo_og_missing", `Open Graph tags incomplete (${ogTags.length}/3)`, ogTags.join(", ") || "none");
  }

  if (/<meta[^>]*name\s*=\s*["']robots["'][^>]*content\s*=\s*["'][^"']*noindex/i.test(html)) {
    add("seo_noindex", "Page marked noindex", "robots meta contains noindex");
  }

  const wellKnown = files.filter((f) => f.kind === "wellknown");
  const sitemap = wellKnown.find((f) => /sitemap\.xml$/.test(f.path));
  if (!sitemap || sitemap.status !== 200) {
    add("seo_sitemap_missing", "No sitemap.xml found", "sitemap.xml missing or not reachable");
  }

  const h1Count = (html.match(/<h1\b/gi) || []).length;
  if (h1Count !== 1) {
    add("seo_h1_count", `${h1Count} <h1> elements (expected exactly 1)`, `h1 count = ${h1Count}`);
  }

  const bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").trim();
  if (bodyText.length < 200 && /<script\b[^>]*src\s*=\s*["'][^"']*\/(src|assets|_next|static)\//i.test(html)) {
    add("seo_empty_shell", "Empty SPA shell — content rendered only by JS", `visible text: ${bodyText.length} chars`);
  }
  return out;
}
