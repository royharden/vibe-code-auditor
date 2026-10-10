import type { FetchedFile } from "../fetch-target.ts";
import type { Finding } from "./secrets.ts";

export function auditA11y(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  if (mode !== "url") return out;
  const page = files.find((f) => f.kind === "page");
  const html = page?.text || "";
  if (!html) return out;
  const loc = page!.path;
  const add = (rule_id: string, title: string, evidence: string, context?: string) =>
    out.push({ auditor: "Accessibility", rule_id, title, location: loc, evidence, mode, context });

  if (!/<html[^>]*\slang\s*=/i.test(html)) {
    add("a11y_lang_missing", "<html> has no lang attribute", "<html …> without lang");
  }
  if (!/<title[^>]*>\s*\S/i.test(html)) {
    add("a11y_title_missing", "Missing or empty <title>", "<title> empty");
  }

  const imgRe = /<img\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  let missingAlt = 0;
  const firstImg: string[] = [];
  while ((m = imgRe.exec(html)) !== null) {
    const attrs = m[1];
    if (!/\salt\s*=/i.test(attrs)) {
      missingAlt++;
      if (firstImg.length < 3) firstImg.push(m[0].slice(0, 80));
    }
  }
  if (missingAlt > 0) {
    add("a11y_img_no_alt", `${missingAlt} image(s) without alt attribute`, firstImg.join(" | "));
  }

  const inputRe = /<input\b([^>]*)>/gi;
  let unlabeled = 0;
  const inputSamples: string[] = [];
  while ((m = inputRe.exec(html)) !== null) {
    const attrs = m[1];
    const type = /\btype\s*=\s*["']?([\w-]+)/i.exec(attrs)?.[1] || "text";
    if (["hidden", "submit", "button", "reset", "checkbox", "radio"].includes(type)) continue;
    const hasId = /\bid\s*=\s*["']([^"']+)["']/i.exec(attrs);
    const hasAria = /\b(aria-label|aria-labelledby)\s*=/i.test(attrs);
    const labelFor = hasId ? new RegExp(`<label[^>]*\\bfor\\s*=\\s*["']${hasId[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`, "i").test(html) : false;
    const wrapped = hasId ? new RegExp(`<label[^>]*>[\\s\\S]{0,200}?<input[^>]*\\bid\\s*=\\s*["']${hasId[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`, "i").test(html) : false;
    if (!hasAria && !labelFor && !wrapped) {
      unlabeled++;
      if (inputSamples.length < 3) inputSamples.push(m[0].slice(0, 80));
    }
  }
  if (unlabeled > 0) {
    add("a11y_input_no_label", `${unlabeled} input(s) without a label`, inputSamples.join(" | "));
  }

  const buttonRe = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;
  let emptyButtons = 0;
  const buttonSamples: string[] = [];
  while ((m = buttonRe.exec(html)) !== null) {
    const attrs = m[1];
    const body = m[2].replace(/<[^>]+>/g, "").trim();
    const hasAria = /\b(aria-label|aria-labelledby)\s*=/i.test(attrs);
    if (!body && !hasAria) {
      emptyButtons++;
      if (buttonSamples.length < 3) buttonSamples.push(m[0].slice(0, 80));
    }
  }
  if (emptyButtons > 0) {
    add("a11y_button_no_name", `${emptyButtons} button(s) without an accessible name`, buttonSamples.join(" | "));
  }

  const headings = [...html.matchAll(/<h([1-6])\b/gi)].map((h) => parseInt(h[1], 10));
  let skipped = false;
  for (let i = 1; i < headings.length; i++) {
    if (headings[i] > headings[i - 1] + 1) {
      skipped = true;
      break;
    }
  }
  if (skipped) {
    add("a11y_heading_skip", "Heading levels skip (e.g. h2 to h4)", headings.join(" → "));
  }

  const viewport = /<meta[^>]*name\s*=\s*["']viewport["'][^>]*content\s*=\s*["']([^"']*)["']/i.exec(html)?.[1] || "";
  if (/user-scalable\s*=\s*no/i.test(viewport) || /maximum-scale\s*=\s*1(\.0)?\b/i.test(viewport)) {
    add("a11y_zoom_disabled", "Zoom disabled in viewport meta", viewport.slice(0, 120));
  }
  return out;
}
