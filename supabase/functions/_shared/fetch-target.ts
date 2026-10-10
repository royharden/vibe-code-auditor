export interface FetchedFile {
  path: string;
  kind: string;
  status: number;
  size: number;
  gzipSize?: number | null;
  headers: Record<string, string>;
  text?: string;
  error?: string;
}

export interface FetchResult {
  mode: "url" | "repo";
  files: FetchedFile[];
  requestsUsed: number;
  bytesTotal: number;
  durationMs: number;
}

const BUDGET = {
  maxRequests: 30,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 6 * 1024 * 1024,
  maxCdnFiles: 10,
  maxRedirects: 5,
  timeoutMs: 20_000,
};

const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^\[::1\]$/,
  /^fe80:/i,
  /^fc00:/i,
  /^fd[0-9a-f]{2}:/i,
  /\.internal$/i,
  /\.local$/i,
];

export function validateTarget(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https are allowed");
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new Error("Non-standard ports are not allowed");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  for (const p of BLOCKED_HOST_PATTERNS) {
    if (p.test(host)) {
      throw new Error("This host is not reachable by the scanner (private or restricted)");
    }
  }
  if (host === "169.254.169.254") {
    throw new Error("This host is not reachable by the scanner");
  }
  return url;
}

async function fetchWithLimits(
  url: URL,
  requestsUsed: { n: number },
  bytesTotal: { n: number }
): Promise<{ res: Response; finalUrl: URL } | { error: string }> {
  let current = url;
  for (let hop = 0; hop <= BUDGET.maxRedirects; hop++) {
    if (requestsUsed.n >= BUDGET.maxRequests) return { error: "Request budget (30) exhausted" };
    let checked: URL;
    try {
      checked = validateTarget(current.toString());
    } catch (e) {
      return { error: (e as Error).message };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), BUDGET.timeoutMs);
    let res: Response;
    try {
      requestsUsed.n += 1;
      res = await fetch(checked.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "VibeCodeAuditor/1.0 (+passive read-only scan)" },
      });
    } catch (e) {
      clearTimeout(timer);
      return { error: `Fetch failed: ${(e as Error).message}` };
    }
    clearTimeout(timer);
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { error: `Redirect ${res.status} without location` };
      try {
        current = new URL(loc, checked);
      } catch {
        return { error: "Invalid redirect location" };
      }
      continue;
    }
    return { res, finalUrl: checked };
  }
  return { error: "Too many redirects (max 5)" };
}

async function readBody(res: Response, bytesTotal: { n: number }): Promise<{ text?: string; size: number; error?: string }> {
  const lenHeader = parseInt(res.headers.get("content-length") || "", 10);
  if (!isNaN(lenHeader) && lenHeader > BUDGET.maxFileBytes) {
    return { size: lenHeader, error: "File exceeds 2 MB limit" };
  }
  let buf = new Uint8Array(0);
  try {
    const reader = res.body?.getReader();
    if (!reader) return { size: 0 };
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > BUDGET.maxFileBytes || bytesTotal.n + total > BUDGET.maxTotalBytes) {
        reader.cancel().catch(() => {});
        return { size: total, error: "Size limit exceeded" };
      }
      chunks.push(value);
    }
    buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.byteLength;
    }
  } catch {
    return { size: buf.byteLength, error: "Failed reading body" };
  }
  bytesTotal.n += buf.byteLength;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(buf);
  return { text, size: buf.byteLength };
}

async function gzipSizeOf(text: string): Promise<number | null> {
  try {
    const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
    const buf = await new Response(stream).arrayBuffer();
    return buf.byteLength;
  } catch {
    return null;
  }
}

function headersToObject(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    out[k] = v;
  });
  return out;
}

function extractAssets(html: string, baseUrl: URL) {
  const scripts: string[] = [];
  const styles: string[] = [];
  const inlineScripts: string[] = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptRe.exec(html)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const src = /src\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (src) {
      try {
        scripts.push(new URL(src[1], baseUrl).toString());
      } catch { /* skip */ }
    } else if (body.trim()) {
      inlineScripts.push(body);
    }
  }
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html)) !== null) {
    const attrs = m[1];
    if (!/rel\s*=\s*["']?stylesheet/i.test(attrs)) continue;
    const href = /href\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (href) {
      try {
        styles.push(new URL(href[1], baseUrl).toString());
      } catch { /* skip */ }
    }
  }
  return { scripts, styles, inlineScripts };
}

function sourcemapUrl(text: string, fileUrl: string): string | null {
  const m = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(text.slice(-2000));
  if (!m) return null;
  try {
    return new URL(m[1], fileUrl).toString();
  } catch {
    return null;
  }
}

export async function fetchTarget(rawUrl: string): Promise<FetchResult> {
  const start = Date.now();
  const requestsUsed = { n: 0 };
  const bytesTotal = { n: 0 };
  const files: FetchedFile[] = [];

  const page = await fetchWithLimits(validateTarget(rawUrl), requestsUsed, bytesTotal);
  if ("error" in page) {
    return {
      mode: "url",
      files: [{ path: rawUrl, kind: "page", status: 0, size: 0, headers: {}, error: page.error }],
      requestsUsed: requestsUsed.n,
      bytesTotal: bytesTotal.n,
      durationMs: Date.now() - start,
    };
  }

  const { res, finalUrl } = page;
  const body = await readBody(res, bytesTotal);
  const headers = headersToObject(res);
  const html = body.text || "";
  const file: FetchedFile = {
    path: finalUrl.toString(),
    kind: "page",
    status: res.status,
    size: body.size,
    headers,
    text: html,
    error: body.error,
  };
  files.push(file);

  const { scripts, styles, inlineScripts } = extractAssets(html, finalUrl);
  const assetUrls = [...scripts, ...styles].slice(0, BUDGET.maxCdnFiles);
  const inlineTexts: string[] = [...inlineScripts];

  for (const assetUrl of assetUrls) {
    const sameOrigin = new URL(assetUrl).origin === finalUrl.origin;
    if (!sameOrigin && !assetUrls.includes(assetUrl)) continue;
    const r = await fetchWithLimits(new URL(assetUrl), requestsUsed, bytesTotal);
    if ("error" in r) {
      files.push({ path: assetUrl, kind: "asset", status: 0, size: 0, headers: {}, error: r.error });
      continue;
    }
    const b = await readBody(r.res, bytesTotal);
    const f: FetchedFile = {
      path: assetUrl,
      kind: sameOrigin ? "asset" : "cdn",
      status: r.res.status,
      size: b.size,
      headers: headersToObject(r.res),
      text: b.text,
      error: b.error,
    };
    if (f.text) {
      f.gzipSize = await gzipSizeOf(f.text);
      const sm = sourcemapUrl(f.text, assetUrl);
      if (sm) {
        const sr = await fetchWithLimits(new URL(sm), requestsUsed, bytesTotal);
        if (!("error" in sr)) {
          const sb = await readBody(sr.res, bytesTotal);
          files.push({
            path: sm,
            kind: "sourcemap",
            status: sr.res.status,
            size: sb.size,
            headers: headersToObject(sr.res),
            error: sb.error,
          });
        } else {
          files.push({ path: sm, kind: "sourcemap", status: 0, size: 0, headers: {}, error: sr.error });
        }
      }
    }
    files.push(f);
  }

  for (const extra of ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]) {
    const u = new URL(extra, finalUrl.origin + "/");
    const r = await fetchWithLimits(u, requestsUsed, bytesTotal);
    if ("error" in r) {
      files.push({ path: u.toString(), kind: "wellknown", status: 0, size: 0, headers: {}, error: r.error });
      continue;
    }
    const b = await readBody(r.res, bytesTotal);
    files.push({
      path: u.toString(),
      kind: "wellknown",
      status: r.res.status,
      size: b.size,
      headers: headersToObject(r.res),
      text: b.text?.slice(0, 5000),
      error: b.error,
    });
  }

  if (inlineTexts.length > 0 && files[0]) {
    (files[0] as FetchedFile & { inlineScripts?: string[] }).inlineScripts = inlineTexts.map((t) => t.slice(0, 20_000));
  }

  return {
    mode: "url",
    files,
    requestsUsed: requestsUsed.n,
    bytesTotal: bytesTotal.n,
    durationMs: Date.now() - start,
  };
}
