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

export const MAX_TOTAL_TEXT_CHARS = 6 * 1024 * 1024;

const BUDGET = {
  maxRequests: 30,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: MAX_TOTAL_TEXT_CHARS,
  maxCdnFiles: 10,
  maxRedirects: 3,
  timeoutMs: 20_000,
  dnsTimeoutMs: 5_000,
};

const BLOCKED_HOST_MESSAGE = "This host is not reachable by the scanner (private or restricted)";

const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /\.localhost$/i,
  /\.internal$/i,
  /\.local$/i,
];

function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  return octets.every((n) => n <= 255) ? octets : null;
}

// Parses a (bracket-less) IPv6 literal into 8 16-bit groups, including an embedded IPv4 tail.
function parseIPv6(input: string): number[] | null {
  let s = input.toLowerCase();
  if (!s.includes(":") || !/^[0-9a-f:.]+$/.test(s)) return null;
  let tail: number[] = [];
  if (s.includes(".")) {
    const cut = s.lastIndexOf(":");
    const v4 = parseIPv4(s.slice(cut + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, cut + 1);
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !rest) return null;
  const explicit = head.length + rest.length + tail.length;
  if (halves.length === 2) {
    if (explicit > 7) return null;
    return [...head, ...new Array(8 - explicit).fill(0), ...rest, ...tail];
  }
  return explicit === 8 ? [...head, ...tail] : null;
}

function isBlockedIPv4([a, b, c]: number[]): boolean {
  return (
    a === 0 || // 0.0.0.0/8 "this network"
    a === 10 || // 10.0.0.0/8 private
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
    a === 127 || // 127.0.0.0/8 loopback
    (a === 169 && b === 254) || // 169.254.0.0/16 link-local, incl. cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 private
    (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24 IETF protocol assignments
    (a === 192 && b === 0 && c === 2) || // 192.0.2.0/24 documentation
    (a === 192 && b === 88 && c === 99) || // 192.88.99.0/24 6to4 relay
    (a === 192 && b === 168) || // 192.168.0.0/16 private
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmarking
    (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24 documentation
    (a === 203 && b === 0 && c === 113) || // 203.0.113.0/24 documentation
    a >= 224 // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, broadcast
  );
}

function isBlockedIPv6(g: number[]): boolean {
  const zeroPrefix = g.slice(0, 5).every((x) => x === 0);
  if (zeroPrefix && g[5] === 0xffff) return true; // ::ffff:0:0/96 IPv4-mapped
  if (zeroPrefix && g[5] === 0) return true; // ::/96: ::, ::1, IPv4-compatible
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if ((g[0] & 0xe000) !== 0x2000) return true; // outside 2000::/3 global unicast (64:ff9b::/96, 100::/64, fec0::/10, ...)
  if (g[0] === 0x2001 && g[1] < 0x0200) return true; // 2001::/23 IETF protocol assignments (Teredo, ...)
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // 2001:db8::/32 documentation
  if (g[0] === 0x2002) return true; // 2002::/16 6to4 (embeds IPv4)
  if (g[0] === 0x3fff && g[1] < 0x1000) return true; // 3fff::/20 documentation
  return false;
}

// Returns true/false for IP literals, or null when `addr` is not an IP address.
function isBlockedAddress(addr: string): boolean | null {
  const v4 = parseIPv4(addr);
  if (v4) return isBlockedIPv4(v4);
  const v6 = parseIPv6(addr);
  if (v6) return isBlockedIPv6(v6);
  return null;
}

// A and AAAA, fail closed: any resolver error other than "no records" rejects, and so does
// a name with no addresses at all.
async function resolveAddresses(host: string): Promise<string[]> {
  const lookups = await Promise.allSettled([
    Deno.resolveDns(host, "A", { signal: AbortSignal.timeout(BUDGET.dnsTimeoutMs) }),
    Deno.resolveDns(host, "AAAA", { signal: AbortSignal.timeout(BUDGET.dnsTimeoutMs) }),
  ]);
  const addrs: string[] = [];
  for (const r of lookups) {
    if (r.status === "fulfilled") addrs.push(...r.value);
    else if (!(r.reason instanceof Deno.errors.NotFound)) throw new Error("DNS lookup failed for this host");
  }
  if (addrs.length === 0) throw new Error("Could not resolve this host");
  return addrs;
}

// Syntax-only checks; validateTarget adds the host and DNS checks.
function parseHttpUrl(raw: string): URL {
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
  return url;
}

export async function validateTarget(raw: string): Promise<URL> {
  const url = parseHttpUrl(raw);
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
  if (!host) throw new Error("Invalid URL");

  const literal = isBlockedAddress(host);
  if (literal !== null) {
    if (literal) throw new Error(BLOCKED_HOST_MESSAGE);
    return url;
  }

  // Single-label names ("metadata", "intranet") and reserved suffixes are never public sites.
  if (!host.includes(".") || BLOCKED_HOSTNAME_PATTERNS.some((p) => p.test(host))) {
    throw new Error(BLOCKED_HOST_MESSAGE);
  }

  // Blocks names that resolve to private space (e.g. 127.0.0.1.nip.io).
  for (const addr of await resolveAddresses(host)) {
    if (isBlockedAddress(addr) !== false) throw new Error(BLOCKED_HOST_MESSAGE);
  }
  return url;
}

interface Fetched {
  res: Response;
  finalUrl: URL;
  // Clears the per-request timeout; call once the body has been read.
  done: () => void;
}

async function fetchWithLimits(
  url: URL,
  requestsUsed: { n: number },
  bytesTotal: { n: number }
): Promise<Fetched | { error: string }> {
  let current = url;
  for (let hop = 0; hop <= BUDGET.maxRedirects; hop++) {
    if (requestsUsed.n >= BUDGET.maxRequests) return { error: "Request budget (30) exhausted" };
    let checked: URL;
    try {
      checked = await validateTarget(current.toString());
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
    if (res.status >= 300 && res.status < 400) {
      clearTimeout(timer);
      res.body?.cancel().catch(() => {});
      const loc = res.headers.get("location");
      if (!loc) return { error: `Redirect ${res.status} without location` };
      try {
        current = new URL(loc, checked);
      } catch {
        return { error: "Invalid redirect location" };
      }
      continue;
    }
    // The timeout stays armed until the caller has read the body (readBody calls done()).
    return { res, finalUrl: checked, done: () => clearTimeout(timer) };
  }
  return { error: `Too many redirects (max ${BUDGET.maxRedirects})` };
}

async function readBody(fetched: Fetched, bytesTotal: { n: number }): Promise<{ text?: string; size: number; error?: string }> {
  try {
    return await readBodyWithin(fetched.res, bytesTotal);
  } finally {
    fetched.done();
  }
}

async function readBodyWithin(res: Response, bytesTotal: { n: number }): Promise<{ text?: string; size: number; error?: string }> {
  const lenHeader = parseInt(res.headers.get("content-length") || "", 10);
  if (!isNaN(lenHeader) && lenHeader > BUDGET.maxFileBytes) {
    res.body?.cancel().catch(() => {});
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

  const page = await fetchWithLimits(parseHttpUrl(rawUrl), requestsUsed, bytesTotal);
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
  const body = await readBody(page, bytesTotal);
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
    const b = await readBody(r, bytesTotal);
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
          const sb = await readBody(sr, bytesTotal);
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
    const b = await readBody(r, bytesTotal);
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
