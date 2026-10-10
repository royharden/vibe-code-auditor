import type { FetchedFile, FetchResult } from "./fetch-target.ts";

const MAX_FILES = 60;
const MAX_FILE_BYTES = 1.5 * 1024 * 1024;

function parseRepo(input: string): { owner: string; repo: string } | null {
  const cleaned = input.trim().replace(/\/+$/, "");
  const m = /(?:github\.com[/:])([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(cleaned);
  if (m) return { owner: m[1], repo: m[2] };
  const short = /^([\w.-]+)\/([\w.-]+)$/.exec(cleaned);
  if (short) return { owner: short[1], repo: short[2] };
  return null;
}

const KIND_MAP: Array<[RegExp, string]> = [
  [/supabase\/migrations\/.*\.sql$/i, "migration"],
  [/firestore\.rules$/i, "rules"],
  [/\.env/i, "env"],
  [/package\.json$/i, "package"],
  [/index\.html$/i, "html"],
  [/vite\.config|next\.config|tailwind\.config|nginx\.conf|Dockerfile|vercel\.json|netlify\.toml|wrangler\.toml/i, "config"],
  [/\.(ts|tsx|js|jsx)$/i, "source"],
];

function kindFor(path: string): string | null {
  for (const [re, kind] of KIND_MAP) {
    if (re.test(path)) return kind;
  }
  return null;
}

const PRIORITY_TERMS = /supabase|auth|api|config/i;

export async function fetchRepo(input: string, githubToken?: string): Promise<FetchResult> {
  const start = Date.now();
  const parsed = parseRepo(input);
  if (!parsed) throw new Error("Could not parse a GitHub repo from that input (expected owner/repo or a github.com URL)");
  const api = "https://api.github.com";
  const authHeaders: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "VibeCodeAuditor/1.0 (+passive read-only scan)",
  };
  if (githubToken) authHeaders.Authorization = `Bearer ${githubToken}`;

  const repoRes = await fetch(`${api}/repos/${parsed.owner}/${parsed.repo}`, { headers: authHeaders });
  if (repoRes.status === 404) throw new Error("Repository not found (it may be private — only public repos can be audited)");
  if (repoRes.status === 403) throw new Error("GitHub rate limit hit. Add a GITHUB_TOKEN secret to raise the limit.");
  if (!repoRes.ok) throw new Error(`GitHub API error ${repoRes.status}`);
  const repoMeta = await repoRes.json();
  if (repoMeta.private) throw new Error("Repository is private — only public repos can be audited");
  const branch = repoMeta.default_branch || "main";

  const treeRes = await fetch(`${api}/repos/${parsed.owner}/${parsed.repo}/git/trees/${branch}?recursive=1`, { headers: authHeaders });
  if (!treeRes.ok) throw new Error(`GitHub tree API error ${treeRes.status}`);
  const tree = await treeRes.json();

  const candidates = (tree.tree || [])
    .filter((e: { type: string; size?: number; path: string }) => e.type === "blob")
    .filter((e: { path: string; size?: number }) => {
      if ((e.size ?? 0) > MAX_FILE_BYTES) return false;
      return kindFor(e.path) !== null;
    })
    .sort((a: { path: string }, b: { path: string }) => {
      const pa = PRIORITY_TERMS.test(a.path) ? 0 : 1;
      const pb = PRIORITY_TERMS.test(b.path) ? 0 : 1;
      if (pa !== pb) return pa - pb;
      return a.path.length - b.path.length;
    })
    .slice(0, MAX_FILES);

  const files: FetchedFile[] = [];
  for (const entry of candidates) {
    const raw = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${branch}/${entry.path}`;
    let text: string | undefined;
    let size = entry.size ?? 0;
    let status = 200;
    try {
      const r = await fetch(raw, { headers: authHeaders });
      status = r.status;
      if (r.ok) text = await r.text();
    } catch {
      status = 0;
    }
    files.push({
      path: entry.path,
      kind: kindFor(entry.path) || "source",
      status,
      size,
      headers: {},
      text: text?.slice(0, MAX_FILE_BYTES),
    });
  }

  return {
    mode: "repo",
    files,
    requestsUsed: files.length + 2,
    bytesTotal: files.reduce((s, f) => s + (f.text?.length ?? 0), 0),
    durationMs: Date.now() - start,
  };
}
