import { runAuditors } from "../_shared/auditors/index.ts";
import { MAX_TOTAL_TEXT_CHARS, type FetchedFile } from "../_shared/fetch-target.ts";
import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";
import { readJsonBody, isRecord, clip } from "../_shared/request.ts";

const MAX_BODY_BYTES = 16 * 1024 * 1024;
const MAX_FILES = 100;

function stringHeaders(v: unknown): Record<string, string> {
  if (!isRecord(v)) return {};
  return Object.fromEntries(Object.entries(v).filter((e): e is [string, string] => typeof e[1] === "string"));
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("audit");
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  const body = await readJsonBody(req, MAX_BODY_BYTES);
  if (!body.ok) return body.response;

  try {
    const { mode, files } = body.data;
    if (!Array.isArray(files)) return json({ error: "files array required" }, 400);
    if (files.length > MAX_FILES) return json({ error: `Too many files (max ${MAX_FILES})` }, 400);
    if (!files.every(isRecord)) return json({ error: "each file must be an object" }, 400);

    const sanitized: FetchedFile[] = files.map((f) => ({
      path: typeof f.path === "string" ? f.path : "",
      kind: typeof f.kind === "string" ? f.kind : "",
      status: typeof f.status === "number" ? f.status : 0,
      size: typeof f.size === "number" ? f.size : 0,
      gzipSize: typeof f.gzipSize === "number" ? f.gzipSize : null,
      headers: stringHeaders(f.headers),
      text: typeof f.text === "string" ? f.text : undefined,
    }));

    const totalText = sanitized.reduce((s, f) => s + (f.text?.length ?? 0), 0);
    if (totalText > MAX_TOTAL_TEXT_CHARS) return json({ error: "Files exceed 6 MB of total text" }, 400);

    const findings = runAuditors(sanitized, clip(mode, 20) || "url");
    return json({ findings });
  } catch (err) {
    console.error(`audit: ${(err as Error).message}`);
    return json({ error: "Audit failed" }, 500);
  }
});

// verify_jwt=true
