import { validateTarget, fetchTarget } from "../_shared/fetch-target.ts";
import { fetchRepo } from "../_shared/fetch-repo.ts";
import { isSensitiveText } from "../_shared/mask.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  try {
    const body = await req.json();
    const mode = body.mode as "url" | "repo";
    const target = (body.target || "").trim();
    const consent = body.consent === true;

    if (!target) return json({ error: "Missing target" }, 400);
    if (mode === "url" && !consent) {
      return json({ error: "Consent required: confirm you own this app or have permission to audit it." }, 403);
    }

    if (mode === "url") {
      try {
        validateTarget(target);
      } catch (e) {
        return json({ error: (e as Error).message }, 400);
      }
    }

    const result = mode === "repo" ? await fetchRepo(target, Deno.env.get("GITHUB_TOKEN")) : await fetchTarget(target);

    const fileMeta = result.files.map((f) => ({
      path: f.path,
      kind: f.kind,
      status: f.status,
      size: f.size,
      gzipSize: f.gzipSize ?? null,
      headers: f.headers,
      error: f.error ?? null,
      secretBearing: f.text ? isSensitiveText(f.text) : false,
    }));

    return json({
      mode: result.mode,
      files: result.files,
      file_meta: fileMeta,
      requestsUsed: result.requestsUsed,
      bytesTotal: result.bytesTotal,
      durationMs: result.durationMs,
    });
  } catch (err) {
    return json({ error: (err as Error).message || "Fetch failed" }, 500);
  }
});
