import { validateTarget, fetchTarget } from "../_shared/fetch-target.ts";
import { fetchRepo } from "../_shared/fetch-repo.ts";
import { isSensitiveText } from "../_shared/mask.ts";
import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";
import { readJsonBody } from "../_shared/request.ts";

const MAX_BODY_BYTES = 16 * 1024;
const MAX_TARGET_CHARS = 2048;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("fetch-target");
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  const parsed = await readJsonBody(req, MAX_BODY_BYTES);
  if (!parsed.ok) return parsed.response;

  try {
    const body = parsed.data;
    // Anything that is not "repo" is treated as a URL scan, so the consent and SSRF checks always apply.
    const mode: "url" | "repo" = body.mode === "repo" ? "repo" : "url";
    const target = typeof body.target === "string" ? body.target.trim() : "";
    const consent = body.consent === true;

    if (!target) return json({ error: "Missing target" }, 400);
    if (target.length > MAX_TARGET_CHARS) return json({ error: "Target too long" }, 400);
    if (mode === "url" && !consent) {
      return json({ error: "Consent required: confirm you own this app or have permission to audit it." }, 403);
    }

    if (mode === "url") {
      try {
        await validateTarget(target);
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

// verify_jwt=true
