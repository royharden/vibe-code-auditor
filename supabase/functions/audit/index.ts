import { runAuditors } from "../_shared/auditors/index.ts";
import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("audit");
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  try {
    const { mode, files } = await req.json();
    if (!Array.isArray(files)) return json({ error: "files array required" }, 400);

    const sanitized = (files as Array<{ path: string; kind: string; text?: string; headers?: Record<string, string>; status?: number; size?: number; gzipSize?: number | null }>).map((f) => ({
      path: f.path,
      kind: f.kind,
      status: f.status ?? 0,
      size: f.size ?? 0,
      gzipSize: f.gzipSize ?? null,
      headers: f.headers || {},
      text: f.text,
    }));

    const findings = runAuditors(sanitized, mode || "url");
    return json({ findings });
  } catch (err) {
    return json({ error: (err as Error).message || "Audit failed" }, 500);
  }
});

// verify_jwt=true
