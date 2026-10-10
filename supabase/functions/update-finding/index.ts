import { createClient } from "npm:@supabase/supabase-js@2.57.4";
import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("update-finding", 1000);
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  try {
    const { finding_id, status } = await req.json();
    if (!finding_id || typeof finding_id !== "string") {
      return json({ error: "finding_id required" }, 400);
    }
    if (status !== "open" && status !== "ignored") {
      return json({ error: "status must be 'open' or 'ignored'" }, 400);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !key) return json({ error: "Server misconfigured" }, 500);

    const serviceClient = createClient(url, key);
    const { error } = await serviceClient
      .from("findings")
      .update({ status })
      .eq("id", finding_id);

    if (error) return json({ error: error.message }, 500);

    return json({ ok: true, id: finding_id, status });
  } catch (err) {
    return json({ error: (err as Error).message || "Update failed" }, 500);
  }
});

// verify_jwt=true
