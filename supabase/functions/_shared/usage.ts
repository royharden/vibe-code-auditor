import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.57.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

export { corsHeaders };

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

let _serviceClient: SupabaseClient | null = null;

function serviceClient(): SupabaseClient {
  if (_serviceClient) return _serviceClient;
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new Error("Server misconfigured: missing Supabase service credentials");
  _serviceClient = createClient(url, key);
  return _serviceClient;
}

export type UsageResult =
  | { ok: true; count: number }
  | { ok: false; over: true }
  | { ok: false; error: string };

export async function checkUsage(fnName: string, cap = 200): Promise<UsageResult> {
  try {
    const client = serviceClient();
    const { data, error } = await client.rpc("increment_usage", { fn_name: fnName, cap });
    if (error) return { ok: false, error: error.message };
    const count = typeof data === "number" ? data : parseInt(String(data), 10);
    if (count === -1) return { ok: false, over: true };
    return { ok: true, count };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

export function overLimitResponse(): Response {
  return json({ error: "Demo daily limit reached - Offline demo still works" }, 429);
}

export function failClosedResponse(detail: string): Response {
  return json({ error: `Usage check failed: ${detail}` }, 503);
}
