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

// Service-role client built only from env. Returns null when either env var is missing,
// so callers fail closed (503) instead of creating a client with empty credentials.
export function getServiceClient(): SupabaseClient | null {
  if (_serviceClient) return _serviceClient;
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return null;
  _serviceClient = createClient(url, key);
  return _serviceClient;
}

const DEFAULT_DAILY_CAP = 200;

function defaultCap(): number {
  const n = Number(Deno.env.get("DAILY_CALL_LIMIT"));
  return Number.isInteger(n) && n > 0 ? n : DEFAULT_DAILY_CAP;
}

export type UsageResult =
  | { ok: true; count: number }
  | { ok: false; over: true; error?: undefined }
  | { ok: false; over: false; error: string };

// Reserves `units` against today's cap for `fnName` (one unit per paid upstream call).
// Fails closed: an RPC error, a missing client, or a null / non-integer result is an error, never ok.
export async function checkUsage(fnName: string, units = 1, cap = defaultCap()): Promise<UsageResult> {
  try {
    const client = getServiceClient();
    if (!client) return { ok: false, over: false, error: "missing Supabase service credentials" };
    const { data, error } = await client.rpc("increment_usage_by", { fn_name: fnName, units, cap });
    if (error) return { ok: false, over: false, error: error.message };
    if (typeof data !== "number" || !Number.isInteger(data)) {
      return { ok: false, over: false, error: `unexpected counter result: ${JSON.stringify(data)}` };
    }
    if (data === -1) return { ok: false, over: true };
    if (data < units) return { ok: false, over: false, error: `unexpected counter result: ${data}` };
    return { ok: true, count: data };
  } catch (e) {
    return { ok: false, over: false, error: (e as Error).message };
  }
}

export function overLimitResponse(): Response {
  return json({ error: "Demo daily limit reached - Offline demo still works" }, 429);
}

// The detail is logged server-side only; the client never sees DB error text.
export function failClosedResponse(detail?: string): Response {
  if (detail) console.error(`Usage check failed: ${detail}`);
  return json({ error: "Usage check failed" }, 503);
}
