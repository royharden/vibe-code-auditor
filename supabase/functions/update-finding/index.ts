import { checkUsage, overLimitResponse, failClosedResponse, getServiceClient, json, corsHeaders } from "../_shared/usage.ts";
import { readJsonBody } from "../_shared/request.ts";

const MAX_BODY_BYTES = 4 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("update-finding", 1, 1000);
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  const body = await readJsonBody(req, MAX_BODY_BYTES);
  if (!body.ok) return body.response;

  try {
    const { finding_id, status } = body.data;
    if (typeof finding_id !== "string" || !UUID_RE.test(finding_id)) {
      return json({ error: "finding_id required" }, 400);
    }
    if (status !== "open" && status !== "ignored") {
      return json({ error: "status must be 'open' or 'ignored'" }, 400);
    }

    const serviceClient = getServiceClient();
    if (!serviceClient) return json({ error: "Server misconfigured" }, 503);

    // Only the status column is ever written.
    const { error } = await serviceClient
      .from("findings")
      .update({ status })
      .eq("id", finding_id);

    if (error) {
      console.error(`update-finding: ${error.message}`);
      return json({ error: "Update failed" }, 500);
    }

    return json({ ok: true, id: finding_id, status });
  } catch (err) {
    console.error(`update-finding: ${(err as Error).message}`);
    return json({ error: "Update failed" }, 500);
  }
});

// verify_jwt=true
