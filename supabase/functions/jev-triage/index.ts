import { triage } from "../_shared/policy.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const JEV_MODEL = "jev-1.13.0";
const JEV_PRICE_PER_MILLION_INPUT = 0.042;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

const INJECTION_PATTERNS = /ignore (all |any )?previous|disregard (all |any )?instructions|system prompt|you are now|new instructions:/i;

function jevStateFor(finding: Record<string, unknown>, mode: string) {
  return {
    finding: {
      auditor: finding.auditor,
      rule_id: finding.rule_id,
      title: finding.title,
      location: finding.location,
      evidence: finding.evidence_masked,
      in_client_bundle: finding.in_client_bundle === true,
      mode,
    },
  };
}

const QUESTIONS = {
  severity: {
    type: "score",
    instructions: "How severe is `finding` if it is real?",
    criteria: [
      "Info: no security or quality impact.",
      "Low: minor hardening or quality issue.",
      "Medium: weakens security or noticeably hurts users.",
      "High: likely leads to data exposure or abuse.",
      "Critical: directly exposes secrets, data, or admin access.",
    ],
  },
  exploitability: {
    type: "choice",
    instructions: "Who could exploit `finding`?",
    criteria: {
      anyone_remote: "Any visitor or anyone on the internet, with no account.",
      needs_user_action: "Requires tricking a user into an action.",
      needs_account: "Requires being logged in.",
      not_exploitable: "Not a security weakness.",
      uncertain: "Can't tell from `finding`.",
    },
  },
  placeholder: {
    type: "noul",
    instructions: "Is the `evidence` in `finding` a placeholder, example, test fixture, or documentation rather than real code or configuration?",
    criteria: {
      true: "It is a placeholder, example, test, or docs.",
      false: "It looks like real code or configuration.",
    },
  },
  fix_route: {
    type: "choice",
    instructions: "What kind of fix does `finding` need?",
    criteria: {
      code_change: "Needs a code or config change worth writing out.",
      quick_tip: "A one-line tip is enough.",
      no_fix: "Nothing to fix.",
      uncertain: "Can't tell.",
    },
  },
};

async function callJev(state: unknown, apiKey: string): Promise<{ data: any; latencyMs: number }> {
  const start = Date.now();
  let lastErr = "";
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 400 * Math.pow(2, attempt)));
    }
    try {
      const res = await fetch("https://api.typesafe.ai/v1/systemone", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: JEV_MODEL, state, questions: QUESTIONS }),
      });
      if (res.status === 429 || res.status === 529) {
        lastErr = `Typesafe API ${res.status}`;
        continue;
      }
      if (!res.ok) throw new Error(`Typesafe API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
      const data = await res.json();
      return { data, latencyMs: Date.now() - start };
    } catch (e) {
      lastErr = (e as Error).message;
      if (!lastErr.includes("429") && !lastErr.includes("529")) throw e;
    }
  }
  throw new Error(lastErr || "Typesafe API unreachable after retries");
}

function parseAnswers(data: any) {
  const q = data.questions || {};
  const sev = q.severity || {};
  const exp = q.exploitability || {};
  const ph = q.placeholder || {};
  const fr = q.fix_route || {};
  const usage = data.usage || { input_tokens: 0, output_tokens: 0 };
  const p = ph.noul != null ? Math.abs(2 * ph.noul - 1) : 0;
  return {
    severity: Math.max(0, Math.min(4, Math.round(sev.score ?? 0))),
    severityConf: sev.confidence ?? 0,
    exploitability: exp.choice || "uncertain",
    exploitConf: exp.confidence ?? 0,
    placeholderP: p,
    fixRoute: fr.choice || "uncertain",
    fixRouteConf: fr.confidence ?? 0,
    model: data.model || JEV_MODEL,
    latencyMs: 0,
    usage: { input_tokens: usage.input_tokens || 0, output_tokens: usage.output_tokens || 0 },
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  try {
    const { findings, mode } = await req.json();
    if (!Array.isArray(findings)) return json({ error: "findings array required" }, 400);

    const apiKey = Deno.env.get("TYPESAFE_API_KEY");
    if (!apiKey) {
      const fallback = findings.map((f: Record<string, unknown>) => ({
        rule_id: f.rule_id,
        triage: triage({ auditor: f.auditor as string, rule_id: f.rule_id as string, title: f.title as string, location: f.location as string, evidence: "" }, null),
        mode: "fallback",
      }));
      return json({ results: fallback, mode: "fallback" });
    }

    const results: Array<Record<string, unknown>> = [];
    const CONCURRENCY = 8;
    const queue = [...findings];

    async function worker() {
      while (queue.length > 0) {
        const finding = queue.shift();
        if (!finding) break;
        const state = jevStateFor(finding, mode || "url");
        const injection = typeof finding.evidence_masked === "string" && INJECTION_PATTERNS.test(finding.evidence_masked);
        try {
          const { data, latencyMs } = await callJev(state, apiKey);
          const answers = parseAnswers(data);
          answers.latencyMs = latencyMs;
          if (injection) answers.placeholderP = Math.max(answers.placeholderP, 0.99);
          const t = triage(finding as never, answers);
          results.push({
            rule_id: finding.rule_id,
            jev_request: { model: JEV_MODEL, state, questions: QUESTIONS },
            jev_response: data,
            triage: t,
            mode: "live",
          });
        } catch (e) {
          const t = triage(finding as never, null);
          results.push({
            rule_id: finding.rule_id,
            triage: t,
            mode: "fallback",
            error: (e as Error).message,
          });
        }
      }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, worker));

    const liveResults = results.filter((r) => r.mode === "live");
    const inputTokens = liveResults.reduce((s, r) => s + ((r.triage as { usage?: { input_tokens?: number } }).usage?.input_tokens || 0), 0);
    const cost = (inputTokens * JEV_PRICE_PER_MILLION_INPUT) / 1_000_000;

    return json({ results, mode: "live", jev_cost_usd: cost, model: JEV_MODEL });
  } catch (err) {
    return json({ error: (err as Error).message || "Triage failed" }, 500);
  }
});
