import { triage, type RawFinding, type Severity } from "../_shared/policy.ts";
import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";
import { readJsonBody, isRecord, clip } from "../_shared/request.ts";

const JEV_MODEL = "jev-1.13.0";
const JEV_PRICE_PER_MILLION_INPUT = 0.042;
const JEV_API_URL = "https://api.typesafe.ai/v1/systemone";

const MAX_BODY_BYTES = 512 * 1024;
const MAX_FINDINGS = 50;
const MAX_FIELD_CHARS = 300;
const MAX_JEV_ATTEMPTS = 2;

const INJECTION_PATTERNS = /ignore (all |any )?previous|disregard (all |any )?instructions|system prompt|you are now|new instructions:/i;

interface TriageFinding {
  auditor?: string;
  rule_id?: string;
  title?: string;
  location?: string;
  evidence_masked?: string;
  in_client_bundle: boolean;
}

// Only these fields reach Jev, each truncated; any other keys in the request are ignored.
function sanitizeFinding(f: Record<string, unknown>): TriageFinding {
  return {
    auditor: clip(f.auditor, MAX_FIELD_CHARS),
    rule_id: clip(f.rule_id, MAX_FIELD_CHARS),
    title: clip(f.title, MAX_FIELD_CHARS),
    location: clip(f.location, MAX_FIELD_CHARS),
    evidence_masked: clip(f.evidence_masked, MAX_FIELD_CHARS),
    in_client_bundle: f.in_client_bundle === true,
  };
}

function policyInput(f: TriageFinding, evidence: string): RawFinding {
  return { auditor: f.auditor ?? "", rule_id: f.rule_id ?? "", title: f.title ?? "", location: f.location ?? "", evidence };
}

function jevStateFor(finding: TriageFinding, mode: string) {
  return {
    finding: {
      auditor: finding.auditor,
      rule_id: finding.rule_id,
      title: finding.title,
      location: finding.location,
      evidence: finding.evidence_masked,
      in_client_bundle: finding.in_client_bundle,
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

// The first attempt for each finding is covered by the up-front reservation; every retry
// reserves one more unit first. Retries only on 429/529 or network errors, never after the
// daily limit or a failed usage check. Upstream error text is logged, never returned.
async function callJev(state: unknown, apiKey: string): Promise<{ data: any; latencyMs: number }> {
  const start = Date.now();
  let lastErr = "Typesafe API unreachable";
  for (let attempt = 0; attempt < MAX_JEV_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 400 * Math.pow(2, attempt)));
      const retry = await checkUsage("jev-triage", 1);
      if (!retry.ok) {
        if (!retry.over) console.error(`jev-triage: usage check failed before retry: ${retry.error}`);
        throw new Error(retry.over ? "Daily limit reached" : "Usage check failed");
      }
    }
    let res: Response;
    try {
      res = await fetch(JEV_API_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: JEV_MODEL, state, questions: QUESTIONS }),
      });
    } catch (e) {
      console.error(`jev-triage: network error: ${(e as Error).message}`);
      lastErr = "Typesafe API unreachable";
      continue;
    }
    if (res.status === 429 || res.status === 529) {
      await res.body?.cancel().catch(() => {});
      lastErr = `Typesafe API ${res.status}`;
      continue;
    }
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      console.error(`jev-triage: Typesafe API error ${res.status}: ${detail.slice(0, 500)}`);
      throw new Error(`Typesafe API error ${res.status}`);
    }
    const data = await res.json().catch(() => {
      throw new Error("Typesafe API returned an invalid response");
    });
    return { data, latencyMs: Date.now() - start };
  }
  throw new Error(lastErr);
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
    severity: Math.max(0, Math.min(4, Math.round(sev.score ?? 0))) as Severity,
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

  const usage = await checkUsage("jev-triage");
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  const body = await readJsonBody(req, MAX_BODY_BYTES);
  if (!body.ok) return body.response;

  try {
    const { findings: rawFindings, mode: rawMode } = body.data;
    if (!Array.isArray(rawFindings)) return json({ error: "findings array required" }, 400);
    if (rawFindings.length > MAX_FINDINGS) return json({ error: `Too many findings (max ${MAX_FINDINGS} per request)` }, 400);
    if (!rawFindings.every(isRecord)) return json({ error: "each finding must be an object" }, 400);
    const findings = rawFindings.map(sanitizeFinding);
    const mode = clip(rawMode, 20) || "url";

    const apiKey = Deno.env.get("TYPESAFE_API_KEY");
    if (!apiKey) {
      const fallback = findings.map((f) => ({
        rule_id: f.rule_id,
        triage: triage(policyInput(f, ""), null),
        mode: "fallback",
      }));
      return json({ results: fallback, mode: "fallback" });
    }
    const key: string = apiKey;

    // Reserve one unit per Jev request before making any of them.
    if (findings.length > 0) {
      const reserved = await checkUsage("jev-triage", findings.length);
      if (!reserved.ok) {
        if (reserved.over) return overLimitResponse();
        return failClosedResponse(reserved.error);
      }
    }

    const results: Array<Record<string, unknown>> = [];
    const CONCURRENCY = 8;
    const queue = [...findings];

    async function worker() {
      while (queue.length > 0) {
        const finding = queue.shift();
        if (!finding) break;
        const state = jevStateFor(finding, mode);
        const injection = typeof finding.evidence_masked === "string" && INJECTION_PATTERNS.test(finding.evidence_masked);
        try {
          const { data, latencyMs } = await callJev(state, key);
          const answers = parseAnswers(data);
          answers.latencyMs = latencyMs;
          if (injection) answers.placeholderP = Math.max(answers.placeholderP, 0.99);
          const t = triage(policyInput(finding, finding.evidence_masked ?? ""), answers);
          results.push({
            rule_id: finding.rule_id,
            jev_request: { model: JEV_MODEL, state, questions: QUESTIONS },
            jev_response: data,
            triage: t,
            mode: "live",
          });
        } catch (e) {
          const t = triage(policyInput(finding, finding.evidence_masked ?? ""), null);
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
    console.error(`jev-triage: ${(err as Error).message}`);
    return json({ error: "Triage failed" }, 500);
  }
});

// verify_jwt=true
