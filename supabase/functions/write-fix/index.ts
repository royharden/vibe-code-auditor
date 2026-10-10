import { checkUsage, overLimitResponse, failClosedResponse, json, corsHeaders } from "../_shared/usage.ts";

const MOCK_FIXES: Record<string, { why_it_matters: string; fix_steps: string[]; patch: string; verify_steps: string[] }> = {
  default: {
    why_it_matters: "This finding weakens the security posture of the application and could be exploited if left unaddressed.",
    fix_steps: [
      "Locate the issue at the reported location.",
      "Apply the recommended configuration change.",
      "Redeploy and re-run the audit to confirm the finding is gone.",
    ],
    patch: "# No automatic patch for this rule — apply the steps manually.",
    verify_steps: ["Re-run the audit and confirm the finding no longer appears."],
  },
  openai_key: {
    why_it_matters: "A leaked API key lets anyone use your account and run up charges.",
    fix_steps: [
      "Rotate the key: revoke it in the provider dashboard and issue a new one.",
      "Move the new key to a server-side environment variable.",
      "Remove it from the client bundle and git history.",
    ],
    patch: "// Move to server: process.env.OPENAI_API_KEY — never in client code.\n// Server route example:\n// const res = await fetch('https://api.openai.com/v1/...', {\n//   headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });",
    verify_steps: [
      "Revoke the old key in the provider dashboard.",
      "Search the repo history for the old key prefix.",
      "Re-run the audit and confirm no secrets are found.",
    ],
  },
  rls_missing: {
    why_it_matters: "Without Row Level Security any client with the API key can read and modify every row in the table.",
    fix_steps: [
      "Enable RLS on the table.",
      "Add per-verb policies scoped to the owning user.",
    ],
    patch: "ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY \"select_own\" ON your_table FOR SELECT\n  TO authenticated USING (auth.uid() = user_id);\nCREATE POLICY \"insert_own\" ON your_table FOR INSERT\n  TO authenticated WITH CHECK (auth.uid() = user_id);",
    verify_steps: ["Query the table with an anon client and confirm it returns no rows.", "Confirm signed-in users can still read their own rows."],
  },
  csp_missing: {
    why_it_matters: "Without a Content-Security-Policy the browser has no guardrails against injected scripts.",
    fix_steps: [
      "Add a CSP response header, starting in report-only mode.",
      "Tighten script-src/style-src to the origins you actually use.",
      "Avoid unsafe-inline; use nonces or hashes if inline scripts are required.",
    ],
    patch: "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    verify_steps: ["Check the browser console for CSP violations.", "Re-run the audit and confirm the header is detected."],
  },
  perf_source_map_exposed: {
    why_it_matters: "Public source maps reveal your original source code, comments, and internal structure to anyone.",
    fix_steps: ["Stop uploading or deploying .map files to production.", "Or strip sourceMappingURL comments from production bundles."],
    patch: "// vite.config.ts\nexport default defineConfig({ build: { sourcemap: false } });",
    verify_steps: ["Confirm *.map files are no longer reachable on production.", "Re-run the audit."],
  },
};

function mockFix(ruleId: string) {
  return MOCK_FIXES[ruleId] || MOCK_FIXES.default;
}

function detectStackHints(packageJson?: string): string[] {
  const hints: string[] = [];
  if (packageJson) {
    for (const [pkg, hint] of [
      ["vite", "Vite"],
      ["next", "Next.js"],
      ["@supabase/supabase-js", "Supabase"],
      ["firebase", "Firebase"],
      ["react", "React"],
    ] as Array<[string, string]>) {
      if (packageJson.includes(`"${pkg}"`)) hints.push(hint);
    }
  }
  return hints;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const usage = await checkUsage("write-fix");
  if (!usage.ok) {
    if (usage.over) return overLimitResponse();
    return failClosedResponse(usage.error);
  }

  try {
    const { finding, package_json, mock } = await req.json();
    if (!finding) return json({ error: "finding required" }, 400);

    const apiKey = Deno.env.get("OPENAI_API_KEY");
    const baseUrl = Deno.env.get("OPENAI_BASE_URL") || "https://api.openai.com/v1";
    const model = Deno.env.get("OPENAI_MODEL") || "gpt-6-luna";

    if (mock === true || !apiKey) {
      return json({ fix: mockFix(finding.rule_id), mode: "mock" });
    }

    const stackHints = detectStackHints(package_json);
    const leaked = ["openai_key", "anthropic_key", "aws_key", "stripe_live_key", "github_token", "google_api_key", "slack_token", "private_key", "service_role_jwt", "high_entropy_secret", "committed_env_file"].includes(finding.rule_id);

    const prompt = `You are a security engineer writing a fix for one audit finding.
Stack: ${stackHints.join(", ") || "unknown web app"}.
Finding (evidence is masked; never output any unmasked secret):
${JSON.stringify(finding, null, 2)}
${leaked ? "The first fix step MUST be to rotate the leaked credential." : ""}
Return ONLY JSON with keys: why_it_matters (string), fix_steps (string[]), patch (string — a code snippet or unified diff), verify_steps (string[]).`;

    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
      }),
    });
    if (!res.ok) throw new Error(`LLM error ${res.status}`);
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content || "{}";
    let fix;
    try {
      fix = JSON.parse(content);
    } catch {
      fix = mockFix(finding.rule_id);
    }
    return json({ fix, mode: "llm", model: data.model || model });
  } catch (err) {
    return json({ error: (err as Error).message || "Write-fix failed" }, 500);
  }
});
