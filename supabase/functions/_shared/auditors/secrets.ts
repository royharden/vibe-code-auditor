import type { FetchedFile } from "../fetch-target.ts";
import { maskEvidence, hashSecret } from "../mask.ts";

export interface Finding {
  auditor: string;
  rule_id: string;
  title: string;
  location: string;
  evidence: string;
  in_client_bundle?: boolean;
  mode?: string;
  context?: string;
  secretHash?: string | null;
}

type RawF = Omit<Finding, "evidence"> & { evidence?: string };

function push(out: Finding[], f: RawF) {
  out.push({ ...f, evidence: f.evidence ? maskEvidence(f.evidence) : "", secretHash: f.secretHash ?? null } as Finding);
}

const RULES: Array<{ rule_id: string; title: string; re: RegExp; sev_hint?: number }> = [
  { rule_id: "openai_key", title: "OpenAI API key found", re: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { rule_id: "anthropic_key", title: "Anthropic API key found", re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { rule_id: "aws_key", title: "AWS access key found", re: /AKIA[0-9A-Z]{16}/g },
  { rule_id: "stripe_live_key", title: "Stripe live secret key found", re: /(?:sk|rk)_live_[A-Za-z0-9]{16,}/g },
  { rule_id: "github_token", title: "GitHub token found", re: /ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}/g },
  { rule_id: "google_api_key", title: "Google API key found", re: /AIza[0-9A-Za-z_-]{30,}/g },
  { rule_id: "slack_token", title: "Slack token found", re: /xox[bp]-[A-Za-z0-9-]{10,}/g },
  { rule_id: "private_key", title: "PEM private key found", re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g },
];

function highEntropy(s: string): boolean {
  if (s.length < 20) return false;
  const unique = new Set(s).size;
  return unique / s.length > 0.5;
}

function decodeJwtRole(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.role ?? null;
  } catch {
    return null;
  }
}

export function auditSecrets(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  const clientKinds = new Set(["page", "asset", "cdn", "source", "html", "package"]);

  for (const file of files) {
    const text = file.text || "";
    if (!text) continue;
    const inClient = clientKinds.has(file.kind);
    const loc = file.path;

    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.re.exec(text)) !== null) {
        const value = m[0];
        push(out, {
          auditor: "Secrets",
          rule_id: rule.rule_id,
          title: rule.title,
          location: loc,
          evidence: `…${value.slice(0, 30)}…`,
          in_client_bundle: inClient,
          mode,
          secretHash: hashSecret(value),
        });
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      }
    }

    const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g;
    let jm: RegExpExecArray | null;
    while ((jm = jwtRe.exec(text)) !== null) {
      const role = decodeJwtRole(jm[0]);
      if (role === "service_role") {
        push(out, {
          auditor: "Secrets",
          rule_id: "service_role_jwt",
          title: "Supabase service_role JWT found",
          location: loc,
          evidence: jm[0].slice(0, 40),
          in_client_bundle: inClient,
          mode,
          secretHash: hashSecret(jm[0]),
        });
      }
    }

    const assignRe = /(["']?)([A-Z0-9_]*(?:SECRET|KEY|TOKEN)[A-Z0-9_]*)\1\s*[:=]\s*["']([^"']{20,})["']/g;
    let am: RegExpExecArray | null;
    while ((am = assignRe.exec(text)) !== null) {
      const name = am[2];
      const value = am[3];
      if (!highEntropy(value)) continue;
      if (RULES.some((r) => r.re.test(value))) continue;
      push(out, {
        auditor: "Secrets",
        rule_id: "high_entropy_secret",
        title: `High-entropy value assigned to ${name}`,
        location: loc,
        evidence: `${name}="…${value.slice(0, 20)}…"`,
        in_client_bundle: inClient,
        mode,
        secretHash: hashSecret(value),
      });
    }

    if (/\.env/.test(file.path) && file.kind === "env" && text.trim()) {
      push(out, {
        auditor: "Secrets",
        rule_id: "committed_env_file",
        title: "Committed .env file in repository",
        location: loc,
        evidence: `${file.path} (${text.split("\n").length} lines)`,
        in_client_bundle: false,
        mode,
      });
    }

    const vitePublicRe = /(VITE_[A-Z0-9_]*(?:SECRET|KEY|TOKEN)[A-Z0-9_]*|NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|KEY|TOKEN)[A-Z0-9_]*)\s*[:=]/g;
    let vm: RegExpExecArray | null;
    while ((vm = vitePublicRe.exec(text)) !== null) {
      push(out, {
        auditor: "Secrets",
        rule_id: "public_secret_var",
        title: `Public env variable with secret-like name: ${vm[1]}`,
        location: loc,
        evidence: vm[0].slice(0, 60),
        in_client_bundle: true,
        mode,
      });
    }
  }
  return out;
}
