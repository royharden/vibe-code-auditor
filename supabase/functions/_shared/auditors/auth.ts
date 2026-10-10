import type { FetchedFile } from "../fetch-target.ts";
import type { Finding } from "./secrets.ts";

export function auditAuth(files: FetchedFile[], mode: string): Finding[] {
  const out: Finding[] = [];
  const add = (f: Omit<Finding, "auditor">) => out.push({ auditor: "Auth & RLS", ...f });

  const migrations = files.filter((f) => /supabase\/migrations\/.*\.sql$/i.test(f.path) || f.kind === "migration");

  for (const mig of migrations) {
    const sql = (mig.text || "").toLowerCase();
    if (!sql) continue;
    const tables = [...sql.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?["`]?([\w.]+)["`]?/gi)].map((m) => m[1]);
    for (const table of tables) {
      const bare = table.split(".").pop() || table;
      const escaped = bare.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const rlsRe = new RegExp(`enable\\s+row\\s+level\\s+security[\\s\\S]{0,400}?["\`]?(?:public\\.)?${escaped}["\`]?|alter\\s+table[\\s\\S]{0,40}?["\`]?(?:public\\.)?${escaped}["\`]?\\s+enable\\s+row\\s+level\\s+security`, "i");
      if (!rlsRe.test(sql)) {
        add({
          rule_id: "rls_missing",
          title: `No ENABLE ROW LEVEL SECURITY found for table "${bare}"`,
          location: mig.path,
          evidence: `create table ${bare} … (no matching RLS enable)`,
          mode,
          context: "Hint from migration text only — confirm in the Supabase dashboard.",
        });
      }
    }
    const updateTrue = [...sql.matchAll(/create\s+policy[^;]*?for\s+update[^;]*?using\s*\(\s*true\s*\)/gis)];
    for (const p of updateTrue) {
      add({
        rule_id: "rls_using_true_update",
        title: "UPDATE policy uses USING (true)",
        location: mig.path,
        evidence: p[0].slice(0, 200),
        mode,
        context: "Any authenticated client can modify any row.",
      });
    }
    const deleteTrue = [...sql.matchAll(/create\s+policy[^;]*?for\s+delete[^;]*?using\s*\(\s*true\s*\)/gis)];
    for (const p of deleteTrue) {
      add({
        rule_id: "rls_using_true_delete",
        title: "DELETE policy uses USING (true)",
        location: mig.path,
        evidence: p[0].slice(0, 200),
        mode,
        context: "Any authenticated client can delete any row.",
      });
    }
  }

  const clientKinds = new Set(["page", "asset", "cdn", "source", "html"]);
  for (const file of files) {
    if (!clientKinds.has(file.kind)) continue;
    const text = file.text || "";
    if (!text) continue;
    const serviceClient = /createClient\s*\([\s\S]{0,200}?(service_role|SERVICE_ROLE)/i.test(text);
    if (serviceClient) {
      add({
        rule_id: "service_key_in_client",
        title: "Supabase client created with a service role key in client code",
        location: file.path,
        evidence: "createClient(… service_role …)",
        in_client_bundle: true,
        mode,
      });
    }
    const firebaseOpen = /allow\s+(read|write)\s*:\s*if\s*true\s*;/i.test(text);
    if (firebaseOpen) {
      add({
        rule_id: "firebase_rules_open",
        title: "Firebase security rule allows open read/write",
        location: file.path,
        evidence: "allow read, write: if true;",
        mode,
      });
    }
    const adminClient = /(?:is_admin|isadmin|role\s*===?\s*["']admin["'])/i.test(text);
    const adminServer = /rpc\s*\(\s*["']is_admin|security\s+definer|has_role/i.test(text);
    if (adminClient && !adminServer) {
      add({
        rule_id: "admin_check_client_only",
        title: "Admin check appears to exist only in client code",
        location: file.path,
        evidence: "role === \"admin\" (no server-side check found)",
        mode,
        context: "Client-side checks can be bypassed; enforce with RLS or an RPC.",
      });
    }
  }

  const anonKey = files.some((f) => f.text && /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/.test(f.text) && (f.kind === "page" || f.kind === "asset"));
  if (anonKey) {
    add({
      rule_id: "anon_key_public",
      title: "Supabase anon key present in client bundle",
      location: "(client bundle)",
      evidence: "anon JWT in JS",
      in_client_bundle: true,
      mode,
      context: "Public by design. Confirm RLS on every table.",
    });
  }
  return out;
}
