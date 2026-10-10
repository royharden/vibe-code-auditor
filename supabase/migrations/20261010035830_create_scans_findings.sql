/*
# Create scans and findings tables for Vibe-Code Auditor

1. New Tables
- `scans`: one row per audit run. Holds the target (URL or repo), mode, status, per-file metadata (paths, statuses, sizes, headers — no file bodies), category scores, overall grade, severity counts, Jev triage cost, and the fixer mode used.
- `findings`: one row per auditor finding. Holds masked evidence (first 4 + last 4 characters only), a SHA-256 hash for dedup (never the secret itself), the full Jev request/response pair, Jev's triage outputs (severity score, exploitability choice, placeholder probability, priority), the LLM fix payload, and open/ignored status.

2. Security
- RLS enabled on both tables.
- No sign-in in this app: this is a single public demo workspace, so policies are permissive `TO anon, authenticated` with `USING (true)`.
- Scans: anon can insert new scans and read any scan (reports are shared by slug through the public read). Deletes are not exposed; updates are not needed.
- Findings: anon can insert findings for their scan and read findings. Row scope is by scan via the foreign key join in the UI, not via policy (public demo).

3. Important notes
- The scanner is read-only and passive; the tables never store full fetched file bodies, only metadata, and secrets are always masked before any insert.
- `jev_request`/`jev_response` are stored for transparency of the triage step.
- `file_meta` deliberately excludes response bodies: only paths, HTTP statuses, sizes, and response headers are persisted.
*/

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text UNIQUE NOT NULL,
  target text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('url', 'repo', 'demo')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','fetching','auditing','triaging','fixing','scoring','done','error')),
  file_meta jsonb NOT NULL DEFAULT '[]'::jsonb,
  scores jsonb NOT NULL DEFAULT '{}'::jsonb,
  grade text NOT NULL DEFAULT '',
  counts jsonb NOT NULL DEFAULT '{}'::jsonb,
  jev_cost_usd numeric(12,6) NOT NULL DEFAULT 0,
  fixer_mode text NOT NULL DEFAULT 'llm',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  auditor text NOT NULL,
  rule_id text NOT NULL,
  title text NOT NULL,
  location text NOT NULL DEFAULT '',
  evidence_masked text NOT NULL DEFAULT '',
  secret_hash text,
  jev_request jsonb,
  jev_response jsonb,
  severity numeric(3,1) NOT NULL DEFAULT 0,
  severity_conf numeric(3,2) NOT NULL DEFAULT 0,
  exploitability text NOT NULL DEFAULT 'uncertain',
  exploit_conf numeric(3,2) NOT NULL DEFAULT 0,
  placeholder_p numeric(3,2) NOT NULL DEFAULT 0,
  priority numeric(8,3) NOT NULL DEFAULT 0,
  fix_route text,
  fix jsonb,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','ignored')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_scans" ON scans;
CREATE POLICY "anon_select_scans" ON scans FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_scans" ON scans;
CREATE POLICY "anon_insert_scans" ON scans FOR INSERT TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_select_findings" ON findings;
CREATE POLICY "anon_select_findings" ON findings FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_findings" ON findings;
CREATE POLICY "anon_insert_findings" ON findings FOR INSERT TO anon, authenticated WITH CHECK (true);