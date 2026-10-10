/*
# Add daily usage cap infrastructure and tighten table grants

1. New Tables
- `usage_counters`: tracks per-edge-function per-day call counts. Columns: fn (text), day (date), calls (int). Primary key (fn, day).
- This table has RLS enabled and NO policies — no anon or authenticated role can read or write it directly.
- All access is through the `increment_usage` SECURITY DEFINER function, executable only by `service_role`.

2. New Functions
- `increment_usage(fn_name text, cap int default 200) returns int`: SECURITY DEFINER, search_path = public.
  Upserts today's row for the given function name, incrementing the call count.
  Returns the new count if under the cap, or -1 if the cap was already reached (no increment performed).
  Called only by edge functions via the service-role client to enforce a daily demo limit.

3. Security changes
- RLS enabled on `usage_counters` with zero policies — locked down completely for anon/authenticated.
- EXECUTE on `increment_usage` revoked from PUBLIC, anon, and authenticated; granted only to `service_role`.
- On `scans` and `findings`: REVOKE UPDATE and DELETE from anon and authenticated roles. The demo only
  needs anon SELECT (read reports by slug) and anon INSERT (create scans/findings). Updates (e.g. ignoring
  a finding) are done through edge functions using the service-role client, which bypasses RLS.

4. Important notes
- No keys, URLs, or JWTs are hardcoded in this migration.
- `increment_usage` uses `current_setting('timezone'::text)` is not needed; `CURRENT_DATE` is used for the day partition.
- The function is idempotent and safe to re-run.
*/

CREATE TABLE IF NOT EXISTS usage_counters (
  fn text NOT NULL,
  day date NOT NULL DEFAULT CURRENT_DATE,
  calls int NOT NULL DEFAULT 0,
  PRIMARY KEY (fn, day)
);

ALTER TABLE usage_counters ENABLE ROW LEVEL SECURITY;

-- Drop all existing policies on usage_counters (there should be none, but be safe)
DO $$
DECLARE r record;
BEGIN
  FOR r IN (SELECT policyname FROM pg_policies WHERE tablename = 'usage_counters' AND schemaname = 'public') LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON usage_counters', r.policyname);
  END LOOP;
END $$;

-- No policies are created on usage_counters — it is fully locked for anon/authenticated.

-- Drop and recreate the increment_usage function to ensure correct definition
DROP FUNCTION IF EXISTS increment_usage(text, int);

CREATE OR REPLACE FUNCTION increment_usage(fn_name text, cap int DEFAULT 200) RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_count int;
BEGIN
  SELECT calls INTO current_count
  FROM usage_counters
  WHERE fn = fn_name AND day = CURRENT_DATE
  FOR UPDATE;

  IF current_count IS NULL THEN
    -- First call today
    INSERT INTO usage_counters (fn, day, calls) VALUES (fn_name, CURRENT_DATE, 1)
    ON CONFLICT (fn, day) DO UPDATE SET calls = usage_counters.calls + 1;
    RETURN 1;
  ELSIF current_count >= cap THEN
    -- Over the cap — do not increment
    RETURN -1;
  ELSE
    UPDATE usage_counters SET calls = calls + 1 WHERE fn = fn_name AND day = CURRENT_DATE;
    RETURN current_count + 1;
  END IF;
END;
$$;

-- Revoke execute from everyone, grant only to service_role
REVOKE EXECUTE ON FUNCTION increment_usage(text, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION increment_usage(text, int) TO service_role;

-- Tighten grants on scans: remove UPDATE and DELETE from anon and authenticated
REVOKE UPDATE ON scans FROM anon, authenticated;
REVOKE DELETE ON scans FROM authenticated;
-- anon DELETE was implicitly granted; revoke explicitly
REVOKE DELETE ON scans FROM anon;

-- Tighten grants on findings: remove UPDATE and DELETE from anon and authenticated
REVOKE UPDATE ON findings FROM anon, authenticated;
REVOKE DELETE ON findings FROM authenticated;
REVOKE DELETE ON findings FROM anon;