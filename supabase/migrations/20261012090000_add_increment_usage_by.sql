/*
# Reservable daily usage counter

1. New Functions
- `increment_usage_by(fn_name text, units int, cap int default 200) returns int`: SECURITY DEFINER,
  search_path = public. In a single INSERT ... ON CONFLICT DO UPDATE ... RETURNING statement it adds
  `units` to today's row only if `calls + units <= cap`, and returns the new count. Returns -1 (and
  increments nothing) when the reservation would exceed the cap. Raises on non-positive units/cap so
  a caller can never decrement the counter.
  Edge functions use it to reserve one unit per paid upstream call (e.g. one per Jev request,
  plus one per retry).

2. Changed Functions
- `increment_usage(fn_name text, cap int)` now delegates to `increment_usage_by(fn_name, 1, cap)`,
  so it is atomic too (the previous SELECT ... FOR UPDATE + INSERT version could double-count on
  the first call of the day). Same signature, same return contract.

3. Security
- EXECUTE on both functions: revoked from PUBLIC, anon, authenticated; granted only to service_role.
- `usage_counters`: REVOKE ALL from anon/authenticated (the earlier migration only revoked
  SELECT/INSERT/UPDATE/DELETE, leaving TRUNCATE/REFERENCES/TRIGGER).
- `scans` / `findings`: also revoke TRUNCATE/REFERENCES/TRIGGER from anon/authenticated
  (UPDATE/DELETE were already revoked). anon keeps only the SELECT/INSERT the demo needs.

4. Important notes
- No keys, URLs, or JWTs are hardcoded in this migration.
*/

CREATE OR REPLACE FUNCTION increment_usage_by(fn_name text, units int, cap int DEFAULT 200) RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_count int;
BEGIN
  IF fn_name IS NULL OR units IS NULL OR units < 1 OR cap IS NULL OR cap < 1 THEN
    RAISE EXCEPTION 'increment_usage_by: invalid arguments';
  END IF;

  INSERT INTO usage_counters AS uc (fn, day, calls)
  SELECT fn_name, CURRENT_DATE, units
  WHERE units <= cap
  ON CONFLICT (fn, day) DO UPDATE
    SET calls = uc.calls + EXCLUDED.calls
    WHERE uc.calls + EXCLUDED.calls <= cap
  RETURNING uc.calls INTO new_count;

  -- No row inserted or updated means the reservation would exceed the cap.
  RETURN COALESCE(new_count, -1);
END;
$$;

REVOKE EXECUTE ON FUNCTION increment_usage_by(text, int, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION increment_usage_by(text, int, int) TO service_role;

CREATE OR REPLACE FUNCTION increment_usage(fn_name text, cap int DEFAULT 200) RETURNS int
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT increment_usage_by(fn_name, 1, cap);
$$;

REVOKE EXECUTE ON FUNCTION increment_usage(text, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION increment_usage(text, int) TO service_role;

REVOKE ALL ON usage_counters FROM anon, authenticated;

REVOKE TRUNCATE, REFERENCES, TRIGGER ON scans FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON findings FROM anon, authenticated;
