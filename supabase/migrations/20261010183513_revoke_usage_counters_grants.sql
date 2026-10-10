/*
# Revoke all table-level grants on usage_counters

usage_counters has RLS enabled with zero policies, so no anon/authenticated
rows are accessible. This migration also revokes the table-level DML grants
(SELECT, INSERT, UPDATE, DELETE) from anon and authenticated as defense in
depth — only the service_role (via the SECURITY DEFINER increment_usage
function) should touch this table.
*/

REVOKE SELECT, INSERT, UPDATE, DELETE ON usage_counters FROM anon, authenticated;