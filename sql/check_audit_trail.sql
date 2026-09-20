-- check_audit_trail.sql
-- Verification query: shows every captured DML event across the
-- SAAOWNER schema, in chronological order. Run as SYS.

SELECT event_timestamp, dbusername, action_name, object_name, object_schema, sql_text
FROM unified_audit_trail
WHERE object_schema = 'SAAOWNER'
ORDER BY event_timestamp ASC
FETCH FIRST 100 ROWS ONLY;
