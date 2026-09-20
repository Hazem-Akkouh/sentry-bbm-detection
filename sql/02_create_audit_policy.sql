-- 02_create_audit_policy.sql
-- Enables Oracle Unified Auditing on all DML actions against the
-- three SAAOWNER tables. Run as SYS, inside XEPDB1, after the schema
-- (01_create_schema.sql) has been created.

CREATE AUDIT POLICY sentry_saaowner_dml
  ACTIONS
    INSERT ON SAAOWNER.MESG_01, UPDATE ON SAAOWNER.MESG_01, DELETE ON SAAOWNER.MESG_01,
    INSERT ON SAAOWNER.TEXT_01, UPDATE ON SAAOWNER.TEXT_01, DELETE ON SAAOWNER.TEXT_01,
    INSERT ON SAAOWNER.JRNL_01, UPDATE ON SAAOWNER.JRNL_01, DELETE ON SAAOWNER.JRNL_01;

AUDIT POLICY sentry_saaowner_dml;

-- To recreate against renamed/rebuilt tables:
-- NOAUDIT POLICY sentry_saaowner_dml;
-- DROP AUDIT POLICY sentry_saaowner_dml;
-- (then re-run the CREATE AUDIT POLICY / AUDIT POLICY statements above)
