-- attack_payload.sql
-- The SQL payload used by simulate_sqlplus_attack.ps1. Reproduces the
-- exact preamble sequence documented in the malware analysis
-- (SET FEEDBACK OFF, set linesize 32567, etc.) followed by the
-- documented deletion order (TEXT_ before MESG_). Validates Rules 2/3.

ALTER SESSION SET CONTAINER = XEPDB1;
set heading off;
set linesize 32567;
SET FEEDBACK OFF;
SET ECHO OFF;
SET FEED OFF;
SET VERIFY OFF;
DELETE FROM SAAOWNER.TEXT_01 WHERE TEXT_S_UMID = 'UMID00001';
DELETE FROM SAAOWNER.MESG_01 WHERE MESG_S_UMID = 'UMID00001';
COMMIT;
exit;
