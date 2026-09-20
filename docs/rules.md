# /rules  Detail Guide

8 SIGMA rules, derived from the behavior taxonomy in [SENTRY01.md](../SENTRY01.md), Section 4-5. Convert with [pySigma](https://github.com/SigmaHQ/pySigma) or [sigconverter.io](https://sigconverter.io).

| File | Behavior detected | Log source | Type |
|---|---|---|---|
| `SENTRY_Rule1_liboradb_access.yml` | Memory-write access to a process hosting liboradb.dll | Sysmon Event ID 10 (ProcessAccess) | Single-event |
| `SENTRY_Rule2_sqlplus_sysdba_piped.yml` | Piped, silent SYSDBA sqlplus execution | Sysmon Event ID 1 (ProcessCreate) | Single-event |
| `SENTRY_Rule3_saaowner_delete.yml` | DELETE on SAAOWNER.MESG_%/TEXT_% | Oracle Unified Audit | Single-event |
| `SENTRY_Rule4_saaowner_balance_update.yml` | UPDATE of MESG_FIN_CCY_AMOUNT | Oracle Unified Audit | Single-event |
| `SENTRY_Rule5_swift_message_file_monitoring.yml` | SWIFT confirmation content in message files | Sysmon Event ID 11 (FileCreate) | Single-event |
| `SENTRY_Rule6_secure_delete_correlation.yml` | Zero-fill → rename → delete anti-forensic pattern | Sysmon Event ID 11 + 23 | **Correlation (multi-event)** |
| `SENTRY_Rule7_self_delete_via_batch.yml` | PING-delay self-deletion batch pattern | Sysmon Event ID 1 (ProcessCreate) | Single-event |
| `SENTRY_Rule8_binary_masquerade_swap.yml` | Legitimate binary backed up + replaced | Sysmon Event ID 11 (FileCreate) | Single-event |

**Known limitation:** Rule 6 uses SIGMA's native `correlation` construct. It converts successfully to Splunk SPL but fails on Microsoft Sentinel (Kusto) with an explicit backend error  current pySigma Kusto backend does not yet implement SIGMA correlation rules. See [SENTRY01.md](../SENTRY01.md) Section 9.2 for full evidence.

**Filter placeholders:** Rules 3 and 4 contain a placeholder `dbusername: 'SAA_SERVICE'`  replace with your actual authorized Alliance Access service account name before deploying.
