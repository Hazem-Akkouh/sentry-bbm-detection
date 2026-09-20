# Environment Build : Full Walkthrough

## Why a simulation, not the real thing

SWIFT Alliance Access is proprietary, licensed exclusively to SWIFT member institutions through a paid commercial process (a 2011 datasheet lists €43,600 one-time + €14,000/year). No free, trial, or academic-access path exists. This environment simulates the environment class Alliance Access operates within : Windows Server, Oracle Database, the documented file/folder structure : not the proprietary application itself. Every primary forensic source this project draws on did the same thing, for the same reason.

## Stack

- Windows Server 2022 Standard (Desktop Experience), VMware Workstation, host-only networking
- Oracle Database 21c Express Edition, pluggable database `XEPDB1`
- Sysmon, SwiftOnSecurity community baseline + 4 targeted fixes (see below)

## Build order

1. Provision the VM, host-only network
2. Install Sysmon with the SwiftOnSecurity baseline config, then apply the 4 fixes in `../sysmon/`
3. Install Oracle XE 21c
4. Run `../sql/01_create_schema.sql`, `02_create_audit_policy.sql`, `03_insert_dummy_data.sql` in order
5. Build the folder structure: `C:\Allians\mcm\`, `mcp\`, `mcs\`, plus `%LOCALAPPDATA%\Allians\gpca.dat`/`recas.dat`
6. Start `../scripts/message_generator.py` for continuous background traffic
7. Run each emulator script in `../scripts/` to validate its corresponding rule

## Sysmon defects found during this build (see `../sysmon/README.md` for full detail)

1. `ImageLoad` and `ProcessAccess` categories were silently disabled by the baseline config (empty `include` blocks log nothing : not obvious from the config alone)
2. A `name` attribute on a `FileDelete` rule element crashes Sysmon 15.21 with a fast-fail exception (`STATUS_STACK_BUFFER_OVERRUN`) : a known historical bug class for this event category, isolated here via minimal reproduction and worked around by omitting the attribute

## Full connection reference

```
sqlplus SAAOWNER/<password>@//localhost:1521/xepdb1
sqlplus / as sysdba          # OS-authenticated, then: ALTER SESSION SET CONTAINER = XEPDB1;
```
