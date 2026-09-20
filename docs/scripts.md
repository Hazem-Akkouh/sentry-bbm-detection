# /scripts : Detail Guide

Emulator scripts that reproduce each documented malware behavior for validation purposes. **The real malware was never sourced, downloaded, or executed at any point in this project** : every script here is original code, authored from scratch based on publicly documented behavior (BAE Systems, U.S. DOJ, Oosthoek & Doerr 2021).

| File | Reproduces | Validates | Run as |
|---|---|---|---|
| `dummy_host.cs` | A process with a stand-in DLL loaded (target for Rule 1) | Rule 1 (setup) | Compile with `csc.exe dummy_host.cs`, then run the .exe |
| `simulate_patch.ps1` | Memory-write access attempt to the dummy host | Rule 1 | PowerShell |
| `simulate_sqlplus_attack.ps1` | The documented `cmd.exe /c echo exit \| sqlplus ...` pattern | Rule 2, 3, 4 (with `../sql/attack_payload.sql`) | PowerShell |
| `secure_delete_sim.ps1` | Zero-fill → rename → delete sequence | Rule 6 | PowerShell |
| `self_delete_batch_sim.ps1` | The `evchk.bat` PING-delay self-delete pattern | Rule 7 | PowerShell |
| `binary_swap_sim.ps1` | Backup-then-replace masquerade pattern | Rule 8 | PowerShell |
| `message_generator.py` | Continuous, mixed-content SWIFT message file generation | Rule 5 (background traffic) | `python message_generator.py` |

**Before running any script**, edit hardcoded paths (Oracle install location, target PIDs) to match your own environment. `simulate_patch.ps1` in particular requires updating `$targetPid` to match the currently-running `dummy_host.exe` process each time.
