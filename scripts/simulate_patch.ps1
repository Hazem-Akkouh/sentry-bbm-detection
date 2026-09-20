# simulate_patch.ps1
# Opens a handle to the target process with memory-write-capable access
# rights, simulating the access pattern used before a memory patch.
# No memory is actually modified -- this only tests whether the access
# attempt itself is logged (Sysmon Event ID 10). Validates SENTRY Rule 1.
#
# Usage: update $targetPid to match the currently running dummy_host.exe
# PID before each run, then:
#   powershell -ExecutionPolicy Bypass -File simulate_patch.ps1

$targetPid = 9992  # <-- must match current dummy_host.exe PID before running

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ProcAccess {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

$PROCESS_VM_WRITE = 0x0020
$PROCESS_VM_OPERATION = 0x0008
$access = $PROCESS_VM_WRITE -bor $PROCESS_VM_OPERATION

$handle = [ProcAccess]::OpenProcess($access, $false, $targetPid)

if ($handle -eq [IntPtr]::Zero) {
    Write-Host "Failed to open process handle."
} else {
    Write-Host "Successfully opened handle to PID $targetPid with VM_WRITE/VM_OPERATION access."
    [ProcAccess]::CloseHandle($handle)
}
