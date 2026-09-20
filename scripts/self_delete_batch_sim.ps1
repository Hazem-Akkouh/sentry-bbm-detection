# self_delete_batch_sim.ps1
# Reproduces evtsys.exe's self-delete mechanism: drops a temp batch file
# that loops deleting a target executable using PING as a portable sleep,
# then deletes itself. Validates SENTRY Rule 7.

$targetExe = "C:\Allians\dummy_evtsys.exe"
"dummy binary content" | Out-File -FilePath $targetExe -Encoding ASCII

$batPath = Join-Path $env:TEMP "evchk.bat"
$batContent = @"
:L1
DEL "$targetExe"
PING 0.0.0.0 > nul
IF EXIST "$targetExe" GOTO L1
DEL "%~f0"
"@
Set-Content -Path $batPath -Value $batContent -Encoding ASCII

Start-Process -FilePath $batPath -WindowStyle Hidden
Write-Host "Dropped and launched $batPath"
