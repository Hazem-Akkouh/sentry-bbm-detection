# binary_swap_sim.ps1
# Simulates the legitimate-binary swap masquerade technique: backs up
# an original file to .bak, then drops a replacement under the original
# name. Validates SENTRY Rule 8.

$original = "C:\Allians\nroff.exe"
"legitimate nroff binary placeholder" | Out-File -FilePath $original -Encoding ASCII

Rename-Item -Path $original -NewName "nroff.exe.bak"
"malicious replacement placeholder" | Out-File -FilePath $original -Encoding ASCII
Write-Host "Swap complete: original backed up, replacement in place."
