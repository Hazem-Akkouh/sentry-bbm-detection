# simulate_sqlplus_attack.ps1
# Reproduces the exact documented attacker command line:
#   cmd.exe /c echo exit | sqlplus -S / as sysdba @[SQL_Statements] > [OUTPUT_FILE]
# Validates SENTRY Rule 2 (process/command-line detection) and, via the
# accompanying attack_payload.sql, Rules 3/4 (DB DELETE/UPDATE audit).

$sqlplusPath = "C:\app\hazem\product\21c\dbhomeXE\BIN\sqlplus.exe"  # adjust to your Oracle install path
$payloadFile = "C:\Allians\attack_payload.sql"
$outputFile  = "C:\Allians\attack_output.log"

cmd.exe /c "echo exit | `"$sqlplusPath`" -S / as sysdba @$payloadFile > $outputFile"

Write-Host "Command executed. Check $outputFile for SQL output."
