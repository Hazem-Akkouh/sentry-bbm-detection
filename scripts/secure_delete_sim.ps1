# secure_delete_sim.ps1
# Reproduces the exact documented secure-delete algorithm from evtsys.exe:
#   (1) open the file, (2) write a 1-byte probe at the end and flush,
#   (3) overwrite the entire file with zeros in 4KB chunks,
#   (4) rename the file to a random lowercase string of the same length,
#   (5) delete the renamed file.
# Validates SENTRY Rule 6 (FileCreate + FileDelete correlation).

$targetPath = "C:\Allians\dummy_target.dat"

# Step A: open file, write 1-byte probe at end, flush
$stream = [System.IO.File]::Open($targetPath, 'Open', 'Write')
$stream.Seek(0, 'End') | Out-Null
$stream.WriteByte(0)
$stream.Flush()

# Step B: overwrite entire file content with zeros, in 4KB chunks
$fileSize = (Get-Item $targetPath).Length
$stream.Seek(0, 'Begin') | Out-Null
$zeroChunk = New-Object byte[] 4096
$written = 0
while ($written -lt $fileSize) {
    $chunkSize = [Math]::Min(4096, $fileSize - $written)
    $stream.Write($zeroChunk, 0, $chunkSize)
    $written += $chunkSize
}
$stream.Flush()
$stream.Close()

Write-Host "File zero-filled ($fileSize bytes)."

# Step C: rename to a random lowercase string, same length as original filename
$originalName = [System.IO.Path]::GetFileName($targetPath)
$dir = [System.IO.Path]::GetDirectoryName($targetPath)
$randomName = -join ((97..122) | Get-Random -Count $originalName.Length | ForEach-Object { [char]$_ })
$randomPath = Join-Path $dir $randomName

Rename-Item -Path $targetPath -NewName $randomName
Write-Host "Renamed to: $randomName"

# Step D: delete the renamed file
Remove-Item -Path $randomPath -Force
Write-Host "Deleted. Secure-delete sequence complete."
