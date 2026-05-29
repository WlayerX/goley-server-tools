# restore-hosts.ps1 -- run from ELEVATED PowerShell
# Removes all GOLEY-EMULATOR lines from hosts file.
$ErrorActionPreference = 'Stop'

$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$marker = '# GOLEY-EMULATOR'

$lines = Get-Content $hosts | Where-Object { $_ -notmatch [Regex]::Escape($marker) }
Set-Content -Path $hosts -Value $lines
ipconfig /flushdns | Out-Null

Write-Host "Removed all emulator hosts entries" -ForegroundColor Green
Get-Content $hosts | Where-Object { $_ -match 'joygame|goley' } | ForEach-Object { Write-Host "  remaining: $_" -ForegroundColor Yellow }
