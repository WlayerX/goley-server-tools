# setup-hosts.ps1 -- run from ELEVATED PowerShell
# Adds hosts entries so Goley client connects to local emulator.
$ErrorActionPreference = 'Stop'

$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$marker = '# GOLEY-EMULATOR'
$entries = @(
    "127.0.0.1`tcdn.joygamedl.com $marker"
    "127.0.0.1`twww.joygame.com $marker"
)

$existing = Get-Content $hosts -Raw
$backupDir = Join-Path (Split-Path $PSScriptRoot) 'backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$backupPath = Join-Path $backupDir ("hosts.before_emulator_{0}.bak" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Copy-Item $hosts $backupPath -Force
Write-Host "Backed up hosts to $backupPath" -ForegroundColor Green

if ($existing -match [Regex]::Escape($marker)) {
    Write-Host "Marker already present, removing old entries first..." -ForegroundColor Yellow
    $lines = Get-Content $hosts | Where-Object { $_ -notmatch [Regex]::Escape($marker) }
    Set-Content -Path $hosts -Value $lines
}

Add-Content -Path $hosts -Value ""
foreach ($e in $entries) {
    Add-Content -Path $hosts -Value $e
    Write-Host "Added: $e" -ForegroundColor Green
}

ipconfig /flushdns | Out-Null
Write-Host "DNS cache flushed" -ForegroundColor Green

Write-Host ""
Write-Host "WARNING: www.joygame.com redirected to localhost." -ForegroundColor Yellow
Write-Host "This will break browsing to joygame.com from this machine until you run restore-hosts.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start patch server:    bin\patch-server.exe"
Write-Host "  2. Start launcher web:    bin\launcher-web.exe -addr :80   # needs admin"
Write-Host "  3. Start login server:    bin\login-server.exe"
Write-Host "  4. Launch Goley.exe and watch logs/"
