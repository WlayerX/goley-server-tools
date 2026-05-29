# Goley server emulator -- start all components.
# Run as Administrator: port 80 + dump access.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Build everything fresh
Write-Host "Building all servers..." -ForegroundColor Cyan
Push-Location $root
go build -o entry-server.exe ./cmd/entry-server
go build -o lobby-server.exe ./cmd/lobby-server
go build -o battle-server.exe ./cmd/battle-server
go build -o daum-auth.exe ./cmd/daum-auth
go build -o patch-server.exe ./cmd/patch-server
go build -o launcher-web.exe ./cmd/launcher-web
Pop-Location

# Start everything in separate windows
$exes = @(
  @{ Name = 'patch-server';   Path = "$root\patch-server.exe";   Port = 80    },
  @{ Name = 'daum-auth';      Path = "$root\daum-auth.exe";      Port = 8081  },
  @{ Name = 'launcher-web';   Path = "$root\launcher-web.exe";   Port = 8080  },
  @{ Name = 'entry-server';   Path = "$root\entry-server.exe";   Port = 2270  },
  @{ Name = 'lobby-server';   Path = "$root\lobby-server.exe";   Port = 2271  },
  @{ Name = 'battle-server';  Path = "$root\battle-server.exe";  Port = 2272  }
)

foreach ($e in $exes) {
  if (-not (Test-Path $e.Path)) {
    Write-Warning "$($e.Name) not built -- skipping"
    continue
  }
  Start-Process -FilePath $e.Path -WindowStyle Normal
  Write-Host ("Started {0,-15} (port {1})" -f $e.Name, $e.Port) -ForegroundColor Green
  Start-Sleep -Milliseconds 250
}

Write-Host "`nAll started. Ports listening:" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 80,2270,2271,2272,8080,8081 } |
  Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table

Write-Host "`nTo stop everything:" -ForegroundColor Yellow
Write-Host '  Get-Process patch-server,daum-auth,launcher-web,entry-server,lobby-server,battle-server -EA SilentlyContinue | Stop-Process'
