# MyLift start script
# Usage: powershell -ExecutionPolicy Bypass -File start.ps1

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition
$FRONTEND = Join-Path $ROOT "frontend"
$PIDFILE  = Join-Path $ROOT ".pids"

if (-not (Test-Path $PIDFILE)) { New-Item -ItemType Directory -Path $PIDFILE | Out-Null }

Write-Host "Cleaning up leftover processes..." -ForegroundColor DarkGray
Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*\mylift\.venv\*"
} | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
@(8000, 5173) | ForEach-Object {
    $port = $_
    $portPids = netstat -ano | Select-String ":$port" | ForEach-Object { ($_ -split "\s+")[-1] } | Select-Object -Unique
    foreach ($p in $portPids) {
        if ($p -match "^\d+$" -and $p -ne "0") { Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue }
    }
}
Start-Sleep -Seconds 1

Write-Host "=== Starting MyLift ===" -ForegroundColor Cyan

Write-Host "[1/2] Starting backend (uvicorn @ http://127.0.0.1:8000) ..." -ForegroundColor Yellow
$backendJob = Start-Process powershell -ArgumentList @("-NoExit","-Command","cd '$ROOT'; .\.venv\Scripts\activate; python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload") -PassThru
$backendJob.Id | Set-Content (Join-Path $PIDFILE "backend.pid")

Write-Host "[2/2] Starting frontend (vite @ http://localhost:5173) ..." -ForegroundColor Yellow
$frontendJob = Start-Process cmd -ArgumentList @("/k","cd /d `"$FRONTEND`" && npm run dev") -PassThru
$frontendJob.Id | Set-Content (Join-Path $PIDFILE "frontend.pid")

Write-Host "Services started:" -ForegroundColor Green
Write-Host "  Backend  -> http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Frontend -> http://localhost:5173"  -ForegroundColor Green
Write-Host "  API Docs -> http://127.0.0.1:8000/api/docs" -ForegroundColor Green
Write-Host ""
Write-Host "To stop: powershell -ExecutionPolicy Bypass -File stop.ps1" -ForegroundColor DarkGray
