# MyLift stop script
# Usage: .\stop.ps1

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PIDFILE = Join-Path $ROOT ".pids"

Write-Host "=== Stopping MyLift ===" -ForegroundColor Cyan

function Stop-ByPid($label, $pidFile) {
    if (Test-Path $pidFile) {
        $id = Get-Content $pidFile -ErrorAction SilentlyContinue
        if ($id) {
            # taskkill /F /T kills the process AND its entire child tree (closes the window)
            $result = taskkill /F /T /PID $id 2>&1
            Write-Host "OK $label (PID $id) stopped" -ForegroundColor Green
        }
        Remove-Item $pidFile -Force
    } else {
        Write-Host "! No PID file for $label, trying port kill..." -ForegroundColor Yellow
    }
}

Stop-ByPid "Backend" (Join-Path $PIDFILE "backend.pid")
Stop-ByPid "Frontend" (Join-Path $PIDFILE "frontend.pid")

# Kill all venv python processes (uvicorn workers / reload processes)
Write-Host "Killing venv Python processes..." -ForegroundColor Yellow
Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*\mylift\.venv\*"
} | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  Killed PID $($_.Id)" -ForegroundColor DarkGray
}

# Fallback: kill by port
Write-Host "Clearing ports 8000 / 5173 ..." -ForegroundColor Yellow
@(8000, 5173) | ForEach-Object {
    $port = $_
    $portPids = netstat -ano | Select-String ":$port\s" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Select-Object -Unique
    foreach ($p in $portPids) {
        if ($p -match '^\d+$' -and $p -ne '0') {
            Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue
            Write-Host "  Port $port -> PID $p stopped" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host "All services stopped." -ForegroundColor Green
