# MyLift start script
# Usage: powershell -ExecutionPolicy Bypass -File start.ps1

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition
$FRONTEND = Join-Path $ROOT "frontend"
$PIDFILE  = Join-Path $ROOT ".pids"
$LOGDIR   = Join-Path $ROOT ".logs"
$BACKEND_PYTHON = Join-Path $ROOT ".venv\Scripts\python.exe"
$BACKEND_LOG = Join-Path $LOGDIR "backend.log"
$BACKEND_ERR = Join-Path $LOGDIR "backend.err.log"
$FRONTEND_LOG = Join-Path $LOGDIR "frontend.log"
$FRONTEND_ERR = Join-Path $LOGDIR "frontend.err.log"

if (-not (Test-Path $PIDFILE)) { New-Item -ItemType Directory -Path $PIDFILE | Out-Null }
if (-not (Test-Path $LOGDIR)) { New-Item -ItemType Directory -Path $LOGDIR | Out-Null }

function Test-CommandAvailable($Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Wait-ForHttp($Url, $TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return $true
            }
        } catch {
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

if (-not (Test-Path $BACKEND_PYTHON)) {
    Write-Host "Missing virtual environment: $BACKEND_PYTHON" -ForegroundColor Red
    Write-Host "Run: python -m venv .venv ; .\.venv\Scripts\python.exe -m pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-CommandAvailable "npm.cmd") -and -not (Test-CommandAvailable "npm")) {
    Write-Host "npm is not available in PATH." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $FRONTEND "node_modules"))) {
    Write-Host "Frontend dependencies are missing. Installing..." -ForegroundColor Yellow
    Push-Location $FRONTEND
    npm install
    $installExitCode = $LASTEXITCODE
    Pop-Location
    if ($installExitCode -ne 0) {
        Write-Host "npm install failed." -ForegroundColor Red
        exit 1
    }
}

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
$backendJob = Start-Process -FilePath $BACKEND_PYTHON -WorkingDirectory $ROOT -ArgumentList @("-m","uvicorn","backend.main:app","--host","127.0.0.1","--port","8000","--reload") -RedirectStandardOutput $BACKEND_LOG -RedirectStandardError $BACKEND_ERR -PassThru
$backendJob.Id | Set-Content (Join-Path $PIDFILE "backend.pid")

if (-not (Wait-ForHttp "http://127.0.0.1:8000/health" 30)) {
    Write-Host "Backend failed to become healthy." -ForegroundColor Red
    if (-not $backendJob.HasExited) { Stop-Process -Id $backendJob.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "stderr:" -ForegroundColor Yellow
    if (Test-Path $BACKEND_ERR) { Get-Content $BACKEND_ERR -Tail 40 }
    Write-Host "stdout:" -ForegroundColor Yellow
    if (Test-Path $BACKEND_LOG) { Get-Content $BACKEND_LOG -Tail 40 }
    exit 1
}

Write-Host "[2/2] Starting frontend (vite @ http://localhost:5173) ..." -ForegroundColor Yellow
$npmCommand = (Get-Command "npm.cmd" -ErrorAction SilentlyContinue)
if (-not $npmCommand) { $npmCommand = Get-Command "npm" -ErrorAction SilentlyContinue }
$frontendJob = Start-Process -FilePath $npmCommand.Source -WorkingDirectory $FRONTEND -ArgumentList @("run","dev","--","--host","127.0.0.1","--port","5173") -RedirectStandardOutput $FRONTEND_LOG -RedirectStandardError $FRONTEND_ERR -PassThru
$frontendJob.Id | Set-Content (Join-Path $PIDFILE "frontend.pid")

if (-not (Wait-ForHttp "http://127.0.0.1:5173" 30)) {
    Write-Host "Frontend failed to become ready." -ForegroundColor Red
    if (-not $frontendJob.HasExited) { Stop-Process -Id $frontendJob.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "stderr:" -ForegroundColor Yellow
    if (Test-Path $FRONTEND_ERR) { Get-Content $FRONTEND_ERR -Tail 40 }
    Write-Host "stdout:" -ForegroundColor Yellow
    if (Test-Path $FRONTEND_LOG) { Get-Content $FRONTEND_LOG -Tail 40 }
    exit 1
}

Write-Host "Services started:" -ForegroundColor Green
Write-Host "  Backend  -> http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Frontend -> http://localhost:5173"  -ForegroundColor Green
Write-Host "  API Docs -> http://127.0.0.1:8000/api/docs" -ForegroundColor Green
Write-Host "  Logs     -> $LOGDIR" -ForegroundColor Green
Write-Host ""
Write-Host "To stop: powershell -ExecutionPolicy Bypass -File stop.ps1" -ForegroundColor DarkGray
