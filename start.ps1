# TriageScript launcher (PowerShell)
# Installs dependencies on first run, then starts the local web UI, which opens
# your browser automatically. Pass extra args through, e.g.:  .\start.ps1 --port 9000
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Locate a Python interpreter: prefer a local .venv, then a shared repo .venv,
# then system Python.
$py = $null
foreach ($candidate in @(
        (Join-Path $PSScriptRoot ".venv\Scripts\python.exe"),
        (Join-Path $PSScriptRoot "..\..\..\.venv\Scripts\python.exe"))) {
    if (Test-Path $candidate) { $py = (Resolve-Path $candidate).Path; break }
}
if (-not $py) {
    if (Get-Command py -ErrorAction SilentlyContinue) { $py = "py" }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
    else { Write-Error "No Python interpreter found. Install Python or create a .venv."; exit 1 }
}

Write-Host "Using Python: $py" -ForegroundColor Cyan

# Install dependencies only if oletools is missing.
& $py -c "import oletools" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & $py -m pip install -q -r requirements.txt
}

Write-Host "Starting TriageScript web UI (a browser tab will open)..." -ForegroundColor Green
& $py -m triagescript.web @args
