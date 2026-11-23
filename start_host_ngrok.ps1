# Starts the SENTINEL X host AND an ngrok tunnel to the ingest-only listener (127.0.0.1:8090).
# The dashboard (8080) is never tunnelled. Usage:  .\start_host_ngrok.ps1   [-JoinCode mycode]
param([string]$JoinCode = "")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$PublicPort = 8090   # fixed on purpose: this is the only port ngrok may ever be pointed at

# Locate ngrok: prefer ngrok.exe next to this script (independent of the working directory), else PATH.
$LocalNgrok = Join-Path $PSScriptRoot "ngrok.exe"
if (Test-Path -LiteralPath $LocalNgrok -PathType Leaf) {
    $NgrokExe = $LocalNgrok
} else {
    $cmd = Get-Command ngrok -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { $NgrokExe = $cmd.Source }
}
if (-not $NgrokExe) {
    Write-Host "ngrok not found. Put ngrok.exe in $PSScriptRoot or install it on PATH (https://ngrok.com/download), then run once: ngrok config add-authtoken <your token>" -ForegroundColor Red
    exit 1
}
Write-Host "Using ngrok: $NgrokExe" -ForegroundColor DarkGray
if (-not $JoinCode) {   # cryptographically random join code
    $b = New-Object byte[] 6; $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b)
    $JoinCode = ([BitConverter]::ToString($b) -replace '-', '').ToLower()
}
$env:SENTINEL_JOIN_CODE = $JoinCode
$env:SAAS_PUBLIC_PORT = "$PublicPort"

Write-Host "Starting SENTINEL X host..." -ForegroundColor Cyan
$host_ = Start-Process python -ArgumentList "run_host.py" -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 6
if ($host_.HasExited) { Write-Host "Host failed to start (is port 8080/8443/$PublicPort in use?)" -ForegroundColor Red; exit 1 }

Write-Host "Starting ngrok tunnel -> http://127.0.0.1:$PublicPort (ingest only)..." -ForegroundColor Cyan
$ng = Start-Process -FilePath $NgrokExe -ArgumentList "http", "http://127.0.0.1:$PublicPort" -PassThru -WindowStyle Minimized
$url = $null
for ($i = 0; $i -lt 20 -and -not $url; $i++) {
    Start-Sleep -Seconds 1
    try { $url = (Invoke-RestMethod http://127.0.0.1:4040/api/tunnels).tunnels | Where-Object { $_.public_url -like "https://*" } | Select-Object -First 1 -ExpandProperty public_url } catch {}
}
if (-not $url) { Write-Host "Could not read the ngrok URL. Check the ngrok window / authtoken." -ForegroundColor Red }
Write-Host ""
Write-Host "================ GIVE YOUR FRIENDS ================" -ForegroundColor Green
Write-Host "  Server URL : $url"
Write-Host "  Join code  : $JoinCode"
Write-Host "===================================================" -ForegroundColor Green
Write-Host "Dashboard (local only): http://127.0.0.1:8080   (acme-admin / Acme#Admin2026)"
Write-Host "Press Ctrl+C or close this window to stop the host and the tunnel."
try { while ($true) { Start-Sleep -Seconds 2; if ($host_.HasExited) { break } } }
finally {
    foreach ($p in @($ng, $host_)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}
