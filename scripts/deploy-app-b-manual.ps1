param(
  [string]$ResourceGroup = "rg-portal-app-prod",
  [string]$WebAppName = "leadi-portal-app-prod-001",
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$serverDir = Join-Path $repoRoot "server"
$distDir = Join-Path $repoRoot "dist"
$serverPublicDir = Join-Path $serverDir "public"
$zipPath = Join-Path $repoRoot "appb-manual-deploy.zip"
$zipHelper = Join-Path $scriptDir "create_linuxsafe_zip.py"

Write-Host "[1/6] Checking prerequisites..."
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw "Azure CLI (az) is required."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw "npm is required."
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw "python is required."
}

Write-Host "[2/6] Building frontend..."
Push-Location $repoRoot
if (-not $SkipInstall) {
  npm ci
} else {
  Write-Host "Skipping npm ci (--SkipInstall enabled)."
}
npm run build
Pop-Location

if (-not (Test-Path $distDir)) {
  throw "Build output not found: $distDir"
}

Write-Host "[3/6] Copying frontend into server/public..."
if (Test-Path $serverPublicDir) {
  Remove-Item $serverPublicDir -Recurse -Force
}
New-Item -ItemType Directory -Path $serverPublicDir -Force | Out-Null
Copy-Item (Join-Path $distDir "*") $serverPublicDir -Recurse -Force

Write-Host "[4/6] Creating Linux-safe deployment zip..."
python $zipHelper --src $serverDir --out $zipPath
if (-not (Test-Path $zipPath)) {
  throw "Zip file was not created: $zipPath"
}

Write-Host "[5/6] Deploying to Azure Web App..."
az webapp deployment source config-zip --resource-group $ResourceGroup --name $WebAppName --src $zipPath | Out-Null

Write-Host "[6/6] Running smoke checks..."
$baseUrl = "https://$WebAppName.azurewebsites.net"
$homeStatus = curl.exe -s -o NUL -w "%{http_code}" "$baseUrl/"
$healthStatus = curl.exe -s -o NUL -w "%{http_code}" "$baseUrl/health"

Write-Host "HOME_STATUS=$homeStatus"
Write-Host "HEALTH_STATUS=$healthStatus"

if ($homeStatus -ne "200" -or $healthStatus -ne "200") {
  throw "Smoke check failed. Home=$homeStatus Health=$healthStatus"
}

Write-Host "Manual deploy completed successfully."
