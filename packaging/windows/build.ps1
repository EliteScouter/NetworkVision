<#
.SYNOPSIS
  Build the NetworkVision Windows installer (PyInstaller one-folder + WinSW + Inno Setup).

.EXAMPLE
  # from the repository root, with Python 3.13, Inno Setup 6 and frontend/dist built:
  pip install -r backend/requirements.txt pyinstaller==6.22.3
  powershell -File packaging/windows/build.ps1 -Version 1.2.3

  Optional code signing: set NV_SIGN_PFX (path to a .pfx) and NV_SIGN_PFX_PASSWORD.
  Without them the binaries are unsigned and SmartScreen warns on first run.
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$OutDir = "dist",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$Version = $Version.TrimStart("v")
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Here = $PSScriptRoot
New-Item -ItemType Directory -Force -Path (Join-Path $Root $OutDir) | Out-Null
$Out = (Resolve-Path (Join-Path $Root $OutDir)).Path
$Work = Join-Path $Root "build\windows"
$Bundle = Join-Path $Out "windows\NetworkVision"

# WinSW 2.12.0 (self-contained x64 build), pinned by hash.
$WinSWUrl = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
$WinSWSha256 = "05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da"

if (-not (Test-Path "$Root\frontend\dist\index.html")) { throw "Build the frontend first (cd frontend; npm ci; npm run build)" }

function Invoke-Checked([string]$Exe, [string[]]$ArgList) {
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}

function Sign-Files([string[]]$Files) {
    if (-not $env:NV_SIGN_PFX) { return }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName | Select-Object -Last 1
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK) or unset NV_SIGN_PFX" }
    foreach ($f in $Files) {
        Invoke-Checked $signtool.FullName @("sign", "/fd", "SHA256", "/f", $env:NV_SIGN_PFX, "/p", $env:NV_SIGN_PFX_PASSWORD,
            "/tr", "http://timestamp.digicert.com", "/td", "SHA256", "/d", "NetworkVision", $f)
    }
}

Write-Host "==> PyInstaller one-folder build ($Version)"
$verFile = Join-Path $Root "backend\app\_build_version.py"
Set-Content -Path $verFile -Value "VERSION = `"$Version`"" -Encoding ascii
try {
    if (Test-Path $Bundle) { Remove-Item -Recurse -Force $Bundle }
    Invoke-Checked $Python @("-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
        "--workpath", $Work, "--distpath", (Split-Path $Bundle), "$Here\networkvision.spec")
} finally {
    Remove-Item -Force $verFile -ErrorAction SilentlyContinue
}

Write-Host "==> Web UI, service wrapper"
Copy-Item -Recurse "$Root\frontend\dist" "$Bundle\static"
$winsw = Join-Path $Work "WinSW-x64.exe"
if (-not (Test-Path $winsw) -or (Get-FileHash $winsw -Algorithm SHA256).Hash -ne $WinSWSha256) {
    Invoke-WebRequest -Uri $WinSWUrl -OutFile $winsw -UseBasicParsing
}
if ((Get-FileHash $winsw -Algorithm SHA256).Hash -ne $WinSWSha256) { throw "WinSW checksum mismatch" }
Copy-Item $winsw "$Bundle\NetworkVisionService.exe"
Copy-Item "$Here\NetworkVisionService.xml" "$Bundle\NetworkVisionService.xml"
Copy-Item "$Root\LICENSE" "$Bundle\LICENSE.txt"

Write-Host "==> Smoke test"
$check = Join-Path $Work "check-data"
if (Test-Path $check) { Remove-Item -Recurse -Force $check }
$env:NV_CONFIG = "nonexistent"; $env:NV_DATA_DIR = $check; $env:NV_STATIC_DIR = "$Bundle\static"
try { Invoke-Checked "$Bundle\networkvision.exe" @("--check") }
finally { Remove-Item Env:NV_CONFIG, Env:NV_DATA_DIR, Env:NV_STATIC_DIR -ErrorAction SilentlyContinue }

Sign-Files @("$Bundle\networkvision.exe", "$Bundle\NetworkVisionService.exe")

Write-Host "==> Inno Setup"
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 (ISCC.exe) not found - install it from https://jrsoftware.org/isdl.php" }
Invoke-Checked $iscc @("/Q", "/DAppVersion=$Version", "/DSourceDir=$Bundle", "/DOutputDir=$Out", "$Here\networkvision.iss")

$setup = Join-Path $Out "NetworkVision-$Version-windows-x64-setup.exe"
Sign-Files @($setup)
Write-Host "Built $setup"
