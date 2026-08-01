# ============================================================================
#  build.ps1 - builds Anchor into a single downloadable folder.
#
#  What it does:
#    1. Makes sure the .NET SDK is installed (installs it via winget if not).
#    2. Downloads the WinDivert driver + library (needed for network filtering).
#    3. Publishes ONE self-contained Anchor.exe (no .NET install needed to RUN it).
#    4. Puts Anchor.exe + the WinDivert files together in .\dist\Anchor\.
#
#  Run it from a normal PowerShell window (no admin needed to BUILD):
#     powershell -ExecutionPolicy Bypass -File build.ps1
#
#  Then, to USE Anchor: right-click dist\Anchor\Anchor.exe -> "Run as administrator".
# ============================================================================

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# WinDivert official release (Microsoft-signed driver). Change the version here if needed.
$winDivertUrl = "https://reqrypt.org/download/WinDivert-2.2.2-A.zip"

Write-Host "=== Anchor build ===" -ForegroundColor Cyan

# --- 1. Ensure the .NET SDK is available ------------------------------------
function Test-DotnetSdk {
    try { $sdks = & dotnet --list-sdks 2>$null; return ($LASTEXITCODE -eq 0 -and $sdks) }
    catch { return $false }
}

if (-not (Test-DotnetSdk)) {
    Write-Host "No .NET SDK found. Installing it with winget..." -ForegroundColor Yellow
    winget install --id Microsoft.DotNet.SDK.10 -e --accept-source-agreements --accept-package-agreements --silent
    # winget updates PATH for NEW shells; make dotnet usable in THIS one too.
    $env:Path = "C:\Program Files\dotnet;$env:Path"
    if (-not (Test-DotnetSdk)) {
        throw "Could not install the .NET SDK automatically. Install it from https://aka.ms/dotnet/download and re-run build.ps1."
    }
}
Write-Host "SDK OK." -ForegroundColor Green

# --- 2. Download WinDivert (driver + DLL) -----------------------------------
$nativeDir = Join-Path $root "native"
New-Item -ItemType Directory -Force -Path $nativeDir | Out-Null

$dll = Join-Path $nativeDir "WinDivert.dll"
$sys = Join-Path $nativeDir "WinDivert64.sys"

if ((Test-Path $dll) -and (Test-Path $sys)) {
    Write-Host "WinDivert already present, skipping download." -ForegroundColor Green
} else {
    Write-Host "Downloading WinDivert..." -ForegroundColor Yellow
    $zip = Join-Path $env:TEMP "windivert.zip"
    $extract = Join-Path $env:TEMP "windivert_extract"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }

    Invoke-WebRequest -Uri $winDivertUrl -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $extract -Force

    # Grab the 64-bit files wherever they are inside the zip.
    $foundDll = Get-ChildItem -Path $extract -Recurse -Filter "WinDivert.dll" |
                Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
    $foundSys = Get-ChildItem -Path $extract -Recurse -Filter "WinDivert64.sys" | Select-Object -First 1

    if (-not $foundDll -or -not $foundSys) { throw "Could not find WinDivert x64 files in the download." }
    Copy-Item $foundDll.FullName $dll -Force
    Copy-Item $foundSys.FullName $sys -Force
    Write-Host "WinDivert ready." -ForegroundColor Green
}

# --- 3. Publish the single self-contained exe -------------------------------
Write-Host "Publishing Anchor.exe (this can take a minute)..." -ForegroundColor Yellow
& dotnet publish (Join-Path $root "Anchor.csproj") -c Release
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$publishDir = Join-Path $root "bin\Release\net10.0-windows\win-x64\publish"

# --- 4. Assemble the distributable folder -----------------------------------
$dist = Join-Path $root "dist\Anchor"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Copy-Item (Join-Path $publishDir "Anchor.exe") $dist -Force
Copy-Item $dll $dist -Force
Copy-Item $sys $dist -Force

# Sanity check: all three required files must be present.
foreach ($f in @("Anchor.exe","WinDivert.dll","WinDivert64.sys")) {
    if (-not (Test-Path (Join-Path $dist $f))) { throw "Missing $f in dist folder." }
}

# --- 5. Create a Desktop shortcut that runs Anchor as administrator ---------
# So you can just double-click the shortcut instead of digging through folders.
function New-AdminShortcut {
    param([string]$TargetExe, [string]$ShortcutPath, [string]$WorkDir)

    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($ShortcutPath)
    $sc.TargetPath = $TargetExe
    $sc.WorkingDirectory = $WorkDir
    $sc.IconLocation = "$TargetExe,0"
    $sc.Description = "Anchor - website blocker"
    $sc.Save()
    # Release the COM handles FIRST, otherwise the .lnk file is still open and our byte
    # edit below won't stick (this was a real bug the first time around).
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sc) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null

    # Flip the "Run as administrator" bit in the .lnk (RunAsUser = LinkFlags 0x2000,
    # which is bit 0x20 of byte 0x15), so it always launches elevated via UAC.
    $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
}

$exe = Join-Path $dist "Anchor.exe"
# Put the shortcut on the visible Desktop. With OneDrive "Known Folder Move", the real
# Desktop is often the OneDrive one, so cover both if they exist.
$desktops = @([Environment]::GetFolderPath("Desktop"), (Join-Path $env:USERPROFILE "OneDrive\Desktop")) |
            Select-Object -Unique | Where-Object { Test-Path $_ }
$shortcutMade = $false
$lnk = $null
foreach ($d in $desktops) {
    try {
        $lnk = Join-Path $d "Anchor.lnk"
        New-AdminShortcut -TargetExe $exe -ShortcutPath $lnk -WorkDir $dist
        $shortcutMade = $true
    } catch {
        Write-Host "Note: could not create shortcut in $d ($($_.Exception.Message))." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "Your app is in: $dist" -ForegroundColor Green
if ($shortcutMade) {
    Write-Host "Desktop shortcut created: $lnk  (double-click it -> it runs as admin)." -ForegroundColor Green
}
Write-Host "Or run directly: right-click $exe  ->  Run as administrator." -ForegroundColor Green
