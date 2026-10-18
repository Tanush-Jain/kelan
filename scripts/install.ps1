# Kelan Security — Windows Installer
#
# Usage (run PowerShell as Administrator):
#   iwr -useb https://install.kelan.io/windows | iex
#
# Optional parameters when saving and running locally:
#   .\install.ps1 -Version v0.3.0
#   .\install.ps1 -InstallDir "C:\Tools\Kelan"

param(
    [string]$Version    = "latest",
    [string]$InstallDir = "$env:ProgramFiles\Kelan Security"
)

$ErrorActionPreference = "Stop"
$Repo     = "kelan-security/kelan-core"
$Platform = "windows-x86_64"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    Kelan Security Windows Installer      ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Resolve 'latest' via GitHub API
if ($Version -eq "latest") {
    Write-Host "  Resolving latest version..." -ForegroundColor Gray
    $Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $Release.tag_name
}

$VersionNum  = $Version.TrimStart("v")
$Archive     = "kelan-$Version-$Platform.zip"
$BaseUrl     = "https://github.com/$Repo/releases/download/$Version"
$ArchiveUrl  = "$BaseUrl/$Archive"
$ChecksumUrl = "$BaseUrl/$Archive.sha256"

Write-Host "  Version:  $Version"    -ForegroundColor Green
Write-Host "  Platform: $Platform"   -ForegroundColor Green
Write-Host "  Install:  $InstallDir" -ForegroundColor Green
Write-Host ""

# ── Temp directory
$TmpDir = Join-Path $env:TEMP "kelan-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    # ── Download
    Write-Host "  Downloading $Archive..." -ForegroundColor Gray
    Invoke-WebRequest $ArchiveUrl  -OutFile "$TmpDir\$Archive"  -UseBasicParsing
    Invoke-WebRequest $ChecksumUrl -OutFile "$TmpDir\$Archive.sha256" -UseBasicParsing

    # ── Verify checksum
    Write-Host "  Verifying checksum..." -ForegroundColor Gray
    $ChecksumLine  = Get-Content "$TmpDir\$Archive.sha256" -Raw
    $ExpectedHash  = ($ChecksumLine.Split()[0]).ToUpper()
    $ActualHash    = (Get-FileHash "$TmpDir\$Archive" -Algorithm SHA256).Hash

    if ($ExpectedHash -ne $ActualHash) {
        throw "Checksum verification FAILED!`n  Expected: $ExpectedHash`n  Got:      $ActualHash"
    }
    Write-Host "  Checksum verified" -ForegroundColor Green

    # ── Extract
    Write-Host "  Extracting archive..." -ForegroundColor Gray
    Expand-Archive "$TmpDir\$Archive" -DestinationPath $TmpDir -Force

    # ── Install
    $ExtractedDir = "$TmpDir\kelan-$VersionNum-$Platform"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    Copy-Item "$ExtractedDir\kelan-server.exe" "$InstallDir\kelan-server.exe" -Force

    Write-Host "  Installed binaries to $InstallDir" -ForegroundColor Green

    # ── Add to System PATH
    $SystemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($SystemPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$SystemPath;$InstallDir", "Machine")
        Write-Host "  Added $InstallDir to system PATH." -ForegroundColor Green
        Write-Host "  Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
    }

} finally {
    # ── Cleanup
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}

# ── Done
Write-Host ""
Write-Host "  ✓ Kelan Security installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host '  $env:OLLAMA_ENDPOINT = "http://localhost:11434"'
Write-Host "  kelan-server"
Write-Host ""
Write-Host "  Docs: https://docs.kelan.io"
Write-Host "  Repo: https://github.com/$Repo"
Write-Host ""
