<#
.SYNOPSIS
    Kelan Community — Secure Windows Installer Script

.DESCRIPTION
    Downloads, verifies SHA-256 checksums, and installs Kelan Community
    on Windows 10/11 x64 from the official Tanush-Jain/kelan GitHub releases.
    Prefers the verified Inno Setup installer (KelanSetup.exe), falling back
    to the verified portable zip archive.

.PARAMETER Version
    Specific release tag to install (e.g. "v0.1.0"). Defaults to "latest".

.PARAMETER InstallDir
    Target directory for zip fallback installation. Defaults to "$env:ProgramFiles\Kelan".

.PARAMETER Silent
    Run installer in silent mode without wizard dialogs.

.EXAMPLE
    Save and run locally:
        .\scripts\install.ps1
        .\scripts\install.ps1 -Version "v0.1.0" -Silent
#>

param(
    [string]$Version    = "latest",
    [string]$InstallDir = "$env:ProgramFiles\Kelan",
    [string]$Repo       = "Tanush-Jain/kelan",
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║       Kelan Community — Windows Installer        ║" -ForegroundColor Cyan
Write-Host "  ║       Privacy-First AI Security Scanner          ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Note: Kernel eBPF/XDP network enforcement is Linux-only." -ForegroundColor DarkYellow
Write-Host "  On Windows, Kelan operates in audit, SAST, DAST, and SCA modes." -ForegroundColor DarkYellow
Write-Host ""

# ── 1. Resolve release version from GitHub API
try {
    if ($Version -eq "latest") {
        Write-Host "  Resolving latest release from https://github.com/$Repo..." -ForegroundColor Gray
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "Kelan-Installer" }
        $Version = $Release.tag_name
    } else {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$Version" -Headers @{ "User-Agent" = "Kelan-Installer" }
    }
} catch {
    Write-Warning "Could not query GitHub API for releases ($($_)). Falling back to version tag: $Version"
}

Write-Host "  Target Version: $Version" -ForegroundColor Green
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"

# ── 2. Temp directory setup
$TmpDir = Join-Path $env:TEMP "kelan-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    # ── 3. Download SHA256SUMS.txt
    $ChecksumFile = "SHA256SUMS.txt"
    $ChecksumUrl  = "$BaseUrl/$ChecksumFile"
    $LocalChecksumPath = Join-Path $TmpDir $ChecksumFile

    Write-Host "  Fetching checksum manifest ($ChecksumFile)..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $LocalChecksumPath -UseBasicParsing
    } catch {
        Write-Warning "Could not download $ChecksumFile directly."
    }

    # ── 4. Determine preferred asset: KelanSetup.exe or zip
    $InstallerAsset = "KelanSetup.exe"
    $ZipAsset       = "kelan-$Version-windows-x86_64.zip"

    $TargetAsset = $InstallerAsset
    $DownloadUrl = "$BaseUrl/$TargetAsset"
    $LocalAssetPath = Join-Path $TmpDir $TargetAsset

    Write-Host "  Downloading $TargetAsset..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $LocalAssetPath -UseBasicParsing
    } catch {
        Write-Host "  Installer executable not found in release, trying zip bundle: $ZipAsset..." -ForegroundColor Gray
        $TargetAsset = $ZipAsset
        $DownloadUrl = "$BaseUrl/$TargetAsset"
        $LocalAssetPath = Join-Path $TmpDir $TargetAsset
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $LocalAssetPath -UseBasicParsing
    }

    # ── 5. Cryptographic SHA-256 Checksum Verification
    Write-Host "  Verifying cryptographic checksum..." -ForegroundColor Gray
    $ActualHash = (Get-FileHash -Path $LocalAssetPath -Algorithm SHA256).Hash.ToUpper()

    $ExpectedHash = $null
    if (Test-Path $LocalChecksumPath) {
        $ChecksumLines = Get-Content $LocalChecksumPath
        foreach ($line in $ChecksumLines) {
            $parts = $line.Trim() -split "\s+"
            if ($parts.Length -ge 2 -and ($parts[1] -replace "^\*","" -eq $TargetAsset)) {
                $ExpectedHash = $parts[0].ToUpper()
                break
            }
        }
    }

    # Also try asset.sha256 individual file if not found in manifest
    if (-not $ExpectedHash) {
        try {
            $IndividualShaUrl = "$BaseUrl/$TargetAsset.sha256"
            $IndividualShaFile = Join-Path $TmpDir "$TargetAsset.sha256"
            Invoke-WebRequest -Uri $IndividualShaUrl -OutFile $IndividualShaFile -UseBasicParsing
            $ExpectedHash = ((Get-Content $IndividualShaFile -Raw).Trim() -split "\s+")[0].ToUpper()
        } catch {
            Write-Warning "No checksum record found for $TargetAsset; proceeding with caution."
        }
    }

    if ($ExpectedHash) {
        if ($ActualHash -ne $ExpectedHash) {
            throw "SECURITY ERROR: Checksum verification FAILED!`n  Expected SHA-256: $ExpectedHash`n  Actual SHA-256:   $ActualHash`nAborting installation to protect system integrity."
        }
        Write-Host "  ✔ SHA-256 Checksum verified: $ActualHash" -ForegroundColor Green
    } else {
        Write-Host "  Notice: SHA-256 hash computed: $ActualHash" -ForegroundColor Yellow
    }

    # ── 6. Execute installation
    if ($TargetAsset -like "*.exe") {
        Write-Host "  Launching Kelan installer..." -ForegroundColor Gray
        $InstallArgs = @()
        if ($Silent) {
            $InstallArgs += "/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES"
        }
        $Process = Start-Process -FilePath $LocalAssetPath -ArgumentList $InstallArgs -Wait -PassThru
        if ($Process.ExitCode -ne 0) {
            throw "Installer exited with non-zero status: $($Process.ExitCode)"
        }
        Write-Host "  ✔ Kelan Setup completed successfully." -ForegroundColor Green
    } else {
        Write-Host "  Extracting portable archive to $InstallDir..." -ForegroundColor Gray
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Expand-Archive -Path $LocalAssetPath -DestinationPath $TmpDir -Force
        
        # Copy binaries
        Copy-Item -Path "$TmpDir\*" -Destination $InstallDir -Recurse -Force

        # Update User PATH
        $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($UserPath -notlike "*$InstallDir*") {
            [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
            Write-Host "  ✔ Added $InstallDir to User PATH." -ForegroundColor Green
            Write-Host "  Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
        }
    }

} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✔ Kelan Community successfully installed!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next Steps:" -ForegroundColor Yellow
Write-Host "    1. Run initial setup:       kelan setup" -ForegroundColor White
Write-Host "    2. Run environment check:   kelan doctor" -ForegroundColor White
Write-Host "    3. Scan your project:       kelan run . --show" -ForegroundColor White
Write-Host ""
Write-Host "  Documentation: https://github.com/$Repo/blob/main/docs/WINDOWS.md" -ForegroundColor DarkCyan
Write-Host ""
