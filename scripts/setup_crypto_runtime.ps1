<#
.SYNOPSIS
    Cryptographic runtime setup and validation script for local development.

.DESCRIPTION
    Validates the local Node.js environment, verifies pinned Barretenberg and
    Noir dependencies, and ensures local CLI wrappers (.bin/bb.cmd, .bin/bb) and
    the native Windows PE launcher (.bin/bb.exe compiled from scripts/bb_launcher.c)
    are available for B1 cryptographic proof verification.

.PARAMETER CheckOnly
    Perform environment and dependency validation without writing wrappers, compiling launcher, or running npm.

.PARAMETER Force
    Force re-generation of the .bin wrappers and native launcher even if they already exist.
#>
[CmdletBinding()]
param (
    [switch]$CheckOnly,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$CryptoDir = Join-Path $ProjectRoot "backend/verification_service/crypto_runtime"
$BinDir = Join-Path $ProjectRoot ".bin"
$PackageJsonPath = Join-Path $CryptoDir "package.json"
$PackageLockPath = Join-Path $CryptoDir "package-lock.json"
$EntrypointRel = "node_modules/@aztec/bb.js/dest/node/main.js"
$EntrypointPath = Join-Path $CryptoDir $EntrypointRel
$BbCmdPath = Join-Path $BinDir "bb.cmd"
$BbShPath = Join-Path $BinDir "bb"
$BbExePath = Join-Path $BinDir "bb.exe"
$LauncherSourcePath = Join-Path $ProjectRoot "scripts/bb_launcher.c"
$runningOnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT

Write-Info "Evaluating local cryptographic runtime environment..."

# 1. Node.js runtime validation
try {
    $nodeVersionRaw = & node --version 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($nodeVersionRaw)) {
        throw "Node.js executable returned non-zero or empty version."
    }
    $nodeVersion = $nodeVersionRaw.Trim()
    $major = [int]($nodeVersion -replace '^v(\d+)\..*', '$1')
    if ($major -lt 18) {
        Write-Failure "Node.js version $nodeVersion is unsupported. Barretenberg CLI requires Node.js >= 18.0.0."
        exit 1
    }
    Write-Success "Node.js runtime discovered: $nodeVersion (minimum >= 18 met)"
}
catch {
    Write-Failure "Node.js is not installed or not discoverable on PATH. Please install Node.js >= 18.0.0."
    exit 1
}

# 2. npm runtime validation
try {
    $npmVersionRaw = & npm --version 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($npmVersionRaw)) {
        throw "npm executable returned non-zero or empty version."
    }
    Write-Success "npm CLI discovered: $($npmVersionRaw.Trim())"
}
catch {
    Write-Failure "npm is not installed or not discoverable on PATH."
    exit 1
}

# 3. Pinned package definition verification
if (-not (Test-Path $PackageJsonPath)) {
    Write-Failure "Required crypto runtime package definition not found: $PackageJsonPath"
    exit 1
}

$pkgContent = Get-Content -Raw $PackageJsonPath | ConvertFrom-Json
$pinnedBb = $pkgContent.dependencies.'@noir-lang/backend_barretenberg'
if ($pinnedBb -ne "0.32.0") {
    Write-Failure "Package pin mismatch: expected @noir-lang/backend_barretenberg '0.32.0', found '$pinnedBb'"
    exit 1
}
Write-Success "Verified pinned dependency: @noir-lang/backend_barretenberg@$pinnedBb"

if (-not (Test-Path $PackageLockPath)) {
    Write-Failure "Package lockfile missing: $PackageLockPath"
    exit 1
}
Write-Success "Discovered cryptographic runtime lockfile: package-lock.json"

# 4. Entrypoint verification & optional npm ci
if (-not (Test-Path $EntrypointPath)) {
    if ($CheckOnly) {
        Write-Failure "Barretenberg WASM entrypoint missing: $EntrypointPath (run setup without -CheckOnly to install)"
        exit 1
    }
    Write-Info "WASM entrypoint missing. Restoring dependencies via npm ci (prefer-offline)..."
    Push-Location $CryptoDir
    try {
        & npm ci --prefer-offline --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) {
            Write-Failure "npm ci failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $EntrypointPath)) {
    Write-Failure "Barretenberg entrypoint still missing after installation check: $EntrypointPath"
    exit 1
}
Write-Success "Verified Barretenberg entrypoint: $EntrypointPath"

# 5. Wrapper generation
if (-not $CheckOnly) {
    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Write-Info "Created directory: $BinDir"
    }

    $cmdContent = "@echo off`r`nnode `"%~dp0..\backend\verification_service\crypto_runtime\node_modules\@aztec\bb.js\dest\node\main.js`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    if ($Force -or (-not (Test-Path $BbCmdPath))) {
        [System.IO.File]::WriteAllText($BbCmdPath, $cmdContent, [System.Text.Encoding]::ASCII)
        Write-Success "Generated Windows CLI wrapper: $BbCmdPath"
    } else {
        Write-Success "Preserved existing Windows CLI wrapper: $BbCmdPath"
    }

    $shLines = @(
        '#!/usr/bin/env sh',
        'DIR="$(cd "$(dirname "$0")" && pwd)"',
        'exec node "$DIR/../backend/verification_service/crypto_runtime/node_modules/@aztec/bb.js/dest/node/main.js" "$@"'
    )
    $shContent = ($shLines -join "`n") + "`n"
    if ($Force -or (-not (Test-Path $BbShPath))) {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($BbShPath, $shContent, $utf8NoBom)
        Write-Success "Generated POSIX CLI wrapper: $BbShPath"
    } else {
        Write-Success "Preserved existing POSIX CLI wrapper: $BbShPath"
    }

    if ($runningOnWindows) {
        if ($Force -or (-not (Test-Path $BbExePath))) {
            $gccCmd = Get-Command "gcc" -ErrorAction SilentlyContinue
            if ($gccCmd -and (Test-Path $LauncherSourcePath)) {
                Write-Info "Compiling native Windows launcher from $LauncherSourcePath..."
                & gcc -O2 "$LauncherSourcePath" -o "$BbExePath"
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Generated native Windows CLI launcher: $BbExePath"
                } else {
                    Write-Warn "gcc compilation of $BbExePath failed with exit code $LASTEXITCODE; falling back to bb.cmd"
                }
            } else {
                Write-Info "gcc compiler or launcher source not found; native bb.exe not built (bb.cmd available)"
            }
        } else {
            Write-Success "Preserved existing native Windows CLI launcher: $BbExePath"
        }
    }
}

# 6. Wrapper functional verification
$targetWrapper = if ($runningOnWindows) {
    if (Test-Path $BbExePath) { $BbExePath } else { $BbCmdPath }
} else {
    $BbShPath
}

try {
    if (Test-Path $targetWrapper) {
        $invokedTarget = $targetWrapper
        if (-not $runningOnWindows) {
            try { & chmod +x $targetWrapper 2>$null } catch {}
        }
        $helpOutput = & "$targetWrapper" --help 2>&1
    } else {
        $invokedTarget = "node $EntrypointPath"
        $helpOutput = & node "$EntrypointPath" --help 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Failure "Barretenberg CLI verification check failed on $invokedTarget with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    Write-Success "Barretenberg CLI verification passed via $invokedTarget (exit code 0; commands available: verify, prove, etc.)"

    if ($runningOnWindows -and (Test-Path $BbShPath)) {
        $posixShell = Get-Command "sh" -ErrorAction SilentlyContinue
        if (-not $posixShell) {
            $gitSh = "C:\Program Files\Git\bin\sh.exe"
            if (Test-Path $gitSh) {
                $posixShell = $gitSh
            }
        }
        if ($posixShell) {
            $shShellPath = if ($posixShell -is [System.Management.Automation.CommandInfo]) { $posixShell.Source } else { [string]$posixShell }
            try {
                $syntaxCheck = & $posixShell -n "$BbShPath" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Validated POSIX CLI wrapper syntax via $shShellPath -n"
                } else {
                    Write-Failure "POSIX CLI wrapper syntax check failed: $syntaxCheck"
                    exit $LASTEXITCODE
                }
            } catch {
                Write-Warn "Could not execute POSIX wrapper syntax check: $_"
            }
        } else {
            Write-Info "POSIX shell (sh) not detected on Windows host; skipping non-mutating wrapper syntax validation."
        }
    }
}
catch {
    Write-Failure "Execution of $invokedTarget failed: $_"
    exit 1
}

Write-Success "Cryptographic runtime reproducibility check complete. Ready for local proof verification."
exit 0
