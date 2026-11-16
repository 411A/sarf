#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    SARF verification pipeline for Windows developers (PowerShell 7).

.DESCRIPTION
    Runs the same ordered stages as scripts/verify.sh, but every cargo command
    uses --offline because crates.io TLS is broken on the Windows dev host and
    the registry cache is pre-seeded.

    Windows has no WSL requirement here. Linux runtime behaviour (e2e/perf) is
    exercised by CI; this script still performs a cargo check for the Linux
    target when the MinGW gcc/ar used by libsqlite3-sys are available.

    tempfile-based tests need a temp directory that is not the user profile
    temp, so this script creates <repo>/.tmp-test, points TEMP/TMP at it for the
    test stages, and removes it in a finally block.

    The normal target directory is deliberately left alone (CARGO_TARGET_DIR is
    not overridden).

.NOTES
    Exit code is non-zero if any stage fails. External commands are checked
    explicitly because PowerShell does not throw on a native non-zero exit.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $RepoRoot

$script:Passed = 0
$script:Total = 0
$script:Skipped = 0
$script:CurrentStage = ''
$script:StartTime = Get-Date

# Repo-local temp directory. Do not use the profile temp: tempfile-based tests
# fail there on this Windows host.
$TempRoot = Join-Path $RepoRoot '.tmp-test'
$OldTemp = $env:TEMP
$OldTmp = $env:TMP

$ExitCode = 0

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "== $Title" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Invoke-CargoStage {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $script:Total++
    $script:CurrentStage = $Name
    Write-Section $Name
    Write-Host ('== cargo ' + ($Arguments -join ' ')) -ForegroundColor DarkGray

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Stage '$Name' failed with exit code $LASTEXITCODE."
    }

    $script:Passed++
    Write-Host "== PASS: $Name" -ForegroundColor Green
}

try {
    $cargoCommand = Get-Command cargo -ErrorAction Stop
    $rustcCommand = Get-Command rustc -ErrorAction Stop

    & cargo --offline --version
    if ($LASTEXITCODE -ne 0) {
        throw "cargo --offline --version failed with exit code $LASTEXITCODE."
    }
    & rustc --version
    if ($LASTEXITCODE -ne 0) {
        throw "rustc --version failed with exit code $LASTEXITCODE."
    }

    if (Test-Path -LiteralPath $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
    $env:TEMP = $TempRoot
    $env:TMP = $TempRoot

    Write-Host ''
    Write-Host 'SARF verification (Windows, cargo --offline)'
    Write-Host "  repository: $RepoRoot"
    Write-Host "  cargo:      $($cargoCommand.Source)"
    Write-Host "  rustc:      $($rustcCommand.Source)"
    Write-Host "  temp:       $TempRoot (repo-local)"
    Write-Host "  started:    $($script:StartTime.ToUniversalTime().ToString('u'))"

    # 1. Compiler / formatting / lint. --offline is a cargo global option, so it
    #    also works for `cargo --offline fmt` (cargo-fmt rejects it after fmt).
    Invoke-CargoStage -Name 'cargo fmt --check' -Arguments @('--offline', 'fmt', '--check')
    Invoke-CargoStage -Name 'cargo clippy --all-targets -- -D warnings' `
        -Arguments @('--offline', 'clippy', '--all-targets', '--', '-D', 'warnings')
    Invoke-CargoStage -Name 'cargo build --all-targets' `
        -Arguments @('--offline', 'build', '--all-targets')

    # 2. Unit, policy and plan/spec tests. TEMP/TMP now point into .tmp-test.
    Invoke-CargoStage -Name 'cargo test --lib' -Arguments @('--offline', 'test', '--lib')
    Invoke-CargoStage -Name 'cargo test --test policy' `
        -Arguments @('--offline', 'test', '--test', 'policy')
    Invoke-CargoStage -Name 'cargo test --test plan_conformance' `
        -Arguments @('--offline', 'test', '--test', 'plan_conformance')

    # 3. Integration and end-to-end tests.
    Invoke-CargoStage -Name 'cargo test --test integration_collectors' `
        -Arguments @('--offline', 'test', '--test', 'integration_collectors')
    Invoke-CargoStage -Name 'cargo test --test integration_report' `
        -Arguments @('--offline', 'test', '--test', 'integration_report')
    Invoke-CargoStage -Name 'cargo test --test e2e' `
        -Arguments @('--offline', 'test', '--test', 'e2e')

    # 4. Release-mode performance checks.
    Invoke-CargoStage -Name 'cargo test --release --test perf -- --nocapture' `
        -Arguments @('--offline', 'test', '--release', '--test', 'perf', '--', '--nocapture')

    # 5. Linux type-check. This is only a check (nothing links); libsqlite3-sys'
    #    build script needs a C compiler and archiver for the target.
    Write-Section 'Linux cross-check: cargo check --target x86_64-unknown-linux-gnu'

    $defaultCc = 'C:\StrawberryPerl\c\bin\gcc.exe'
    $defaultAr = 'C:\StrawberryPerl\c\bin\ar.exe'

    $crossCc = if ([string]::IsNullOrWhiteSpace($env:CC_x86_64_unknown_linux_gnu)) {
        $defaultCc
    } else {
        $env:CC_x86_64_unknown_linux_gnu
    }
    $crossAr = if ([string]::IsNullOrWhiteSpace($env:AR_x86_64_unknown_linux_gnu)) {
        $defaultAr
    } else {
        $env:AR_x86_64_unknown_linux_gnu
    }

    if ((Test-Path -LiteralPath $crossCc -PathType Leaf) -and
        (Test-Path -LiteralPath $crossAr -PathType Leaf)) {
        $env:CC_x86_64_unknown_linux_gnu = $crossCc
        $env:AR_x86_64_unknown_linux_gnu = $crossAr
        Invoke-CargoStage -Name 'cargo check --target x86_64-unknown-linux-gnu' `
            -Arguments @('--offline', 'check', '--target', 'x86_64-unknown-linux-gnu')
    } else {
        $script:Skipped++
        Write-Host 'SKIP: Linux cross-check.' -ForegroundColor Yellow
        Write-Host "      Missing compiler/archiver (need both):" -ForegroundColor Yellow
        Write-Host "        CC_x86_64_unknown_linux_gnu = $crossCc" -ForegroundColor Yellow
        Write-Host "        AR_x86_64_unknown_linux_gnu = $crossAr" -ForegroundColor Yellow
        Write-Host '      Set these variables to MinGW gcc/ar to enable the check.' -ForegroundColor Yellow
    }

    $elapsed = [int](((Get-Date) - $script:StartTime).TotalSeconds)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGreen
    Write-Host ("All {0} verification stages passed in {1}s." -f $script:Passed, $elapsed) `
        -ForegroundColor Green
    if ($script:Skipped -gt 0) {
        Write-Host ("Skipped {0} optional stage(s)." -f $script:Skipped) -ForegroundColor Yellow
    }
    Write-Host ('=' * 70) -ForegroundColor DarkGreen
} catch {
    $ExitCode = 1
    Write-Host ''
    Write-Host 'VERIFICATION FAILED' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if (-not [string]::IsNullOrWhiteSpace($script:CurrentStage)) {
        Write-Host "Last stage: $($script:CurrentStage)" -ForegroundColor Red
    }
} finally {
    # Restore the caller's temp variables and remove the repo-local directory,
    # even when a stage failed. Tests must not leave temp data in the tree.
    if ($null -eq $OldTemp) {
        Remove-Item Env:TEMP -ErrorAction SilentlyContinue
    } else {
        $env:TEMP = $OldTemp
    }
    if ($null -eq $OldTmp) {
        Remove-Item Env:TMP -ErrorAction SilentlyContinue
    } else {
        $env:TMP = $OldTmp
    }

    if (Test-Path -LiteralPath $TempRoot) {
        try {
            Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Warning "Could not remove $TempRoot : $($_.Exception.Message)"
        }
    }
}

if ($ExitCode -ne 0) {
    exit $ExitCode
}
