# v5.0 Track 5 - verdict regression harness (LOCAL pre-release gate; needs real cases).
# Replays every historical case through -Mode Parse on a throwaway COPY, then compares
# verdict Level + confidence + signal count against tests\verdict_baseline.txt.
# Baseline drift is EXPECTED when verdict semantics consciously change - refresh with
# -WriteBaseline in the same commit as the semantic change.
#   generate baseline:  powershell -File tests\run-verdict-regression.ps1 -WriteBaseline
#   regression gate:    powershell -File tests\run-verdict-regression.ps1
param([switch]$WriteBaseline, [string]$RepoRoot = '')
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$ophira = Join-Path $RepoRoot 'Ophira.ps1'
$baselineFile = Join-Path $PSScriptRoot 'verdict_baseline.txt'
if (-not (Test-Path $ophira)) { Write-Host "Ophira.ps1 not found at $ophira" -ForegroundColor Red; exit 1 }

$cases = @(Get-ChildItem -LiteralPath $RepoRoot -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'case.json') })
if ($cases.Count -eq 0) { Write-Host 'No OPHIRA_* cases with case.json found in repo root - nothing to replay.' -ForegroundColor Yellow; exit 0 }

function Get-CaseInputs([string]$Src) {
    # Copy the Parse inputs (case.json + csv tree + manifest) to a fresh temp dir.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_regr_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $Src 'case.json') -Destination $tmp -Force
    if (Test-Path (Join-Path $Src 'manifest.txt')) { Copy-Item -LiteralPath (Join-Path $Src 'manifest.txt') -Destination $tmp -Force }
    if (Test-Path (Join-Path $Src 'csv')) { Copy-Item -LiteralPath (Join-Path $Src 'csv') -Destination (Join-Path $tmp 'csv') -Recurse -Force }
    return $tmp
}

$results = @()
foreach ($c in $cases) {
    $tmp = Get-CaseInputs $c.FullName
    try {
        $null = & $ophira -Mode Parse -ParsePath $tmp 2>&1
        $vf = Join-Path $tmp 'verdict.json'
        if (-not (Test-Path $vf)) { Write-Host "  $($c.Name): NO verdict.json produced" -ForegroundColor Red; $results += "$($c.Name)|ERROR|0|0"; continue }
        $v = Get-Content $vf -Raw | ConvertFrom-Json
        $sigN = 0; if ($null -ne $v.Signals) { $sigN = @($v.Signals).Count }
        $line = "$($c.Name)|$($v.Level)|$($v.ConfidencePercent)|$sigN"
        $results += $line
        Write-Host "  $($c.Name): $($v.Level) $($v.ConfidencePercent)% ($sigN signals)" -ForegroundColor Gray
    } catch {
        Write-Host "  $($c.Name): PARSE FAILED - $($_.Exception.Message)" -ForegroundColor Red
        $results += "$($c.Name)|ERROR|0|0"
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($WriteBaseline) {
    $results | Out-File -LiteralPath $baselineFile -Encoding utf8
    Write-Host "Baseline written ($($results.Count) cases) -> $baselineFile" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $baselineFile)) {
    Write-Host "No baseline yet - run with -WriteBaseline first to record current verdicts." -ForegroundColor Yellow
    exit 0
}

$base = @(Get-Content -LiteralPath $baselineFile | Where-Object { "$_".Trim() })
$drift = @()
foreach ($r in $results) {
    $key = ($r -split '\|')[0]
    $b = $base | Where-Object { $_.StartsWith("$key|") } | Select-Object -First 1
    if (-not $b) { $drift += "NEW CASE (not in baseline): $r"; continue }
    if ($b.Trim() -ne $r.Trim()) { $drift += "DRIFT:`n  baseline: $b`n  current : $r" }
}
foreach ($b in $base) {
    $key = ($b -split '\|')[0]
    if (-not ($results | Where-Object { $_.StartsWith("$key|") })) { $drift += "MISSING (was in baseline, failed now): $key" }
}
if ($drift.Count -gt 0) {
    Write-Host "VERDICT REGRESSION - $($drift.Count) drift item(s):" -ForegroundColor Red
    $drift | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host 'If the drift is an intended semantic change, refresh the baseline with -WriteBaseline in the same commit.' -ForegroundColor Gray
    exit 1
}
Write-Host "VERDICT REGRESSION CLEAN - $($results.Count) case(s) match baseline." -ForegroundColor Green
exit 0
