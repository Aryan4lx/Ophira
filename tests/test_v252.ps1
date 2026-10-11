$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.52 - live-test hotfix: module 8.2 hive stat raced AV quarantine between Test-Path and
# Get-Item (red errors on a detonation box); report focus reads printed red noise when the
# focus dossier didn't seed (non-terminating error under try/catch without -ErrorAction Stop).
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# extract module 8.2's Run block
$m82 = [regex]::Match($src, "(?s)Id = '8\.2';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '8\.3'")
if (-not $m82.Success) { throw 'extract failed: module 8.2' }
$run82 = $m82.Groups[1].Value

Check "8.2: hive stat is guarded (no bare Get-Item .Length)" (($run82 -match [regex]::Escape('$fi = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue')) -and ($run82 -notmatch [regex]::Escape('(Get-Item $out).Length')))
Check "8.2: all Test-Path/Remove-Item on the saved hive use -LiteralPath" (($run82 -match [regex]::Escape('if ($ok -and (Test-Path -LiteralPath $out))')) -and ($run82 -match [regex]::Escape('elseif (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force')))
Check "8.2: vanished hive reported as suspected AV quarantine (not silent)" ($run82 -match [regex]::Escape('saved hive vanished after save (AV quarantine suspected)'))
Check "8.2: both NTUSER and UsrClass sites hardened" ((@([regex]::Matches($run82, [regex]::Escape('$fi = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue'))).Count -eq 2))
Check "5.2: SYSTEM hive stat keeps its existing guarded pattern" ($src -match [regex]::Escape('((Get-Item $out -ErrorAction SilentlyContinue).Length -gt 0)'))
Check "report: leads focus_terms read is terminating under its try/catch" (($src -match [regex]::Escape("'focus_terms.json') -Raw -ErrorAction Stop | ConvertFrom-Json")) -and (@([regex]::Matches($src, [regex]::Escape('focus_terms.json') + '.{0,80}?-Raw \| ConvertFrom-Json')).Count -eq 0))
Check "report: focus detail read is terminating under its try/catch" ($src -match [regex]::Escape("'focus_instances_detail.json') -Raw -ErrorAction Stop | ConvertFrom-Json"))

Write-Host ""
Write-Host "test_v252: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
