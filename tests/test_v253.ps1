$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.53 - malware-test feedback pack: focus engine perf/seeds/zero-hit UX (test_focus),
# front screen Run/Advanced (test_v238), RECmd .reb (test_v225). This suite covers the rest:
# hayabusa PwSh storm demotion, chainsaw shimcache patterns, R1 access-denied guard, DOT guard.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$root = Split-Path -Parent $PSScriptRoot

# ============================================================================
# hayabusa: the 4104 "Potentially Malicious PwSh" storm is demoted via shipped tuning
# ============================================================================
$tuning = Get-Content -LiteralPath (Join-Path $root 'tools\endpoint\hayabusa\ophira-level-tuning.txt') -Raw
Check "tuning: PwSh 4104 storm rule entry present" ($tuning -match '73be1519-4648-4ed7-b305-605504afc242,informational')
$pwshRule = Join-Path $root 'tools\endpoint\hayabusa\rules\hayabusa\builtin\PowerShell_Op\PwSh_4104_Med_ScriptblockLog_PotentiallyMalicious.yml'
Check "tuning: the rule file itself carries level: informational" ((Test-Path $pwshRule) -and ((Get-Content -LiteralPath $pwshRule) -match '^level: informational').Count -eq 1)

# ============================================================================
# chainsaw: shimcache analysis carries the required -r regexfile (was silently dead)
# ============================================================================
$patFile = Join-Path $root 'tools\endpoint\chainsaw\shimcache_patterns.txt'
$pats = @()
if (Test-Path $patFile) { $pats = @(Get-Content -LiteralPath $patFile | Where-Object { $_.Trim() }) }
Check "chainsaw: shimcache_patterns.txt bundled with anchored patterns" ($pats.Count -ge 10 -and @($pats | Where-Object { $_ -match '^\^\[a-z\]' }).Count -eq $pats.Count)
Check "chainsaw: module passes -r + retries shimcache-only when amcache enrichment aborts" (($src -match [regex]::Escape("'-r', $scPat")) -and $src.Contains('retrying shimcache-only'))

# ============================================================================
# R1 hunt rule: Test-Path on live process paths can hit access-denied (red console noise)
# ============================================================================
Check "hunt R1: path Test-Path is access-denied guarded" ($src.Contains('Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue'))

# ============================================================================
# focus DOT export: instances with empty Image no longer throw Split-Path red noise
# ============================================================================
Check "focus DOT: empty-image instances guarded" ($src.Contains("if (-not `$leaf2) { `$leaf2 = '(unknown image)' }"))

# ============================================================================
# front screen dispatch: run -> SimpleUI collect, advanced -> task menu loop
# ============================================================================
Check "dispatch: bare-launch uses the front screen result" (($src.Contains('$front = Show-RoleGate')) -and ($src.Contains("if (`$front -eq 'run') {")))

# ============================================================================
# report: focus JSON reads stay terminating (v2.52 pattern preserved)
# ============================================================================
Check "report: focus_terms lead read carries -ErrorAction Stop" (($src -split "`n" | Where-Object { $_.Contains('focus_terms.json') -and $_.Contains('-ErrorAction Stop') }).Count -ge 1)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
