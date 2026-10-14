# test_v260.ps1 - truth pack: credential signal fix, Defender weight split, parse_needed honesty
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: Get-CompromiseVerdict - credential signal + Defender weight split ----
foreach ($n in 'Get-CompromiseVerdict', 'Get-LvlRank') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$tmp = Join-Path $env:TEMP ("ophira_v260_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $tmp 'raw\evtx') -Force | Out-Null
$RawDir = Join-Path $tmp 'raw'
$MemDir = Join-Path $tmp 'mem'
$CaseDir = $tmp
$global:LogHours = 168

function Import-CaseCsv([string]$name) { if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function Test-CaseCsv([string]$n) { return $false }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Test-IsAdmin { return $false }

# scenario 1: credential HIGH row + fresh Defender detection (live catalog) + stale 1116 history
$script:fixtureRows = @{
    'credential_sweep'  = @([pscustomobject]@{ Item = 'Possible credential dump on disk'; Detail = 'C:\temp\lsass.dmp (1.2 MB)'; Risk = 'HIGH' })
    'defender_threats'  = @(
        [pscustomobject]@{ ThreatName = 'Trojan:Win32/Fresh'; SeverityID = 4; Source = 'live-catalog'; DetectedUTC = $null }
        [pscustomobject]@{ ThreatName = 'PUA:Win32/Old'; SeverityID = 5; Source = 'evtx-history'; DetectedUTC = '2020-01-01 00:00:00' }
    )
}
$v1 = Get-CompromiseVerdict
$cred = @($v1.Signals | Where-Object { $_.Signal -eq 'Credential material exposure' })
Check "credential signal FIRES on Risk column (was dead code on Severity)" ($cred.Count -eq 1 -and $cred[0].Count -eq 1)
Check "credential signal detail carries Item: Detail (Description never existed)" ($cred[0].Detail -match 'credential dump on disk: C:\\temp\\lsass\.dmp')
$dfresh = @($v1.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' })
$dstale = @($v1.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
Check "defender split: live-catalog = weight 2 fresh" ($dfresh.Count -eq 1 -and $dfresh[0].Weight -eq 2 -and $dfresh[0].Count -eq 1)
Check "defender split: stale 1116 history = weight 1 report-only" ($dstale.Count -eq 1 -and $dstale[0].Weight -eq 1 -and $dstale[0].Count -eq 1)

# scenario 2: ONLY a months-old resolved detection - must NOT reach LIKELY COMPROMISED (the FP scenario)
$script:fixtureRows = @{
    'defender_threats' = @([pscustomobject]@{ ThreatName = 'PUA:Win32/Old'; SeverityID = 5; Source = 'evtx-history'; DetectedUTC = '2020-01-01 00:00:00' })
}
$v2 = Get-CompromiseVerdict
Check "stale-only Defender history cannot declare LIKELY COMPROMISED (old: weight 2 + any w2 = rank 3)" ($v2.LevelRank -le 2)
Check "stale-only still visible as weight-1 signal" (@($v2.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' }).Count -eq 1)

# ---- behavioral: Get-ParseNeeds - empty-input branch, Preset wording, shimcache deferral ----
$m = [regex]::Match($src, "(?s)function Get-ParseNeeds \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-ParseNeeds extract failed' }
Invoke-Expression $m.Value
$captured = $null
function Save-Rows([string]$Name, [object[]]$Rows) { $script:captured = $Rows }
function Write-CaseLog([string]$m2, [object]$c2) { }

# case A: Standard preset, empty recyclebin input, covered shimcache, missing browser + recentfilecache
New-Item -ItemType Directory -Path (Join-Path $RawDir 'recyclebin'), (Join-Path $RawDir 'registry') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $RawDir 'registry\Amcache.hve') -Value 'x'
Set-Content -LiteralPath (Join-Path $tmp 'case.json') -Value '{ "Preset": "Standard" }'
function Test-CaseCsv([string]$n) { return $n -eq 'execution_timeline.csv' }
Get-ParseNeeds
$byArtifact = @{}
foreach ($r in $captured) { $byArtifact[$r.Artifact] = $r }
Check "empty-input: recyclebin says collected-but-empty, never 'run Parse'" ("$($byArtifact['recyclebin.csv'].HowToFinish)" -match 'collected but empty on the endpoint')
Check "shimcache deferred: row absent while execution_timeline covers it" (-not $byArtifact.ContainsKey('shimcache.csv'))
Check "Standard preset + missing input: honest not-present wording" ("$($byArtifact['browser_history.csv'].HowToFinish)" -match 'not present on this endpoint')
Check "recentfilecache carries the Win11 absent-note" ("$($byArtifact['recentfilecache.csv'].HowToFinish)" -match 'often absent on current Win11')
Check "input present + tool missing: Setup advice intact" ("$($byArtifact['amcache.csv'].HowToFinish)" -match 'parser tool missing from the kit.*AmcacheParser')

# case B: Quick preset -> skipped-module wording
Set-Content -LiteralPath (Join-Path $tmp 'case.json') -Value '{ "Preset": "Quick" }'
Get-ParseNeeds
$byArtifactB = @{}
foreach ($r in $captured) { $byArtifactB[$r.Artifact] = $r }
Check "Quick preset: missing input says module skipped (rerun deeper)" ("$($byArtifactB['browser_history.csv'].HowToFinish)" -match 'module skipped on the endpoint \(Quick preset\)')

# ---- statics ----
Check "module 7.1 uses Get-KitRoot (worker-safe) not \$BaseDir" ($src -match [regex]::Escape('# v2.60: Get-KitRoot (worker-seeded) instead of $BaseDir'))
Check "Test-IsPublicIp dead 172.31 branch removed" (-not ($src -match [regex]::Escape('if ($b[0] -eq 172 -and $b[1] -eq 31)')))
Check "MFT window: LogHours-aware, floor 30 days" ($src -match [regex]::Escape('$mftDays = [Math]::Max(30, [int][double]($lh / 24))'))
Check "local_admins: CIM by language-neutral Administrators SID" ($src -match [regex]::Escape("'S-1-5-32-544'"))
Check "local_admins: net.exe parser kept as fallback" ($src -match [regex]::Escape('Get-LocalAdminMembers @(& net.exe localgroup administrators'))

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { Write-Host "`ntest_v260: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v260: $pass passed, 0 failed" -ForegroundColor Green
exit 0
