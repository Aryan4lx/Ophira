# test_v49.ps1 - fleet deployment waves (v4.9 Track 4)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$script:checks = 0; $script:fails = 0
function Check { param($Name, $Ok, $Detail) $script:checks++; if (-not $Ok) { $script:fails++; Write-Host "[FAIL] $Name $Detail" -ForegroundColor Red } else { Write-Host "[ok] $Name" } }

$src = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1') -Raw
$fn = [regex]::Match($src, '(?s)function New-FleetWaveRows \{.*?\r?\n\}').Value
if (-not $fn) { Write-Host '[FAIL] cannot extract New-FleetWaveRows'; exit 1 }
Invoke-Expression $fn

$L = New-Object 'System.Collections.Generic.List[object]'
$L.Add([pscustomobject]@{ Host = 'H1'; Leaf = 'tool.exe'; Stamp = '2026-11-20 10:00:00' })
$L.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'tool.exe'; Stamp = '2026-11-20 10:15:00' })
$L.Add([pscustomobject]@{ Host = 'H3'; Leaf = 'tool.exe'; Stamp = '2026-11-20 10:25:00' })
$L.Add([pscustomobject]@{ Host = 'H1'; Leaf = 'chrome.exe'; Stamp = '2026-11-20 09:00:00' })
$L.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'chrome.exe'; Stamp = '2026-11-01 09:00:00' })   # slow -> dropped
$L.Add([pscustomobject]@{ Host = 'H1'; Leaf = 'stagger.exe'; Stamp = '2026-11-20 08:00:00' })
$L.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'stagger.exe'; Stamp = '2026-11-20 14:00:00' })  # 6h -> staggered
$L.Add([pscustomobject]@{ Host = 'H1'; Leaf = 'single.exe'; Stamp = '2026-11-20 10:00:00' })   # 1 host -> dropped
$L.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'badstamp.exe'; Stamp = 'not-a-date' })          # unparsable
$L.Add([pscustomobject]@{ Host = 'H3'; Leaf = 'badstamp.exe'; Stamp = '2026-11-20 10:00:00' })
$L.Add([pscustomobject]@{ Host = 'H1'; Leaf = ''; Stamp = '2026-11-20 10:00:00' })             # empty leaf

$rows = @(New-FleetWaveRows $L)
Check 'rows only wave+stagger' ($rows.Count -eq 2) "got $($rows.Count)"
$wave = @($rows | Where-Object Class -eq 'wave')
Check 'tool.exe wave' ($wave.Count -eq 1 -and $wave[0].Name -eq 'tool.exe' -and $wave[0].HostCount -eq 3) ''
Check 'wave spread 25min' ($wave[0].SpreadMinutes -eq 25) "got $($wave[0].SpreadMinutes)"
Check 'wave hosts sorted' ($wave[0].Hosts -eq 'H1, H2, H3') ''
$stag = @($rows | Where-Object Class -eq 'staggered')
Check 'stagger.exe staggered' ($stag.Count -eq 1 -and $stag[0].SpreadMinutes -eq 360) ''
Check 'wave sorts first' ($rows[0].Class -eq 'wave') ''

# min-tick per host: H2 saw tool.exe twice, keep earliest
$L2 = New-Object 'System.Collections.Generic.List[object]'
$L2.Add([pscustomobject]@{ Host = 'H1'; Leaf = 'dup.exe'; Stamp = '2026-11-20 10:00:00' })
$L2.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'dup.exe'; Stamp = '2026-11-20 11:00:00' })
$L2.Add([pscustomobject]@{ Host = 'H2'; Leaf = 'dup.exe'; Stamp = '2026-11-20 10:30:00' })
$r2 = @(New-FleetWaveRows $L2)
Check 'per-host min tick' ($r2.Count -eq 1 -and $r2[0].SpreadMinutes -eq 30) "got $($r2[0].SpreadMinutes)"

# custom windows: 25min misses the 10min wave window but fits a 1h stagger window;
# 6h stagger.exe exceeds it -> dropped
$r3 = @(New-FleetWaveRows $L -WaveMaxMin 10 -StaggerMaxH 1)
Check 'custom windows keep stagger only' ($r3.Count -eq 1 -and $r3[0].Name -eq 'tool.exe' -and $r3[0].Class -eq 'staggered') "got $($r3.Count): $($r3 | ForEach-Object { $_.Name + '/' + $_.Class })"

# empty input safe
$r4 = @(New-FleetWaveRows (New-Object 'System.Collections.Generic.List[object]'))
Check 'empty input' ($r4.Count -eq 0) ''

# wiring pins
Check 'version bumped' ($src -match 'Ophira v5\.2' -and $src -match '\$ScriptVersion = "5\.2"') ''
Check 'merge ingests amcache stamps' ($src.Contains("foreach (`$cn in @('FileKeyLastWriteTimestamp', 'KeyLastWriteTimestamp', 'LastWriteTimestamp'))")) ''
Check 'waves csv exported' ($src.Contains("fleet_waves.csv")) ''
Check 'report h2 present' ($src.Contains('Deployment waves (coordinated first-seen across hosts)')) ''
Check 'console line present' ($src.Contains('DEPLOYMENT WAVES')) ''
Check 'honesty meta present' ($src.Contains('clock skew between hosts is real')) ''
Check 'gate: needs 2+ hosts' ($src.Contains('if ($hosts.Count -ge 2 -and $leafStamps.Count -ge 2)')) ''

Write-Host ""
Write-Host "test_v49: $script:checks checks, $script:fails failed" -ForegroundColor $(if ($script:fails) { 'Red' } else { 'Green' })
exit $(if ($script:fails) { 1 } else { 0 })
