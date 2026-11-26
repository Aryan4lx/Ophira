# test_v61.ps1 - v6.2 t-corr upgrades: top-3 ranked candidates, IOC/YARA seeds, candidate-flagged bond.
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check { param($name, $ok, $extra = '') if ($ok) { Write-Host "  [ok] $name" } else { Write-Host "  [FAIL] $name $extra" -ForegroundColor Red; $script:fails++ } }

# extract New-TCorr body
$m = [regex]::Match($src, "(?s)function New-TCorr \{.*?\r?\n\}")
Check 'extract New-TCorr' ($m.Success)
$m2 = [regex]::Match($src, "(?s)function Get-InvariantDate \{.*?\r?\n\}")
if ($m2.Success) { Invoke-Expression $m2.Value }

# stubs
$script:caseCsv = @{}
$script:savedRows = New-Object System.Collections.Generic.List[object]
function Import-CaseCsv { param($Name) if ($null -eq $script:caseCsv[$Name]) { return @() } return $script:caseCsv[$Name] }
function Save-Rows { param($Name, $Rows) foreach ($r in @($Rows)) { $script:savedRows.Add($r) }; if ($Name -eq $null) { } }
function Write-CaseLog { param($m, $c) if ($m -eq $null -and $c -eq $null) { } }
Set-Variable -Name QuietLog -Value {} -Scope Script 2>$null

# fixtures: 1 hunt seed (evil.exe) + ioc/yara seeds + pool with 4 neighbours at decreasing weights
$script:caseCsv['hunt_findings'] = @(
    [pscustomobject]@{ Severity = 'high'; Rule = 'R'; Entity = 'C:\x\evil.exe'; Evidence = 'e' }
    [pscustomobject]@{ Severity = 'low';  Rule = 'R'; Entity = 'C:\x\lowbin.exe'; Evidence = 'e' }  # low: NOT a seed
)
$script:caseCsv['ioc_hits'] = @(
    [pscustomobject]@{ Entity = 'C:\users\public\iocdrop.exe'; Indicator = 'iocdrop.exe' }
    [pscustomobject]@{ Entity = '203.0.113.9'; Indicator = 'ip' }   # non-exe: NOT a seed
)
$script:caseCsv['yara_scanned'] = @(
    [pscustomobject]@{ File = 'E:\apps\yarahit.exe'; SHA256 = 'a'; Hits = 'x'; Rules = 'y' }
    [pscustomobject]@{ File = ''; SHA256 = 'b'; Hits = 'x'; Rules = 'y' }   # empty file: skipped
)
function P([string]$n, [string]$t) { [pscustomobject]@{ Name = $n; T = [datetime]$t; Path = "c:\p\$n" } }
$pool = @(
    (P 'evil.exe' '2026-11-26 10:00:00'),    # the seed's own run - t-corr anchors on it
    (P 'n1.exe' '2026-11-26 10:00:30'), (P 'n2.exe' '2026-11-26 10:02:00'),
    (P 'n3.exe' '2026-11-26 10:10:00'), (P 'n4.exe' '2026-11-26 10:25:00'),
    (P 'n5.exe' '2026-11-26 10:45:00'),   # >30min from 10:00 seed: excluded
    (P 'iocdrop.exe' '2026-11-26 10:05:00'), (P 'yarahit.exe' '2026-11-26 10:20:00')  # seeded via ioc/yara need own runs too
)
# New-TCorr builds its own pool from CSVs; feed via amcache (Name + FileKeyLastWriteTimestamp)
$am = @()
foreach ($p in $pool) { $am += [pscustomobject]@{ Name = $p.Name; FullPath = "c:\p\$($p.Name)"; FileKeyLastWriteTimestamp = $p.T.ToString('yyyy-MM-dd HH:mm:ss') } }
$script:caseCsv['amcache'] = $am
$script:caseCsv['prefetch_parsed'] = @()
$script:caseCsv['security_proc_events'] = @()
$script:caseCsv['sysmon_proc_create'] = @()

# a neighbour that is itself flagged (n2 also a hunt finding at med) -> candidate flagged
$script:caseCsv['hunt_findings'] = @(
    [pscustomobject]@{ Severity = 'high'; Rule = 'R'; Entity = 'C:\x\evil.exe'; Evidence = 'e' }
    [pscustomobject]@{ Severity = 'medium'; Rule = 'R2'; Entity = 'C:\y\n2.exe'; Evidence = 'e' }
)

Invoke-Expression $m.Value
New-TCorr

$rows = @($script:savedRows.ToArray())
Check 'rows exist' ($rows.Count -gt 0)
# v6.3: pin single-hop rows only (chain rows carry Via and grow the set legitimately)
$singleHop = @($rows | Where-Object { -not "$($_.Via)" })
Check 'top3 per seed' ($singleHop.Count -eq 12) "got $($singleHop.Count)"
# v6.3: rank assertions apply to single-hop rows only (chain rows have their own Rank 1..2 space)
$evRows = @($singleHop | Where-Object { $_.Seed -eq 'evil.exe' } | Sort-Object Rank)
Check 'ranks 1..3' ($evRows[0].Rank -eq 1 -and $evRows[1].Rank -eq 2 -and $evRows[2].Rank -eq 3)
Check 'rank1 = closest' ($evRows[0].Name -eq 'n1.exe') "got $($evRows[0].Name)"
Check 'rank3 = next-nearest by weight' ($evRows[2].Name -eq 'iocdrop.exe') "got $($evRows[2].Name)"
$flagged = @($rows | Where-Object { $_.Seed -eq 'evil.exe' -and $_.Name -eq 'n2.exe' })
Check 'candidate flagged bond' ($flagged.Count -eq 1 -and "$($flagged[0].Bond)" -match 'candidate flagged') "bond=$($flagged[0].Bond) count=$($flagged.Count)"
Check 'ioc seed present' (@($rows | Where-Object { $_.Seed -eq 'iocdrop.exe' }).Count -gt 0)
Check 'yara seed present' (@($rows | Where-Object { $_.Seed -eq 'yarahit.exe' }).Count -gt 0)
Check 'low-severity never seeded' (@($rows | Where-Object { $_.Seed -eq 'lowbin.exe' }).Count -eq 0)
Check 'ip ioc never seeded' (@($rows | Where-Object { $_.Seed -eq '203.0.113.9' }).Count -eq 0)

# bidirectional still works: n2 flagged seed correlated back to evil.exe? make evil.exe run near n2's run
$am2 = $am + (P 'evil.exe' '2026-11-26 10:03:00')
$am2 = $am2 | ForEach-Object { $_ }
$script:caseCsv['amcache'] = $am2
$script:savedRows.Clear()
Invoke-Expression $m.Value
New-TCorr
$rows2 = @($script:savedRows.ToArray())
$bi = @($rows2 | Where-Object { "$($_.Bond)" -match 'bidirectional' })
Check 'bidirectional retained' ($bi.Count -ge 1)

# wiring pins
Check 'Rank column in report table' ($src.Contains('<th>Rank</th>'))
Check 'candidate flagged in report meta' ($src.Contains('candidate flagged'))
Check 'fleet_tcorr csv written' ($src.Contains("fleet_tcorr.csv"))
Check 'fleet t-corr console line' ($src.Contains('FLEET T-CORR SPREAD'))
Check 'fleet per-host exec_tcorr load' ($src.Contains("Join-Path `$csvDir 'exec_tcorr.csv'"))
Check 'fleet report h2' ($src.Contains('Fleet t-corr spread'))
Check 'version 6.3' ($src.Contains('$ScriptVersion = "6.3"'))

Write-Host "test_v61: $(16 - $fails) checks passed, $fails failed"
if ($fails -gt 0) { exit 1 } else { exit 0 }
