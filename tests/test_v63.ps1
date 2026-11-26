# test_v63.ps1 - v6.3 t-corr depth-2 chains: pivot expansion (rank-1 + candidate-flagged), Via column.
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check { param($name, $ok, $extra = '') if ($ok) { Write-Host "  [ok] $name" } else { Write-Host "  [FAIL] $name $extra" -ForegroundColor Red; $script:fails++ } }

# extract New-TCorr body
$m = [regex]::Match($src, "(?s)function New-TCorr \{.*?\r?\n\}")
Check 'extract New-TCorr' ($m.Success)

# stubs
$script:caseCsv = @{}
$script:savedRows = New-Object System.Collections.Generic.List[object]
function Import-CaseCsv { param($Name) if ($null -eq $script:caseCsv[$Name]) { return @() } return $script:caseCsv[$Name] }
function Save-Rows { param($Name, $Rows) foreach ($r in @($Rows)) { $script:savedRows.Add($r) } }
function Write-CaseLog { param($m, $c) }

# fixture pool (amcache) - weights vs evil.exe 10:00 / cmd.exe 10:02 / msiexec.exe 10:01:
#   msiexec 10:01:00 (dt 60 -> 0.905) rank1, cmd 10:02:00 (dt 120 -> 0.819) rank2,
#   psexec 10:03:30 (dt 210 -> 0.705) rank3, 7za 10:06:00 (dt 360 -> 0.549) rank4 -> NOT single-hop,
#   rpcx 10:40:00 outside every window.
$script:caseCsv['hunt_findings'] = @(
    [pscustomobject]@{ Severity = 'high'; Rule = 'R'; Entity = 'C:\x\evil.exe'; Evidence = 'e' }
)
$script:caseCsv['ioc_hits'] = @()
$script:caseCsv['yara_scanned'] = @()
function P([string]$n, [string]$t) { [pscustomobject]@{ Name = $n; T = [datetime]$t; Path = "c:\p\$n" } }
$pool = @(
    (P 'evil.exe' '2026-11-26 10:00:00'),
    (P 'msiexec.exe' '2026-11-26 10:01:00'),
    (P 'cmd.exe' '2026-11-26 10:02:00'),
    (P 'psexec.exe' '2026-11-26 10:03:30'),
    (P '7za.exe' '2026-11-26 10:06:00'),
    (P 'rpcx.exe' '2026-11-26 10:40:00')
)
$am = @()
foreach ($p in $pool) { $am += [pscustomobject]@{ Name = $p.Name; FullPath = "c:\p\$($p.Name)"; FileKeyLastWriteTimestamp = $p.T.ToString('yyyy-MM-dd HH:mm:ss') } }
$script:caseCsv['amcache'] = $am
$script:caseCsv['prefetch_parsed'] = @()
$script:caseCsv['security_proc_events'] = @()
$script:caseCsv['sysmon_proc_create'] = @()

Invoke-Expression $m.Value

# --- scenario 1: one seed, no flagged neighbours -> pivot = rank-1 (msiexec) only ---
New-TCorr
$rows = @($script:savedRows.ToArray())
Check 's1: 3 single-hop + 1 chain row' ($rows.Count -eq 4) "got $($rows.Count)"
$singles = @($rows | Where-Object { -not "$($_.Via)" })
Check 's1: 3 single-hop rows with empty Via' ($singles.Count -eq 3 -and @($singles | Where-Object { $_.Name -in @('msiexec.exe','cmd.exe','psexec.exe') }).Count -eq 3)
$ch = @($rows | Where-Object { "$($_.Via)" })
Check 's1: chain row via msiexec -> 7za' ($ch.Count -eq 1 -and $ch[0].Seed -eq 'evil.exe' -and $ch[0].Via -eq 'msiexec.exe' -and $ch[0].Name -eq '7za.exe') "via=$($ch[0].Via) name=$($ch[0].Name)"
Check 's1: chain bond' ("$($ch[0].Bond)" -eq 'chain hop') "bond=$($ch[0].Bond)"
Check 's1: chain anchored on PIVOT time (10:01, delta 5.0)' ("$($ch[0].SeedTime)" -eq '2026-11-26 10:01' -and [double]$ch[0].DeltaMinutes -eq 5.0) "t=$($ch[0].SeedTime) dt=$($ch[0].DeltaMinutes)"
Check 's1: chain weight vs pivot (0.607)' ([double]$ch[0].Weight -eq 0.607) "w=$($ch[0].Weight)"
Check 's1: rpcx never appears' (@($rows | Where-Object { $_.Name -eq 'rpcx.exe' }).Count -eq 0)
Check 's1: no self-chain' (@($rows | Where-Object { "$($_.Via)" -and $_.Name -eq $_.Seed }).Count -eq 0)

# --- scenario 2: cmd.exe also flagged -> candidate-flagged pivot (cmd) expands a second path ---
$script:caseCsv['hunt_findings'] = @(
    [pscustomobject]@{ Severity = 'high'; Rule = 'R'; Entity = 'C:\x\evil.exe'; Evidence = 'e' }
    [pscustomobject]@{ Severity = 'medium'; Rule = 'R2'; Entity = 'C:\y\cmd.exe'; Evidence = 'e' }
)
$script:savedRows.Clear()
New-TCorr
$rows2 = @($script:savedRows.ToArray())
$ch2 = @($rows2 | Where-Object { "$($_.Via)" })
# chains: (evil,7za,via msiexec 0.607) (evil,7za,via cmd 0.670) (cmd,7za,via msiexec 0.607) (cmd,7za,via evil 0.549)
Check 's2: 4 chain rows across both seeds' ($ch2.Count -eq 4) "got $($ch2.Count)"
$eViaM = @($ch2 | Where-Object { $_.Seed -eq 'evil.exe' -and $_.Via -eq 'msiexec.exe' })
$eViaC = @($ch2 | Where-Object { $_.Seed -eq 'evil.exe' -and $_.Via -eq 'cmd.exe' })
$cViaE = @($ch2 | Where-Object { $_.Seed -eq 'cmd.exe' -and $_.Via -eq 'evil.exe' })
Check 's2: flagged pivot cmd expands its own path' ($eViaC.Count -eq 1 -and $eViaC[0].Name -eq '7za.exe' -and [double]$eViaC[0].Weight -eq 0.67) "w=$($eViaC[0].Weight)"
Check 's2: rank-1 pivot path still present' ($eViaM.Count -eq 1 -and [double]$eViaM[0].Weight -eq 0.607)
Check 's2: cmd seed follows evil pivot (chain from candidate-flagged neighbour)' ($cViaE.Count -eq 1 -and [double]$cViaE[0].Weight -eq 0.549)
Check 's2: chain SeedTime anchored per pivot (via cmd -> 10:02)' ("$($eViaC[0].SeedTime)" -eq '2026-11-26 10:02' -and [double]$eViaC[0].DeltaMinutes -eq 4.0)
$cf = @($rows2 | Where-Object { $_.Seed -eq 'evil.exe' -and $_.Name -eq 'cmd.exe' -and -not "$($_.Via)" })
Check 's2: candidate flagged retained on single-hop' ($cf.Count -eq 1 -and "$($cf[0].Bond)" -match 'candidate flagged')
$bi = @($rows2 | Where-Object { "$($_.Bond)" -match 'bidirectional' })
Check 's2: bidirectional only on single-hop rows' ($bi.Count -ge 1 -and @($bi | Where-Object { "$($_.Via)" }).Count -eq 0)
Check 's2: singles stay 6 (3 per seed)' (@($rows2 | Where-Object { -not "$($_.Via)" }).Count -eq 6)

# --- wiring pins ---
Check 'report Via column' ($src.Contains('<th>Via</th>'))
Check 'report meta explains chain hops' ($src.Contains('depth-2 chain hops'))
Check 'chain rows capped at 100' ($src.Contains('-First 100'))
Check 'fleet spread skips Via rows' ($src.Contains('if ("$($r.Via)") { continue }'))
Check 'artifact description mentions chains' ($src.Contains('depth-2 chain hops (Via column)'))

Write-Host "test_v63: $(22 - $fails) checks passed, $fails failed"
if ($fails -gt 0) { exit 1 } else { exit 0 }
