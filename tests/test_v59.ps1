# test_v59.ps1 - v5.9 cross-artifact consistency engine (New-ConsistencyCheck + verdict doors)
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$checks = 0; $failed = 0
function Check([string]$Name, [bool]$Ok) {
    $script:checks++
    if (-not $Ok) { $script:failed++; Write-Host "[FAIL] $Name" } else { Write-Host "[ ok ] $Name" }
}

# ---- extracts ----
function Get-Fn([string]$Name) {
    $m = [regex]::Match($src, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $Name failed" }
    return $m.Value
}
$iwPath = Get-Fn 'Test-IsUserWritablePath'
$ccBody = Get-Fn 'New-ConsistencyCheck'
Invoke-Expression $iwPath

# ---- stubs ----
$script:caseCsv = @{}
function Import-CaseCsv([string]$Name) {
    $k = $Name -replace '\.csv$', ''
    if ($null -eq $script:caseCsv[$k]) { return @() }
    return $script:caseCsv[$k]
}
$script:saved = @{}
function Save-Rows([string]$Name, $Rows) { $script:saved[$Name] = @($Rows) }
function Write-CaseLog([string]$m, [string]$c) { }

function Row([hashtable]$h) { [pscustomobject]$h }
function ShimRow([string]$p, [string]$ex) { Row @{ Path = $p; LastModified = '2026-11-01 10:00:00'; Executed = $ex; ControlSet = '1'; CachePosition = '1'; Signature = '10ts' } }
function PfRow([string]$n) { Row @{ ExecutableName = $n; RunCount = '3'; LastRun = '2026-11-01 10:00:00' } }
function AmcRow([string]$fp, [string]$app) { Row @{ FullPath = $fp; ApplicationName = $app; Name = ''; FileKeyLastWriteTimestamp = '2026-11-01 10:00:00' } }
function ProcRow([string]$np) { Row @{ NewProcess = $np; Account = 'aryan' } }

function Run-CC {
    # PS quirk: & on a function-DEFINITION scriptblock only defines it - call the name after;
    # missing hashtable key + @() = one null element, so guard with ContainsKey
    $script:saved = @{}
    $cc = [scriptblock]::Create($ccBody)
    . $cc
    New-ConsistencyCheck
    if (-not $script:saved.ContainsKey('consistency_flags')) { return @() }
    return $script:saved['consistency_flags']
}

# ---- T1: PREFETCH-GAP fires (prefetch populated, shimcache yes, non-Windows path, silent prefetch) ----
$script:caseCsv = @{
    'shimcache_exec'      = @(ShimRow 'C:\Users\Aryan\Downloads\tool.exe' 'yes')
    'prefetch_parsed'     = @(1..55 | ForEach-Object { PfRow "app$_.exe" })
    'amcache'             = @(1..120 | ForEach-Object { AmcRow "C:\Users\Aryan\app$_.exe" "app$_.exe" })
    'security_proc_events' = @()
    'sysmon_proc_create'  = @()
}
$f = Run-CC
$pg = @($f | Where-Object { $_.Kind -eq 'PREFETCH-GAP' })
Check 'T1: prefetch-gap fires on populated prefetch + silent name' ($pg.Count -eq 1 -and "$($pg[0].Item)" -eq 'C:\Users\Aryan\Downloads\tool.exe')
Check 'T1: prefetch-gap severity low + churn-honest detail' ("$($pg[0].Severity)" -eq 'low' -and "$($pg[0].Detail)" -match 'churn')

# ---- T2: Windows-path shimcache row exempt ----
$script:caseCsv['shimcache_exec'] = @(ShimRow 'C:\Windows\System32\tool.exe' 'yes')
$f = Run-CC
Check 'T2: windows-path executed row exempt' (@($f | Where-Object { $_.Kind -eq 'PREFETCH-GAP' }).Count -eq 0)

# ---- T3: sparse prefetch (<50) gates the check entirely ----
$script:caseCsv['shimcache_exec'] = @(ShimRow 'C:\Users\Aryan\Downloads\tool.exe' 'yes')
$script:caseCsv['prefetch_parsed'] = @(1..10 | ForEach-Object { PfRow "app$_.exe" })
$f = Run-CC
Check 'T3: sparse prefetch gates prefetch-gap' (@($f | Where-Object { $_.Kind -eq 'PREFETCH-GAP' }).Count -eq 0)

# ---- T3b: empty shimcache does not kill the staged/amcache views (gate is per-check) ----
$script:caseCsv['shimcache_exec'] = @()
$script:caseCsv['security_proc_events'] = @()
$f = Run-CC
Check 'T3b: shimcache-empty keeps staged view alive' (@($f | Where-Object { $_.Kind -eq 'STAGED-NORUN' }).Count -gt 0)

# ---- T4: AMCACHE-GAP fires (proc event, user path, amcache silent) ----
$script:caseCsv['prefetch_parsed'] = @(1..55 | ForEach-Object { PfRow "app$_.exe" })
$script:caseCsv['security_proc_events'] = @(ProcRow 'C:\Users\Aryan\Downloads\evil.exe')
$f = Run-CC
$ag = @($f | Where-Object { $_.Kind -eq 'AMCACHE-GAP' })
Check 'T4: amcache-gap fires on 4688 run not in amcache' ($ag.Count -eq 1 -and "$($ag[0].Item)" -eq 'C:\Users\Aryan\Downloads\evil.exe')

# ---- T5: system32 proc run exempt (not user-writable) ----
$script:caseCsv['security_proc_events'] = @(ProcRow 'C:\Windows\System32\cmd.exe')
$f = Run-CC
Check 'T5: system32 proc run exempt' (@($f | Where-Object { $_.Kind -eq 'AMCACHE-GAP' }).Count -eq 0)

# ---- T6: STAGED-NORUN (amcache exe, no run evidence anywhere) ----
$script:caseCsv['security_proc_events'] = @()
$script:caseCsv['shimcache_exec'] = @()
$script:caseCsv['amcache'] = @(AmcRow 'C:\Users\Aryan\staged.exe' 'staged.exe') + @(1..120 | ForEach-Object { AmcRow "C:\Users\Aryan\app$_.exe" "app$_.exe" })
# app1..app120 also staged (no prefetch hit) - cap proves below; keep prefetch hitting app1
$script:caseCsv['prefetch_parsed'] = @(PfRow 'app1.exe') + @(2..54 | ForEach-Object { PfRow "other$_.exe" })
$f = Run-CC
$st = @($f | Where-Object { $_.Kind -eq 'STAGED-NORUN' })
$staged1 = @($st | Where-Object { "$($_.Item)" -eq 'C:\Users\Aryan\staged.exe' })
Check 'T6: staged-no-run fires for amcache exe with no run evidence' ($staged1.Count -eq 1)
Check 'T6: staged rows capped at 15' ($st.Count -eq 15)
Check 'T6: staged severity info (no verdict weight)' ("$($staged1[0].Severity)" -eq 'info')

# ---- T7: dll excluded from staged (exe/scr/pif only) ----
$script:caseCsv['amcache'] = @(AmcRow 'C:\Users\Aryan\lib.dll' 'lib.dll') + @(1..120 | ForEach-Object { AmcRow "C:\Users\Aryan\app$_.exe" "app$_.exe" })
$f = Run-CC
Check 'T7: dll excluded from staged view' (-not ($f | Where-Object { "$($_.Item)" -eq 'C:\Users\Aryan\lib.dll' }))

# ---- T8: prefetch-known name not staged ----
$script:caseCsv['amcache'] = @(AmcRow 'C:\Users\Aryan\app1.exe' 'app1.exe') + @(2..120 | ForEach-Object { AmcRow "C:\Users\Aryan\app$_.exe" "app$_.exe" })
$f = Run-CC
Check 'T8: prefetch-known name not staged' (-not ($f | Where-Object { $_.Kind -eq 'STAGED-NORUN' -and "$($_.Item)" -eq 'C:\Users\Aryan\app1.exe' }))

# ---- T9: missing evidence skips cleanly ----
$script:caseCsv = @{ 'shimcache_exec' = @(); 'prefetch_parsed' = @(); 'amcache' = @() }
$f = Run-CC
Check 'T9: empty evidence -> no rows, no crash' ($f.Count -eq 0)

# ---- T10: verdict doors + wiring ----
Check 'T10: prefetch-gap has NO verdict door (report-only)' (-not $src.Contains("Add-Signal 'Execution-evidence inconsistency (prefetch gap)'"))
Check 'T10: amcache-gap door floor 2' ($src.Contains("Add-Signal 'Execution-evidence inconsistency (amcache gap)' 2"))
Check 'T10: regen step wired' ($src.Contains("'consistency flags' 'New-ConsistencyCheck'"))
Check 'T10: CsvCatMap derived entry' ($src.Contains("'consistency_flags' = 'derived'"))
Check 'T10: hunt anchor arm covers consistency_flags' ($src.Contains('|exec_tcorr|consistency_flags)'))
Check 'T10: desc map entry' ($src.Contains("'consistency_flags'              = 'Cross-artifact consistency:"))
Check 'T10: emptyWhy entry' ($src.Contains("'consistency_flags'              = 'all execution artifacts consistent"))
Check 'T10: report import + nav count + section' ($src.Contains("Import-CaseCsv 'consistency_flags.csv'") -and $src.Contains('+ $consFlags.Count') -and $src.Contains('Cross-artifact consistency - evidence that contradicts itself'))
Check 'T10: honesty meta in section' ($src.Contains('NOT a verdict weight') -and $src.Contains('STAGED-NORUN is context only') -and $src.Contains('floor-2 signal'))

Write-Host ''
Write-Host "test_v59: $checks checks, $failed failed"
if ($failed -gt 0) { exit 1 }
exit 0
