$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
# v2.80 verdict-truth tests - F1 gap-tamper FP (clear|stop), F3 'Admin-share' regex term,
# R33 'Sysmon configuration changed' verdict weight, plus a two-way drift pin between the
# hunt rules' high-severity names and the verdict's high-precision regex.
# Source-analysis suite: extracts function bodies, no case fixtures needed.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- extract function bodies (house pattern: lazy match to column-0 closing brace) ----
$mh = [regex]::Match($src, '(?s)function New-HuntFindings \{.*?\r?\n\}')
if (-not $mh.Success) { throw 'New-HuntFindings extract failed' }
$mv = [regex]::Match($src, '(?s)function Get-CompromiseVerdict \{.*?\r?\n\}')
if (-not $mv.Success) { throw 'Get-CompromiseVerdict extract failed' }
$huntBody = $mh.Value
$verdictBody = $mv.Value

# ---- extract the huntHi verdict high-precision regex from Get-CompromiseVerdict ----
$mRe = [regex]::Match($verdictBody, '"\$\(\$_\.Rule\)" -match ''([^'']+)''')
if (-not $mRe.Success) { throw 'huntHi verdict regex extract failed' }
$verdictRe = $mRe.Groups[1].Value

# ---- extract rule names + severity args from & $find calls in New-HuntFindings ----
# shape: & $find 'Name' 'sev' ... (single or double quoted name; severity literal or $variable)
$findRe = '& \$find (?:(?:''([^'']+)''|"([^"]+)")) (?:''(\w+)''|(\$[A-Za-z0-9_]+))'
$litHi = New-Object System.Collections.Generic.List[string]
$varSev = New-Object System.Collections.Generic.List[string]
$totalFinds = 0
foreach ($m in [regex]::Matches($huntBody, $findRe)) {
    $totalFinds++
    $name = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
    $sev = if ($m.Groups[3].Success) { $m.Groups[3].Value } else { $m.Groups[4].Value }
    if ($sev -eq 'high') { [void]$litHi.Add($name) }
    elseif ($sev.StartsWith('$')) { [void]$varSev.Add($name) }
}

# ---- F3 + R33: every LITERAL-high rule name must match the verdict high-precision regex ----
$expectedHi = @(
    'Admin-share executable staging',
    'C2-style named pipe (known C2 family)',
    'DCSync - replication access by user account',
    'Defender exclusion configuration changed',
    'Defender real-time protection DISABLED',
    'Direct volume access (raw \\.\ read)',
    'DLL side-load - planted system DLL name in user path',
    'DLL side-load - proxy DLL in user-writable path',
    'LSASS access - non-system process opened lsass.exe',
    'Office app spawned interpreter',
    'Password spray - many accounts from one source',
    'Process image tampering (hollowing)',
    'RDP ServiceDll tamper',
    'Remote-access tunnel binary active',
    'Renamed LOLBin (version-info mismatch)',
    'Renamed LOLBin at rest (Sysmon identity mismatch)',
    'SSH authorized_keys present',
    'Sysmon configuration changed',
    'Web server spawned interpreter',
    'WMI event subscription persistence',
    # v2.83: these two reach the verdict through DEDICATED Add-Signal lines (floor 3) instead
    # of the huntHi catch-all regex - the mapping must stay explicit so a new high rule cannot
    # silently skip the verdict
    'Hidden scheduled task (TaskCache SD value stripped)',
    'ntds.dit accessed (ESENT 325/326)'
)
Check "hunt rules: found $totalFinds &find call sites (extraction sane)" ($totalFinds -ge 40)
$litHiUniq = @($litHi | Sort-Object -Unique)
$dedicatedHi = @('Hidden scheduled task (TaskCache SD value stripped)', 'ntds.dit accessed (ESENT 325/326)')
Check "literal-high rules: 22 distinct (got $($litHiUniq.Count))" ($litHiUniq.Count -eq 22)
$misses = @($expectedHi | Where-Object { $_ -notin $dedicatedHi -and $_ -notmatch $verdictRe })
Check "dedicated verdict-door highs are wired as signals" ($src.Contains("Add-Signal 'Hidden scheduled task (TaskCache SD stripped)' 3") -and $src.Contains("Add-Signal 'ntds.dit accessed - non-backup pattern (ESENT 325/326)' 3"))
Check "every literal-high rule name matches the verdict high-precision regex$(if ($misses.Count) { ' - misses: ' + ($misses -join '; ') })" ($misses.Count -eq 0)

# ---- two-way drift pin: extracted names must EQUAL the hardcoded list (catches renames and
# new high rules that were not classified as verdict-relevant) ----
$gotHi = (@($litHiUniq | Sort-Object) -join "`n")
$wantHi = (@($expectedHi | Sort-Object) -join "`n")
Check "two-way drift pin: literal-high names extracted from source == hardcoded list" ($gotHi -eq $wantHi)

# ---- the 5 variable-severity rules (can emit high) must match the verdict regex too ----
$expectedVar = @('Downloaded then executed', 'LOLBin proxy-execution - $hit', 'Svchost masquerade indicator', 'Cross-process injection (remote thread)', 'Lookalike system binary (Levenshtein near-name)')
$varUniq = @($varSev | Sort-Object -Unique)
$varMiss = @($expectedVar | Where-Object { $_ -notmatch $verdictRe })
Check "variable-severity rules: 5 distinct (got $($varUniq.Count))" ($varUniq.Count -eq 5)
Check "two-way drift pin: variable-severity names == hardcoded list" ((@($varUniq | Sort-Object) -join "`n") -eq (@($expectedVar | Sort-Object) -join "`n"))
Check "every variable-severity rule name matches the verdict regex$(if ($varMiss.Count) { ' - misses: ' + ($varMiss -join '; ') })" ($varMiss.Count -eq 0)

# ---- F1 behavioral pin: the gap-tamper filters no longer count benign 6006 'STOPPED' rows ----
# Isolate the Where-Object filter expression, compile it to a predicate scriptblock.
$mGt = [regex]::Match($verdictBody, '\$gapTamper = @\(\$gaps \| Where-Object \{ (.*?) \}\)\.Count')
if (-not $mGt.Success) { throw 'gapTamper filter extract failed' }
$isTamper = [scriptblock]::Create('param($row) ' + $mGt.Groups[1].Value.Replace('$_', '$row'))
Check "F1 verdict filter: 6006 'Event logging STOPPED (shutdown)' NOT counted" (-not (& $isTamper ([pscustomobject]@{ EventId = '6006'; Meaning = 'Event logging STOPPED (shutdown)' })))
Check "F1 verdict filter: 1102 'Audit log was cleared' counted" (& $isTamper ([pscustomobject]@{ EventId = '1102'; Meaning = 'Audit log was cleared' }))
Check "F1 verdict filter: 104 'System log was cleared' counted" (& $isTamper ([pscustomobject]@{ EventId = '104'; Meaning = 'System log was cleared' }))

# same predicate lives in the report's Log-integrity clean-check (v2.64 'SAME predicate' promise)
$mClean = [regex]::Match($src, 'if \(\(Test-CaseCsv ''logging_gaps''\) -and @\(\$gaps \| Where-Object \{ (.*?) \}\)\.Count -eq 0\)')
if (-not $mClean.Success) { throw 'clean-check filter extract failed' }
$cleanExpr = $mClean.Groups[1].Value
$isTamperClean = [scriptblock]::Create('param($row) ' + $cleanExpr.Replace('$_', '$row'))
Check "F1 clean-check filter: 6006 'STOPPED (shutdown)' NOT counted" (-not (& $isTamperClean ([pscustomobject]@{ EventId = '6006'; Meaning = 'Event logging STOPPED (shutdown)' })))
Check "F1 clean-check filter: 1102 'Audit log was cleared' counted" (& $isTamperClean ([pscustomobject]@{ EventId = '1102'; Meaning = 'Audit log was cleared' }))
Check "F1 clean-check filter: 104 'System log was cleared' counted" (& $isTamperClean ([pscustomobject]@{ EventId = '104'; Meaning = 'System log was cleared' }))
Check "F1: clean-check filter text identical to the verdict's tamper filter" ($cleanExpr -eq $mGt.Groups[1].Value)
Check "F1: neither filter still contains the 'clear|stop' fallback" (($mGt.Groups[1].Value -notmatch 'stop') -and ($cleanExpr -notmatch 'stop'))

# ---- prose pin: hunt-table meta line no longer carves out Sysmon configuration changes ----
Check "prose: hunt-table meta no longer contains the Sysmon report-only exception clause" ($src -notmatch 'the exception is Sysmon configuration changes')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
