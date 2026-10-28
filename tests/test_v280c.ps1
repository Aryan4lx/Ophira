# test_v280c.ps1 - v2.80 T4 (report accuracy + custody):
#   I1 supertimeline per-source caps keep the NEWEST events (were: head-count kept the oldest
#       while the final total cap kept the newest - newest evidence silently dropped on busy cases)
#   I2 $null EndpointAdmin (parsed package) = UNKNOWN: no -15 penalty, no false "NOT elevated"
#       caveat; honest unknown caveat instead. Explicit $false keeps today's behavior.
#   I3 Parse-mode repack regenerates manifest.txt via shared New-CaseManifest (endpoint header
#       lines kept + ANALYST-PARSED line + refreshed hashes + PACKAGE SHA256 of the new zip)
#   M1 timeline caption uses the real shown count (hardcoded 150 removed)
#   M3 run-keys label honest when the table truncates at 60
#   M4 evidence-index supertimeline link points at the mapped csv tree path (was case-root file)
#   M6 Sigma rule-name sanitize collisions get deterministic _2/_3 suffixes (no merged drills /
#       overwritten per-rule CSVs); unique names keep today's keys
#   M7 culture-invariant datetime parsing (Get-InvariantDate) for the supertimeline weave and
#       the IOC context probe; helper shared into $script:SharedFunctions for pool workers
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
function Get-Extracted([string]$name) {
    # IEX must run at TOP level (script scope) or the defined function dies with this scope
    $m = [regex]::Match($src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $name" }
    return $m.Value
}

$tmp = Join-Path $env:TEMP ("ophira_v280c_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $tmp 'csv'), (Join-Path $tmp 'csv\derived'), (Join-Path $tmp 'raw\evtx'), (Join-Path $tmp 'mem') -Force | Out-Null
$CsvDir = Join-Path $tmp 'csv'; $RawDir = Join-Path $tmp 'raw'; $MemDir = Join-Path $tmp 'mem'; $CaseDir = $tmp
$Computer = 'T4HOST'; $Analyst = 'fixture'; $ScriptVersion = '9.99'; $global:LogHours = 168
$script:CurrentCaseID = 'CASE-T4'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null; $script:DeltaCount = 0
$script:ShareOk = $false; $Sysmon = $true; $IsAdmin = $true; $script:HostRole = 'workstation'
$StartTime = Get-Date
function Test-IsAdmin { return $false }   # analyst token NOT elevated - must not leak into the $null handling
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Save-Rows { param([string]$Name, $Rows) }
function Get-HayabusaExe { return $null }
function Invoke-NativeTool { param($ExePath, $ToolArgs, $WorkingDirectory, $QuietLog) return $null }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Get-LogRangeText { 'From 2026-09-01 08:00 to 2026-09-24 08:00' }
$script:fixtureRows = @{}
$script:presentCsvs = @()
function Import-CaseCsv([string]$name) { $name = "$name" -replace '\.csv$', ''; if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function Test-CaseCsv([string]$n) { return ($script:presentCsvs -contains $n) }

# ---- M7: Get-InvariantDate ----
Invoke-Expression (Get-Extracted 'Get-InvariantDate')
$gd = Get-InvariantDate '02/03/2026'
Check "M7: '02/03/2026' parses invariant MM/dd/yyyy (Feb 3 - no locale flip)" ($gd.Month -eq 2 -and $gd.Day -eq 3 -and $gd.Year -eq 2026)
Check "M7: ISO-ish '2026-01-05 10:00:00' parses" ((Get-InvariantDate '2026-01-05 10:00:00') -eq [datetime]'2026-01-05 10:00:00')
Check "M7: garbage -> MinValue sentinel" ((Get-InvariantDate 'not a date') -eq [datetime]::MinValue)
Check "M7: [datetime] passes through unchanged" ((Get-InvariantDate ([datetime]'2026-03-02 01:02:03')) -eq [datetime]'2026-03-02 01:02:03')
Check "M7: helper shared with pool workers (SharedFunctions)" ($src -match "(?s)\`$script:SharedFunctions = @\(.*?'Get-InvariantDate'")
Check "M7: supertimeline weave uses the helper (no [datetime] cast in `$add)" (($src -match [regex]::Escape('$dt = Get-InvariantDate $ts')) -and ($src -notmatch [regex]::Escape('try { $iso = ([datetime]$ts)')))
Check "M7: IOC context probe uses the helper" (($src -match [regex]::Escape('$fs = Get-InvariantDate $e.FirstSeen')) -and ($src -notmatch [regex]::Escape('([datetime]$e.FirstSeen)')))

# ---- M6: collision-free rule keys ----
Invoke-Expression (Get-Extracted 'Get-SafeRuleKey')
Invoke-Expression (Get-Extracted 'Get-SafeRuleKeyMap')
Invoke-Expression (Get-Extracted 'Resolve-SafeRuleKey')
$rows6 = @(
    [pscustomobject]@{ RuleTitle = 'Rule A'; X = 1 }
    [pscustomobject]@{ RuleTitle = 'Rule_A'; X = 2 }
    [pscustomobject]@{ RuleTitle = 'Totally Different'; X = 3 }
)
$map6 = Get-SafeRuleKeyMap $rows6 'RuleTitle'
$k1 = $map6['Rule A']; $k2 = $map6['Rule_A']
Check "M6: colliding names sanitize-equal -> two DISTINCT keys" (($k1 -ne $k2) -and $k1 -and $k2)
Check "M6: first name keeps plain sanitize, second gets _2" ($k1 -eq 'Rule_A' -and $k2 -eq 'Rule_A_2')
Check "M6: unique name keeps plain key (no suffix)" ($map6['Totally Different'] -eq 'Totally_Different')
Check "M6: Resolve hits the map, falls back plain for unknowns" (((Resolve-SafeRuleKey $map6 'Rule_A') -eq $k2) -and ((Resolve-SafeRuleKey $map6 'Unknown Rule') -eq 'Unknown_Rule'))
$map6b = Get-SafeRuleKeyMap $rows6 'RuleTitle'
Check "M6: map deterministic across calls (report keys == sigma-logs keys)" (($map6b['Rule A'] -eq $k1) -and ($map6b['Rule_A'] -eq $k2))
$long1 = ('x' * 90) + 'aaa'; $long2 = ('x' * 90) + 'bbb'
$mapL = Get-SafeRuleKeyMap @([pscustomobject]@{ N = $long1 }, [pscustomobject]@{ N = $long2 }) 'N'
Check "M6: 80-char truncate collisions still get distinct keys" ($mapL[$long1] -ne $mapL[$long2])
Check "M6: report builds ONE shared map from raw hayabusa rows" (($src -match [regex]::Escape('Get-SafeRuleKeyMap $hayRaw $nameColPre')) -and ($src -match [regex]::Escape('$sigmaRuleMap = Get-SafeRuleKeyMap $hay $nameCol')))

# ---- I1: per-source caps keep the NEWEST ----
Invoke-Expression (Get-Extracted 'New-SuperTimeline')
$st = Join-Path $CsvDir (Get-CaseCsvPath 'supertimeline')
$base = [datetime]'2026-05-01 00:00:00'
$rowsI1 = @(0..504 | ForEach-Object { [pscustomobject]@{ Time = $base.AddMinutes($_).ToString('yyyy-MM-dd HH:mm:ss'); EventId = '5001'; Detail = "evt $_" } })
$script:fixtureRows = @{ defender_config_events = $rowsI1 }   # weave source, cap 500
$null = New-SuperTimeline
$tlOut = @(Import-Csv -LiteralPath $st)
$dc = @($tlOut | Where-Object { $_.Source -eq 'defender_config_events' })
Check "I1: cap 500 on a 505-row source keeps exactly 500" ($dc.Count -eq 500)
$exp = @(0..504 | ForEach-Object { $base.AddMinutes($_).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') })
$keptTimes = @($dc | ForEach-Object { $_.Timestamp })
$dropped = @($exp | Where-Object { $keptTimes -notcontains $_ })
Check "I1: keeps the NEWEST 500 - exactly the oldest 5 dropped" (($dropped.Count -eq 5) -and ((@($dropped | Sort-Object) -join '|') -eq ((@($exp[0..4]) | Sort-Object) -join '|')))
Check "I1: newest row kept" ($keptTimes -contains $exp[504])
$rowsG = @(0..5001 | ForEach-Object { [pscustomobject]@{ TimeCreated = $base.AddSeconds($_).ToString('yyyy-MM-dd HH:mm:ss'); Id = '4624'; Message = "m $_" } })
$script:fixtureRows = @{ security_events = $rowsG }   # generic event-log loop, cap 5000
$null = New-SuperTimeline
$tlOut3 = @(Import-Csv -LiteralPath $st)
$sec = @($tlOut3 | Where-Object { $_.Source -eq 'security_events' })
$secDetails = @($sec | ForEach-Object { $_.Detail })
Check "I1: generic event-log cap 5000 keeps exactly 5000, the NEWEST half" (($sec.Count -eq 5000) -and ($secDetails -notcontains 'm 0') -and ($secDetails -contains 'm 5001'))
$script:fixtureRows = @{
    sysmon_file_delete = @(
        [pscustomobject]@{ Time = '2026-05-02 10:00:00'; Image = 'C:\a.exe'; TargetFilename = 'C:\del1.dll' }
        [pscustomobject]@{ Time = '2026-05-02 11:00:00'; Image = 'C:\b.exe'; TargetFilename = 'C:\del2.dll' }
    )
}
$null = New-SuperTimeline
$tlOut2 = @(Import-Csv -LiteralPath $st)
Check "I1: under-cap source keeps all rows (no off-by-one)" (@($tlOut2 | Where-Object { $_.Source -eq 'sysmon_file_delete' }).Count -eq 2)
$script:fixtureRows = @{ srum_usage = @(
    [pscustomobject]@{ Timestamp = '2026-09-01 03:11:00'; Application = 'tool.exe'; User = 'aryan'; BytesSent = '5000'; BytesReceived = '3000'; InterfaceType = '' }
) }
$null = New-SuperTimeline
$tlOut1 = @(Import-Csv -LiteralPath $st)
# regression: exactly one buffered row must weave as ONE row, not iterate the row's fields
Check "I1: single-row source weaves exactly one intact row (PS unroll guard)" (@($tlOut1 | Where-Object { $_.Source -eq 'srum_usage' }).Count -eq 1 -and @($tlOut1 | Where-Object { $_.Source -eq 'srum_usage' })[0].Detail -eq 'sent 5000 / recv 3000 bytes')
Check "I1: total cap still keeps the newest tail" ($src -match [regex]::Escape('Select-Object -Last 120000'))

# ---- I2: $null EndpointAdmin = unknown, not non-elevated ----
Invoke-Expression (Get-Extracted 'Get-LvlRank')
Invoke-Expression (Get-Extracted 'Get-CompromiseVerdict')
$script:fixtureRows = @{}
$script:presentCsvs = @('security_events', 'powershell_events', 'sysmon_events', 'prefetch_index', 'amcache', 'hayabusa_timeline', 'flash_process_scored')
$script:EndpointAdmin = $true; $vT = Get-CompromiseVerdict
$script:EndpointAdmin = $null; $vN = Get-CompromiseVerdict
$script:EndpointAdmin = $false; $vF = Get-CompromiseVerdict
Check "I2: null (parsed pkg) -> NO 'Run was NOT elevated' caveat" (@($vN.Caveats | Where-Object { $_ -like 'Run was NOT elevated*' }).Count -eq 0)
Check "I2: null -> unknown-status caveat present" (@($vN.Caveats | Where-Object { $_ -like 'Endpoint elevation status unknown*' }).Count -eq 1)
Check "I2: null -> no -15 penalty (confidence == explicit-elevated run, Test-IsAdmin `$false ignored)" ($vN.ConfidencePercent -eq $vT.ConfidencePercent)
Check "I2: explicit `$false keeps today's behavior (NOT-elevated caveat)" (@($vF.Caveats | Where-Object { $_ -like 'Run was NOT elevated*' }).Count -eq 1)
Check "I2: explicit `$false -> no unknown caveat" (@($vF.Caveats | Where-Object { $_ -like 'Endpoint elevation status unknown*' }).Count -eq 0)
Check "I2: explicit `$false -> penalty path live (confidence <= elevated run)" ($vF.ConfidencePercent -le $vT.ConfidencePercent)
Check "I2: no Test-IsAdmin fallback left in Get-CompromiseVerdict" ($src -notmatch [regex]::Escape('else { Test-IsAdmin }'))

# ---- I3: manifest regen on repack ----
Invoke-Expression (Get-Extracted 'New-CaseManifest')
$mfDir = Join-Path $tmp 'mfcase'; New-Item -ItemType Directory -Path $mfDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $mfDir 'evidence.csv') -Value 'a,b' -Encoding UTF8
New-CaseManifest -ForDir $mfDir -HeaderLines @('Ophira v9.99 evidence manifest + chain of custody', 'CaseID: CASE-T4  Analyst: fixture')
$mf = @(Get-Content -LiteralPath (Join-Path $mfDir 'manifest.txt'))
$i3a = $mf -contains 'Ophira v9.99 evidence manifest + chain of custody'
$i3b = @($mf | Where-Object { $_ -like 'SCRIPT: Ophira v9.99*' }).Count -eq 1
$i3c = @($mf | Where-Object { $_ -match '^evidence\.csv\s+\d+\s+[0-9A-F]{64}$' }).Count -eq 1
Check "I3: shared helper writes header + SCRIPT line + per-file SHA256 table" ($i3a -and $i3b -and $i3c)
if (-not ($i3a -and $i3b -and $i3c)) { Write-Host "  [I3 debug] a=$i3a b=$i3b c=$i3c lines=$($mf.Count)"; $mf | ForEach-Object { Write-Host "    |$_" } }
Check "I3: manifest itself excluded from its own hash table" (@($mf | Where-Object { $_ -like '*manifest.txt*' }).Count -eq 0)
Check "I3: New-Package routes through the shared helper" ($src -match [regex]::Escape('New-CaseManifest -ForDir $CaseDir -HeaderLines $manifest'))
Check "I3: repack keeps endpoint header lines + adds ANALYST-PARSED + refreshes hashes before re-zip" (($src -match [regex]::Escape('ANALYST-PARSED: Ophira v$ScriptVersion re-processed this package')) -and ($src -match [regex]::Escape('New-CaseManifest -ForDir $caseDirP -HeaderLines $mfHdr')) -and ($src -match [regex]::Escape('$rpZipHash')))

# ---- M1 / M3 / M4 statics ----
Check "M1: no-noise caption uses the real shown count (hardcoded 150 gone)" (($src -match [regex]::Escape('"Newest $($tlShow.Count) of $($tlAll.Count) events, newest first:"')) -and ($src -notmatch 'Newest 150 of'))
Check "M3: run-keys label honest when truncating at 60" (($src -match [regex]::Escape('"showing first 60 of $($runKeys.Count) entries"')) -and ($src -notmatch [regex]::Escape('show $($runKeys.Count) entries</summary>')))
Check "M4: evidence-index supertimeline link uses the mapped csv path (case-root file link gone)" (($src -match [regex]::Escape('ConvertTo-CaseFileLink (Join-Path $CsvDir (Get-CaseCsvPath ''supertimeline''))')) -and ($src -cnotmatch [regex]::Escape("Join-Path `$caseRoot 'supertimeline.csv'")))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed (test_v280c)" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
