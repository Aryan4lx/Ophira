# test_v270.ps1 - hunt signal honesty: "Hunt techniques (N fired)" name + deduped per-rule detail
# (Release 1 task 1 of the report-accuracy plan: the old 20-technique laundry-list name and the
# repeating raw-rule detail are replaced by distinct-rule counts, count desc then name, capped
# at 3 with '+N more'. Weight 2 and the total-events Count contract are pinned unchanged.)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

foreach ($n in 'Get-CompromiseVerdict', 'Get-LvlRank') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$tmp = Join-Path $env:TEMP ("ophira_v270_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $tmp 'raw\evtx') -Force | Out-Null
$RawDir = Join-Path $tmp 'raw'
$MemDir = Join-Path $tmp 'mem'
$CaseDir = $tmp
$global:LogHours = 168
$script:EndpointAdmin = $true

function Import-CaseCsv([string]$name) { if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function Test-CaseCsv([string]$n) { return ($script:presentCsvs -contains $n) }
function Save-Rows { param([string]$Name, $Rows) }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Test-IsAdmin { return $false }

$script:presentCsvs = @()
$script:fixtureRows = @{}

# rows use the real hunt_findings shape (module 8.10: Found,Rule,Severity,Entity,Attck,Evidence)
function Hf([string]$rule, [string]$evidence) {
    [pscustomobject]@{ Found = '2026-10-14 12:00:00'; Rule = $rule; Severity = 'high'; Entity = 'HOST'; Attck = 'T0000'; Evidence = $evidence }
}

# ---- 1-4: two distinct rules, one firing twice ----
$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf 'Downloaded then executed' 'ev1')
        (Hf 'Downloaded then executed' 'ev2')
        (Hf 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'ev3')
    )
}
$v = Get-CompromiseVerdict
$hunt = @($v.Signals | Where-Object { $_.Signal -like 'Hunt technique*' })
Check "two distinct rules (one twice) -> signal named 'Hunt techniques (2 fired)'" ($hunt.Count -eq 1 -and $hunt[0].Signal -eq 'Hunt techniques (2 fired)')
Check "detail: duplicated rule as x2, single rule as x1" ("$($hunt[0].Detail)" -match 'Downloaded then executed x2' -and "$($hunt[0].Detail)" -match 'Renamed LOLBin at rest \(Sysmon identity mismatch\) x1')
Check "detail: no un-deduped repeated rule name" (@([regex]::Matches("$($hunt[0].Detail)", 'Downloaded then executed')).Count -eq 1)
Check "weight still 2, Count still total events (3)" ($hunt[0].Weight -eq 2 -and $hunt[0].Count -eq 3)
Check "detail orders by count desc (x2 entry first)" ("$($hunt[0].Detail)" -like 'Downloaded then executed x2*')

# ---- 5: five distinct rules -> cap at 3 entries + '+N more', count desc then name tie-break ----
$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf 'DCSync' 'e1')
        (Hf 'DCSync' 'e2')
        (Hf 'DCSync' 'e3')
        (Hf 'LSASS access' 'e4')
        (Hf 'LSASS access' 'e5')
        (Hf 'Admin-share staging' 'e6')
        (Hf 'Admin-share staging' 'e7')
        (Hf 'Password spray' 'e8')
        (Hf 'Direct volume access' 'e9')
    )
}
$v5 = Get-CompromiseVerdict
$h5 = @($v5.Signals | Where-Object { $_.Signal -like 'Hunt technique*' })
Check "five distinct rules -> 'Hunt techniques (5 fired)'" ($h5[0].Signal -eq 'Hunt techniques (5 fired)')
Check "detail capped at 3 entries + '+2 more' (true remaining count)" ("$($h5[0].Detail)" -match '; \+2 more$')
Check "cap keeps the count-desc, name-asc head (DCSync x3; Admin-share staging x2; LSASS access x2)" ("$($h5[0].Detail)" -eq 'DCSync x3; Admin-share staging x2; LSASS access x2; +2 more')
Check "Count still total events (9), weight still 2" ($h5[0].Count -eq 9 -and $h5[0].Weight -eq 2)

# ---- 6: zero hunt findings -> signal absent (Add-Signal zero-count guard intact) ----
$script:fixtureRows = @{}
$v0 = Get-CompromiseVerdict
Check "zero hunt findings -> no hunt signal rendered" (@($v0.Signals | Where-Object { $_.Signal -like 'Hunt technique*' }).Count -eq 0)

# ---- statics: laundry-list name gone, $huntHi input filter untouched ----
Check "static: old laundry-list signal name removed" ($src -notmatch 'Hunt technique - renamed binary')
Check "static: huntHi input filter unchanged (high severity + rule regex)" ($src -match '-match ''Renamed LOLBin\|side-load\|Downloaded then executed\|LSASS access')
Check "static: distinct-rule grouping present" ($src -match [regex]::Escape('$huntHiRules = @($huntHi | Group-Object Rule'))

# ---- v2.70 task 4: draft BEST LEADS entity dedupe + generated-stamp dialect ----
# Real WIN11 case shape: the SAME file flagged by TWO hunt rules rendered as two draft leads and
# two cards. The draft builder now dedupes hunt findings by Entity (case-insensitive), joins rules
# with ' + ' / ATT&CK tags with '/', keeps the first row's evidence, and rewrites embedded locale
# stamps (10/12/2026 7:43:01 AM) to the generated dialect yyyy-MM-dd HH:mm (unparseable untouched).
$mNar = [regex]::Match($src, "(?s)function Get-CaseNarrative \{.*?\r?\n\}")
if (-not $mNar.Success) { throw 'extract failed: Get-CaseNarrative' }
Invoke-Expression $mNar.Value
$Computer = 'V270HOST'; $script:HostRole = 'workstation'; $StartTime = Get-Date; $ScriptVersion = '9.99'
$CsvDir = Join-Path $tmp 'csv'
$mkVd = {
    param($sigs)
    [pscustomobject]@{ Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 60; OwnerLine = 'fixture owner'
        Signals = $sigs; Caveats = @(); Coverage = @(); CoverageSourcesCollected = 3; CoverageSourcesTotal = 4 }
}
function Hf2([string]$rule, [string]$entity, [string]$attck, [string]$evidence) {
    [pscustomobject]@{ Found = '2026-10-14 12:00:00'; Rule = $rule; Severity = 'high'; Entity = $entity; Attck = $attck; Evidence = $evidence }
}

# task4-1: same entity (row 2 differs in case only), two rules -> ONE lead naming both rules
$script:Verdict = & $mkVd @()
$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf2 'Downloaded then executed' 'C:\Users\Ary\Downloads\7z2603-x64.exe' 'T1650' 'downloaded 10/12/2026 7:43:01 AM then executed')
        (Hf2 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'c:\users\ary\downloads\7z2603-x64.exe' 'T1036.003' 'second-rule evidence')
    )
}
$draftT4 = @(Get-CaseNarrative)
$leadT4 = @($draftT4 | Where-Object { $_ -match '^ - \[' })
Check "task4 draft: same entity two rules -> ONE lead" ($leadT4.Count -eq 1)
Check "task4 draft: lead joins both rules with +" ("$($leadT4[0])" -match 'Downloaded then executed \+ Renamed LOLBin at rest \(Sysmon identity mismatch\)')
Check "task4 draft: ATT&CK tags deduped + joined with /" ("$($leadT4[0])" -match '^ - \[T1650/T1036\.003\]')
Check "task4 draft: entity keeps the first row's casing" ("$($leadT4[0])" -match 'on C:\\Users\\Ary\\Downloads\\7z2603-x64\.exe:')
Check "task4 draft: evidence from the first row, locale stamp normalized" ("$($leadT4[0])" -match ': downloaded 2026-10-12 07:43 then executed')
Check "task4 draft: second row's evidence not duplicated" ("$($leadT4[0])" -notmatch 'second-rule evidence')

# task4-2: two different entities -> two leads (dedupe not over-eager)
$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf2 'RuleAlpha' 'C:\a\one.exe' 'T1000' 'ev a')
        (Hf2 'RuleBeta' 'C:\b\two.exe' 'T1001' 'ev b')
    )
}
$draftT4b = @(Get-CaseNarrative)
$leadT4b = @($draftT4b | Where-Object { $_ -match '^ - \[' })
Check "task4 draft: two different entities -> two leads" ($leadT4b.Count -eq 2)

# task4-3: locale stamp inside a signal detail normalizes to yyyy-MM-dd HH:mm
$script:Verdict = & $mkVd @([pscustomobject]@{ Signal = 'Hunt techniques (1 fired)'; Weight = 3; Count = 1; Detail = 'first seen 10/12/2026 7:43:01 AM on HOST' })
$draftT4c = @(Get-CaseNarrative)
Check "task4 draft: signal detail locale stamp normalizes" (@($draftT4c | Where-Object { $_ -match 'first seen 2026-10-12 07:43 on HOST' }).Count -eq 1)

# task4-4: text the regex matches but DateTime cannot parse stays verbatim (no mangle)
$script:Verdict = & $mkVd @()
$script:fixtureRows = @{
    'hunt_findings' = @((Hf2 'RuleOdd' 'C:\x\odd.exe' 'T9' 'seen 99/99/2026 9:99:99 AM and not-a-date'))
}
$draftT4d = @(Get-CaseNarrative)
$leadT4d = @($draftT4d | Where-Object { $_ -match '^ - \[' })
Check "task4 draft: unparseable timestamp text stays verbatim" ($leadT4d.Count -eq 1 -and "$($leadT4d[0])" -match 'seen 99/99/2026 9:99:99 AM and not-a-date')

# ---- render: weight-0 signals leave the contributing list (Release 1 task 2) ----
# Full-report harness (test_v266/test_v268 pattern): the real New-HtmlReport renders a
# hand-built fixture verdict in a temp case dir; assertions run on the banner HTML.
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
foreach ($n2 in @('Import-CaseCsv', 'New-VtLink', 'Split-TagList', 'Get-TacticLabel', 'New-HtmlReport')) {
    $m2 = [regex]::Match($src, "(?s)function $n2 \{.*?\r?\n\}")
    if (-not $m2.Success) { throw "render extract failed: $n2" }
    Invoke-Expression $m2.Value
}

$rcase = Join-Path $env:TEMP ("ophira_v270r_" + (Get-Date -Format 'HHmmss'))
$rcsv = Join-Path $rcase 'csv'
New-Item -ItemType Directory -Path $rcsv, (Join-Path $rcase 'raw\evtx'), (Join-Path $rcase 'focus') -Force | Out-Null
$CaseDir = $rcase; $CsvDir = $rcsv; $RawDir = Join-Path $rcase 'raw'; $MemDir = Join-Path $rcase 'mem'
$Computer = 'V270HOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-270'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Get-LogRangeText { 'analysis window' }
'{"Indicator":"x.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $rcase 'focus\focus_terms.json') -Encoding UTF8
foreach ($empty in @('flash_process_scored', 'flash_ioc_hits', 'yara_hits', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'entities_accounts', 'entities_remotes', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'security_bruteforce_candidates', 'flash_public_connections', 'supertimeline', 'posture', 'credential_sweep', 'hunt_findings', 'process_chains', 'ioc_hits_amcache')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $rcsv "$empty.csv") -Encoding UTF8
}

# one w2 (drivers anchor) + one w0 (sigma anchor, real storm-gated wording)
$mkV = {
    param($sigs)
    [pscustomobject]@{
        Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 60; OwnerLine = 'fixture owner'
        Signals = $sigs; Caveats = @(); Coverage = @(); CoveragePercentUnadjusted = 60
        CoverageSourcesCollected = 3; CoverageSourcesTotal = 4; Counts = $null; GeneratedUTC = 'x'
    }
}
$script:Verdict = & $mkV @(
    [pscustomobject]@{ Signal = 'Known-malicious driver on disk (LOLDrivers)'; Weight = 2; Count = 1; Detail = 'bad.sys: C:\Windows\System32\drivers\bad.sys' }
    [pscustomobject]@{ Signal = 'Sigma detection - high'; Weight = 0; Count = 5; Detail = '5 events from 1 distinct rules - single-rule storm carries no verdict weight (see -Mode Tune)' }
)
$null = New-HtmlReport
$htmlV270 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

$contribV270 = [regex]::Match($htmlV270, "(?s)<b>Contributing signals</b>(.*?)<b>Noted</b>").Groups[1].Value
$notedIdx = $htmlV270.IndexOf("<b>Noted</b>")
$rowStart = $htmlV270.IndexOf("<div class='sig'>", [Math]::Max($notedIdx, 0))
$rowEnd = $htmlV270.IndexOf('</div>', $rowStart) + 6
$notedRow = if ($rowStart -ge 0 -and $rowEnd -gt $rowStart) { $htmlV270.Substring($rowStart, $rowEnd - $rowStart) } else { '' }
Check "render: Noted group renders after the contributing list" (($contribV270 -ne '') -and ($notedIdx -gt $htmlV270.IndexOf('<b>Contributing signals</b>')))
Check "render: Noted label wording matches the banner label pattern" ($htmlV270.Contains("<b>Noted</b> (no verdict weight - context, not evidence of compromise)"))
Check "render: w0 storm signal leaves the contributing list" (-not $contribV270.Contains('Sigma detection - high'))
Check "render: contributing list keeps the w2 row unchanged" ($contribV270.Contains("<span class='med'>[w2]</span> <a href='#drivers' style='color:inherit'>Known-malicious driver on disk (LOLDrivers) x1"))
Check "render: w0 row under Noted keeps info badge + evidence link intact" ($notedRow.Contains("<span class='info'>[w0]</span> <a href='#sigma' style='color:inherit'>Sigma detection - high x5"))

# zero w0 signals -> the whole Noted group stays off; contributing list still renders w3 + w1
$script:Verdict = & $mkV @(
    [pscustomobject]@{ Signal = 'IOC hit - live system'; Weight = 3; Count = 2; Detail = '1.2.3.4' }
    [pscustomobject]@{ Signal = 'Process anomaly verdict MEDIUM'; Weight = 1; Count = 1; Detail = 'worth review' }
)
$null = New-HtmlReport
$htmlV270b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "render: zero w0 signals -> no Noted group at all" (-not $htmlV270b.Contains('<b>Noted</b>'))
Check "render: zero w0 -> contributing list still renders its w3 + w1 rows" (($htmlV270b.Contains("<span class='high'>[w3]</span>")) -and ($htmlV270b.Contains("<span class='info'>[w1]</span>")))

# ---- task4 render: hunt lead cards collapse per ENTITY (same grouping as the draft) ----
# same entity via two rules -> ONE card with rules joined; report evidence stays verbatim
# (the raw-evidence rule is untouched - only the DRAFT normalizes its embedded stamps)
@"
"Found","Rule","Severity","Entity","Attck","Evidence"
"2026-10-14 12:00:00","Downloaded then executed","high","C:\Users\Ary\Downloads\7z2603-x64.exe","T1650","downloaded 10/12/2026 7:43:01 AM then executed"
"2026-10-14 12:05:00","Renamed LOLBin at rest (Sysmon identity mismatch)","high","c:\users\ary\downloads\7z2603-x64.exe","T1036.003","second-rule evidence"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlT4 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task4 render: same entity two rules -> ONE hunt lead card" (@([regex]::Matches($htmlT4, [regex]::Escape("hunt rule: Downloaded then executed + Renamed LOLBin at rest (Sysmon identity mismatch)"))).Count -eq 1)
Check "task4 render: card ATT&CK tags joined with /" ($htmlT4.Contains('ATT&amp;CK T1650/T1036.003'))
Check "task4 render: card evidence verbatim (report does not rewrite stamps)" ($htmlT4.Contains('10/12/2026 7:43:01 AM'))
Check "task4 render: no second card for the case-variant entity path" (@([regex]::Matches($htmlT4, "leadtitle'>\d+\. C:\\Users\\Ary\\Downloads\\7z2603-x64\.exe <span")).Count -eq 1)

# two different entities -> two cards (dedupe not over-eager)
@"
"Found","Rule","Severity","Entity","Attck","Evidence"
"2026-10-14 12:00:00","RuleAlpha","high","C:\a\one.exe","T1000","ev a"
"2026-10-14 12:05:00","RuleBeta","high","C:\b\two.exe","T1001","ev b"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlT4b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task4 render: two different entities -> two hunt lead cards" ((@([regex]::Matches($htmlT4b, [regex]::Escape('hunt rule: RuleAlpha'))).Count -eq 1) -and (@([regex]::Matches($htmlT4b, [regex]::Escape('hunt rule: RuleBeta'))).Count -eq 1))

# restore the empty fixture so the file's remaining scenarios see the original shape
"# no entries" | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8

Remove-Item -LiteralPath $rcase -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.70 rider (Release 1 task 3): Defender stale-history detail honesty ----
# Real WIN11 1116 dialect (OPHIRA_WIN11_20261016_153713 csv\defender\defender_events.csv, verbatim):
#   '...&name=VirTool:Win32/DefenderTamperingRestore&threatid=2147741622&enterprise=0 Name:
#   VirTool:Win32/DefenderTamperingRestore ID: 2147741622 Severity: Severe Category: Tool Path: ...'
# The old parse knew only 'Threat Name:' -> empty ThreatName rows, and the verdict then rendered
# bare ' @ 10/11/2026 5:45:17 PM' fragments. Root cause fixed in module 6.1's 1116 parse; render
# side: nameless rows contribute NOTHING, stamps normalize to yyyy-MM-dd HH:mm (raw on parse fail).
$realMsg1116 = 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software. For more information please see the following: https://go.microsoft.com/fwlink/?linkid=37020&name=VirTool:Win32/DefenderTamperingRestore&threatid=2147741622&enterprise=0 Name: VirTool:Win32/DefenderTamperingRestore ID: 2147741622 Severity: Severe Category: Tool Path: regkeyvalue:_hklm\software\policies\microsoft\windows defender\\DisableAntiSpyware Detection Origin: Unknown Detection Type: Concrete Detectio...'
$noNameMsg1116 = 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software. For more information please see the following: https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Unnamed&threatid=9999&enterprise=0 Severity: Moderate Category: Trojan'

# (a) root cause: module 6.1 EID-1116 parse captures the real 'Name: <value> ID: <n>' dialect
function Get-MpComputerStatus { throw 'stub: not under test' }
function Get-MpThreat { throw 'stub: not under test' }
function Get-MpPreference { throw 'stub: not under test' }
function Get-LogStart { return $null }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg) return $script:v270Events }
function Export-Evtx { param($LogName, $FileName) }
function Save-Rows { param([string]$Name, $Rows) $script:v270Saved[$Name] = $Rows }
$m61 = [regex]::Match($src, "(?s)Id = '6\.1';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '7\.1'")
if (-not $m61.Success) { throw 'module 6.1 extract failed' }
$d61 = Join-Path $env:TEMP ("ophira_v270d61_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $d61 -Force | Out-Null
$CaseDir = $d61; $CsvDir = $d61; $RawDir = $d61; $MemDir = $d61
$script:v270Saved = @{}
$script:v270Events = @(
    [pscustomobject]@{ TimeCreated = '10/11/2026 5:45:17 PM'; Id = 1116; Provider = 'Microsoft-Windows-Windows Defender'; Level = 'Warning'; Message = $realMsg1116 }
    [pscustomobject]@{ TimeCreated = '10/11/2026 5:44:48 PM'; Id = 1116; Provider = 'Microsoft-Windows-Windows Defender'; Level = 'Warning'; Message = $noNameMsg1116 }
)
& ([scriptblock]::Create($m61.Groups[1].Value))
$savedT = @($script:v270Saved['defender_threats'])
Check "1116 parse: real WIN11 'Name: <v> ID: <n>' dialect -> non-empty ThreatName" ($savedT.Count -eq 2 -and "$($savedT[0].ThreatName)" -eq 'VirTool:Win32/DefenderTamperingRestore')
Check "1116 parse: Severity + evtx-history source still captured from the real dialect" ("$($savedT[0].Severity)" -eq 'Severe' -and "$($savedT[0].Source)" -eq 'evtx-history')
Check "1116 parse: message without the name dialect -> graceful empty ThreatName (URL name= never leaks)" ($savedT.Count -eq 2 -and "$($savedT[1].ThreatName)" -eq '')

# (b) render: real Import-CaseCsv reads a fresh temp case; write defender_threats.csv per scenario
$t3 = Join-Path $env:TEMP ("ophira_v270d_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $t3 'raw\evtx'), (Join-Path $t3 'csv') -Force | Out-Null
$CaseDir = $t3; $CsvDir = Join-Path $t3 'csv'; $RawDir = Join-Path $t3 'raw'; $MemDir = Join-Path $t3 'mem'

# broken pre-v2.70 case shape: empty ThreatName + dated evtx-history (real WIN11 case data)
@([pscustomobject]@{ ThreatName = ''; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = '10/11/2026 5:45:17 PM' }) |
    Export-Csv -LiteralPath (Join-Path $CsvDir 'defender_threats.csv') -NoTypeInformation -Encoding UTF8
$vBroken = Get-CompromiseVerdict
$staleBroken = @($vBroken.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
Check "render: empty-ThreatName dated evtx rows -> stale signal weight 1, EMPTY detail (no ' @ date' fragment)" ($staleBroken.Count -eq 1 -and $staleBroken[0].Weight -eq 1 -and "$($staleBroken[0].Detail)" -eq '')

# named rows: locale stamp normalizes; sev row keeps the 'Name (sev N) @ stamp' shape
@(
    [pscustomobject]@{ ThreatName = 'Trojan:Win32/Malgent'; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = '10/11/2026 5:45:17 PM' }
    [pscustomobject]@{ ThreatName = 'Trojan:Win32/Fresh'; SeverityID = '4'; Source = 'live-catalog'; DetectedUTC = '2026-10-11 17:45:17' }
) | Export-Csv -LiteralPath (Join-Path $CsvDir 'defender_threats.csv') -NoTypeInformation -Encoding UTF8
$vNamed = Get-CompromiseVerdict
$staleNamed = @($vNamed.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
$freshNamed = @($vNamed.Signals | Where-Object { $_.Signal -eq 'Defender detection - active or in log window' })
Check "render: named row stamp normalizes to '2026-10-11 17:45' style (not '10/11/2026 5:45:17 PM')" ("$($staleNamed[0].Detail)" -eq 'Trojan:Win32/Malgent @ 2026-10-11 17:45')
Check "render: named + sev row renders 'Name (sev N) @ yyyy-MM-dd HH:mm'" ("$($freshNamed[0].Detail)" -eq 'Trojan:Win32/Fresh (sev 4) @ 2026-10-11 17:45')

# unparseable stamp keeps the raw string (documented fallback, never dropped silently)
@([pscustomobject]@{ ThreatName = 'Trojan:Win32/OddStamp'; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = 'not-a-date' }) |
    Export-Csv -LiteralPath (Join-Path $CsvDir 'defender_threats.csv') -NoTypeInformation -Encoding UTF8
$vRaw = Get-CompromiseVerdict
$staleRaw = @($vRaw.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
Check "render: unparseable stamp keeps the raw string as fallback" ("$($staleRaw[0].Detail)" -eq 'Trojan:Win32/OddStamp @ not-a-date')

# (c) task4 rider: an ALL-nameless stale list renders an EMPTY detail - never a bare '; +N more'
# headless tail (nameless rows filtered BEFORE the 3-entry window, suffix counts NAMED rows only)
$nless = New-Object System.Collections.Generic.List[object]
1..5 | ForEach-Object { $null = $nless.Add([pscustomobject]@{ ThreatName = ''; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = "9/1$_/2026 5:45:17 PM" }) }
$nless.ToArray() | Export-Csv -LiteralPath (Join-Path $CsvDir 'defender_threats.csv') -NoTypeInformation -Encoding UTF8
$vNless = Get-CompromiseVerdict
$staleNless = @($vNless.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
Check "rider: 5 nameless stale rows -> weight 1, EMPTY detail (no bare '; +N more')" ($staleNless.Count -eq 1 -and $staleNless[0].Weight -eq 1 -and "$($staleNless[0].Detail)" -eq '')

# rider: the '+N more' suffix counts NAMED rows only (4 named + 2 nameless -> 3 entries + '+1 more')
$mixed = New-Object System.Collections.Generic.List[object]
1..4 | ForEach-Object { $null = $mixed.Add([pscustomobject]@{ ThreatName = "Trojan:Win32/M$_"; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = "9/1$_/2026 5:45:17 PM" }) }
1..2 | ForEach-Object { $null = $mixed.Add([pscustomobject]@{ ThreatName = ''; SeverityID = ''; Source = 'evtx-history'; DetectedUTC = '9/20/2026 5:45:17 PM' }) }
$mixed.ToArray() | Export-Csv -LiteralPath (Join-Path $CsvDir 'defender_threats.csv') -NoTypeInformation -Encoding UTF8
$vMixed = Get-CompromiseVerdict
$staleMixed = @($vMixed.Signals | Where-Object { $_.Signal -like 'Defender detection - stale history*' })
Check "rider: 4 named + 2 nameless -> 3 named entries + '; +1 more', no nameless leak" ("$($staleMixed[0].Detail)" -eq 'Trojan:Win32/M1 @ 2026-09-11 17:45; Trojan:Win32/M2 @ 2026-09-12 17:45; Trojan:Win32/M3 @ 2026-09-13 17:45; +1 more')

Remove-Item -LiteralPath $t3 -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $d61 -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { Write-Host "`ntest_v270: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v270: $pass passed, 0 failed" -ForegroundColor Green
exit 0
