$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.77 - report truth + scanability:
#   T6: coverage honesty (banner shows weighted percent AND raw source fraction with missing
#       count; coverage table column 'Weight' -> 'Importance') + provenance line (Collected by
#       <case.json Tool> / Rendered by Ophira vN / Preset / Window, per-field fallback, empty
#       CaseID -> case folder name)
#   T7: verdict banner signals sorted (Weight desc, Count desc, Name asc; Noted stays last),
#       plain-language rank labels ([wN] chips -> near-certain/strong/corroborating/context),
#       hunt signal wording 'N rules / M findings', hunt evidence table LEADING-stamp
#       normalization (embedded/quoted dates stay verbatim)
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

foreach ($n in @('Import-CaseCsv', 'ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass', 'Get-TriageLeads', 'New-VtLink', 'Split-TagList', 'Get-TacticLabel', 'New-HtmlReport')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression $m.Value
}

$case = Join-Path $env:TEMP "ophira_v277_$stamp"
$csvDir = Join-Path $case 'csv'
New-Item -ItemType Directory -Path $csvDir, (Join-Path $case 'raw\evtx'), (Join-Path $case 'focus') -Force | Out-Null
$CaseDir = $case; $CsvDir = $csvDir; $RawDir = Join-Path $case 'raw'; $MemDir = Join-Path $case 'mem'
$Computer = 'V277HOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Get-LogRangeText { 'analysis window' }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
'{"Indicator":"x.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $case 'focus\focus_terms.json') -Encoding UTF8
foreach ($empty in @('flash_process_scored', 'flash_ioc_hits', 'yara_hits', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'entities_accounts', 'entities_remotes', 'entities_binaries', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'security_bruteforce_candidates', 'flash_public_connections', 'supertimeline', 'posture', 'credential_sweep', 'hunt_findings', 'process_chains', 'ioc_hits_amcache', 'ps_decoded_commands', 'session_activity', 'sysmon_process_access', 'sysmon_remote_thread', 'sysmon_pipes')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}
$mkV = {
    param($sigs, $cov = @(), $pct = 92, $collected = 24, $total = 29)
    [pscustomobject]@{
        Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = $pct; OwnerLine = 'fixture owner'
        Signals = $sigs; Caveats = @(); Coverage = $cov; CoveragePercentUnadjusted = $pct
        CoverageSourcesCollected = $collected; CoverageSourcesTotal = $total; Counts = $null; GeneratedUTC = 'x'
    }
}
$caseJson = Join-Path $case 'case.json'

# ============================================================================
# PART A - T6: provenance line + coverage honesty
# ============================================================================
# A1: full case.json (real-case shape: collector Tool differs from renderer version,
# empty CaseID, Preset + LogHours window) -> folder-name fallback for Case
'{"Tool":"Ophira v2.66","CaseID":"","Analyst":"","Computer":"WIN11","Preset":"Standard","AdminElevated":true,"LogHours":168,"LogStart":"","LogEnd":""}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$script:CurrentCaseID = ''
$script:Verdict = & $mkV @()
$null = New-HtmlReport
$htmlA1 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A1: Collected-by segment names the case.json collector tool" ($htmlA1.Contains('Collected by Ophira v2.66'))
Check "A1: Rendered-by segment names the renderer version" ($htmlA1.Contains('Rendered by Ophira v9.99'))
Check "A1: Preset segment from case.json" ($htmlA1.Contains('Preset Standard'))
Check "A1: Window segment from LogHours" ($htmlA1.Contains('Window last 168 h'))
Check "A1: elevation still reads case.json AdminElevated" ($htmlA1.Contains('Elevated: yes'))
Check "A1: empty CaseID falls back to the case FOLDER name (was 'unknown')" ($htmlA1 -match "Case: ophira_v277_$stamp &nbsp;\|&nbsp; Analyst: fixture")
Check "A1: no bare 'Case: unknown' left" (-not $htmlA1.Contains('Case: unknown'))

# A2: explicit LogStart/LogEnd window beats LogHours shape - TWO writer shapes:
# (a) space-separated string the PS 5.1 serializer does NOT coerce; (b) the REAL case.json
# writer shape (ISO round-trip with T+Z), which PS 5.1's ConvertFrom-Json coerces into a
# LOCAL-Kind DateTime - stringifying it rendered the box's locale dialect mislabeled UTC
'{"Tool":"Ophira v2.66","Preset":"Full","LogHours":0,"LogStart":"2026-09-01 08:00","LogEnd":"2026-09-24 08:00"}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$null = New-HtmlReport
$htmlA2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A2: explicit LogStart-LogEnd window renders in one segment (string shape)" ($htmlA2.Contains('Window 2026-09-01 08:00 - 2026-09-24 08:00 UTC'))
Check "A2: no hours-shape window when LogStart/LogEnd present" (-not $htmlA2.Contains('Window last'))
'{"Tool":"Ophira v2.66","Preset":"Full","LogHours":0,"LogStart":"2026-09-01T08:00:00.0000000Z","LogEnd":"2026-09-24T08:00:00.0000000Z"}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$null = New-HtmlReport
$htmlA2b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$provA2b = [regex]::Match($htmlA2b, "<div class='meta'>Host:.*?</div>").Value
Check "A2: ISO writer shape (coerced DateTime) renders the UTC stamp dialect" ($provA2b.Contains('Window 2026-09-01 08:00 - 2026-09-24 08:00 UTC'))
Check "A2: ISO shape never renders locale dialect (no AM/PM, no / date)" ((-not $provA2b.Contains('AM')) -and (-not $provA2b.Contains('PM')) -and (-not ($provA2b -match 'Window \d+/\d+/\d{4}')))

# A3: absent case.json (old cases) -> collector/preset/window segments omitted, renderer stays
Remove-Item -LiteralPath $caseJson -Force
$null = New-HtmlReport
$htmlA3 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$provA3 = [regex]::Match($htmlA3, "<div class='meta'>Host:.*?</div>").Value
Check "A3: no case.json -> no Collected-by segment" (-not $htmlA3.Contains('Collected by'))
Check "A3: no case.json -> no Preset/Window segments in the provenance line" ((-not $provA3.Contains('Preset ')) -and (-not $provA3.Contains('Window ')))
Check "A3: renderer version still shown" ($htmlA3.Contains('Rendered by Ophira v9.99'))
Check "A3: no case.json -> elevation stays tri-state 'unknown'" ($htmlA3.Contains('Elevated: unknown'))

# A4: minimal case.json (no provenance fields at all) -> same graceful omission
'{"Computer":"WIN11"}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$null = New-HtmlReport
$htmlA4 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$provA4 = [regex]::Match($htmlA4, "<div class='meta'>Host:.*?</div>").Value
Check "A4: minimal case.json -> no Collected-by/Preset/Window segments" ((-not $provA4.Contains('Collected by')) -and (-not $provA4.Contains('Preset ')) -and (-not $provA4.Contains('Window ')))

# A5: session CaseID wins over everything; case.json CaseID used when the session has none
$script:CurrentCaseID = 'CASE-277'
$null = New-HtmlReport
$htmlA5 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A5: session CaseID wins over the folder fallback" ($htmlA5.Contains('Case: CASE-277'))
$script:CurrentCaseID = ''
'{"CaseID":"FROM-JSON"}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$null = New-HtmlReport
$htmlA5b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A5: case.json CaseID used before the folder fallback" ($htmlA5b.Contains('Case: FROM-JSON'))
Remove-Item -LiteralPath $caseJson -Force

# A6: case.json Tool is untrusted input - goes through the section's escaping
'{"Tool":"Ophira v2.66<img src=x onerror=alert(1)>"}' | Set-Content -LiteralPath $caseJson -Encoding UTF8
$null = New-HtmlReport
$htmlA6 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A6: raw Tool payload absent from the report" (-not $htmlA6.Contains('<img src=x'))
Check "A6: Tool payload rendered escaped" ($htmlA6.Contains('Collected by Ophira v2.66&lt;img src=x onerror=alert(1)&gt;'))
Remove-Item -LiteralPath $caseJson -Force

# A7: coverage honesty - weighted percent AND raw source fraction with missing count.
# Fractional pct (the real verdict can carry one) pins the rider fix: banner TEXT and bar
# label read the SAME rounded integer - never '95.6% weighted' beside a bar labeled 96%.
$covFix = @(
    [pscustomobject]@{ Source = 'Volatile process inventory'; Collected = $true; Weight = 12 }
    [pscustomobject]@{ Source = 'RAM capture (bonus)'; Collected = $false; Weight = 3 }
)
$script:Verdict = & $mkV @() $covFix 95.6 24 29
$null = New-HtmlReport
$htmlA7 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "A7: banner shows weighted percent AND raw fraction with missing count (rounded)" ($htmlA7.Contains('Evidence coverage: 96% weighted (24/29 sources, 5 missing)'))
Check "A7: banner text and bar label agree on ONE rounded number (no 95.6)" ((-not $htmlA7.Contains('95.6%')) -and $htmlA7.Contains("<div class='conftext'>96% weighted (24/29 sources, 5 missing)"))
Check "A7: coverage table column renamed 'Importance'" ($htmlA7.Contains('<th>Evidence source</th><th>Collected</th><th>Importance</th></tr>'))
Check "A7: no 'Weight' column header left" (-not $htmlA7.Contains('<th>Weight</th>'))
Check "A7: coverage footer uses the honest both-numbers shape (same rounded number as the banner)" ($htmlA7.Contains('Coverage: 96% weighted (24/29 sources, 5 missing) - missing sources narrow what can be ruled out.'))
Check "A7: Importance cells still carry the weight integers" ($htmlA7.Contains('<td>Volatile process inventory</td><td><span class=' + "'cov-ok'" + '>yes</span></td><td>12</td>'))

# ============================================================================
# PART B - T7: signal order + rank labels + rules/findings wording + hunt stamps
# ============================================================================
# B1: sort order with tie-breaks (Weight desc, Count desc, Name asc) + labels + hunt wording
$script:Verdict = & $mkV @(
    [pscustomobject]@{ Signal = 'Sig-ZZ'; Weight = 2; Count = 1; Detail = '' }
    [pscustomobject]@{ Signal = 'Sig-AA'; Weight = 2; Count = 1; Detail = '' }
    [pscustomobject]@{ Signal = 'Hunt techniques (3 fired)'; Weight = 2; Count = 7; Detail = 'Renamed LOLBin x1; Downloaded then executed x2' }
    [pscustomobject]@{ Signal = 'Sig-Mid'; Weight = 2; Count = 7; Detail = '' }
    [pscustomobject]@{ Signal = 'Sig-Top'; Weight = 3; Count = 1; Detail = '' }
    [pscustomobject]@{ Signal = 'Sig-Low'; Weight = 1; Count = 9; Detail = '' }
)
$null = New-HtmlReport
$htmlB1 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$contribB1 = [regex]::Match($htmlB1, "(?s)<b>Contributing signals</b>(.*?)\r?\n</div>").Groups[1].Value
Check "B1: contributing slice extracted" ($contribB1.Contains('Sig-Top') -and $contribB1.Contains('Sig-Low'))
$iTop = $contribB1.IndexOf('Sig-Top'); $iHunt = $contribB1.IndexOf('Hunt techniques'); $iMid = $contribB1.IndexOf('Sig-Mid'); $iAA = $contribB1.IndexOf('Sig-AA'); $iZZ = $contribB1.IndexOf('Sig-ZZ'); $iLow = $contribB1.IndexOf('Sig-Low')
Check "B1: Weight desc (w3 first, w1 last)" (($iTop -ge 0) -and ($iTop -lt $iHunt) -and ($iZZ -lt $iLow))
Check "B1: Count desc tie-break (2x w2-count7 before 2x w2-count1)" (($iHunt -lt $iMid) -and ($iMid -lt $iAA))
Check "B1: Name asc tie-break (AA before ZZ at equal weight+count)" ($iAA -lt $iZZ)
Check "B1: rank labels replace the [wN] chips (strong/corroborating/context)" (($contribB1.Contains("<span class='high'>strong</span>")) -and ($contribB1.Contains("<span class='med'>corroborating</span>")) -and ($contribB1.Contains("<span class='info'>context</span>")))
Check "B1: no [wN] chips left anywhere in the banner" (-not $contribB1.Contains('[w'))
Check "B1: hunt signal wording reads 'N rules / M findings'" ($contribB1.Contains("Hunt techniques: 3 rules / 7 findings"))
Check "B1: no '(N fired) xM' shape left on the hunt row" ((-not $contribB1.Contains('Hunt techniques (3 fired)')) -and (-not $contribB1.Contains('fired) x')))
Check "B1: hunt signal still links to the hunt section + keeps its detail" (($contribB1.Contains("<a href='#hunt'")) -and ($contribB1.Contains('Renamed LOLBin x1; Downloaded then executed x2')))

# B2: near-certain label + w0 'Noted' group stays last
$script:Verdict = & $mkV @(
    [pscustomobject]@{ Signal = 'Sig-Storm'; Weight = 0; Count = 5; Detail = 'single-rule storm' }
    [pscustomobject]@{ Signal = 'Sig-Crit'; Weight = 4; Count = 1; Detail = 'live IOC' }
)
$null = New-HtmlReport
$htmlB2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$contribB2 = [regex]::Match($htmlB2, "(?s)<b>Contributing signals</b>(.*?)<b>Noted</b>").Groups[1].Value
$notedB2 = [regex]::Match($htmlB2, "(?s)<b>Noted</b>(.*?)\r?\n</div>").Groups[1].Value
Check "B2: w4 label reads 'near-certain'" ($contribB2.Contains("<span class='crit'>near-certain</span>"))
Check "B2: contributing list holds only the w4 row" ($contribB2.Contains('Sig-Crit') -and (-not $contribB2.Contains('Sig-Storm')))
Check "B2: w0 row under Noted keeps the 'noted' label" ($notedB2.Contains("<span class='info'>noted</span> Sig-Storm x5"))
Check "B2: Noted group renders after the contributing list" ($htmlB2.IndexOf('<b>Noted</b>') -gt $htmlB2.IndexOf('<b>Contributing signals</b>'))

# B3: hunt evidence table - LEADING-stamp normalization only (polarity: quoted/embedded
# command-line dates and unparseable leading text stay verbatim)
New-Csv (Join-Path $csvDir 'hunt_findings.csv') '"Found","Rule","Severity","Entity","Attck","Evidence"' @(
    '"2026-10-14 12:00:00","Proxy-execution LOLBin command line","high","C:\Windows\Temp\svc.exe","T1059.001","10/12/2026 7:43:01 AM: ""C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"" -nop -w hidden -enc AA"',
    '"2026-10-14 12:01:00","Discovery command storm","medium","dev","T1082","powershell -c ""backup ran 10/12/2026 7:43:01 AM ok"""',
    '"2026-10-14 12:02:00","Timestamp anomaly","low","C:\x\odd.exe","T1070","99/99/2026 9:99:99 AM: unparseable leading text"'
)
$script:Verdict = & $mkV @()
$null = New-HtmlReport
$htmlB3 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "B3: leading locale stamp normalized to the Ophira dialect" ($htmlB3.Contains('2026-10-12 07:43: &quot;C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe&quot;'))
Check "B3: quoted command line INSIDE the cell keeps its verbatim shape after the stamp" ($htmlB3.Contains('-nop -w hidden -enc AA</td>'))
Check "B3: polarity - date-like token inside a quoted command line NOT rewritten" ($htmlB3.Contains('backup ran 10/12/2026 7:43:01 AM ok'))
Check "B3: unparseable leading stamp text stays verbatim" ($htmlB3.Contains('99/99/2026 9:99:99 AM: unparseable leading text'))
Check "B3: no leading locale stamp left on any hunt evidence cell" (-not $htmlB3.Contains('7:43:01 AM: "'))
Check "B3: hunt table heading/counters untouched (v2.76 tiers intact)" ($htmlB3.Contains('<h2>Hunt technique findings - 1 high / 1 medium / 1 informational</h2>'))

Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
