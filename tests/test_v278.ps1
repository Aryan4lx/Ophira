$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.78 - navigation polish:
#   T9: the embedded case draft collapses into a <details> block (verbatim summary text,
#       case_draft.txt keeps shipping), and the Do-now block links the Recommendations section
#   T10: jump-nav items carry row counts ((none) when the section renders zero rows), and the
#       Processes heading states its top-30 cap when truncation happened
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART A - static source pins
# ============================================================================
Check "T9: draft renders inside a details/summary wrapper (verbatim summary text)" ($src.Contains('<a name=''draft''></a><details><summary>Case draft (auto-written - paste into your report)</summary><div class=''draft''>'))
Check "T9: the old always-open draft heading is gone" (-not ($src.Contains('<h2>Case draft')))
Check "T9: the draft block closes its details after the plain-text pointer" ($src.Contains('not a conclusion.</div></details>'))
Check "T9: case_draft.txt still written by the shared output regeneration" ($src.Contains("Get-CaseNarrative | Set-Content -LiteralPath (Join-Path `$CaseDir 'case_draft.txt')"))
Check "T9: donow block carries the Recommendations jump link" ($src -match "class='donow'><b>Do now:</b>.*<a href='#recommendations'>-&gt; full Recommendations</a>")
Check "T10: Processes heading interpolates the computed cap label" (($src.Contains('$procCap = if ($scored.Count -gt $procTop.Count)')) -and ($src.Contains('<h2>Process verdicts (correlation scored)$(ConvertTo-HtmlEsc $procCap)</h2>')))
Check "T10: nav items fall back to the (none) marker when the count is zero" ($src.Contains('else { ''(none)'' }'))
$navLoopSeg = [regex]::Match($src, '(?s)\$navParts = New-Object.*?class=''nav''').Value
Check "T10: nav counts come from one precomputed table (no reads inside the nav loop)" (($src.Contains('$nCount = @{')) -and ($navLoopSeg.Length -gt 0) -and (-not $navLoopSeg.Contains('Import-CaseCsv')))

# ============================================================================
# PART B - behavioral render (extract-and-stub harness)
# ============================================================================
foreach ($n in @('Import-CaseCsv', 'ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass', 'New-VtLink', 'Split-TagList', 'Get-TacticLabel', 'Get-LvlRank', 'New-HtmlReport')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression $m.Value
}
# deterministic stubs: the leads builder and the narrative writer
function Get-TriageLeads {
    return @(
        [pscustomobject]@{ Rank = 'crit'; Title = 'lead one'; Class = 'hunt rule: Renamed LOLBin'; Why = 'why one'; Ident = 'C:\mal\one.exe'; Extra = 'T1059'; Anchor = 'hunt'; Rule = '' },
        [pscustomobject]@{ Rank = 'med'; Title = 'lead two'; Class = 'hunt rule: x'; Why = 'why two'; Ident = 'C:\mal\two.exe'; Extra = ''; Anchor = 'sigma'; Rule = '' }
    )
}
function Get-CaseNarrative { return @('ASSESSMENT', 'body line of the draft', ' - sub line') }

$case = Join-Path $env:TEMP "ophira_v278_$stamp"
$csvDir = Join-Path $case 'csv'
New-Item -ItemType Directory -Path $csvDir, (Join-Path $case 'raw\evtx'), (Join-Path $case 'focus') -Force | Out-Null
$CaseDir = $case; $CsvDir = $csvDir; $RawDir = Join-Path $case 'raw'; $MemDir = Join-Path $case 'mem'
$Computer = 'V278HOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-278'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Get-LogRangeText { 'analysis window' }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }

# focus dossier with 7 evidence rows -> nav Focus (7)
'{"Indicator":"one.exe","Rounds":1,"HitCount":7,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $case 'focus\focus_terms.json') -Encoding UTF8

foreach ($empty in @('flash_ioc_hits', 'yara_hits', 'ioc_hits_amcache', 'yara_scanned', 'ioc_hits_dns', 'ioc_hits_network', 'ioc_hits_hash', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'ps_decoded_commands', 'entities_accounts', 'entities_remotes', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'execution_timeline', 'security_bruteforce_candidates', 'flash_public_connections', 'posture', 'session_activity', 'sysmon_process_access', 'sysmon_remote_thread', 'sysmon_pipes')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

# credential sweep: 1 populated row (same Item/Detail/Risk shape the module writes) ->
# the snapshot sweep table renders + nav Snapshot (1)
@'
"Item","Detail","Risk"
"WLAN key (NETGEAR-GUEST)","profile 'NETWEAR-GUEST', key PSK: PRESENT (raw\wifi)","HIGH"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'credential_sweep.csv') -Encoding UTF8

# sigma: 3 rows (2 high T1059.001, 1 low T1547.001) -> Sigma (3), tactics (2), ATT&CK (2 distinct)
@'
"Timestamp","Computer","EventID","Level","RuleTitle","Details","MitreTactics","MitreTags"
"2026-09-24 10:00:00.000 +00:00","V278HOST","1","high","Suspicious PowerShell","-enc cmd","Exec","T1059.001"
"2026-09-24 10:05:00.000 +00:00","V278HOST","1","high","Suspicious PowerShell","encoded","Exec","T1059.001"
"2026-09-24 10:06:00.000 +00:00","V278HOST","7045","low","Run key persistence","reg add","Persis","T1547.001"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'hayabusa_timeline.csv') -Encoding UTF8

# hunt: 2 findings -> Hunt (2)
@'
"Rule","Severity","Entity","ATT&CK","Evidence"
"R8 User-path LOLBin","high","C:\mal\one.exe","T1059","binary ran from user path"
"R9 Storm","medium","C:\mal\two.exe","T1082","storm detail"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'hunt_findings.csv') -Encoding UTF8

# 32 scored processes -> Processes (32) + heading cap 'showing 30 of 32'
$procLines = New-Object System.Collections.Generic.List[string]
$null = $procLines.Add('"Name","Path","PID","Verdict","Score","Evidence","Signer"')
1..32 | ForEach-Object { $null = $procLines.Add(('"proc{0}.exe","C:\Windows\System32\p{0}.exe","{0}","MEDIUM","3","score: review items",""' -f $_)) }
$procLines | Set-Content -LiteralPath (Join-Path $csvDir 'flash_process_scored.csv') -Encoding UTF8

# timeline: 4 rows -> Timeline (4)
@'
"Timestamp","Source","Type","Actor","Entity","Detail"
"2026-09-24 09:00:00","Security","logon","V278HOST\user1","user1","4624 interactive logon"
"2026-09-24 10:00:30","Sysmon","process","V278HOST\user1","C:\mal\one.exe","process create"
"2026-09-24 10:05:00","Security","logon","V278HOST\user1","user1","4624 logon type 10"
"2026-09-25 08:30:00","Prefetch","exec","V278HOST\user1","CMD.EXE","prefetch touched"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'supertimeline.csv') -Encoding UTF8

# entities: 1 multi-source binary -> Connections (1)
@'
"Path","Name","CatCount","Categories","Verdict","Signer","FirstSeen","LastSeen","Hashes","Bytes","Evidence"
"C:\mal\one.exe","one.exe","3","sigma;hunt;prefetch","HIGH","","2026-09-24 10:00:00","2026-09-24 11:00:00","","","sigma: [high] Suspicious PowerShell: encoded | hunt: [high] R8 User-path LOLBin: binary ran from user path | prefetch: run count 3"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'entities_binaries.csv') -Encoding UTF8

# logons: 2 explicit-credential events -> Logons (2)
@'
"Id","EventId","TargetDomainName","TargetServerName","TargetUserName","ProcessName"
"4648","4648","CORP","srv1","adminA","taskhost.exe"
"4648","4648","CORP","srv2","adminB","cmd.exe"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'security_events.csv') -Encoding UTF8

# 1 live IOC hit -> IOCs (1)
@'
"Type","Indicator","Where","Context"
"domain","evil.example.com","dns cache","fixture hit"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'flash_ioc_hits.csv') -Encoding UTF8

# verdict stub: 3 coverage rows -> Coverage (3); LevelRank 2 renders the Do-now block
$script:Verdict = [pscustomobject]@{
    Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 92; OwnerLine = 'fixture owner'
    Signals = @(); Caveats = @()
    Coverage = @(
        [pscustomobject]@{ Source = 'prefetch'; Collected = $true; Weight = 2 },
        [pscustomobject]@{ Source = 'amcache'; Collected = $true; Weight = 2 },
        [pscustomobject]@{ Source = 'memory'; Collected = $false; Weight = 1 }
    )
    CoveragePercentUnadjusted = 92; CoverageSourcesCollected = 24; CoverageSourcesTotal = 29
    Counts = $null; GeneratedUTC = 'x'
}

$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

# ---- T10: nav counts (populated + empty sections) ----
Check "T10: populated section shows its count - Processes (32)" ($html.Contains("<a href='#processes'>Processes (32)</a>"))
Check "T10: populated section shows its count - Hunt (2)" ($html.Contains("<a href='#hunt'>Hunt (2)</a>"))
Check "T10: populated section shows its count - Leads (2)" ($html.Contains("<a href='#leads'>Leads (2)</a>"))
Check "T10: populated section shows its count - Sigma (3)" ($html.Contains("<a href='#sigma'>Sigma (3)</a>"))
Check "T10: med+ only - Findings by tactic (2)" ($html.Contains("<a href='#tactics'>Findings by tactic (2)</a>"))
Check "T10: distinct techniques - ATT&CK (2) with the escaped ampersand" ($html.Contains("<a href='#attack'>ATT&amp;CK (2)</a>"))
Check "T10: populated section shows its count - IOCs (1)" ($html.Contains("<a href='#ioc'>IOCs (1)</a>"))
Check "T10: populated section shows its count - Timeline (4)" ($html.Contains("<a href='#timeline'>Timeline (4)</a>"))
Check "T10: focus dossier row count from focus_terms.json - Focus (7)" ($html.Contains("<a href='#focus'>Focus (7)</a>"))
Check "T10: coverage rows + gaps - Coverage (3)" ($html.Contains("<a href='#coverage'>Coverage (3)</a>"))
Check "T10: 4648 rows counted - Logons (2)" ($html.Contains("<a href='#logons'>Logons (2)</a>"))
Check "T10: multi-source binaries only - Connections (1)" ($html.Contains("<a href='#entities'>Connections (1)</a>"))
Check "T10: populated snapshot source counted - Snapshot (1)" ($html.Contains("<a href='#snapshot'>Snapshot (1)</a>"))
Check "T10: credential sweep table renders from the populated CSV" (($html.Contains('<h3>Credential exposure sweep</h3>')) -and ($html.Contains('WLAN key (NETGEAR-GUEST)')))
Check "T10: empty section shows the (none) marker - YARA" ($html.Contains("<a href='#yara'>YARA (none)</a>"))
Check "T10: empty section shows the (none) marker - Drivers" ($html.Contains("<a href='#drivers'>Drivers (none)</a>"))

# nav counts must not break the v2.66 B1 contract: every link still targets a real anchor
$navHtml278 = [regex]::Match($html, "(?s)<div class='nav'>(.*?)</div>").Groups[1].Value
$navSeq278 = @([regex]::Matches($navHtml278, "href='#([a-z]+)'") | ForEach-Object { $_.Groups[1].Value })
$docSeq278 = @([regex]::Matches($html, "<a name='([a-z]+)'></a>") | ForEach-Object { $_.Groups[1].Value })
$deadNav278 = @($navSeq278 | Where-Object { $docSeq278 -notcontains $_ })
Check "T10: counts did not break nav anchors - every link targets an existing document anchor" (($navSeq278.Count -ge 20) -and ($deadNav278.Count -eq 0))
Check "T10: verdict/recommendations/evidence carry no count" ((-not $navHtml278.Contains('>Verdict (')) -and (-not $navHtml278.Contains('>Recommendations (')) -and (-not $navHtml278.Contains('>Evidence index (')))

# ---- T10: Processes cap label polarity ----
Check "T10: truncated section states the cap in the heading (showing 30 of 32)" ($html.Contains('<h2>Process verdicts (correlation scored) - showing 30 of 32</h2>'))
'# no entries' | Set-Content -LiteralPath (Join-Path $csvDir 'flash_process_scored.csv') -Encoding UTF8
$null = New-HtmlReport
$htmlFew = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "T10: untruncated/empty section keeps the plain heading (no cap text)" (($htmlFew.Contains('<h2>Process verdicts (correlation scored)</h2>')) -and (-not ($htmlFew.Contains('correlation scored) - showing'))))
Check "T10: nav count follows the data - Processes (none)" ($htmlFew.Contains("<a href='#processes'>Processes (none)</a>"))

# restore a small scored set -> cap must stay absent, count updates
@'
"Name","Path","PID","Verdict","Score","Evidence","Signer"
"notepad.exe","C:\Windows\System32\notepad.exe","111","MEDIUM","3","score: review items",""
"cmd.exe","C:\Windows\System32\cmd.exe","222","MEDIUM","3","score: review items",""
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'flash_process_scored.csv') -Encoding UTF8
$null = New-HtmlReport
$html12 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "T10: 2 scored rows -> Processes (2), no cap text" (($html12.Contains("<a href='#processes'>Processes (2)</a>")) -and (-not ($html12.Contains('correlation scored) - showing'))))

# ---- T9: draft collapse (behavioral) + Recommendations anchor resolution ----
$null = New-HtmlReport
$html9 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "T9: rendered draft opens with the verbatim summary inside details" ($html9.Contains("<a name='draft'></a><details><summary>Case draft (auto-written - paste into your report)</summary><div class='draft'>"))
Check "T9: draft body renders inside the collapsed block" (($html9.Contains('<p><b>ASSESSMENT</b></p>')) -and ($html9.Contains("<p style='margin:2px 0 2px 18px'> - sub line</p>")))
Check "T9: plain-text pointer closes the details block" ($html9.Contains('not a conclusion.</div></details>'))
Check "T9: no open h2 draft heading left in the render" (-not ($html9.Contains('Case draft (auto-written - edit before use)')))
$donowFrag = ($html -split "<div class='donow'>" | Select-Object -Skip 1 | Select-Object -First 1)
Check "T9: Do-now block carries the Recommendations jump link" (($null -ne $donowFrag) -and $donowFrag.Contains("<a href='#recommendations'>-&gt; full Recommendations</a>"))
Check "T9: the Recommendations link target exists in the document" ($html.Contains("<a name='recommendations'></a>"))

# case_draft.txt on disk after the full pipeline is covered by the static pin in PART A
# (the txt write lives in Invoke-RegenerateOutputs, outside this render)

if ($pass -eq 0 -and $fail -eq 0) { Write-Host "no checks ran" -ForegroundColor Red; exit 1 }
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $case" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
