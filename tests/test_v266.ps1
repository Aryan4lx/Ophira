# test_v266.ps1 - v2.66 report nav + linking pack:
#   B1 nav order mirrors the rendered H2/anchor order (was: Leads before Verdict, Timeline
#       before Snapshot/Drivers/Hunt/Entities)
#   B3 'Security posture gaps' + 'Credential material exposure' signal rows resolve to a
#       section anchor that actually exists (were dead/plain text; both tables render in snapshot)
#   B5 sigma per-rule drill-down "full CSV" pointer is a ConvertTo-CaseFileLink, not a bare span
#   B2 case-file hrefs are case-RELATIVE (no file:// scheme, no drive letters, forward slashes);
#       label text unchanged; missing files still degrade to plain text (v2.56 pin)
#   B10 sigma drill-down honesty: 'showing N of M embedded' on truncated rules, zero-embedded
#       rules lose the filter/pager UI (budget exhausted), EID datalist, page-size jump
#   B11 timeline table filters: source dropdown + from/to date inputs composing with the text box
#   B12 one shared text filter box on Processes / Tactics / Entities (one JS function, 3 bindings)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$names = @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel', 'ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass', 'Get-TriageLeads', 'Get-InvariantDate', 'Get-SafeRuleKey', 'Get-SafeRuleKeyMap', 'Resolve-SafeRuleKey')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$case = Join-Path $env:TEMP ("ophira_v266_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, (Join-Path $rawDir 'evtx'), (Join-Path $csvDir 'sigma_rules') -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
# B13: the analysis-window rec renders only when a window was resolved - pin one so the
# generated-stamp dialect check can assert on its rendered text
$script:LogStartDT = [datetime]'2026-09-01 08:00'; $script:LogEndDT = [datetime]'2026-09-24 08:00'
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
# console-side range text (verdict caveat wording only) - stubbed with the real function's shape
function Get-LogRangeText { 'From 2026-09-01 08:00 to 2026-09-24 08:00' }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

# hay rows -> sigma section + per-rule drill-down for rule 'Suspicious PowerShell' (B6 link
# source) plus a 20-row medium storm (B7 sigma lead with a drill-down-able top rule).
# RecordID column = the real hayabusa verbose profile carries it (B6 deep links prefer it).
$hay = New-Object System.Collections.Generic.List[string]
$null = $hay.Add('"Timestamp","Computer","EventID","RecordID","Level","RuleTitle","Details","MitreTactics","MitreTags"')
$null = $hay.Add('"2026-09-24 10:00:00.000 +00:00","TESTHOST","1","rid-a","high","Suspicious PowerShell","-enc command","Exec","T1059.001"')
$null = $hay.Add('"2026-09-24 10:05:00.000 +00:00","TESTHOST","1","rid-b","high","Suspicious PowerShell","encoded payload","Exec","T1059.001"')
$null = $hay.Add('"2026-09-24 10:06:00.000 +00:00","TESTHOST","7045","rid-c","low","Run key persistence","reg add","Persis","T1547.001"')
1..20 | ForEach-Object { $null = $hay.Add(('"2026-09-24 11:{0:00}:00.000 +00:00","TESTHOST","1","rid-s{0}","medium","Storm Rule","storm detail {0}","Disc","T1082"' -f $_)) }
# B10 budget walk: 4963 filler + 20 storm + 12 suspicious = 4995 of the 5000-row embed budget
# spent -> 'Run key persistence' (8 hits) embeds 5/8 (truncated summary), 'Starved Rule'
# (6 hits) embeds 0 (drill-down UI hidden, no deep links). The embedded RunKey rows carry
# EIDs 7045/1547/1; the non-embedded tail carries 9999 (reaches the EID datalist since
# v2.68 B14 - the datalist covers the rule's FULL row set).
1..10 | ForEach-Object { $null = $hay.Add(('"2026-09-24 10:{0:00}:00.000 +00:00","TESTHOST","1","rid-p{0}","high","Suspicious PowerShell","encoded payload {0}","Exec","T1059.001"' -f (6 + $_))) }
1..7 | ForEach-Object {
    $rkMin = '{0:00}' -f (6 + $_)
    $rkEid = @('7045', '1547', '7045', '1', '9999', '9999', '9999')[$_-1]
    $null = $hay.Add("`"2026-09-24 10:$rkMin`:00.000 +00:00`",`"TESTHOST`",`"$rkEid`",`"rid-r$_`",`"low`",`"Run key persistence`",`"reg add $_`",`"Persis`",`"T1547.001`"")
}
1..6 | ForEach-Object { $null = $hay.Add(('"2026-09-24 12:{0:00}:00.000 +00:00","TESTHOST","4648","rid-z{0}","low","Starved Rule","starved detail {0}","",""' -f $_)) }
$fillerBase = [datetime]'2026-09-20 00:00:00'
1..4963 | ForEach-Object { $null = $hay.Add('"' + $fillerBase.AddMinutes($_).ToString('yyyy-MM-dd HH:mm:ss.000 +00:00') + '","TESTHOST","1","rid-f' + $_ + '","low","Budget Filler Rule","filler detail ' + $_ + '","",""') }
$hay | Set-Content -LiteralPath (Join-Path $csvDir 'hayabusa_timeline.csv') -Encoding UTF8
# the per-rule drill-down CSV must exist on disk so ConvertTo-CaseFileLink emits a link
'"Timestamp","Computer","EventID","RecordID","Level","Details"' | Set-Content -LiteralPath (Join-Path $csvDir 'sigma_rules\Suspicious_PowerShell.csv') -Encoding UTF8
foreach ($rn in @('Run_key_persistence', 'Starved_Rule', 'Budget_Filler_Rule')) {
    '"Timestamp","Computer","EventID","RecordID","Level","Details"' | Set-Content -LiteralPath (Join-Path $csvDir "sigma_rules\$rn.csv") -Encoding UTF8
}

# posture BAD row -> 'Security posture gaps' signal + snapshot posture table
@'
"Check","Status","Detail"
"Defender exclusions","BAD","2 exclusion(s) configured - attackers add these; review: C:\tools"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'posture.csv') -Encoding UTF8
# credential HIGH row -> 'Credential material exposure' signal + snapshot credential table
@'
"Item","Detail","Risk"
"Auto-logon (Winlogon)","user 'a', cached password: PRESENT","HIGH"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'credential_sweep.csv') -Encoding UTF8

# the report links Focus in the nav - give the fixture a focus_terms.json so the section renders
# (minimal dossier: the section body renders just the h2 + meta line for an empty terms file)
New-Item -ItemType Directory -Path (Join-Path $case 'focus') -Force | Out-Null
'{"Indicator":"suspicious.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $case 'focus\focus_terms.json') -Encoding UTF8
# B9: the focus embed's activity graph + per-instance tables - the sticky mini-key renders
# above the per-instance details only when a graph exists
'{"Indicator":"evil.exe","GraphSvg":"<svg id=''g6''></svg>","CorrNotes":[],"Instances":[{"Pid":"4242","Guid":"g-1","Started":"2026-09-24 10:00","Image":"C:\\mal\\evil.exe","Parent":"","User":"u","Lineage":[],"Respawn":"","Children":[{"Time":"2026-09-24 10:01","Image":"C:\\mal\\child.exe","ProcessId":"99","User":"u"}],"Net":[],"Dns":[],"Dll":[],"Reg":[],"File":[],"FileCreate":[],"FileDelete":[],"Persist":[],"Beacon":[],"CrtIn":[],"CrtOut":[],"Pipes":[],"Tamper":[],"RawDisk":[],"Exec":[]}]}' | Set-Content -LiteralPath (Join-Path $case 'focus\focus_instances_detail.json') -Encoding UTF8

# B7: hunt lead targets a section WITHOUT a filter -> must keep the plain section-top link
@'
"Rule","Severity","Entity","ATT&CK","Evidence"
"R8 User-path LOLBin","high","C:\mal\evil.exe","T1059","binary ran from user path and spawned cmd"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'hunt_findings.csv') -Encoding UTF8

# B8: entity card with mapped (sigma, hunt - v2.67 B2 links category tokens) and one
# unmapped (legacy-agent - no artifact name, no category token) evidence source
@'
"Path","Name","CatCount","Categories","Verdict","Signer","FirstSeen","LastSeen","Hashes","Bytes","Evidence"
"C:\mal\evil.exe","evil.exe","3","sigma;hunt;legacy-agent","HIGH","","2026-09-24 10:00:00","2026-09-24 11:19:00","","","sigma: [medium] Storm Rule: storm detail 1 | hunt: [high] R8 User-path LOLBin: binary ran from user path | legacy-agent: custom feed note"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'entities_binaries.csv') -Encoding UTF8

# B11: real supertimeline rows -> the newest-150 inline table renders with its filters
# (3 distinct sources, events spanning two days for the date-window filter)
@'
"Timestamp","Source","Type","Actor","Entity","Detail"
"2026-09-24 09:00:00","Security","logon","TESTHOST\user1","user1","4624 interactive logon"
"2026-09-24 10:00:30","Sysmon","process","TESTHOST\user1","C:\mal\evil.exe","process create"
"2026-09-24 10:05:00","Security","logon","TESTHOST\user1","user1","4624 logon type 10"
"2026-09-24 15:00:00","Sysmon","network","TESTHOST\user1","evil.exe","TCP connect to 203.0.113.9"
"2026-09-25 08:30:00","Prefetch","exec","TESTHOST\user1","CMD.EXE","prefetch touched"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'supertimeline.csv') -Encoding UTF8
# B13: the entity-card context window is +/-30 min around FirstSeen (10:00 local wall) rendered
# against the weave's UTC wall-clock rows - cover the surrounding hours so the window has
# neighbors whatever timezone the box runs in (the weave would emit exactly this shape)
$tl266 = New-Object System.Collections.Generic.List[string]
$null = $tl266.Add('"Timestamp","Source","Type","Actor","Entity","Detail"')
foreach ($ln in (Get-Content -LiteralPath (Join-Path $csvDir 'supertimeline.csv'))) { if ($ln -notmatch '^"Timestamp"') { $null = $tl266.Add($ln) } }
1..37 | ForEach-Object {
    $u = ([datetime]'2026-09-23 12:00').AddHours($_).ToString('yyyy-MM-dd HH:mm:ss')
    $null = $tl266.Add('"' + $u + '","Amcache","exec","TESTHOST\user1","C:\mal\evil.exe","amcache exec (UTC-span ' + $_ + ')"')
}
$tl266 | Set-Content -LiteralPath (Join-Path $csvDir 'supertimeline.csv') -Encoding UTF8

# B12: a few scored processes so the Processes filter box has cards to filter
# (MEDIUM/score 3 -> stays below the lead threshold, leads fixture untouched)
@'
"Name","Path","PID","Verdict","Score","Evidence","Signer"
"notepad.exe","C:\Windows\System32\notepad.exe","111","MEDIUM","3","score: review items",""
"cmd.exe","C:\Windows\System32\cmd.exe","222","MEDIUM","3","score: review items",""
"rundll32.exe","C:\Windows\System32\rundll32.exe","333","MEDIUM","3","score: review items",""
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'flash_process_scored.csv') -Encoding UTF8

foreach ($empty in @('flash_ioc_hits', 'ioc_hits_amcache', 'yara_hits', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'ps_decoded_commands', 'entities_accounts', 'entities_remotes', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'execution_timeline', 'security_bruteforce_candidates', 'flash_public_connections')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- render the fixture case ----
$v = Get-CompromiseVerdict
$script:Verdict = $v
$bothSignals = @($v.Signals | Where-Object { $_.Signal -in @('Security posture gaps', 'Credential material exposure') })
Check "fixture sanity: both target signals present in the verdict" ($bothSignals.Count -eq 2)

$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

# ---- B1: nav order mirrors the rendered document ----
$navHtml = [regex]::Match($html, "(?s)<div class='nav'>(.*?)</div>").Groups[1].Value
$navSeq = @([regex]::Matches($navHtml, "href='#([a-z]+)'") | ForEach-Object { $_.Groups[1].Value })
$docSeq = @([regex]::Matches($html, "<a name='([a-z]+)'></a>") | ForEach-Object { $_.Groups[1].Value })
Check "nav: extracted $($navSeq.Count) nav links and $($docSeq.Count) document anchors" ($navSeq.Count -ge 20 -and $docSeq.Count -ge 20)
$deadNav = @($navSeq | Where-Object { $docSeq -notcontains $_ })
Check "B1: every nav link targets an existing document anchor" ($deadNav.Count -eq 0)
$docInNavOrder = @($docSeq | Where-Object { $navSeq -contains $_ })
Check "B1: nav sequence == document render order (was Leads-before-Verdict, Timeline-before-Snapshot)" ((($navSeq -join ',') -eq ($docInNavOrder -join ',')))
Check "B1: Verdict nav link precedes Leads" ($navSeq.IndexOf('verdict') -lt $navSeq.IndexOf('leads'))
Check "B1: Drivers/Hunt/Entities nav links precede Snapshot and Timeline" (($navSeq.IndexOf('drivers') -lt $navSeq.IndexOf('snapshot')) -and ($navSeq.IndexOf('hunt') -lt $navSeq.IndexOf('snapshot')) -and ($navSeq.IndexOf('entities') -lt $navSeq.IndexOf('snapshot')) -and ($navSeq.IndexOf('snapshot') -lt $navSeq.IndexOf('timeline')))

# ---- B3: posture + credential signal rows resolve to an existing section anchor ----
foreach ($sigName in @('Security posture gaps', 'Credential material exposure')) {
    $frag = @($html -split "<div class='sig'>" | Where-Object { $_ -like "*$sigName*" })[0]
    $pre = ($frag -split '</div>')[0]
    $targ = ''
    if ($pre -match "href='#([a-z]+)'") { $targ = $Matches[1] }
    Check "B3: '$sigName' signal row carries a section link (was dead/plain text)" ($targ -ne '')
    Check "B3: '$sigName' anchor '#$targ' exists in the rendered document" (($targ -ne '') -and ($html -match "<a name='$targ'></a>"))
}

# ---- B5: sigma drill-down pointer is a case-file link ----
Check "B5: drill-down per-rule CSV renders as an anchor tag with a relative href" ($html -match [regex]::Escape("<a href='csv/sigma_rules/Suspicious_PowerShell.csv'>csv\sigma_rules\Suspicious_PowerShell.csv</a>"))
Check "B5: no bare span pointer left for the per-rule CSV" (-not $html.Contains("<span class='meta'>csv\sigma_rules\Suspicious_PowerShell.csv</span>"))

# ---- B2: relative case-file hrefs ----
$rf = ConvertTo-CaseFileLink (Join-Path $csvDir 'sigma_rules\Suspicious_PowerShell.csv') 'csv\sigma_rules\Suspicious_PowerShell.csv'
$rd = ConvertTo-CaseFileLink (Join-Path $case 'raw') 'raw\'
Check "B2: existing csv file -> relative href, forward slashes" ($rf -eq "<a href='csv/sigma_rules/Suspicious_PowerShell.csv'>csv\sigma_rules\Suspicious_PowerShell.csv</a>")
Check "B2: existing dir -> relative href" ($rd -eq "<a href='raw/'>raw\</a>")
Check "B2: no file:// scheme in links" (($rf -notmatch 'file://') -and ($rd -notmatch 'file://'))
Check "B2: no drive letter in hrefs" (($rf -notmatch "href='[A-Za-z]:") -and ($rd -notmatch "href='[A-Za-z]:"))
Check "B2: visible label text unchanged (plain relative path as today)" ($rf.EndsWith('>csv\sigma_rules\Suspicious_PowerShell.csv</a>'))
$miss = ConvertTo-CaseFileLink (Join-Path $case 'csv\no_such.csv') 'csv\no_such.csv'
Check "B2: missing file still degrades to plain text (v2.56 pin)" ($miss -eq 'csv\no_such.csv')
$outside = ConvertTo-CaseFileLink (Join-Path $env:TEMP 'outside_case.html') 'x'
Check "B2: path outside the case root -> plain text (never leak an absolute path)" ($outside -eq 'x')
Check "B2: rendered report contains no file:// anywhere" (-not $html.Contains('file://'))
Check "B2: rendered report contains no drive-letter hrefs" (-not ($html -match "href='[A-Za-z]:[/\\]"))
Check "B2: 'Also in the case' raw dir renders as a relative link" ($html.Contains("<a href='raw/'>raw\</a>"))

# ---- B6: ATT&CK expansion deep-links into the same-rule sigma drill-down ----
Check "B6: ATT&CK expansion rows link to the Sigma section carrying the rule identity (data-rule)" ($html -match [regex]::Escape("<a href='#sigma' class='a-drill' data-rule='Suspicious_PowerShell'"))
Check "B6: the ATT&CK expansion link carries the event identity in data-q (RecordID preferred)" ($html -match [regex]::Escape('data-q="rid-a"'))
Check "B6: delegated handler exists (a[data-rule] -> open details + prefill + renderRule)" (($html -match "closest\('a\[data-rule\]'\)") -and ($html -match "q_'\+id") -and ($html -match "renderRule\(id\)"))
Check "B6: drill-down embed rows carry RecordID so the pre-filled filter can hit them" (($html -match '"rid":"rid-a"') -and ($html -match '"rid":"rid-s1"'))

# ---- B7: lead cards carry the entity into the target section's filter ----
Check "B7: sigma lead link carries its top rule into the drill-down filter (data-rule)" ($html.Contains("<a href='#sigma' data-rule='Storm_Rule'>-> evidence in the sigma section</a>"))
Check "B7: lead targeting a section without a filter keeps the plain section-top link" ($html.Contains("<a href='#hunt'>-> evidence in the hunt section</a>"))

# ---- B8: entity chips polish ----
Check "B8: hunt chip links to the hunt section (v2.67 B2: category tokens link)" ($html.Contains("<a href='#hunt'><span class='chip'>hunt</span></a>"))
Check "B8: mapped chip stays a normal linked chip" ($html.Contains("<a href='#sigma'><span class='chip'>sigma</span></a>"))
Check "B8: unknown-category chip renders with the grey/dead class" ($html.Contains("<span class='chip chipdead'>legacy-agent</span>"))
# v2.67 (B2): lead-card "corroborated by" chips route through the anchor mapper too
# (no @() wrap here - a 1-element array's .Contains is membership, not substring)
$corr = $html -split 'corroborated by' | Select-Object -Skip 1 | Select-Object -First 1
Check "B2: lead-card corroboration chips render as links" (($null -ne $corr) -and $corr.Contains("<a href='#sigma'><span class='chip'>sigma</span></a>") -and $corr.Contains("<a href='#hunt'><span class='chip'>hunt</span></a>"))
Check "B2: lead-card unmapped category stays a grey/dead chip" (($null -ne $corr) -and $corr.Contains("<span class='chip chipdead'>legacy-agent</span>"))
$chips1 = @([regex]::Matches(([regex]::Match($html, '(?s)appears in:(.*?)</div>').Groups[1].Value), "class='chip[^']*'>([^<]+)<") | ForEach-Object { $_.Groups[1].Value })
$null = New-HtmlReport
$html2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
$chips2 = @([regex]::Matches(([regex]::Match($html2, '(?s)appears in:(.*?)</div>').Groups[1].Value), "class='chip[^']*'>([^<]+)<") | ForEach-Object { $_.Groups[1].Value })
Check "B8: chip sequence deterministic across two renders (sorted by category name)" ((($chips1 -join '|') -eq ($chips2 -join '|')) -and ($chips1 -contains 'sigma') -and ($chips1 -contains 'hunt'))
$chipIdxH = [array]::IndexOf($chips1, 'hunt'); $chipIdxS = [array]::IndexOf($chips1, 'sigma')
Check "B8: chips sort by category name (hunt before sigma, not insertion order)" (($chipIdxH -ge 0) -and ($chipIdxS -gt $chipIdxH))
Check "B8: mapped evidence Detail cell renders as a section link" ($html.Contains("<td class='path'><a href='#sigma'>[medium] Storm Rule: storm detail 1</a></td>"))
Check "B8: hunt evidence Detail cell links to the hunt section (v2.67 B2)" ($html.Contains("<td class='path'><a href='#hunt'>[high] R8 User-path LOLBin: binary ran from user path</a></td>"))
Check "B8: unknown-category evidence Source + Detail cells stay plain" ($html.Contains("<td><b>legacy-agent</b></td><td class='path'>custom feed note</td>"))

# ---- B9: sticky mini-key above the per-instance section ----
Check "B9: sticky mini-key markup present with the graph's own color vocabulary" (($html -match "class='mkey'") -and ($html.Contains('background:#3a1518;border-color:#a33')) -and ($html.Contains('background:#33290f;border-color:#c93')))
Check "B9: mini-key CSS is position:sticky" ($html -match '\.mkey\{position:sticky')
Check "B9: mini-key sits above the per-instance tables" ((($html.IndexOf("class='mkey'") -ge 0)) -and ($html.IndexOf("class='mkey'") -lt $html.IndexOf('everything it did')))

# ---- B10: sigma drill-down honesty (embedded-vs-total, zero-embed UI hidden, EID datalist, page jump) ----
Check "B10: truncated rule summary states both counts (showing N of M embedded)" ($html -match [regex]::Escape('Run key persistence</b></span> - 8 hit(s), showing 5 of 8 embedded'))
Check "B10: fully embedded rule summary carries no truncation note" (-not ($html -match [regex]::Escape('Storm Rule</b></span> - 20 hit(s), showing')))
Check "B10: zero-embedded rule keeps summary + CSV pointer but no filter input" (($html -match [regex]::Escape('Starved Rule</b></span> - 6 hit(s)')) -and (-not ($html.Contains("id='q_Starved_Rule'"))))
Check "B10: zero-embedded rule has no table/pager target box" (-not ($html.Contains("id='b_Starved_Rule'")))
Check "B10: zero-embedded rule explains the budget exhaustion" ($html -match [regex]::Escape('Embed budget exhausted before this rule'))
Check "B10: no deep link targets a rule without a rendered drill-down" (-not ($html.Contains("data-rule='Starved_Rule'")))
$datalist = [regex]::Match($html, "(?s)<datalist id='ed_Run_key_persistence'>(.*?)</datalist>").Groups[1].Value
Check "B10: EID datalist lists distinct EIDs of the FULL row set (v2.68 B14: budget tail's 9999 included)" (($datalist -match '<option>7045</option>') -and ($datalist -match '<option>1547</option>') -and ($datalist -match '<option>1</option>') -and ($datalist -match '<option>9999</option>'))
Check "B10: filter input references the EID datalist" ($html -match [regex]::Escape("list='ed_Run_key_persistence'"))
Check "B10: page-size jump control rendered (50/100/200/all)" (($html -match [regex]::Escape("<select id='ps_Run_key_persistence'")) -and ($html -match [regex]::Escape("<option value='all'>all embedded</option>")))
Check "B10: renderRule honors the page-size control" (($html -match "getElementById\('ps_'\+id\)") -and ($html -match "psv==='all'"))

# ---- B11: timeline table filters (source dropdown + date window composing with the text box) ----
Check "B11: source dropdown rendered with distinct sources of the embedded rows" (($html -match "id='tls'") -and ($html.Contains('<option>Security</option>')) -and ($html.Contains('<option>Sysmon</option>')) -and ($html.Contains('<option>Prefetch</option>')))
Check "B11: from/to date inputs rendered" (($html -match [regex]::Escape("<input type='date' id='tlfrom'")) -and ($html -match [regex]::Escape("<input type='date' id='tlto'")))
$tlfn = [regex]::Match($html, "(?s)function tlFilter\(\)\{(.*?)</script>").Groups[1].Value
Check "B11: filter composes substring AND source AND date window" (($tlfn.Contains('indexOf(q)>=0') -and $tlfn.Contains('c[1].textContent===s') -and $tlfn.Contains('d>=f') -and $tlfn.Contains('d<=t')))
Check "B11: count line reacts to any filter dimension" ($tlfn.Contains('(q||s||f||t)'))

# ---- B12: one shared filter box on Processes / Tactics / Entities ----
Check "B12: shared filter function defined exactly once" (([regex]::Matches($html, 'function secFilter\(')).Count -eq 1)
Check "B12: exactly three filter boxes bound to the shared function" (([regex]::Matches($html, "data-secfilter='1'")).Count -eq 3)
Check "B12: processes box targets the wrapped process cards" (($html -match [regex]::Escape("id='procf' data-secfilter='1' data-wrap='procwrap' data-sel='div.card'")) -and ($html.Contains("<div id='procwrap'>")) -and ($html.IndexOf('rundll32.exe') -gt $html.IndexOf("id='procwrap'")))
Check "B12: tactics box targets the wrapped tactic blocks" (($html -match [regex]::Escape("id='tacf' data-secfilter='1' data-wrap='tacwrap' data-sel='div.tacblk'")) -and ($html.Contains("<div id='tacwrap'>")) -and ($html.Contains("class='tacblk'")))
Check "B12: entities box targets the wrapped entity cards" (($html -match [regex]::Escape("id='entf' data-secfilter='1' data-wrap='entwrap' data-sel='details'")) -and ($html.Contains("<div id='entwrap'>")))
Check "B12: per-section count displays present" (($html.Contains("id='cnt_proc'")) -and ($html.Contains("id='cnt_tac'")) -and ($html.Contains("id='cnt_ent'")))
Check "B12: boxes auto-bind to the shared function on load" ($html -match "querySelectorAll\('input\[data-secfilter\]'\)")

# ---- B16: findings-by-tactic grouping actually groups by row tactic (was: $_ not set by a
# foreach STATEMENT -> empty/stale key -> every med+ alert collapsed into one wrong bucket) ----
Check "B16: Execution tactic block renders with its 12 med+ events" ($html -match 'Execution \(12 events\)')
Check "B16: Discovery tactic block renders with its 20 med+ events" ($html -match 'Discovery \(20 events\)')
$tacBlocks = @([regex]::Matches($html, "<div class='tacblk'><h3>([^<]+) \(\d+ events\)") | ForEach-Object { $_.Groups[1].Value })
Check "B16: 2+ distinct tactic headings, Execution + Discovery both present (was one collapsed bucket)" (($tacBlocks.Count -ge 2) -and ($tacBlocks -contains 'Execution') -and ($tacBlocks -contains 'Discovery'))

# ---- B13: one timestamp dialect for Ophira's own generated stamps (evidence cells NEVER rewritten) ----
# v2.77: the banner's Collected stamp became the provenance line (Collected by <tool> from
# case.json / Rendered by Ophira vN); the dialect checks live on the footer + evidence-window
# stamps below.
Check "B13: provenance line separates the collector tool from the renderer version (no case.json -> collector segment omitted)" ($html.Contains('Rendered by Ophira v9.99') -and (-not $html.Contains('Collected by')))
Check "B13: footer 'Generated' stamp in the same dialect (was Get-Date -Format u: seconds + Z)" ($html -match 'Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC by Ophira v9\.99')
Check "B13: no seconds+Z dialect left on the banner stamp" (-not ($html -match 'Collected: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z'))
Check "B13: no seconds+Z dialect left on the footer stamp" (-not ($html -match 'Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z'))
Check "B13: evidence-window stamps carry the UTC suffix (was TZ-less)" ($html -match 'Evidence window:</b> \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC to \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC')
Check "B13: analysis-window rec stamps carry the UTC suffix (was TZ-less)" ($html.Contains('Analysis window started at 2026-09-01 08:00 UTC (ends 2026-09-24 08:00 UTC)'))
Check "B13: first-seen context prose stamp in the dialect (was seconds, TZ-less)" ($html -match 'around first seen \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC')
Check "B13: RAW evidence cell untouched - timeline row keeps its exact CSV timestamp" ($html.Contains('<td>2026-09-24 10:00:30</td>'))
Check "B13: RAW hayabusa timestamp cell untouched (ATT&ACK last-seen keeps its +00:00 offset)" ($html.Contains('2026-09-24 10:00:00.000 +00:00'))

# ---- B14: blank identity fallback (same pattern as the elevation 'unknown' fix) ----
Check "B14: banner carries the real CaseID/Analyst when present" ($html.Contains("Case: CASE-1 &nbsp;|&nbsp; Analyst: fixture"))
$script:CurrentCaseID = ''; $script:CurrentAnalyst = ''
$null = New-HtmlReport
$htmlNoId = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "B14: missing CaseID falls back to the case FOLDER name (v2.77, was bare 'unknown')" ($htmlNoId -match "Case: ophira_v266_\d+ &nbsp;\|&nbsp; Analyst: not recorded")
Check "B14: missing Analyst renders 'not recorded'" ($htmlNoId.Contains("Analyst: not recorded &nbsp;|&nbsp;"))
Check "B14: no blank identity slots left (no 'Case:  |')" (-not ($htmlNoId.Contains("Case:  &nbsp;")))
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'

# ---- B15: empty-state honesty (processes meta / VT column header / gaps link) ----
$case2 = Join-Path $env:TEMP ("ophira_v266b_" + (Get-Date -Format 'HHmmss'))
$csv2 = Join-Path $case2 'csv'
New-Item -ItemType Directory -Path $csv2, (Join-Path $case2 'raw\analysis') -Force | Out-Null
'chainsaw gaps raw output' | Set-Content -LiteralPath (Join-Path $case2 'raw\analysis\evtx_gaps.txt') -Encoding UTF8
@'
"Time","EventId","Meaning"
"","","chronological gaps detected in evtx (see raw\analysis\evtx_gaps.txt)"
'@ | Set-Content -LiteralPath (Join-Path $csv2 'logging_gaps.csv') -Encoding UTF8
@'
"SourceIp","FailedLogons"
"203.0.113.66","9"
'@ | Set-Content -LiteralPath (Join-Path $csv2 'security_bruteforce_candidates.csv') -Encoding UTF8
$saveCase = $CaseDir; $saveCsv = $CsvDir; $saveRaw = $RawDir
$CaseDir = $case2; $CsvDir = $csv2; $RawDir = Join-Path $case2 'raw'
$null = New-HtmlReport
$html2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "B15a: empty processes section explains why (source CSV absent)" ($html2 -match "(?s)<a name='processes'></a><h2>Process verdicts \(correlation scored\)</h2>\s*<div class='meta'>No scored processes to show - source CSV flash_process_scored\.csv is absent")
Check "B15a: empty processes section renders no bare shell (no filter box)" (-not $html2.Contains("id='procf'"))
'# no entries' | Set-Content -LiteralPath (Join-Path $csv2 'flash_process_scored.csv') -Encoding UTF8
$null = New-HtmlReport
$html2b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "B15a: empty scored CSV words the other branch honestly (module ran, nothing above threshold)" ($html2b.Contains('No scored processes to show - the scoring module ran but recorded no processes above the reporting threshold'))
Check "B15b: brute-force table names its VT column (was an unnamed <th></th>)" ($html2b.Contains('<th>Source IP</th><th>Failed logons</th><th>VT</th>'))
Check "B15c: gap row with empty Time/Event cells links the raw gaps output" ($html2b.Contains("<td colspan='2'><a href='raw/analysis/evtx_gaps.txt'>raw\analysis\evtx_gaps.txt</a></td>"))
$CaseDir = $saveCase; $CsvDir = $saveCsv; $RawDir = $saveRaw
Remove-Item -LiteralPath $case2 -Recurse -Force -ErrorAction SilentlyContinue

# ---- deep-link wiring sanity: every emitted data-rule target has a matching drill-down ----
$drillRefs = @([regex]::Matches($html, "data-rule='([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$orphanRefs = @($drillRefs | Where-Object { $html -notmatch [regex]::Escape("id='q_$_'") })
Check "wiring: every data-rule deep link resolves to a rendered drill-down filter input" ($drillRefs.Count -ge 2 -and $orphanRefs.Count -eq 0)

if ($pass -eq 0 -and $fail -eq 0) { Write-Host "no checks ran" -ForegroundColor Red; exit 1 }
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $case" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
