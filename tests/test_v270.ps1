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

function Import-CaseCsv([string]$name) { $name = "$name" -replace '\.csv$', ''; if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
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

# ---- v2.71 task 5+6: ONE lead builder (Get-TriageLeads) + strength-ordered leads ----
$mTl = [regex]::Match($src, "(?s)function Get-TriageLeads \{.*?\r?\n\}")
Check "task5: Get-TriageLeads extractable (column-0 brace)" ($mTl.Success)
if (-not $mTl.Success) { throw 'extract failed: Get-TriageLeads' }
Invoke-Expression $mTl.Value
foreach ($n3 in @('ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass')) {
    $m3 = [regex]::Match($src, "(?s)function $n3 \{.*?\r?\n\}")
    if ($m3.Success) { Invoke-Expression $m3.Value }
}
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
function Ent2([string]$path, [string]$cats) {
    [pscustomobject]@{ Path = $path; Categories = $cats }
}
$toCsvRow = {
    param($ld)
    [pscustomobject]@{ Rank = "$($ld.Rank)"; Title = "$($ld.Title)"; Class = "$($ld.Class)"; Why = "$($ld.Why)"; Ident = "$($ld.Ident)"; Extra = "$($ld.Extra)"; Anchor = "$($ld.Anchor)"; Rule = "$($ld.Rule)" }
}

# task6-1: strength order - the 2-corroboration renamed binary outranks the 1-corroboration download
$script:fixtureRows = @{
    'hunt_findings'     = @(
        (Hf2 'Downloaded then executed' 'C:\Users\Ary\Downloads\7z2603-x64.exe' 'T1650' 'downloaded then executed')
        (Hf2 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'C:\Windows\Temp\svcroot.exe' 'T1036.003' 'identity mismatch evidence')
    )
    'entities_binaries' = @(
        (Ent2 'c:\users\ary\downloads\7z2603-x64.exe' 'hunt_findings')
        (Ent2 'C:\Windows\Temp\svcroot.exe' 'hunt_findings;processes')
    )
}
$leadsT6 = @(Get-TriageLeads)
Check "task6: 2-corroboration renamed binary ranks #1 (download #2)" ($leadsT6.Count -eq 2 -and "$($leadsT6[0].Title)" -eq 'C:\Windows\Temp\svcroot.exe' -and "$($leadsT6[1].Title)" -eq 'C:\Users\Ary\Downloads\7z2603-x64.exe')
Check "task6: hunt lead shape preserved (Class/Extra/Ident)" ("$($leadsT6[0].Class)" -eq 'hunt rule: Renamed LOLBin at rest (Sysmon identity mismatch)' -and "$($leadsT6[0].Extra)" -eq 'ATT&CK T1036.003' -and "$($leadsT6[0].Ident)" -eq 'C:\Windows\Temp\svcroot.exe')
$leadsT6r = @(Get-TriageLeads)
Check "task6: ranking deterministic across two calls" ((@($leadsT6r | ForEach-Object { "$($_.Title)" }) -join '|') -eq (@($leadsT6 | ForEach-Object { "$($_.Title)" }) -join '|'))

# task4 (builder side, unchanged semantics): entity dedupe + joins + first-row evidence
$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf2 'Downloaded then executed' 'C:\Users\Ary\Downloads\7z2603-x64.exe' 'T1650' 'downloaded 10/12/2026 7:43:01 AM then executed')
        (Hf2 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'c:\users\ary\downloads\7z2603-x64.exe' 'T1036.003' 'second-rule evidence')
    )
}
$leadEntT4 = @(Get-TriageLeads | Where-Object { "$($_.Anchor)" -eq 'hunt' })
Check "task4 builder: same entity two rules -> ONE lead" ($leadEntT4.Count -eq 1)
Check "task4 builder: lead joins both rules with +" ("$($leadEntT4[0].Class)" -eq 'hunt rule: Downloaded then executed + Renamed LOLBin at rest (Sysmon identity mismatch)')
Check "task4 builder: ATT&CK tags deduped + joined with /" ("$($leadEntT4[0].Extra)" -eq 'ATT&CK T1650/T1036.003')
Check "task4 builder: entity keeps the first row's casing" ("$($leadEntT4[0].Title)" -eq 'C:\Users\Ary\Downloads\7z2603-x64.exe')
Check "task4 builder: evidence from the first row" ("$($leadEntT4[0].Why)" -eq 'downloaded 10/12/2026 7:43:01 AM then executed')
Check "task4 builder: second row's evidence not duplicated" ("$($leadEntT4[0].Why)" -notmatch 'second-rule evidence')

$script:fixtureRows = @{
    'hunt_findings' = @(
        (Hf2 'RuleAlpha' 'C:\a\one.exe' 'T1000' 'ev a')
        (Hf2 'RuleBeta' 'C:\b\two.exe' 'T1001' 'ev b')
    )
}
$leadEntT4b = @(Get-TriageLeads)
Check "task4 builder: two different entities -> two leads" ($leadEntT4b.Count -eq 2)

# task6-2: cap 8, crit-first, stable source priority when corroboration ties at 0
$manyT6 = @{
    'hunt_findings'          = (New-Object System.Collections.Generic.List[object])
    'flash_process_scored'   = (New-Object System.Collections.Generic.List[object])
    'yara_hits'              = (New-Object System.Collections.Generic.List[object])
    'beacon_candidates'      = (New-Object System.Collections.Generic.List[object])
    'ioc_hits_amcache'       = (New-Object System.Collections.Generic.List[object])
    'process_chains'         = (New-Object System.Collections.Generic.List[object])
    'hayabusa_timeline'      = (New-Object System.Collections.Generic.List[object])
}
1..3 | ForEach-Object { $null = $manyT6['flash_process_scored'].Add([pscustomobject]@{ Name = "proc$_"; PID = "$_"; Verdict = 'HIGH'; Score = "$_"; Evidence = 'e'; Path = "C:\p\proc$_.exe"; Signer = '' }) }
1..3 | ForEach-Object { $null = $manyT6['yara_hits'].Add([pscustomobject]@{ File = "C:\y\y$_.exe"; Severity = 'high'; Rule = "R$_"; Description = 'd' }) }
1..3 | ForEach-Object { $null = $manyT6['beacon_candidates'].Add([pscustomobject]@{ Severity = 'high'; Process = "p$_"; RemoteIp = "10.0.0.$_"; Port = '8443'; Events = '10'; SpanMin = '60'; MedianIntervalSec = '30'; Regularity = '0.9' }) }
1..3 | ForEach-Object { $null = $manyT6['hunt_findings'].Add([pscustomobject]@{ Found = 'x'; Rule = "HR$_"; Severity = 'high'; Entity = "C:\h\h$_.exe"; Attck = "T10$_"; Evidence = 'he' }) }
1..3 | ForEach-Object { $null = $manyT6['ioc_hits_amcache'].Add([pscustomobject]@{ Application = "ioc$_.exe"; Indicator = "sha$_"; SourceFile = "C:\i\ioc$_.exe" }) }
1..3 | ForEach-Object { $null = $manyT6['process_chains'].Add([pscustomobject]@{ Parent = "C:\p\par$_.exe"; Child = "C:\c\kid$_.exe"; Evidence = 'ce' }) }
$script:fixtureRows = $manyT6
$leadsCap = @(Get-TriageLeads)
Check "task6: cap 8 enforced (14 crit candidates -> 8 leads)" ($leadsCap.Count -eq 8)
Check "task6: crit source priority on corroboration ties (proc,yara,beacon)" ((@($leadsCap | ForEach-Object { "$($_.Anchor)" }) -join ',') -eq 'processes,processes,processes,yara,yara,yara,beacons,beacons')
1..20 | ForEach-Object { $null = $manyT6['hayabusa_timeline'].Add([pscustomobject]@{ RuleTitle = 'StormRule'; Level = 'medium'; Timestamp = '2026-10-14 12:00:00' }) }
$null = $manyT6['flash_process_scored'].Add([pscustomobject]@{ Name = 'medproc'; PID = '99'; Verdict = 'MEDIUM'; Score = '5'; Evidence = 'e'; Path = 'C:\p\medproc.exe'; Signer = '' })
$leadsCap2 = @(Get-TriageLeads)
Check "task6: med leads stay behind the crit cap (storm capped out)" ($leadsCap2.Count -eq 8 -and @($leadsCap2 | Where-Object { "$($_.Rank)" -eq 'med' }).Count -eq 0)
$medOnly = @{
    'hayabusa_timeline'        = $manyT6['hayabusa_timeline']
    'flash_process_scored'     = @([pscustomobject]@{ Name = 'medproc'; PID = '99'; Verdict = 'MEDIUM'; Score = '5'; Evidence = 'e'; Path = 'C:\p\medproc.exe'; Signer = '' })
    'flash_public_connections' = @([pscustomobject]@{ RemoteAddress = '1.2.3.4'; RemotePort = '4444'; ProcessPath = ''; PID = '5' })
}
$script:fixtureRows = $medOnly
$leadsMed = @(Get-TriageLeads)
Check "task6: med-only case keeps today's relative order (storm, med proc, conn)" ((@($leadsMed | ForEach-Object { "$($_.Anchor)" }) -join ',') -eq 'sigma,processes,network')

# ---- v2.70 task 4 (retargeted v2.71): draft BEST LEADS is a projection of leads.csv ----
$mNar = [regex]::Match($src, "(?s)function Get-CaseNarrative \{.*?\r?\n\}")
if (-not $mNar.Success) { throw 'extract failed: Get-CaseNarrative' }
Invoke-Expression $mNar.Value
$script:Verdict = & $mkVd @()
$script:presentCsvs = @('leads')
$script:fixtureRows = @{ 'leads' = @(& $toCsvRow $leadEntT4[0]) }
$draftT4 = @(Get-CaseNarrative)
$leadT4 = @($draftT4 | Where-Object { $_ -match '^ - \[' })
Check "task4 draft: same entity two rules -> ONE lead" ($leadT4.Count -eq 1)
Check "task4 draft: lead joins both rules with +" ("$($leadT4[0])" -match 'Downloaded then executed \+ Renamed LOLBin at rest \(Sysmon identity mismatch\)')
Check "task4 draft: ATT&CK tags deduped + joined with /" ("$($leadT4[0])" -match '^ - \[T1650/T1036\.003\]')
Check "task4 draft: entity keeps the first row's casing" ("$($leadT4[0])" -match 'on C:\\Users\\Ary\\Downloads\\7z2603-x64\.exe:')
Check "task4 draft: evidence from the first row, locale stamp normalized" ("$($leadT4[0])" -match ': downloaded 2026-10-12 07:43 then executed')
Check "task4 draft: second row's evidence not duplicated" ("$($leadT4[0])" -notmatch 'second-rule evidence')

# task5: draft entities + order == the shared list's hunt rows (exact projected lines)
$script:fixtureRows = @{ 'leads' = @($leadEntT4b | ForEach-Object { & $toCsvRow $_ }) }
$draftT4b2 = @(Get-CaseNarrative)
$leadT4b2 = @($draftT4b2 | Where-Object { $_ -match '^ - \[' })
$expectedT5 = @($script:fixtureRows['leads'] | Where-Object { "$($_.Anchor)" -eq 'hunt' } | Select-Object -First 5 | ForEach-Object { " - [$(("$($_.Extra)") -replace '^ATT&CK ', '')] $(("$($_.Class)") -replace '^hunt rule: ', '') on $($_.Title): $($_.Why)" })
Check "task5: draft BEST LEADS == shared hunt rows (exact lines, order)" ((($leadT4b2 -join "`n")) -eq (($expectedT5 -join "`n")))
Check "task4 draft: two different entities -> two leads" ($leadT4b2.Count -eq 2)

# task5: missing leads.csv -> the draft skips its BEST LEADS block gracefully (no second builder)
$script:presentCsvs = @()
$draftT4skip = @(Get-CaseNarrative)
Check "task5: missing leads.csv -> draft skips its BEST LEADS block gracefully" ((@($draftT4skip | Where-Object { $_ -match 'BEST LEADS' }).Count -eq 0) -and (@($draftT4skip | Where-Object { $_ -match '^ - \[' }).Count -eq 0))

# task4-3: locale stamp inside a signal detail normalizes to yyyy-MM-dd HH:mm
$script:Verdict = & $mkVd @([pscustomobject]@{ Signal = 'Hunt techniques (1 fired)'; Weight = 3; Count = 1; Detail = 'first seen 10/12/2026 7:43:01 AM on HOST' })
$draftT4c = @(Get-CaseNarrative)
Check "task4 draft: signal detail locale stamp normalizes" (@($draftT4c | Where-Object { $_ -match 'first seen 2026-10-12 07:43 on HOST' }).Count -eq 1)

# task4-4: text the regex matches but DateTime cannot parse stays verbatim (no mangle) - now
# flowing through the leads.csv projection dialect
$script:Verdict = & $mkVd @()
$script:presentCsvs = @('leads')
$script:fixtureRows = @{ 'leads' = @([pscustomobject]@{ Rank = 'crit'; Title = 'C:\x\odd.exe'; Class = 'hunt rule: RuleOdd'; Why = 'seen 99/99/2026 9:99:99 AM and not-a-date'; Ident = 'C:\x\odd.exe'; Extra = 'ATT&CK T9'; Anchor = 'hunt'; Rule = '' }) }
$draftT4d = @(Get-CaseNarrative)
$leadT4d = @($draftT4d | Where-Object { $_ -match '^ - \[' })
Check "task4 draft: unparseable timestamp text stays verbatim" ($leadT4d.Count -eq 1 -and "$($leadT4d[0])" -match 'seen 99/99/2026 9:99:99 AM and not-a-date')

# ---- v2.71 task 5 statics: regen writes leads.csv; it is a report artifact, never evidence ----
$mReT5 = [regex]::Match($src, "(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}")
Check "task5 static: regen calls Get-TriageLeads" ($mReT5.Success -and $mReT5.Value.Contains('Get-TriageLeads'))
Check "task5 static: leads export uses the derived path" ($mReT5.Success -and $mReT5.Value.Contains("`$leadP = Get-CaseCsvFullPath 'leads'") -and $mReT5.Value.Contains('Export-Csv -LiteralPath $leadP'))
Check "task5 static: leads built before the case draft write" ($mReT5.Success -and $mReT5.Value.IndexOf('Get-TriageLeads') -lt $mReT5.Value.IndexOf('Get-CaseNarrative'))
Check "task5 static: leads built before the report render" ($mReT5.Success -and $mReT5.Value.IndexOf('Get-TriageLeads') -lt $mReT5.Value.IndexOf('New-HtmlReport | Out-Null'))
Check "task5 static: leads routed to csv\derived (sortment)" ($src -match [regex]::Escape("'leads' = 'derived'"))
$mStT5 = [regex]::Match($src, "(?s)function New-SuperTimeline \{.*?\r?\n\}")
Check "task5 static: supertimeline weave never weaves leads.csv" ($mStT5.Success -and $mStT5.Value -notmatch "'leads'")
Check "task5 static: report reads persisted leads, falls back inline" (($src -match [regex]::Escape("if (Test-CaseCsv 'leads') { `$leads = @(Import-CaseCsv 'leads') }")) -and ($src -match [regex]::Escape("else { `$leads = @(Get-TriageLeads) }")))
Check "task5 static: focus scan excludes the leads report artifact" ($src -match [regex]::Escape('^(focus_|process_pivot|supertimeline|parse_needed|leads)'))

# ---- render: weight-0 signals leave the contributing list (Release 1 task 2) ----
# Full-report harness (test_v266/test_v268 pattern): the real New-HtmlReport renders a
# hand-built fixture verdict in a temp case dir; assertions run on the banner HTML.
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
foreach ($n2 in @('ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-IpCloudClass', 'Get-TriageLeads', 'Import-CaseCsv', 'New-VtLink', 'Split-TagList', 'Get-TacticLabel', 'New-HtmlReport')) {
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
Check "render: contributing list keeps the w2 row unchanged (v2.77: plain-language rank label)" ($contribV270.Contains("<span class='med'>corroborating</span> <a href='#drivers' style='color:inherit'>Known-malicious driver on disk (LOLDrivers) x1"))
Check "render: w0 row under Noted keeps info badge + evidence link intact (v2.77: 'noted' label)" ($notedRow.Contains("<span class='info'>noted</span> <a href='#sigma' style='color:inherit'>Sigma detection - high x5"))

# zero w0 signals -> the whole Noted group stays off; contributing list still renders w3 + w1
$script:Verdict = & $mkV @(
    [pscustomobject]@{ Signal = 'IOC hit - live system'; Weight = 3; Count = 2; Detail = '1.2.3.4' }
    [pscustomobject]@{ Signal = 'Process anomaly verdict MEDIUM'; Weight = 1; Count = 1; Detail = 'worth review' }
)
$null = New-HtmlReport
$htmlV270b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "render: zero w0 signals -> no Noted group at all" (-not $htmlV270b.Contains('<b>Noted</b>'))
Check "render: zero w0 -> contributing list still renders its w3 + w1 rows (v2.77: rank labels)" (($htmlV270b.Contains("<span class='high'>strong</span>")) -and ($htmlV270b.Contains("<span class='info'>context</span>")))

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
Check "task4 render: no leads.csv -> inline fallback still rendered the cards" (-not (Test-CaseCsv 'leads'))

# restore the empty fixture so the file's remaining scenarios see the original shape
"# no entries" | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8

# ---- v2.71 task 5 render/export: regen's export path mirrored, report + draft on one list ----
# two-entity hunt fixture + corroboration counts -> builder ranks two.exe (2 categories) first,
# the export persists that order, the report renders it verbatim and the draft projects it.
@"
"Found","Rule","Severity","Entity","Attck","Evidence"
"2026-10-14 12:00:00","RuleAlpha","high","C:\a\one.exe","T1000","ev a"
"2026-10-14 12:05:00","RuleBeta","high","C:\b\two.exe","T1001","ev b"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'hunt_findings.csv') -Encoding UTF8
@"
"Path","Categories"
"c:\a\one.exe","hunt_findings"
"c:\b\two.exe","hunt_findings;processes"
"@ | Set-Content -LiteralPath (Join-Path $rcsv 'entities_binaries.csv') -Encoding UTF8
$leadsExp = @(Get-TriageLeads)
Check "task5 export: builder ranks the 2-corroboration entity first" ($leadsExp.Count -eq 2 -and "$($leadsExp[0].Title)" -eq 'C:\b\two.exe')
$leadsExp | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
Check "task5 export: leads.csv lands in csv\derived and Test-CaseCsv finds it" ((Test-Path -LiteralPath (Join-Path $rcsv 'derived\leads.csv')) -and (Test-CaseCsv 'leads'))
$leadsRb = @(Import-Csv -LiteralPath (Join-Path $rcsv 'derived\leads.csv'))
Check "task5 export: persisted rows keep the ranked order + uniform 8 columns" ((@($leadsRb | ForEach-Object { "$($_.Title)" }) -join '|') -eq (@($leadsExp | ForEach-Object { "$($_.Title)" }) -join '|') -and ((@($leadsRb[0].PSObject.Properties.Name) -join ',') -eq 'Rank,Title,Class,Why,Ident,Extra,Anchor,Rule'))

# report renders the PERSISTED order (no re-rank at render time)
$null = New-HtmlReport
$htmlT5 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task5 render: report card #1 == persisted rank #1 (2-corroboration entity)" ($htmlT5.Contains("leadtitle'>1. C:\b\two.exe <span"))
Check "task5 render: report card #2 == persisted rank #2" ($htmlT5.Contains("leadtitle'>2. C:\a\one.exe <span"))

# draft reads the SAME persisted rows -> same entities, same order, hunt rows only
$draftT5 = @(Get-CaseNarrative)
$draftLeads5 = @($draftT5 | Where-Object { $_ -match '^ - \[' })
Check "task5: draft BEST LEADS == report lead cards (same list, same order)" ($draftLeads5.Count -eq 2 -and "$($draftLeads5[0])" -match '^ - \[T1001\] RuleBeta on C:\\b\\two\.exe: ev b' -and "$($draftLeads5[1])" -match 'RuleAlpha on C:\\a\\one\.exe: ')

# a med lead rides along in leads.csv: the report shows it, the draft (hunt-only) does not
$leadsExp2 = New-Object System.Collections.Generic.List[object]
foreach ($r in $leadsExp) { $null = $leadsExp2.Add($r) }
$null = $leadsExp2.Add([pscustomobject]@{ Rank = 'med'; Title = 'Sigma storm: 40 detection rows'; Class = 'review: sigma volume spike'; Why = 'review sample'; Ident = ''; Extra = ''; Anchor = 'sigma'; Rule = 'SomeRule' })
$leadsExp2.ToArray() | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$htmlT5b = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task5 render: med lead from leads.csv shows in the report (card #3)" ($htmlT5b.Contains("leadtitle'>3. Sigma storm: 40 detection rows"))
$draftT5b = @(Get-CaseNarrative)
$draftLeads5b = @($draftT5b | Where-Object { $_ -match '^ - \[' })
Check "task5: draft projects hunt-source rows only (med lead stays report-side)" ($draftLeads5b.Count -eq 2)

# cleanup: back to the empty shape
"# no entries" | Set-Content -LiteralPath (Join-Path $rcsv 'entities_binaries.csv') -Encoding UTF8

# ---- v2.71 task 8: lead cards gain ONE static Upgrade/Dismiss line after the Why ----
# Map keyed on the Class prefix the builder writes (leads.csv's Class column): mapped classes
# render 'Upgrade if: <x> - Dismiss if: <y>'; IOC hash, review:* and unmapped classes render none.
# Scenarios ride the render harness above (persisted leads.csv -> real render).
$upL1 = [pscustomobject]@{ Rank = 'crit'; Title = 'C:\Windows\Temp\svcroot.exe'; Class = 'hunt rule: Renamed LOLBin at rest (Sysmon identity mismatch)'; Why = 'identity mismatch'; Ident = 'C:\Windows\Temp\svcroot.exe'; Extra = 'ATT&CK T1036.003'; Anchor = 'hunt'; Rule = '' }
$upL2 = [pscustomobject]@{ Rank = 'crit'; Title = 'C:\Users\Ary\Downloads\setup.exe'; Class = 'hunt rule: Downloaded then executed'; Why = 'downloaded then executed'; Ident = 'C:\Users\Ary\Downloads\setup.exe'; Extra = 'ATT&CK T1105'; Anchor = 'hunt'; Rule = '' }
@($upL1, $upL2) | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$upHtml = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task8: renamed-LOLBin lead renders its exact mapped Upgrade/Dismiss text" ($upHtml.Contains('Upgrade if: the embedded identity is a known-malicious tool or the path is user-writable - Dismiss if: the path is a known test/canary or software-updater staging dir'))
Check "task8: download-exec lead renders its exact mapped text" ($upHtml.Contains('Upgrade if: the download came from a non-cloud unknown host or re-appears in persistence - Dismiss if: a signed installer from a known vendor path with plausible download history'))
Check "task8: exactly one line per mapped card (2 cards -> 2 lines)" (@([regex]::Matches($upHtml, 'Upgrade if: ')).Count -eq 2)

$upL3 = [pscustomobject]@{ Rank = 'crit'; Title = 'iocapp.exe'; Class = 'IOC hash match (known-bad binary ran on this host)'; Why = 'SHA1 abc matched the IOC feed'; Ident = 'C:\i\ioc.exe'; Extra = ''; Anchor = 'ioc'; Rule = '' }
$upL4 = [pscustomobject]@{ Rank = 'med'; Title = 'Sigma storm: 40 detection rows'; Class = 'review: sigma volume spike'; Why = 'review sample'; Ident = ''; Extra = ''; Anchor = 'sigma'; Rule = 'SomeRule' }
$upL5 = [pscustomobject]@{ Rank = 'crit'; Title = 'y5.exe'; Class = 'YARA high: RuleY'; Why = 'yara description'; Ident = 'C:\y\y5.exe'; Extra = ''; Anchor = 'yara'; Rule = '' }
@($upL3, $upL4, $upL5) | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$upHtml2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task8: IOC hash lead renders NO upgrade line (near-certain already)" (@([regex]::Matches($upHtml2, 'Upgrade if: ')).Count -eq 0)
Check "task8: review: lead renders NO upgrade line (explicitly not a verdict)" (@([regex]::Matches($upHtml2, 'Upgrade if: ')).Count -eq 0)
Check "task8: unmapped class (YARA) renders no line AND no crash (all 3 cards still render)" ((@([regex]::Matches($upHtml2, "leadtitle'>")).Count -eq 3) -and ($upHtml2.Contains("leadtitle'>1. iocapp.exe <span")))

Check "task8 static: the line routes through ConvertTo-HtmlEsc like sibling card text" ($src -match [regex]::Escape("<div style='margin-top:4px' class='meta'>`$(ConvertTo-HtmlEsc `$up2)</div>"))

# hostile Class text: still matches the map prefix, card text escapes, the static line renders once
$upL6 = [pscustomobject]@{ Rank = 'crit'; Title = 'C:\x\img.exe'; Class = 'hunt rule: Renamed LOLBin <img src=x onerror=alert(1)>'; Why = 'ev'; Ident = 'C:\x\img.exe'; Extra = ''; Anchor = 'hunt'; Rule = '' }
@($upL6) | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$upHtml3 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task8: hostile Class escaped, mapped line still renders exactly once" ((@([regex]::Matches($upHtml3, [regex]::Escape('Upgrade if: the embedded identity is a known-malicious tool'))).Count -eq 1) -and (-not $upHtml3.Contains('<img src=x')) -and $upHtml3.Contains('&lt;img src=x'))

# fix: the config-change guidance is for the Defender-tamper family only. R30's hollowing rule
# (no agent makes an in-memory image swap) must render NO line; R14's DISABLED leg must render it.
$upL7 = [pscustomobject]@{ Rank = 'high'; Title = 'C:\Windows\System32\svchost.exe'; Class = 'hunt rule: Process image tampering (hollowing)'; Why = 'Sysmon EID 25 image swap'; Ident = 'C:\Windows\System32\svchost.exe'; Extra = 'ATT&CK T1055.012'; Anchor = 'hunt'; Rule = 'Process image tampering (hollowing)' }
@($upL7) | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$upHtml4 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task8 fix: R30 hollowing lead renders NO config-change upgrade line (incoherent guidance removed)" ((@([regex]::Matches($upHtml4, 'Upgrade if: ')).Count -eq 0) -and (@([regex]::Matches($upHtml4, "leadtitle'>")).Count -eq 1))

$upL8 = [pscustomobject]@{ Rank = 'high'; Title = 'Defender real-time protection DISABLED'; Class = 'hunt rule: Defender real-time protection DISABLED'; Why = '2 disable event(s) - tamper or manual change'; Ident = ''; Extra = 'ATT&CK T1562.001'; Anchor = 'hunt'; Rule = 'Defender real-time protection DISABLED' }
@($upL8) | Export-Csv -LiteralPath (Get-CaseCsvFullPath 'leads') -NoTypeInformation -Encoding UTF8
$null = New-HtmlReport
$upHtml5 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "task8 fix: R14 DISABLED lead renders the exact mapped config-change line" ((@([regex]::Matches($upHtml5, [regex]::Escape('Upgrade if: no installed software plausibly explains the change - Dismiss if: a management/AV agent made a documented configuration change'))).Count -eq 1) -and $upHtml5.Contains("hunt rule: Defender real-time protection DISABLED</span>"))

Remove-Item -LiteralPath (Join-Path $rcsv 'derived\leads.csv') -Force -ErrorAction SilentlyContinue

# ---- task 9 (focus embed cap): interesting-first instance embed + 15-ordinary cap ----
# Rides the render case above: write focus_instances_detail.json per scenario, render the real
# report, assert on the Focus section HTML. Presentation only - the JSON on disk must stay
# byte-identical through every render (the focus engine keeps all instances in its own outputs).
'fixture focus report body' | Set-Content -LiteralPath (Join-Path $rcase 'focus\focus_report.html') -Encoding UTF8
function New-T9Rows([int]$n, [string]$img) {
    $l = New-Object System.Collections.Generic.List[object]
    1..$n | ForEach-Object { $null = $l.Add([pscustomobject]@{ Time = "2026-10-14 10:$('{0:d2}' -f ($_ % 60))"; Image = $img; ProcessId = "$_"; User = 'u' }) }
    return $l.ToArray()
}
function New-T9Inst([string]$pid9, [hashtable]$secs) {
    $o = [ordered]@{ Pid = $pid9; Guid = "g-$pid9"; Started = '2026-10-14 10:00'; Image = "C:\mal\$pid9.exe"; Parent = ''; User = 'u'; Lineage = @(); Respawn = ''
        Children = @(); CrtIn = @(); CrtOut = @(); Pipes = @(); Tamper = @(); RawDisk = @(); Exec = @(); Persist = @(); Beacon = @(); Net = @(); Dns = @(); Dll = @(); Reg = @(); File = @(); FileCreate = @(); FileDelete = @() }
    foreach ($k in $secs.Keys) { $o[$k] = $secs[$k] }
    return [pscustomobject]$o
}
function Invoke-T9Scenario {
    param($Insts)
    $detailT9 = [pscustomobject]@{ Indicator = 'x.exe'; GraphSvg = "<svg id='g9'></svg>"; CorrNotes = @(); Instances = @($Insts) }
    $jsonT9 = Join-Path $rcase 'focus\focus_instances_detail.json'
    (ConvertTo-Json -InputObject $detailT9 -Depth 8) | Set-Content -LiteralPath $jsonT9 -Encoding UTF8
    $beforeT9 = Get-Content -LiteralPath $jsonT9 -Raw
    $null = New-HtmlReport
    $htmlT9 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
    return @{ Html = $htmlT9; JsonUnchanged = ("$beforeT9" -ceq (Get-Content -LiteralPath $jsonT9 -Raw)) }
}

# s1: 20 ordinary (Children rows 1..20) + 3 interesting -> 18 embedded: interesting first
# (JSON order), then ordinary by total evidence rows desc (o20..o06); pointer line present
$s1i = New-Object System.Collections.Generic.List[object]
$null = $s1i.Add((New-T9Inst 'i01' @{ CrtIn = (New-T9Rows 1 'C:\inj.exe') }))
$null = $s1i.Add((New-T9Inst 'i02' @{ Beacon = (New-T9Rows 2 'C2') }))
$null = $s1i.Add((New-T9Inst 'i03' @{ Persist = (New-T9Rows 1 'run key') }))
1..20 | ForEach-Object { $null = $s1i.Add((New-T9Inst ('o{0:d2}' -f $_) @{ Children = (New-T9Rows $_ 'C:\c.exe') })) }
$r1 = Invoke-T9Scenario $s1i.ToArray()
Check "task9 s1: 20 ordinary + 3 interesting -> exactly 18 embedded" (([regex]::Matches($r1.Html, 'everything it did</summary>')).Count -eq 18)
Check "task9 s1: pointer line reads 'showing 18 of 23 instances' with the focus_report.html link" ($r1.Html.Contains("showing 18 of 23 instances - everything else: <a href='focus/focus_report.html'>focus\focus_report.html</a>"))
$pos1 = @('g-i01', 'g-i02', 'g-i03', 'g-o20', 'g-o19', 'g-o06') | ForEach-Object { $r1.Html.IndexOf("$_ ") }
Check "task9 s1: order - 3 interesting first (JSON order), then ordinary rows-desc (o20,o19..o06)" (($pos1 | Where-Object { $_ -lt 0 }).Count -eq 0 -and $pos1[0] -lt $pos1[1] -and $pos1[1] -lt $pos1[2] -and $pos1[2] -lt $pos1[3] -and $pos1[3] -lt $pos1[4] -and $pos1[4] -lt $pos1[5])
Check "task9 s1: o01..o05 (smallest ordinary) are the skipped tail" (-not $r1.Html.Contains('g-o05'))
Check "task9 s1: focus_instances_detail.json byte-identical after render" $r1.JsonUnchanged
Check "task9 s1: sticky mini-key still renders above the embedded instances" (($r1.Html.IndexOf("class='mkey'") -ge 0) -and ($r1.Html.IndexOf("class='mkey'") -lt $pos1[0]))

# s2: a 1-row interesting instance still embeds ahead of a 50-row ordinary one
$r2 = Invoke-T9Scenario @((New-T9Inst 'x01' @{ CrtIn = (New-T9Rows 1 'C:\inj.exe') }), (New-T9Inst 'x02' @{ Children = (New-T9Rows 50 'C:\c.exe') }))
Check "task9 s2: 1-row interesting embeds ahead of the 50-row ordinary" (($r2.Html.IndexOf('g-x01 ') -ge 0) -and ($r2.Html.IndexOf('g-x01 ') -lt $r2.Html.IndexOf('g-x02 ')))
Check "task9 s2: both embedded, nothing skipped -> no pointer line" (([regex]::Matches($r2.Html, 'everything it did</summary>')).Count -eq 2 -and (-not $r2.Html.Contains('instances - everything else')))
Check "task9 s2: per-instance 25-row truncation note intact on the 50-row section" ($r2.Html.Contains("showing 25 of 50 - full table: <a href='focus/focus_report.html'>"))
Check "task9 s2: focus_instances_detail.json byte-identical after render" $r2.JsonUnchanged

# s3: all-interesting dossier -> everything embedded, no pointer line
$r3 = Invoke-T9Scenario @(
    (New-T9Inst 'y01' @{ Tamper = (New-T9Rows 1 'T') }),
    (New-T9Inst 'y02' @{ FileCreate = (New-T9Rows 1 'F') }),
    (New-T9Inst 'y03' @{ FileDelete = (New-T9Rows 2 'D') })
)
Check "task9 s3: all-interesting (3, 0 ordinary) -> all 3 embedded" (([regex]::Matches($r3.Html, 'everything it did</summary>')).Count -eq 3)
Check "task9 s3: no pointer line" (-not $r3.Html.Contains('instances - everything else'))
Check "task9 s3: focus_instances_detail.json byte-identical after render" $r3.JsonUnchanged

# s4: 15 ordinary + 1 interesting = small-dossier behavior (everything embedded, no pointer)
$s4i = New-Object System.Collections.Generic.List[object]
$null = $s4i.Add((New-T9Inst 'z01' @{ Beacon = (New-T9Rows 1 'C2') }))
1..15 | ForEach-Object { $null = $s4i.Add((New-T9Inst ('w{0:d2}' -f $_) @{ Children = (New-T9Rows $_ 'C:\c.exe') })) }
$r4 = Invoke-T9Scenario $s4i.ToArray()
Check "task9 s4: 16 total (<=15 ordinary) -> everything embedded" (([regex]::Matches($r4.Html, 'everything it did</summary>')).Count -eq 16)
Check "task9 s4: no pointer line (today's behavior for small dossiers)" (-not $r4.Html.Contains('instances - everything else'))
Check "task9 s4: focus_instances_detail.json byte-identical after render" $r4.JsonUnchanged

Remove-Item -LiteralPath (Join-Path $rcase 'focus\focus_instances_detail.json'), (Join-Path $rcase 'focus\focus_report.html') -Force -ErrorAction SilentlyContinue

# ---- task 10: sparkline + evidence window clamp (display window = LogHours clamped [30d, 90d]) ----
# Stray decade-old amcache/MFT stamps used to spend the sparkline's bars and stretch the banner's
# evidence window into a 20-year span (real WIN11 case: 2006-11-01 -> 2026-10-16). Both now render
# only the case's analysis window (LogHours days clamped to [30, 90], 90 when 0/unset); events
# older than the cutoff collapse into one '+ N older event(s) before <cutoff> (stray timestamps)'
# note. Display only - supertimeline.csv / -Mode Timeline / the newest-150 table keep every event.
$now10 = Get-Date
$cutKey30 = $now10.Date.AddDays(-30).ToString('yyyy-MM-dd')
$cutKey90 = $now10.Date.AddDays(-90).ToString('yyyy-MM-dd')
$dayA10 = $now10.AddDays(-5); $dayB10 = $now10.AddDays(-3)
$dayM40 = $now10.AddDays(-40); $dayO100 = $now10.AddDays(-100)
$d2006 = [datetime]'2006-11-01'; $d2020 = [datetime]'2020-06-15'
$script:t10i = 0
function New-T10Row([datetime]$day, [int]$n) {
    $l = New-Object System.Collections.Generic.List[string]
    1..$n | ForEach-Object { $script:t10i++; $null = $l.Add(('"{0:yyyy-MM-dd} {1:d2}:10:00","fixture","test","u","e","ev{2}"' -f $day, $_, $script:t10i)) }
    return $l.ToArray()
}
function Invoke-T10Render {
    param([string[]]$Rows)
    @('"Timestamp","Source","Type","Actor","Entity","Detail"') + $Rows | Set-Content -LiteralPath (Join-Path $rcsv 'supertimeline.csv') -Encoding UTF8
    $null = New-HtmlReport
    $h10 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
    return @{
        Ev = [regex]::Match($h10, "(?s)<b>Evidence window:</b>.*?</p>").Value
        Sp = [regex]::Match($h10, "(?s)<b>Activity per day</b>.*?</svg></div>").Value
    }
}

# sA: strays (2006 x9 = the GLOBAL busiest day, 2020 x2) + a busy 2-day cluster inside 30 days
$rA = Invoke-T10Render (@(New-T10Row $dayA10 4) + @(New-T10Row $dayB10 5) + @(New-T10Row $d2006 9) + @(New-T10Row $d2020 2))
$kA10 = $dayA10.ToString('yyyy-MM-dd'); $kB10 = $dayB10.ToString('yyyy-MM-dd')
Check "task10 sA: sparkline bars only for in-window days (2006/2020 titles gone)" ((-not $rA.Sp.Contains('<title>2006-11-01')) -and (-not $rA.Sp.Contains('<title>2020-06-15')) -and $rA.Sp.Contains("<title>$kA10 : 4 event(s)</title>") -and $rA.Sp.Contains("<title>$kB10 : 5 event(s)</title>"))
Check "task10 sA: caption note = true count + cutoff date" ($rA.Sp.Contains("showing the last 2 day(s) with activity) + 11 older event(s) before $cutKey30 (stray timestamps)</span>"))
Check "task10 sA: busiest pick = busiest INSIDE the window (not the 9-event 2006 day)" (($rA.Sp.Contains("(busiest: $kB10 with 5 events")) -and (-not $rA.Sp.Contains('busiest: 2006-11-01')))
Check "task10 sA: evidence window shows the clamped range (2006 first stamp gone)" ($rA.Ev.Contains("<b>Evidence window:</b> $kA10 01:10 UTC to $kB10 05:10 UTC (20 events)"))
Check "task10 sA: evidence window carries the same note after the busiest day" ($rA.Ev.Contains("busiest day $kB10 (5 events). + 11 older event(s) before $cutKey30 (stray timestamps). Full chronology:"))
Check "task10 sA: no stray stamp anywhere in the evidence window line" ((-not $rA.Ev.Contains('2006-11-01')) -and (-not $rA.Ev.Contains('2020-06-15')))

# sB: everything inside the window -> byte-identical to today (no note, no clamp artifacts)
$rB = Invoke-T10Render (@(New-T10Row $dayA10 4) + @(New-T10Row $dayB10 5))
Check "task10 sB: caption byte-identical when nothing predates the cutoff" ($rB.Sp.Contains("(busiest: $kB10 with 5 events - hover a bar for its count; showing the last 2 day(s) with activity)</span>"))
Check "task10 sB: no clamp artifacts in the sparkline card" (($rB.Sp -notmatch 'stray timestamps') -and ($rB.Sp -notmatch 'older event'))
Check "task10 sB: evidence window line byte-identical to today" ($rB.Ev.Contains("<b>Evidence window:</b> $kA10 01:10 UTC to $kB10 05:10 UTC (9 events) - busiest day $kB10 (5 events). Full chronology: <a href='#timeline'>master timeline</a>"))

# sC: the clamp follows LogHours (168 -> 30d floor; 4320/0 -> the 90d ceiling)
$rC90 = Invoke-T10Render (@(New-T10Row $dayA10 1) + @(New-T10Row $dayM40 1) + @(New-T10Row $dayO100 1))
$kM40 = $dayM40.ToString('yyyy-MM-dd'); $kO100 = $dayO100.ToString('yyyy-MM-dd')
Check "task10 sC: LogHours 168 -> 30d window clamps the 40d + 100d events" (($rC90.Ev.Contains("+ 2 older event(s) before $cutKey30 (stray timestamps)")) -and ($rC90.Ev.Contains("<b>Evidence window:</b> $kA10 01:10 UTC to $kA10 01:10 UTC (3 events)")))
$LogHours = 4320
$rC4320 = Invoke-T10Render (@(New-T10Row $dayA10 1) + @(New-T10Row $dayM40 1) + @(New-T10Row $dayO100 1))
$LogHours = 0
$rC0 = Invoke-T10Render (@(New-T10Row $dayA10 1) + @(New-T10Row $dayM40 1) + @(New-T10Row $dayO100 1))
$LogHours = 168
Check "task10 sC: LogHours 4320 -> 90d window keeps the 40d event, clamps the 100d one" (($rC4320.Sp.Contains("+ 1 older event(s) before $cutKey90 (stray timestamps)")) -and (-not $rC4320.Sp.Contains("<title>$kO100")) -and $rC4320.Sp.Contains("<title>$kM40"))
Check "task10 sC: LogHours 0 -> 90d window (same cutoff as 4320)" ($rC0.Ev.Contains("+ 1 older event(s) before $cutKey90 (stray timestamps)"))

# sD: degenerate - every event predates the window -> full unclamped range, no bogus note
$rD = Invoke-T10Render (@(New-T10Row $d2006 2) + @(New-T10Row $d2020 1))
Check "task10 sD: all events older than the window -> full range, no clamp artifacts" (($rD.Ev.Contains("<b>Evidence window:</b> 2006-11-01 01:10 UTC to 2020-06-15 01:10 UTC (3 events)")) -and ($rD.Ev -notmatch 'older event'))
Check "task10 sD: sparkline skips cleanly (zero in-window days)" ($rD.Sp -eq '')

# ---- task 11: newest-150 collector self-noise suppression ----
# The collector runs last before export, so the plain newest-150 pick led with Ophira's own
# wevtutil evtx-export commands (real WIN11 case). The render now skips rows whose Detail/Entity
# carry the case's raw\evtx\*.evtx export path / the case folder name, or a kit path (the
# Test-SigmaSelfNoise vocabulary, no PID logic), backfilling with the next newest events; the
# caption states the true post-suppression numbers. Display only - supertimeline.csv, the
# sparkline, the evidence window and -Mode Timeline keep every event. On by default, no toggle.
$script:t11i = 0
function New-T11Row([string]$detail, [int]$agoMin) {
    $ts = (Get-Date).AddMinutes(-$agoMin).ToString('yyyy-MM-dd HH:mm')
    return ('"{0}:00","fixture","test","u","e","{1}"' -f $ts, $detail)
}
function Invoke-T11Render {
    param([string[]]$Rows)
    @('"Timestamp","Source","Type","Actor","Entity","Detail"') + $Rows | Set-Content -LiteralPath (Join-Path $rcsv 'supertimeline.csv') -Encoding UTF8
    $before11 = Get-Content -LiteralPath (Join-Path $rcsv 'supertimeline.csv') -Raw
    $null = New-HtmlReport
    $h11 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
    return @{
        Html = $h11
        Cap = [regex]::Match($h11, "<div class='meta'>Newest [^<]*</div>").Value
        Tl = [regex]::Match($h11, "(?s)<table id='tlt'>.*?</table>").Value
        CsvUnchanged = ("$before11" -ceq (Get-Content -LiteralPath (Join-Path $rcsv 'supertimeline.csv') -Raw))
    }
}

# s1: 2 wevtutil-epl-case-evtx rows + 150 normal -> 150 rows shown, both noise rows gone,
# honest note (the 150 shown includes the 2 backfilled replacements)
$s1rows = New-Object System.Collections.Generic.List[string]
$null = $s1rows.Add((New-T11Row "wevtutil.exe epl Microsoft-Windows-PowerShell/Operational $rcase\raw\evtx\PowerShell_Operational.evtx" 1))
$null = $s1rows.Add((New-T11Row "wevtutil.exe epl Security $rcase\raw\evtx\Security.evtx" 2))
1..150 | ForEach-Object { $null = $s1rows.Add((New-T11Row "normal $_" ($_ + 2))) }
$r11a = Invoke-T11Render $s1rows.ToArray()
Check "task11 s1: 150 rows rendered (2 suppressed, backfilled from the older events)" (([regex]::Matches($r11a.Tl, '<tr><td>')).Count -eq 150)
Check "task11 s1: neither wevtutil case row present" ((-not $r11a.Tl.Contains('PowerShell_Operational.evtx')) -and (-not $r11a.Tl.Contains('wevtutil')))
Check "task11 s1: caption = true post-suppression numbers + note" ($r11a.Cap -eq "<div class='meta'>Newest 150 of 152 events (collector self-noise suppressed: 2 rows)</div>")
Check "task11 s1: the backfilled tail (normal 1/normal 150) is in the table" (($r11a.Tl.Contains('normal 1<')) -and ($r11a.Tl.Contains('normal 150<')))
Check "task11 s1: supertimeline.csv byte-identical through the render" $r11a.CsvUnchanged

# s2: a wevtutil row targeting a DIFFERENT (non-case) path stays in the table
$r11b = Invoke-T11Render @(
    (New-T11Row "wevtutil.exe epl Microsoft-Windows-PowerShell/Operational $rcase\raw\evtx\PowerShell_Operational.evtx" 1)
    (New-T11Row "wevtutil.exe epl Security E:\corp-logs\Security.evtx" 2)
    (New-T11Row 'normal row' 3)
)
Check "task11 s2: case-evtx wevtutil row suppressed" (-not $r11b.Tl.Contains('PowerShell_Operational.evtx'))
Check "task11 s2: foreign-path wevtutil row STAYS" ($r11b.Tl.Contains('E:\corp-logs\Security.evtx'))
Check "task11 s2: caption counts only the case row" ($r11b.Cap -eq "<div class='meta'>Newest 2 of 3 events (collector self-noise suppressed: 1 rows)</div>")

# s3: suppression leaves fewer than 150 candidates -> show what exists, honest caption (no padding)
$s3rows = New-Object System.Collections.Generic.List[string]
1..5 | ForEach-Object { $null = $s3rows.Add((New-T11Row "wevtutil.exe epl System $rcase\raw\evtx\System.evtx" $_)) }
1..3 | ForEach-Object { $null = $s3rows.Add((New-T11Row "keep $_" ($_ + 5))) }
$r11c = Invoke-T11Render $s3rows.ToArray()
Check "task11 s3: only the 3 unsuppressed rows render (no padding)" (([regex]::Matches($r11c.Tl, '<tr><td>')).Count -eq 3)
Check "task11 s3: caption shows the honest 3-of-8 numbers" ($r11c.Cap -eq "<div class='meta'>Newest 3 of 8 events (collector self-noise suppressed: 5 rows)</div>")
Check "task11 s3: no wevtutil row leaked" (-not $r11c.Tl.Contains('wevtutil'))

# s4: no self-noise rows -> caption byte-identical to today, no note anywhere
$s4rows = New-Object System.Collections.Generic.List[string]
1..150 | ForEach-Object { $null = $s4rows.Add((New-T11Row "plain $_" $_)) }
$r11d = Invoke-T11Render $s4rows.ToArray()
Check "task11 s4: caption byte-identical to today (no note)" ($r11d.Cap -eq "<div class='meta'>Newest 150 of 150 events, newest first:</div>")
Check "task11 s4: no self-noise note anywhere in the report" (-not $r11d.Html.Contains('collector self-noise'))
Check "task11 s4: all 150 rows render" (([regex]::Matches($r11d.Tl, '<tr><td>')).Count -eq 150)

# s5: kit-path rows (Test-SigmaSelfNoise vocabulary) suppress only while $script:KitPaths is set -
# the analyst-side render (Mode Parse, KitPaths unset) keeps them and relies on the case matchers
$kitRow11 = New-T11Row 'powershell.exe -File C:\OphiraKit\tools\collector.ps1 -Case x' 1
$base11 = @((New-T11Row 'old row' 2), (New-T11Row 'older row' 3))
$script:KitPaths = @('C:\OphiraKit')
$r11e = Invoke-T11Render (@($kitRow11) + $base11)
Check "task11 s5: kit-path row suppressed while KitPaths is set" (([regex]::Matches($r11e.Tl, '<tr><td>')).Count -eq 2 -and -not $r11e.Tl.Contains('OphiraKit'))
$script:KitPaths = $null
$r11f = Invoke-T11Render (@($kitRow11) + $base11)
Check "task11 s5: KitPaths unset (analyst side) -> kit row stays, no note" (([regex]::Matches($r11f.Tl, '<tr><td>')).Count -eq 3 -and $r11f.Tl.Contains('OphiraKit') -and (-not $r11f.Html.Contains('collector self-noise')))

# restore the empty fixture for anything that reads this case afterwards
"# no entries" | Set-Content -LiteralPath (Join-Path $rcsv 'supertimeline.csv') -Encoding UTF8

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

# ---- v2.71 task 7: auto-focus seeds the FULL hunt path (leaf only as zero-hit fallback) ----
# Real WIN11 repro: the hunt entity C:\Windows\Temp\needle-am-hsbxrtoq\svchost.exe was stripped
# to its leaf -> the core seeded the OS process name and buried the ONE malicious instance under
# 400 legit svchosts. Now the Entity goes to the focus core AS-IS (its own seed classification
# handles paths); the leaf re-seeds ONCE only when the path run wrote no dossier (zero hits).
# Harness: the full regen is EXECUTED against a fixture case (test_v215 PART 2 pattern) - the
# real Invoke-FocusCore scans the CSVs on disk, everything else stays on the in-memory stubs.
$mRe7 = [regex]::Match($src, "(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}")
$mFc7 = [regex]::Match($src, "(?s)function Invoke-FocusCore \{.*?\r?\n\}")
if (-not $mRe7.Success) { throw 'extract failed: Invoke-RegenerateOutputs' }
if (-not $mFc7.Success) { throw 'extract failed: Invoke-FocusCore' }
Invoke-Expression $mRe7.Value
Invoke-Expression $mFc7.Value
function Get-CaseCsvPath { param($Name) "$Name.csv" }
function Get-CaseCsvFullPath { param($Name) Join-Path $script:CsvDir "derived\$Name.csv" }
function New-HtmlReport { }
# the render section above swapped in the REAL Import-CaseCsv (disk reader) - the seed
# selection must see the in-memory fixture again (same stub shape as the file top)
function Import-CaseCsv([string]$name) { $name = "$name" -replace '\.csv$', ''; if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function New-Af7Row([string]$Entity) {
    [pscustomobject]@{ Found = '2026-10-14 12:00:00'; Rule = 'Renamed LOLBin at rest (Sysmon identity mismatch)'; Severity = 'high'; Entity = $Entity; Attck = 'T1036.003'; Evidence = 'identity mismatch evidence' }
}
$script:afLog = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:afLog.Add("$Message") }
$Computer = 'V270HOST'; $script:CurrentCaseID = 'CASE-270'

function Invoke-Af7Scenario {
    param([string]$Tag, [string]$Entity, [string]$ProcsPath, [string]$ProcsName, [string]$ProcsPid)
    $case7 = Join-Path $env:TEMP "ophira_v270af$Tag"
    $csv7 = Join-Path $case7 'csv'
    New-Item -ItemType Directory -Path $csv7, (Join-Path $csv7 'derived') -Force | Out-Null
    @"
"PID","PPID","Name","Path","Created"
"$ProcsPid","800","$ProcsName","$ProcsPath","2026-10-14 12:00:00"
"@ | Set-Content -LiteralPath (Join-Path $csv7 'processes.csv') -Encoding UTF8
    $script:fixtureRows = @{ 'hunt_findings' = @(New-Af7Row $Entity) }
    $null = $script:afLog.Clear()
    $script:CaseDir = $case7; $script:CsvDir = $csv7
    $script:RawDir = Join-Path $case7 'raw'; $script:MemDir = Join-Path $case7 'mem'
    Invoke-RegenerateOutputs -Case ([pscustomobject]@{ Computer = $Computer })
    $termsP7 = Join-Path (Join-Path $case7 'focus') 'focus_terms.json'
    $terms7 = $null
    if (Test-Path -LiteralPath $termsP7) { $terms7 = Get-Content -LiteralPath $termsP7 -Raw | ConvertFrom-Json }
    Remove-Item -LiteralPath $case7 -Recurse -Force -ErrorAction SilentlyContinue
    return @{ Terms = $terms7; Log = $script:afLog.ToArray() }
}

# s1: full-path entity with an OS-shared leaf -> the dossier seeds the FULL PATH (not the leaf)
$s1 = Invoke-Af7Scenario -Tag 'p' -Entity 'C:\Windows\Temp\needle-am-hsbxrtoq\svchost.exe' -ProcsPath 'C:\Windows\Temp\needle-am-hsbxrtoq\svchost.exe' -ProcsName 'svchost.exe' -ProcsPid '4242'
Check "task7 s1: path entity seeds AS-IS (focus_terms Indicator == full path, not the leaf)" ($null -ne $s1.Terms -and "$($s1.Terms.Indicator)" -eq 'C:\Windows\Temp\needle-am-hsbxrtoq\svchost.exe')
Check "task7 s1: the path seed matched evidence (dossier not empty)" ($null -ne $s1.Terms -and [int]"$($s1.Terms.HitCount)" -ge 1)
Check "task7 s1: no fallback re-seed logged" (@($s1.Log | Where-Object { $_ -match 'fallback re-seed' }).Count -eq 0)

# s2: path matches nothing on disk -> one leaf re-seed, fallback line in the log
$s2 = Invoke-Af7Scenario -Tag 'f' -Entity 'C:\Windows\Temp\ghostdir-xyzabc\svchost.exe' -ProcsPath 'C:\Windows\System32\svchost.exe' -ProcsName 'svchost.exe' -ProcsPid '777'
Check "task7 s2: zero-hit path run re-seeds with the leaf (Indicator == leaf)" ($null -ne $s2.Terms -and "$($s2.Terms.Indicator)" -eq 'svchost.exe')
Check "task7 s2: fallback line names the path seed + the leaf" (@($s2.Log | Where-Object { $_ -match "path seed 'C:\\Windows\\Temp\\ghostdir-xyzabc\\svchost\.exe' matched nothing" -and $_ -match "leaf name 'svchost\.exe'" }).Count -eq 1)
Check "task7 s2: the leaf fallback run matched evidence" ($null -ne $s2.Terms -and [int]"$($s2.Terms.HitCount)" -ge 1)

# s3: bare-name hunt entity (no separator) -> direct name seed, identical to v2.70 behavior
$s3 = Invoke-Af7Scenario -Tag 'n' -Entity 'evil.exe' -ProcsPath 'C:\Users\Ary\AppData\evil.exe' -ProcsName 'evil.exe' -ProcsPid '999'
Check "task7 s3: bare-name entity seeds directly (Indicator == name)" ($null -ne $s3.Terms -and "$($s3.Terms.Indicator)" -eq 'evil.exe')
Check "task7 s3: no fallback re-seed for bare names" (@($s3.Log | Where-Object { $_ -match 'fallback re-seed' }).Count -eq 0)
Check "task7 s3: the name seed matched evidence" ($null -ne $s3.Terms -and [int]"$($s3.Terms.HitCount)" -ge 1)

# ---- v2.73 task 13: focus time window (real core, real CSVs on disk) ----
# Window filters EVIDENCE rows only (focus_hits + focus_chain): out-of-window rows dropped,
# undated rows dropped AND counted when a window is set, kept when none is. The expansion
# term graph (names/paths/hashes) and the instance records are NOT windowed. With no window
# the outputs must stay byte-identical to v2.72 (baseline captured at HEAD 83ce19c).
function Invoke-FcWinScenario {
    param([string]$Tag, [string]$After = '', [string]$Before = '')
    $caseW = Join-Path $env:TEMP ("ophira_v270win$Tag")
    $csvW = Join-Path $caseW 'csv'
    New-Item -ItemType Directory -Path $csvW -Force | Out-Null
    @"
"Time","ProcessGuid","ProcessId","Image","User","ParentImage"
"2026-10-10 08:00:00","G1","101","C:\evil\evil.exe","user","C:\Windows\explorer.exe"
"2026-10-12 08:00:00","G2","102","C:\evil\evil.exe","user","C:\Windows\explorer.exe"
"2026-10-14 08:00:00","G3","103","C:\evil\evil.exe","user","C:\Windows\explorer.exe"
"","G4","104","C:\evil\evil.exe","user","C:\Windows\explorer.exe"
"@ | Set-Content -LiteralPath (Join-Path $csvW 'sysmon_proc_create.csv') -Encoding UTF8
    @"
"Timestamp","Source","Type","Actor","Entity","Detail"
"2026-10-11 09:00:00","sysmon","ProcessCreate","user","C:\evil\evil.exe","chain in-window"
"2026-10-15 09:00:00","sysmon","ProcessCreate","user","C:\evil\evil.exe","chain out-window"
"","sysmon","ProcessCreate","user","C:\evil\evil.exe","chain undated"
"@ | Set-Content -LiteralPath (Join-Path $csvW 'supertimeline.csv') -Encoding UTF8
    $script:CaseDir = $caseW; $script:CsvDir = $csvW
    $script:RawDir = Join-Path $caseW 'raw'; $script:MemDir = Join-Path $caseW 'mem'
    $coreArgs = @{ Indicator = 'C:\evil\evil.exe'; Meta = ([pscustomobject]@{ Computer = 'WINHOST'; CaseID = 'WIN-1' }) }
    if ($After) { $coreArgs.After = $After }
    if ($Before) { $coreArgs.Before = $Before }
    $null = Invoke-FocusCore @coreArgs
    $fDir = Join-Path $caseW 'focus'
    $res = @{
        HitsB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $fDir 'focus_hits.csv')))
        ChainB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $fDir 'focus_chain.csv')))
        Hits = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv'))
        Chain = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_chain.csv'))
        Inst = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_instances.csv'))
        Terms = (Get-Content -LiteralPath (Join-Path $fDir 'focus_terms.json') -Raw | ConvertFrom-Json)
        Report = (Get-Content -LiteralPath (Join-Path $fDir 'focus_report.html') -Raw)
    }
    Remove-Item -LiteralPath $caseW -Recurse -Force -ErrorAction SilentlyContinue
    return $res
}
$t13BaseHits = '77u/IkluZGljYXRvciIsIlNvdXJjZSIsIlRpbWUiLCJNYXRjaGVkT24iLCJEZXRhaWwiDQoiQzpcZXZpbFxldmlsLmV4ZSIsInN5c21vbl9wcm9jX2NyZWF0ZSIsIjIwMjYtMTAtMTAgMDg6MDA6MDAiLCJwYXRoIGM6XGV2aWxcZXZpbC5leGUiLCJUaW1lPTIwMjYtMTAtMTAgMDg6MDA6MDAgfCBQcm9jZXNzR3VpZD1HMSB8IFByb2Nlc3NJZD0xMDEgfCBJbWFnZT1DOlxldmlsXGV2aWwuZXhlIHwgVXNlcj11c2VyIHwgUGFyZW50SW1hZ2U9QzpcV2luZG93c1xleHBsb3Jlci5leGUgfCAiDQoiQzpcZXZpbFxldmlsLmV4ZSIsInN5c21vbl9wcm9jX2NyZWF0ZSIsIjIwMjYtMTAtMTIgMDg6MDA6MDAiLCJuYW1lIGM6XGV2aWxcZXZpbC5leGUiLCJUaW1lPTIwMjYtMTAtMTIgMDg6MDA6MDAgfCBQcm9jZXNzR3VpZD1HMiB8IFByb2Nlc3NJZD0xMDIgfCBJbWFnZT1DOlxldmlsXGV2aWwuZXhlIHwgVXNlcj11c2VyIHwgUGFyZW50SW1hZ2U9QzpcV2luZG93c1xleHBsb3Jlci5leGUgfCAiDQoiQzpcZXZpbFxldmlsLmV4ZSIsInN5c21vbl9wcm9jX2NyZWF0ZSIsIjIwMjYtMTAtMTQgMDg6MDA6MDAiLCJuYW1lIGM6XGV2aWxcZXZpbC5leGUiLCJUaW1lPTIwMjYtMTAtMTQgMDg6MDA6MDAgfCBQcm9jZXNzR3VpZD1HMyB8IFByb2Nlc3NJZD0xMDMgfCBJbWFnZT1DOlxldmlsXGV2aWwuZXhlIHwgVXNlcj11c2VyIHwgUGFyZW50SW1hZ2U9QzpcV2luZG93c1xleHBsb3Jlci5leGUgfCAiDQoiQzpcZXZpbFxldmlsLmV4ZSIsInN5c21vbl9wcm9jX2NyZWF0ZSIsIiIsIm5hbWUgYzpcZXZpbFxldmlsLmV4ZSIsIlByb2Nlc3NHdWlkPUc0IHwgUHJvY2Vzc0lkPTEwNCB8IEltYWdlPUM6XGV2aWxcZXZpbC5leGUgfCBVc2VyPXVzZXIgfCBQYXJlbnRJbWFnZT1DOlxXaW5kb3dzXGV4cGxvcmVyLmV4ZSB8ICINCg=='
$t13BaseChain = '77u/IlRpbWVzdGFtcCIsIlNvdXJjZSIsIlR5cGUiLCJBY3RvciIsIkVudGl0eSIsIkRldGFpbCINCiIiLCJzeXNtb24iLCJQcm9jZXNzQ3JlYXRlIiwidXNlciIsIkM6XGV2aWxcZXZpbC5leGUiLCJjaGFpbiB1bmRhdGVkIg0KIjIwMjYtMTAtMTEgMDk6MDA6MDAiLCJzeXNtb24iLCJQcm9jZXNzQ3JlYXRlIiwidXNlciIsIkM6XGV2aWxcZXZpbC5leGUiLCJjaGFpbiBpbi13aW5kb3ciDQoiMjAyNi0xMC0xNSAwOTowMDowMCIsInN5c21vbiIsIlByb2Nlc3NDcmVhdGUiLCJ1c2VyIiwiQzpcZXZpbFxldmlsLmV4ZSIsImNoYWluIG91dC13aW5kb3ciDQo='
$wNo = Invoke-FcWinScenario -Tag 'a'
Check "t13 no-window: focus_hits.csv byte-identical to v2.72" ($wNo.HitsB64 -eq $t13BaseHits)
Check "t13 no-window: focus_chain.csv byte-identical to v2.72" ($wNo.ChainB64 -eq $t13BaseChain)
Check "t13 no-window: undated rows kept (4 hits incl. G4, 3 chain rows)" ($wNo.Hits.Count -eq 4 -and $wNo.Chain.Count -eq 3)
Check "t13 no-window: focus_terms TimeWindow empty + RowsOutsideWindow 0" ("$($wNo.Terms.TimeWindow.From)" -eq '' -and "$($wNo.Terms.TimeWindow.To)" -eq '' -and [int]$wNo.Terms.RowsOutsideWindow -eq 0)
Check "t13 no-window: no 'time window' line in the dossier" (-not $wNo.Report.Contains('time window:'))
$wWin = Invoke-FcWinScenario -Tag 'b' -After '2026-10-11' -Before '2026-10-13'
Check "t13 window: only the in-window hit stays (1 row, G2 2026-10-12)" ($wWin.Hits.Count -eq 1 -and "$($wWin.Hits[0].Time)" -eq '2026-10-12 08:00:00')
Check "t13 window: undated hit row dropped" (@($wWin.Hits | Where-Object { "$($_.Detail)" -match 'ProcessGuid=G4\b' }).Count -eq 0)
Check "t13 window: focus_terms TimeWindow from/to (date-only = midnight)" ("$($wWin.Terms.TimeWindow.From)" -eq '2026-10-11 00:00' -and "$($wWin.Terms.TimeWindow.To)" -eq '2026-10-13 00:00')
Check "t13 window: RowsOutsideWindow = 3 hits + 2 chain rows = 5" ([int]$wWin.Terms.RowsOutsideWindow -eq 5)
Check "t13 window: instance/term graph NOT windowed (4 instances)" ($wWin.Inst.Count -eq 4)
Check "t13 window: focus_chain keeps only the in-window row" ($wWin.Chain.Count -eq 1 -and "$($wWin.Chain[0].Detail)" -eq 'chain in-window')
Check "t13 window: report header prints window + honest suppressed count" ($wWin.Report.Contains('time window: 2026-10-11 00:00 to 2026-10-13 00:00 - 5 row(s) outside window suppressed'))

# t13 statics: regen seeds untouched, CLI parity, verbatim prompts
$t13SeedLines = @($src -split "\r?\n" | Where-Object { $_ -match 'Invoke-FocusCore -Indicator \$seed' })
Check "t13 static: regen auto-focus seed calls exist and carry no -After/-Before" ($t13SeedLines.Count -ge 2 -and @($t13SeedLines | Where-Object { $_ -match '-After|-Before' }).Count -eq 0)
Check "t13 static: -Mode Focus arm passes -After/-Before" ($src.Contains("'Focus' { Invoke-FocusEngine -Path `$ParsePath -Indicator `$ProcessName -After `$After -Before `$Before | Out-Null }"))
Check "t13 static: -Mode Process alias arm passes -After/-Before" ($src.Contains("'Process' { Invoke-FocusEngine -Path `$ParsePath -Indicator `$ProcessName -After `$After -Before `$Before | Out-Null }"))
Check "t13 static: -After/-Before exist as script + engine + core params" ($src.Contains("[string]`$After = '',") -and $src.Contains("[string]`$Before = '',") -and $src.Contains('param([string]$Path, [string]$Indicator, [string]$After, [string]$Before)') -and $src.Contains('param([string]$Indicator, [pscustomobject]$Meta, [string]$After, [string]$Before)'))
Check "t13 static: menu [9] Focus arm routes through the wizard" ($src.Contains("'Focus' { Invoke-FocusEngine | Out-Null }"))
Check "t13 static: menu [P] Process arm routes through the wizard" ($src.Contains("Invoke-FocusEngine -Path `$ParsePath -Indicator `$pn | Out-Null"))
Check "t13 static: From/To prompts verbatim" ($src.Contains('  From (yyyy-MM-dd [HH:mm], blank = all)') -and $src.Contains('  To (blank = all)'))
Check "t13 static: engine passes -After/-Before into the core" ($src.Contains('-After $After -Before $Before') -and $src.Contains('Invoke-FocusCore -Indicator $Indicator -Meta'))

# t13: the main-report Focus embed meta shows the window when the dossier carries one
$mNr = [regex]::Match($src, "(?s)function New-HtmlReport \{.*?\r?\n\}")
if (-not $mNr.Success) { throw 'extract failed: New-HtmlReport (re-extract)' }
Invoke-Expression $mNr.Value
$t13case = Join-Path $env:TEMP ("ophira_v270t13_" + (Get-Date -Format 'HHmmss'))
$t13csv = Join-Path $t13case 'csv'
New-Item -ItemType Directory -Path $t13csv, (Join-Path $t13case 'raw\evtx'), (Join-Path $t13case 'focus') -Force | Out-Null
$script:CaseDir = $t13case; $script:CsvDir = $t13csv
$script:RawDir = Join-Path $t13case 'raw'; $script:MemDir = Join-Path $t13case 'mem'
$script:fixtureRows = @{}
'{"Indicator":"x.exe","Rounds":1,"HitCount":2,"InstanceCount":1,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[],"TimeWindow":{"From":"2026-10-01 00:00","To":"2026-10-02 00:00"},"RowsOutsideWindow":3}' | Set-Content -LiteralPath (Join-Path $t13case 'focus\focus_terms.json') -Encoding UTF8
$null = New-HtmlReport
$htmlT13w = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "t13 embed: meta line shows the window + suppressed count" ($htmlT13w.Contains('time window: 2026-10-01 00:00 to 2026-10-02 00:00 - 3 row(s) outside window suppressed'))
'{"Indicator":"x.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $t13case 'focus\focus_terms.json') -Encoding UTF8
$null = New-HtmlReport
$htmlT13o = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "t13 embed: old dossier JSON (no TimeWindow) renders with no window line" (-not $htmlT13o.Contains('time window:'))
'{"Indicator":"x.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[],"TimeWindow":{"From":"","To":""}}' | Set-Content -LiteralPath (Join-Path $t13case 'focus\focus_terms.json') -Encoding UTF8
$null = New-HtmlReport
$htmlT13e = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "t13 embed: empty window strings render no line" (-not $htmlT13e.Contains('time window:'))
Remove-Item -LiteralPath $t13case -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.73 task 12: focus wizard - case auto-detect + declined Quick-collect offer ----
# Invoke-FocusEngine extracted; the candidate scan rides a stubbed Get-KitRoot (temp dirs with
# real OPHIRA_* names), Open-CaseSession/Invoke-FocusCore are spies, Read-Host is scripted.
$mFe = [regex]::Match($src, "(?s)function Invoke-FocusEngine \{.*?\r?\n\}")
if (-not $mFe.Success) { throw 'extract failed: Invoke-FocusEngine' }
Invoke-Expression $mFe.Value
$script:feOpens = New-Object System.Collections.Generic.List[string]
$script:feCores = New-Object System.Collections.Generic.List[object]
$script:fePrompts = New-Object System.Collections.Generic.List[string]
$script:feAnswers = New-Object System.Collections.Generic.List[string]
$script:feFailNext = $false
$script:feKit = ''
function Get-KitRoot { return $script:feKit }
function Open-CaseSession {
    param([string]$Path)
    $script:feOpens.Add("$Path")
    if ($script:feFailNext) { $script:feFailNext = $false; Write-Host "  case.json not found - not an Ophira case folder?" -ForegroundColor Red; return $null }
    return [pscustomobject]@{ Computer = 'FEHOST'; CaseID = 'FE-1' }
}
function Invoke-FocusCore {
    param([string]$Indicator, [pscustomobject]$Meta, [string]$After, [string]$Before)
    $script:feCores.Add([pscustomobject]@{ Indicator = "$Indicator"; After = "$After"; Before = "$Before" })
    return $true
}
function Read-Host {
    param([string]$Prompt)
    $script:fePrompts.Add("$Prompt")
    if ($script:feAnswers.Count -eq 0) { return '' }
    $a = "$($script:feAnswers[0])"
    $script:feAnswers.RemoveAt(0)
    return $a
}
function Invoke-FeScenario {
    param([string]$Tag, [string[]]$Dirs = @(), [string[]]$Zips = @(), [string[]]$Answers = @(), [switch]$NoMenu, [switch]$FailFirst)
    $script:feKit = Join-Path $env:TEMP ("ophira_v270fe$Tag")
    if (Test-Path -LiteralPath $script:feKit) { Remove-Item -LiteralPath $script:feKit -Recurse -Force }
    New-Item -ItemType Directory -Path $script:feKit | Out-Null
    foreach ($d in $Dirs) { New-Item -ItemType Directory -Path (Join-Path $script:feKit $d) | Out-Null }
    foreach ($z in $Zips) { Set-Content -LiteralPath (Join-Path $script:feKit $z) -Value 'zip placeholder' -Encoding ASCII }
    $script:feOpens.Clear(); $script:feCores.Clear(); $script:fePrompts.Clear(); $script:feAnswers.Clear()
    foreach ($a in $Answers) { $script:feAnswers.Add("$a") }
    $script:feFailNext = [bool]$FailFirst
    $savedNoMenu = $script:NoMenu
    $script:NoMenu = [bool]$NoMenu
    $r = Invoke-FocusEngine
    $script:NoMenu = $savedNoMenu
    return @{ Result = $r; Opens = $script:feOpens.ToArray(); Cores = $script:feCores.ToArray(); Prompts = $script:fePrompts.ToArray(); AnswersLeft = $script:feAnswers.Count }
}
# fixture names share a host prefix so name-desc order == newest-first (real OPHIRA_<host>_<ts> names)
$t12D3 = @('OPHIRA_HOST_20261019_090000', 'OPHIRA_HOST_20261020_120000', 'OPHIRA_HOST_20261021_100000')
# 0 candidates, offer declined -> returns without ever calling Open-CaseSession (spy assert)
$feD = Invoke-FeScenario -Tag 'dec' -Answers @('n')
Check "t12 decline: returns \$false with no Open-CaseSession call" ($feD.Result -eq $false -and $feD.Opens.Count -eq 0 -and $feD.Cores.Count -eq 0)
Check "t12 decline: exactly the collect-offer prompt was asked" ($feD.Prompts.Count -eq 1 -and "$($feD.Prompts[0])" -match 'Quick collection now')
Check "t12 static: collect offer prompt verbatim" ($src.Contains('  No case found on this PC. Run a Quick collection now (~1-2 min), then focus? [Y/n]'))
Check "t12 static: declined/NoMenu hint names the CLI alternative" ($src.Contains('-Mode Focus -ParsePath <case folder or OPHIRA_*.zip> -ProcessName <indicator>'))
Check "t12 static: collect relaunch is the menu-[1] shape (Quick, NoMenu, kit-root OutputPath)" ($src.Contains('-Mode Collect -NoMenu -NoElevate -Preset Quick -OutputPath'))
# 0 candidates + -NoMenu -> hint only, no prompt at all (unattended never offers collection)
$feN = Invoke-FeScenario -Tag 'nm' -NoMenu
Check "t12 no-menu: hint and return, zero prompts, zero opens" ($feN.Result -eq $false -and $feN.Opens.Count -eq 0 -and $feN.Prompts.Count -eq 0 -and $feN.AnswersLeft -eq 0)
# 1 candidate -> used automatically, no case-number prompt (indicator + From + To only)
$fe1 = Invoke-FeScenario -Tag 'one' -Dirs @('OPHIRA_HOST_20261019_090000') -Answers @('evil.exe')
Check "t12 one: the single candidate opened" ($fe1.Result -eq $true -and $fe1.Opens.Count -eq 1 -and ("$($fe1.Opens[0])".EndsWith('OPHIRA_HOST_20261019_090000')))
Check "t12 one: no pick prompt (indicator + window prompts only), core got the indicator" ($fe1.Cores.Count -eq 1 -and "$($fe1.Cores[0].Indicator)" -eq 'evil.exe' -and $fe1.Prompts.Count -eq 3 -and @($fe1.Prompts | Where-Object { "$_" -match 'case number' }).Count -eq 0)
# N candidates -> numbered list newest-first; Enter = newest
$feE = Invoke-FeScenario -Tag 'ent' -Dirs $t12D3 -Answers @('', 'ind')
Check "t12 many: Enter picks the newest (name-desc)" ($feE.Result -eq $true -and ("$($feE.Opens[0])".EndsWith('OPHIRA_HOST_20261021_100000')) -and "$($feE.Cores[0].Indicator)" -eq 'ind')
# N candidates -> explicit number picks that entry
$fe2 = Invoke-FeScenario -Tag 'p2' -Dirs $t12D3 -Answers @('2', 'ind')
Check "t12 many: '2' picks the second newest" (("$($fe2.Opens[0])".EndsWith('OPHIRA_HOST_20261020_120000')))
# zips are candidates too (newest-named zip wins on Enter)
$feZ = Invoke-FeScenario -Tag 'zip' -Dirs @('OPHIRA_HOST_20261019_090000') -Zips @('OPHIRA_HOST_20261023_000000.zip') -Answers @('', 'ind')
Check "t12 many: OPHIRA_*.zip candidates scan + newest zip auto-picked" (("$($feZ.Opens[0])".EndsWith('OPHIRA_HOST_20261023_000000.zip')))
# failed open -> re-prompt (the numbered list), not a crash
$feF = Invoke-FeScenario -Tag 'fail' -Dirs @('OPHIRA_HOST_20261021_100000', 'OPHIRA_HOST_20261020_120000') -Answers @('1', '2', 'ind') -FailFirst
Check "t12 fail: first open failed, re-prompt succeeded on the 2nd pick" ($feF.Result -eq $true -and $feF.Opens.Count -eq 2 -and ("$($feF.Opens[0])".EndsWith('OPHIRA_HOST_20261021_100000')) -and ("$($feF.Opens[1])".EndsWith('OPHIRA_HOST_20261020_120000')) -and $feF.Cores.Count -eq 1)
Check "t12 fail: the case-number prompt appeared twice" (@($feF.Prompts | Where-Object { "$_" -match 'case number' }).Count -eq 2)
# window prompts: valid answers ride to the core
$feW = Invoke-FeScenario -Tag 'win' -Dirs @('OPHIRA_HOST_20261019_090000') -Answers @('ind', '2026-10-01', '2026-10-02 03:00')
Check "t13 wizard: From/To answers reach the core" ("$($feW.Cores[0].After)" -eq '2026-10-01' -and "$($feW.Cores[0].Before)" -eq '2026-10-02 03:00')
# -After passed -> prompts skipped entirely (CLI parity)
$theDir = Join-Path $script:feKit 'OPHIRA_HOST_20261019_090000'
$script:feOpens.Clear(); $script:feCores.Clear(); $script:fePrompts.Clear(); $script:feAnswers.Clear()
$rCli = Invoke-FocusEngine -Path $theDir -Indicator 'x' -After '2026-10-01'
Check "t13 wizard: -After on the CLI skips every prompt, Before stays blank" ($rCli -eq $true -and $script:fePrompts.Count -eq 0 -and "$($script:feCores[0].After)" -eq '2026-10-01' -and "$($script:feCores[0].Before)" -eq '')
# v2.75 fix pin: a -Path (CLI -ParsePath) run WITHOUT window args must stay zero-prompt -
# v2.73 regressed this into two From/To Read-Hosts. The wizard (unbound -Path) still asks
# indicator + From + To (pinned above by the t12 'one' scenario: Prompts.Count -eq 3).
$script:feOpens.Clear(); $script:feCores.Clear(); $script:fePrompts.Clear(); $script:feAnswers.Clear()
$rCliNw = Invoke-FocusEngine -Path $theDir -Indicator 'evil.exe'
Check "t13 fix: -ParsePath CLI run without window args performs NO prompts" ($rCliNw -eq $true -and $script:fePrompts.Count -eq 0 -and $script:feOpens.Count -eq 1 -and "$($script:feCores[0].After)" -eq '' -and "$($script:feCores[0].Before)" -eq '')
Check "t13 fix static: window prompts gated on unbound -Path (wizard-only)" ($src.Contains("if (-not `$PSBoundParameters.ContainsKey('Path') -and -not `$After -and -not `$Before) {"))
# invalid window input: re-prompt once, then proceed without the bound (warning)
$feI = Invoke-FeScenario -Tag 'inv' -Dirs @('OPHIRA_HOST_20261019_090000') -Answers @('ind', 'garbage1', 'garbage2', 'garbage3', '2026-10-05')
Check "t13 wizard: From invalid twice -> dropped with warning, To valid on retry" ("$($feI.Cores[0].After)" -eq '' -and "$($feI.Cores[0].Before)" -eq '2026-10-05' -and $feI.Prompts.Count -eq 5)

# ---- v2.74 tasks 14+15: sortment completion sweep + ANALYST-START-HERE.txt + [O] offer ----
# A) map + reader contract: real CsvCatMap literal + real Get-CaseCsvPath extracted
Check "t14 static: wildcard map entries present" (($src -match [regex]::Escape("'amcache_*' = 'artifacts'")) -and ($src -match [regex]::Escape("'jumplist_parsed*' = 'artifacts'")) -and ($src -match [regex]::Escape("'prefetch_parsed*' = 'artifacts'")))
Check "t14 static: usn_write_bursts mapped (was flat since v2.42)" ($src -match [regex]::Escape("'usn_write_bursts' = 'artifacts'"))
Check "t14 static: Get-CaseCsvPath wildcard scan present" ($src -match [regex]::Escape('foreach ($k in ($script:CsvCatMap.Keys | Sort-Object))'))
$mRe74 = [regex]::Match($src, "(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}")
if (-not $mRe74.Success) { throw 'extract failed: Invoke-RegenerateOutputs (v2.74)' }
Check "t14 static: sweep runs before New-SuperTimeline in regen" ($mRe74.Value.IndexOf('sortment completion sweep') -lt $mRe74.Value.IndexOf('{ New-SuperTimeline }')) # v2.79: producers moved into $rgStep scriptblocks
$mMap74 = [regex]::Match($src, "(?s)\`$script:CsvCatMap = @\{.*?\r?\n\}")
if (-not $mMap74.Success) { throw 'extract failed: CsvCatMap' }
Invoke-Expression $mMap74.Value
$mG74 = [regex]::Match($src, "(?s)function Get-CaseCsvPath \{.*?\r?\n\}")
if (-not $mG74.Success) { throw 'extract failed: Get-CaseCsvPath' }
Invoke-Expression $mG74.Value
Check "t14 reader: amcache_* wildcard -> artifacts" ((Get-CaseCsvPath 'amcache_DevicePnp') -eq 'artifacts\amcache_DevicePnp.csv')
Check "t14 reader: jumplist_parsed* wildcard -> artifacts" ((Get-CaseCsvPath 'jumplist_parsed_AutomaticDestinations') -eq 'artifacts\jumplist_parsed_AutomaticDestinations.csv')
Check "t14 reader: prefetch_parsed* wildcard (Timeline projection) -> artifacts" ((Get-CaseCsvPath 'prefetch_parsed_Timeline') -eq 'artifacts\prefetch_parsed_Timeline.csv')
Check "t14 reader: exact key still outranks wildcard (amcache)" ((Get-CaseCsvPath 'amcache') -eq 'artifacts\amcache.csv')
Check "t14 reader: other categories untouched" ((Get-CaseCsvPath 'processes') -eq 'volatile\processes.csv' -and (Get-CaseCsvPath 'supertimeline') -eq 'derived\supertimeline.csv')
Check "t14 reader: unmapped names stay flat" ((Get-CaseCsvPath 'notes') -eq 'notes.csv')
Check "t14 reader: wildcard match is case-insensitive" ((Get-CaseCsvPath 'AMCACHE_DevicePnp') -eq 'artifacts\AMCACHE_DevicePnp.csv')

# B) regen behavioral: real sweep + START-HERE run over a fixture case. All derived-artifact
# builders are stubbed; the try/catch around each regen step means a missing stub only logs.
foreach ($nR74 in 'Get-CaseCsvFullPath', 'Test-CaseCsv', 'Import-CaseCsv', 'Invoke-RegenerateOutputs') {
    $mR74 = [regex]::Match($src, "(?s)function $nR74 \{.*?\r?\n\}")
    if (-not $mR74.Success) { throw "extract failed: $nR74" }
    Invoke-Expression $mR74.Value
}
$script:regenLog = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole) $script:regenLog.Add("$Message") }
function Get-CompromiseVerdict { return [pscustomobject]@{ Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 60; OwnerLine = 'fixture owner line'; Signals = @(); Caveats = @(); Coverage = @(); CoverageSourcesCollected = 3; CoverageSourcesTotal = 4 } }
function New-SuperTimeline { New-Item -ItemType Directory -Path (Join-Path $CsvDir 'derived') -Force | Out-Null; 'ts,source' | Set-Content -LiteralPath (Join-Path $CsvDir 'derived\supertimeline.csv') -Encoding UTF8 }
function New-HtmlReport { '<html>fixture report</html>' | Set-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Encoding UTF8; return 'x' }
function Get-CaseNarrative { 'draft text' }
function Get-TriageLeads { return @([pscustomobject]@{ Rank = 1; Title = 'lead one'; Class = 'hunt rule: x'; Why = 'why'; Ident = 'id'; Extra = 'ATT&CK T0000'; Anchor = 'hunt'; Rule = 'x' }) }
$t74 = Join-Path $env:TEMP ("ophira_v270t74_" + (Get-Date -Format 'HHmmss'))
$Csv74 = Join-Path $t74 'csv'
New-Item -ItemType Directory -Path $Csv74, (Join-Path $Csv74 'artifacts'), (Join-Path $t74 'raw') -Force | Out-Null
'ApplicationName,Path' | Set-Content -LiteralPath (Join-Path $Csv74 'prefetch_parsed.csv') -Encoding UTF8
'x.exe,C:\x' | Add-Content -LiteralPath (Join-Path $Csv74 'prefetch_parsed.csv') -Encoding UTF8
'hdr1,hdr2' | Set-Content -LiteralPath (Join-Path $Csv74 'amcache_DevicePnp.csv') -Encoding UTF8
'v1,v2' | Add-Content -LiteralPath (Join-Path $Csv74 'amcache_DevicePnp.csv') -Encoding UTF8
'hdr' | Set-Content -LiteralPath (Join-Path $Csv74 'jumplist_parsed_AutomaticDestinations.csv') -Encoding UTF8
'hdr' | Set-Content -LiteralPath (Join-Path $Csv74 'prefetch_parsed_Timeline.csv') -Encoding UTF8
'WindowStart,Drive' | Set-Content -LiteralPath (Join-Path $Csv74 'usn_write_bursts.csv') -Encoding UTF8
'ApplicationName,Path' | Set-Content -LiteralPath (Join-Path $Csv74 'artifacts\amcache.csv') -Encoding UTF8
'old.exe,C:\old' | Add-Content -LiteralPath (Join-Path $Csv74 'artifacts\amcache.csv') -Encoding UTF8
'whatever' | Set-Content -LiteralPath (Join-Path $Csv74 'notes.csv') -Encoding UTF8
'txt' | Set-Content -LiteralPath (Join-Path $t74 'readme.txt') -Encoding UTF8
$CaseDir = $t74; $CsvDir = $Csv74
Invoke-RegenerateOutputs -Case $null
Check "t14 sweep: all five loose mapped files moved, one line each" ((@($script:regenLog | Where-Object { $_ -match '^    sortment: moved ' }).Count -eq 5) -and ($script:regenLog -contains '    sortment: moved amcache_DevicePnp.csv -> csv\artifacts\'))
Check "t14 sweep: files landed in csv\artifacts" ((Test-Path (Join-Path $Csv74 'artifacts\amcache_DevicePnp.csv')) -and (Test-Path (Join-Path $Csv74 'artifacts\jumplist_parsed_AutomaticDestinations.csv')) -and (Test-Path (Join-Path $Csv74 'artifacts\prefetch_parsed_Timeline.csv')) -and (Test-Path (Join-Path $Csv74 'artifacts\usn_write_bursts.csv')))
Check "t14 sweep: csv root no longer holds them" ((-not (Test-Path (Join-Path $Csv74 'amcache_DevicePnp.csv'))) -and (-not (Test-Path (Join-Path $Csv74 'jumplist_parsed_AutomaticDestinations.csv'))) -and (-not (Test-Path (Join-Path $Csv74 'prefetch_parsed.csv'))) -and (-not (Test-Path (Join-Path $Csv74 'usn_write_bursts.csv'))))
Check "t14 sweep: already-foldered file untouched" ((Test-Path (Join-Path $Csv74 'artifacts\amcache.csv')) -and (@(Import-Csv (Join-Path $Csv74 'artifacts\amcache.csv'))[0].ApplicationName -eq 'old.exe'))
Check "t14 sweep: unmapped csv and non-csv stay in root" ((Test-Path (Join-Path $Csv74 'notes.csv')) -and (Test-Path (Join-Path $t74 'readme.txt')))
$pp74 = @(Import-CaseCsv 'prefetch_parsed')
Check "t14 parity: Import-CaseCsv 'prefetch_parsed' resolves AFTER the move" ($pp74.Count -eq 1 -and "$($pp74[0].ApplicationName)" -eq 'x.exe')
Check "t14 parity: Test-CaseCsv wildcard covers the mapped splits" ((Test-CaseCsv 'jumplist_parsed*') -eq $true)
$script:regenLog = New-Object System.Collections.Generic.List[string]
Invoke-RegenerateOutputs -Case $null
Check "t14 idempotent: second run moves nothing, errors nothing" ((@($script:regenLog | Where-Object { $_ -match 'sortment:' }).Count -eq 0))
'ApplicationName,Path' | Set-Content -LiteralPath (Join-Path $Csv74 'prefetch_parsed.csv') -Encoding UTF8
'late.exe,C:\late' | Add-Content -LiteralPath (Join-Path $Csv74 'prefetch_parsed.csv') -Encoding UTF8
$script:regenLog = New-Object System.Collections.Generic.List[string]
Invoke-RegenerateOutputs -Case $null
Check "t14 flat-wins: destination exists -> flat duplicate left alone (read contract keeps it authoritative)" ((Test-Path (Join-Path $Csv74 'prefetch_parsed.csv')) -and (@(Import-CaseCsv 'prefetch_parsed')[0].ApplicationName -eq 'late.exe') -and (@($script:regenLog | Where-Object { $_ -match 'sortment: moved prefetch_parsed' }).Count -eq 0))
Remove-Item -LiteralPath (Join-Path $Csv74 'prefetch_parsed.csv') -Force -ErrorAction SilentlyContinue
'hdr' | Set-Content -LiteralPath (Join-Path $Csv74 'amcache_LockedTable.csv') -Encoding UTF8
$fs74 = [IO.File]::Open((Join-Path $Csv74 'amcache_LockedTable.csv'), 'Open', 'Read', 'None')
$script:regenLog = New-Object System.Collections.Generic.List[string]
Invoke-RegenerateOutputs -Case $null
$fs74.Close()
Check "t14 locked: move failure logged + file skipped" ((Test-Path (Join-Path $Csv74 'amcache_LockedTable.csv')) -and (@($script:regenLog | Where-Object { $_ -match 'sortment: could not move amcache_LockedTable\.csv' }).Count -eq 1))
Check "t14 locked: regen continued to completion (START-HERE + report written)" ((Test-Path (Join-Path $t74 'ANALYST-START-HERE.txt')) -and (Test-Path (Join-Path $t74 'report.html')))
$sh74 = Get-Content -LiteralPath (Join-Path $t74 'ANALYST-START-HERE.txt') -Raw
Check "t15: START-HERE at case root, header names the host" ($sh74 -match [regex]::Escape('OPHIRA CASE - V270HOST'))
Check "t15: verdict one-liner (draft ASSESSMENT wording family)" ($sh74 -match [regex]::Escape('ASSESSMENT: SUSPICIOUS (evidence coverage 60% of expected sources - 3/4 sources, not a probability of compromise). fixture owner line'))
Check "t15: open-report instruction present" ($sh74 -match 'START HERE: open report\.html')
$t74mapOk = $true
foreach ($fm74 in @('csv\volatile\', 'csv\persistence\', 'csv\network\', 'csv\logs\', 'csv\artifacts\', 'csv\defender\', 'csv\memory\', 'csv\context\', 'csv\derived\', 'focus\', 'raw\')) {
    if (@(@($sh74 -split "\r?\n") | Where-Object { $_ -match [regex]::Escape("$fm74 = ") }).Count -ne 1) { $t74mapOk = $false }
}
Check "t15: folder map - all 11 folders, one line each" $t74mapOk
Check "t15: top list only-existing entries, focus line absent when no dossier" (($sh74 -match [regex]::Escape('1. report.html')) -and ($sh74 -match [regex]::Escape('2. csv\derived\supertimeline.csv')) -and ($sh74 -match [regex]::Escape('3. case_draft.txt')) -and ($sh74 -match [regex]::Escape('4. csv\derived\leads.csv')) -and (-not ($sh74 -match 'focus_report\.html')))
Check "t15: START-HERE wrote without failure" ((@($script:regenLog | Where-Object { $_ -match 'start-here failed' }).Count -eq 0))
New-Item -ItemType Directory -Path (Join-Path $t74 'focus') -Force | Out-Null
'focus' | Set-Content -LiteralPath (Join-Path $t74 'focus\focus_report.html') -Encoding UTF8
Invoke-RegenerateOutputs -Case $null
$sh74b = Get-Content -LiteralPath (Join-Path $t74 'ANALYST-START-HERE.txt') -Raw
Check "t15: re-regen inserts the focus dossier line in position" (($sh74b -match [regex]::Escape('3. focus\focus_report.html')) -and ($sh74b -match [regex]::Escape('4. case_draft.txt')) -and ($sh74b -match [regex]::Escape('5. csv\derived\leads.csv')))
Check "t15: re-regen overwrites cleanly (single ASSESSMENT line)" ((@([regex]::Matches($sh74b, 'ASSESSMENT:')).Count -eq 1))
# v2.75 fix: a re-parse that ranks ZERO leads removes the stale leads.csv so the report's
# inline fallback + the draft's skip-block take over (the old code kept serving the previous
# ranking). leads.csv exists here from the earlier t14 regens (1-lead stub).
$leads74Was = Test-Path -LiteralPath (Join-Path $Csv74 'derived\leads.csv')
function Get-TriageLeads { return @() }
$script:regenLog = New-Object System.Collections.Generic.List[string]
Invoke-RegenerateOutputs -Case $null
Check "t14 leads: regen wrote leads.csv before the zero-lead re-parse" $leads74Was
Check "t14 leads: zero-lead re-parse removed the stale leads.csv" (-not (Test-Path -LiteralPath (Join-Path $Csv74 'derived\leads.csv')))
Check "t14 leads: stale removal logged" ((@($script:regenLog | Where-Object { $_ -match 'stale ranking removed' }).Count -eq 1))
Remove-Item -LiteralPath $t74 -Recurse -Force -ErrorAction SilentlyContinue

# C) [O] offer statics
Check "t15 static: OfferOpenReport defined once" ((@([regex]::Matches($src, [regex]::Escape('$script:OfferOpenReport = {'))).Count -eq 1))
Check "t15 static: wired on all three done screens" ((@([regex]::Matches($src, [regex]::Escape('& $script:OfferOpenReport'))).Count -eq 3))
Check "t15 static: -NoMenu/unattended never prompts" ($src -match [regex]::Escape('if (-not $Prompt) { return }'))
Check "t15 static: Parse offer gated on interactive path entry + NoMenu" (($src -match [regex]::Escape("-not `$PSBoundParameters.ContainsKey('Path') -and -not `$NoMenu")) -and ($src -match [regex]::Escape('Before the re-pack so the temp copy of a zip-parsed case still exists')))
Check "t15 static: missing report answers honestly" ($src -match [regex]::Escape('no report.html in'))
Check "t15 static: key read uses the try/catch ReadKey pattern, opens via Invoke-Item" (($src -match [regex]::Escape("try { `$k = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character } catch { return }")) -and ($src -match [regex]::Escape('Invoke-Item -LiteralPath $rep')))
Check "t15 static: SimpleUI [O] offer suppressed under -NoMenu (v2.75 fix)" ($src.Contains('& $script:OfferOpenReport -Dir $CaseDir -Prompt:(-not $script:NoMenu)'))

# D) worker map round-trip: the seeded CsvCatMap literal must stay a valid hashtable carrying
# the wildcard entries (Save-Rows in pooled workers writes through it) - v2.58-style smoke
foreach ($nW74 in 'New-WorkerPreamble') {
    $mW74 = [regex]::Match($src, "(?s)function $nW74 \{.*?\r?\n\}")
    if (-not $mW74.Success) { throw "extract failed: $nW74" }
    Invoke-Expression $mW74.Value
}
$sf74 = [regex]::Match($src, "(?s)\`$script:SharedFunctions = @\(.*?\r?\n\)").Value
Invoke-Expression $sf74
foreach ($fn74 in $script:SharedFunctions) {
    $mW75 = [regex]::Match($src, "(?s)function $fn74 \{.*?\r?\n\}")
    if ($mW75.Success) { Invoke-Expression $mW75.Value }
}
$wt74 = [regex]::Match($src, "(?s)\`$script:ModuleWorkerText = @'.*?'@").Value
Invoke-Expression $wt74
$w74 = Join-Path $env:TEMP ("ophira_v270w74_" + (Get-Date -Format 'HHmmss'))
$CsvW74 = Join-Path $w74 'csv'
New-Item -ItemType Directory -Path $CsvW74, (Join-Path $w74 'raw'), (Join-Path $w74 'mem') -Force | Out-Null
$CaseDir = $w74; $CsvDir = $CsvW74; $RawDir = Join-Path $w74 'raw'; $MemDir = Join-Path $w74 'mem'
$Preset = 'Standard'; $global:CaseLog = Join-Path $w74 'c.log'
$script:SimpleUI = $true; $script:Verbosity = 1
$fakeW74 = @{ Id = 'W74'; Name = 'map-roundtrip'; RunText = "@(`$script:CsvCatMap['amcache_*'], (Get-CaseCsvPath 'amcache_DevicePnp'), (Get-CaseCsvPath 'prefetch_parsed_Timeline'), (Get-CaseCsvPath 'usn_write_bursts')) | Set-Content -LiteralPath '$w74\out.txt'; Save-Rows -Name 'usn_write_bursts' -Rows @([pscustomobject]@{ WindowStart = 't'; Drive = 'C'; WriteEvents = 1; DistinctFiles = 1 })" }
$ps74 = [powershell]::Create()
$null = $ps74.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog (Join-Path $w74 'w.log'))).AddArgument($fakeW74)
$rW74 = $ps74.Invoke() | Select-Object -First 1
$ps74.Dispose()
Check "t14 worker: module ran without error" ($rW74 -and -not $rW74.Error)
$outW74 = @(Get-Content -LiteralPath (Join-Path $w74 'out.txt') -ErrorAction SilentlyContinue)
Check "t14 worker: seeded map round-trips with the wildcard entries" (($outW74.Count -eq 4) -and ($outW74[0] -eq 'artifacts') -and ($outW74[1] -eq 'artifacts\amcache_DevicePnp.csv') -and ($outW74[2] -eq 'artifacts\prefetch_parsed_Timeline.csv') -and ($outW74[3] -eq 'artifacts\usn_write_bursts.csv'))
Check "t14 worker: Save-Rows writes through the seeded wildcard-era map" ((Test-Path (Join-Path $CsvW74 'artifacts\usn_write_bursts.csv')) -and (@(Import-Csv (Join-Path $CsvW74 'artifacts\usn_write_bursts.csv')).Count -eq 1))
Remove-Item -LiteralPath $w74 -Recurse -Force -ErrorAction SilentlyContinue

if ($fail -gt 0) { Write-Host "`ntest_v270: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v270: $pass passed, 0 failed" -ForegroundColor Green
exit 0
