# test_v268.ps1 - v2.68 robustness batch:
#   B7 CoveragePercentUnadjusted was a lie - both verdict properties read the SAME corrected
#       value ($coverageRaw, i.e. AFTER the non-elevated -15 weight correction). Now the
#       unadjusted property carries the pre-correction fraction (same Round/Max math, same
#       0..100 clamps on both): elevated runs keep identical values by design, non-elevated
#       runs read Unadjusted >= Confidence with the gap exactly the -15 weight fraction.
#   B8 EcsConfigs path regex truncated at the first non-\w char - a quoted exclusion VALUE
#       like 'Windows Defender\Exclusions\Paths\C:\Program Files\Bad' captured as
#       '...\Paths\C' (colon/space/dot stop the old \w class), so the EcsConfigs-only drop
#       decision misjudged real evidence. New capture runs until whitespace/quote/pipe/
#       semicolon (the 5007 Detail shapes are whitespace-normalized messages where
#       ' = value' and 'New value:' separators are space-led). Drop/keep logic unchanged.
#   B5-class producer casts: the entity correlation builder (New-EntityCorrelation, runs
#       main-thread in New-Package + -Mode Parse via Invoke-RegenerateOutputs) still had two
#       unguarded CSV-cell casts - a garbage powershell_console_history KB cell or
#       bruteforce row aborted entity building. Both route through ConvertTo-SafeDbl/Int.
#   B10 stale comments said +/-15 min while the code window has been +/-30 since v2.66.
#   B18 dead wildcard fallback in the emptyWhy lookup - no $emptyWhy key is starred (the
#       starred keys belong to the $desc map whose own lookup stays), so the foreach could
#       never match. Deleted, behavior unchanged.
#   B17 sweep guard: no Write-Host call carries a PowerShell argument comma before
#       -ForegroundColor / a closing paren (the historical :8904 site's comma is prose
#       inside the string - a legitimate line-wrap continuation, pinned here as a guard).
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ===================== B7: CoveragePercentUnadjusted is really unadjusted =====================
# behavioral - Get-CompromiseVerdict driven with the test_v264 fixture harness
foreach ($n in 'Get-CompromiseVerdict', 'Get-LvlRank') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$tmp7 = Join-Path $env:TEMP ("ophira_v268_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path (Join-Path $tmp7 'raw\evtx') -Force | Out-Null
$RawDir = Join-Path $tmp7 'raw'
$MemDir = Join-Path $tmp7 'mem'
$CaseDir = $tmp7
$global:LogHours = 168

function Import-CaseCsv([string]$name) { if ($script:fixtureRows.ContainsKey($name)) { return $script:fixtureRows[$name] }; return @() }
function Test-CaseCsv([string]$n) { return ($script:presentCsvs -contains $n) }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Test-IsAdmin { return $false }
function Get-IocList { return @{ Hashes = @{ 'deadbeef' = $true }; Ips = @{}; Domains = @{}; Names = @{} } }

$script:presentCsvs = @('flash_process_scored', 'hayabusa_timeline', 'autoruns_runkeys', 'amcache')
$script:fixtureRows = @{}

# elevated: no -15 correction - the two coverage properties are identical BY DESIGN
$script:EndpointAdmin = $true
$vElev = Get-CompromiseVerdict
Check "B7: elevated run - Unadjusted == Confidence (identical is correct there)" ($vElev.CoveragePercentUnadjusted -eq $vElev.ConfidencePercent)

# non-elevated: Confidence keeps the -15-corrected value, Unadjusted is the pre-correction
# fraction - same Round/Max math on the same sums, so it must equal the ELEVATED confidence
$script:EndpointAdmin = $false
$vNon = Get-CompromiseVerdict
Check "B7: non-elevated run - Unadjusted equals the elevated (pre-correction) percent, not the corrected one" ($vNon.CoveragePercentUnadjusted -eq $vElev.ConfidencePercent)
Check "B7: non-elevated run - Unadjusted > Confidence (the -15 weight correction shows)" ($vNon.CoveragePercentUnadjusted -gt $vNon.ConfidencePercent)
Check "B7: non-elevated run - corrected confidence is the clamped fraction of (got-15)" ($vNon.ConfidencePercent -lt $vNon.CoveragePercentUnadjusted -and $vNon.ConfidencePercent -ge 0)

# source-scan: the two properties receive DIFFERENT variables (the v2.64 lie pin)
Check "B7: CoveragePercentUnadjusted no longer reads `$coverageRaw" (-not $src.Contains('CoveragePercentUnadjusted = $coverageRaw'))
Check "B7: unadjusted fraction computed before the -15 correction" ($src.Contains('$covUnadj') -and $src.Contains('CoveragePercentUnadjusted = $covUnadj'))

# ===================== B8: EcsConfigs path regex spans real full paths =====================
# the old \w-only run class is gone
Check "B8: old [\w\\]+ capture class removed" (-not $src.Contains('Windows Defender\\[\w\\]+'))
# extract the LIVE regex string from the source (single-quoted in source -> '' is a literal ')
$mRx = [regex]::Match($src, '\[regex\]::Matches\(\$hd, ''((?:[^'']|'''')+)''\)')
Check "B8: hd capture regex extractable from source" $mRx.Success
if ($mRx.Success) {
    $rxStr = $mRx.Groups[1].Value.Replace("''", "'")

    # capture shapes - real 5007 Detail (defender_config_events.csv, whitespace-normalized message)
    $evSpaces = '10/11/2026 5:44:59 PM: Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware. Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Program Files\Bad Tools\svc.exe = 0x1'
    $capSpaces = @([regex]::Matches($evSpaces, $rxStr) | ForEach-Object { $_.Value })
    Check "B8: full exclusion path with spaces+colons captured WHOLE" ($capSpaces.Count -eq 1 -and $capSpaces[0] -eq 'Windows Defender\Exclusions\Paths\C:\Program Files\Bad Tools\svc.exe')

    $evMixed = '10/14/2026 3:40:55 AM: Microsoft Defender Antivirus Configuration has changed. Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpFC_Nis_WdFilterProcessExclusions = 0x0 New value: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\C:\Program Files\Bad Tools = 0x1'
    $capMixed = @([regex]::Matches($evMixed, $rxStr) | ForEach-Object { $_.Value })
    Check "B8: multi-finding evidence splits into per-path captures" ($capMixed.Count -eq 2 -and $capMixed[0] -like '*EcsConfigs*' -and $capMixed[1] -eq 'Windows Defender\Exclusions\Paths\C:\Program Files\Bad Tools')

    # real-case shape (x86 parens + version dots ride along; the ' = value' separator terminates)
    $evReal = 'Old value: HKLM\SOFTWARE\Microsoft\Windows Defender\Diagnostics\LastKnownGoodPlatformLocation = C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0 New value: Default\Diagnostics\LastKnownGoodPlatformLocation ='
    $capReal = @([regex]::Matches($evReal, $rxStr) | ForEach-Object { $_.Value })
    Check "B8: value-side path (parens/dots/hyphen) captured whole, 'New value:' terminates" ($capReal.Count -eq 2 -and $capReal[1] -eq 'Windows Defender\Platform\4.18.26080.4-0')

    # drop/keep decision - the surrounding EcsConfigs-only logic, replicated byte-for-byte
    # (Rule carries 'Defender exclusion', Evidence is the 5007 Detail - exactly the real shape)
    $script:rxStr = $rxStr
    function Test-EcsDecision([string]$rule, [string]$hd) {
        $script:postureExclusions = $false
        if ("$rule" -notmatch '(?i)Defender exclusion' -or "$hd" -notmatch 'EcsConfigs' -or $script:postureExclusions) { return 'keep' }
        $hp = @([regex]::Matches($hd, $script:rxStr) | ForEach-Object { $_.Value })
        if (-not (@($hp).Count -gt 0 -and @($hp | Where-Object { $_ -notmatch '\\EcsConfigs\\' }).Count -eq 0)) { return 'keep' }
        return 'drop'
    }
    $rDef = 'Defender exclusion configuration changed'

    $ecsOnly = '10/14/2026 3:40:55 AM: Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware. Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpFC_Nis_WdFilterProcessExclusions = 0x1'
    Check "B8: EcsConfigs-only 5007 finding -> drop (verdict-input honesty preserved)" ((Test-EcsDecision $rDef $ecsOnly) -eq 'drop')

    $ecsPathSpaces = '5007: Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpExclusions\Paths\C:\Program Files\Platform App = C:\Program Files\Platform App\tool.exe'
    Check "B8: platform-managed EcsConfigs path whose value has spaces+colons -> drop" ((Test-EcsDecision $rDef $ecsPathSpaces) -eq 'drop')

    Check "B8: EcsConfigs old value + real Exclusions\Paths new value -> keep" ((Test-EcsDecision $rDef $evMixed) -eq 'keep')

    $ecsValueMention = '5007: Old value: New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\svc\EcsConfigs Share\bad.exe = 0x1'
    Check "B8: real exclusion path merely MENTIONING EcsConfigs in its value -> keep" ((Test-EcsDecision $rDef $ecsValueMention) -eq 'keep')

    $realCaseEcs = '10/11/2026 5:44:59 PM: Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware. Old value: Default\Exclusions\DisableAutoExclusions = 0x0 New value: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions = 0x1'
    Check "B8: real-case DisableAutoExclusions finding (no EcsConfigs) -> keep at the first gate" ((Test-EcsDecision $rDef $realCaseEcs) -eq 'keep')

    Check "B8: non-Defender rule never drops, even with EcsConfigs text" ((Test-EcsDecision 'LSASS access' 'handle to Windows Defender\Features\EcsConfigs\MpFC requested') -eq 'keep')

    # the non-regex half of the predicate is byte-identical
    Check "B8: '\EcsConfigs\' containment predicate unchanged" ($src.Contains("-notmatch '\\EcsConfigs\\'"))
}

# ===================== B5-class: producer casts in New-EntityCorrelation =====================
Check "B5f: no bare [double] cast on the console-history KB cell" (-not $src.Contains('[double]"$($r.KB)"'))
Check "B5f: ConsoleKB accumulates through ConvertTo-SafeDbl" ($src.Contains('$a2.ConsoleKB = [math]::Round($a2.ConsoleKB + (ConvertTo-SafeDbl "$($r.KB)"), 1)'))
Check "B5f: no bare [int] cast on the bruteforce FailedLogons cell" (-not $src.Contains('$e.Brute = [int]"$($r.FailedLogons)"'))
Check "B5f: Brute reads through ConvertTo-SafeInt" ($src.Contains('$e.Brute = ConvertTo-SafeInt "$($r.FailedLogons)"'))
# context pin: the builder runs main-thread (Invoke-RegenerateOutputs -> New-Package / -Mode Parse),
# so the top-level helpers are in scope directly - no scoped-fallback shim needed
$mEc = [regex]::Match($src, "(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}")
Check "B5f: New-EntityCorrelation is called from Invoke-RegenerateOutputs (main-thread regen path)" ($mEc.Success -and $mEc.Value.Contains('New-EntityCorrelation'))

# ===================== B10: comments say the 30 they mean =====================
Check "B10: no '+/-15 min' comments left (code has been +/-30 since v2.66)" (-not $src.Contains('+/-15 min'))
$mB10a = [regex]::Match($src, '(?s)master-timeline context for the top cards: rows within \+/-30 min.*?AddMinutes\(-30\); \$hi = \$fs\.AddMinutes\(30\)')
Check "B10: top-card comment and the window constant agree on 30" $mB10a.Success
$mB10b = [regex]::Match($src, '(?s)\+/-30 min context window around first seen.*?\$fs\.AddMinutes\(-30\)')
Check "B10: context-window comment matches the AddMinutes(-30) code" $mB10b.Success

# ===================== B18: dead wildcard fallback in the emptyWhy lookup =====================
$whyMap268 = [regex]::Match($src, '(?s)\$emptyWhy = \@\{.*?\r?\n    \}')
Check "B18: emptyWhy map extractable" $whyMap268.Success
$starredKeys = @([regex]::Matches($whyMap268.Value, "'([^']*)'\s*=") | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_.Contains('*') })
Check "B18: no $emptyWhy key is starred (precondition for the dead-foreach deletion)" ($starredKeys.Count -eq 0)
Check "B18: dead wildcard foreach deleted from the emptyWhy lookup" (-not $src.Contains('foreach ($wk in $emptyWhy.Keys)'))
Check "B18: exact-name emptyWhy lookup survives" ($src.Contains('$why = $emptyWhy[$base]'))
# the desc map's OWN wildcard lookup (alive, different map) stays
Check "B18: desc-map wildcard lookup untouched" ($src.Contains('foreach ($k in $desc.Keys)'))

# ===================== B17: no Write-Host argument commas (sweep guard) =====================
Check "B17: no '..., -ForegroundColor' argument comma in any Write-Host" (-not ([regex]::IsMatch($src, 'Write-Host [^\r\n]*",\s*-Fore')))
Check "B17: no Write-Host line ends with an argument comma" (-not ([regex]::IsMatch($src, '(?m)^\s*Write-Host [^\r\n]*[\w"],\s*$')))

# ===================== v2.68 Task 2 (B11-B16): cosmetic/wording batch =====================
#   B11 confbar bar width + bar label derive from ONE rounded integer (was: [int] truncated
#       the bar while the text rendered the raw value - a fractional provenance would show a
#       95% bar next to a 95.6% label)
#   B12 ATT&CK section counts a rule under EVERY tagged tactic (was: first tactic only) and
#       the technique table's Tactic cell lists the full label set
#   B13 'First N' captions read 'All N' when N == M (no implied hidden rows); M > N keeps
#       'First N of M' - ps_decoded_commands + the execution-history sibling
#   B14 the sigma drill-down's EID datalist covers the rule's FULL row set (was: embedded
#       share only - budget-truncated EIDs were unfilterable); deduped EIDs are tiny
#   B15 no redundant inline ^(?i) on -match/-notmatch (case-insensitive by default); the
#       .NET [regex]::Match site KEEPS its flag (case-sensitive there) and the
#       test_v235-pinned Read-WizardLine sentinel stays (that file is not editable here)
#   B16 the Process dossier is reachable from the task menu ([P]) - mandatory non-empty
#       process prompt, then the exact -Mode Process CLI invocation (-Path $ParsePath -Indicator)
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
foreach ($n2 in @('Import-CaseCsv', 'Test-CaseCsv', 'ConvertTo-HtmlEsc', 'New-VtLink', 'ConvertTo-CaseFileLink', 'Split-TagList', 'Get-TacticLabel', 'Get-LvlRank', 'New-HtmlReport')) {
    $m2 = [regex]::Match($src, "(?s)function $n2 \{.*?\r?\n\}")
    if (-not $m2.Success) { throw "task2 extract failed: $n2" }
    Invoke-Expression $m2.Value
}

$tmp2 = Join-Path $env:TEMP ("ophira_v268t2_" + (Get-Date -Format 'HHmmss'))
$csvT2 = Join-Path $tmp2 'csv'
New-Item -ItemType Directory -Path $csvT2, (Join-Path $tmp2 'raw\evtx'), (Join-Path $csvT2 'sigma_rules'), (Join-Path $tmp2 'focus') -Force | Out-Null
$CaseDir = $tmp2; $CsvDir = $csvT2; $RawDir = Join-Path $tmp2 'raw'; $MemDir = Join-Path $tmp2 'mem'
$Computer = 'T2HOST'; $Analyst = 'fixture2'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-2'; $script:CurrentAnalyst = 'fixture2'; $script:DeltaBaseline = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Get-LogRangeText { 'analysis window' }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }

# hay fixture (embed budget walks Count-desc): Filler 4965 (take 4965, 35 left)
# -> Big Rule 30 (take 30, 5 left) -> Run Key Rule 8 (take 5 - TRUNCATED, its tail rows
# carry EID 9999) -> Two Tactic Rule 2 (take 0; ATT&CK chips/table still read the full rows)
$hayT2 = New-Object System.Collections.Generic.List[string]
$null = $hayT2.Add('"Timestamp","Computer","EventID","RecordID","Level","RuleTitle","Details","MitreTactics","MitreTags"')
$fBaseT2 = [datetime]'2026-09-20 00:00:00'
1..4965 | ForEach-Object { $null = $hayT2.Add('"' + $fBaseT2.AddMinutes($_).ToString('yyyy-MM-dd HH:mm:ss.000 +00:00') + '","T2HOST","1","rid2-f' + $_ + '","low","Budget Filler Rule","filler ' + $_ + '","",""') }
1..30 | ForEach-Object { $null = $hayT2.Add(('"2026-09-23 09:{0:00}:00.000 +00:00","T2HOST","1102","rid2-b{0}","low","Big Rule","big {0}","",""' -f $_)) }
$rkEidsT2 = @('7045', '1547', '1', '7045', '1547', '9999', '9999', '9999')
1..8 | ForEach-Object { $null = $hayT2.Add('"2026-09-24 10:{0:00}:00.000 +00:00","T2HOST","' + $rkEidsT2[$_-1] + '","rid2-r' + $_ + '","low","Run Key Rule","reg add ' + $_ + '","Persis","T1547.001"') }
1..2 | ForEach-Object { $null = $hayT2.Add(('"2026-09-24 11:{0:00}:00.000 +00:00","T2HOST","4688","rid2-t{0}","high","Two Tactic Rule","whoami {0}","Disc,CredAccess","T1087"' -f $_)) }
$hayT2 | Set-Content -LiteralPath (Join-Path $csvT2 'hayabusa_timeline.csv') -Encoding UTF8

# B13 fixtures: ps commands exactly at the 30 cap (N == M == cap); exec timeline fully shown
$psT2 = New-Object System.Collections.Generic.List[string]
$null = $psT2.Add('"Timestamp","Channel","EventID","DecodedText"')
1..30 | ForEach-Object { $null = $psT2.Add(('"2026-09-24 12:{0:00}:00","PowerShell/Operational","4104","decoded command {0}"' -f $_)) }
$psT2 | Set-Content -LiteralPath (Join-Path $csvT2 'ps_decoded_commands.csv') -Encoding UTF8
@'
"Time","Path"
"2026-09-24 12:00:00","C:\Users\a\evil.exe"
"2026-09-24 12:01:00","C:\Users\a\evil2.exe"
'@ | Set-Content -LiteralPath (Join-Path $csvT2 'execution_timeline.csv') -Encoding UTF8

foreach ($emptyT2 in @('flash_process_scored', 'flash_ioc_hits', 'yara_hits', 'beacon_candidates', 'dns_beacon_candidates', 'memory_live_scan', 'loldrivers_hits', 'entities_accounts', 'entities_remotes', 'srum_usage', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'logging_gaps', 'asep_sweep', 'certificates', 'defender_status', 'defender_threats', 'saved_credentials', 'rdp_client_targets', 'bits_jobs', 'memory_malfind', 'ioc_hits_browser', 'security_bruteforce_candidates', 'flash_public_connections', 'supertimeline', 'posture', 'credential_sweep', 'hunt_findings', 'process_chains', 'ioc_hits_amcache')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvT2 "$emptyT2.csv") -Encoding UTF8
}
'{"Indicator":"evil2.exe","Rounds":1,"HitCount":0,"InstanceCount":0,"Degraded":false,"VerdictHint":"","Masquerade":[],"Paths":[]}' | Set-Content -LiteralPath (Join-Path $tmp2 'focus\focus_terms.json') -Encoding UTF8

# B11 wants a FRACTIONAL confidence: the old bar [int]-truncated 95.6 -> 95 while the label
# showed 95.6 - the shared rounded value must render 96 for both
$script:Verdict = [pscustomobject]@{
    Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 95.6; OwnerLine = 'test owner'
    Signals = @(); Caveats = @(); Coverage = @(); CoveragePercentUnadjusted = 96
    CoverageSourcesCollected = 3; CoverageSourcesTotal = 4; Counts = $null; GeneratedUTC = 'x'
}
$null = New-HtmlReport
$htmlT2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

# ---- B11: confidence bar width and label agree ----
Check "B11: fractional 95.6 renders width:96 AND label 96 from one rounded value" (($htmlT2.Contains("width:96%;background:#b93")) -and ($htmlT2.Contains("<div class='conftext'>96% weighted (3/4 sources, 1 missing)")))
Check "B11: no [int] truncation left on the confbar width" (-not $src.Contains('[int]$v.ConfidencePercent'))
Check "B11: conftext reads the shared `$confPct (v2.77: weighted percent + raw fraction, no collision)" ($src.Contains('<div class=''conftext''>$confPct% weighted ($($v.CoverageSourcesCollected)/'))

# ---- B12: ATT&CK tactic chips + technique Tactic cell cover every tagged tactic ----
Check "B12: two-tactic rule counts under BOTH chips (Discovery AND Credential Access)" (($htmlT2.Contains("<span class='tac hi'>Discovery : 2</span>")) -and ($htmlT2.Contains("<span class='tac hi'>Credential Access : 2</span>")))
Check "B12: technique table Tactic cell lists the full label set" ($htmlT2.Contains('<td>Discovery, Credential Access</td>'))
Check "B12: first-tactic-only truncation gone from the ATT&CK row walk" (-not $src.Contains('"$($r.MitreTactics)" | Select-Object -First 1'))
Check "B12: the walk keeps the full Split-TagList result" ($src.Contains('$tacs = @(Split-TagList "$($r.MitreTactics)")'))

# ---- B13: equals-cap captions stop implying hidden rows ----
Check "B13: 30-of-30 ps caption reads 'All 30 recovered commands'" (($htmlT2.Contains('All 30 recovered commands')) -and (-not $htmlT2.Contains('First 30 recovered commands')))
Check "B13: exec caption reads 'All 2 entries' when everything is shown" (($htmlT2.Contains('All 2 entries - full: csv\execution_timeline.csv')) -and (-not $htmlT2.Contains('First 2 of 2 entries')))
Check "B13: M > N still says 'First 30 of M' (source pin)" ($src.Contains('"First 30 of $($psCmds.Count)"'))
Check "B13: exec sibling uses the same equals-cap shape" (($src.Contains('"First $shown of $($execRows.Count) entries"')) -and ($src.Contains('"All $shown entries"')))

# ---- B14: EID datalist from the FULL row set ----
$dlistT2 = [regex]::Match($htmlT2, "(?s)<datalist id='ed_Run_Key_Rule'>(.*?)</datalist>").Groups[1].Value
Check "B14: truncated rule summary stays honest (5 of 8 embedded)" ($htmlT2.Contains('Run Key Rule</b></span> - 8 hit(s), showing 5 of 8 embedded'))
Check "B14: EID datalist covers the full row set - budget tail's 9999 included" (($dlistT2 -match '<option>7045</option>') -and ($dlistT2 -match '<option>1547</option>') -and ($dlistT2 -match '<option>1</option>') -and ($dlistT2 -match '<option>9999</option>'))
Check "B14: datalist built from the rule's full `$g.Group (source pin)" ($src.Contains('@($g.Group | ForEach-Object { "$($_.EventID)" } | Sort-Object -Unique)'))
Check "B14: embedded-only `$eids list gone" (-not $src.Contains('$eids = New-Object'))

# ---- B15: redundant ^(?i) swept from inline -match/-notmatch literals ----
$leftT15 = @([regex]::Matches($src, '-(?:not)?match\s+''\^\(\?i\)'))
Check "B15: exactly ONE inline ^(?i) -match literal left - the test_v235-pinned Read-WizardLine sentinel" (($leftT15.Count -eq 1) -and $src.Contains('if ($v -match ''^(?i)b(ack)?$'') { return $null }'))
Check "B15: .NET [regex]::Match site keeps its (?i) (case-sensitive by default there)" ($src.Contains("[regex]::Match(`$u, '^(?i)https?://([^/:]+)')"))
Check "B15: representative verdict sites cleaned" (-not $src.Contains("-match '^(?i)(high|critical)$'"))

# ---- B16: Process dossier reachable from the task menu ----
$mMenuT2 = [regex]::Match($src, "(?s)function Show-TaskMenu \{.*?\r?\n\}")
Check "B16: Show-TaskMenu extractable" $mMenuT2.Success
if ($mMenuT2.Success) {
    Invoke-Expression $mMenuT2.Value
    function Clear-Host { }
    $script:menuQT2 = New-Object System.Collections.Queue
    $script:menuQT2.Enqueue('p'); $script:menuQT2.Enqueue('q')
    function Read-Host { param([string]$Prompt) $script:menuQT2.Dequeue() }
    Check "B16: menu [P] returns 'Process' (behavioral, shadowed prompts)" ((Show-TaskMenu) -eq 'Process')
}
Check "B16: [P] menu line rendered" ($src.Contains('[P]  Process dossier (deep-dive one process in a case)'))
Check "B16: menu key 'p' dispatches Process" ($src.Contains("'^(?i)p`$' { return 'Process' }"))
Check "B16: menu Process arm prompts mandatory non-empty then calls the CLI invocation" (($src.Contains('while (-not $pn)')) -and ($src.Contains('Invoke-FocusEngine -Path $ParsePath -Indicator $pn')))
Check "B16: old bare Process menu arm gone (was Invoke-FocusEngine without -Indicator)" (-not $src.Contains("'Process' { Invoke-FocusEngine | Out-Null }"))
Check "B16: ValidateSet still carries 'Process' (CLI path intact)" ($src.Contains("'Parse', 'Process', 'Timeline'"))

Remove-Item -LiteralPath $tmp2 -Recurse -Force -ErrorAction SilentlyContinue

if ($pass -eq 0 -and $fail -eq 0) { Write-Host "no checks ran" -ForegroundColor Red; exit 1 }
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
