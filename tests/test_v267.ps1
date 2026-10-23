# test_v267.ps1 - v2.67 quick fixes:
#   B1 New-VtLink stops VT-linking file paths / executable+document filenames (process names
#       like OneDrive.exe rendered as VT search links - analyst noise, not a lookup). Hashes,
#       IPs and real domains keep linking; signature and HTML shape unchanged.
#   B6 browser_files gets an evidence-index description (was the only blank 'What it is' row).
#   B2 entity category tokens (svc-persist, 4688-exec, ...) resolve to section anchors so the
#       "appears in:" chips and lead-card chips become links; artifact-name behavior unchanged.
#   B4 memory_live_scan anchors to hunt (live memory triage table), memory_netscan stays
#       unmapped (CSV-only), memory_malfind keeps snapshot.
#   B3 Open-CaseSession keeps EndpointAdmin tri-state: legacy case.json records
#       AdminElevated as null (unknown) - [bool]$null collapsed it to $false, so the
#       verdict applied the non-admin penalty and claimed "Run was NOT elevated" while
#       the report banner honestly showed 'Elevated: unknown'.
#   B9 DeltaBaseline is per-case: Open-CaseSession resets it (no stale leak / no empty
#       "()" in the delta heading), and the heading drops the parens when unknown.
#   Floor pin: verdict signal floors serialize as the 'Weight' property (the R&D session
#       that read '.Floor' used the wrong property name - not a serialization bug).
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$defs = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Get-SectionAnchorForSource')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- B1: file paths / executable+document filenames render NO link (escaped label only) ----
foreach ($fn in @('OneDrive.exe', 'node.exe', 'FileCoAuth.exe', 'svcghost.dll', 'report.pdf', 'run.bat', 'install.msi', 'evil.scr', 'lib.jar', 'archive.rar', 'notes.txt', 'data.dat', 'svchost.mui', 'C:\Windows\evil.bat', '\\share\x.dat', 'my file.txt')) {
    $r = New-VtLink $fn
    Check "B1: '$fn' renders no VT anchor" (-not $r.Contains('<a'))
    Check "B1: '$fn' label passthrough (escaped)" ($r -eq (ConvertTo-HtmlEsc $fn))
}

# ---- B1: hashes, IPs and domains KEEP linking ----
foreach ($ioc in @('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'd41d8cd98f00b204e9800998ecf8427e', '192.168.1.10', 'evil.com', 'EVIL.COM', 'malware-c2.evil.co.uk')) {
    $r = New-VtLink $ioc
    Check "B1: '$ioc' still VT-links" (($r.StartsWith('<a ')) -and $r.Contains('virustotal.com/gui/search/'))
}

# ---- B1: signature / output shape unchanged ----
Check "B1: label param honored for non-linked indicators" ((New-VtLink 'OneDrive.exe' 'OneDrive') -eq 'OneDrive')
Check "B1: VT anchor HTML format unchanged" ((New-VtLink 'evil.com') -eq "<a target='_blank' href='https://www.virustotal.com/gui/search/evil.com'>VT&nearr;</a>")

# ---- B6: browser_files has an evidence-index DESCRIPTION entry (not the artifact-category
# map at the top of the script, which also has a 'browser_files' key - anchor on the desc-map
# 'Parsed browser history' wording to disambiguate) ----
$bhDesc = [regex]::Match($src, "'browser_history'\s*=\s*'Parsed browser history")
Check "B6: desc map located via browser_history description" ($bhDesc.Success)
if ($bhDesc.Success) {
    $winStart = [math]::Max(0, $bhDesc.Index - 600)
    $win = $src.Substring($winStart, [math]::Min(1200, $src.Length - $winStart))
    $bfDesc = [regex]::Match($win, "'browser_files'\s*=\s*'([^']+)'")
    Check "B6: browser_files desc entry sits in the desc map browser_* cluster" ($bfDesc.Success -and ($bfDesc.Groups[1].Value.Trim().Length -gt 5))
    Check "B6: desc value is not the category-map stub" ($bfDesc.Success -and $bfDesc.Groups[1].Value -ne 'artifacts')
}

# ---- B2/B4: entity category tokens + memory anchors ----
# rendered anchor set (every <a name='...'> target the report actually emits)
$renderedAnchors = @('attack', 'beacons', 'coverage', 'draft', 'drivers', 'entities', 'evidence', 'filesystem', 'focus', 'hunt', 'ioc', 'leads', 'logons', 'network', 'persistence', 'processes', 'pscmds', 'recommendations', 'sigma', 'snapshot', 'tactics', 'timeline', 'verdict', 'yara')

# verified token vocabulary - every token the correlation builder stamps into entity
# Evidence/Categories, mapped to the section that actually renders that data
$tokMap = @{
    'running' = 'processes'; 'hash' = 'processes'; 'verdict' = 'processes'
    '4688-exec' = 'timeline'; 'share-staging' = 'timeline'; 'web-anomaly' = 'timeline'
    'beacon' = 'beacons'; 'conn' = 'network'; 'srum-usage' = 'entities'
    'svc-persist' = 'persistence'; 'task-persist' = 'persistence'; 'autorun-persist' = 'persistence'
    'mft-created' = 'filesystem'; 'loldriver' = 'drivers'; 'ioc' = 'ioc'; 'yara' = 'yara'
    'sigma' = 'sigma'; 'hunt' = 'hunt'
}
foreach ($kv in $tokMap.GetEnumerator()) {
    Check "B2: token '$($kv.Key)' -> $($kv.Value)" ((Get-SectionAnchorForSource $kv.Key) -eq $kv.Value)
}

# B4: memory anchors (live scan table renders in hunt; malfind table renders in snapshot;
# netscan is CSV-only and must stay an honest unmapped chip)
Check "B4: memory_live_scan -> hunt (live memory triage table)" ((Get-SectionAnchorForSource 'memory_live_scan') -eq 'hunt')
Check "B4: memory_malfind -> snapshot (malfind table)" ((Get-SectionAnchorForSource 'memory_malfind') -eq 'snapshot')
Check "B4: memory_netscan stays unmapped (CSV-only, never rendered)" ((Get-SectionAnchorForSource 'memory_netscan') -eq '')

# artifact-name behavior pinned as-is (v2.56 switch arms byte-identical)
$artMap = @{
    'hayabusa' = 'sigma'; 'yara_scan' = 'yara'; 'beacon_candidates' = 'beacons'; 'dns_beacon_candidates' = 'beacons'
    'flash_process_scored' = 'processes'; 'process_hashes' = 'processes'; 'mft_recent' = 'filesystem'
    'loldrivers' = 'drivers'; 'supertimeline' = 'timeline'; 'entities_ip' = 'snapshot'
    'hunt_findings' = 'hunt'; 'ioc_hits_amcache' = 'ioc'; 'security_auth_events' = 'logons'
    'autoruns_runkeys' = 'persistence'; 'sysmon_network' = 'network'
}
foreach ($kv in $artMap.GetEnumerator()) {
    Check "artifact '$($kv.Key)' -> $($kv.Value) (unchanged)" ((Get-SectionAnchorForSource $kv.Key) -eq $kv.Value)
}

# every anchor the mapper emits for the representative input set exists in the rendered report
foreach ($inp in @($tokMap.Keys + $artMap.Keys + @('totally_unknown_source'))) {
    $a = Get-SectionAnchorForSource "$inp"
    if (@('memory_netscan', 'totally_unknown_source') -contains $inp) {
        Check "B2: '$inp' returns no anchor (honest dead chip)" ($a -eq '')
    } else {
        Check "B2: '$inp' anchor '$a' exists in the rendered report" ($renderedAnchors -contains $a)
    }
}

# lead-card chips route through the mapper (source scan around the corroboration block)
$lcIdx = $src.IndexOf('corroborated by')
Check "B2: lead-card chip block found in source" ($lcIdx -ge 0)
if ($lcIdx -ge 0) {
    $lcWin = $src.Substring($lcIdx, [Math]::Min(1200, $src.Length - $lcIdx))
    Check "B2: lead-card chips route through Get-SectionAnchorForSource" ($lcWin.Contains('Get-SectionAnchorForSource'))
    Check "B2: mapped lead chips render the linked-chip shape" ($lcWin.Contains('<a href=''#$anch''><span class=''chip''>'))
    Check "B2: unmapped lead chips keep the grey/dead class" ($lcWin.Contains('chipdead'))
}

# ---- Task 3 / B3: EndpointAdmin tri-state (legacy AdminElevated null stays unknown) ----
Check "B3: Open-CaseSession no longer [bool]-collapses AdminElevated" (-not $src.Contains('$script:EndpointAdmin = [bool]$meta.AdminElevated'))
$ocs = [regex]::Match($src, "(?s)function Open-CaseSession \{.*?\r?\n\}")
Check "B3: Open-CaseSession extractable" $ocs.Success
Check "B3: tri-state guard at the AdminElevated site" ($ocs.Success -and $ocs.Value.Contains('if ($null -ne $rawAdmin) { [bool]$rawAdmin } else { $null }'))
# ---- Task 3 / B9: DeltaBaseline per-case reset + conditional heading ----
Check "B9: Open-CaseSession initializes DeltaBaseline to empty" ($ocs.Success -and $ocs.Value.Contains("`$script:DeltaBaseline = ''"))
Check "B9: unconditional baseline-paren heading removed" (-not $src.Contains('<h2>NEW since previous collection ($(ConvertTo-HtmlEsc $script:DeltaBaseline))</h2>'))
Check "B9: bare heading variant present" ($src.Contains('<h2>NEW since previous collection$deltaLbl</h2>'))
Check "B9: baseline label conditional on non-empty DeltaBaseline" ($src.Contains('if ("$($script:DeltaBaseline)")'))

# ---- Task 3 / B3+B9 behavioral: Open-CaseSession is self-contained - drive it for real ----
if ($ocs.Success) {
    Invoke-Expression $ocs.Value
    $caseTmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_t267_b3_" + (Get-Date -Format 'HHmmss'))
    New-Item -ItemType Directory -Path $caseTmp -Force | Out-Null
    $cjPath = Join-Path $caseTmp 'case.json'

    # legacy case: AdminElevated recorded as null (unknown) - must stay null
    Set-Content -LiteralPath $cjPath -Encoding UTF8 -Value '{"Computer":"T3HOST","CaseID":"C-NULL","Analyst":"fx","AdminElevated":null,"SysmonPresent":true,"StartedUTC":"2026-10-19T10:00:00Z"}'
    $script:EndpointAdmin = $true # pre-poison: old code flips this to $false
    $null = Open-CaseSession -Path $caseTmp
    Check "B3: AdminElevated null stays null (unknown, not False)" ($null -eq $script:EndpointAdmin)

    Set-Content -LiteralPath $cjPath -Encoding UTF8 -Value '{"Computer":"T3HOST","CaseID":"C-T","Analyst":"fx","AdminElevated":true,"SysmonPresent":true,"StartedUTC":"2026-10-19T10:00:00Z"}'
    $script:EndpointAdmin = 'poison'
    $null = Open-CaseSession -Path $caseTmp
    Check "B3: AdminElevated true stays true" ($script:EndpointAdmin -eq $true)

    Set-Content -LiteralPath $cjPath -Encoding UTF8 -Value '{"Computer":"T3HOST","CaseID":"C-F","Analyst":"fx","AdminElevated":false,"SysmonPresent":true,"StartedUTC":"2026-10-19T10:00:00Z"}'
    $script:EndpointAdmin = 'poison'
    $null = Open-CaseSession -Path $caseTmp
    Check "B3: AdminElevated false stays false" ($script:EndpointAdmin -eq $false)

    Set-Content -LiteralPath $cjPath -Encoding UTF8 -Value '{"Computer":"T3HOST","CaseID":"C-MISS","Analyst":"fx","SysmonPresent":true,"StartedUTC":"2026-10-19T10:00:00Z"}'
    $script:EndpointAdmin = 'poison'
    $null = Open-CaseSession -Path $caseTmp
    Check "B3: missing AdminElevated property stays null" ($null -eq $script:EndpointAdmin)

    # B9: stale baseline from a previous case resets on adoption
    Set-Content -LiteralPath $cjPath -Encoding UTF8 -Value '{"Computer":"T3HOST","CaseID":"C-B9","Analyst":"fx","AdminElevated":true,"SysmonPresent":true,"StartedUTC":"2026-10-19T10:00:00Z"}'
    $script:DeltaBaseline = 'stale_OPHIRA_OLD.zip'
    $null = Open-CaseSession -Path $caseTmp
    Check "B9: stale DeltaBaseline resets to empty on case adoption" ($script:DeltaBaseline -eq '')

    Remove-Item -LiteralPath $caseTmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- Task 3: floor serialization pin (signal floors ride the 'Weight' property) ----
$mAS = [regex]::Match($src, "(?s)function Add-Signal\(.*?\r?\n    \}")
Check "Floor: nested Add-Signal extractable" $mAS.Success
if ($mAS.Success) {
    Check "Floor: Add-Signal stamps the floor as the Weight property" ($mAS.Value.Contains('Weight = $floor'))
    $signals = New-Object System.Collections.Generic.List[object]
    Invoke-Expression $mAS.Value
    Add-Signal 'Unit test signal' 3 2 'evidence detail'
    $vj = [pscustomobject]@{ Level = 'LIKELY COMPROMISED'; LevelRank = 3; Signals = $signals.ToArray() } | ConvertTo-Json -Depth 5
    $back = $vj | ConvertFrom-Json
    Check "Floor: serialized verdict JSON carries Weight: 3" ($vj -match '"Weight":\s*3')
    Check "Floor: no Floor property exists to read empty" (-not ($vj -match '"Floor"'))
    Check "Floor: round-trip reads Weight non-empty (R&D '.Floor' reader was the bug)" ("$($back.Signals[0].Weight)" -eq '3')
}

# ===================== Task 4 (v2.67): B5 blank-cell casts + R1 empty-why completeness =====================
# ---- B5 behavioral: ConvertTo-SafeInt / ConvertTo-SafeDbl never throw on blank/garbage cells ----
$msi = [regex]::Match($src, "(?s)function ConvertTo-SafeInt \{.*?\r?\n\}")
$msd = [regex]::Match($src, "(?s)function ConvertTo-SafeDbl \{.*?\r?\n\}")
Check "B5: ConvertTo-SafeInt extractable (column-0 closing brace)" $msi.Success
Check "B5: ConvertTo-SafeDbl extractable (column-0 closing brace)" $msd.Success
if ($msi.Success -and $msd.Success) {
    Invoke-Expression ($msi.Value + "`r`n" + $msd.Value)
    Check "B5: '' -> 0" ((ConvertTo-SafeInt '') -eq 0)
    Check "B5: 'abc' -> 0" ((ConvertTo-SafeInt 'abc') -eq 0)
    Check "B5: '12' -> 12" ((ConvertTo-SafeInt '12') -eq 12)
    Check "B5: ' 12 ' -> 12 (whitespace tolerated)" ((ConvertTo-SafeInt ' 12 ') -eq 12)
    Check "B5: '-3' -> -3" ((ConvertTo-SafeInt '-3') -eq -3)
    Check "B5: `$null -> 0" ((ConvertTo-SafeInt $null) -eq 0)
    Check "B5: '4294967296' overflow degrades to 0 (pinned)" ((ConvertTo-SafeInt '4294967296') -eq 0)
    Check "B5: -Default override honored" ((ConvertTo-SafeInt '' -Default 7) -eq 7)
    Check "B5: SafeDbl '' -> 0" ((ConvertTo-SafeDbl '') -eq 0)
    Check "B5: SafeDbl 'abc' -> 0" ((ConvertTo-SafeDbl 'abc') -eq 0)
    Check "B5: SafeDbl '3.5' -> 3.5" ((ConvertTo-SafeDbl '3.5') -eq 3.5)
    Check "B5: SafeDbl `$null -> 0" ((ConvertTo-SafeDbl $null) -eq 0)

    # Sort-Object scriptblock usage smoke - the exact shape the report sorts use
    $rows4 = @(
        [pscustomobject]@{ Name = 'blank'; Score = '' }
        [pscustomobject]@{ Name = 'two'; Score = '2' }
        [pscustomobject]@{ Name = 'ten'; Score = '10' }
    )
    $sorted4 = @($rows4 | Sort-Object { ConvertTo-SafeInt $_.Score } -Descending)
    Check "B5: Sort-Object { ConvertTo-SafeInt ... } orders numerically, blank sinks" ($sorted4[0].Name -eq 'ten' -and $sorted4[2].Name -eq 'blank')
    # the Where-Object comparison shape - operator must sit OUTSIDE the call (parenthesized)
    $f4 = @($rows4 | Where-Object { (ConvertTo-SafeInt $_.Score) -ge 4 })
    Check "B5: (ConvertTo-SafeInt ...) -ge N filters correctly" ($f4.Count -eq 1 -and $f4[0].Name -eq 'ten')
}

# ---- B5 source-scan: the previously-fatal report casts route through the helpers ----
$lines4 = $src -split "\r?\n"
if ($lines4.Count -ge 6100) {
    # window end widened 6099 -> 6199 (v2.68 Task 2 added ~11 lines upstream, pushing the
    # process-chain sort past the old slice - same report region, no behavioral change)
    # window shifted 5199..6199 -> 5534..6534 (v2.69 F2 help block added ~291 lines above
    # [CmdletBinding()] + ~44 elsewhere upstream - same report region, no behavioral change)
    # window shifted 5534..6534 -> 6021..6601 (v2.77 provenance line / signal sort / hunt-stamp
    # blocks added ~487 lines upstream of the yara Hits guard - same report region)
    # window shifted 6021..6601 -> 6041..6620 (v2.77 fix round 1: ISO-window coercion parse +
    # rounded banner percent added ~20 more upstream lines - same report region)
    # window shifted 6041..6620 -> 6127..6706 (v2.78 nav row counts: the counted-nav build +
    # hoisted reads added ~86 lines upstream of the processes top-30 sort - same report region)
    $region4 = ($lines4[6127..6706] -join "`n")
    Check "B5: no bare [int]quoted casts left in the report region" (-not $region4.Contains('[int]"$('))
    Check "B5: no bare [double]quoted casts left in the report region" (-not $region4.Contains('[double]"$('))
    Check "B5: no bare [long]quoted casts left in the report region" (-not $region4.Contains('[long]"$('))

    $highLead = @($lines4 | Where-Object { $_.Contains('foreach ($p in @(Import-CaseCsv') -and $_.Contains("'HIGH' -and") })
    Check "B5: HIGH lead sort uses ConvertTo-SafeInt (was the quoted [int] cast)" ($highLead.Count -eq 1 -and "$($highLead[0])".Contains('Sort-Object { ConvertTo-SafeInt $_.Score }'))
    $medLead = @($lines4 | Where-Object { $_.Contains("'MEDIUM' -and") -and $_.Contains('flash_process_scored') })
    Check "B5: MEDIUM lead filter+sort use ConvertTo-SafeInt" ($medLead.Count -eq 1 -and "$($medLead[0])".Contains('(ConvertTo-SafeInt $_.Score) -ge 4') -and "$($medLead[0])".Contains('Sort-Object { ConvertTo-SafeInt $_.Score }'))
    $entLine = @($lines4 | Where-Object { $_.Contains('$entAll = @($entB') })[0]
    Check "B5: entity CatCount filter+sort use ConvertTo-SafeInt" ("$entLine".Contains('(ConvertTo-SafeInt $_.CatCount) -ge 2') -and "$entLine".Contains('Sort-Object { ConvertTo-SafeInt $_.CatCount }'))
    $acctLine = @($lines4 | Where-Object { $_.Contains('if ($entA.Count -gt 0') })[0]
    Check "B5: account-entity Logons/Failed/ConsoleHistoryKB use the helpers" ("$acctLine".Contains('(ConvertTo-SafeInt $_.Logons)') -and "$acctLine".Contains('(ConvertTo-SafeInt $_.Failed)') -and "$acctLine".Contains('(ConvertTo-SafeDbl $_.ConsoleHistoryKB)'))
    $remLine = @($lines4 | Where-Object { $_.Contains('if ($entR.Count -gt 0') })[0]
    Check "B5: remote-entity Connections/FailedLogons/RdpOutCount use ConvertTo-SafeInt" ("$remLine".Contains('(ConvertTo-SafeInt $_.Connections)') -and "$remLine".Contains('(ConvertTo-SafeInt $_.FailedLogons)') -and "$remLine".Contains('(ConvertTo-SafeInt $_.RdpOutCount)'))
    Check "B5: account Failed severity class uses ConvertTo-SafeInt" ($region4.Contains('(ConvertTo-SafeInt $a2.Failed) -ge 5') -and $region4.Contains('(ConvertTo-SafeInt $a2.Failed) -gt 0'))
    Check "B5: remote FailedLogons severity class uses ConvertTo-SafeInt" ($region4.Contains('(ConvertTo-SafeInt $e.FailedLogons) -gt 0'))
    Check "B5: SRUM numeric sort uses ConvertTo-SafeDbl (byte counts)" ($region4.Contains('ConvertTo-SafeDbl $p2.Value'))
    Check "B5: prefetch run-count sort uses ConvertTo-SafeInt" ($region4.Contains('ConvertTo-SafeInt $_.$rcCol'))
    Check "B5: process-chain steps sort uses ConvertTo-SafeInt" ($region4.Contains('Sort-Object { ConvertTo-SafeInt $_.Steps }'))
    Check "B5: scored-process top-30 sort uses ConvertTo-SafeInt" ($region4.Contains('Sort-Object { ConvertTo-SafeInt $_.Score }'))
    # deliberately NOT converted: [int]$_.Hits at ~5540 (regex-guarded '^\d+$' short-circuits first)
}

# ---- R1: every zero-row-capable artifact explains itself in the evidence index ----
# single-quoted pattern: '$emptyWhy' must reach the REGEX, not PS string interpolation
$whyMap = [regex]::Match($src, '(?s)\$emptyWhy = \@\{.*?\r?\n    \}')
Check "R1: emptyWhy map extractable" $whyMap.Success
$r1names = @(
    'ads_findings', 'application_events', 'arp_table', 'autoruns_runkeys', 'autoruns_startup_folders',
    'bam_lastexec', 'beacon_candidates', 'bits_jobs', 'browser_files', 'connections_public_established',
    'credential_sweep', 'defender_config_events', 'defender_events', 'defender_preferences', 'defender_status',
    'defender_threats', 'delta_new', 'dns_beacon_candidates', 'dns_cache', 'domain_info',
    'entities_accounts', 'entities_binaries', 'entities_remotes', 'flash_public_connections', 'hunt_findings',
    'iis_anomalies', 'iis_requests', 'ioc_hits_amcache', 'ioc_hits_browser', 'ioc_hits_dns',
    'ioc_hits_hash', 'ioc_hits_mft', 'ioc_hits_network', 'loldrivers_hits', 'logging_gaps',
    'memory_live_scan', 'mft_recent', 'parse_needed', 'powershell_console_history', 'powershell_events',
    'prefetch_index', 'processes_flagged', 'registry_recmd', 'saved_credentials', 'scheduled_tasks_flagged',
    'security_auth_events', 'security_auth_summary', 'security_ds_access', 'security_events', 'security_kerberos',
    'services_flagged', 'shellbags', 'smb_hosted_shares', 'sysmon_dns', 'sysmon_events',
    'sysmon_file_create', 'sysmon_file_delete', 'sysmon_file_time', 'sysmon_image_load', 'sysmon_network',
    'sysmon_pipes', 'sysmon_proc_create', 'sysmon_proc_tamper', 'sysmon_process_access', 'sysmon_raw_access',
    'sysmon_registry', 'sysmon_remote_thread', 'sysmon_wmi', 'system_events', 'ual_files',
    'usb_devices', 'webshell_candidates', 'wer_reports', 'wmi_event_filters', 'yara_scanned'
)
foreach ($n in $r1names) {
    Check "R1: '$n' has an emptyWhy entry" ($whyMap.Success -and [regex]::IsMatch($whyMap.Value, "'$n'\s*=\s*'[^']{10,}'"))
}
# completeness sweep: every Save-Rows artifact outside the never-zero list carries a why
$skipWhy = @(
    'asep_sweep', 'certificates', 'connections', 'drivers', 'firewall_profiles', 'flash_process_scored',
    'logon_sessions', 'net_active_probes', 'net_interfaces', 'net_reachable_subnets', 'posture',
    'process_hashes', 'processes', 'proxy_settings', 'srum_usage', 'scheduled_tasks', 'services'
)
$allArts = @([regex]::Matches($src, "Save-Rows -Name '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$missingWhy = @($allArts | Where-Object { $skipWhy -notcontains $_ -and $whyMap.Success -and -not [regex]::IsMatch($whyMap.Value, "'$($_)'\s*=\s*'[^']{10,}'") })
Check "R1: no Save-Rows artifact renders '0 rows' unexplained (outside the never-zero list)" ($missingWhy.Count -eq 0)
if ($missingWhy.Count -gt 0) { Write-Host "    unexplained: $($missingWhy -join ', ')" -ForegroundColor Yellow }
# sysmon partial-coverage note: mixed has-rows/zero-row sysmon artifacts must flag the blind spot
Check "R1: sysmon has-rows/zero-row mix is computed in the index loop" ($src.Contains('$sysHas++') -and $src.Contains('$sysZero++'))
Check "R1: sysmon partial-coverage note renders on the mix condition" ($src.Contains('if ($sysHas -gt 0 -and $sysZero -gt 0)') -and $src.Contains('Sysmon partial coverage'))

if ($pass -eq 0 -and $fail -eq 0) { Write-Host "no checks ran" -ForegroundColor Red; exit 1 }
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
