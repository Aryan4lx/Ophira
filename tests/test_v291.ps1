# test_v291.ps1 - v2.91 truth-first batch:
#   A1 supertimeline UTC-dialect split ($addUtc + -IsUtc weave routing)
#   A2 R38 UTC-normalized earliest-stamp hour buckets
#   A3 R37 Win10 (10ts) order-check gate
#   A4 Get-IpCloudClass specific-first overrides
#   A5 Get-DomainProvider user-hosting platforms removed
#   A6 coverage spine accepts execution_timeline.csv
$ErrorActionPreference = 'Stop'
$passed = 0; $failed = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { $script:passed++; Write-Host "  [ok] $name" }
    else { $script:failed++; Write-Host "  [FAIL] $name" }
}
$repo = Split-Path -Parent $PSScriptRoot
$src = [IO.File]::ReadAllText((Join-Path $repo 'Ophira.ps1'))
function Get-Extracted([string]$name) {
    $m = [regex]::Match($script:src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $name failed" }
    return $m.Value
}
$Check = { param($n, $o) Check $n $o }

# shared helper the timeline/hunt code calls
. ([ScriptBlock]::Create((Get-Extracted 'Get-InvariantDate')))
. ([ScriptBlock]::Create((Get-Extracted 'New-HuntFindings')))
. ([ScriptBlock]::Create((Get-Extracted 'Get-IpCloudClass')))
. ([ScriptBlock]::Create((Get-Extracted 'Get-DomainProvider')))

# stubs captured per-phase
$script:caseCsv = @{}
$script:savedRows = @{}
function Import-CaseCsv([string]$Name) { if ($null -ne $script:caseCsv[$Name]) { return @($script:caseCsv[$Name]) } return @() }
function Save-Rows([string]$Name, $Rows) { $script:savedRows[$Name] = @($Rows) }
function Write-CaseLog([string]$m, [string]$c = 'Gray') { }
function QuietLog([string]$m) { }
function Get-CaseCsvFullPath([string]$Name) { return Join-Path $script:tmpDir "$Name.csv" }
function Get-CaseCsvPath([string]$Name) { return "$Name.csv" }
function Test-CaseCsv([string]$Name) { return ($null -ne $script:caseCsv[$Name]) }
function Get-HayabusaExe { return $null }
function Get-ToolsDir { return $null }
function Invoke-NativeTool { return $null }
function Get-KnownBadRegexes { return @() }

Write-Host "== P1: supertimeline UTC dialects (A1) =="
$script:tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("oph291_" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $script:tmpDir -Force | Out-Null
$tl = Get-Extracted 'New-SuperTimeline'
$tlFix = @'
# fixture injection
$script:caseCsv['prefetch_parsed'] = @(
    [pscustomobject]@{ ExecutableName = 'WWAHOST.EXE'; RunCount = '3'; LastRun = '2026-08-18 22:51:22' }
)
$script:caseCsv['security_auth_events'] = @(
    [pscustomobject]@{ Time = '2026-08-18 22:51:22'; EventId = '4624'; Account = 'DOM\u'; LogonId = '0x1'; LogonType = '2'; SourceIp = '10.0.0.5' }
)
$script:caseCsv['iis_requests'] = @(
    [pscustomobject]@{ Time = '2026-10-29 08:04:08'; Method = 'GET'; Uri = '/x'; Status = '200'; ClientIp = '1.2.3.4'; UserAgent = 'ua' }
)
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ Name = 'tool.exe'; SourceFile = 'Amcache.hve'; FileKeyLastWriteTimestamp = '2026-08-19 10:40:17.123' }
)
'@
$tlTest = $tlFix + "`n" + $tl + "`n" + 'New-SuperTimeline' + "`n" + @'
$tlRows = Import-Csv (Join-Path $script:tmpDir 'supertimeline.csv')
Check 'P1: prefetch naive-UTC stamp NOT shifted (-3:30 bug gone)' ((@($tlRows | Where-Object { $_.Source -eq 'prefetch_parsed' }).Timestamp) -contains '2026-08-18 22:51:22')
Check 'P1: prefetch stamp not the shifted value' (-not ((@($tlRows | Where-Object { $_.Source -eq 'prefetch_parsed' }) | ForEach-Object { "$($_.Type)=$($_.Timestamp)" }) -contains 'execution=2026-08-18 19:21:22'))
Check 'P1: 4624 local stamp still converted to UTC' ((@($tlRows | Where-Object { $_.Source -eq 'security_auth_events' }).Timestamp) -contains '2026-08-18 19:21:22')
Check 'P1: iis W3C stamp kept (UTC dialect)' ((@($tlRows | Where-Object { $_.Source -eq 'iis_requests' }).Timestamp) -contains '2026-10-29 08:04:08')
Check 'P1: amcache fractional stamp normalized unshifted' ((@($tlRows | Where-Object { $_.Source -eq 'amcache' }).Timestamp) -contains '2026-08-19 10:40:17')
'@
Invoke-Expression $tlTest

Write-Host "== P2: R37 Win10 order-check gate (A3) =="
$hf = Get-Extracted 'New-HuntFindings'
$stub = @'
# stubs for the hunt engine (R37/R38 focus)
function Get-LevenshteinDistance { param($a,$b) return 9 }
function Test-IsUserWritablePath { param($Path) return $Path -match '\\Temp\\' }
$script:caseCsv['amcache'] = @()
$script:caseCsv['prefetch_parsed'] = @()
$script:caseCsv['bam_lastexec'] = @()
$script:caseCsv['processes'] = @()
$script:caseCsv['services'] = @()
$script:caseCsv['scheduled_taskcache'] = @()
$script:caseCsv['esent_ntds'] = @()
$script:caseCsv['recon_sessions'] = @()
$script:caseCsv['exec_stacks_byname'] = @()
$script:caseCsv['connections_dns'] = @()
$script:caseCsv['flash_public_connections'] = @()
$script:caseCsv['connections_public_established'] = @()
$script:caseCsv['security_proc_events'] = @()
$script:caseCsv['sysmon_proc_create'] = @()
$script:caseCsv['session_activity'] = @()
$script:caseCsv['process_chains'] = @()
$script:caseCsv['yara_scanned'] = @()
$script:caseCsv['beacons'] = @()
$script:caseCsv['dns_beacon_candidates'] = @()
$script:caseCsv['dns_tunnels'] = @()
$script:caseCsv['browser_files'] = @()
$script:caseCsv['iis_requests'] = @()
$script:caseCsv['hayabusa_timeline'] = @()
'@
$r37w10 = @'
$script:caseCsv['execution_timeline'] = @(
    [pscustomobject]@{ 'Entry Type' = 'ShimcacheFileEntry'; 'File Path' = '\VOLUME{a}\windows\system32\kernel32.dll'; 'Timeline Entry Number' = '0'; 'Raw Entry' = '{"signature":"10ts","last_modified_ts":"2026-05-01 12:00:00"}' },
    [pscustomobject]@{ 'Entry Type' = 'ShimcacheFileEntry'; 'File Path' = '\VOLUME{a}\windows\system32\user32.dll'; 'Timeline Entry Number' = '1'; 'Raw Entry' = '{"signature":"10ts","last_modified_ts":"2026-01-01 08:00:00"}' }
)
New-HuntFindings
Check 'P2: Win10 10ts cache -> NO order-violation finding' (@($script:savedRows['hunt_findings'] | Where-Object { $_.Rule -eq 'ShimCache order violation' }).Count -eq 0)
'@
# Win7-shaped cache (no 10ts signature) still flags
$r37w7 = @'
$script:savedRows['hunt_findings'] = $null
$script:caseCsv['execution_timeline'] = @(
    [pscustomobject]@{ 'Entry Type' = 'ShimcacheFileEntry'; 'File Path' = '\VOLUME{a}\windows\system32\kernel32.dll'; 'Timeline Entry Number' = '0'; 'Raw Entry' = '{"signature":"MAM","last_modified_ts":"2026-05-01 12:00:00"}' },
    [pscustomobject]@{ 'Entry Type' = 'ShimcacheFileEntry'; 'File Path' = '\VOLUME{a}\windows\system32\user32.dll'; 'Timeline Entry Number' = '1'; 'Raw Entry' = '{"signature":"MAM","last_modified_ts":"2026-01-01 08:00:00"}' }
)
New-HuntFindings
Check 'P2: Win7-era cache STILL flags order violation' (@($script:savedRows['hunt_findings'] | Where-Object { $_.Rule -eq 'ShimCache order violation' }).Count -gt 0)
'@
# reset remaining case csvs the P2 runs rely on
$r37reset = @'
$script:caseCsv['scheduled_tasks'] = @(); $script:caseCsv['autoruns_runkeys'] = @(); $script:caseCsv['asep_sweep'] = @()
$script:caseCsv['svchost_audit'] = @(); $script:caseCsv['remote_access'] = @(); $script:caseCsv['usb_devices'] = @()
$script:caseCsv['lnk_parsed'] = @(); $script:caseCsv['shellbags'] = @(); $script:caseCsv['recyclebin_index'] = @()
$script:caseCsv['office_mru'] = @(); $script:caseCsv['startup_info'] = @(); $script:caseCsv['wer_reports'] = @()
$script:caseCsv['mft_recent'] = @(); $script:caseCsv['usn_write_bursts'] = @(); $script:caseCsv['drivers'] = @()
$script:caseCsv['loldrivers_hits'] = @(); $script:caseCsv['srum_usage'] = @(); $script:caseCsv['browser_downloads'] = @()
$script:caseCsv['sysmon_image_load'] = @(); $script:caseCsv['sysmon_registry'] = @(); $script:caseCsv['sysmon_file_time'] = @()
$script:caseCsv['sysmon_file_create'] = @(); $script:caseCsv['sysmon_file_delete'] = @(); $script:caseCsv['sysmon_network'] = @()
$script:caseCsv['sysmon_dns'] = @(); $script:caseCsv['sysmon_process_access'] = @(); $script:caseCsv['sysmon_remote_thread'] = @()
$script:caseCsv['sysmon_pipes'] = @(); $script:caseCsv['sysmon_proc_tamper'] = @(); $script:caseCsv['sysmon_raw_access'] = @()
$script:caseCsv['security_share_access'] = @(); $script:caseCsv['security_task_install'] = @(); $script:caseCsv['task_deletions'] = @()
$script:caseCsv['security_kerberos'] = @(); $script:caseCsv['security_ds_access'] = @(); $script:caseCsv['defender_config_events'] = @()
$script:caseCsv['defender_threats'] = @(); $script:caseCsv['browser_history'] = @()
$script:caseCsv['appswitched'] = @(); $script:caseCsv['radar_exec'] = @(); $script:caseCsv['shimcache_exec'] = @()
$script:caseCsv['exec_stacks_bypath'] = @(); $script:caseCsv['exec_window_ratio'] = @()
'@
Invoke-Expression ($stub + "`n" + $r37reset + "`n" + $r37w10)
Invoke-Expression ($r37reset + "`n" + $r37w7)

Write-Host "== P3: R38 UTC buckets + earliest stamp (A2) =="
$r38t = @'
$script:savedRows['hunt_findings'] = $null
# amcache (UTC dialect): evil.exe rows 10:00 UTC then 03:00 UTC - earliest (03:00) must win;
# 7 more tools at 03:00 push the 03:00 bucket to 8 distinct = burst threshold.
# If first-row-wins remained, evil.exe would sit at 10:00 (on-hours) and 03:00 would hold only 7 -> no finding.
$r38rows = @(
    [pscustomobject]@{ Name = 'evil.exe'; FullPath = 'c:\temp\evil.exe'; FileKeyLastWriteTimestamp = '2026-08-19 10:00:00'; SourceFile = 'Amcache.hve' },
    [pscustomobject]@{ Name = 'evil.exe'; FullPath = 'c:\temp\evil.exe'; FileKeyLastWriteTimestamp = '2026-08-19 03:00:00'; SourceFile = 'Amcache.hve' }
)
1..7 | ForEach-Object { $r38rows += [pscustomobject]@{ Name = "tool$_.exe"; FullPath = "c:\temp\tool$_.exe"; FileKeyLastWriteTimestamp = '2026-08-19 03:00:00'; SourceFile = 'Amcache.hve' } }
$script:caseCsv['amcache'] = $r38rows
# 4688 (LOCAL dialect): wall-clock 03:00 local = 23:30 UTC prev day (off-hours too, different bucket)
$script:caseCsv['security_proc_events'] = @(
    [pscustomobject]@{ Time = '2026-08-19 03:00:00'; EventId = '4688'; Account = 'u'; NewProcess = 'c:\windows\system32\notepad.exe'; CommandLine = ''; ParentProcess = 'explorer.exe' }
)
New-HuntFindings
$tr38 = (@($script:savedRows['hunt_findings']) | Where-Object { $_.Rule -eq 'Off-hours execution burst' })
$ent38 = (@($tr38) | ForEach-Object { "$($_.Entity)" }) -join ';'
$det38 = (@($tr38) | ForEach-Object { "$($_.Evidence)" }) -join ';'
$comb = @(@($tr38) | Where-Object { "$($_.Entity)" -eq '03:00-03:59 UTC' -and "$($_.Evidence)" -match '\b8\b distinct' })
Check 'P3: burst finding labels hours UTC' ("$ent38 $det38" -match 'UTC')
Check 'P3: earliest-stamp wins (evil.exe at 03:00 -> 8 distinct -> finding exists)' ($comb.Count -eq 1)
Check 'P3: local 4688 shifted to UTC (23:30 bucket, no 9-distinct double-count)' (-not ("$det38" -match '9 distinct'))
'@
Invoke-Expression ($r37reset + "`n" + $r38t)

Write-Host "== P4: Get-IpCloudClass specific-first (A4) =="
. ([ScriptBlock]::Create((Get-Extracted 'Get-IpCloudClass')))
Check 'P4: google 34.64-127 not amazon' ((Get-IpCloudClass '34.66.1.1') -eq 'google')
Check 'P4: akamai 104.64-127 not microsoft' ((Get-IpCloudClass '104.100.5.5') -eq 'akamai')
Check 'P4: google 104.196-247 (overlap band) wins' ((Get-IpCloudClass '104.220.3.3') -eq 'google')
Check 'P4: cloudflare 103.21 not microsoft' ((Get-IpCloudClass '103.21.5.5') -eq 'cloudflare')
Check 'P4: cloudflare 198.41 not microsoft' ((Get-IpCloudClass '198.45.1.1') -eq 'cloudflare')
Check 'P4: google 199.36-159 not microsoft' ((Get-IpCloudClass '199.50.1.1') -eq 'google')
Check 'P4: microsoft 104.40 still microsoft' ((Get-IpCloudClass '104.40.1.1') -eq 'microsoft')
Check 'P4: azure 4.213 still microsoft' ((Get-IpCloudClass '4.213.25.242') -eq 'microsoft')

Write-Host "== P5: Get-DomainProvider user-hosting removal (A5) =="
. ([ScriptBlock]::Create((Get-Extracted 'Get-DomainProvider')))
Check 'P5: evil.github.io NO LONGER microsoft' ((Get-DomainProvider 'evil.github.io') -eq '')
Check 'P5: anything.pages.dev NO LONGER cloudflare' ((Get-DomainProvider 'anything.pages.dev') -eq '')
Check 'P5: github.com still microsoft (MS-operated infra)' ((Get-DomainProvider 'api.github.com') -eq 'microsoft')
Check 'P5: microsoft.com still microsoft' ((Get-DomainProvider 'www.microsoft.com') -eq 'microsoft')
Check 'P5: cloudfront still amazon' ((Get-DomainProvider 'd2x.cloudfront.net') -eq 'amazon')

Write-Host "== P6: coverage spine + wiring (A6) =="
Check 'P6: coverage spine accepts execution_timeline' ($src.Contains("-or (Test-CaseCsv 'execution_timeline')) 3"))
Check 'P6: $addUtc exists' ($src.Contains('$addUtc = {'))
Check 'P6: AssumeUniversal used' ($src.Contains('AssumeUniversal'))
Check 'P6: UTC weaves declared' (([regex]::Matches($src, '-IsUtc \$true')).Count -eq 12)
Check 'P6: version bumped' ($src.Contains('$ScriptVersion = "2.91"'))

Remove-Item $script:tmpDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "RESULT: $passed passed, $failed failed"
if ($failed -gt 0) { exit 1 } else { exit 0 }
