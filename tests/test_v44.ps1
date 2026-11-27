# tests\test_v44.ps1 - v4.4: SRUM consumers card, ::ffff: normalization, UserAssist + shellbags joins
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $repo 'Ophira.ps1'
$src = [IO.File]::ReadAllText($srcPath)

$script:pass = 0; $script:fail = 0
function Check { param($Name, $Ok)
    if ($Ok) { $script:pass++; Write-Host "  [ok] $Name" }
    else { $script:fail++; Write-Host "  [FAIL] $Name" -ForegroundColor Red }
}

# ---- P1: Get-IpCloudClass ::ffff: normalization
$fn = [regex]::Match($src, "(?s)function Get-IpCloudClass \{.*?\r?\n\}").Value
Invoke-Expression $fn
Check 'P1: mapped-ipv6 classifies as ipv4' ((Get-IpCloudClass '::ffff:4.213.25.242') -eq 'microsoft')
Check 'P1: plain ipv4 unchanged' ((Get-IpCloudClass '4.213.25.242') -eq 'microsoft')
Check 'P1: uppercase prefix also stripped' ((Get-IpCloudClass '::FFFF:52.94.236.248') -eq 'amazon')
Check 'P1: garbage still empty' ((Get-IpCloudClass 'not-an-ip') -eq '')
Check 'P1: ipv6 non-mapped still empty' ((Get-IpCloudClass '2606:4700::6810:84e5') -eq '')

# ---- P2: v4.4 report fragments with real-ish CSVs
foreach ($name in @('ConvertTo-HtmlEsc','ConvertTo-SafeInt','ConvertTo-SafeDbl','Get-IpCloudClass','Get-DomainProvider')) {
    $m = [regex]::Match($src, "(?s)function $name \{.*?\r?\n\}")
    if ($m.Success) { Invoke-Expression $m.Value }
}
$script:caseCsv = @{
    'hunt_findings.csv' = @()
    'srum_app_totals.csv' = @(
        [pscustomobject]@{ Application = '\device\harddiskvolume4\apps\xray\xray.exe'; Leaf = 'xray.exe'; BytesSent = '5000000000'; BytesReceived = '1000000000'; TotalBytes = '6000000000'; UploadRatio = '0.83'; Rounds = '100'; Users = 'aryan'; FirstSeen = '2026-09-17 16:46:00'; LastSeen = '2026-11-16 16:42:00' },
        [pscustomobject]@{ Application = 'VMware NAT Service'; Leaf = 'vmware nat service'; BytesSent = '1000000'; BytesReceived = '9000000000'; TotalBytes = '9001000000'; UploadRatio = '0.01'; Rounds = '50'; Users = 'system'; FirstSeen = '2026-09-20 12:17:00'; LastSeen = '2026-10-23 14:02:00' }
    )
    'userassist.csv' = @(
        [pscustomobject]@{ User = 'S-1-5-21-1-2-3-1001'; Guid = '{A}'; Kind = 'executable'; Entry = 'C:\Windows\system32\mspaint.exe'; RunCount = '7'; LastRun = '2026-11-01 10:00:00' },
        [pscustomobject]@{ User = 'S-1-5-21-1-2-3-1001'; Guid = '{B}'; Kind = 'executable'; Entry = 'UEME_CTLSESSION'; RunCount = '4'; LastRun = '' }
    )
    'shellbags.csv' = @(
        [pscustomobject]@{ BagPath = 'BagMRU'; Slot = '0'; NodeSlot = '0'; MRUPosition = '2'; AbsolutePath = 'Desktop\USB-DISK'; ShellType = 'Volume'; Value = 'USB-DISK'; CreatedOn = ''; ModifiedOn = ''; AccessedOn = ''; LastWriteTime = '2026-11-10 08:00:00'; FirstInteracted = '2026-11-10 08:00:00'; LastInteracted = '2026-11-15 21:30:00'; SourceFile = 'X:\raw\registry\users\aryan_UsrClass.dat' }
    )
    'profile_list.csv' = @(
        [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001'; Path = 'C:\Users\aryan'; Account = 'aryan'; Loaded = 'True' }
    )
}
function Import-CaseCsv { param($Name)
    if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }
    return @()
}

$mSrum = [regex]::Match($src, "(?s)# v4\.4: SRUM top data consumers.*?\r?\n(?=    # v2\.66)")
Check 'P2: SRUM card block extractable' $mSrum.Success
if ($mSrum.Success) {
    $sbS = [scriptblock]::Create($mSrum.Value)
    $actB = New-Object System.Text.StringBuilder
    $sb = New-Object System.Text.StringBuilder
    try { & $sbS } catch { Write-Host "      srum-frag err: $($_.Exception.Message)" -ForegroundColor Red }
    $html = $actB.ToString()
    Check 'P2: SRUM card title rendered' ($html.Contains('Top data consumers (SRUM)'))
    Check 'P2: xray bar flagged bad (ratio 0.83 >= 0.5)' ($html.Contains('barfill bad'))
    Check 'P2: humanized GB + upload pct' ($html.Contains('GB up83%'))
    Check 'P2: low-ratio row unflagged' ($html.Contains('vmware nat service') -and $html -notmatch 'VMware[^<]*</span><span class=.bartr.><span class=.barfill bad')
    Check 'P2: hover carries user + window' ($html.Contains('aryan | 2026-09-17'))
}

$mUa = [regex]::Match($src, "(?s)# v4\.4: per-user program counters.*?(?=\r?\n    # ---------- connections: correlated entities)")
Check 'P2: useract-join block extractable' $mUa.Success
if ($mUa.Success) {
    $sbU = [scriptblock]::Create($mUa.Value)
    $uaAssist = $script:caseCsv['userassist.csv']
    $shellRows = $script:caseCsv['shellbags.csv']
    $profBySid = @{ 'S-1-5-21-1-2-3-1001' = 'aryan' }
    $sb = New-Object System.Text.StringBuilder
    try { & $sbU } catch { Write-Host "      ua-frag err: $($_.Exception.Message)" -ForegroundColor Red }
    $html2 = $sb.ToString()
    Check 'P2: UserAssist digest names account + program' ($html2.Contains('aryan</b> - most-run') -and $html2.Contains('mspaint.exe (7x)'))
    Check 'P2: UEME control row skipped' ($html2 -notmatch 'CTLSESSION')
    Check 'P2: shellbags table renders user from hive leaf' ($html2.Contains('<td>aryan</td><td>Desktop\USB-DISK</td>'))
    Check 'P2: shellbags stamp rendered' ($html2.Contains('2026-11-15 21:30:00'))
}

# ---- P3: structural pins
Check 'P3: SRUM consumers card wired' ($src.Contains('Top data consumers (SRUM)'))
Check 'P3: upload-ratio threshold 0.5' ($src.Contains('if ($ur4 -ge 0.5)'))
Check 'P3: UserAssist h3 present' ($src.Contains('Program runs (UserAssist)'))
Check 'P3: UserAssist skips UEME control rows' ($src.Contains("-notmatch '^UEME_'"))
Check 'P3: UserAssist exe/dll filter' ($src.Contains('(exe|dll)$'))
Check 'P3: shellbags h3 present' ($src.Contains('Folder access history (shellbags)'))
Check 'P3: shellbags user from UsrClass.dat leaf' ($src.Contains('_UsrClass\.dat'))
Check 'P3: ::ffff: strip comment pinned' ($src.Contains('IPv4-mapped IPv6 forms'))
Check 'P3: jump-list h3 + import wired' ($src.Contains('Recent file targets (jump lists)') -and $src.Contains("Import-CaseCsv 'jumplist_parsed_AutomaticDestinations'"))
Check 'P3: jump-list sort falls back to CreationTime' ($src.Contains('else { $_.CreationTime }'))
Check 'P3: version 6.3' ($src.Contains('Ophira v6.6') -and $src.Contains('$ScriptVersion = "6.6"'))

Write-Host ''
if ($script:fail -gt 0) { Write-Host "v4.4: $($script:pass) passed, $($script:fail) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "v4.4: $($script:pass) passed, 0 failed" -ForegroundColor Green
exit 0
