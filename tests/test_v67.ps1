# test_v67.ps1 - v6.6 Session Stories
# Extracts New-SessionStories (+ Get-InvariantDate) from Ophira.ps1, feeds fixture CSVs,
# and asserts session assembly, bookends, activity attribution, end reasons, chips.
# House harness: regex extraction + stubs + positional Check calls (project test style).
$ErrorActionPreference = 'Stop'
$script:src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$script:pass = 0; $script:fail = 0
function Check { param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green }
    else { $script:fail++; Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red }
}
function Get-Fn { param([string]$Name)
    $m = [regex]::Match($script:src, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "function $Name not found" }
    return $m.Value
}

Invoke-Expression (Get-Fn 'Get-InvariantDate')
Invoke-Expression (Get-Fn 'New-SessionStories')

# ---- fixtures (Saturday 2026-11-28: weekend chip; 22:30 session: off-hours) ----
function T { param([string]$s) return $s }
$script:caseCsv = @{
    'security_auth_events' = @(
        [pscustomobject]@{ Time = '2026-11-28 10:00:00'; EventId = '4624'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '-'; LogonType = '2'; LogonId = '0x1234'; TargetSid = 'S-1-5-21-1-1001' }
        [pscustomobject]@{ Time = '2026-11-28 10:00:03'; EventId = '4624'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '-'; LogonType = '2'; LogonId = '0x2468'; TargetSid = 'S-1-5-21-1-1001' }
        [pscustomobject]@{ Time = '2026-11-28 10:00:05'; EventId = '4624'; Account = 'svc_backup'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '-'; LogonType = '5'; LogonId = '0x0AAA'; TargetSid = 'S-1-5-21-1-2000' }
        [pscustomobject]@{ Time = '2026-11-28 11:00:00'; EventId = '4800'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = ''; LogonType = '2'; LogonId = '0x1234'; TargetSid = '' }
        [pscustomobject]@{ Time = '2026-11-28 11:02:00'; EventId = '4801'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = ''; LogonType = '2'; LogonId = '0x1234'; TargetSid = '' }
        [pscustomobject]@{ Time = '2026-11-28 11:50:00'; EventId = '4779'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '10.0.0.5'; LogonType = ''; LogonId = '0x1234'; TargetSid = '' }
        [pscustomobject]@{ Time = '2026-11-28 11:51:00'; EventId = '4624'; Account = 'Bob'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '-'; LogonType = '2'; LogonId = '0x5678'; TargetSid = 'S-1-5-21-1-1002' }
        [pscustomobject]@{ Time = '2026-11-28 22:30:00'; EventId = '4624'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = '-'; LogonType = '2'; LogonId = '0x9999'; TargetSid = 'S-1-5-21-1-1001' }
        [pscustomobject]@{ Time = '2026-11-28 23:00:00'; EventId = '4647'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = ''; LogonType = '2'; LogonId = '0x9999'; TargetSid = '' }
        [pscustomobject]@{ Time = '2026-11-28 12:00:00'; EventId = '4800'; Account = 'Aryan'; AccountDomain = 'DESKTOP-88Q1H74'; SubjectAccount = '-'; SourceIp = ''; LogonType = '2'; LogonId = '0xABCD'; TargetSid = '' }
    )
    'security_proc_events' = @(
        [pscustomobject]@{ Time = '2026-11-28 10:05:00'; LogonId = '0x1234'; NewProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd.exe /c dir' }
        [pscustomobject]@{ Time = '2026-11-28 10:07:00'; LogonId = '0x2468'; NewProcess = 'C:\Windows\System32\reg.exe'; CommandLine = 'reg.exe query HKLM' }
        [pscustomobject]@{ Time = '2026-11-28 11:55:00'; LogonId = '0x5678'; NewProcess = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = 'powershell -enc AAAA' }
    )
    'security_share_access' = @(
        [pscustomobject]@{ Time = '2026-11-28 10:06:00'; LogonId = '0x1234'; ShareName = '\\*IPC$'; RelativeTargetName = 'a.txt' }
    )
    'userassist' = @(
        [pscustomobject]@{ User = 'S-1-5-21-1-1001'; Kind = 'executable'; Entry = 'C:\Program Files\7-Zip\7z.exe'; RunCount = '3'; LastRun = '2026-11-28 10:10:00' }
        [pscustomobject]@{ User = 'S-1-5-21-1-1001'; Kind = 'executable'; Entry = 'C:\Windows\System32\notepad.exe'; RunCount = '1'; LastRun = '2026-11-28 22:40:00' }
        [pscustomobject]@{ User = 'S-1-5-21-1-1001'; Kind = 'executable'; Entry = 'UEME_CTCAUW:20260101'; RunCount = '1'; LastRun = '2026-11-28 10:11:00' }
        [pscustomobject]@{ User = 'S-1-5-21-9-9999'; Kind = 'executable'; Entry = 'C:\Temp\ghost.exe'; RunCount = '1'; LastRun = '2026-11-28 10:12:00' }
        [pscustomobject]@{ User = 'S-1-5-21-1-1001'; Kind = 'executable'; Entry = 'C:\Temp\early.exe'; RunCount = '1'; LastRun = '2026-11-28 08:00:00' }
    )
    'rdp_localsession' = @(
        [pscustomobject]@{ TimeCreated = '2026-11-28 10:00:05'; Id = '21'; Provider = 'Microsoft-Windows-TerminalServices-LocalSessionManager'; Level = '4'; Message = 'User: DESKTOP-88Q1H74\Aryan Session ID: 1 Source Network Address: LOCAL' }
        [pscustomobject]@{ TimeCreated = '2026-11-28 11:50:10'; Id = '24'; Provider = 'Microsoft-Windows-TerminalServices-LocalSessionManager'; Level = '4'; Message = 'User: DESKTOP-88Q1H74\Aryan Session ID: 1 Source Network Address: LOCAL' }
        [pscustomobject]@{ TimeCreated = '2026-11-28 13:00:00'; Id = '21'; Provider = 'Microsoft-Windows-TerminalServices-LocalSessionManager'; Level = '4'; Message = 'User: DESKTOP-88Q1H74\Carol Session ID: 2 Source Network Address: LOCAL' }
        [pscustomobject]@{ TimeCreated = '2026-11-28 23:05:00'; Id = '23'; Provider = 'Microsoft-Windows-TerminalServices-LocalSessionManager'; Level = '4'; Message = 'User: DESKTOP-88Q1H74\Carol Session ID: 2 Source Network Address: LOCAL' }
    )
    'system_events' = @(
        [pscustomobject]@{ TimeCreated = '2026-11-28 11:57:00'; Id = '6006'; Provider = 'EventLog'; Level = '4'; Message = 'Event log STOPPED' }
    )
    'profile_list' = @(
        [pscustomobject]@{ Sid = 'S-1-5-21-1-1001'; User = 'Aryan' }
        [pscustomobject]@{ Sid = 'S-1-5-21-1-1002'; User = 'Bob' }
    )
}
$script:saved = New-Object System.Collections.Generic.List[object]
function Save-Rows { param([string]$Name, $Rows) foreach ($r in @($Rows)) { $script:saved.Add([pscustomobject]@{ Name = $Name; Row = $r }) } }
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return @($script:caseCsv[$Name]) } return @() }
function Write-CaseLog { param($_m) }

New-SessionStories
$rows = @($script:saved | Where-Object { $_.Name -eq 'session_stories' } | ForEach-Object { $_.Row })

Write-Host "`ntest_v67 - v6.6 Session Stories" -ForegroundColor Cyan

# ---- session assembly ----
$logons = @($rows | Where-Object { $_.Kind -eq 'logon' })
Check '4 sessions built (2x Aryan, Bob, Carol-LSM)' ($logons.Count -eq 4)
$aryan1 = @($logons | Where-Object { $_.SessionKey -eq 'L0x1234' })[0]
$bobby  = @($logons | Where-Object { $_.SessionKey -eq 'L0x5678' })[0]
$aryan2 = @($logons | Where-Object { $_.SessionKey -eq 'L0x9999' })[0]
$carol  = @($logons | Where-Object { $_.SessionKey -like 'LSM*' })[0]
Check 'session A logon row first + metadata' ($aryan1 -and $aryan1.SessionStart -eq '2026-11-28 10:00:00' -and $aryan1.SessionEnd -eq '2026-11-28 11:50:00')
Check 'paired twin 4624 (0x2468) folds into A, no extra card' ("$($aryan1.Detail)" -match 'paired logon session' -and -not (@($logons | Where-Object { $_.SessionKey -eq 'L0x2468' }).Count))
$twinProc = @($rows | Where-Object { $_.Kind -eq 'ran (4688)' -and "$($_.Detail)" -match 'reg\.exe' })[0]
Check 'twin-key 4688 joins the merged session' ($twinProc -and $twinProc.SessionKey -eq 'L0x1234')
Check 'session A duration 110 min' ("$($aryan1.DurationMinutes)" -eq '110')
Check 'session A user DOMAIN\user' ($aryan1.User -eq 'DESKTOP-88Q1H74\Aryan')
Check 'service 4624 (type 5) excluded' (-not (@($logons | Where-Object { $_.SessionKey -eq 'L0x0AAA' }).Count))

# ---- bookends ----
$kinds1 = @($rows | Where-Object { $_.SessionKey -eq 'L0x1234' } | ForEach-Object { $_.Kind })
Check 'A story: ran (4688) x2 (primary + merged twin key), share, UserAssist, locked, unlocked, switched away' ((@($kinds1 | Where-Object { $_ -eq 'ran (4688)' }).Count -eq 2) -and (@($kinds1 | Where-Object { $_ -eq 'share access' }).Count -eq 1) -and (@($kinds1 | Where-Object { $_ -eq 'ran (UserAssist)' }).Count -eq 1) -and (@($kinds1 | Where-Object { $_ -eq 'locked' }).Count -eq 1) -and (@($kinds1 | Where-Object { $_ -eq 'unlocked' }).Count -eq 1) -and (@($kinds1 | Where-Object { $_ -eq 'switched away' }).Count -eq 1))
Check 'A end reason = switched away' ($aryan1.EndReason -eq 'switched away')
Check 'orphan 4800 (0xABCD) dropped' (-not (@($rows | Where-Object { "$($_.Detail)" -match '0xABCD' }).Count))
$sw = @($rows | Where-Object { $_.SessionKey -eq 'L0x1234' -and $_.Kind -eq 'switched away' })[0]
Check '4779 wins over LSM 24 (dedupe, same minute)' ($sw -and $sw.Source -eq 'EID 4779')
Check 'LSM 21 near 4624 deduped (no extra Aryan session)' ($logons.Count -eq 4)
Check 'Carol LSM session created without 4624' ($carol -and "$($carol.LogonType)" -eq 'console (LSM)')
$carolRows = @($rows | Where-Object { $_.SessionKey -eq $carol.SessionKey })
Check 'Carol LSM logoff bookend (EID 23)' ((@($carolRows | Where-Object { $_.Kind -eq 'logged off' -and $_.Source -eq 'LSM EID 23' }).Count) -eq 1)

# ---- activity attribution ----
$cmdRow = @($rows | Where-Object { $_.Kind -eq 'ran (4688)' -and "$($_.Detail)" -match 'cmd\.exe' })[0]
Check '4688 join by LogonId into session A' ($cmdRow -and $cmdRow.SessionKey -eq 'L0x1234' -and $cmdRow.Attribution -eq 'session-joined')
$ua1 = @($rows | Where-Object { $_.Kind -eq 'ran (UserAssist)' -and "$($_.Detail)" -match '7z\.exe' })[0]
Check 'UserAssist SID join into session A (account history)' ($ua1 -and $ua1.SessionKey -eq 'L0x1234' -and $ua1.Attribution -eq 'account history')
$ua2 = @($rows | Where-Object { $_.Kind -eq 'ran (UserAssist)' -and "$($_.Detail)" -match 'notepad' })[0]
Check 'UserAssist in second Aryan session (covering-span match)' ($ua2 -and $ua2.SessionKey -eq 'L0x9999')
Check 'UEME_/unknown-SID/pre-window userassist rows skipped' (-not (@($rows | Where-Object { "$($_.Detail)" -match 'UEME_|ghost|early\.exe' }).Count))
$shareRow = @($rows | Where-Object { $_.Kind -eq 'share access' })[0]
Check '5145 share join detail (IPC$ -> a.txt)' ($shareRow -and "$($shareRow.Detail)" -match 'IPC\$ -> a\.txt')

# ---- end reasons + chips ----
Check 'session B ended by host shutdown (6006 within 5 min)' ($bobby.EndReason -eq 'host shutdown/reboot' -and $bobby.SessionEnd -eq '2026-11-28 11:57:00')
Check 'session C ended by explicit logoff (4647)' ($aryan2.EndReason -eq 'logged off')
Check 'chip: A first session for account' ("$($aryan1.Chips)" -match 'first session seen for this account')
Check 'chip: A off-hours (Saturday)' ("$($aryan1.Chips)" -match 'off-hours start')
Check 'chip: switch handoff pair A -> B' ("$($aryan1.Chips)" -match 'handed off to DESKTOP-88Q1H74\\Bob' -and "$($bobby.Chips)" -match 'took over from DESKTOP-88Q1H74\\Aryan')
Check 'chip: B ended by reboot' ("$($bobby.Chips)" -match 'ended by reboot')
Check 'chip: C off-hours (22:30)' ("$($aryan2.Chips)" -match 'off-hours start')
Check 'no first-session chip on later sessions' (-not ("$($aryan2.Chips)" -match 'first session'))

# ---- wiring pins in Ophira.ps1 ----
Check 'wiring: regen step' ($script:src -match [regex]::Escape("& `$rgStep 'session stories' 'New-SessionStories' { New-SessionStories }"))
Check 'wiring: CsvCatMap derived' ($script:src -match "'session_stories' = 'derived'")
Check 'wiring: report section anchor' ($script:src -match [regex]::Escape("<a name='sessions'></a><h2>Session stories</h2>"))
Check 'wiring: nav entry' ($script:src -match "'logons','sessions','useract'")
Check 'wiring: coverage row' ($script:src -match "Add-Cov 'Session stories \(per-session narrative\)' \(Test-CaseCsv 'session_stories'\) 1")
Check 'wiring: fleet harvest + fleet section' ($script:src -match 'session_stories\.csv' -and $script:src -match [regex]::Escape('<h2>Session stories across hosts (per-session narratives)</h2>'))
Check 'wiring: collector lifecycle EIDs' ($script:src -match [regex]::Escape('1102, 4634, 4647, 4800, 4801, 4778, 4779)'))
Check 'wiring: 4624 TargetSid parse' ($script:src -match 'TargetSid = \$tsid')
Check 'wiring: LSM EID 23 collected' ($script:src -match [regex]::Escape('Ids @(21, 22, 23, 24, 25, 39, 40)'))
Check 'wiring: 4624-family EventData parse (TargetLogonId)' ($script:src -match "Ids = @\(4647, 4800, 4801\)")
Check 'wiring: desc + emptyWhy entries' ($script:src -match 'Per-session narrative: logon \(type/source\)' -and $script:src -match 'needs interactive/RDP 4624 logons \(types 2/7/10\)')

Write-Host ""
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
