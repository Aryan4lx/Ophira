# Test v6.9 hunt rules (R74 run-key write window + hidden valuename, R75 kerberos port-88 join, R76 bcdedit testsigning/CI)
# House harness: extract New-HuntFindings from the script, stub case CSVs, assert on returned findings.
$script:src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw

$script:passN = 0
$script:failN = 0
function Check { param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:passN++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:failN++; Write-Host "  FAIL  $Name" -ForegroundColor Red }
}

function Get-Fn { param([string]$Name)
    $m = [regex]::Match($script:src, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "function $Name not found" }
    return $m.Value
}

# ---- stubs + harness ----
$script:caseCsv = @{}
$script:saved = @{}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] } return @() }
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }
function Test-IsUserWritablePath { param([string]$Path) return ("$Path".ToLower() -like 'c:\users\*') }
function Get-KnownBadRegexes { return @('(?i)mimikatz', '(?i)secretsdump') }
$script:Verbosity = 2
$script:logs = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$m) $script:logs.Add($m) }

Invoke-Expression (Get-Fn 'Get-InvariantDate')
Invoke-Expression (Get-Fn 'New-HuntFindings')

function Invoke-Hunt {
    # New-HuntFindings has no return - it emits via Save-Rows 'hunt_findings' (Ophira.ps1:13235)
    New-HuntFindings | Out-Null
    return @($script:saved['hunt_findings'])
}

function Reset-Fixtures {
    foreach ($k in @('sysmon_registry', 'security_proc_events', 'sysmon_proc_create', 'powershell_events', 'dns_cache',
        'system_new_services', 'security_auth_events', 'sysmon_network', 'security_kerberos')) { $script:caseCsv[$k] = @() }
}

Write-Host '--- v6.9 R74/R75/R76 (test_v70) ---'

# ================= R74: run-key write window + hidden valuename =================
Reset-Fixtures
$script:caseCsv['sysmon_registry'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:00:00'; EventType = 'SetValue'; TargetObject = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater'; Details = 'C:\Users\aryan\AppData\evil.exe'; Image = 'C:\Users\aryan\AppData\evil.exe' }
    [pscustomobject]@{ Time = '2026-11-28 10:01:00'; EventType = 'SetValue'; TargetObject = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\'; Details = 'C:\Windows\Temp\hid.exe'; Image = 'C:\Windows\Temp\hid.exe' }   # trailing backslash = hidden name
    [pscustomobject]@{ Time = '2026-11-28 10:02:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SOFTWARE\Vendor\Key'; Details = '1'; Image = 'C:\Windows\setup.exe' }   # not a run path: silent
    [pscustomobject]@{ Time = '2026-11-28 10:03:00'; EventType = 'DeleteValue'; TargetObject = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Old'; Details = ''; Image = 'C:\Windows\reg.exe' }   # delete: silent
    [pscustomobject]@{ Time = '2026-11-28 10:04:00'; EventType = 'SetValue'; TargetObject = 'HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater'; Details = 'C:\Users\aryan\AppData\evil.exe'; Image = 'C:\Users\aryan\AppData\evil.exe' }   # dedup repeat
)
$allF = Invoke-Hunt
$r74 = @($allF | Where-Object { "$($_.Rule)" -match 'run-key' })
Check 'R74-1 broad run-key write flagged medium (T1547.001)' (@($r74 | Where-Object { "$($_.Rule)" -eq 'Run-key write during collection window' -and "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1547.001' }).Count -eq 1)
Check 'R74-2 hidden trailing-backslash valuename flagged high' (@($r74 | Where-Object { "$($_.Rule)" -eq 'Hidden run-key valuename write' -and "$($_.Severity)" -eq 'high' }).Count -eq 1)
Check 'R74-3 non-run path and deletes silent' (@($r74 | Where-Object { "$($_.Rule)" -eq 'Run-key write during collection window' -and "$($_.Entity)" -like '*setup.exe*' }).Count -eq 0)
Check 'R74-4 dedup per target|image' (@($r74 | Where-Object { "$($_.Rule)" -eq 'Run-key write during collection window' }).Count -eq 1)
Check 'R74-5 entity is the writing process leaf' (@($r74 | Where-Object { "$($_.Entity)" -eq 'evil.exe' }).Count -eq 1)
Check 'R74-6 huntHi regex carries the hidden-name term' ($script:src -match '\|hidden run-key valuename write')

# ================= R75: kerberos port-88 join =================
Reset-Fixtures
$script:caseCsv['sysmon_network'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:00:00'; Image = 'C:\Users\aryan\app\implant.exe'; DestIp = '10.0.0.10'; DestPort = '88'; DestPortName = ''; SourceIp = '10.1.1.5' }
    [pscustomobject]@{ Time = '2026-11-28 10:10:00'; Image = 'C:\Windows\System32\lsass.exe'; DestIp = '10.0.0.10'; DestPort = '88'; DestPortName = ''; SourceIp = '10.1.1.9' }   # lsass: silent
    [pscustomobject]@{ Time = '2026-11-28 10:11:00'; Image = 'C:\Users\aryan\app\implant.exe'; DestIp = '10.0.0.10'; DestPort = '445'; DestPortName = ''; SourceIp = '10.1.1.5' }   # not 88: silent
    [pscustomobject]@{ Time = '2026-11-28 10:12:00'; Image = 'C:\Users\aryan\app\implant.exe'; DestIp = '10.0.0.10'; DestPort = '88'; DestPortName = ''; SourceIp = '127.0.0.1' }   # loopback: silent
    [pscustomobject]@{ Time = '2026-11-28 10:13:00'; Image = 'C:\Windows\System32\klist.exe'; DestIp = '10.0.0.11'; DestPort = ''; DestPortName = 'kerberos'; SourceIp = '10.1.1.8' }   # portname path joins below
)
$script:caseCsv['security_kerberos'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:02:00'; EventId = 4768; Account = 'bob'; IpAddress = '10.1.1.5' }
    [pscustomobject]@{ Time = '2026-11-28 10:15:00'; EventId = 4769; Account = 'carol'; IpAddress = '10.1.1.8' }
    [pscustomobject]@{ Time = '2026-11-28 10:16:00'; EventId = 4771; Account = 'eve'; IpAddress = '10.1.1.5' }   # 4771 never joins
    [pscustomobject]@{ Time = '2026-11-28 10:40:00'; EventId = 4768; Account = 'late'; IpAddress = '10.1.1.5' }   # outside 5 min
)
$allF = Invoke-Hunt
$r75 = @($allF | Where-Object { "$($_.Rule)" -match 'Kerberos ticket issued' })
Check 'R75-1 join flagged medium (T1558)' (@($r75 | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1558' -and "$($_.Entity)" -eq 'implant.exe' }).Count -eq 1)
Check 'R75-2 portname join works' (@($r75 | Where-Object { "$($_.Entity)" -eq 'klist.exe' }).Count -eq 1)
Check 'R75-3 lsass/loopback/non-88/4771/late all silent' (@($r75).Count -eq 2)
Check 'R75-4 evidence names account and gap' (@($r75 | Where-Object { "$($_.Evidence)" -match 'bob' }).Count -ge 1)

# ================= R76: bcdedit testsigning / nointegritychecks =================
Reset-Fixtures
$script:caseCsv['security_proc_events'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:00:00'; NewProcess = 'C:\Windows\System32\bcdedit.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'bcdedit /set testsigning on'; Account = 'admin' }
    [pscustomobject]@{ Time = '2026-11-28 10:01:00'; NewProcess = 'C:\Windows\System32\bcdedit.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'bcdedit /enum'; Account = 'admin' }   # enum chatter: silent
    [pscustomobject]@{ Time = '2026-11-28 10:02:00'; NewProcess = 'C:\Windows\System32\bcdedit.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'bcdedit /set testsigning off'; Account = 'admin' }   # off: silent
    [pscustomobject]@{ Time = '2026-11-28 10:03:00'; NewProcess = 'C:\Windows\System32\bcdedit.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'bcdedit /set testsigning on'; Account = 'admin' }   # dedup repeat
)
$script:caseCsv['sysmon_proc_create'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:05:00'; Image = 'C:\Windows\System32\bcdedit.exe'; ParentImage = 'C:\Windows\System32\cmd.exe'; CommandLine = 'bcdedit.exe /set nointegritychecks yes'; Hash = '' }
)
$script:caseCsv['powershell_events'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-28 10:06:00'; Id = 4104; Message = 'bcdedit /set testsigning 1' }
    [pscustomobject]@{ TimeCreated = '2026-11-28 10:07:00'; Id = 4103; Message = 'bcdedit /set testsigning 1' }   # non-4104: silent
)
$allF = Invoke-Hunt
$r76 = @($allF | Where-Object { "$($_.Rule)" -match 'bcdedit' })
Check 'R76-1 testsigning on flagged high (T1553.002), deduped' (@($r76 | Where-Object { "$($_.Rule)" -eq 'Test-signing enabled (bcdedit)' -and "$($_.Severity)" -eq 'high' }).Count -eq 2)
Check 'R76-2 nointegritychecks flagged high' (@($r76 | Where-Object { "$($_.Rule)" -eq 'Integrity checks disabled (bcdedit)' }).Count -eq 1)
Check 'R76-3 enum/off/4103 silent' (@($r76 | Where-Object { "$($_.Evidence)" -match '/enum|off' }).Count -eq 0)
Check 'R76-4 attck tag on both rules' (@($r76 | Where-Object { "$($_.Attck)" -ne 'T1553.002' }).Count -eq 0)
Check 'R76-5 huntHi regex carries both terms' (($script:src -match '\|test-signing enabled') -and ($script:src -match '\|integrity checks disabled'))

# ================= wiring =================
Check 'W1 R74 trace line' (@($script:logs | Where-Object { $_ -match 'R74' }).Count -ge 1)
Check 'W2 R75 trace line' (@($script:logs | Where-Object { $_ -match 'R75' }).Count -ge 1)
Check 'W3 R76 trace line' (@($script:logs | Where-Object { $_ -match 'R76' }).Count -ge 1)
Check 'W4 rules inserted after R73' ((($script:src.IndexOf('R73'' ''7045')) -lt ($script:src.IndexOf('R74'))) -and (($script:src.IndexOf('R75')) -lt ($script:src.IndexOf('R76'))))

Write-Host ''
Write-Host ("v6.9 hunt rules: $($script:passN) passed, $($script:failN) failed")
if ($script:failN -gt 0) { exit 1 }
exit 0
