# Test v6.8 hunt rules (R71 DNS C2 scoring, R72 blocklist tamper, R73 7045+T3 lateral join)
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

Write-Host '--- v6.8 R71/R72/R73 (test_v69) ---'

# ================= collector: 7045 Acct column =================
Check 'C1 7045 parser captures Service Account tail' ($script:src -match [regex]::Escape('Service Account:\s+(.+?)\s*$'))
Check 'C2 7045 row carries Acct column' ($script:src -match 'Acct = \$acct')

# ================= R72: blocklist tamper =================
$script:caseCsv['sysmon_registry'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:00:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable'; Details = 'DWORD (0x00000000)'; Image = 'C:\Windows\reg.exe' }
    [pscustomobject]@{ Time = '2026-11-28 10:01:00'; EventType = 'SetValue'; TargetObject = 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable'; Details = 'DWORD (0x00000001)'; Image = 'C:\Windows\reg.exe' }   # re-enable: silent
    [pscustomobject]@{ Time = '2026-11-28 10:02:00'; EventType = 'CreateKey'; TargetObject = 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config'; Details = ''; Image = 'C:\Windows\svchost.exe' }   # key open only: silent
)
$script:caseCsv['security_proc_events'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:05:00'; NewProcess = 'C:\Windows\System32\reg.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'reg add HKLM\SYSTEM\CurrentControlSet\Control\CI\Config /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f'; Account = 'admin' }
    [pscustomobject]@{ Time = '2026-11-28 10:06:00'; NewProcess = 'C:\Windows\System32\reg.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'reg query HKLM\SYSTEM\CurrentControlSet\Control\CI\Config'; Account = 'admin' }   # query only: silent
)
$script:caseCsv['sysmon_proc_create'] = @()
$script:caseCsv['powershell_events'] = @()
$script:caseCsv['dns_cache'] = @()
$script:caseCsv['system_new_services'] = @()
$script:caseCsv['security_auth_events'] = @()
$allF = Invoke-Hunt
$r72 = @($allF | Where-Object { "$($_.Rule)" -match 'Vulnerable driver blocklist' })
Check 'R72-1 registry zero-write flagged high (T1685)' (@($r72 | Where-Object { "$($_.Rule)" -eq 'Vulnerable driver blocklist disabled (registry)' -and "$($_.Severity)" -eq 'high' -and "$($_.Attck)" -eq 'T1685' }).Count -eq 1)
Check 'R72-2 re-enable (0x1) and key-open silent' (@($r72 | Where-Object { "$($_.Rule)" -eq 'Vulnerable driver blocklist disabled (registry)' }).Count -eq 1)
Check 'R72-3 command-line write flagged, query silent' (@($r72 | Where-Object { "$($_.Rule)" -eq 'Vulnerable driver blocklist write attempt (command line)' }).Count -eq 1)
Check 'R72-4 huntHi regex carries the term' ($script:src -match '\|vulnerable driver blocklist')

# ================= R71: DNS cache scoring =================
$script:caseCsv['dns_cache'] = @(
    [pscustomobject]@{ Entry = 'd4f90a1b7c3e2f8d6a5b4c3d2e1f0a9b7c6d5e4f3a2b1c0d.evil.example'; Data = '203.0.113.7'; Type = 'A'; TimeToLive = '300' }   # hex blob label -> medium tunneling
    [pscustomobject]@{ Entry = 'checkout.bank-example.top'; Data = '198.51.100.9'; Type = 'A'; TimeToLive = '60' }   # susp TLD -> info
    [pscustomobject]@{ Entry = 'mimikatz.badie.example'; Data = '203.0.113.99'; Type = 'A'; TimeToLive = '120' }     # known-bad pattern -> medium
    [pscustomobject]@{ Entry = 'checkout.bank-example.top'; Data = '198.51.100.9'; Type = 'A'; TimeToLive = '55' }   # dup domain: silent
    [pscustomobject]@{ Entry = '5.1.1.10.in-addr.arpa'; Data = 'host.local'; Type = 'PTR'; TimeToLive = '86400' }    # reverse: silent
    [pscustomobject]@{ Entry = 'not-a-domain'; Data = '-'; Type = 'A'; TimeToLive = '0' }                            # shape miss: silent
    [pscustomobject]@{ Entry = 'api.microsoft.com'; Data = '20.70.246.20'; Type = 'A'; TimeToLive = '60' }           # benign: silent
)
$script:caseCsv['sysmon_registry'] = @()
$script:caseCsv['security_proc_events'] = @()
$allF = Invoke-Hunt
$r71tun = @($allF | Where-Object { "$($_.Rule)" -eq 'DNS tunneling-shaped query' })
$r71tld = @($allF | Where-Object { "$($_.Rule)" -eq 'Suspicious-TLD DNS query' })
$r71bad = @($allF | Where-Object { "$($_.Rule)" -eq 'Known-bad pattern in DNS query' })
Check 'R71-1 hex-blob label -> medium tunneling T1071.004' ($r71tun.Count -eq 1 -and "$($r71tun[0].Severity)" -eq 'medium' -and "$($r71tun[0].Attck)" -eq 'T1071.004')
Check 'R71-2 susp TLD -> info' ($r71tld.Count -eq 1 -and "$($r71tld[0].Severity)" -eq 'info')
Check 'R71-3 known-bad pattern -> medium' ($r71bad.Count -eq 1 -and "$($r71bad[0].Severity)" -eq 'medium')
Check 'R71-4 per-domain dedup + benign/reverse/shape skips (total 3)' (@($allF | Where-Object { "$($_.Attck)" -eq 'T1071.004' }).Count -eq 3)

# ================= R73: 7045 + T3 lateral join =================
$script:caseCsv['dns_cache'] = @()
$script:caseCsv['system_new_services'] = @(
    [pscustomobject]@{ Time = '2026-11-28 10:00:00'; Service = 'BounceSvc'; Binary = 'C:\Windows\Temp\b.exe'; Type = 'NewService'; Acct = 'admin' }            # T3 @09:52 -> hit (8 min)
    [pscustomobject]@{ Time = '2026-11-28 11:00:00'; Service = 'QuietSvc'; Binary = 'C:\Windows\System32\q.exe'; Type = 'NewService'; Acct = 'admin' }        # nearest T3 10:55 (5 min) -> hit
    [pscustomobject]@{ Time = '2026-11-28 12:00:00'; Service = 'NoT3Svc'; Binary = 'C:\Windows\Temp\n.exe'; Type = 'NewService'; Acct = 'admin' }             # no T3 in window: silent
    [pscustomobject]@{ Time = '2026-11-28 12:30:00'; Service = 'SysSvc'; Binary = 'C:\Windows\Temp\s.exe'; Type = 'NewService'; Acct = 'SYSTEM' }             # excluded acct
    [pscustomobject]@{ Time = '2026-11-28 12:40:00'; Service = 'MachSvc'; Binary = 'C:\Windows\Temp\m.exe'; Type = 'NewService'; Acct = 'PC-01$' }            # machine acct
    [pscustomobject]@{ Time = '2026-11-28 12:50:00'; Service = 'EmptySvc'; Binary = 'C:\Windows\Temp\e.exe'; Type = 'NewService'; Acct = '' }                 # empty acct
)
$script:caseCsv['security_auth_events'] = @(
    [pscustomobject]@{ Time = '2026-11-28 09:52:00'; EventId = '4624'; Account = 'admin'; AccountDomain = 'CORP'; SourceIp = '10.1.1.5'; LogonType = '3' }
    [pscustomobject]@{ Time = '2026-11-28 10:55:00'; EventId = '4624'; Account = 'admin'; AccountDomain = 'CORP'; SourceIp = '10.1.1.5'; LogonType = '3' }
    [pscustomobject]@{ Time = '2026-11-28 09:30:00'; EventId = '4624'; Account = 'admin'; AccountDomain = 'CORP'; SourceIp = '10.1.1.5'; LogonType = '3' }    # 30 min before 10:00 svc: outside window
    [pscustomobject]@{ Time = '2026-11-28 09:58:00'; EventId = '4624'; Account = 'admin'; AccountDomain = 'CORP'; SourceIp = 'LOCAL'; LogonType = '3' }       # LOCAL ip: not network evidence
    [pscustomobject]@{ Time = '2026-11-28 09:59:00'; EventId = '4624'; Account = 'admin'; AccountDomain = 'CORP'; SourceIp = '10.9.9.9'; LogonType = '2' }    # type 2: not T3
    [pscustomobject]@{ Time = '2026-11-28 13:00:00'; EventId = '4624'; Account = 'jane'; AccountDomain = 'CORP'; SourceIp = '10.1.1.6'; LogonType = '3' }     # other account: unused
)
$allF = Invoke-Hunt
$r73 = @($allF | Where-Object { "$($_.Rule)" -eq 'Service install preceded by network logon (same account)' })
Check 'R73-1 joined installs flagged medium T1021.002 (2 of 6 services)' ($r73.Count -eq 2 -and "$($r73[0].Severity)" -eq 'medium' -and "$($r73[0].Attck)" -eq 'T1021.002')
Check 'R73-2 evidence carries minutes + source IP' (@($r73 | Where-Object { "$($_.Evidence)" -match '8 min' -and "$($_.Evidence)" -match '10\.1\.1\.5' }).Count -eq 1)
Check 'R73-3 excluded accounts never flag' (@($r73 | Where-Object { "$($_.Entity)" -match 'SYSTEM|PC-01\$' }).Count -eq 0)
$tl = @($script:logs | Where-Object { "$_" -match '^R7[123] ' })
Check 'R73-4 trace lines for all three rules' ($tl.Count -ge 3 -and (@($tl | Where-Object { "$_" -like 'R71 *' }).Count -ge 1) -and (@($tl | Where-Object { "$_" -like 'R72 *' }).Count -ge 1) -and (@($tl | Where-Object { "$_" -like 'R73 *' }).Count -ge 1))

Write-Host ''
Write-Host "$script:passN passed, $script:failN failed"
if ($script:failN -gt 0) { exit 1 }
