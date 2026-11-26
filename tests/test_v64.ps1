# test_v64.ps1 - v6.3 hunt rules R61 (Audit-CVE exploitation events) + R62 (system process wrong parent).
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check { param($name, $ok, $extra = '') if ($ok) { Write-Host "  [ok] $name" } else { Write-Host "  [FAIL] $name $extra" -ForegroundColor Red; $script:fails++ } }

# extract New-HuntFindings body
$m = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
Check 'extract New-HuntFindings' ($m.Success)

# stubs (house pattern)
$script:caseCsv = @{}
$script:savedRows = New-Object System.Collections.Generic.List[object]
$script:logLines = New-Object System.Collections.Generic.List[string]
function Import-CaseCsv { param($Name) if ($null -eq $script:caseCsv[$Name]) { return @() } return $script:caseCsv[$Name] }
function Save-Rows { param($Name, $Rows) foreach ($r in @($Rows)) { $script:savedRows.Add([pscustomobject]@{ Name = $Name; Row = $r }) } }
function Write-CaseLog { param($m) $script:logLines.Add("$m") }   # extra color arg lands in $args
function Test-IsUserWritablePath { param($p) return ($p -match '(?i)^c:\\users\\') }
function Get-KnownBadRegexes { return @() }   # R50 pack not under test here
$script:Verbosity = 2   # trace goes through Write-CaseLog stub (capturable)

Invoke-Expression $m.Value

# --- fixtures ---
$script:caseCsv['audit_cve'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-26 10:00:00'; Id = 1; Provider = 'Microsoft-Windows-Audit-CVE'; Level = 'Error'; Message = 'Vulnerability CVE-2020-0601 exploited by crypt32.dll caller' }
    [pscustomobject]@{ TimeCreated = '2026-11-26 10:05:00'; Id = 1; Provider = 'Microsoft-Windows-Audit-CVE'; Level = 'Error'; Message = 'Vulnerability CVE-2020-0601 exploited again' }
)
$script:caseCsv['security_proc_events'] = @(
    # violation: core system proc, parent outside System32
    [pscustomobject]@{ NewProcess = 'C:\Windows\svchost.exe'; ParentProcess = 'C:\Users\aryan\AppData\evil.exe'; CommandLine = 'svchost.exe -k evil' }
    # filtered: System32 parent
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\svchost.exe'; ParentProcess = 'C:\Windows\System32\services.exe'; CommandLine = '' }
    # filtered: MsMpEng leaf (Defender filter)
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\lsass.exe'; ParentProcess = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe'; CommandLine = '' }
    # filtered: SavService leaf
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\services.exe'; ParentProcess = 'C:\Program Files\AV\SavService.exe'; CommandLine = '' }
    # filtered: null parent
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\winlogon.exe'; ParentProcess = '-'; CommandLine = '' }
    # filtered: empty parent
    [pscustomobject]@{ NewProcess = 'C:\Windows\System32\winlogon.exe'; ParentProcess = ''; CommandLine = '' }
    # violation again via second source (same pair -> deduped to ONE finding)
    [pscustomobject]@{ NewProcess = 'C:\Windows\svchost.exe'; ParentProcess = 'C:\Users\aryan\AppData\evil.exe'; CommandLine = 'svchost.exe -k evil' }
)
$script:caseCsv['sysmon_proc_create'] = @(
    # violation: lsass spawned by user-path implant
    [pscustomobject]@{ Image = 'C:\Windows\System32\lsass.exe'; ParentImage = 'C:\Users\aryan\implant.exe'; OriginalFileName = 'lsass.exe'; CommandLine = 'lsass.exe' }
    # filtered: SysWOW64 parent
    [pscustomobject]@{ Image = 'C:\Windows\SysWOW64\services.exe'; ParentImage = 'C:\Windows\SysWOW64\wininit.exe'; OriginalFileName = 'services.exe'; CommandLine = '' }
)
# every other Import-CaseCsv name returns @() from the stub - earlier rules stay quiet.

New-HuntFindings

$rows = @($script:savedRows.ToArray() | Where-Object { $_.Name -eq 'hunt_findings' } | ForEach-Object { $_.Row })

# --- R61 ---
$r61 = @($rows | Where-Object { "$($_.Rule)" -match 'Audit-CVE' })
Check 'R61: one high finding per audit_cve row' ($r61.Count -eq 2) "got $($r61.Count)"
Check 'R61: severity high' (@($r61 | Where-Object { "$($_.Severity)" -eq 'high' }).Count -eq 2)
Check 'R61: entity carries the provider' ($r61[0].Entity -eq 'Microsoft-Windows-Audit-CVE') "entity=$($r61[0].Entity)"
Check 'R61: evidence carries time + EID + message' ("$($r61[0].Evidence)" -match '2026-11-26 10:00:00 EID 1')
Check 'R61: attack T1203' ("$($r61[0].Attck)" -eq 'T1203')

# --- R62 ---
$r62 = @($rows | Where-Object { "$($_.Rule)" -match 'wrong parent' })
Check 'R62: 2 distinct violations (deduped across both sources)' ($r62.Count -eq 2) "got $($r62.Count)"
Check 'R62: svchost spawned by user-path evil.exe' (@($r62 | Where-Object { $_.Entity -eq 'svchost.exe' -and "$($_.Evidence)" -match 'evil\.exe' }).Count -eq 1)
Check 'R62: lsass spawned by user-path implant' (@($r62 | Where-Object { $_.Entity -eq 'lsass.exe' -and "$($_.Evidence)" -match 'implant\.exe' }).Count -eq 1)
Check 'R62: severity medium, attack T1036.005' (@($r62 | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Attck)" -eq 'T1036.005' }).Count -eq 2)
Check 'R62: System32 parents filtered' (@($rows | Where-Object { "$($_.Evidence)" -match 'services\.exe|wininit\.exe' }).Count -eq 0)
Check 'R62: MsMpEng/SavService filters applied' (@($r62 | Where-Object { "$($_.Evidence)" -match 'MsMpEng|SavService' }).Count -eq 0)
Check 'R62: null/empty parent never emitted' (@($r62 | Where-Object { $_.Entity -eq 'winlogon.exe' }).Count -eq 0)

# --- trace lines (verbosity 2 -> Write-CaseLog stub) ---
$tr61 = @($script:logLines | Where-Object { $_ -match '^R61 ' })
$tr62 = @($script:logLines | Where-Object { $_ -match '^R62 ' })
Check 'trace: R61 line with counts' ($tr61.Count -eq 1 -and "$tr61" -match 'audit_cve: 2 row')
Check 'trace: R62 line with counts' ($tr62.Count -eq 1 -and "$tr62" -match '2 distinct violation')

# --- wiring pins in the script source ---
Check 'wiring: CsvCatMap audit_cve=logs' ($src -match "'audit_cve' = 'logs'")
Check 'wiring: module 4.10 collects audit_cve' ($src -match "Save-Rows -Name 'audit_cve'")
Check 'wiring: Get-FilteredEvents Provider param' ($src -match '\[string\]\$Provider =')
Check 'wiring: supertimeline weave list has audit_cve' ($src -match "'application_events', 'audit_cve'")
Check 'wiring: report description map entry' ($src -match "'audit_cve'\s+= 'Audit-CVE events")
Check 'wiring: emptyWhy map entry' ($src -match "'audit_cve'\s+= 'no Audit-CVE events")
Check 'wiring: verdict door (floor 3)' ($src -match "Add-Signal 'Audit-CVE exploitation event \(CveEventWrite\)' 3")
Check 'wiring: coverage row' ($src -match "Add-Cov 'Audit-CVE telemetry \(CveEventWrite\)'")

Write-Host ''
if ($fails -eq 0) { Write-Host 'test_v64: ALL CHECKS PASSED' -ForegroundColor Green } else { Write-Host "test_v64: $fails CHECK(S) FAILED" -ForegroundColor Red; exit 1 }
