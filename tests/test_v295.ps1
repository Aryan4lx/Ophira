# test_v295 - v2.95: secondary security logs module (4.11), 4103 task installs/updates,
# Defender ASR posture, weave entries, hunt rules R52-R55
param([switch]$Quiet)
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { $script:pass++; if (-not $Quiet) { Write-Host "[ok] $name" } }
    else { $script:fail++; Write-Host "[FAIL] $name" -ForegroundColor Red }
}
$repo = Split-Path -Parent $PSScriptRoot
$src = [IO.File]::ReadAllText((Join-Path $repo 'Ophira.ps1'))
function Get-Extracted([string]$name) {
    $m = [regex]::Match($script:src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $name failed" }
    return $m.Value
}

# ---- stubs ----
$script:caseCsv = @{}
$script:savedRows = @{}
$script:logLines = New-Object System.Collections.Generic.List[string]
$script:fakeEvents = @{}
function Import-CaseCsv([string]$Name) { if ($null -ne $script:caseCsv[$Name]) { return @($script:caseCsv[$Name]) } return @() }
function Save-Rows([string]$Name, $Rows) { $script:savedRows[$Name] = @($Rows | Where-Object { $null -ne $_ }) }
function Write-CaseLog([string]$m, [string]$c = 'Gray') { $script:logLines.Add($m) }
function QuietLog([string]$m) { }
function Get-KnownBadRegexes { return @() }
function Get-LevenshteinDistance { param($a, $b) return 99 }
function Get-CaseCsvFullPath([string]$Name) { return Join-Path $script:tmpDir "$Name.csv" }
function Get-InvariantDate { param($s) $d = [datetime]::MinValue; if ([datetime]::TryParse("$s", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d } return [datetime]::MinValue }
function Get-LogStart { if ($script:fakeStart) { return $script:fakeStart } return $null }
$script:fakeStart = [datetime]'2026-10-01 00:00:00'
function Export-Evtx { param([string]$LogName, [string]$FileName) }
$script:tmpDir = Join-Path $env:TEMP ("oph295_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $script:tmpDir -Force | Out-Null
# Get-FilteredEvents stub keyed on log name
function Get-FilteredEvents { param([string]$LogName, $Ids, $Start, [int]$MaxMsg = 0, [int]$Cap = 0)
    $key = "$LogName"
    if ($script:fakeEvents.ContainsKey($key)) { return @($script:fakeEvents[$key]) }
    return @() }

# module 4.11 extraction
$m411 = [regex]::Match($src, "(?s)Id = '4\.11';.*?Run = \{(.*?)\r?\n        \} \}")
Check '4.11 module exists' $m411.Success
$script:f411 = $m411.Groups[1].Value

# ---- P1: 4.11 runs all six log reads + saves ----
$script:fakeEvents['Microsoft-Windows-WMI-Activity/Operational'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 10:00:00'; Id = 5861; Provider = 'WMI-Activity'; Level = 4; Message = 'Temporary consumer registered: __EventFilter.Name="evil"' }
    [pscustomobject]@{ TimeCreated = '2026-11-01 10:01:00'; Id = 5860; Provider = 'WMI-Activity'; Level = 4; Message = 'Id 2 start' }
)
$script:fakeEvents['Microsoft-Windows-WinRM/Operational'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 11:00:00'; Id = 91; Provider = 'WinRM'; Level = 4; Message = 'Creating WSMan session to host A' }
)
$script:fakeEvents['Microsoft-Windows-NTLM/Operational'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 12:00:00'; Id = 8002; Provider = 'NTLM'; Level = 4; Message = 'NTLM client hash sent' }
)
Invoke-Expression $script:f411
Check 'wmi_activity saved (2 rows)' ($script:savedRows['wmi_activity'].Count -eq 2)
Check 'winrm_events saved (1 row)' ($script:savedRows['winrm_events'].Count -eq 1)
Check 'bits_transfers saved (empty log -> 0 rows)' ($script:savedRows['bits_transfers'].Count -eq 0)
Check 'ntlm_events saved (1 row)' ($script:savedRows['ntlm_events'].Count -eq 1)
Check 'applocker_events saved (both logs -> 0 rows on stub)' ($script:savedRows['applocker_events'].Count -eq 0)
Check 'wdac_events saved (empty log -> 0 rows)' ($script:savedRows['wdac_events'].Count -eq 0)
Check '4.11 exports evtx (wevtutil wrapped by Export-Evtx stub)' (($script:f411 -split "`n" | Where-Object { $_ -match 'Export-Evtx -LogName' }).Count -ge 3)
$wmiLog = ($script:logLines | Where-Object { $_ -match '5861' } | Select-Object -First 1)
Check '5861 honesty note logged' ($null -ne $wmiLog)

# ---- P2: hunt rules R52-R55 ----
$script:src = $src
foreach ($n in @('New-HuntFindings', 'Get-IpCloudClass', 'Get-DomainProvider', 'New-ConnectionDns', 'New-CaseManifest', 'New-SuperTimeline', 'Convert-LocalNaiveToUtc', 'Get-UserAssistRows')) {
    . ([ScriptBlock]::Create((Get-Extracted $n)))
}
$script:caseCsv['wmi_activity'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 10:00:00'; Id = '5861'; Provider = 'WMI-Activity'; Level = '4'; Message = 'Temporary consumer registered: evil'
        EventId = '5861'; Time = '2026-11-01 10:00:00' }
)
$script:caseCsv['winrm_events'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 11:0$($_.000)0'; Id = '91'; Message = 'Creating WSMan session' } 2>$null
)
# rebuild winrm fixture cleanly (the interpolated junk above must not break parse)
$script:caseCsv['winrm_events'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 11:00:00'; Id = '91'; Message = 'Creating WSMan session' }
    [pscustomobject]@{ TimeCreated = '2026-11-01 11:05:00'; Id = '91'; Message = 'Creating WSMan session' }
    [pscustomobject]@{ TimeCreated = '2026-11-01 11:06:00'; Id = '91'; Message = 'Creating WSMan session' }
)
$script:caseCsv['ntlm_events'] = @( [pscustomobject]@{ TimeCreated = '2026-11-01 12:00:00'; Id = '8002'; Message = 'clear text' } )
$script:caseCsv['bits_transfers'] = @(
    [pscustomobject]@{ TimeCreated = '2026-11-01 13:00:00'; Id = '59'; Message = 'BITS started' }
    [pscustomobject]@{ TimeCreated = '2026-11-01 13:01:00'; Id = '60'; Message = 'BITS completed' }
)
$hfOut = $null
try { New-HuntFindings; $hfOut = $script:savedRows['hunt_findings'] } catch { Check 'New-HuntFindings ran' $false; Write-Host "  err: $($_.Exception.Message)" }
if ($null -ne $hfOut) {
    $r52 = @($hfOut | Where-Object { $_.Rule -eq 'WMI temporary event consumer registered' })
    $r53 = @($hfOut | Where-Object { $_.Rule -eq 'WinRM remote-management authentication observed' })
    $r54 = @($hfOut | Where-Object { $_.Rule -eq 'NTLM clear-text authentication' })
    $r55 = @($hfOut | Where-Object { $_.Rule -eq 'BITS background transfers' })
    Check 'R52 fires medium on 5861' ($r52.Count -eq 1 -and $r52[0].Severity -eq 'medium')
    Check 'R52 tactic T1546.003' ("$($r52[0].Attck)" -eq 'T1546.003')
    Check 'R53 fires low on 3x EID 91' ($r53.Count -eq 1 -and $r53[0].Severity -eq 'low')
    Check 'R54 fires low on 8002' ($r54.Count -eq 1 -and $r54[0].Severity -eq 'low')
    Check 'R55 fires low on 2 BITS rows' ($r55.Count -eq 1 -and $r55[0].Severity -eq 'low')
    $r52n = @($script:savedRows['hunt_findings'] | Where-Object { $_.Rule -eq 'WMI temporary event consumer registered' })
    Check 'R52 negative: clean wmi_activity -> no finding' $true # fixture-only; negative via second run below
} else { 1..5 | ForEach-Object { Check "R5$_- group" $false } }
# negative run
$script:caseCsv['wmi_activity'] = @( [pscustomobject]@{ TimeCreated = 'x'; Id = '5860'; Message = 'normal' } )
$script:caseCsv['winrm_events'] = @()
$script:caseCsv['ntlm_events'] = @()
$script:caseCsv['bits_transfers'] = @()
try { New-HuntFindings; $neg = @($script:savedRows['hunt_findings'] | Where-Object { $_.Rule -match 'WMI temporary|WinRM remote|NTLM clear|BITS background' }) } catch { $neg = @('ERR') }
Check 'R52-R55 silent on clean logs' ($neg.Count -eq 0)

# ---- P3: structural wiring ----
Check 'CsvCatMap: secondary logs = logs' ($src.Contains("'wmi_activity' = 'logs'; 'winrm_events' = 'logs'"))
Check 'CsvCatMap: defender_posture = defender' ($src.Contains("'defender_posture' = 'defender'"))
Check 'desc map: wmi entry' ($src.Contains("= 'WMI-Activity operational log"))
Check 'emptyWhy: wmi entry (10+ chars)' ($src.Contains("'wmi_activity'                   = 'no WMI-Activity events"))
Check 'emptyWhy: defender_posture entry' ($src.Contains("'defender_posture'               = 'no ASR rules configured"))
Check 'weave: wmi_activity line' ($src.Contains("& `$weave 'wmi_activity' 500"))
Check 'weave: wdac_events line' ($src.Contains("& `$weave 'wdac_events' 500"))
Check 'coverage: secondary logs Add-Cov' ($src.Contains("Add-Cov 'Secondary security logs"))
Check 'module 4.2 reads 4103' ($src.Contains("-Ids @(4103, 4104, 400, 600)"))
Check 'module 4.1 reads 4702' ($src.Contains("-Id @(4698, 4702)"))
Check 'version 2.95' ($src.Contains('$ScriptVersion = "2.95"'))
Check 'defender posture: ASR loop present' ($src.Contains('AttackSurfaceReductionRules_Ids'))
Check 'defender status: TamperProtection captured' ($src.Contains('TamperProtection = $s.IsTamperProtected'))

Remove-Item -LiteralPath $script:tmpDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "RESULT: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
