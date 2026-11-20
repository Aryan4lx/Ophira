# test_v42.ps1 - v4.6 process-lineage upgrade (sysmon edges, descendants, Child/Parent columns, report block)
$ErrorActionPreference = 'Stop'
$script:fail = 0
function Check { param($name, $ok) if ($ok) { Write-Host "  [ok] $name" } else { $script:fail++; Write-Host "  [FAIL] $name" } }

$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fnEx = [regex]::Match($src, '(?s)function New-ProcessChains \{.*?\r?\n\}').Value
Check 'P1: New-ProcessChains extracted' ($fnEx.Length -gt 1000)

# --- synthetic edges: explorer -> winword -> evil.ps1 (4688), sysmon adds evil.ps1 -> cmd.exe, live adds nothing
$secProc = @(
    [pscustomobject]@{ Time = '2026-11-16 10:00:00'; EventId = 4688; Account = 'u'; NewProcess = 'C:\\Users\\u\\evil.ps1'; CommandLine = 'powershell -f evil.ps1'; ParentProcess = 'C:\\Windows\\System32\\winword.exe'; ParentProcessId = ''; NewProcessId = ''; CreatorPid = ''; LogonId = '' },
    [pscustomobject]@{ Time = '2026-11-16 09:59:00'; EventId = 4688; Account = 'u'; NewProcess = 'C:\\Program Files\\Microsoft Office\\winword.exe'; CommandLine = ''; ParentProcess = 'C:\\Windows\\explorer.exe'; ParentProcessId = ''; NewProcessId = ''; CreatorPid = ''; LogonId = '' }
)
$sysProc = @(
    [pscustomobject]@{ Image = 'C:\\Windows\\System32\\cmd.exe'; CommandLine = 'cmd /c del evil.ps1'; User = 'u'; ProcessId = '700'; ProcessGuid = 'g-700'; ParentImage = 'C:\\Users\\u\\evil.ps1'; ParentProcessGuid = 'g-evil' },
    [pscustomobject]@{ Image = 'C:\\Windows\\System32\\cmd.exe'; CommandLine = 'dup'; User = 'u'; ProcessId = '701'; ProcessGuid = 'g-701'; ParentImage = 'C:\\Users\\u\\evil.ps1'; ParentProcessGuid = 'g-evil2' }
)
$live = @(
    [pscustomobject]@{ PID = '900'; PPID = '901'; Name = 'notepad.exe'; Path = 'C:\\Windows\\notepad.exe'; Company = ''; Description = '' },
    [pscustomobject]@{ PID = '901'; PPID = ''; Name = 'services.exe'; Path = 'C:\\Windows\\System32\\services.exe'; Company = ''; Description = '' }
)
$scored = @( [pscustomobject]@{ Path = 'C:\\Users\\u\\evil.ps1'; Verdict = 'HIGH'; Score = 8; Reasons = 'x' } )
$hunt = @()
$captured = @{}
function Save-Rows { param($Name, $Rows) $script:captured[$Name] = @($Rows) }
function Write-CaseLog { param($m, $c = 'Gray') }
function QuietLog { param($m) }
function Import-CaseCsv { param($Name) if ($Name -eq 'security_proc_events') { return $script:secProc }; if ($Name -eq 'sysmon_proc_create') { return $script:sysProc }; if ($Name -eq 'processes') { return $script:live }; if ($Name -eq 'flash_process_scored') { return $script:scored }; if ($Name -eq 'hunt_findings') { return $script:hunt }; return @() }
function Split-Path { param([string]$Path, [switch]$Leaf) if ($Leaf) { "$Path" -replace '^.*[\\/]', '' } else { '' } }

IEX $fnEx
New-ProcessChains
$rows = $script:captured['process_chains']
Check 'P2: chain emitted for flagged binary' (@($rows | Where-Object { $_.Child -eq 'evil.ps1' }).Count -eq 1)
$ch = @($rows | Where-Object { $_.Child -eq 'evil.ps1' })[0]
Check 'P2: full ancestry chain (explorer -> winword -> evil.ps1)' ($ch.Chain -match 'explorer\.exe -> winword\.exe -> evil\.ps1')
Check 'P2: Parent column = topmost ancestor' ($ch.Parent -eq 'explorer.exe')
Check 'P2: sysmon children captured, deduped' ($ch.Children -eq 'cmd.exe' -and [int]$ch.ChildrenN -eq 1)
Check 'P2: Evidence carries cmd line' ($ch.Evidence -match 'cmd /c del')
Check 'P2: Steps = 3' ([int]$ch.Steps -eq 3)

# --- P3: sysmon-only case (no 4688) still builds edges
$script:captured = @{}
$script:secProc = @()
IEX $fnEx
New-ProcessChains
Check 'P3: sysmon-only edges produce chains' (@($script:captured['process_chains']).Count -ge 1)

# --- P4: no sources at all -> honest early-out, no artifact
$script:captured = @{}
$script:sysProc = @(); $script:live = @()
IEX $fnEx
New-ProcessChains
Check 'P4: no edges -> no artifact rows' ($script:captured['process_chains'].Count -eq 0)

# --- P5: wiring pins
Check 'P5: sysmon edge loop in fn' ($fnEx -match "Import-CaseCsv 'sysmon_proc_create'")
Check 'P5: children map built' ($fnEx.Contains('$children'))
Check 'P5: output has Child/Parent/Children columns' ($fnEx.Contains('Child = $leaf') -and $fnEx.Contains('ChildrenN'))
Check 'P5: report renders Also launched column' ($src.Contains('<th>Also launched</th>'))
Check 'P5: report meta mentions Sysmon' ($src.Contains('Rebuilt from 4688/Sysmon parent-child'))
Check 'P5: version 4.9' ($src.Contains('Ophira v4.9') -and $src.Contains('$ScriptVersion = "4.9"'))
Check 'P5: leads consumer reads Child/Parent (dead since v2.56, now live)' ($src.Contains('$ch2.Parent) -> $($ch2.Child)'))

Write-Host ''
if ($script:fail -gt 0) { Write-Host "test_v42: $($script:fail) FAILED"; exit 1 }
Write-Host 'test_v42: all passed'
exit 0
