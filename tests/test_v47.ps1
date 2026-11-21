# test_v47.ps1 - v4.7 Track-2 completion: task updates (4702), PS Module Logging (4103), LAPS state
$ErrorActionPreference = 'Stop'
$scriptPath = $PSScriptRoot -replace 'tests$', ''
$script:Checks = 0; $script:Fails = New-Object System.Collections.Generic.List[string]
function Check($name, $ok, $detail) {
    $script:Checks++
    if ($ok) { Write-Host "  [PASS] $name" -ForegroundColor DarkGray }
    else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:Fails.Add("$name $detail") }
}
$src = [IO.File]::ReadAllText((Join-Path $scriptPath 'Ophira.ps1'))

# --- extracts -------------------------------------------------------------
$m411 = [regex]::Match($src, "(?s)Id = '4\.11'.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m411.Success) { throw 'cannot extract module 4.11' }
$m411Body = $m411.Groups[1].Value
$gfe = [regex]::Match($src, "(?s)function Get-FilteredEvents \{.*?\r?\n\}")
if (-not $gfe.Success) { throw 'cannot extract Get-FilteredEvents' }
$gfeBody = $gfe.Value

Write-Host "== P1: Get-FilteredEvents optional Ids ==" -ForegroundColor Cyan
Check 'Id optional (if guard)' ($gfeBody -match 'if \(\$Ids\) \{ \$filter\.Id = \$Ids \}') ''
Check 'no unconditional Id key' (-not ($gfeBody -match '@\{ LogName = \$LogName; Id = \$Ids \}')) ''

Write-Host "== P2: module 4.11 additions ==" -ForegroundColor Cyan
Check '4702 task updates pull' ($m411Body -match "Ids @\(4702\)") ''
Check 'task_updates Save-Rows' ($m411Body -match "Save-Rows -Name 'task_updates'") ''
Check 'ModuleLog 4103 pull' ($m411Body -match "'Microsoft-Windows-PowerShell/ModuleLog' -Ids @\(4103\)") ''
Check 'ps_module_log Save-Rows' ($m411Body -match "Save-Rows -Name 'ps_module_log'") ''
Check 'LAPS service check' ($m411Body -match "Get-Service -Name 'LAPS'") ''
Check 'LAPS channel pull (all ids)' ($m411Body.Contains("'Microsoft-Windows-LAPS/Operational' -Ids `$null")) ''
Check 'laps_state Save-Rows' ($m411Body -match "Save-Rows -Name 'laps_state'") ''
Check 'laps_state always one row' ($m411Body.Contains('lapsRows = @([pscustomobject]@{ Kind = $lapsKind')) ''
Check 'LAPS evtx export' ($m411Body -match "Export-Evtx -LogName 'Microsoft-Windows-LAPS/Operational' -FileName 'LAPS_Operational\.evtx'") ''
Check 'ModuleLog evtx export' ($m411Body -match "Export-Evtx -LogName 'Microsoft-Windows-PowerShell/ModuleLog' -FileName 'PowerShell_ModuleLog\.evtx'") ''
Check 'no TaskScheduler evtx dup (4.1 owns it)' (-not ($m411Body -match 'TaskScheduler_Operational\.evtx')) ''

# behavioral: module 4.11 run block with stubs
function Get-LogStart { return (Get-Date).AddDays(-7) }
function Get-FilteredEvents { param([string]$LogName, [int[]]$Ids, $Start, [int]$MaxMsg = 500)
    $script:pulled += "$LogName|$($Ids -join ',')`n"
    if ($LogName -match 'TaskScheduler') { return @([pscustomobject]@{ TimeCreated = '2026-11-20 10:00:00'; Id = 4702; Provider = 'p'; Level = 'info'; Message = 'Task updated' }) }
    return @() }
function Save-Rows { param($Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param($m, $c) }
function Export-Evtx { param($LogName, $FileName) $script:exported += $FileName }
$script:pulled = ''; $script:saved = @{}; $script:exported = @()
$run = [scriptblock]::Create($m411Body)
& $run
Check 'behavior: task_updates rows saved' ($script:saved['task_updates'].Count -eq 1) ''
Check 'behavior: ps_module_log empty (graceful)' ($script:saved['ps_module_log'].Count -eq 0) ''
Check 'behavior: laps_state not-installed row' ($script:saved['laps_state'][0].Kind -eq 'not installed') ''
Check 'behavior: LAPS export ran' ($script:exported -contains 'LAPS_Operational.evtx') ''

Write-Host "== P3: maps + weave + wiring ==" -ForegroundColor Cyan
Check 'csvcat task_updates persistence' ($src -match "'task_updates' = 'persistence'") ''
Check 'csvcat ps_module_log logs' ($src -match "'ps_module_log' = 'logs'") ''
Check 'csvcat laps_state context' ($src -match "'laps_state' = 'context'") ''
Check 'anchor arm gains task_updates' ($src -match '\^\(autoruns\|asep\|services\|scheduled_task\|task_deletions\|task_updates\|esent_ntds\)') ''
Check 'weave task_updates' ($src.Contains("& `$weave 'task_updates' 200")) ''
Check 'weave ps_module_log' ($src.Contains("& `$weave 'ps_module_log' 500")) ''
Check 'desc entries' ($src -match "'task_updates'\s+= 'Scheduled task updates \(4702\)" -and $src -match "'ps_module_log'\s+= 'PowerShell Module Logging events \(4103\)" -and $src -match "'laps_state'\s+= 'Local admin password solution") ''
Check 'emptyWhy entries' ($src -match "'task_updates'\s+= 'no scheduled task updates" -and $src -match "'ps_module_log'\s+= 'no PowerShell Module Logging" -and $src -match "'laps_state'\s+= 'no LAPS state recorded") ''
Check 'version bumped' ($src -match 'Ophira v5\.0' -and $src -match '\$ScriptVersion = "5\.0"') ''

Write-Host ''
if ($script:Fails.Count -gt 0) {
    Write-Host "FAILED: $($script:Fails.Count) of $($script:Checks)" -ForegroundColor Red
    exit 1
}
Write-Host "ALL PASSED: $($script:Checks) checks" -ForegroundColor Green
exit 0
