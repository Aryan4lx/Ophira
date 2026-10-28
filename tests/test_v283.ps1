# test_v283.ps1 - v2.83: shimcache executed-flag decode + ghost/hidden TaskCache checks +
#                  ESENT ntds.dit access + RADAR + AppSwitched
# Part 1: Get-RegKeyLastWrite P/Invoke (real key + missing key degrade).
# Part 2: Get-RadarRows / Get-AppSwitchedRows / Get-TaskDeletionRows / Get-EsentNtdsRows.
# Part 3: New-ShimcacheExec - Win10+ executed-flag from the last 4 bytes of the record blob,
#         chainsaw executed:true/false precedence, malformed/summary rows skipped.
# Part 4: module 2.3 TaskCache block - Tree GID link + Tasks SD presence -> flags.
# Part 5: New-HuntFindings R45 (SD-MISSING high / ORPHANED med) + R46 (ntds high/low).
# Part 6: structural wiring (regen step, SharedFunctions, weave, signals, maps, sections).
$ErrorActionPreference = 'Stop'
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
$src = Get-Content -LiteralPath $repoScript -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-KnownBadRegexes { return @() }
function QuietLog { param($Message) }
$script:saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }

# ---- extract the real functions ----
foreach ($n in @('Get-RegKeyLastWrite', 'Get-RadarRows', 'Get-AppSwitchedRows', 'Get-EsentNtdsRows', 'Get-TaskDeletionRows', 'New-ShimcacheExec')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}

# ============================================================================
# PART 1 - Get-RegKeyLastWrite
# ============================================================================
$lwt = Get-RegKeyLastWrite 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Check "reglwt: real key returns a DateTime" ($lwt -is [datetime] -and $lwt.Year -gt 2000)
$lwt2 = Get-RegKeyLastWrite 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\OphiraNoSuchKey42'
Check "reglwt: missing key degrades to null" ($null -eq $lwt2)

# ============================================================================
# PART 2 - RADAR / AppSwitched / task deletions / ESENT ntds
# ============================================================================
$radar = @(Get-RadarRows)
Check "radar: returns array without throwing" ($radar.Count -ge 0)
$asw = @(Get-AppSwitchedRows)
Check "appswitched: returns array without throwing" ($asw.Count -ge 0)
if ($asw.Count -gt 0) {
    Check "appswitched: rows carry User/App/SwitchCount" ($null -ne $asw[0].PSObject.Properties['User'] -and $null -ne $asw[0].PSObject.Properties['App'] -and $null -ne $asw[0].PSObject.Properties['SwitchCount'])
}

function Get-FilteredEvents { param([string]$LogName, [int[]]$Id, $Start, [int]$MaxMsg = 500) return @($script:fakeEvents) }

# 4699 parsing: 'User X deleted task "\Name" for user Y.' + quoted fallback + non-matching
$script:fakeEvents = @(
    [pscustomobject]@{ TimeCreated = '2026-10-28 10:00:00'; Id = 4699; Provider = 'Microsoft-Windows-TaskScheduler'; Level = 'Information'; Message = 'User DESKTOP\a deleted task "\EvilTask" for user "DESKTOP\a".' }
    [pscustomobject]@{ TimeCreated = '2026-10-28 10:05:00'; Id = 4699; Provider = 'Microsoft-Windows-TaskScheduler'; Level = 'Information'; Message = 'User DESKTOP\a deleted task "\Microsoft\Windows\Maintenance\Clean" for user "DESKTOP\a".' }
    [pscustomobject]@{ TimeCreated = '2026-10-28 10:07:00'; Id = 4699; Provider = 'Microsoft-Windows-TaskScheduler'; Level = 'Information'; Message = 'odd phrasing "QuotedName" here' }
)
$td = @(Get-TaskDeletionRows $null)
Check "taskdel: three 4699 rows kept" ($td.Count -eq 3)
Check "taskdel: task + user parsed" ("$($td[0].TaskName)" -eq '\EvilTask' -and "$($td[0].User)" -eq 'DESKTOP\a')
Check "taskdel: long path task parsed" ("$($td[1].TaskName)" -eq '\Microsoft\Windows\Maintenance\Clean')
Check "taskdel: quoted fallback" ("$($td[2].TaskName)" -eq 'QuotedName')

# ESENT: ntds rows kept, non-ntds dropped, backup pattern detected by message
$script:fakeEvents = @(
    [pscustomobject]@{ TimeCreated = '2026-10-28 11:00:00'; Id = 325; Provider = 'ESENT'; Level = 'Information'; Message = 'lsass.exe (600) NTDS Database opens ntds.dit' }
    [pscustomobject]@{ TimeCreated = '2026-10-28 11:01:00'; Id = 326; Provider = 'ESENT'; Level = 'Information'; Message = 'wbengine.exe (2212) backup: ntds.dit copied via vss' }
    [pscustomobject]@{ TimeCreated = '2026-10-28 11:02:00'; Id = 325; Provider = 'ESENT'; Level = 'Information'; Message = 'software.exe (99) some other database opened' }
)
$es = @(Get-EsentNtdsRows $null)
Check "esent: only ntds rows kept" ($es.Count -eq 2)
Check "esent: non-backup flagged false" ($es[0].BackupPattern -eq $false)
Check "esent: vss/wbengine flagged backup" ($es[1].BackupPattern -eq $true)

# ============================================================================
# PART 3 - New-ShimcacheExec executed-flag decode
# ============================================================================
$rawYes = '{"cache_entry_position":1,"controlset":1,"data":[0,2,0,0,4,0,0,0,0,0,0,0,0,32,0,0,2,0,0,0,100,134,0,0,0,8,0,0,2,0,0,0,100,134,0,0,0,4,0,0,4,0,0,0,3,0,0,0,64,0,0,0,4,0,0,0,1,0,0,0,32,0,0,0,4,0,0,0,0,0,0,0,0,1,0,0,4,0,0,0,1,0,0,0],"entry_type":{"File":{"path":"E:\\tools\\httpx.exe"}},"executed":null,"last_modified_ts":"2026-09-08T13:39:32Z","path_size":112,"signature":"10ts"}'
$rawNo = '{"cache_entry_position":0,"controlset":1,"data":[0,2,0,0,4,0,0,0,0,0,0,0,32,0,0,0,4,0,0,0,0,0,0,0],"entry_type":{"File":{"path":"C:\\Program Files\\x\\pyshellext.exe"}},"executed":null,"last_modified_ts":"2026-10-10T16:30:50Z","path_size":224,"signature":"10ts"}'
$rawTrue = '{"cache_entry_position":2,"controlset":2,"data":[0,0,0,0],"entry_type":{"File":{"path":"C:\\evil\\beacon.exe"}},"executed":true,"last_modified_ts":"2026-10-20T00:00:00Z","path_size":16,"signature":"10ts"}'
$rawFalse = '{"cache_entry_position":3,"controlset":2,"data":[1,0,0,0],"entry_type":{"File":{"path":"C:\\evil\\dropper.exe"}},"executed":false,"last_modified_ts":"2026-10-20T01:00:00Z","path_size":16,"signature":"10ts"}'
$script:caseCsv = @{}
$script:caseCsv['execution_timeline'] = @(
    [pscustomobject]@{ Timestamp = ''; 'File Path' = ''; 'Program Name' = ''; 'SHA-1 Hash' = ''; 'Timeline Entry Number' = 0; 'Entry Type' = ''; 'Timestamp Description' = 'Latest shimcache update'; 'Raw Entry' = '' }
    [pscustomobject]@{ Timestamp = ''; 'File Path' = 'E:\tools\httpx.exe'; 'Entry Type' = 'ShimcacheFileEntry'; 'Raw Entry' = $rawYes }
    [pscustomobject]@{ Timestamp = ''; 'File Path' = 'C:\Program Files\x\pyshellext.exe'; 'Entry Type' = 'ShimcacheFileEntry'; 'Raw Entry' = $rawNo }
    [pscustomobject]@{ Timestamp = ''; 'File Path' = 'C:\evil\beacon.exe'; 'Entry Type' = 'ShimcacheFileEntry'; 'Raw Entry' = $rawTrue }
    [pscustomobject]@{ Timestamp = ''; 'File Path' = 'C:\evil\dropper.exe'; 'Entry Type' = 'ShimcacheFileEntry'; 'Raw Entry' = $rawFalse }
    [pscustomobject]@{ Timestamp = ''; 'File Path' = 'C:\broken.exe'; 'Entry Type' = 'ShimcacheFileEntry'; 'Raw Entry' = '{"broken' }
)
function Import-CaseCsv { param([string]$Name) if ("$Name" -match '\.csv$') { $Name = "$Name" -replace '\.csv$', '' }; if ($null -eq $script:caseCsv[$Name]) { return @() }; return @($script:caseCsv[$Name]) }

New-ShimcacheExec
$scOut = $script:saved['shimcache_exec']
Check "shimc: 4 decodable rows saved (summary + malformed skipped)" ($scOut.Count -eq 4)
$scYesRow = @($scOut | Where-Object { $_.Path -eq 'E:\tools\httpx.exe' })[0]
Check "shimc: httpx last-dword 1 -> yes" ("$($scYesRow.Executed)" -eq 'yes')
$scNoRow = @($scOut | Where-Object { $_.Path -match 'pyshellext' })[0]
Check "shimc: pyshellext last-dword 0 -> no" ("$($scNoRow.Executed)" -eq 'no')
Check "shimc: paths + controlset + signature carried" ("$($scYesRow.Signature)" -eq '10ts' -and "$($scYesRow.ControlSet)" -eq '1' -and "$($scNoRow.LastModified)" -match '2026-10-10')
$scTrueRow = @($scOut | Where-Object { $_.Path -eq 'C:\evil\beacon.exe' })[0]
Check "shimc: chainsaw executed:true wins over zero data" ("$($scTrueRow.Executed)" -eq 'yes')
$scFalseRow = @($scOut | Where-Object { $_.Path -eq 'C:\evil\dropper.exe' })[0]
Check "shimc: chainsaw executed:false wins over 1 data" ("$($scFalseRow.Executed)" -eq 'no')

# ============================================================================
# PART 4 - module 2.3 TaskCache block
# ============================================================================
$m23 = [regex]::Match($src, "(?s)Id = '2\.3';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m23.Success) { throw 'extract failed: module 2.3' }
Invoke-Expression ('$script:m23Run = {' + $m23.Groups[1].Value + "`r`n}")
function Get-Command { param([string]$Name) return [pscustomobject]@{ Name = $Name } }
function Get-ScheduledTask { return @() }
function Test-IsUserWritablePath { param([string]$Path) return $false }
function Invoke-ExeCapture { param($SubDir, $Name, $Exe, $Arguments) }
function New-FakeRegKey([string]$name, [hashtable]$values, [string]$fullName) {
    $k = [pscustomobject]@{ PSChildName = $name; Name = $fullName }
    $k | Add-Member -MemberType NoteProperty -Name Values -Value $values -Force
    $k | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($n) if ($this.Values.ContainsKey($n)) { return $this.Values[$n] } else { return $null } } -Force
    return $k
}
$tcBase = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$script:fakeTree = @(
    New-FakeRegKey 'EvilTask' @{ GID = '{11111111-1111-1111-1111-111111111111}' } "$tcBase\Tree\EvilTask"
    New-FakeRegKey 'NoGid' @{} "$tcBase\Tree\NoGid"
)
$script:fakeTasks = @(
    New-FakeRegKey '{11111111-1111-1111-1111-111111111111}' @{ SD = [byte[]](1, 2, 3) } "$tcBase\Tasks\{11111111-1111-1111-1111-111111111111}"
    New-FakeRegKey '{22222222-2222-2222-2222-222222222222}' @{} "$tcBase\Tasks\{22222222-2222-2222-2222-222222222222}"
    New-FakeRegKey '{33333333-3333-3333-3333-333333333333}' @{ SD = [byte[]](9) } "$tcBase\Tasks\{33333333-3333-3333-3333-333333333333}"
)
function Get-ChildItem { param($Path) if ("$Path" -match 'Tree') { return $script:fakeTree } elseif ("$Path" -match 'Tasks') { return $script:fakeTasks }; return @() }
function Test-Path { param($Path) return $true }
$script:saved = @{}
& $script:m23Run
$tcOut = $script:saved['scheduled_taskcache']
Check "taskcache: 5 rows (2 tree + 3 tasks)" ($tcOut.Count -eq 5)
$tcLinked = @($tcOut | Where-Object { $_.Kind -eq 'tasks' -and "$($_.Guid)" -eq '{11111111-1111-1111-1111-111111111111}' })[0]
Check "taskcache: linked + SD present -> no flags" ("$($tcLinked.Flags)" -eq '' -and "$($tcLinked.SdPresent)" -eq 'True')
$tcGhost = @($tcOut | Where-Object { "$($_.Guid)" -eq '{22222222-2222-2222-2222-222222222222}' })[0]
Check "taskcache: no SD + no link -> SD-MISSING + ORPHANED" ("$($tcGhost.Flags)" -match 'SD-MISSING' -and "$($tcGhost.Flags)" -match 'ORPHANED')
$tcOrph = @($tcOut | Where-Object { "$($_.Guid)" -eq '{33333333-3333-3333-3333-333333333333}' })[0]
Check "taskcache: SD present but unlinked -> ORPHANED only" ("$($tcOrph.Flags)" -eq 'ORPHANED (no Tree link)')
$tcTree = @($tcOut | Where-Object { $_.Kind -eq 'tree' -and $_.TaskPath -eq '\EvilTask' })[0]
Check "taskcache: tree row path relative to Tree" ($null -ne $tcTree -and "$($tcTree.Guid)" -eq '{11111111-1111-1111-1111-111111111111}')
Check "taskcache: tree row without GID still recorded" (@($tcOut | Where-Object { $_.Kind -eq 'tree' -and "$($_.Guid)" -eq '' }).Count -eq 1)

# ============================================================================
# PART 5 - New-HuntFindings R45 + R46
# ============================================================================
foreach ($n in @('Get-InvariantDate', 'Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}
$script:Verbosity = 2
$script:caseCsv = @{}
$script:caseCsv['scheduled_taskcache'] = @(
    [pscustomobject]@{ Kind = 'tree'; TaskPath = '\EvilTask'; Guid = '{11111111-1111-1111-1111-111111111111}'; SdPresent = ''; Flags = '' }
    [pscustomobject]@{ Kind = 'tasks'; TaskPath = ''; Guid = '{22222222-2222-2222-2222-222222222222}'; SdPresent = 'False'; Flags = 'SD-MISSING (hidden from schtasks/GUI);ORPHANED (no Tree link)' }
    [pscustomobject]@{ Kind = 'tasks'; TaskPath = ''; Guid = '{33333333-3333-3333-3333-333333333333}'; SdPresent = 'True'; Flags = 'ORPHANED (no Tree link)' }
)
$script:caseCsv['esent_ntds'] = @(
    [pscustomobject]@{ Time = '2026-10-28 11:00:00'; EventId = '325'; BackupPattern = 'False'; Message = 'lsass.exe (600) NTDS Database opens ntds.dit' }
    [pscustomobject]@{ Time = '2026-10-28 11:01:00'; EventId = '326'; BackupPattern = 'True'; Message = 'wbengine.exe backup: ntds.dit copied via vss' }
)
$script:saved = @{}
New-HuntFindings
$hf = $script:saved['hunt_findings']
$hfHidden = @($hf | Where-Object { "$($_.Rule)" -match '^Hidden scheduled task' })
Check "R45: SD-MISSING -> high hidden-task finding" ($hfHidden.Count -eq 1 -and "$($hfHidden[0].Severity)" -eq 'high' -and "$($hfHidden[0].Attck)" -eq 'T1053.005')
Check "R45: evidence explains the trick" ("$($hfHidden[0].Evidence)" -match 'schtasks/GUI')
$hfOrph = @($hf | Where-Object { "$($_.Rule)" -match 'Orphaned' })
Check "R45: ORPHANED -> medium finding" ($hfOrph.Count -eq 1 -and "$($hfOrph[0].Severity)" -eq 'medium')
$hfNtds = @($hf | Where-Object { "$($_.Rule)" -match 'ntds\.dit accessed' })
Check "R46: non-backup ntds -> high finding" (@($hfNtds | Where-Object { "$($_.Rule)" -match '325/326' -and "$($_.Severity)" -eq 'high' }).Count -eq 1)
Check "R46: backup-pattern ntds -> low finding" (@($hfNtds | Where-Object { "$($_.Rule)" -match 'backup-pattern' -and "$($_.Severity)" -eq 'low' }).Count -eq 1)
Check "R45/R46: ATT&CK tags carried" (@($hfNtds | Where-Object { "$($_.Attck)" -eq 'T1003.003' }).Count -eq 2)

# ============================================================================
# PART 6 - structural wiring
# ============================================================================
Check "wire: regen step registered" ([regex]::Match($src, "& \`\$rgStep 'shimcache exec flags' 'New-ShimcacheExec'").Success -or $src.Contains("& `$(rgStep) 'shimcache exec flags'") -or $src.Contains("rgStep 'shimcache exec flags' 'New-ShimcacheExec'"))
Check "wire: SharedFunctions carry the five helpers" ($src.Contains("'Get-RegKeyLastWrite', 'Get-RadarRows', 'Get-AppSwitchedRows', 'Get-EsentNtdsRows', 'Get-TaskDeletionRows'"))
Check "wire: task_deletions woven into supertimeline" ($src.Contains('& $weave ''task_deletions'' 200'))
Check "wire: esent_ntds woven into supertimeline" ($src.Contains('& $weave ''esent_ntds'' 200'))
Check "wire: TaskScheduler evtx exported" ($src.Contains("Export-Evtx -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FileName 'TaskScheduler_Operational.evtx'"))
Check "wire: verdict signal - hidden task floor 3" ($src.Contains("Add-Signal 'Hidden scheduled task (TaskCache SD stripped)' 3"))
Check "wire: verdict signal - orphaned floor 2" ($src.Contains("Add-Signal 'Orphaned TaskCache entries (no Tree link)' 2"))
Check "wire: verdict signal - ntds theft floor 3" ($src.Contains("Add-Signal 'ntds.dit accessed - non-backup pattern (ESENT 325/326)' 3"))
Check "wire: verdict signal - ntds backup noted weight 0" ($src.Contains("Add-Signal 'ntds.dit accessed - backup pattern (verify schedule)' 0"))
Check "wire: CsvCatMap - scheduled_taskcache persistence" ($src.Contains("'scheduled_taskcache' = 'persistence'"))
Check "wire: CsvCatMap - shimcache_exec timeline" ($src.Contains("'shimcache_exec' = 'timeline'"))
Check "wire: CsvCatMap - radar/appswitched artifacts" ($src.Contains("'radar_exec' = 'artifacts'; 'appswitched' = 'artifacts'"))
Check "wire: anchor switch - task_deletions/esent -> persistence" ($src.Contains("'^(autoruns|asep|services|scheduled_task|task_deletions|esent_ntds)'"))
Check "wire: anchor switch - radar/appswitched -> snapshot" ($src.Contains("'^(radar_exec|appswitched)'"))
foreach ($k in @('scheduled_taskcache', 'task_deletions', 'esent_ntds', 'shimcache_exec', 'radar_exec', 'appswitched')) {
    Check "wire: desc + emptyWhy maps carry $k (2 spots)" (([regex]::Matches($src, "(?m)^\s+'$k'\s*=\s*'")).Count -ge 2)
}
Check "wire: report persistence h3 present" ($src.Contains('Task cache anomalies (ghost / hidden scheduled tasks)'))
Check "wire: report deletions h3 present" ($src.Contains('Scheduled task deletions (EID 4699)'))
Check "wire: report esent h3 present" ($src.Contains('ntds.dit access (ESENT 325/326)'))
Check "wire: report radar h3 present" ($src.Contains('RADAR diagnosed applications (execution evidence)'))
Check "wire: report appswitched h3 present" ($src.Contains('App focus switches (taskbar FeatureUsage)'))
Check "wire: report shimcache exec h3 present" ($src.Contains('Shimcache executed-flag (Win10+ records'))
Check "wire: report imports for the six artifacts" ($src.Contains("Import-CaseCsv 'scheduled_taskcache.csv'") -and $src.Contains("Import-CaseCsv 'task_deletions.csv'") -and $src.Contains("Import-CaseCsv 'esent_ntds.csv'") -and $src.Contains("Import-CaseCsv 'shimcache_exec.csv'") -and $src.Contains("Import-CaseCsv 'radar_exec.csv'") -and $src.Contains("Import-CaseCsv 'appswitched.csv'"))
Check "wire: version bumped to 2.85" ($src.Contains('$ScriptVersion = "2.85"'))

# ============================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host "v2.83: all $pass checks passed" -ForegroundColor Green; exit 0 }
Write-Host "v2.83: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1
