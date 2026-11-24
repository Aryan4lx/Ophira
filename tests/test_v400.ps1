# tests/test_v400.ps1 - v4.0 truth batch fixtures
#   P1 BAM decoder (module 8.11): value NAME = executable, value bytes = last-exec FILETIME
#   P2 new-service parse (module 4.5): bounded captures survive whitespace-collapsed messages
#   P3 R37 scrub survivor honors shimcache Executed=no (no finding for never-executed paths)
#   P4 R53 WinRM evidence is one argument (sample text present, ATT&CK tag = T1021.006)
#   P5 brute-force candidates exclude local/loopback sources (empty, '-', ::1, 127.0.0.1)
#   P6 sigma-storm lead fires on hayabusa 'med' levels (Level column, not Severity)
#   P7 ransom-note regex: bare readme.txt no longer flags; readme_decrypt.html does
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$stamp = Get-Date -Format 'HHmmss'

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

$defs = ''
foreach ($n in @('Get-InvariantDate', 'Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'Test-IsPublicIp', 'ConvertTo-HtmlEsc', 'ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-KnownBadRegexes', 'Get-LvlRank', 'Get-TriageLeads', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

# ---- shared harness stubs ----
function Save-Rows { param([string]$Name, $Rows) $script:rows[$Name] = @($Rows) }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function QuietLog { param([string]$Message) }
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $null }
function Test-Path { param([string]$LiteralPath, [string]$PathType, $ErrorAction) return ("$LiteralPath" -match 'UserSettings') }
function Test-CaseCsv([string]$n) { return $false }
function Get-ToolsDir { return $null }
function Get-Changes { return @() }
function Invoke-RegenerateOutputs { }
function Export-Evtx { param($LogName, $OutPath, $rest) }
function Get-LogStart { return (Get-InvariantDate '2026-11-10 00:00:00') }
function Get-EventDataRows { param($LogName, $Id, $Start, $Cap, $Fields, $rest) return @() }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $rest) return $script:fakeEvents }
function Get-TaskDeletionRows { param($Start) return @() }
function Get-Item { param($Path, $LiteralPath, $rest) return $null }
function New-Item { param($Path, $ItemType, $Force, $LiteralPath, $rest) }
function Copy-Item { param($LiteralPath, $Destination, $Force, $Path, $ErrorAction, $rest) }
function Get-ChildItem { param($Path, $Filter, $File, $Recurse, $ErrorAction, $rest) if ("$Path" -match 'UserSettings') { return @($script:sidObj) }; return @() }
function Get-ItemProperty { param($LiteralPath, $ErrorAction, $rest) if ("$LiteralPath" -match 'UserSettings') { return $script:propsObj }; return $null }
$script:rows = @{}
$script:fakeEvents = @()
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return @($script:caseCsv[$k]) }; return @() }

# ================= P1: BAM decoder (module 8.11) =================
$script:rows = @{}
$m811 = [regex]::Match($src, "(?s)Id = '8\.11';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m811.Success) { throw 'extract failed: module 8.11' }
$ft = [DateTime]::FromFileTime(0x01DD75ED0B8A0588)
$bamVal = [BitConverter]::GetBytes([long]0x01DD75ED0B8A0588) + [byte[]](0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
$script:sidObj = [pscustomobject]@{ PSPath = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1'; PSChildName = 'S-1-5-21-1'; LastWriteTime = $ft }
$script:propsObj = [pscustomobject]@{ }
$script:propsObj | Add-Member NoteProperty 'Version' 1
$script:propsObj | Add-Member NoteProperty 'SequenceNumber' 2
$script:propsObj | Add-Member NoteProperty 'C:\Users\Aryan\AppData\Local\evil.exe' $bamVal
$RawDir = $env:TEMP
& ([ScriptBlock]::Create($m811.Groups[1].Value))
$bam = @($script:rows['bam_lastexec'])
Check "P1: bam rows emitted" ($bam.Count -ge 1)
Check "P1: Executable = value NAME (path)" ($bam.Count -gt 0 -and "$($bam[0].Executable)" -eq 'C:\Users\Aryan\AppData\Local\evil.exe')
Check "P1: Executable is NOT the byte blob" ($bam.Count -gt 0 -and "$($bam[0].Executable)" -notmatch '^\d')
Check "P1: LastWrite decoded from FILETIME bytes" ($bam.Count -gt 0 -and "$($bam[0].LastWrite)" -eq "$ft")
Check "P1: Sid captured" ($bam.Count -gt 0 -and "$($bam[0].Sid)" -eq 'S-1-5-21-1')

# ================= P2: new-service parse (module 4.5) =================
$script:rows = @{}
$m45 = [regex]::Match($src, "(?s)Id = '4\.5';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m45.Success) { throw 'extract failed: module 4.5' }
$collapsed = 'Service Name: Windows Font Cache  Service  Service File Name: C:\Windows\evil.exe  Service Type: user mode service  Service Start Type: demand start  Account Name: LocalSystem'
$script:fakeEvents = @(
    [pscustomobject]@{ TimeCreated = $ft; Id = 7045; Provider = 'Service Control Manager'; Level = 4; Message = $collapsed }
)
function Get-FilteredEvents { param($LogName, $Ids, $Start) return $script:fakeEvents }
& ([ScriptBlock]::Create($m45.Groups[1].Value))
$svc = @($script:rows['system_new_services'])
Check "P2: 7045 row emitted" ($svc.Count -eq 1)
Check "P2: Service bounded (no message tail)" ($svc.Count -eq 1 -and "$($svc[0].Service)" -eq 'Windows Font Cache  Service')
Check "P2: Binary = File Name value" ($svc.Count -eq 1 -and "$($svc[0].Binary)" -eq 'C:\Windows\evil.exe')

# ================= P3+P4+P7: New-HuntFindings (R37 gate, R53 args, ransom regex) =================
$script:rows = @{}
$toolPath = 'C:\Users\Aryan\AppData\Local\Temp\tool.exe'
$evilPath = 'C:\Users\Public\evil.exe'
function ShimRaw([string]$path, [int]$pos, [string]$ts, [string]$flagByte) {
    "$path"
    $raw = '{"signature":"10ts","last_modified_ts":"' + $ts + '","data":[' + $flagByte + ',0,0,0]}'
    [pscustomobject]@{ 'Entry Type' = 'ShimcacheFileEntry'; 'File Path' = $path; 'Timeline Entry Number' = "$pos"; 'Raw Entry' = $raw }
}
$script:caseCsv = @{
    'execution_timeline' = @(
        [pscustomobject]@{ 'Entry Type' = 'summary'; },
        (ShimRaw $toolPath 0 '2026-11-01 10:00:00' '0'),
        (ShimRaw $evilPath 1 '2026-11-02 11:00:00' '1')
    )
    'shimcache_exec' = @(
        [pscustomobject]@{ Path = $toolPath; Executed = 'no' },
        [pscustomobject]@{ Path = $evilPath; Executed = 'yes' }
    )
    'amcache' = @(); 'prefetch_parsed' = @(); 'bam_lastexec' = @()
    'winrm_events' = @(
        [pscustomobject]@{ TimeCreated = $ft; Id = 91; Provider = 'WinRM'; Level = 4; Message = 'WSMan response 200 from 10.0.0.5' },
        [pscustomobject]@{ TimeCreated = $ft; Id = 91; Provider = 'WinRM'; Level = 4; Message = 'WSMan response 200 from 10.0.0.5' },
        [pscustomobject]@{ TimeCreated = $ft; Id = 91; Provider = 'WinRM'; Level = 4; Message = 'WSMan response 200 from 10.0.0.5' }
    )
    'processes' = @()
}
$script:Verbosity = 1
New-HuntFindings
$hf = @($script:rows['hunt_findings'])
$scrub = @($hf | Where-Object { "$($_.Rule)" -match 'scrub survivor' })
Check "P3: Executed=no path NOT flagged as scrub survivor" (@($scrub | Where-Object { "$($_.Entity)" -eq $toolPath }).Count -eq 0)
Check "P3: Executed=yes uncorroborated path STILL flagged" (@($scrub | Where-Object { "$($_.Entity)" -eq $evilPath }).Count -eq 1)
$r53 = @($hf | Where-Object { "$($_.Rule)" -match 'WinRM remote-management' })
Check "P4: R53 finding emitted for 3 events" ($r53.Count -eq 1 -and "$($r53[0].Entity)" -eq '3 events')
Check "P4: R53 evidence carries the sample text" ($r53.Count -eq 1 -and "$($r53[0].Evidence)" -match 'sample: .{5,}')
Check "P4: R53 ATT&CK tag intact (not '+')" ($r53.Count -eq 1 -and "$($r53[0].Attck)" -eq 'T1021.006')
$ransom = @($hf | Where-Object { "$($_.Rule)" -match 'Known-bad name pattern' -and "$($_.Evidence)" -match 'ransom-note' })
Check "P7: no ransom finding for plain names" ($ransom.Count -eq 0)
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ FullPath = 'C:\Users\Aryan\Documents\readme.txt'; Name = 'readme.txt' },
    [pscustomobject]@{ FullPath = 'C:\Users\Aryan\Documents\readme_decrypt.html'; Name = 'readme_decrypt.html' }
)
$script:rows = @{}
New-HuntFindings
$hf2 = @($script:rows['hunt_findings'])
$ransom2 = @($hf2 | Where-Object { "$($_.Rule)" -match 'Known-bad name pattern' -and "$($_.Evidence)" -match 'ransom-note' })
Check "P7: bare readme.txt NOT flagged" (@($ransom2 | Where-Object { "$($_.Entity)" -eq 'readme.txt' }).Count -eq 0)
Check "P7: readme_decrypt.html flagged" (@($ransom2 | Where-Object { "$($_.Entity)" -eq 'readme_decrypt.html' }).Count -eq 1)

# ================= P5: brute-force local-source exclusion (module 4.1) =================
$script:rows = @{}
$m41 = [regex]::Match($src, "(?s)Id = '4\.1';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m41.Success) { throw 'extract failed: module 4.1' }
function AuthEv([int]$id, [string]$ipField) {
    $msg = "Logon Type: 2  Account Name: user  Account Domain: D  Logon ID: 0x1  New Logon  Account Name: user  Account Domain: D  Logon ID: 0x2  Process Information  Source Network Address: $ipField"
    [pscustomobject]@{ TimeCreated = $ft; Id = $id; Provider = 'Microsoft-Windows-Security-Auditing'; Level = 0; Message = $msg }
}
$script:fakeEvents = @(
    1..5 | ForEach-Object { AuthEv 4625 '' }
    1..5 | ForEach-Object { AuthEv 4625 '-' }
    1..5 | ForEach-Object { AuthEv 4625 '::1' }
    1..6 | ForEach-Object { AuthEv 4625 '203.0.113.9' }
    AuthEv 4624 '203.0.113.9'
)
& ([ScriptBlock]::Create($m41.Groups[1].Value))
$brute = @($script:rows['security_bruteforce_candidates'])
Check "P5: only the real remote source survives" ($brute.Count -eq 1 -and "$($brute[0].SourceIp)" -eq '203.0.113.9' -and "$($brute[0].FailedLogons)" -eq '6')
Check "P5: auth CSV still has all 4625 rows (local failures stay visible)" (@($script:rows['security_auth_events'] | Where-Object { "$($_.EventId)" -eq '4625' }).Count -eq 21)

# ================= P6: sigma-storm lead fires on hayabusa 'med' =================
$script:rows = @{}
$haya = 1..25 | ForEach-Object { [pscustomobject]@{ Timestamp = '2026-11-15 10:00:00 +00:00'; RuleTitle = 'Suspicious PowerShell Keywords'; Level = 'med'; Computer = 'X'; Channel = 'PwSh'; EventID = 4104; MitreTactics = 'exec'; MitreTags = ''; OtherTags = ''; RecordID = "$_"; Details = 'x'; ExtraFieldInfo = ''; RuleFile = 'r.yml'; RuleID = "r$_"; EvtxFile = 'e' } }
$script:caseCsv = @{
    'hayabusa_timeline' = $haya
    'flash_process_scored' = @(); 'yara_hits' = @(); 'beacon_candidates' = @(); 'dns_beacon_candidates' = @()
    'hunt_findings' = @(); 'ioc_hits' = @(); 'autoruns' = @(); 'scheduled_tasks_flagged' = @()
    'services' = @(); 'usn_write_bursts' = @(); 'security_bruteforce_candidates' = @()
    'connections_dns' = @(); 'flash_public_connections' = @(); 'system_new_services' = @()
    'security_auth_events' = @(); 'userassist' = @(); 'mft_recent' = @(); 'powershell_events' = @()
}
$leads = @(Get-TriageLeads)
$storm = @($leads | Where-Object { "$($_.Title)" -match '^Sigma storm:' })
Check "P6: sigma-storm lead fires on 25 'med' rows" ($storm.Count -ge 1)
Check "P6: storm lead rank med" ($storm.Count -ge 1 -and "$($storm[0].Rank)" -eq 'med')
$hi = 1..25 | ForEach-Object { [pscustomobject]@{ Timestamp = '2026-11-15 10:00:00 +00:00'; RuleTitle = "Cobalt Strike $_"; Level = 'high'; Computer = 'X'; Channel = 'PwSh'; EventID = 4104; MitreTactics = 'exec'; MitreTags = ''; OtherTags = ''; RecordID = "$_"; Details = 'x'; ExtraFieldInfo = ''; RuleFile = 'r.yml'; RuleID = "r$_"; EvtxFile = 'e' } }
$script:caseCsv['hayabusa_timeline'] = $hi
$leads2 = @(Get-TriageLeads)
$storm2 = @($leads2 | Where-Object { "$($_.Title)" -match '^Sigma storm: 25' })
Check "P6: 'high' hayabusa rows also fire the storm lead (25 rows)" ($storm2.Count -ge 1)

# ================= structural pins =================
Check "P8: R37 trace mentions no-flag gate" ($src -match 'shimcache_exec\(no-flag gate\)')
Check "P8: brute filter excludes '-'/'::1'/127.0.0.1" ($src.Contains(" `$_.Name -ne '-' -and `$_.Name -ne '::1' -and `$_.Name -ne '127.0.0.1'"))
Check "P8: anyT matches deleted columns" ($src.Contains('(?i)time|date|deleted'))
Check "P8: recyclebin RBCmd weave present" ($src.Contains("& `$weave 'recyclebin' 1000"))
Check "P8: version 5.1" ($src -match '\$ScriptVersion = "5\.6"')

Write-Host ''
if ($fail -gt 0) { Write-Host "PASSED: $pass FAILED: $fail" -ForegroundColor Red; exit 1 }
else { Write-Host "PASSED: $pass FAILED: 0" -ForegroundColor Green; exit 0 }
