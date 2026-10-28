# test_v285.ps1 - v2.85: recon-session clustering (SANS-2017 recon-scan) + temporal
# execution correlation (t-corr) + R51 verdict wiring.
# Part 1: New-ReconSessions - discovery-tool clustering, PS 4104 join, cmdletization out.
# Part 2: New-TCorr - decay weighting, +-30 min gate, bidirectional bond.
# Part 3: New-HuntFindings R51 - burst severities.
# Part 4: structural wiring.
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
function QuietLog { param($Message) }
$script:saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }

foreach ($n in @('Get-InvariantDate', 'New-ReconSessions', 'New-TCorr')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) if ("$Name" -match '\.csv$') { $Name = "$Name" -replace '\.csv$', '' }; if ($null -eq $script:caseCsv[$Name]) { return @() }; return @($script:caseCsv[$Name]) }

# ============================================================================
# PART 1 - New-ReconSessions
# ============================================================================
$script:caseCsv = @{}
$script:caseCsv['security_proc_events'] = @(
    [pscustomobject]@{ Time = '2026-10-27 10:00:00'; NewProcess = 'C:\Windows\System32\whoami.exe'; CommandLine = 'whoami /priv' }
    [pscustomobject]@{ Time = '2026-10-27 10:05:00'; NewProcess = 'C:\Windows\System32\net.exe'; CommandLine = 'net user /domain' }
    [pscustomobject]@{ Time = '2026-10-27 10:12:00'; NewProcess = 'C:\Windows\System32\nltest.exe'; CommandLine = 'nltest /dclist:corp' }
    [pscustomobject]@{ Time = '2026-10-27 10:20:00'; NewProcess = 'C:\Windows\System32\tasklist.exe'; CommandLine = 'tasklist' }
    [pscustomobject]@{ Time = '2026-10-27 12:00:00'; NewProcess = 'C:\Windows\System32\quser.exe'; CommandLine = 'quser' }
)
$script:caseCsv['powershell_events'] = @(
    [pscustomobject]@{ TimeCreated = '10/27/2026 10:15:00 PM'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): { Get-ADUser -Filter * }' }
    [pscustomobject]@{ TimeCreated = '10/27/2026 10:16:00 PM'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): { $__cmdletization_defaultParameterValues = @{}; Get-NetTCPSetting }' }
    [pscustomobject]@{ TimeCreated = '10/27/2026 10:17:00 PM'; Id = '4103'; Message = 'not a scriptblock' }
)
# note: PS stamps use the filtered-events dialect; 10:15 PM is out of the 10:00-10:20 window
# (kept deliberately - proves non-matching time events do not break clustering), and the
# cmdletization 4104 must be dropped even inside a session window. Add an in-window one:
$script:caseCsv['powershell_events'] += [pscustomobject]@{ TimeCreated = '10/27/2026 10:09:00 AM'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): { Get-LocalGroup }' }
New-ReconSessions
$rs = $script:saved['recon_sessions']
Check "recon: one burst session emitted" (@($rs).Count -eq 1)
$rs1 = $rs[0]
Check "recon: 4 distinct tools (powershell host is not a tool)" ([int]$rs1.ToolCount -eq 4)
Check "recon: all four tool names present" ("$($rs1.Tools)" -match 'whoami' -and "$($rs1.Tools)" -match 'net' -and "$($rs1.Tools)" -match 'nltest' -and "$($rs1.Tools)" -match 'tasklist')
Check "recon: cmdletization 4104 dropped, recon 4104 counted" ([int]$rs1.Events -eq 5 -and "$($rs1.Sample)" -match 'Get-LocalGroup')
Check "recon: session spans 10:00-10:20" ("$($rs1.StartUTC)" -eq '2026-10-27 10:00' -and "$($rs1.EndUTC)" -eq '2026-10-27 10:20')
Check "recon: 16-min-gap stray quser does not join or form a session" (@($rs | Where-Object { "$($_.Tools)" -match 'quser' }).Count -eq 0)

# empty evidence -> honest zero
$script:caseCsv = @{}
$script:saved = @{}
New-ReconSessions
Check "recon: no evidence -> recon_sessions saved empty" ($null -ne $script:saved['recon_sessions'] -and $script:saved['recon_sessions'].Count -eq 0)

# ============================================================================
# PART 2 - New-TCorr
# ============================================================================
$script:caseCsv = @{}
$script:caseCsv['hunt_findings'] = @(
    [pscustomobject]@{ Severity = 'high'; Entity = 'C:\Recycle\svchost.exe'; Rule = 'Misplaced system binary (stack view)' }
    [pscustomobject]@{ Severity = 'medium'; Entity = 'C:\evil\tool'; Rule = 'some rule' }
    [pscustomobject]@{ Severity = 'low'; Entity = 'C:\x\low.exe'; Rule = 'info rule' }
)
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ Name = 'svchost.exe'; FullPath = 'C:\Recycle\svchost.exe'; FileKeyLastWriteTimestamp = '2026-10-27 10:00:00' }
    [pscustomobject]@{ Name = 'tool.exe'; FullPath = 'C:\evil\tool.exe'; FileKeyLastWriteTimestamp = '2026-10-27 10:05:00' }
    [pscustomobject]@{ Name = 'notepad.exe'; FullPath = 'C:\Windows\System32\notepad.exe'; FileKeyLastWriteTimestamp = '2026-10-27 10:45:00' }
    [pscustomobject]@{ Name = 'rpcx.exe'; FullPath = 'C:\Windows\System32\rpcx.exe'; FileKeyLastWriteTimestamp = '2026-10-27 12:00:00' }
)
$script:caseCsv['prefetch_parsed'] = @(
    [pscustomobject]@{ ExecutableName = 'NOTEPAD'; LastRun = '2026-10-27 09:58:00'; PreviousRun0 = '' }
    [pscustomobject]@{ ExecutableName = 'TOOL'; LastRun = '2026-10-27 10:04:00'; PreviousRun0 = '' }
)
$script:saved = @{}
New-TCorr
$tc = $script:saved['exec_tcorr']
Check "tcorr: correlations produced" (@($tc).Count -ge 3)
$pairA = @($tc | Where-Object { $_.Seed -eq 'svchost.exe' -and $_.Name -eq 'tool.exe' })[0]
$pairB = @($tc | Where-Object { $_.Seed -eq 'tool.exe' -and $_.Name -eq 'svchost.exe' })[0]
Check "tcorr: svchost->tool within window" ($null -ne $pairA -and [double]$pairA.Weight -ge 0.5)
Check "tcorr: bond is bidirectional both ways" ("$($pairA.Bond)" -eq 'bidirectional' -and "$($pairB.Bond)" -eq 'bidirectional')
$np = @($tc | Where-Object { $_.Seed -eq 'svchost.exe' -and $_.Name -eq 'notepad.exe' })[0]
Check "tcorr: near prefetch run correlates with high weight" ($null -ne $np -and [double]$np.Weight -ge 0.8)
Check "tcorr: far executions (>30 min) excluded" (@($tc | Where-Object { $_.Name -eq 'rpcx.exe' }).Count -eq 0)
Check "tcorr: low-severity entity never seeds" (@($tc | Where-Object { $_.Seed -eq 'low.exe' }).Count -eq 0)
Check "tcorr: seed leaf no-ext normalized to tool.exe" ($null -ne $pairB)

# no seeds -> early out
$script:caseCsv['hunt_findings'] = @([pscustomobject]@{ Severity = 'low'; Entity = 'x.exe' })
$script:saved = @{}
New-TCorr
Check "tcorr: no seeds -> no exec_tcorr output" ($null -eq $script:saved['exec_tcorr'])

# ============================================================================
# PART 3 - New-HuntFindings R51
# ============================================================================
foreach ($n in @('Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'Get-KnownBadRegexes', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression ($m.Value + "`r`n")
}
$script:Verbosity = 2
$script:caseCsv = @{}
$script:caseCsv['recon_sessions'] = @(
    [pscustomobject]@{ StartUTC = '2026-10-27 10:00'; EndUTC = '2026-10-27 10:14'; Minutes = 14; Events = 7; ToolCount = 7; Tools = 'net; nltest; quser; tasklist; whoami; wmic; systeminfo'; Sample = 'whoami /all' }
    [pscustomobject]@{ StartUTC = '2026-10-27 11:00'; EndUTC = '2026-11-27 11:09'; Minutes = 9; Events = 4; ToolCount = 4; Tools = 'arp; net; netstat; whoami'; Sample = 'net view' }
    [pscustomobject]@{ StartUTC = '2026-10-27 12:00'; EndUTC = '2026-10-27 12:05'; Minutes = 5; Events = 2; ToolCount = 2; Tools = 'whoami; net'; Sample = 'whoami' }
)
$script:saved = @{}
New-HuntFindings
$hf = $script:saved['hunt_findings']
$r51 = @($hf | Where-Object { "$($_.Rule)" -eq 'Recon tool burst' })
Check "R51: 4+ tool bursts flagged (2 of 3 sessions)" ($r51.Count -eq 2)
Check "R51: 7-tool burst is high" (@($r51 | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Entity)" -match '10:00' }).Count -eq 1)
Check "R51: 4-tool burst is medium" (@($r51 | Where-Object { "$($_.Severity)" -eq 'medium' -and "$($_.Entity)" -match '11:00' }).Count -eq 1)
Check "R51: 2-tool session below threshold" (@($r51 | Where-Object { "$($_.Entity)" -match '12:00' }).Count -eq 0)
Check "R51: T1087 tagged + evidence carries tool list" (@($r51 | Where-Object { "$($_.Attck)" -eq 'T1087' -and "$($_.Evidence)" -match 'distinct discovery tools' }).Count -eq 2)

# ============================================================================
# PART 4 - structural wiring
# ============================================================================
$rsIdx = $src.IndexOf("rgStep 'recon sessions' 'New-ReconSessions'")
$hfIdx = $src.IndexOf("rgStep 'hunt findings' 'New-HuntFindings'")
$tcIdx = $src.IndexOf("rgStep 'temporal correlation' 'New-TCorr'")
Check "wire: recon sessions step BEFORE hunt findings (R51 reads its csv)" ($rsIdx -gt 0 -and $hfIdx -gt $rsIdx)
Check "wire: t-corr step AFTER hunt findings (seeds read its csv)" ($tcIdx -gt $hfIdx)
Check "wire: anchor switch carries the two new artifacts" ($src.Contains("'^(hunt_findings|exec_stacks|exec_window|recon_sessions|exec_tcorr)'"))
Check "wire: CsvCatMap - recon_sessions + exec_tcorr derived" ($src.Contains("'recon_sessions' = 'derived'; 'exec_tcorr' = 'derived'"))
Check "wire: verdict floor-3 door for 6+ bursts" ($src.Contains("Add-Signal 'Recon tool burst - 6+ distinct discovery tools in one session' 3"))
Check "wire: verdict floor-2 door for 4-5 bursts" ($src.Contains("Add-Signal 'Recon tool burst - 4-5 distinct discovery tools in one session' 2"))
foreach ($k in @('recon_sessions', 'exec_tcorr')) {
    Check "wire: desc + emptyWhy maps carry $k (2 spots)" (([regex]::Matches($src, "(?m)^\s+'$k'\s*=\s*'")).Count -ge 2)
}
Check "wire: report recon h3 present" ($src.Contains('Recon sessions - clustered discovery-tool activity'))
Check "wire: report t-corr h3 present" ($src.Contains('Temporal execution correlation (t-corr)'))
Check "wire: report imports for the two artifacts" ($src.Contains("Import-CaseCsv 'recon_sessions.csv'") -and $src.Contains("Import-CaseCsv 'exec_tcorr.csv'"))
Check "wire: nav hunt count includes both" ($src.Contains('hunt = $huntRows.Count + $liveScan.Count + $reconSessions.Count + $tcorrRows.Count'))
Check "wire: version bumped to 2.86" ($src.Contains('$ScriptVersion = "2.86"'))

# ============================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host "v2.85: all $pass checks passed" -ForegroundColor Green; exit 0 }
Write-Host "v2.85: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1
