$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.79 - tool debuggability:
#   T12: per-rule hunt traces (inputs in -> findings out + gate decisions) and verdict
#        signal-add / coverage-miss traces - always in collection.log, console at Verbose
#   T13: end-of-run regen summary block (RUN-detail shape, one line per derived artifact)
#        + "debugging a suspicious number" cookbook in -Mode Help and README
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART A - static source pins
# ============================================================================
$huntFn = [regex]::Match($src, '(?s)function New-HuntFindings \{.*?\r?\n\}').Value
Check "T12: hunt trace helper exists inside New-HuntFindings" (($huntFn.Contains('$trState = @{ Base = 0 }')) -and ($huntFn.Contains('$trace = {')))
Check "T12: hunt traces always reach the log on the quiet path (direct Add-Content, no -NoConsole switch)" (($huntFn.Contains('Add-Content -LiteralPath $CaseLog')) -and ($huntFn -notmatch 'Write-CaseLog \$tMsg .DarkGray. -NoConsole'))
Check "T12: verdict signal-add trace wired into Add-Signal" ($src.Contains('verdict signal: $name (floor $floor x $count)'))
Check "T12: coverage-miss trace wired into Add-Cov" ($src.Contains('verdict coverage miss: $name (weight $weight)'))
Check "T12: worker Write-CaseLog override stays file-only (no Write-Host)" (($src -match 'function Write-CaseLog \{ param\(\[string\][^\r\n]*Add-Content -LiteralPath') -and -not ($src -match 'function Write-CaseLog \{ param\(\[string\][^\r\n]*Write-Host'))
$regenFn = [regex]::Match($src, '(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}').Value
Check "T13: regen step helper + summary block present" (($regenFn.Contains('$rgStep = {')) -and ($regenFn.Contains('regen summary:')))
Check "T13: summary lines carry the RUN-detail shape" ($regenFn.Contains('[regen] {0} {1} {2} -> {3} in {4:N1}s'))
Check "T13: cookbook section in the comment-based help" ($src.Contains('DEBUGGING A SUSPICIOUS NUMBER'))

# ============================================================================
# PART B - hunt rule traces (real quiet path: Verbosity 1 -> lines land in the case log file)
# ============================================================================
$huntLog = Join-Path $env:TEMP "ophira_v279_hunt_$stamp.log"
$CaseLog = $huntLog
$script:Verbosity = 1
$CaseDir = ''
$Computer = 'V279HOST'
$huntSaved = New-Object System.Collections.Generic.List[object]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }  # console sink unused at Verbosity 1
function Get-KnownBadRegexes { return @() }
function Save-Rows { param([string]$Name, $Rows) $script:huntSaved.Add([pscustomobject]@{ Name = $Name; Rows = @($Rows).Count }) }
function Test-IsUserWritablePath { param([string]$Path) $false }
function Test-IsPublicIp { param([string]$Ip) $false }
$script:FixtureCsv = @{}
$procRows = New-Object System.Collections.Generic.List[object]
1..16 | ForEach-Object { $null = $procRows.Add([pscustomobject]@{ Time = "2026-10-23 10:$($_.toString('00')):00"; Account = 'V279HOST\alice'; NewProcess = 'C:\Windows\System32\whoami.exe'; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = 'whoami' }) }
foreach ($t in @('nltest.exe', 'net.exe', 'systeminfo.exe', 'ipconfig.exe', 'tasklist.exe', 'netstat.exe')) { $null = $procRows.Add([pscustomobject]@{ Time = '2026-10-23 11:00:00'; Account = 'V279HOST\bob'; NewProcess = "C:\Windows\System32\$t"; ParentProcess = 'C:\Windows\System32\cmd.exe'; CommandLine = $t }) }
$script:FixtureCsv['security_proc_events'] = $procRows.ToArray()
$script:FixtureCsv['defender_config_events'] = @([pscustomobject]@{ Time = '2026-10-23 09:00:00'; EventId = '5001'; Detail = 'Real-time protection disabled' })
function Import-CaseCsv { param([string]$Name) $k = ("$Name" -replace '\.csv$', ''); if ($script:FixtureCsv.ContainsKey($k)) { return $script:FixtureCsv[$k] }; return @() }

$m = [regex]::Match($src, '(?s)function New-HuntFindings \{.*?\r?\n\}')
if (-not $m.Success) { throw "extract failed: New-HuntFindings" }
Invoke-Expression $m.Value
$null = New-HuntFindings

$huntLogText = Get-Content -LiteralPath $huntLog -Raw
Check "T12: exactly one trace line per rule (41 rule blocks)" (@([regex]::Matches($huntLogText, '(?m)^\[[\d:]+\] R\d')).Count -eq 41)
Check "T12: R13 trace carries input counts AND findings-out counts (the brief's polarity example)" ($huntLogText -match [regex]::Escape('R13 discovery command storm: 2 accounts x 22 cmds (security_proc_events: 22 rows) -> 2 findings (2 low)'))
Check "T12: R14 rule with a finding logs 1 in / 1 high out" ($huntLogText -match [regex]::Escape('R14 Defender tamper (5001/5007): defender_config_events: 1 rows -> 1 finding (1 high)'))
Check "T12: clean rule logs its empty-input gate (R34)" ($huntLogText -match [regex]::Escape('R34 ADS on executables: ads_findings: 0 rows -> 0 findings'))
Check "T12: skipped rule logs its gate decision (R5)" ($huntLogText -match [regex]::Escape('R5 USB execution trail: gate: usb_devices empty or missing - skipped'))
Check "T12: traces did not change findings output (2 R13 low + 1 R14 high)" (($huntSaved.Count -eq 1) -and ($huntSaved[0].Name -eq 'hunt_findings') -and ($huntSaved[0].Rows -eq 3))

# ============================================================================
# PART C - verdict signal + coverage traces
# ============================================================================
$verdLog = Join-Path $env:TEMP "ophira_v279_verdict_$stamp.log"
$CaseLog = $verdLog
$verdCap = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:verdCap.Add($Message) }
$verdDir = Join-Path $env:TEMP "ophira_v279_vcase_$stamp"
New-Item -ItemType Directory -Path $verdDir -Force | Out-Null
$RawDir = $verdDir; $MemDir = Join-Path $verdDir 'mem'
$LogHours = 168; $Sysmon = $true; $script:EndpointAdmin = $true
$script:LogStartDT = $null; $script:LogEndDT = $null
$script:VFixCsv = @{
    'flash_ioc_hits'      = @([pscustomobject]@{ Type = 'domain'; Indicator = 'evil.example.com'; Where = 'dns cache'; Context = 'fixture' })
    'hayabusa_timeline'   = @([pscustomobject]@{ Timestamp = '2026-10-23 10:00:00'; Channel = 'Security'; Level = 'low'; RuleTitle = 'Benign rule'; Computer = 'V279HOST' })
}
function Import-CaseCsv { param([string]$Name) $k = ("$Name" -replace '\.csv$', ''); if ($script:VFixCsv.ContainsKey($k)) { return $script:VFixCsv[$k] }; return @() }
$script:VFixPresent = @('flash_process_scored', 'flash_public_connections', 'autoruns_runkeys', 'hayabusa_timeline', 'amcache')
function Test-CaseCsv { param([string]$Name) $k = ("$Name" -replace '\.csv$', ''); return ($script:VFixPresent -contains $k) }

$m = [regex]::Match($src, '(?s)function Get-CompromiseVerdict \{.*?\r?\n\}')
if (-not $m.Success) { throw "extract failed: Get-CompromiseVerdict" }
Invoke-Expression $m.Value
$v = Get-CompromiseVerdict
$verdLogText = Get-Content -LiteralPath $verdLog -Raw

Check "T12: signal-add trace logs name/floor/count" ($verdLogText -match [regex]::Escape('verdict signal: IOC hit - live system (floor 3 x 1)'))
Check "T12: zero-count signals add NO trace line (only 1 signal line total)" (@([regex]::Matches($verdLogText, 'verdict signal:')).Count -eq 1)
Check "T12: missing coverage source logs a miss line with its weight (prefetch)" ($verdLogText -match [regex]::Escape('verdict coverage miss: Prefetch execution history (weight 8)'))
Check "T12: absent evtx export logs a miss line (weight 20)" ($verdLogText -match [regex]::Escape('verdict coverage miss: Event log export (weight 20)'))
Check "T12: collected sources log NO miss line" (-not $verdLogText.Contains('verdict coverage miss: Volatile process inventory'))
Check "T12: traces did not change the verdict output (rank 3, 1 signal)" (($v.LevelRank -eq 3) -and (@($v.Signals).Count -eq 1) -and ($v.Level -eq 'LIKELY COMPROMISED'))

# ============================================================================
# PART D - regen summary block
# ============================================================================
$regCap = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:regCap.Add($Message) }
$regDir = Join-Path $env:TEMP "ophira_v279_rcase_$stamp"
$regCsv = Join-Path $regDir 'csv'
New-Item -ItemType Directory -Path $regCsv, (Join-Path $regDir 'raw') -Force | Out-Null
$CaseDir = $regDir; $script:CsvDir = $regCsv; $RawDir = Join-Path $regDir 'raw'; $MemDir = Join-Path $regDir 'mem'
$Computer = 'V279HOST'; $ScriptVersion = '2.79'; $StartTime = Get-Date
$script:CurrentCaseID = 'CASE-279'; $script:Verdict = $null
$script:LogStartDT = $null; $script:LogEndDT = $null
$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]
function ConvertTo-SafeInt { param([string]$Value, [int]$Default = 0) if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }; try { return [int]$Value } catch { return $Default } }
function Save-Rows { param([string]$Name, $Rows) if ($null -ne $script:SavedArtifacts) { $script:SavedArtifacts.Add([pscustomobject]@{ Path = "csv\fake\$Name.csv"; Rows = @($Rows).Count }) } }
function New-SuperTimeline { Save-Rows -Name 'supertimeline' -Rows (1..1234) }
function Import-PlasoTimeline { param($p) -1 }
function New-SigmaRuleLogs { }
function New-HuntFindings { Save-Rows -Name 'hunt_findings' -Rows (1..2) }
function New-IocHits { Save-Rows -Name 'ioc_hits_dns' -Rows (1..1); Save-Rows -Name 'ioc_hits_amcache' -Rows (1..2) }
function New-CaseIocExport { }
function New-EntityCorrelation { Save-Rows -Name 'entities_binaries' -Rows (1..5) }
function New-SessionAttribution { Save-Rows -Name 'session_activity' -Rows (1..3) }
function New-ProcessChains { Save-Rows -Name 'process_chains' -Rows (1..7) }
function New-LoggingGaps { Save-Rows -Name 'logging_gaps' -Rows (1..2) }
function Get-ParseNeeds { Save-Rows -Name 'parse_needed' -Rows (1..1) }
function Get-CompromiseVerdict {
    return [pscustomobject]@{ Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 80; OwnerLine = 'fixture'
        Signals = @(); Caveats = @(); Coverage = @()
        CoveragePercentUnadjusted = 80; CoverageSourcesCollected = 20; CoverageSourcesTotal = 29
        Counts = $null; GeneratedUTC = 'x' }
}
function Get-TriageLeads { return @() }
function Get-CaseNarrative { return @('ASSESSMENT', 'fixture line') }
function New-SiemExport { Set-Content -LiteralPath (Join-Path $CaseDir 'siem_export.ndjson') -Value @('{"a":1}', '{"b":2}', '{"c":3}') -Encoding UTF8 }
function New-AttackLayer { }
function New-HtmlReport { }

$m = [regex]::Match($src, '(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}')
if (-not $m.Success) { throw "extract failed: Invoke-RegenerateOutputs" }
Invoke-Expression $m.Value
Invoke-RegenerateOutputs -Case $null

$regLines = @($regCap | Where-Object { $_ -match '\[regen\]|regen summary:' })
Check "T13: summary header with step count + total seconds" (($regCap | Where-Object { $_ -match '^  regen summary: 20 steps in [\d.]+s$' }).Count -eq 1)
Check "T13: one summary line per derived artifact (20)" (@($regLines | Where-Object { $_ -match '\[regen\]' }).Count -eq 20)
Check "T13: Save-Rows producer line carries producer + path + row count + elapsed" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] supertimeline') -and $_ -match [regex]::Escape('New-SuperTimeline -> csv\fake\supertimeline.csv 1234 rows in ') }).Count -eq 1)
Check "T13: multi-artifact step aggregates counts (2 csv, 3 rows)" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] IOC xref') -and $_ -match [regex]::Escape('2 csv, 3 rows') }).Count -eq 1)
Check "T13: step without csv output gets the (no csv) marker (plaso)" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] plaso import') -and $_ -match [regex]::Escape('Import-PlasoTimeline -> (no csv) in ') }).Count -eq 1)
Check "T13: verdict step names its output artifact + level" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] verdict') -and $_ -match [regex]::Escape('Get-CompromiseVerdict -> verdict.json - SUSPICIOUS') }).Count -eq 1)
Check "T13: leads step counts its rows" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] triage leads') -and $_ -match [regex]::Escape('0 lead(s) -> csv\derived\leads.csv') }).Count -eq 1)
Check "T13: report step names report.html" (($regCap | Where-Object { $_ -match [regex]::Escape('[regen] report') -and $_ -match [regex]::Escape('New-HtmlReport -> report.html in ') }).Count -eq 1)
Check "T13: summary block prints AFTER the step logs (end of run)" ((($regCap | ForEach-Object { $_ -match 'VERDICT:' }).IndexOf($true) -ge 0) -and (($regCap | ForEach-Object { $_ -match 'regen summary:' }).IndexOf($true) -gt ($regCap | ForEach-Object { $_ -match 'VERDICT:' }).IndexOf($true)))

# ============================================================================
# PART E - -Mode Help renders the cookbook (behavioral: Get-Help against the real file)
# ============================================================================
$helpText = (Get-Help "$repoScript" -Full | Out-String)
Check "T13: -Mode Help text contains the cookbook section" ($helpText.Contains('DEBUGGING A SUSPICIOUS NUMBER'))
Check "T13: cookbook maps coverage % to its log line" ($helpText.Contains('verdict coverage miss:'))
Check "T13: cookbook maps hunt findings to the rule traces" (($helpText.Contains('hunt_findings.csv')) -and ($helpText.Contains('-> <N> findings')))
Check "T13: cookbook points at the regen summary block" ($helpText.Contains('regen summary:'))

if ($pass -eq 0 -and $fail -eq 0) { Write-Host "no checks ran" -ForegroundColor Red; exit 1 }
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($huntLog, $verdLog, $verdDir, $regDir)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
