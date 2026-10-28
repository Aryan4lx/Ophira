<#
Ophira v2.83  -  Windows Incident Response Triage Toolkit
READ-ONLY by design: never modifies the system, only reads and copies data
into its own output folder. Intended to be handed to a system owner or run
by a responder during early triage / threat hunting.
#>

<#
.SYNOPSIS
    Ophira - single-file Windows incident response triage toolkit for Windows
    endpoints (PowerShell 5.0+, zero dependencies).

.DESCRIPTION
    Ophira is a READ-ONLY triage tool: it never kills processes, deletes files
    or changes system state - it only reads and copies evidence into its own
    OPHIRA_<host>_<timestamp> output folder. One script covers the whole
    triage loop: collect on this endpoint, push and run across a fleet over
    WinRM, merge the results into one fleet report, and finish or deep-dive a
    collected case on the analyst PC. Every collection ends with a 5-level
    compromise verdict, an HTML report, a supertimeline, a SIEM export and a
    ZIP package. Companion tools (hayabusa, the EZ parsers, winpmem, ...) are
    optional and downloaded by -Mode Setup; everything degrades gracefully
    when a tool, admin rights or telemetry is missing.
    Default (no flags): interactive role gate + collection menu.
    Run "-Mode Help" (or press H in the task menu) to see this text.
    NOTE: verdicts are correlation heuristics over collected evidence -
    verify against the raw CSV/evtx inside the package before acting.

.PARAMETER Mode
    What to do. Collect (default) triages THIS PC. Deploy pushes the kit to
    remote hosts over WinRM and collects there. Analyze merges collected
    case zips into one fleet report (a single case passed in is
    auto-finished analyst-side instead). Setup downloads companion tools
    into tools\. Links lists the tool download pages. UpdateRules refreshes
    the hayabusa Sigma rules. Tune is the Sigma false-positive feedback loop
    (exclude or demote noisy rules). Parse re-runs the forensic parsers on a
    case from your PC and regenerates timeline, verdict and report (finish
    what the endpoint could not). Process/Focus build the activity-chain
    dossier of one entity in a case. Timeline filters a case's master
    timeline to a window. Watch is a live read-only diff of this PC while a
    sample detonates. Canary runs the detection self-test. SeedIocs appends
    one indicator to the IOC feed. Help prints this text and exits.

.PARAMETER CaseID
    Optional case label (e.g. INC-2026-042) stamped into case.json, the
    report and the fleet view so collections can be tied to a ticket.

.PARAMETER Analyst
    Name of the responding analyst, recorded in the case metadata.

.PARAMETER OutputPath
    Root folder for the OPHIRA_<host>_<timestamp> case folder.
    Default: the folder Ophira.ps1 itself lives in.

.PARAMETER Preset
    Collection depth: Flash (volatile only, ~15s), Quick (1-2 min),
    Standard (3-5 min, recommended default), Full (everything plus the
    unfiltered MFT/USN exports - needs free disk space), Custom (pick the
    modules in the menu), DC or WebServer (force the role-specific modules
    on regardless of auto-detection). Deploy applies the same values on the
    remote hosts.

.PARAMETER NoMenu
    Skip the module menu and collect immediately with the chosen Preset -
    the unattended form used by automation and handoff wrappers.

.PARAMETER SimpleUI
    Owner-friendly guided run (what RUN-OPHIRA.bat uses): minimal questions,
    plain-language progress and a DONE screen that hands the result zip back
    to the system owner.

.PARAMETER LogLevel
    Console noise: Quiet (banner + run summary only; the log file keeps everything), Normal (default)
    or Verbose (extra detail per module).

.PARAMETER IncludeMemory
    Also capture RAM with winpmem (module 7.1). Adds minutes and a multi-GB
    file to the package; only worth it on a box you suspect at depth.

.PARAMETER PushTools
    Deploy only: ship the bundled tools\endpoint\ folder to every remote
    host first (Kansa-style push, run, remove) so Sigma and prefetch
    parsing work on the endpoint too. Roughly 72 MB zipped per host.

.PARAMETER Sequential
    Run collection modules one after another instead of the default parallel
    pool. Slower; use it to isolate a misbehaving module.

.PARAMETER NoElevate
    Do not request administrator rights. Collection continues with whatever
    the current token can read and the report's coverage table shows what
    was skipped. Useful for a first look from a limited account.

.PARAMETER LogHours
    How far back event-log analysis (and the hayabusa timeline) looks, in
    hours. Default 168 = 7 days.

.PARAMETER LogWindow
    Friendlier alternative to -LogHours: 90h / 30d / 3m / 0 (= all time) or
    a start date like 2026-09-01. Wins over -LogHours.

.PARAMETER LogStart
    Explicit analysis window start, e.g. "2026-09-01 08:00". Wins over
    -LogWindow. Combine with -LogEnd for an exact range.

.PARAMETER LogEnd
    Explicit analysis window end (same format as -LogStart). Must be after
    -LogStart.

.PARAMETER SharePath
    Copy the finished case zip to this UNC share (e.g. \\IR-SRV\collections$)
    after collection, in addition to leaving it in the output folder.

.PARAMETER ComputerName
    Deploy mode: one or more remote host names to push and run on, in
    parallel (-MaxThreads).

.PARAMETER TargetsFile
    Deploy mode: a text file with one host per line (# comments allowed) as
    an alternative to -ComputerName.

.PARAMETER MaxThreads
    Deploy mode: how many hosts to collect in parallel. Default 8.

.PARAMETER AnalyzePath
    Analyze mode: folder containing OPHIRA_*.zip packages (or a single zip
    or case folder) to merge into the fleet report. Default: current folder.

.PARAMETER ParsePath
    Case to operate on for Parse, Focus/Process and Timeline: an
    OPHIRA_*.zip or its unzipped folder. Prompts when omitted.

.PARAMETER ProcessName
    Focus/Process mode: the seed entity - a process name, PID, path, hash,
    IP, ip:port or port. The engine expands it across the case's CSVs into
    an activity-chain dossier (focus\focus_report.html).

.PARAMETER After
    Focus/Process mode: optional evidence-row window start ("yyyy-MM-dd
    [HH:mm]", date-only = midnight). Rows outside [After..Before] are
    dropped; undated rows are dropped and counted when any window is set.
    When omitted interactively, the wizard prompts From/To (blank = all).

.PARAMETER Before
    Focus/Process mode: optional evidence-row window end (same format as
    -After).

.PARAMETER TimelineStart
    Timeline mode: window start in UTC ("yyyy-MM-dd HH:mm"). The case's
    supertimeline.csv is filtered to the Start..End window.

.PARAMETER TimelineEnd
    Timeline mode: window end in UTC (same format as -TimelineStart).

.PARAMETER HayabusaPath
    Analyze mode: explicit path to hayabusa.exe when it is not found
    recursively under tools\.

.PARAMETER CanaryTarget
    Canary mode: optional second host; the canary touches it over SMB so
    lateral-movement detections can be validated cross-host.

.PARAMETER CanaryTargetUser
    Canary mode: account name to use for the optional SMB touch.

.PARAMETER KeepLogging
    Canary mode only: keep the audit-policy changes the canary enabled (they
    are restored afterwards by default).

.PARAMETER DeltaPath
    Explicit previous OPHIRA_*.zip to diff the new collection against. By
    default the newest previous case is found automatically and the report
    shows only what is NEW.

.PARAMETER SetupTools
    Setup mode: restrict the download to specific tools, e.g.
    "hayabusa,winpmem" (default: offer and confirm all of them).

.PARAMETER Credential
    Deploy mode: alternate credential for the WinRM connection to the
    targets. Prompts when omitted.

.PARAMETER WatchInterval
    Watch mode: seconds between live-diff ticks (minimum 3, default 15).

.PARAMETER SeedValue
    SeedIocs mode: the indicator to validate, dedupe and append to the IOC
    feed (a hash, IP or domain).

.PARAMETER ExitVerdict
    Automation hook: after a run that computes a verdict (Collect/Parse),
    exit with the verdict rank as the process exit code when it is an alert
    (2 = SUSPICIOUS, 3 = LIKELY COMPROMISED, 4 = COMPROMISED; otherwise 0).
    Lets a scheduler sort hundreds of hosts by exit code alone.

.EXAMPLE
    .\Ophira.ps1
    Interactive start: pick your role, then collect this PC from the menu or
    pick any other task (deploy, analyze, tune, parse...). After each task
    you return to the menu.

.EXAMPLE
    .\Ophira.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
    Unattended Standard-depth collection of this PC with a ticket label;
    results land in OPHIRA_<host>_<stamp>\ next to the script.

.EXAMPLE
    .\Ophira.ps1 -SimpleUI
    The owner-friendly run used by RUN-OPHIRA.bat: guided, plain-language,
    ends with the DONE screen for sending the zip back to the IR team.

.EXAMPLE
    .\Ophira.ps1 -NoMenu -Preset Quick -LogWindow 30d
    Fast collection but analyze the last 30 days of logs instead of the
    default 7 (-LogStart/-LogEnd give an exact window instead).

.EXAMPLE
    .\Ophira.ps1 -NoMenu -Preset Standard -SharePath \\IR-SRV\collections$
    Collect and upload the finished zip straight to the IR share. Re-runs on
    the same host auto-diff against the previous case and report only NEW
    findings; -DeltaPath pins a specific older package instead.

.EXAMPLE
    .\Ophira.ps1 -Mode Deploy -ComputerName SRV01,SRV02 -Preset Quick -Credential (Get-Credential)
    Push-and-run on remote hosts over WinRM, 8 hosts in parallel. Use
    -TargetsFile hosts.txt for lists and -MaxThreads to tune parallelism.

.EXAMPLE
    .\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -PushTools
    Fleet run that also ships tools\endpoint\ (hayabusa, parsers) to each
    host first so full parsing happens on the endpoint, then cleans up.

.EXAMPLE
    .\Ophira.ps1 -Mode Analyze -AnalyzePath .\collections
    Merge every OPHIRA_*.zip in the folder into fleet_report.html: per-host
    verdicts, worst-first list, fleet ATT&CK roll-up, baselining proposals.

.EXAMPLE
    .\Ophira.ps1 -Mode Setup -SetupTools hayabusa,winpmem
    Download companion tools into tools\ (ENTER for all, or a comma list).
    -Mode Links just prints the official download pages.

.EXAMPLE
    .\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip
    Finish a case on YOUR PC: re-run every raw-driven parser (Amcache,
    LECmd, SQLECmd, chainsaw, hayabusa...) over the case's raw\ evidence and
    regenerate supertimeline, verdict, SIEM export and report.html.

.EXAMPLE
    .\Ophira.ps1 -Mode Focus -ParsePath .\OPHIRA_HOST_20260926_120000.zip -ProcessName evil.exe
    Build the activity-chain dossier of one entity (name, PID, path, hash,
    IP, ip:port or port) into focus\focus_report.html. -Mode Process is an
    alias. -After/-Before (yyyy-MM-dd [HH:mm]) optionally cut the dossier's
    evidence rows to a time window (date-only = midnight; undated rows are
    dropped and counted). -Mode Timeline -TimelineStart/-TimelineEnd cuts
    the case's master timeline to a UTC window the same way.

.EXAMPLE
    .\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip -ExitVerdict
    Automation: the exit code carries the verdict (2 SUSPICIOUS, 3 LIKELY
    COMPROMISED, 4 COMPROMISED, 0 clean/none) so a scheduler can sort
    hundreds of finished cases without reading reports.

.EXAMPLE
    .\Ophira.ps1 -Mode Tune
    False-positive feedback: shows your top-hit Sigma rules from the latest
    case; pick offenders to exclude or demote (travels with -PushTools).
    Related: -Mode UpdateRules refreshes the rule pack, -Mode Watch is a
    live read-only diff while a sample detonates, -Mode Canary self-tests
    the whole detection pipeline on this PC.

.EXAMPLE
    .\Ophira.ps1 -Mode Help
    Print this help text (same as pressing H in the task menu). No
    elevation, no configuration, no side effects.

.NOTES
    Read-only by design. PowerShell 5.0 or newer; older hosts get a clear
    fail-fast message (collect them remotely with -Mode Deploy instead).

    DEBUGGING A SUSPICIOUS NUMBER (v2.79 cookbook)
    Every number the report shows is backed by a CSV, a producer function and
    a case-log line (collection.log). Traceback path, most common claims:

    - Verdict rank / "LIKELY COMPROMISED": csv\verdict.json Signals[]. Each
      contributing signal is one log line "verdict signal: <name> (floor W x
      N) - <detail>" from Get-CompromiseVerdict/Add-Signal. A signal with
      count 0 is never added - no line means no contribution.
    - Coverage % (banner "evidence coverage N%"): the same verdict's
      Coverage[] rows. Every missing source logs "verdict coverage miss:
      <source> (weight W)". The percent is weighted-collected over total
      possible, minus 15 when the run was not elevated.
    - Hunt findings count (report Hunt section): csv\hunt_findings.csv, built
      by New-HuntFindings. Each rule R1-R38 logs one line "Rxx <rule>: <inputs
      in> -> <N> findings (<severities>)"; a skipped rule logs its gate (e.g.
      "gate: usb_devices empty or missing - skipped"). 0 rows in = the source
      CSV was empty or absent, not that the technique passed.
    - Sigma detections: csv\hayabusa_timeline.csv (+ per-rule event CSVs in
      csv\sigma_rules\, index.csv has per-rule hit counts). Producer
      New-SigmaRuleLogs. Verdict inputs are the crit/high rows AFTER the
      dedupe + self-noise filter (Remove-SigmaDuplicateEvents).
    - Process verdicts (report Processes section): csv\flash_process_scored.csv
      from the flash scoring module; the verdict's HIGH signal reads only
      Verdict=HIGH rows and needs score >= 8 or corroboration.
    - Leads (report lead cards): csv\derived\leads.csv, one ranked list built
      by Get-TriageLeads during regeneration.
    - What ran during a parse/finish: the end-of-run "regen summary:" block -
      one "[regen] <step> ... <producer> -> <output> in <X.X>s" line per
      derived artifact, plus each producer's own "    <thing>: N ..." lines.
    - Where collection itself is logged: collection.log in the case folder
      (worker_*.log files are merged into it). -LogLevel Quiet silences the
      console only; the log file always carries the full detail.
#>

[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Deploy', 'Analyze', 'Setup', 'Links', 'UpdateRules', 'Tune', 'Parse', 'Process', 'Timeline', 'Canary', 'Focus', 'Watch', 'SeedIocs', 'Help')]
    [string]$Mode = 'Collect',
    [string]$CaseID = "",
    [string]$Analyst = "",
    [string]$OutputPath = "",
    [ValidateSet('Flash', 'Quick', 'Standard', 'Full', 'Custom', 'DC', 'WebServer')]
    [string]$Preset = 'Standard',
    [switch]$NoMenu,
    [switch]$SimpleUI,
    [ValidateSet('Quiet', 'Normal', 'Verbose')]
    [string]$LogLevel = 'Normal',
    [switch]$IncludeMemory,
    [switch]$PushTools,
    [switch]$Sequential,
    [switch]$NoElevate,
    [int]$LogHours = 168,
    [string]$LogWindow = '',
    [string]$LogStart = '',
    [string]$LogEnd = '',
    [string]$SharePath = "",
    [string[]]$ComputerName,
    [string]$TargetsFile = '',
    [int]$MaxThreads = 8,
    [string]$AnalyzePath = '.',
    [string]$ParsePath = '',
    [string]$ProcessName = '',
    [string]$After = '',
    [string]$Before = '',
    [string]$TimelineStart = '',
    [string]$TimelineEnd = '',
    [string]$HayabusaPath = '',
    [string]$CanaryTarget = '',
    [string]$CanaryTargetUser = '',
    [switch]$KeepLogging,
    [string]$DeltaPath = '',
    [string[]]$SetupTools,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$WatchInterval = 15,
    [string]$SeedValue = '',
    [switch]$ExitVerdict
)

$ScriptVersion = "2.83"
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " Ophira needs PowerShell 5.0 or newer - this host runs" -ForegroundColor Red
    Write-Host " PowerShell v$($PSVersionTable.PSVersion). Collection here is not possible." -ForegroundColor Red
    Write-Host " What works instead:" -ForegroundColor White
    Write-Host "  - Run Ophira on a PC with PowerShell 5.1 and use menu option 2" -ForegroundColor Gray
    Write-Host "    (Push & run on REMOTE PCs) - it reaches this host over WinRM" -ForegroundColor Gray
    Write-Host "  - Or collect manually: evtx logs, registry hives, Prefetch folder" -ForegroundColor Gray
    Write-Host "  - Or have the IR team install WMF 5.1 on this host first" -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor Red
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    exit 1
}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# v2.69 (F2): help has ONE source of truth - the comment-based help block above the param
# block, rendered by Get-Help against this very file (no duplicate text to keep in sync).
# -Mode Help prints it and exits BEFORE config load, elevation and any case context;
# the menu's [H] entry calls the same renderer and returns to the menu.
function Show-ScriptHelp {
    try { Get-Help "$PSCommandPath" -Full }
    catch { Write-Host "  Ophira: could not render help ($($_.Exception.Message))" -ForegroundColor Yellow }
}
if ($Mode -eq 'Help') { Show-ScriptHelp; exit 0 }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostRole {
    # v2.21 lightweight role fingerprint: DC (NTDS present), WebServer (IIS installed), else Workstation.
    try {
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters') { return 'DC' }
    } catch { }
    try {
        if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\InetStp') -or (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return 'WebServer' }
    } catch { }
    return 'Workstation'
}
$script:HostRole = Get-HostRole
# Endpoint elevation is a LIVE fact during collection; Open-CaseSession replaces it with the
# case.json tri-state on -Mode Parse (null stays unknown there). Without this init the verdict
# rendered 'Endpoint elevation status unknown (parsed package)' on every fresh collect.
$script:EndpointAdmin = Test-IsAdmin

function Get-ArgString {
    $parts = @()
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $parts += "-$k" } }
        elseif ($v -is [bool]) { $parts += "-$k`:$v" }
        elseif ($v -is [int]) { $parts += "-$k $v" }
        else { $parts += "-$k `"$v`"" }
    }
    if ($script:ExtraRelaunchArgs.Count -gt 0) { $parts += $script:ExtraRelaunchArgs }
    $parts -join ' '
}

function Get-KitRoot {
    if ($KitRoot) { return $KitRoot }
    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Get-Location).Path
}

$cfgFile = Join-Path (Get-KitRoot) 'ophira.config.txt'
$script:OphiraRole = ''
$script:CfgTargets = ''
$script:CfgDeployPreset = ''
$script:CfgPushTools = $false
$script:CfgDeployShare = ''
$script:CfgThreads = 0
$script:ExtraRelaunchArgs = @()
if (Test-Path -LiteralPath $cfgFile) {
    try {
        foreach ($line in (Get-Content -LiteralPath $cfgFile)) {
            $l = ($line -replace '#.*$', '').Trim()
            if ($l -match '^(SHARE|CASE|ANALYST|ROLE|TARGETS|PRESET|PUSHTOOLS|DEPLOYSHARE|THREADS|LOGWINDOW|LOGSTART|LOGEND|LOGHOURS)\s*=\s*(.+)$') {
                $val = $Matches[2].Trim()
                switch ($Matches[1]) {
                    'SHARE' { if (-not $PSBoundParameters.ContainsKey('SharePath') -and $val) { $SharePath = $val } }
                    'CASE' { if (-not $PSBoundParameters.ContainsKey('CaseID') -and $val) { $CaseID = $val } }
                    'ANALYST' { if (-not $PSBoundParameters.ContainsKey('Analyst') -and $val) { $Analyst = $val } }
                    'ROLE' { if ($val -match '^(responder|owner)$') { $script:OphiraRole = $val.ToLower() } }
                    'TARGETS' { $script:CfgTargets = $val }
                    'PRESET' { if ($val -match '^(quick|standard)$') { $script:CfgDeployPreset = (Get-Culture).TextInfo.ToTitleCase($val.ToLower()) } }
                    'PUSHTOOLS' { $script:CfgPushTools = ($val -match '^(1|y|yes|true|t)$') }
                    'DEPLOYSHARE' { $script:CfgDeployShare = $val }
                    'THREADS' { $n = 0; if ([int]::TryParse($val, [ref]$n) -and $n -gt 0) { $script:CfgThreads = $n } }
                    # v2.43 analysis-window keys for the owner handoff: pre-fill before sending the
                    # folder; explicit flags always win; validated by Resolve-LogWindow downstream
                    'LOGWINDOW' { if (-not $PSBoundParameters.ContainsKey('LogWindow') -and $val) { $LogWindow = $val } }
                    'LOGSTART' { if (-not $PSBoundParameters.ContainsKey('LogStart') -and $val) { $LogStart = $val } }
                    'LOGEND' { if (-not $PSBoundParameters.ContainsKey('LogEnd') -and $val) { $LogEnd = $val } }
                    'LOGHOURS' { $n2 = 0; if ([int]::TryParse($val, [ref]$n2) -and $n2 -ge 0 -and -not $PSBoundParameters.ContainsKey('LogHours')) { $LogHours = $n2 } }
                }
            }
        }
    } catch { }
}

function Save-OphiraConfig {
    param([hashtable]$Values)
    try {
        $path = Join-Path (Get-KitRoot) 'ophira.config.txt'
        $lines = @()
        if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
        foreach ($key in $Values.Keys) {
            $pattern = "^\s*$key\s*="
            $found = $false
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match $pattern) { $lines[$i] = "$key=$($Values[$key])"; $found = $true }
            }
            if (-not $found) { $lines += "$key=$($Values[$key])" }
        }
        Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
        return $true
    } catch { return $false }
}
$script:SimpleUI = [bool]$SimpleUI
$script:NoMenu = [bool]$NoMenu
$script:Verbosity = @('Quiet', 'Normal', 'Verbose').IndexOf("$LogLevel")
if ($script:Verbosity -lt 0) { $script:Verbosity = 1 }

function Write-CaseLog {
    param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    if (-not $NoConsole -and -not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host $line -ForegroundColor $Color }
    Add-Content -LiteralPath $CaseLog -Value $line -Encoding UTF8
}

function Out-Flash {
    param([string]$Text, [string]$Color = 'White')
    if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host $Text -ForegroundColor $Color }
    $script:FlashLines.Add(($Text -replace "\x1b\[[0-9;]*m", ''))
}

# v2.69 (F1): RUN detail data - Save-Rows appends every artifact save (relative path + row
# count); the module dispatchers reset the list per module and Write-RunDetail renders it.
# Console-only: the case log keeps its own Save-Rows records, this list feeds nothing else.
$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]

# v2.69 (F1): one RUN detail line per finished module - id + name, key artifact + row count,
# elapsed. Prints on BOTH screens (the SimpleUI front-screen and the standard menu run) at
# Normal and Verbose: unlike Write-CaseLog/Out-Flash these lines ARE the run feedback itself,
# so they are NOT SimpleUI-gated (the front screen shows nothing else per-module) - but
# -LogLevel Quiet still silences them like the rest of the console noise. Controller-side
# only (the inline dispatcher and the pooled phase loops call it; workers report artifacts
# through the Saved result field), so it is deliberately NOT in $script:SharedFunctions.
function Write-RunDetail {
    param($Id, [string]$Name, [double]$Seconds, [string]$ErrMsg = '', $Saved = $null)
    if ($script:Verbosity -lt 1) { return }
    $disp = "$Name"
    if ($disp.Length -gt 38) { $disp = $disp.Substring(0, 35) + '...' }
    $dots = '.' * [math]::Max(1, 42 - $disp.Length)
    $art = 'no csv artifacts'
    if ("$ErrMsg") {
        $emsg = "$ErrMsg"
        if ($emsg.Length -gt 70) { $emsg = $emsg.Substring(0, 67) + '...' }
        $art = "ERROR: $emsg"
    } elseif ($Saved -and @($Saved).Count -gt 0) {
        $rows = 0; $failed = 0
        foreach ($s in @($Saved)) { if ((ConvertTo-SafeInt $s.Rows) -lt 0) { $failed++ } else { $rows += (ConvertTo-SafeInt $s.Rows) } }
        if (@($Saved).Count -eq 1) {
            $one = @($Saved)[0]
            $art = if ((ConvertTo-SafeInt $one.Rows) -lt 0) { "$($one.Path) FAILED" } else { "$($one.Path) $($one.Rows) rows" }
        } else {
            $art = ("{0} csv, {1} rows" -f @($Saved).Count, $rows)
            if ($failed -gt 0) { $art += ", $failed FAILED" }
        }
    }
    Write-Host ("  [{0}] {1} {2} {3} {4:N1}s" -f $Id, $disp, $dots, $art, $Seconds) -ForegroundColor DarkGray
}

# v2.42 CSV sortment: one name->category map decides where every known case CSV lives
# (csv\<cat>\<name>.csv). Unknown names stay flat. Import-CaseCsv / Test-CaseCsv read
# flat-first-then-mapped, so old flat cases and every existing consumer keep working.
$script:CsvCatMap = @{
    # VOLATILE
    'processes' = 'volatile'; 'processes_flagged' = 'volatile'; 'process_hashes' = 'volatile'
    'connections' = 'volatile'; 'connections_public_established' = 'volatile'; 'dns_cache' = 'volatile'
    'arp_table' = 'volatile'; 'logon_sessions' = 'volatile'; 'drivers' = 'volatile'; 'drivers_flagged' = 'volatile'
    'svchost_audit' = 'volatile'; 'bam_lastexec' = 'volatile'
    'flash_process_scored' = 'volatile'; 'flash_ioc_hits' = 'volatile'; 'flash_public_connections' = 'volatile'
    # PERSISTENCE
    'autoruns_runkeys' = 'persistence'; 'autoruns_startup_folders' = 'persistence'
    'services' = 'persistence'; 'services_flagged' = 'persistence'
    'scheduled_tasks' = 'persistence'; 'scheduled_tasks_flagged' = 'persistence'
    'scheduled_taskcache' = 'persistence'; 'task_deletions' = 'persistence'; 'esent_ntds' = 'persistence'
    'wmi_event_filters' = 'persistence'; 'wmi_event_consumers' = 'persistence'; 'wmi_bindings' = 'persistence'
    'asep_sweep' = 'persistence'
    # NETWORK
    'net_interfaces' = 'network'; 'net_reachable_subnets' = 'network'; 'smb_hosted_shares' = 'network'
    'smb_mounted_shares' = 'network'; 'smb_active_connections' = 'network'; 'saved_credentials' = 'network'
    'proxy_settings' = 'network'; 'net_active_probes' = 'network'; 'firewall_profiles' = 'network'
    # LOGS
    'security_events' = 'logs'; 'security_auth_events' = 'logs'; 'security_bruteforce_candidates' = 'logs'
    'security_auth_summary' = 'logs'; 'security_proc_events' = 'logs'; 'security_task_install' = 'logs'
    'security_share_access' = 'logs'; 'security_kerberos' = 'logs'; 'security_ds_access' = 'logs'
    'powershell_events' = 'logs'; 'sysmon_events' = 'logs'; 'sysmon_network' = 'logs'; 'sysmon_dns' = 'logs'
    'sysmon_image_load' = 'logs'; 'sysmon_process_access' = 'logs'; 'sysmon_registry' = 'logs'
    'sysmon_file_time' = 'logs'; 'sysmon_proc_create' = 'logs'
    'sysmon_file_create' = 'logs'; 'sysmon_file_delete' = 'logs'
    'sysmon_remote_thread' = 'logs'; 'sysmon_pipes' = 'logs'
    'sysmon_proc_tamper' = 'logs'; 'sysmon_raw_access' = 'logs'; 'sysmon_wmi' = 'logs'
    'shimcache' = 'artifacts'; 'shimcache_exec' = 'timeline'
    'radar_exec' = 'artifacts'; 'appswitched' = 'artifacts'
    'rdp_localsession' = 'logs'; 'rdp_connections' = 'logs'; 'system_events' = 'logs'; 'system_new_services' = 'logs'
    'hayabusa_timeline' = 'logs'; 'hayabusa_report' = 'logs'; 'logon_summary' = 'logs'
    'ps_decoded_commands' = 'logs'; 'yara_hits' = 'logs'; 'yara_scanned' = 'logs'
    'beacon_candidates' = 'logs'; 'dns_beacon_candidates' = 'logs'; 'application_events' = 'logs'
    # ARTIFACTS
    'prefetch_index' = 'artifacts'; 'prefetch_parsed' = 'artifacts'; 'userassist' = 'artifacts'
    'srum_usage' = 'artifacts'; 'execution_timeline' = 'artifacts'; 'mft_recent' = 'artifacts'
    'ads_findings' = 'artifacts'
    'amcache' = 'artifacts'; 'lnk_parsed' = 'artifacts'; 'jumplist_parsed' = 'artifacts'
    # v2.74: the EZ native tools write --csvf output straight into the csv ROOT, so the split
    # families (amcache_*, jumplist_parsed*) and the USN burst export landed loose - the v2.42
    # exact-name map never caught them and the analyst opened csv\ to a wall. Wildcard keys:
    # Get-CaseCsvPath tries the exact key first, then -like over the sorted keys.
    'amcache_*' = 'artifacts'; 'jumplist_parsed*' = 'artifacts'; 'prefetch_parsed*' = 'artifacts'
    'usn_write_bursts' = 'artifacts'
    'recyclebin' = 'artifacts'; 'recentfilecache' = 'artifacts'; 'shellbags' = 'artifacts'
    'registry_recmd' = 'artifacts'; 'browser_files' = 'artifacts'; 'browser_history' = 'artifacts'
    'browser_downloads' = 'artifacts'; 'browser_searches' = 'artifacts'
    # DEFENDER
    'defender_status' = 'defender'; 'defender_threats' = 'defender'; 'defender_preferences' = 'defender'
    'defender_events' = 'defender'; 'defender_config_events' = 'defender'
    # MEMORY
    'memory_live_scan' = 'memory'; 'memory_malfind' = 'memory'; 'memory_netscan' = 'memory'
    # CONTEXT
    'powershell_console_history' = 'context'; 'rdp_client_targets' = 'context'; 'recyclebin_index' = 'context'
    'bits_jobs' = 'context'; 'domain_info' = 'context'; 'local_admins' = 'context'
    'certificates' = 'context'; 'posture' = 'context'; 'loldrivers_hits' = 'context'
    'usb_devices' = 'context'; 'office_mru' = 'context'; 'ual_files' = 'context'
    'webshell_candidates' = 'context'
    'iis_requests' = 'context'; 'iis_anomalies' = 'context'; 'startup_info' = 'context'
    'wer_reports' = 'context'; 'server_logs' = 'context'; 'credential_sweep' = 'context'; 'remote_access' = 'context'
    # DERIVED (rebuilt by Invoke-RegenerateOutputs / analyst modes)
    'supertimeline' = 'derived'; 'parse_needed' = 'derived'; 'hunt_findings' = 'derived'
    'entities_binaries' = 'derived'; 'entities_accounts' = 'derived'; 'entities_remotes' = 'derived'
    'session_activity' = 'derived'; 'process_chains' = 'derived'; 'logging_gaps' = 'derived'
    'ioc_hits_amcache' = 'derived'; 'ioc_hits_browser' = 'derived'; 'ioc_hits_dns' = 'derived'
    'ioc_hits_network' = 'derived'; 'ioc_hits_mft' = 'derived'; 'ioc_hits_hash' = 'derived'
    'ioc_export' = 'derived'; 'process_pivot' = 'derived'; 'leads' = 'derived'
}

function Get-LocalAdminMembers {
    # v2.58: parse the member lines out of "net localgroup administrators" output. The old
    # code used a hardcoded Select-Object -Skip 6 which overshot the 4 non-blank header lines
    # real output has (Alias/Comment/Members/dashes) - the members themselves were skipped and
    # local_admins.csv was ALWAYS empty. Locale ceiling: net.exe output is localized on
    # non-English Windows; this parser matches the English shapes (status quo there).
    param([string[]]$Lines)
    $members = @()
    $inMembers = $false
    foreach ($line in @($Lines)) {
        if ("$line" -notmatch '\S') { continue }
        if ("$line" -match '^Members\s*$') { $inMembers = $true; continue }
        if (-not $inMembers) { continue }
        if ("$line" -match '^-{5,}') { continue }
        if ("$line" -match 'command completed successfully') { break }
        $members += ("$line".Trim())
    }
    return $members
}

function Get-CaseCsvPath {
    # Relative path of a case CSV under CsvDir: mapped category subfolder or flat fallback.
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $key = ($Name -replace '\.csv$', '').ToLower()
    $cat = $null
    if ($script:CsvCatMap) {
        $cat = $script:CsvCatMap[$key]
        if (-not $cat) {
            # v2.74: wildcard map entries (amcache_*, jumplist_parsed*, prefetch_parsed*) - the
            # EZ parsers' --csvf split families. Exact keys above always outrank wildcards and
            # the sorted scan keeps the first match deterministic.
            foreach ($k in ($script:CsvCatMap.Keys | Sort-Object)) {
                if ($k -match '[*?\[]' -and $key -like $k) { $cat = $script:CsvCatMap[$k]; break }
            }
        }
    }
    if ($cat) { return "$cat\$Name" }
    return $Name
}

function Test-CaseCsv {
    # Existence check for a case CSV: flat first (old cases, native-tool leftovers, wildcards),
    # then the mapped subfolder. Wildcard names keep working through the flat branch.
    # v2.65: this wildcard-awareness is INTENTIONAL - jumplist_parsed*-style lookups resolve
    # here. Import-CaseCsv reads -LiteralPath instead; that asymmetry is by design, don't unify.
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    if (Test-Path (Join-Path $CsvDir $Name)) { return $true }
    return (Test-Path (Join-Path $CsvDir (Get-CaseCsvPath $Name)))
}

function Get-CaseCsvFullPath {
    # Absolute path for WRITES/native-tool args into the mapped location; creates the folder.
    param([string]$Name)
    $p = Join-Path $CsvDir (Get-CaseCsvPath $Name)
    $d = Split-Path $p -Parent
    if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $p
}

function Import-CsvFlatMapped {
    # Flat-first-then-mapped reader for ARBITRARY case csv dirs (canary B-side zips, fleet).
    param([string]$Dir, [string]$Name)
    $n = if ($Name -match '\.csv$') { $Name } else { "$Name.csv" }
    foreach ($p in @((Join-Path $Dir $n), (Join-Path $Dir (Get-CaseCsvPath $Name)))) {
        if (Test-Path -LiteralPath $p) { try { return @(Import-Csv -LiteralPath $p -ErrorAction Stop) } catch { return @() } }
    }
    return @()
}

function Save-Rows {
    param([string]$Name, $Rows)
    $path = Get-CaseCsvFullPath $Name
    $rel = "$((Get-CaseCsvPath $Name))"
    try {
        if ($Rows -and @($Rows).Count -gt 0) {
            # v2.80 (F2): Export-Csv keeps only the FIRST object's properties as the header, so mixed
            # event-ID lists lose later schemas (4.9: 4769 TicketEnc after a 4768, 5136 ObjectDN after
            # a 4662). Union schema: every row carries all columns seen on any row, empty when N/A.
            $all = @($Rows)
            $cols = New-Object System.Collections.Generic.List[string]
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' (,[System.StringComparer]::OrdinalIgnoreCase)
            foreach ($r in $all) {
                if ($null -eq $r) { continue }
                foreach ($p in $r.PSObject.Properties) { if ($seen.Add("$($p.Name)")) { $cols.Add("$($p.Name)") } }
            }
            foreach ($r in $all) {
                if ($null -eq $r) { continue }
                foreach ($c in $cols) {
                    if ($null -eq $r.PSObject.Properties[$c]) { Add-Member -InputObject $r -NotePropertyName $c -NotePropertyValue '' }
                }
            }
            $all | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
            Write-CaseLog ("    saved {0} rows -> csv\{1}" -f @($Rows).Count, $rel) 'DarkGray'
            # v2.69 (F1): feed the RUN detail line (path + real row count; console-only, log keeps its own record)
            # ($null -ne, NOT truthiness - an EMPTY List is falsy in PS and would skip the first save forever)
            if ($null -ne $script:SavedArtifacts) { $script:SavedArtifacts.Add([pscustomobject]@{ Path = "csv\$rel"; Rows = @($Rows).Count }) }
        } else {
            "# no entries" | Set-Content -LiteralPath $path -Encoding UTF8
            Write-CaseLog "    csv\$rel (empty)" 'DarkGray'
            if ($null -ne $script:SavedArtifacts) { $script:SavedArtifacts.Add([pscustomobject]@{ Path = "csv\$rel"; Rows = 0 }) }
        }
    } catch {
        "FAILED: $($_.Exception.Message)" | Set-Content -LiteralPath $path -Encoding UTF8
        Write-CaseLog "    csv\$rel FAILED" 'DarkYellow'
        if ($null -ne $script:SavedArtifacts) { $script:SavedArtifacts.Add([pscustomobject]@{ Path = "csv\$rel"; Rows = -1 }) }
    }
}

function Out-RawText {
    param([string]$SubDir, [string]$Name, [string[]]$Text)
    try {
        $dir = Join-Path $RawDir $SubDir
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $path = Join-Path $dir $Name
        if ($Text) { $Text | Set-Content -LiteralPath $path -Encoding UTF8 } else { "# empty" | Set-Content -LiteralPath $path -Encoding UTF8 }
    } catch { }
}

function Invoke-ExeCapture {
    param([string]$SubDir, [string]$Name, [string]$Exe, [string]$Arguments)
    try {
        $out = if ($Arguments) { & $Exe $Arguments 2>&1 } else { & $Exe 2>&1 }
        Out-RawText -SubDir $SubDir -Name $Name -Text (@($out) | ForEach-Object { "$_" })
    } catch { }
}

function Get-WmiOrCim {
    param([string]$Class, [string]$Filter = '', [string]$Namespace = '')
    try {
        $extra = @{}
        if ($Namespace) { $extra.Namespace = $Namespace }
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter @extra }
            return Get-CimInstance -ClassName $Class @extra
        } else {
            if ($Filter) { return Get-WmiObject -Class $Class -Filter $Filter @extra }
            return Get-WmiObject -Class $Class @extra
        }
    } catch { return $null }
}

function Convert-WmiDate {
    param($Value)
    if (-not $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    try { return [System.Management.ManagementDateTimeConverter]::ToDateTime("$Value") } catch { return $null }
}

function Get-InvariantDate {
    # Culture-invariant datetime parse for persisted CSV values ('02/03/2026' must not flip
    # meaning with the OS locale); returns [datetime]::MinValue when unparseable so callers
    # can filter. Shared with pool workers via $script:SharedFunctions.
    param([object]$Value)
    if ($Value -is [datetime]) { return $Value }
    try { return [datetime]::Parse("$Value", [System.Globalization.CultureInfo]::InvariantCulture) } catch { return [datetime]::MinValue }
}

function Test-IsPublicIp {
    param([string]$IpString)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$ip)) { return $false }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq 'InterNetworkV6') {
    if ($b[0] -eq 0 -and $b[1] -eq 0) { return $false }
    if ((($b[0] -band 0xFE) -eq 0xFC)) { return $false }
    if ($b[0] -eq 0xFE -and (($b[1] -band 0xC0) -eq 0x80)) { return $false }
    if ($b[0] -eq 0xFF) { return $false }
    return $true
    }
    if ($b[0] -eq 0) { return $false }
    if ($b[0] -eq 10 -or $b[0] -eq 127) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false } # CGNAT 100.64.0.0/10 - ISP carrier NAT (mobile hotspots), not public internet
    if ($b[0] -ge 224) { return $false }
    return $true
}

function Get-IpCloudClass {
    # v2.55: static cloud-provider IP classification (no network calls). Returns the provider
    # name for known cloud/CDN ranges, empty string for unknown/non-cloud. Ranges sourced
    # from provider published IP docs as of 2026-10; refresh periodically.
    param([string]$IpString)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$ip)) { return '' }
    if ($ip.AddressFamily -ne 'InterNetwork') { return '' }
    $b = $ip.GetAddressBytes()
    $o1 = [int]$b[0]; $o2 = [int]$b[1]
    # Microsoft (Azure/O365/Defender cloud) - major published ranges
    # v2.82: Azure fills - 4.208.0.0/12, 13.64.0.0/11, 13.96.0.0/13 (a 4.213.x hit on a real
    # case surfaced as "unknown provider" because no octet-1 rule existed for 4.x)
    if ($o1 -eq 4 -and $o2 -ge 208 -and $o2 -le 223) { return 'microsoft' }
    if ($o1 -eq 13 -and $o2 -ge 65 -and $o2 -le 95) { return 'microsoft' }
    if ($o1 -eq 13 -and $o2 -ge 96 -and $o2 -le 106) { return 'microsoft' }
    if ($o1 -eq 13 -and $o2 -ge 107 -and $o2 -le 109) { return 'microsoft' }
    if ($o1 -eq 13 -and $o2 -eq 64) { return 'microsoft' }
    if ($o1 -eq 20 -and $o2 -ge 36 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 20 -and $o2 -ge 143 -and $o2 -le 190) { return 'microsoft' }
    if ($o1 -eq 40 -and $o2 -ge 64 -and $o2 -le 124) { return 'microsoft' }
    if ($o1 -eq 48 -and $o2 -ge 44 -and $o2 -le 218) { return 'microsoft' }
    if ($o1 -eq 51 -and $o2 -ge 4 -and $o2 -le 152) { return 'microsoft' }
    if ($o1 -eq 52 -and $o2 -ge 96 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 64 -and $o2 -ge 124 -and $o2 -le 144) { return 'microsoft' }
    if ($o1 -eq 65 -and $o2 -ge 44 -and $o2 -le 152) { return 'microsoft' }
    if ($o1 -eq 70 -and $o2 -ge 36 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 74 -and $o2 -ge 122 -and $o2 -le 255) { return 'microsoft' }
    if ($o1 -eq 98 -and $o2 -ge 164 -and $o2 -le 252) { return 'microsoft' }
    if ($o1 -eq 103 -and $o2 -ge 4 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 104 -and $o2 -ge 40 -and $o2 -le 200) { return 'microsoft' }
    if ($o1 -eq 131 -and $o2 -ge 107 -and $o2 -le 255) { return 'microsoft' }
    if ($o1 -eq 134 -and $o2 -ge 148 -and $o2 -le 208) { return 'microsoft' }
    if ($o1 -eq 147 -and $o2 -ge 16 -and $o2 -le 40) { return 'microsoft' }
    if ($o1 -eq 150 -and $o2 -ge 128 -and $o2 -le 248) { return 'microsoft' }
    if ($o1 -eq 152 -and $o2 -ge 96 -and $o2 -le 188) { return 'microsoft' }
    if ($o1 -eq 157 -and $o2 -ge 54 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 158 -and $o2 -ge 160 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 191 -and $o2 -ge 232 -and $o2 -le 255) { return 'microsoft' }
    if ($o1 -eq 192 -and $o2 -eq 32) { return 'microsoft' }
    if ($o1 -eq 192 -and $o2 -eq 200) { return 'microsoft' }
    if ($o1 -eq 192 -and $o2 -eq 250) { return 'microsoft' }
    if ($o1 -eq 193 -and $o2 -eq 220) { return 'microsoft' }
    if ($o1 -eq 198 -and $o2 -ge 1 -and $o2 -le 252) { return 'microsoft' }
    if ($o1 -eq 199 -and $o2 -ge 6 -and $o2 -le 240) { return 'microsoft' }
    if ($o1 -eq 204 -and $o2 -ge 136 -and $o2 -le 160) { return 'microsoft' }
    if ($o1 -eq 207 -and $o2 -ge 128 -and $o2 -le 152) { return 'microsoft' }
    if ($o1 -eq 208 -and $o2 -ge 68 -and $o2 -le 192) { return 'microsoft' }
    if ($o1 -eq 209 -and $o2 -ge 240 -and $o2 -le 255) { return 'microsoft' }
    if ($o1 -eq 216 -and $o2 -ge 32 -and $o2 -le 224) { return 'microsoft' }
    if ($o1 -eq 217 -and $o2 -eq 168) { return 'microsoft' }
    # Amazon AWS
    if ($o1 -eq 3 -and $o2 -ge 0 -and $o2 -le 255) { return 'amazon' }
    if ($o1 -eq 13 -and $o2 -ge 226 -and $o2 -le 250) { return 'amazon' }
    if ($o1 -eq 15 -and $o2 -ge 176 -and $o2 -le 255) { return 'amazon' }
    if ($o1 -eq 18 -and $o2 -ge 32 -and $o2 -le 255) { return 'amazon' }
    if ($o1 -eq 34 -and $o2 -ge 0 -and $o2 -le 255) { return 'amazon' }
    if ($o1 -eq 52 -and $o2 -ge 0 -and $o2 -le 95) { return 'amazon' }
    if ($o1 -eq 54 -and $o2 -ge 64 -and $o2 -le 255) { return 'amazon' }
    if ($o1 -eq 99 -and $o2 -ge 76 -and $o2 -le 159) { return 'amazon' }
    if ($o1 -eq 205 -and $o2 -ge 251 -and $o2 -le 255) { return 'amazon' }
    # Google Cloud
    if ($o1 -eq 8 -and $o2 -ge 0 -and $o2 -le 31) { return 'google' }
    if ($o1 -eq 34 -and $o2 -ge 64 -and $o2 -le 127) { return 'google' }
    if ($o1 -eq 35 -and $o2 -ge 184 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 104 -and $o2 -ge 196 -and $o2 -le 247) { return 'google' }
    if ($o1 -eq 107 -and $o2 -ge 180 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 142 -and $o2 -ge 250 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 146 -and $o2 -ge 148 -and $o2 -le 207) { return 'google' }
    if ($o1 -eq 162 -and $o2 -ge 216 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 172 -and $o2 -ge 253 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 173 -and $o2 -ge 194 -and $o2 -le 255) { return 'google' }
    if ($o1 -eq 192 -and $o2 -ge 158 -and $o2 -le 31) { return 'google' }
    if ($o1 -eq 199 -and $o2 -ge 36 -and $o2 -le 159) { return 'google' }
    if ($o1 -eq 209 -and $o2 -ge 85 -and $o2 -le 127) { return 'google' }
    # Cloudflare
    if ($o1 -eq 103 -and $o2 -ge 21 -and $o2 -le 22) { return 'cloudflare' }
    if ($o1 -eq 103 -and $o2 -eq 31) { return 'cloudflare' }
    if ($o1 -eq 103 -and $o2 -eq 224) { return 'cloudflare' }
    if ($o1 -eq 104 -and $o2 -ge 16 -and $o2 -le 31) { return 'cloudflare' }
    if ($o1 -eq 108 -and $o2 -eq 162) { return 'cloudflare' }
    if ($o1 -eq 131 -and $o2 -eq 107) { return 'cloudflare' }
    if ($o1 -eq 141 -and $o2 -ge 101 -and $o2 -le 107) { return 'cloudflare' }
    if ($o1 -eq 162 -and $o2 -ge 158 -and $o2 -le 163) { return 'cloudflare' }
    if ($o1 -eq 172 -and $o2 -ge 64 -and $o2 -le 127) { return 'cloudflare' }
    if ($o1 -eq 173 -and $o2 -eq 245) { return 'cloudflare' }
    if ($o1 -eq 188 -and $o2 -ge 114 -and $o2 -le 121) { return 'cloudflare' }
    if ($o1 -eq 190 -and $o2 -eq 93) { return 'cloudflare' }
    if ($o1 -eq 197 -and $o2 -eq 234) { return 'cloudflare' }
    if ($o1 -eq 198 -and $o2 -ge 41 -and $o2 -le 64) { return 'cloudflare' }
    if ($o1 -eq 103 -and $o2 -eq 252) { return 'cloudflare' }
    # Akamai
    if ($o1 -eq 23 -and $o2 -ge 32 -and $o2 -le 255) { return 'akamai' }
    if ($o1 -eq 104 -and $o2 -ge 64 -and $o2 -le 127) { return 'akamai' }
    if ($o1 -eq 118 -and $o2 -eq 6) { return 'akamai' }
    if ($o1 -eq 172 -and $o2 -ge 224 -and $o2 -le 252) { return 'akamai' }
    if ($o1 -eq 184 -and $o2 -ge 24 -and $o2 -le 51) { return 'akamai' }
    if ($o1 -eq 184 -and $o2 -ge 84 -and $o2 -le 107) { return 'akamai' }
    if ($o1 -eq 193 -and $o2 -ge 108 -and $o2 -le 111) { return 'akamai' }
    if ($o1 -eq 205 -and $o2 -ge 185 -and $o2 -le 223) { return 'akamai' }
    return ''
}

function Get-DomainProvider {
    # v2.82: classify a hostname by domain suffix - complements Get-IpCloudClass (an IP-range
    # miss is often still the provider's own domain, e.g. Azure front doors fronting
    # microsoft.com). Ordered, deterministic, no network calls. Empty string = unrecognized.
    param([string]$Hostname)
    if (-not "$Hostname") { return '' }
    $h = "$Hostname".TrimEnd('.').ToLower()
    foreach ($e in @(
        # ordered list 'provider suffix' - first suffix match wins
        'microsoft microsoft.com','microsoft windows.com','microsoft windowsupdate.com','microsoft update.microsoft.com','microsoft msn.com','microsoft office.com','microsoft office.net','microsoft live.com','microsoft microsoftonline.com','microsoft msftconnecttest.com','microsoft msedge.net','microsoft azure.com','microsoft azureedge.net','microsoft windowsazure.com','microsoft onedrive.com','microsoft sharepoint.com','microsoft sharepointonline.com','microsoft bing.com','microsoft xbox.com','microsoft visualstudio.com','microsoft github.com','microsoft githubusercontent.com','microsoft github.io','microsoft msocsp.com','microsoft msocsp.net','microsoft msft.net',
        'amazon amazonaws.com','amazon amazon.com','amazon awsstatic.com','amazon cloudfront.net','amazon primevideo.com',
        'google google.com','google gstatic.com','google googleapis.com','google googleusercontent.com','google youtube.com','google ytimg.com','google googlevideo.com','google google-analytics.com','google doubleclick.net','google android.com','google googlemail.com',
        'cloudflare cloudflare.com','cloudflare cloudflareclient.com','cloudflare cloudflareinsights.com','cloudflare pages.dev',
        'akamai akamai.com','akamai akamaihd.net','akamai akamaized.net','akamai akamai.net','akamai edgekey.net','akamai edgesuite.net'
    )) {
        $sp = $e.IndexOf(' ')
        $s = $e.Substring($sp + 1)
        if ($h -eq $s -or $h -like "*.$s") { return $e.Substring(0, $sp) }
    }
    return ''
}

function Test-IsUserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    # v2.44 FP fix: Store-app payloads under WindowsApps are TrustedInstaller-only - never flag
    if ($Path -match '(?i)\\WindowsApps\\') { return $false }
    # C:\Intel, C:\AMD, C:\Windows\Tasks are only user-writable AT THE DRIVE ROOT - unanchored
    # \Intel\ also matched Store VFS paths (...\VFS\ProgramFilesX64\Intel\...) and flagged
    # Intel's signed graphics service as running from a user-writable path
    return ($Path -match '(?i)\\Users\\|\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\AppData\\|\\Users\\Public\\|\\PerfLogs\\|^[A-Za-z]:\\Intel\\|^[A-Za-z]:\\AMD\\|^[A-Za-z]:\\Windows\\Tasks\\|\\Downloads\\|\\Desktop\\|\\Temporary Internet')
}

function Get-SignatureInfo {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        $signer = ''
        if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -replace ',.*$', '') -replace '^CN=', '' }
        return [pscustomobject]@{ Status = "$($sig.Status)"; Signer = $signer }
    } catch { return $null }
}

function Get-ProcessInventory {
    $wmi = Get-WmiOrCim -Class Win32_Process
    if (-not $wmi) { return @() }
    $meta = @{}
    try {
        Get-Process | ForEach-Object {
            $c = ''; $d = ''
            try { $c = $_.Company; $d = $_.Description } catch { }
            $meta[[int]$_.Id] = @{ Company = $c; Desc = $d }
        }
    } catch { }
    $fileMeta = @{}

    $rows = foreach ($p in $wmi) {
        $m = $meta[[int]$p.ProcessId]
        $flags = New-Object System.Collections.Generic.List[string]
        $path = $p.ExecutablePath
        $company = ''; $desc = ''
        if ($path) {
            if ($m -and $m.Company) { $company = $m.Company; $desc = $m.Desc }
            elseif (Test-Path -LiteralPath $path) {
                if (-not $fileMeta.ContainsKey($path)) {
                    try {
                        $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
                        $fileMeta[$path] = @{ Company = $vi.CompanyName; Desc = $vi.FileDescription }
                    } catch { $fileMeta[$path] = @{ Company = ''; Desc = '' } }
                }
                $company = $fileMeta[$path].Company
                $desc = $fileMeta[$path].Desc
                if (-not $company) { $flags.Add('NO-COMPANY') }
            } else { $flags.Add('BINARY-MISSING') }
        }
        if (Test-IsUserWritablePath $path) { $flags.Add('USER-WRITABLE-PATH') }
        if ($p.Name -match '(?i)^svchost\.exe$' -and $path -and $path -notmatch '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\') { $flags.Add('SVCHOST-OUT-OF-SYSTEM32') }
        if ($p.Name -match '(?i)^(lsass|csrss|services|winlogon|smss)\.exe$' -and $path -and $path -notmatch '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\') { $flags.Add('CRITICAL-PROC-ODD-PATH') }
        [pscustomobject]@{
            PID          = $p.ProcessId
            PPID         = $p.ParentProcessId
            Name         = $p.Name
            Path         = $path
            Company      = $company
            Description  = $desc
            CommandLine  = $p.CommandLine
            Created      = (Convert-WmiDate $p.CreationDate)
            Flags        = ($flags -join ';')
        }
    }
    return $rows
}

function Get-ConnectionTable {
    $rows = @()
    $pmap = @{}
    try { Get-Process | ForEach-Object { $pmap[[int]$_.Id] = $_.Path } } catch { }
    $tcp = $null
    try { $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue } catch { }
    if ($tcp) {
        $rows = foreach ($c in $tcp) {
            $procPath = $pmap[[int]$c.OwningProcess]
            [pscustomobject]@{
                Proto = 'TCP'; LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
                RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; State = $c.State
                PID = $c.OwningProcess; ProcessPath = $procPath
                Public = (Test-IsPublicIp "$($c.RemoteAddress)")
            }
        }
    } else {
        $lines = & netstat.exe -ano 2>$null | Where-Object { $_ -match '^\s*(TCP|UDP)' }
        $rows = foreach ($l in $lines) {
            $t = ($l -replace '^\s+', '') -split '\s+'
            $proto = $t[0]
            $local = ($t[1] -split ':')[0]; $lport = ($t[1] -split ':')[-1]
            $remote = ''; $rport = ''; $state = ''
            if ($proto -eq 'TCP') { $remote = ($t[2] -split ':')[0]; $rport = ($t[2] -split ':')[-1]; $state = $t[3]; $pid = $t[4] }
            else { $remote = $t[2]; $state = ''; $pid = $t[3] }
            $procPath = $pmap[[int]$pid]
            [pscustomobject]@{
                Proto = $proto; LocalAddress = $local; LocalPort = $lport
                RemoteAddress = $remote; RemotePort = $rport; State = $state
                PID = $pid; ProcessPath = $procPath
                Public = (Test-IsPublicIp "$remote")
            }
        }
    }
    return $rows
}

function Get-DnsCacheRows {
    try {
        if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
            return @(Get-DnsClientCache | Select-Object Entry, Data, Type, TimeToLive)
        }
    } catch { }
    $out = & ipconfig.exe /displaydns 2>$null
    return @($out | Select-String -Pattern 'Record Name|--------' | ForEach-Object { "$_".Trim() })
}

function Get-ArpRows {
    try {
        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
            return @(Get-NetNeighbor | Where-Object { $_.IPAddress -notmatch '^(224\.|239\.|ff)' } |
                Select-Object IPAddress, LinkLayerAddress, State, ifIndex)
        }
    } catch { }
    $out = & arp.exe -a 2>$null
    return @($out | Select-String -Pattern '\d+\.\d+\.\d+\.\d+' | ForEach-Object { "$_".Trim() })
}

function Get-SysmonState {
    $present = $false
    try {
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64') { $present = $true }
        elseif (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon') { $present = $true }
        elseif (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) { $present = $true }
    } catch { }
    return $present
}

function Get-ToolsDir {
    $root = Get-KitRoot
    if (Test-Path (Join-Path $root 'tools')) { return (Join-Path $root 'tools') }
    return $null
}

function Copy-LockedFile {
    # Read-only copy of an in-use file via esentutl VSS snapshot, with retry - parallel
    # esentutl /vss calls (e.g. SRUM + NTDS in different workers) race on the VSS snapshot set.
    param([string]$Source, [string]$Dest, [int]$Retries = 2)
    $errTxt = ''
    for ($i = 0; $i -le $Retries; $i++) {
        $errTxt = & esentutl.exe /y "$Source" /vss /d "$Dest" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Dest)) { return $true }
        if ($i -lt $Retries) { Start-Sleep -Seconds (3 * ($i + 1)) }
    }
    $tail = (@($errTxt -split "\r?\n") | Where-Object { "$_".Trim() } | Select-Object -Last 1)
    Write-CaseLog "    locked-file copy failed ($Source): $tail" 'DarkYellow'
    return $false
}

function Get-HayabusaExe {
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    return Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1
}

function Get-LogStart {
    if ($script:LogStartDT) { return $script:LogStartDT }
    if ($script:LogHours -gt 0) { return (Get-Date).AddHours(-1 * $script:LogHours) }
    return $null
}

function ConvertTo-LogStart {
    # Accepts a window expression: 90 (hours), 90h, 30d, 3m (months), 0 = all-time,
    # or an explicit start date (2026-09-01 / '2026-09-01 08:00'). Returns a [datetime]
    # start, the string 'ALL' for 0, or $null when not understood.
    param([string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $null }
    if ($v -match '^0\s*(h|d|m)?$') { return 'ALL' }
    if ($v -match '^(\d+)\s*(h|d|m)$') {
        $n = [int]$Matches[1]
        $now = Get-Date
        switch ($Matches[2].ToLower()) {
            'd' { return $now.AddDays(-$n) }
            'm' { return $now.AddMonths(-$n) }
            default { return $now.AddHours(-$n) }
        }
    }
    if ($v -match '^\d+$') { return (Get-Date).AddHours(-1 * [int]$v) }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($v, [ref]$dt)) { return $dt }
    return $null
}

function Resolve-LogWindow {
    # Validates -LogStart/-LogEnd/-LogWindow into $script:LogStartDT/$script:LogEndDT.
    # Precedence: explicit -LogStart > -LogWindow > -LogHours. Returns '' or an error message.
    $script:LogStartDT = $null
    $script:LogEndDT = $null
    foreach ($pair in @(@($LogStart, '-LogStart'), @($LogEnd, '-LogEnd'))) {
        $v = "$($pair[0])".Trim()
        if (-not $v) { continue }
        $dt = [datetime]::MinValue
        if (-not [datetime]::TryParse($v, [ref]$dt)) { return "$($pair[1]) '$v' is not a valid date (examples: 2026-09-01, '2026-09-01 08:00')" }
        if ($pair[1] -eq '-LogStart') { $script:LogStartDT = $dt } else { $script:LogEndDT = $dt }
    }
    $w = "$LogWindow".Trim()
    if ($w) {
        $r = ConvertTo-LogStart $w
        if ($null -eq $r) { return "-LogWindow '$w' not understood (use 90h / 30d / 3m / 0 = all, or a start date like 2026-09-01)" }
        if ("$r" -eq 'ALL') { $script:LogHours = 0 }
        elseif (-not $script:LogStartDT) { $script:LogStartDT = $r }
    }
    if ($script:LogStartDT -and $script:LogEndDT -and $script:LogEndDT -le $script:LogStartDT) { return '-LogEnd must be after -LogStart' }
    return ''
}

function Get-LogRangeText {
    if ($script:LogStartDT) { return "From $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm'))$(if ($script:LogEndDT) { " to $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm'))" })" }
    if ($script:LogHours -eq 0) { return 'All time' }
    if ($script:LogHours % 24 -eq 0) { return "Last $([int]($script:LogHours/24))d" }
    return "Last $($script:LogHours)h"
}

$rwErr = Resolve-LogWindow
if ($rwErr) { Write-Host "  Ophira: $rwErr" -ForegroundColor Red; exit 1 }

function Test-TrustedPublisher {
    param([string]$Signer)
    if (-not $Signer) { return $false }
    $trusted = @('Microsoft', 'Google', 'Mozilla', 'Adobe', 'Apple', 'Intel', 'NVIDIA', 'Dell', 'HP Inc', 'Lenovo', 'Citrix', 'VMware', 'Oracle', 'Python Software Foundation', 'GitHub', 'Slack', 'Discord', 'Zoom Video Communications', 'Dropbox', 'Notepad++')
    try {
        $tDir = Get-ToolsDir
        if ($tDir) {
            $tf = Join-Path $tDir 'trusted.txt'
            if (Test-Path -LiteralPath $tf) {
                $trusted += @(Get-Content -LiteralPath $tf | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
            }
        }
    } catch { }
    foreach ($t in $trusted) { if ($Signer -match [regex]::Escape($t)) { return $true } }
    return $false
}

function Get-IocList {
    # IOC feeds: classic tools\iocs.txt PLUS v2.26 feed folder tools\iocs\*.json
    # (STIX 2.x bundles and MISP exports - drop files in, no network, no API keys).
    # $iocs.Feed maps each indicator to its source feed for hit attribution.
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    $iocs = @{ Hashes = @{}; Sha1 = @{}; Ips = @{}; Domains = @{}; Names = @{}; Feed = @{} }
    $addIoc = {
        param([string]$kind, [string]$key, [string]$feed)
        if (-not $key) { return }
        if ($kind -eq 'sha1') { $iocs.Sha1[$key] = $true; $iocs.Hashes[$key] = $true }
        elseif ($kind -eq 'hash') { $iocs.Hashes[$key] = $true }
        elseif ($kind -eq 'ip') { $iocs.Ips[$key] = $true }
        elseif ($kind -eq 'name') { $iocs.Names[$key] = $true }
        else { $iocs.Domains[$key] = $true }
        if (-not $iocs.Feed.ContainsKey($key)) { $iocs.Feed[$key] = $feed }
    }
    $f = Join-Path $tDir 'iocs.txt'
    if (Test-Path -LiteralPath $f) {
        foreach ($line in (Get-Content -LiteralPath $f)) {
            $l = ($line -replace '#.*$', '').Trim()
            if (-not $l) { continue }
            if ($l -match '^[a-fA-F0-9]{40}$') { & $addIoc 'sha1' $l.ToUpper() 'iocs.txt' }
            elseif ($l -match '^[a-fA-F0-9]{32,64}$') { & $addIoc 'hash' $l.ToUpper() 'iocs.txt' }
            elseif ($l -match '^(\d{1,3}\.){3}\d{1,3}$') { & $addIoc 'ip' $l 'iocs.txt' }
            else { & $addIoc 'domain' $l.ToLower() 'iocs.txt' }
        }
    }
    $feedDir = Join-Path $tDir 'iocs'
    if (Test-Path -LiteralPath $feedDir) {
        foreach ($jf in @(Get-ChildItem -LiteralPath $feedDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $feedName = $jf.BaseName
            try {
                $j = Get-Content -LiteralPath $jf.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                # STIX 2.x bundle
                if ($j.type -eq 'bundle' -and $j.objects) {
                    foreach ($o in @($j.objects)) {
                        if ("$($o.type)" -ne 'indicator' -or -not "$($o.pattern)") { continue }
                        $p = "$($o.pattern)"
                        foreach ($m in ([regex]::Matches($p, "(?i)hashes\.'?(?:SHA|MD5)[^']*'?\s*=\s*'([a-f0-9]{32,64})'"))) {
                            & $addIoc $(if ($m.Groups[1].Value.Length -eq 40) { 'sha1' } else { 'hash' }) $m.Groups[1].Value.ToUpper() $feedName
                        }
                        foreach ($m in ([regex]::Matches($p, "(?i)domain-name:value\s*=\s*'([^']+)'"))) { & $addIoc 'domain' $m.Groups[1].Value.ToLower() $feedName }
                        foreach ($m in ([regex]::Matches($p, "(?i)(ipv4|ipv6)-addr:value\s*=\s*'([^']+)'"))) { & $addIoc 'ip' $m.Groups[2].Value $feedName }
                        foreach ($m in ([regex]::Matches($p, "(?i)file:name\s*=\s*'([^']+)'"))) { & $addIoc 'name' $m.Groups[1].Value.ToLower() $feedName }
                    }
                }
                # MISP export (direct or response-wrapped)
                $attrs = $null
                if ($j.Attribute) { $attrs = @($j.Attribute) }
                elseif ($j.response -and $j.response.Attribute) { $attrs = @($j.response.Attribute) }
                if ($attrs) {
                    foreach ($a in $attrs) {
                        $av = "$($a.value)"; $at = "$($a.type)"
                        if (-not $av -or -not $at) { continue }
                        switch -Regex ($at) {
                            '^(md5|sha256)$' { & $addIoc 'hash' $av.ToUpper() $feedName }
                            '^sha1$' { & $addIoc 'sha1' $av.ToUpper() $feedName }
                            '^(domain|hostname)' { & $addIoc 'domain' $av.ToLower() $feedName }
                            '^ip-(dst|src)' { & $addIoc 'ip' $av $feedName }
                            '^filename' { & $addIoc 'name' $av.ToLower() $feedName }
                        }
                    }
                }
            } catch { Write-CaseLog "    IOC feed '$feedName' failed to parse: $($_.Exception.Message)" 'DarkYellow' }
        }
    }
    if ($iocs.Hashes.Count -eq 0 -and $iocs.Ips.Count -eq 0 -and $iocs.Domains.Count -eq 0) { return $null }
    return $iocs
}

function Show-ToolLinks {
    Write-Host ""
    Write-Host "=== Ophira companion tools ===" -ForegroundColor Cyan
    $rows = @(
        [pscustomobject]@{ Tool = 'winpmem (RAM capture)'; Url = 'https://github.com/Velocidex/winpmem/releases'; Use = 'module 7.1 memory capture; drop exe in tools\' }
        [pscustomobject]@{ Tool = 'hayabusa (Sigma hunt)'; Url = 'https://github.com/Yamato-Security/hayabusa/releases'; Use = 'module 4.6 on-host Sigma timeline; get win-x64.zip' }
        [pscustomobject]@{ Tool = 'volatility3 (memory analysis)'; Url = 'https://github.com/volatilityfoundation/volatility3/releases'; Use = 'offline: pslist/netscan/malfind; get win-exes zip, keep vol.exe' }
        [pscustomobject]@{ Tool = 'chainsaw (artifact analysis)'; Url = 'https://github.com/WithSecureOpenSource/chainsaw/releases'; Use = 'offline: sigma hunt + shimcache/amcache timeline' }
        [pscustomobject]@{ Tool = 'AmcacheParser (EZ)'; Url = 'https://github.com/EricZimmerman/AmcacheParser/releases'; Use = 'module 8.4 execution inventory + SHA1 x IOC' }
        [pscustomobject]@{ Tool = 'RBCmd (EZ)'; Url = 'https://github.com/EricZimmerman/RBCmd/releases'; Use = 'module 8.4 recycle bin parse' }
        [pscustomobject]@{ Tool = 'yara-x (binary scanning)'; Url = 'https://github.com/VirusTotal/yara-x/releases'; Use = 'module 4.7 YARA scan of flagged binaries; bundled pack in tools\yara\rules' }
        [pscustomobject]@{ Tool = 'MFTECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 5.5 live $MFT + USN journal forensics' }
        [pscustomobject]@{ Tool = 'PECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 5.1 prefetch parse (run counts)' }
        [pscustomobject]@{ Tool = 'LECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.5 LNK parse (Recent docs)' }
        [pscustomobject]@{ Tool = 'JLECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.5 Jump List parse' }
        [pscustomobject]@{ Tool = 'SBECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.8 ShellBags (folder browsing history)' }
        [pscustomobject]@{ Tool = 'RECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'Parse mode: batch registry deep-dive over saved hives (bundled batch: tools\recmd\ophira-registry.reb)' }
        [pscustomobject]@{ Tool = 'EvtxECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'Parse mode: FULL evtx->CSV conversion into csv\evtx_ecmd (timeframe deep-dives beyond the EID-filtered parses)' }
        [pscustomobject]@{ Tool = 'SQLECmd (EZ, .NET 9)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.7 browser SQLite parse (History/Downloads)' }
        [pscustomobject]@{ Tool = 'SrumECmd (EZ, .NET 9)'; Url = 'https://ericzimmerman.github.io/'; Use = 'analyst-side SRUM parse in -Mode Parse (per-app network usage history)' }
        [pscustomobject]@{ Tool = 'LOLDrivers datasets'; Url = 'https://github.com/magicsword-io/LOLDrivers'; Use = 'module 8.10 malicious/vulnerable driver hash lists into tools\loldrivers' }
        [pscustomobject]@{ Tool = 'velociraptor (enterprise)'; Url = 'https://github.com/Velocidex/velociraptor/releases'; Use = 'if you move to always-on agent-based DFIR' }
    )
    $rows | Format-Table Tool, Url, Use -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host "Tip: -Mode Setup downloads winpmem/hayabusa/volatility3/chainsaw into tools\ automatically." -ForegroundColor Yellow
}

function Invoke-SetupMode {
    param([string[]]$Wanted)
    if ($Wanted) { $Wanted = @($Wanted | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $toolsDir = Join-Path (Get-KitRoot) 'tools'
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    $catalog = @(
        [pscustomobject]@{ Name = 'winpmem';     Repo = 'Velocidex/winpmem';                Pattern = '^go-winpmem_amd64.*signed\.exe$|^winpmem.*x64.*\.exe$'; Zip = $false; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'hayabusa';    Repo = 'Yamato-Security/hayabusa';         Pattern = '^hayabusa-[\d\.]+-win-x64\.zip$'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'volatility3'; Repo = 'volatilityfoundation/volatility3'; Pattern = '^volatility3-win-exes-.*\.zip$'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'chainsaw';    Repo = 'WithSecureOpenSource/chainsaw';     Pattern = '^chainsaw_all_platforms\+rules\.zip$'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'AmcacheParser'; Direct = 'https://download.ericzimmermanstools.com/AmcacheParser.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'RBCmd';       Direct = 'https://download.ericzimmermanstools.com/RBCmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'MFTECmd';     Direct = 'https://download.ericzimmermanstools.com/MFTECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'PECmd';       Direct = 'https://download.ericzimmermanstools.com/PECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'LECmd';       Direct = 'https://download.ericzimmermanstools.com/LECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'JLECmd';      Direct = 'https://download.ericzimmermanstools.com/JLECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'SBECmd';      Direct = 'https://download.ericzimmermanstools.com/SBECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'AppCompatParser'; Direct = 'https://download.ericzimmermanstools.com/AppCompatParser.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'SQLECmd';     Direct = 'https://download.ericzimmermanstools.com/net9/SQLECmd.zip'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'SrumECmd';    Direct = 'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'RECmd';       Direct = 'https://download.ericzimmermanstools.com/RECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'EvtxECmd';    Direct = 'https://download.ericzimmermanstools.com/EvtxECmd.zip'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'loldrivers';  Raw = @('https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_malicious.sha256', 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_vulnerable.sha256'); Zip = $false; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'yara';        Repo = 'VirusTotal/yara-x';                 Pattern = '^yara-x-v[\d\.]+-x86_64-pc-windows-msvc\.zip$'; Zip = $true; Target = 'endpoint' }
    )
    $installed = @()
    foreach ($t in $catalog) {
        if ($Wanted -and $Wanted.Count -gt 0 -and $Wanted -notcontains $t.Name) { continue }
        Write-Host ""
        Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
        try {
            $target = if ($t.PSObject.Properties['Target'] -and $t.Target) { $t.Target } else { 'endpoint' }
            if ($t.PSObject.Properties['Raw'] -and $t.Raw) {
                $confirm = Read-Host "  download to tools\$target\$($t.Name)\? [Y/n]"
                if ($confirm -match '^[Nn]') { continue }
                $dest = Join-Path (Join-Path $toolsDir $target) $t.Name
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                foreach ($u in @($t.Raw)) {
                    $fn = ($u -split '/')[-1]
                    Invoke-WebRequest -Uri $u -OutFile (Join-Path $dest $fn) -UseBasicParsing -ErrorAction Stop
                }
                Write-Host "  saved -> tools\$target\$($t.Name)\" -ForegroundColor Green
                $installed += $t.Name
                continue
            }
            $assetUrl = $null
            $assetName = $null
            if ($t.PSObject.Properties['Direct' ] -and $t.Direct) {
                $assetUrl = $t.Direct
                $assetName = ($t.Direct -split '/')[-1]
                Write-Host "  source: ericzimmermanstools.com ($assetName)"
            } else {
                $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers @{ 'User-Agent' = 'Ophira' } -TimeoutSec 30 -ErrorAction Stop
                $asset = @($rel.assets | Where-Object { $_.name -match $t.Pattern } | Select-Object -First 1)[0]
                if (-not $asset) { Write-Host "  no matching asset found in latest release ($($rel.tag_name)) - download manually: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow; continue }
                $mb = [math]::Round($asset.size / 1MB, 1)
                Write-Host "  latest: $($asset.name) ($mb MB)"
                $assetUrl = $asset.browser_download_url
                $assetName = $asset.name
            }
            $confirm = Read-Host "  download to tools\? [Y/n]"
            if ($confirm -match '^[Nn]') { continue }
            $tmp = Join-Path ([IO.Path]::GetTempPath()) $assetName
            Invoke-WebRequest -Uri $assetUrl -OutFile $tmp -UseBasicParsing -ErrorAction Stop
            if ($t.Zip) {
                $dest = Join-Path (Join-Path $toolsDir $target) $t.Name
                $keepRules = $null
                if ($t.Name -eq 'hayabusa') { $keepTuning = Join-Path $dest 'ophira-level-tuning.txt' } else { $keepTuning = $null }
                if ($t.Name -eq 'yara') {
                    $keepRules = Join-Path $dest 'rules'
                    if (Test-Path $keepRules) {
                        $bak = "$keepRules.bak"
                        if (Test-Path $bak) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
                        Move-Item -LiteralPath $keepRules -Destination $bak -Force -ErrorAction SilentlyContinue
                    } else { $keepRules = $null }
                } else { $keepRules = $null }
                if ($keepTuning -and (Test-Path $keepTuning)) {
                    $bak2 = "$keepTuning.bak"
                    Move-Item -LiteralPath $keepTuning -Destination $bak2 -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
                Expand-Archive -LiteralPath $tmp -DestinationPath $dest -Force -ErrorAction Stop
                Get-ChildItem -Path $dest -Recurse -File -ErrorAction SilentlyContinue | Unblock-File
                if ($keepRules -and (Test-Path "$keepRules.bak")) { Move-Item -LiteralPath "$keepRules.bak" -Destination $keepRules -Force -ErrorAction SilentlyContinue }
                if ($keepTuning -and (Test-Path "$keepTuning.bak")) {
                    Move-Item -LiteralPath "$keepTuning.bak" -Destination $keepTuning -Force -ErrorAction SilentlyContinue
                    $hExe = Get-ChildItem -Path $dest -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1
                    Apply-ShippedRuleTuning -HayabusaExe $hExe
                }
                Write-Host "  extracted -> tools\$($t.Name)\" -ForegroundColor Green
            } else {
                Copy-Item -LiteralPath $tmp -Destination (Join-Path $toolsDir $assetName) -Force -ErrorAction Stop
                Write-Host "  saved -> tools\$assetName" -ForegroundColor Green
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $installed += $t.Name
        } catch {
            Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
            if ($t.PSObject.Properties['Direct'] -and $t.Direct) { Write-Host "  manual download: $($t.Direct)" -ForegroundColor Yellow }
            else { Write-Host "  manual download: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow }
        }
    }
    Write-Host ""
    Write-Host "Setup done: $(if ($installed) { $installed -join ', ' } else { 'nothing installed' })" -ForegroundColor $(if ($installed) { 'Green' } else { 'Yellow' })
    Write-Host "tools\endpoint\ = shipped to remote hosts via Deploy (-PushTools). tools\analyst\ = never shipped (your PC only)." -ForegroundColor Gray
    Write-Host "Ophira finds tools recursively in both folders." -ForegroundColor Gray
}

function Compress-ToolZip {
    # AV-resilient packaging: Defender flags some bundled Sigma .yml files and blocks
    # Compress-Archive entirely. Zip per-entry and skip whatever AV objects to.
    param([string]$SourceDir, [string]$DestZip)
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (Test-Path $DestZip) { Remove-Item $DestZip -Force }
    $zipPath = $DestZip
    if ($zipPath.Length -gt 240) { $zipPath = "\\?\$zipPath" }
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    $added = 0
    $skipped = 0
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $SourceDir -Recurse -File)) {
            $rel = $f.FullName.Substring($SourceDir.Length + 1).Replace('\', '/')
            $srcPath = $f.FullName
            if ($srcPath.Length -gt 240) { $srcPath = "\\?\$srcPath" }
            try {
                $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $srcPath, $rel, [IO.Compression.CompressionLevel]::Fastest)
                $added++
            } catch { $skipped++ }
        }
    } finally { $zip.Dispose() }
    return [pscustomobject]@{ Added = $added; Skipped = $skipped }
}

function Invoke-DeployMode {
    param([string[]]$Targets, [string]$DeployPreset, $Cred, [string]$DeployCaseID, [string]$DeploySharePath, [int]$Threads = 8, [bool]$PushBin = $false, [int]$DeployLogHours = 0, [string]$DeployLogWindow = '')

    $kit = Get-KitRoot
    $scriptPath = Join-Path $kit 'Ophira.ps1'
    $tools = Join-Path $kit 'tools'
    $outFolder = Join-Path $kit 'collections'
    if (-not (Test-Path $scriptPath)) { Write-Host "Ophira.ps1 not found in $kit" -ForegroundColor Red; return }
    if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $toolsDir = if (Test-Path $tools) { $tools } else { $null }
    $binZip = $null
    if ($PushBin -and $toolsDir) {
        $epDir = Join-Path $toolsDir 'endpoint'
        $legacyHay = Join-Path $toolsDir 'hayabusa'
        $packDir = if (Test-Path $epDir) { $epDir } elseif (Test-Path $legacyHay) { $legacyHay } else { $null }
        if ($packDir) {
            try {
                $what = if ($packDir -eq $epDir) { 'endpoint toolset (hayabusa/chainsaw/yara/EZ/loldrivers/winpmem)' } else { 'hayabusa (legacy layout)' }
                Write-Host "Packaging $what for push (bin push)..." -ForegroundColor Cyan
                $binZip = Join-Path ([IO.Path]::GetTempPath()) 'ophira-bin-endpoint.zip'
                $zipRes = Compress-ToolZip -SourceDir $packDir -DestZip $binZip
                $skipNote = if ($zipRes.Skipped -gt 0) { ", $($zipRes.Skipped) files skipped (AV-blocked)" } else { '' }
                Write-Host ("  packaged ({0} MB, {1} files{2}) - will be REMOVED from targets after run" -f [math]::Round((Get-Item $binZip).Length / 1MB, 1), $zipRes.Added, $skipNote) -ForegroundColor Gray
            } catch { Write-Host "  bin packaging failed: $($_.Exception.Message) - continuing without on-host tools" -ForegroundColor Yellow; $binZip = $null }
        } else { Write-Host "  tools\endpoint not found - PushTools has nothing to push" -ForegroundColor Yellow }
    }

    $worker = {
        param($c, $scriptPath, $toolsDir, $preset, $caseID, $sharePath, $cred, $outFolder, $binZip, $logHours, $logWindow)
        $result = [pscustomobject]@{ Host = $c; Ok = $false; Detail = '' }
        $s = $null
        $remoteDir = 'C:\Windows\Temp\Ophira'
        try {
            $sp = @{ ComputerName = $c; SessionOption = (New-PSSessionOption -NoMachineProfile) }
            if ($cred) { $sp.Credential = $cred }
            $s = New-PSSession @sp -ErrorAction Stop
            Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $remoteDir -ErrorAction Stop | Out-Null
            Copy-Item -Path $scriptPath -Destination "$remoteDir\Ophira.ps1" -ToSession $s -Force
            if ($toolsDir) {
                $rd = "$remoteDir\tools"
                Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $rd | Out-Null
                Get-ChildItem $toolsDir -File -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$rd\$($_.Name)" -ToSession $s -Force
                }
            }
            if ($binZip -and (Test-Path -LiteralPath $binZip)) {
                Copy-Item -Path $binZip -Destination "$remoteDir\bin.zip" -ToSession $s -Force -ErrorAction Stop
                Invoke-Command -Session $s -ScriptBlock {
                    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
                    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                    $null = New-Item -ItemType Directory -Path "$using:remoteDir\tools" -Force
                    $zip = [IO.Compression.ZipFile]::OpenRead("$using:remoteDir\bin.zip")
                    $skipped = 0
                    try {
                        foreach ($entry in $zip.Entries) {
                            if ("$($entry.Name)" -eq '') { continue }
                            $dest = Join-Path "$using:remoteDir\tools" $entry.FullName
                            if ($dest.Length -gt 240) { $dest = "\\?\$dest" }
                            $destDir = Split-Path $dest -Parent
                            if (-not (Test-Path $destDir)) { $null = New-Item -ItemType Directory -Path $destDir -Force }
                            try { [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true) } catch { $skipped++ }
                        }
                    } finally { $zip.Dispose() }
                    Remove-Item "$using:remoteDir\bin.zip" -Force -ErrorAction SilentlyContinue
                } -ErrorAction Stop
            }
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDir\Ophira.ps1`" -Mode Collect -NoMenu -NoElevate -Preset $preset -OutputPath `"$remoteDir\out`""
            if ($caseID) { $cmd += " -CaseID `"$caseID`"" }
            if ($sharePath) { $cmd += " -SharePath `"$sharePath`"" }
            if ($logHours -ge 0) { $cmd += " -LogHours $logHours" }
            if ($logWindow) { $cmd += " -LogWindow '" + ($logWindow -replace "'", "''") + "'" }
            $res = Invoke-Command -Session $s -ScriptBlock {
                param($k, $t)
                $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $k -Wait -PassThru -WindowStyle Hidden
                $z = Get-ChildItem "$t\out" -Filter '*.zip' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($z) { $z.FullName } else { "NORESULT:exit=$($p.ExitCode)" }
            } -ArgumentList $cmd, $remoteDir
            if ($res -and $res -notmatch '^NORESULT') {
                if ($sharePath) {
                    $result.Detail = "uploaded to share ($res)"
                } else {
                    Copy-Item -Path $res -Destination $outFolder -FromSession $s -Force -ErrorAction Stop
                    $result.Detail = "pulled $(Split-Path $res -Leaf)"
                }
                $result.Ok = $true
            } else { $result.Detail = "no result zip ($res)" }
        } catch { $result.Detail = $_.Exception.Message }
        finally {
            if ($s) {
                Invoke-Command -Session $s -ScriptBlock { Remove-Item 'C:\Windows\Temp\Ophira' -Recurse -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
                Remove-PSSession $s -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        return $result
    }

    function Invoke-DeployBatch {
        param([string[]]$Batch)
        $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Threads))
        $pool.Open()
        $jobs = New-Object System.Collections.ArrayList
        foreach ($c in $Batch) {
            $ps = [powershell]::Create()
            $null = $ps.AddScript($worker.ToString()).AddArgument($c).AddArgument($scriptPath).AddArgument($toolsDir).AddArgument($DeployPreset).AddArgument($DeployCaseID).AddArgument($DeploySharePath).AddArgument($Cred).AddArgument($outFolder).AddArgument($binZip).AddArgument($DeployLogHours).AddArgument($DeployLogWindow)
            $ps.RunspacePool = $pool
            $null = $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Target = $c })
        }
        $results = @()
        while ($jobs.Count -gt 0) {
            $doneIdx = @()
            for ($i = 0; $i -lt $jobs.Count; $i++) {
                if ($jobs[$i].Handle.IsCompleted) { $doneIdx += $i }
            }
            foreach ($i in ($doneIdx | Sort-Object -Descending)) {
                $j = $jobs[$i]
                try {
                    $out = @($j.PS.EndInvoke($j.Handle))
                    foreach ($o in $out) {
                        $results += $o
                        $mark = if ($o.Ok) { 'OK  ' } else { 'FAIL' }
                        $col = if ($o.Ok) { 'Green' } else { 'Red' }
                        Write-Host ("  [{0}] {1,-25} {2}" -f $mark, $o.Host, $o.Detail) -ForegroundColor $col
                    }
                } catch {
                    $results += [pscustomobject]@{ Host = $j.Target; Ok = $false; Detail = "worker error: $($_.Exception.Message)" }
                    Write-Host ("  [FAIL] {0,-25} worker error" -f $j.Target) -ForegroundColor Red
                }
                $j.PS.Dispose()
                $jobs.RemoveAt($i)
            }
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
        $pool.Close()
        $pool.Dispose()
        return $results
    }

    $total = $Targets.Count
    Write-Host "Deploying to $total hosts ($Threads parallel, $DeployPreset preset)..." -ForegroundColor Cyan
    $results = @(Invoke-DeployBatch -Batch $Targets)
    $retry = @($results | Where-Object { -not $_.Ok } | Select-Object -ExpandProperty Host -Unique)
    if ($retry.Count -gt 0) {
        Write-Host "`nRetrying $($retry.Count) failed host(s) sequentially..." -ForegroundColor Yellow
        $results += @(Invoke-DeployBatch -Batch $retry)
        $results = @($results | Group-Object Host | ForEach-Object {
            $good = @($_.Group | Where-Object Ok)
            if ($good.Count -gt 0) { $good[0] } else { $_.Group | Select-Object -Last 1 }
        })
    }
    $ok = @($results | Where-Object Ok)
    $fail = @($results | Where-Object { -not $_.Ok })
    if ($binZip -and (Test-Path -LiteralPath $binZip)) { Remove-Item $binZip -Force -ErrorAction SilentlyContinue }
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  DEPLOYMENT SUMMARY: $($ok.Count)/$total succeeded" -ForegroundColor $(if ($fail.Count) { 'Yellow' } else { 'Green' })
    if ($fail.Count) { $fail | ForEach-Object { Write-Host "  FAILED: $($_.Host) - $($_.Detail)" -ForegroundColor Red } }
    Write-Host "  Collections in: $(if ($DeploySharePath) { $DeploySharePath } else { $outFolder })"
    Write-Host "  Next: .\Ophira.ps1 -Mode Analyze -AnalyzePath <that folder>" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Invoke-AnalyzeMode {
    param([string]$Path, [string]$HayabusaExe)
    if (-not (Test-Path $Path)) { Write-Host "Path not found: $Path" -ForegroundColor Red; return }
    $OutFolder = $Path
    if (-not $HayabusaExe) {
        $tDir = Get-ToolsDir
        if ($tDir) {
            $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1
            if ($h) { $HayabusaExe = $h.FullName }
        }
    } elseif (-not (Test-Path $HayabusaExe)) {
        Write-Host "hayabusa not found at $HayabusaExe" -ForegroundColor Red; $HayabusaExe = ''
    }
    $sources = @()
    $sources += Get-ChildItem $Path -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue
    $sources += Get-ChildItem $Path -Filter 'IRCASE_*.zip' -File -ErrorAction SilentlyContinue
    foreach ($d in (Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(OPHIRA|IRCASE)_' })) {
        if ((Test-Path (Join-Path $d.FullName 'case.json')) -and -not ($sources | Where-Object { $_.BaseName -eq $d.Name })) { $sources += $d }
    }
    if (-not $sources) { Write-Host "No OPHIRA_*/IRCASE_* packages found in $Path" -ForegroundColor Red; return }
    $findings = @()
    $hosts = @()
    $evtxDirs = @()
    $signerRows = @()
    $extractWorker = {
        param($zipPath, $tmp)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tmp)
        return $tmp
    }
    $extractJobs = New-Object System.Collections.ArrayList
    $pool = [runspacefactory]::CreateRunspacePool(1, 4)
    $pool.Open()
    foreach ($src in $sources) {
        if ($src -is [System.IO.FileInfo]) {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
            if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
            $ps = [powershell]::Create()
            $null = $ps.AddScript($extractWorker.ToString()).AddArgument($src.FullName).AddArgument($tmp)
            $ps.RunspacePool = $pool
            $null = $extractJobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Src = $src; Tmp = $tmp })
        }
    }
    $extractMap = @{}
    while ($extractJobs.Count -gt 0) {
        $doneIdx = @()
        for ($i = 0; $i -lt $extractJobs.Count; $i++) {
            if ($extractJobs[$i].Handle.IsCompleted) { $doneIdx += $i }
        }
        foreach ($i in ($doneIdx | Sort-Object -Descending)) {
            $j = $extractJobs[$i]
            try { $null = $j.PS.EndInvoke($j.Handle); $extractMap[$j.Src.Name] = $j.Tmp }
            catch { Write-Host "cannot extract $($j.Src.Name): $($_.Exception.Message)" -ForegroundColor Red }
            $j.PS.Dispose()
            $extractJobs.RemoveAt($i)
        }
        if ($extractJobs.Count -gt 0) { Start-Sleep -Milliseconds 200 }
    }
    $pool.Close()
    $pool.Dispose()
    $lateralRaw = New-Object System.Collections.Generic.List[object]
    $hostIps = @{}
    foreach ($src in $sources) {
        $tmp = $null
        $dir = $src.FullName
        if ($src -is [System.IO.FileInfo]) {
            if (-not $extractMap.ContainsKey($src.Name)) { continue }
            $tmp = $extractMap[$src.Name]
            $dir = $tmp
        }
        $host_ = $src.Name -replace '^(OPHIRA|IRCASE)_', '' -replace '_\d{8}_\d{6}.*$', ''
        $caseJson = Join-Path $dir 'case.json'
        $meta = $null
        if (Test-Path $caseJson) { try { $meta = Get-Content $caseJson -Raw | ConvertFrom-Json } catch { } }
        if ($meta -and $meta.Computer) { $host_ = $meta.Computer }
        $vd = $null
        $verdictJson = Join-Path $dir 'verdict.json'
        if (Test-Path $verdictJson) { try { $vd = Get-Content $verdictJson -Raw | ConvertFrom-Json } catch { } }
        $hosts += [pscustomobject]@{
            Host = $host_; Source = $src.Name; CaseID = $meta.CaseID
            Role = $(if ($meta -and $meta.Role) { "$($meta.Role)" } else { '' })
            Preset = $(if ($meta -and $meta.Preset) { "$($meta.Preset)" } else { '' })
            Collected = $meta.StartedUTC; Admin = $meta.AdminElevated; Sysmon = $meta.SysmonPresent
            Verdict = "$(if ($vd) { $vd.Level } else { '' })"
            VerdictRank = $(if ($vd) { [int]$vd.LevelRank } else { -1 })
            Confidence = $(if ($vd) { $vd.ConfidencePercent } else { $null })
            Signals = $(if ($vd) { @($vd.Signals).Count } else { 0 })
            Caveats = $(if ($vd) { @($vd.Caveats).Count } else { 0 })
        }
        $csvDir = Join-Path $dir 'csv'
        if (Test-Path $csvDir) {
            $map = @{
                'flash_process_scored.csv'           = 'ProcAnomaly'
                'flash_ioc_hits.csv'                 = 'IOC-HIT'
                'flash_public_connections.csv'       = 'PublicConn'
                'scheduled_tasks_flagged.csv'        = 'TaskFlagged'
                'services_flagged.csv'               = 'ServiceFlagged'
                'security_bruteforce_candidates.csv' = 'BruteForce'
                'defender_threats.csv'               = 'AVDetection'
                'system_new_services.csv'            = 'NewService'
                'process_hashes.csv'                 = 'FileHash'
                'loldrivers_hits.csv'                = 'LolDriver'
                'dns_beacon_candidates.csv'          = 'DnsBeacon'
                'hunt_findings.csv'                  = 'HuntHit'
            }
            foreach ($k in $map.Keys) {
                $f = Join-Path $csvDir $k
                if (-not (Test-Path $f)) { $f = Join-Path $csvDir (Get-CaseCsvPath $k) }
                if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) {
                    try {
                        $rows = Import-Csv $f
                        foreach ($r in @($rows)) {
                            $detail = ''
                            if ($k -eq 'process_hashes.csv') { $detail += "$($r.SHA256) $($r.Path) " }
                            if ($r.PSObject.Properties['Name']) { $detail += "$($r.Name) " }
                            if ($r.PSObject.Properties['Path']) { $detail += "$($r.Path) " }
                            if ($r.PSObject.Properties['Indicator']) { $detail += "[$($r.Indicator)] $($r.Where)" }
                            if ($r.PSObject.Properties['SourceIp']) { $detail += "$($r.SourceIp) ($($r.FailedLogons) failures)" }
                            if ($r.PSObject.Properties['ThreatName']) { $detail += "$($r.ThreatName) $($r.Resources)" }
                            if ($r.PSObject.Properties['RemoteAddress']) { $detail += "$($r.RemoteAddress):$($r.RemotePort) <- $($r.ProcessPath)" }
                            if ($r.PSObject.Properties['Service']) { $detail += "$($r.Service) $($r.Binary)" }
                            if ($r.PSObject.Properties['Verdict']) { $detail = "[$($r.Verdict) $($r.Score)] " + $detail + " {$($r.Evidence)}" }
                            if ($k -eq 'hunt_findings.csv') { $detail = "[$($r.Severity)] $($r.Rule): $($r.Entity) - $($r.Evidence)" }
                        if ($k -eq 'flash_process_scored.csv' -and $r.PSObject.Properties['Signer'] -and "$($r.Signer)") {
                            $signerRows += [pscustomobject]@{ Host = $host_; Signer = "$($r.Signer)"; Name = "$($r.Name)"; Verdict = "$($r.Verdict)" }
                        }
                            if (-not $detail) { $detail = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' }
                            $findings += [pscustomobject]@{ Host = $host_; Type = $map[$k]; Detail = $detail.Trim(); Source = $k }
                        }
                    } catch { }
                }
            }
            # lateral-chain input: share access rows + local IPs for cross-host stitching (v2.20)
            $sa = Join-Path $csvDir 'security_share_access.csv'
            if (Test-Path $sa) {
                try {
                    foreach ($r in (Import-Csv $sa)) {
                        $ip = "$($r.SourceIp)"
                        if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { continue }
                        $lateralRaw.Add([pscustomobject]@{ Host = $host_; Time = "$($r.Time)"; EventId = "$($r.EventId)"; Account = "$($r.Account)"; ShareName = "$($r.ShareName)"; TargetName = "$($r.RelativeTargetName)"; SourceIp = $ip })
                    }
                } catch { }
            }
            $ni = Join-Path $csvDir 'net_interfaces.csv'
            if (Test-Path $ni) {
                try {
                    foreach ($r in (Import-Csv $ni)) {
                        foreach ($ip in ("$($r.IPv4)" -split ',')) {
                            $ip = $ip.Trim()
                            if ($ip) { $hostIps[$ip] = $host_ }
                        }
                    }
                } catch { }
            }
        }
        $e = Join-Path $dir 'raw\evtx'
        if (Test-Path $e) { $evtxDirs += $e }
    }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  FLEET ANALYSIS - $($hosts.Count) hosts, $($findings.Count) findings" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    $byType = $findings | Group-Object Type | Sort-Object Count -Descending
    Write-Host "`n  Findings by type:" -ForegroundColor White
    foreach ($g in $byType) { Write-Host ("    {0,-14} {1}" -f $g.Name, $g.Count) }
    $withVerdict = @($hosts | Where-Object { $_.VerdictRank -ge 0 })
    if ($withVerdict.Count -gt 0) {
        Write-Host "`n  Verdicts:" -ForegroundColor White
        foreach ($g in @($withVerdict | Group-Object Verdict)) { Write-Host ("    {0,-30} {1} host(s)" -f $g.Name, $g.Count) }
        $attention = @($withVerdict | Where-Object { $_.VerdictRank -ge 3 } | Sort-Object VerdictRank -Descending)
        if ($attention.Count -gt 0) {
            Write-Host "    ATTENTION FIRST:" -ForegroundColor Red
            foreach ($a in $attention) { Write-Host ("      {0,-22} {1} (conf {2}%)" -f $a.Host, $a.Verdict, $a.Confidence) -ForegroundColor Red }
        }
        if ($hosts.Count -gt $withVerdict.Count) { Write-Host "    ($($hosts.Count - $withVerdict.Count) legacy case(s) without verdict - rerun those hosts with Ophira v2.6+)" -ForegroundColor DarkGray }
    }
    $highRisk = @($findings | Where-Object { @('IOC-HIT', 'AVDetection', 'HuntHit') -contains $_.Type })
    if ($highRisk.Count) {
        Write-Host "`n  *** HIGH-PRIORITY (IOC hits / AV detections / hunt hits) ***" -ForegroundColor Red
        $highRisk | Group-Object Host | ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor Red }
    }
    $crossHost = @()
    foreach ($g in ($findings | Where-Object { @('ProcAnomaly', 'IOC-HIT', 'TaskFlagged', 'ServiceFlagged', 'FileHash') -contains $_.Type } | Group-Object { ($_.Detail -split ' ')[0] })) {
        $hs = @($g.Group | Select-Object -ExpandProperty Host -Unique)
        if ($hs.Count -gt 1) { $crossHost += [pscustomobject]@{ Indicator = $g.Name; Hosts = ($hs -join ', '); HostCount = $hs.Count } }
    }
    # v2.51: fleet hash pivot - one row per binary hash with the hosts it executed on
    $fleetHash = @{}
    foreach ($f in ($findings | Where-Object Type -eq 'FileHash')) {
        $dt = "$($f.Detail)"
        $hx = ($dt -split ' ')[0]
        if ($hx -notmatch '^[A-Fa-f0-9]{32,64}$') { continue }
        if (-not $fleetHash.ContainsKey($hx)) { $fleetHash[$hx] = @{ Hosts = New-Object 'System.Collections.Generic.HashSet[string]'; Name = '' } }
        $null = $fleetHash[$hx].Hosts.Add($f.Host)
        if (-not $fleetHash[$hx].Name) { $rest = @($dt -split ' ' | Select-Object -Skip 1) -join ' '; $fleetHash[$hx].Name = ($rest -replace '\s+', ' ').Trim() }
    }
    $fleetHashRows = @($fleetHash.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{ SHA256 = $_.Key; Name = $_.Value.Name; HostCount = $_.Value.Hosts.Count; Hosts = (($_.Value.Hosts.ToArray() | Sort-Object) -join ', '); MultiHost = $(if ($_.Value.Hosts.Count -gt 1) { 'YES - lateral candidate' } else { '' }) }
    } | Sort-Object HostCount -Descending)
    $null = $fleetHashRows | Export-Csv -LiteralPath (Join-Path $OutFolder 'fleet_hashes.csv') -NoTypeInformation -Encoding UTF8
    $mhHash = @($fleetHashRows | Where-Object HostCount -gt 1).Count
    if ($mhHash -gt 0) { Write-Host "`n  HASH PIVOT: $mhHash binary hash(es) executed on MULTIPLE hosts - lateral-movement candidates -> fleet_hashes.csv" -ForegroundColor Red }
    $proposedTrusted = @()
    if ($signerRows.Count -gt 0 -and $hosts.Count -ge 2) {
        $threshold = [Math]::Max(2, [Math]::Ceiling($hosts.Count * 0.6))
        foreach ($g in ($signerRows | Group-Object Signer)) {
            $sh = @($g.Group | Select-Object -ExpandProperty Host -Unique)
            $anyHigh = @($g.Group | Where-Object { $_.Verdict -eq 'HIGH' })
            if ($sh.Count -ge $threshold -and $anyHigh.Count -eq 0) {
                $proposedTrusted += [pscustomobject]@{ Signer = $g.Name; Hosts = $sh.Count; Samples = (($g.Group | Select-Object -ExpandProperty Name -Unique | Select-Object -First 3) -join '; ') }
            }
        }
        if ($proposedTrusted.Count -gt 0) {
            $pt = Join-Path $OutFolder 'proposed_trusted.txt'
            $pl = @("# Proposed trusted publishers - generated by Ophira fleet baselining $(Get-Date -Format u)")
            $pl += "# These publishers appear on >= 60% of $($hosts.Count) hosts with no HIGH verdicts."
            $pl += "# Review, then copy the lines you trust into tools\trusted.txt to cut future false positives."
            $pl += ""
            $pl += @($proposedTrusted | Select-Object -ExpandProperty Signer)
            $pl | Set-Content -LiteralPath $pt -Encoding UTF8
            Write-Host "`n  Baselining: $($proposedTrusted.Count) publishers proposed as trusted -> proposed_trusted.txt" -ForegroundColor Cyan
        }
    }
    if ($crossHost.Count) {
        Write-Host "`n  SAME INDICATOR ON MULTIPLE HOSTS (outbreak signal):" -ForegroundColor Magenta
        $crossHost | Sort-Object HostCount -Descending | Select-Object -First 20 | ForEach-Object {
            Write-Host ("    {0,-45} {1} hosts: {2}" -f $_.Indicator, $_.HostCount, $_.Hosts) -ForegroundColor Magenta
        }
    }
    $hayOut = $null
    $lateral = New-Object System.Collections.Generic.List[object]
    foreach ($r in $lateralRaw) {
        if (-not $hostIps.ContainsKey($r.SourceIp)) { continue }
        $from = $hostIps[$r.SourceIp]
        if ($from -eq $r.Host) { continue }
        $null = $lateral.Add([pscustomobject]@{ FromHost = $from; ToHost = $r.Host; Account = $r.Account; Share = $r.ShareName; Target = $r.TargetName; Time = $r.Time; SourceIp = $r.SourceIp; EventId = $r.EventId })
    }
    if ($lateral.Count -gt 0) {
        $latCsv = Join-Path $OutFolder 'fleet_lateral_chain.csv'
        $lateral.ToArray() | Sort-Object FromHost, ToHost | Export-Csv -LiteralPath $latCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`n  LATERAL MOVEMENT CHAINS (share access from another collected host): $($lateral.Count) -> fleet_lateral_chain.csv" -ForegroundColor Magenta
        foreach ($l in ($lateral.ToArray() | Sort-Object FromHost, ToHost | Select-Object -First 20)) {
            Write-Host ("    {0} -> {1} [{2}] share={3} target={4} ({5})" -f $l.FromHost, $l.ToHost, $l.Account, $l.Share, $l.Target, $l.SourceIp) -ForegroundColor Magenta
        }
    }
    if ($HayabusaExe -and $evtxDirs.Count -gt 0) {
        Write-Host "`n  Running hayabusa fleet timeline over $($evtxDirs.Count) hosts' evtx..." -ForegroundColor Cyan
        $merged = Join-Path ([IO.Path]::GetTempPath()) 'fleet_merged_evtx'
        if (Test-Path $merged) { Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $merged -Force | Out-Null
        $i = 0
        foreach ($e in $evtxDirs) {
            $i++
            Get-ChildItem $e -Filter '*.evtx' -File -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $merged ("{0}_{1}" -f $i, $_.Name)) -Force
            }
        }
        $hayOut = Join-Path $OutFolder 'fleet_hayabusa_timeline.csv'
        $hayHtml = Join-Path $OutFolder 'fleet_hayabusa_report.html'
        Write-Host "    hayabusa fleet timeline running..." -ForegroundColor Cyan
        $null = Invoke-NativeTool -ExePath $HayabusaExe -ToolArgs @('dfir-timeline', '-p', 'verbose', '-d', $merged, '-o', $hayOut, '-H', $hayHtml, '-q', '-w', '-U', '-C', '-K', '-m', 'low', '-E') -WorkingDirectory (Split-Path $HayabusaExe -Parent) -QuietLog
        if (Test-Path $hayOut) {
            $null = Invoke-NativeTool -ExePath $HayabusaExe -ToolArgs @('sort-csv', '-f', $hayOut, '-o', $hayOut, '-C', '-q', '-K') -WorkingDirectory (Split-Path $HayabusaExe -Parent) -QuietLog
            $n = @(Get-Content $hayOut | Select-Object -Skip 1).Count
            Write-Host "    hayabusa: $n detections (deduped) -> $hayOut" -ForegroundColor Yellow
        }
        Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue
    }
    $reportCsv = Join-Path $OutFolder 'fleet_report.csv'
    $findings | Sort-Object Host, Type | Export-Csv -LiteralPath $reportCsv -NoTypeInformation -Encoding UTF8
    $hostsCsv = Join-Path $OutFolder 'fleet_hosts.csv'
    $hosts | Sort-Object Host | Select-Object Host, Verdict, VerdictRank, Confidence, Role, Preset, Signals, Caveats, Collected, Admin, Sysmon, Source, CaseID | Export-Csv -LiteralPath $hostsCsv -NoTypeInformation -Encoding UTF8

    $fleetHtml = Join-Path $OutFolder 'fleet_report.html'
    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #2a2f3a;padding:6px 10px;text-align:left}
th{background:#1d222c;color:#8ab4f8}tr:nth-child(even){background:#151920}
.HIGH{color:#ff8789;font-weight:700}.IOC{color:#ff8789}.path{font-family:Consolas,monospace;font-size:12px;color:#8ab4f8;word-break:break-all}
.V4{color:#ff8789;font-weight:800}.V3{color:#ff8789;font-weight:700}.V2{color:#ffce6b}.V1{color:#7ee2a8}.V0{color:#9ec1f0}.VN{color:#7d8590}
.chips{margin:14px 0}.chip{display:inline-block;padding:5px 13px;border-radius:14px;margin-right:6px;font-size:13px;font-weight:600;background:#243447;color:#9ec1f0}
a{color:#8ab4f8}.foot{margin-top:40px;color:#565e6b;font-size:11px}
</style>
'@
    $fsb = New-Object System.Text.StringBuilder
    $null = $fsb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira Fleet</title>$css</head><body>")
    $null = $fsb.AppendLine("<h1>OPHIRA FLEET REPORT</h1><div class='meta'>$(Get-Date -Format u) - $($hosts.Count) hosts - $($findings.Count) findings - Ophira v$ScriptVersion</div>")
    if (@($hosts | Where-Object { $_.VerdictRank -ge 0 }).Count -gt 0) {
        $chipParts = @()
        foreach ($lvl in @(4, 3, 2, 1, 0)) {
            $n = @($hosts | Where-Object VerdictRank -eq $lvl).Count
            if ($n -gt 0) { $chipParts += "<span class='chip V$lvl'>$((@{4='COMPROMISED';3='LIKELY COMPROMISED';2='SUSPICIOUS';1='NO EVIDENCE';0='INCONCLUSIVE'})[$lvl]): $n</span>" }
        }
        $leg = @($hosts | Where-Object VerdictRank -lt 0).Count
        if ($leg -gt 0) { $chipParts += "<span class='chip VN'>no verdict: $leg</span>" }
        $null = $fsb.AppendLine("<div class='chips'>$($chipParts -join '')</div>")
    }
    $null = $fsb.AppendLine("<h2>Host summary (worst verdict first)</h2><table><tr><th>Host</th><th>Verdict</th><th>Conf</th><th>Role</th><th>High-priority</th><th>Proc anomalies</th><th>Brute force</th><th>Collected</th></tr>")
    foreach ($h in ($hosts | Sort-Object -Property @{Expression='VerdictRank';Descending=$true}, 'Host')) {
        $hf = @($findings | Where-Object Host -eq $h.Host)
        $hp = @($hf | Where-Object { @('IOC-HIT', 'AVDetection') -contains $_.Type }).Count
        $pa = @($hf | Where-Object { $_.Type -eq 'ProcAnomaly' -and $_.Detail -match '^\[HIGH' }).Count
        $bf = @($hf | Where-Object Type -eq 'BruteForce').Count
        $rowClass = if ($hp -gt 0 -or $pa -gt 0) { 'HIGH' } else { '' }
        $vCell = if ($h.VerdictRank -ge 0) { "<span class='V$($h.VerdictRank)'>$(ConvertTo-HtmlEsc $h.Verdict)</span>" } else { "<span class='VN'>n/a</span>" }
        $cCell = if ($h.VerdictRank -ge 0) { "$($h.Confidence)%" } else { '' }
        $null = $fsb.AppendLine("<tr><td class='$rowClass'>$(ConvertTo-HtmlEsc $h.Host)</td><td>$vCell</td><td>$cCell</td><td>$(ConvertTo-HtmlEsc $h.Role)</td><td>$hp</td><td>$pa</td><td>$bf</td><td>$(ConvertTo-HtmlEsc $h.Collected)</td></tr>")
    }
    $null = $fsb.AppendLine("</table><div class='meta'>Per-host verdict details: each case zip's verdict.json + report.html. Host list CSV: fleet_hosts.csv</div>")
    if ($highRisk.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>High-priority findings (IOC / AV / hunt)</h2><table><tr><th>Host</th><th>Type</th><th>Detail</th></tr>")
        foreach ($f in ($highRisk | Sort-Object Host | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $f.Host)</td><td>$(ConvertTo-HtmlEsc $f.Type)</td><td class='path'>$(ConvertTo-HtmlEsc $f.Detail)</td></tr>")
        }
        $null = $fsb.AppendLine("</table><div class='meta'>HuntHit rows are high/medium technique detections from each host's csv\hunt_findings.csv</div>")
    }
    if ($lateral.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Lateral movement chains (share access between collected hosts)</h2><table><tr><th>From</th><th>To</th><th>Account</th><th>Share</th><th>Target</th><th>Time</th><th>Source IP</th></tr>")
        foreach ($l in ($lateral.ToArray() | Sort-Object FromHost, ToHost | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $l.FromHost)</td><td>$(ConvertTo-HtmlEsc $l.ToHost)</td><td>$(ConvertTo-HtmlEsc $l.Account)</td><td>$(ConvertTo-HtmlEsc $l.Share)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Target)</td><td>$(ConvertTo-HtmlEsc $l.Time)</td><td>$(ConvertTo-HtmlEsc $l.SourceIp)</td></tr>")
        }
        $null = $fsb.AppendLine("</table><div class='meta'>Joined each host's csv\security_share_access.csv SourceIp against every other host's csv\net_interfaces.csv. CSV: fleet_lateral_chain.csv</div>")
    }
    if ($hayOut -and (Test-Path $hayOut)) {
        $ftech = @{}
        try {
            foreach ($r in (Import-Csv -LiteralPath $hayOut)) {
                $comp = "$($r.Computer)"
                foreach ($m in [regex]::Matches("$($r.MitreTags)", 'T\d{4}(?:\.\d{3})?')) {
                    $k = $m.Value
                    if (-not $ftech.ContainsKey($k)) { $ftech[$k] = @{ N = 0; Hosts = @{} } }
                    $ftech[$k].N++
                    if ($comp) { $ftech[$k].Hosts[$comp] = $true }
                }
            }
        } catch { }
        if ($ftech.Count -gt 0) {
            $null = $fsb.AppendLine("<h2>Fleet ATT&CK roll-up (Sigma-tagged detections across hosts)</h2><table><tr><th>Technique</th><th>Detections</th><th>Hosts</th></tr>")
            foreach ($k in @($ftech.Keys | Sort-Object { $ftech[$_].N } -Descending | Select-Object -First 40)) {
                $href = 'https://attack.mitre.org/techniques/' + ($k -replace '\.', '/')
                $null = $fsb.AppendLine("<tr><td><a target='_blank' href='$href'>$k</a></td><td>$($ftech[$k].N)</td><td>$($ftech[$k].Hosts.Count)</td></tr>")
            }
            $null = $fsb.AppendLine("</table><div class='meta'>Load attack_layer_fleet.json at navigator.mitre.org for the full heat map.</div>")
            try {
                $layerTech = @($ftech.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ techniqueID = $_; score = $ftech[$_].N } })
                $flayer = [pscustomobject]@{
                    name = "Ophira Fleet - $(Split-Path $Path -Leaf)"
                    domain = 'enterprise-attack'
                    description = "Ophira v$ScriptVersion fleet Sigma detections"
                    versions = @{ navigator = '4.9'; layer = '4.5' }
                    techniques = $layerTech
                }
                $flayer | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutFolder 'attack_layer_fleet.json') -Encoding UTF8
            } catch { }
        }
    }
    if ($crossHost.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Cross-host indicators (outbreak signal)</h2><table><tr><th>Indicator</th><th>Hosts</th><th>Count</th></tr>")
        foreach ($c in ($crossHost | Sort-Object HostCount -Descending | Select-Object -First 30)) {
            $null = $fsb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $c.Indicator)</td><td>$(ConvertTo-HtmlEsc $c.Hosts)</td><td><b>$($c.HostCount)</b></td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
        if ($mhHash -gt 0) {
            $null = $fsb.AppendLine("<h2>Fleet hash pivot (same binary on multiple hosts - lateral shortlist)</h2><table><tr><th>SHA256</th><th>Name / path</th><th>Hosts</th><th>Host list</th></tr>")
            foreach ($c in ($fleetHashRows | Where-Object HostCount -gt 1 | Select-Object -First 30)) {
                $null = $fsb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $c.SHA256)</td><td class='path'>$(ConvertTo-HtmlEsc $c.Name)</td><td><b>$($c.HostCount)</b></td><td class='path'>$(ConvertTo-HtmlEsc $c.Hosts)</td></tr>")
            }
            $null = $fsb.AppendLine("</table><div class='meta'>Every collected binary hash with its host list: fleet_hashes.csv. Multi-host hashes are the lateral-movement shortlist.</div>")
        }
    }
    if ($proposedTrusted.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Fleet baselining - proposed trusted publishers</h2><div class='meta'>Present on >= 60% of hosts, never HIGH. Review proposed_trusted.txt and merge into tools\trusted.txt to reduce false positives.</div><table><tr><th>Publisher</th><th>Hosts</th><th>Sample binaries</th></tr>")
        foreach ($p in ($proposedTrusted | Sort-Object Hosts -Descending)) {
            $null = $fsb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $p.Signer)</td><td>$($p.Hosts)</td><td>$(ConvertTo-HtmlEsc $p.Samples)</td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
    }
    if ($hayOut -and (Test-Path $hayOut)) {
        try {
            $hayRows = @(Import-Csv -LiteralPath $hayOut)
            $ruleCol = $null
            foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
                if ($hayRows.Count -gt 0 -and $hayRows[0].PSObject.Properties[$cand]) { $ruleCol = $cand; break }
            }
            if ($hayRows.Count -gt 0 -and $ruleCol) {
                $null = $fsb.AppendLine("<h2>Top Sigma detections across fleet</h2><table><tr><th>Alert</th><th>Hits</th><th>Max level</th><th>Hosts</th></tr>")
                foreach ($g in ($hayRows | Group-Object $ruleCol | Sort-Object Count -Descending | Select-Object -First 20)) {
                    $lvl = (@($g.Group | ForEach-Object { $_.Level }) | Sort-Object -Descending | Select-Object -First 1) -join ''
                    $lvlClass = switch -Regex ("$lvl") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                    $hostsN = @($g.Group | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
                    $null = $fsb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td>$($g.Count)</td><td class='$lvlClass'>$(ConvertTo-HtmlEsc $lvl)</td><td>$hostsN</td></tr>")
                }
                $null = $fsb.AppendLine("</table><div class='meta'>Full timeline: fleet_hayabusa_timeline.csv / fleet_hayabusa_report.html</div>")
            }
        } catch { }
    }
    $null = $fsb.AppendLine("<div class='foot'>Generated by Ophira -Mode Analyze. Per-host details: fleet_report.csv; Sigma timeline: fleet_hayabusa_timeline.csv / fleet_hayabusa_report.html</div></body></html>")
    $fsb.ToString() | Set-Content -LiteralPath $fleetHtml -Encoding UTF8

    $summaryTxt = Join-Path $OutFolder 'fleet_summary.txt'
    $lines = @()
    $lines += "Ophira fleet analysis - $(Get-Date -Format u)"
    $lines += "Hosts: $($hosts.Count)  Findings: $($findings.Count)"
    $lines += ""
    $lines += "HOSTS:"
    foreach ($h in $hosts) { $lines += "  $($h.Host)  collected=$($h.Collected) admin=$($h.Admin) sysmon=$($h.Sysmon) src=$($h.Source)" }
    $lines += ""
    $lines += "HIGH PRIORITY:"
    if ($highRisk.Count) { foreach ($f in $highRisk) { $lines += "  $($f.Host) $($f.Type) $($f.Detail)" } } else { $lines += "  none" }
    $lines += ""
    $lines += "CROSS-HOST INDICATORS:"
    if ($crossHost.Count) { foreach ($c in $crossHost) { $lines += "  $($c.Indicator) -> $($c.Hosts)" } } else { $lines += "  none" }
    $lines += ""
    $lines += "PROPOSED TRUSTED PUBLISHERS (fleet baselining):"
    if ($proposedTrusted.Count) { foreach ($p in $proposedTrusted) { $lines += "  $($p.Signer) ($($p.Hosts) hosts)" } } else { $lines += "  none" }
    $lines | Set-Content -LiteralPath $summaryTxt -Encoding UTF8
    $vdTot = @($hosts | Where-Object { "$($_.Verdict)" } | Group-Object Verdict | Sort-Object { $_.Group[0].VerdictRank } -Descending)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ("  VERDICTS: " + (($vdTot | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '  |  ')) -ForegroundColor $(if (@($hosts | Where-Object { $_.VerdictRank -ge 3 }).Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  fleet_hosts.csv   : $hostsCsv" -ForegroundColor Green
    Write-Host "  fleet_report.csv  : $reportCsv" -ForegroundColor Green
    Write-Host "  fleet_report.html : $fleetHtml" -ForegroundColor Green
    Write-Host "  fleet_summary.txt : $summaryTxt" -ForegroundColor Green
    if ($hayOut) { Write-Host "  hayabusa timeline : $hayOut" -ForegroundColor Green }
    Write-Host "================================================================" -ForegroundColor Green
    foreach ($src in $sources) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-FlashTriage {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host "" }
    Out-Flash "==============================================================" 'Cyan'
    Out-Flash "  FLASH TRIAGE  -  $Computer  -  $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" 'Cyan'
    Out-Flash "==============================================================" 'Cyan'

    $iocs = Get-IocList
    $iocHits = @()

    $procs = Get-ProcessInventory
    $bad = @($procs | Where-Object { $_.Flags })
    $sigChecked = @()
    if ($bad.Count -gt 0) {
        foreach ($b in $bad) {
            $s = Get-SignatureInfo -Path $b.Path
            $sigChecked += [pscustomobject]@{
                PID = $b.PID; Name = $b.Name; Path = $b.Path; Company = $b.Company
                Flags = $b.Flags; SigStatus = if ($s) { $s.Status } else { 'N/A' }
                Signer = if ($s) { $s.Signer } else { '' }
            }
        }
    }
    if ($iocs -and $iocs.Hashes.Count -gt 0) {
        $paths = @($procs | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) } | Select-Object -ExpandProperty Path -Unique)
        foreach ($p in $paths) {
            try {
                $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
                if ($iocs.Hashes.ContainsKey($h)) {
                    $pn = ($procs | Where-Object { $_.Path -eq $p } | Select-Object -First 1)
                    $iocHits += [pscustomobject]@{ Type = 'SHA256'; Indicator = $h.Substring(0, 16) + '...'; Where = $p; Context = "process PID $($pn.PID)" }
                }
            } catch { }
        }
    }

    $conns = Get-ConnectionTable
    $est = @($conns | Where-Object { $_.Proto -eq 'TCP' -and $_.State -eq 'Established' })
    $ext = @($est | Where-Object { $_.Public })
    if ($iocs -and $iocs.Ips.Count -gt 0) {
        foreach ($c in @($conns | Where-Object { $_.RemoteAddress -and $iocs.Ips.ContainsKey("$($_.RemoteAddress)") })) {
            $iocHits += [pscustomobject]@{ Type = 'IP'; Indicator = "$($c.RemoteAddress)"; Where = "conn PID $($c.PID) $($c.ProcessPath)"; Context = "$($c.RemoteAddress):$($c.RemotePort) $($c.State)" }
        }
    }

    $dns = Get-DnsCacheRows
    if ($iocs -and $iocs.Domains.Count -gt 0) {
        foreach ($d in $dns) {
            if ($d.PSObject.Properties['Entry']) {
                $e = "$($d.Entry)".ToLower()
                foreach ($dom in $iocs.Domains.Keys) {
                    if ($e -eq $dom -or $e.EndsWith("." + $dom)) {
                        $iocHits += [pscustomobject]@{ Type = 'Domain'; Indicator = $dom; Where = "dns cache: $e"; Context = "$($d.Data)" }
                        break
                    }
                }
            }
        }
    }

    $svcPaths = @()
    try { $svcPaths = @(Get-WmiOrCim -Class Win32_Service | ForEach-Object { "$($_.PathName)" }) } catch { }
    $taskActions = @()
    try {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $taskActions = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ' })
        }
    } catch { }

    $scored = foreach ($b in $sigChecked) {
        $score = 0; $evidence = New-Object System.Collections.Generic.List[string]
        if ($b.Flags -match 'USER-WRITABLE-PATH') { $score += 1; $evidence.Add('runs-from-user-path') }
        if ($b.Flags -match 'NO-COMPANY' -or $b.SigStatus -eq 'NotSigned') { $score += 2; $evidence.Add('unsigned/no-company') }
        if ($b.Flags -match 'BINARY-MISSING') { $score += 3; $evidence.Add('binary-deleted-from-disk') }
        $myExt = @($ext | Where-Object { $_.PID -eq $b.PID })
        if ($myExt.Count -gt 0) {
            $score += 2; $evidence.Add("public-conn:$($myExt[0].RemoteAddress):$($myExt[0].RemotePort)")
            # v2.55: non-cloud public connection is a stronger signal than a CDN/azure egress
            $nonCloud = @($myExt | Where-Object { -not (Get-IpCloudClass "$($_.RemoteAddress)") } | Select-Object -First 1)
            if ($nonCloud.Count -gt 0) { $score += 2; $evidence.Add("non-cloud-conn:$($nonCloud[0].RemoteAddress)") }
        }
        if ($iocHits | Where-Object { $_.Where -eq $b.Path }) { $score += 4; $evidence.Add('IOC-HASH-MATCH') }
        $name = Split-Path $b.Path -Leaf -ErrorAction SilentlyContinue
        if ($name) {
            $svcRef = @($svcPaths | Where-Object { $_ -and $_ -match [regex]::Escape($name) })
            if ($svcRef.Count -gt 0) { $score += 2; $evidence.Add("persistence:service($($svcRef.Count))") }
            $taskRef = @($taskActions | Where-Object { $_ -and $_ -match [regex]::Escape($name) })
            if ($taskRef.Count -gt 0) { $score += 2; $evidence.Add("persistence:task($($taskRef.Count))") }
        }
        $iocHit = [bool]($iocHits | Where-Object { $_.Where -eq $b.Path })
        $trustedSigned = ($b.SigStatus -eq 'Valid' -and (Test-TrustedPublisher $b.Signer))
        if ($trustedSigned -and -not $iocHit) {
            $score = [Math]::Min($score, 2)
            $evidence.Add("signed-trusted-publisher:$($b.Signer)")
        } elseif ($trustedSigned -and $iocHit) {
            $evidence.Add("TRUSTED-PUBLISHER-BUT-IOC-HIT")
        }
        $verdict = if ($score -ge 6) { 'HIGH' } elseif ($score -ge 4) { 'MEDIUM' } else { 'LOW' }
        [pscustomobject]@{ PID = $b.PID; Name = $b.Name; Path = $b.Path; Score = $score; Verdict = $verdict; Evidence = ($evidence -join '; '); Flags = $b.Flags; Signer = $b.Signer }
    }

    Out-Flash ("PROCESS ANOMALIES : {0} flagged of {1} processes" -f $sigChecked.Count, $procs.Count) $(if ($sigChecked.Count) { 'Yellow' } else { 'Green' })
    foreach ($s in ($scored | Sort-Object Score -Descending | Select-Object -First 10)) {
        $c = if ($s.Verdict -eq 'HIGH') { 'Red' } elseif ($s.Verdict -eq 'MEDIUM') { 'Yellow' } else { 'DarkYellow' }
        Out-Flash ("    [{0,-6} {1}] {2} (PID {3})  {4}" -f $s.Verdict, $s.Score, $s.Name, $s.PID, $s.Evidence) $c
    }
    if ($sigChecked.Count -gt 10) { Out-Flash "    ... and $($sigChecked.Count - 10) more (see flash_process_scored.csv)" 'DarkGray' }

    Out-Flash ("ESTABLISHED CONNS : {0} total, {1} to PUBLIC IPs" -f $est.Count, $ext.Count) $(if ($ext.Count) { 'Yellow' } else { 'Gray' })
    $shown = @{}
    foreach ($c in ($ext | Sort-Object ProcessPath | Select-Object -First 12)) {
        $key = "$($c.RemoteAddress):$($c.RemotePort)"
        if (-not $shown[$key]) {
            $shown[$key] = $true
            $pname = if ($c.ProcessPath) { Split-Path $c.ProcessPath -Leaf } else { "PID $($c.PID)" }
            Out-Flash "    $key  <- $pname" 'Yellow'
        }
    }

    $suspDns = @($dns | Where-Object { $_.PSObject.Properties['Entry'] -and ($_.Entry.Length -gt 30 -or "$($_.Entry)" -match '^\w{20,}\.') })
    Out-Flash ("DNS CACHE         : {0} entries ({1} long-name suspects)" -f $dns.Count, $suspDns.Count) $(if ($suspDns.Count) { 'Yellow' } else { 'Gray' })

    $arp = Get-ArpRows
    Out-Flash ("ARP NEIGHBORS     : {0} hosts seen at network layer" -f $arp.Count) 'Gray'

    $smbMaps = @(); $smbHosted = @(); $cmdKeys = @()
    try { if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) { $smbMaps = @(Get-SmbMapping) } } catch { }
    try { if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { $smbHosted = @(Get-SmbShare) } } catch { }
    $cmdOut = & cmdkey.exe /list 2>$null
    $cmdKeys = @($cmdOut | Select-String -Pattern 'Target:' | ForEach-Object { ($_ -replace '.*Target:\s*', '').Trim() })
    Out-Flash ("SMB               : hosts {0} shares, mounts {1} remote, saved creds: {2}" -f $smbHosted.Count, $smbMaps.Count, $cmdKeys.Count) 'Gray'
    foreach ($k in ($cmdKeys | Select-Object -First 5)) { Out-Flash "    cred: $k" 'DarkYellow' }

    $users = & quser.exe 2>$null
    $uCount = [Math]::Max(0, (@($users | Where-Object { $_ -match '\S' }).Count - 1))
    Out-Flash ("LOGGED-ON USERS   : {0}" -f $uCount) 'Gray'

    $lastDet = ''
    try {
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            $d = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
            if ($d) { $lastDet = $d.InitialDetectionTime }
        }
    } catch { }
    if ($lastDet) {
        Out-Flash ("DEFENDER          : LAST DETECTION $lastDet  <<< INVESTIGATE" ) 'Red'
    } else {
        Out-Flash "DEFENDER          : no detections on record (or service absent)" 'Gray'
    }

    if ($iocs) {
        if ($iocHits.Count -gt 0) {
            Out-Flash ("IOC HITS          : {0} MATCHES !!!" -f $iocHits.Count) 'Red'
            foreach ($h in ($iocHits | Select-Object -First 10)) {
                Out-Flash ("    [{0}] {1}  @  {2}" -f $h.Type, $h.Indicator, $h.Where) 'Red'
            }
        } else {
            Out-Flash ("IOC CHECK         : 0 hits against {0} hashes / {1} IPs / {2} domains" -f $iocs.Hashes.Count, $iocs.Ips.Count, $iocs.Domains.Count) 'Green'
        }
    } else {
        Out-Flash "IOC CHECK         : no iocs.txt in tools\ (add one for instant matching)" 'DarkGray'
    }

    $sw.Stop()
    Out-Flash "==============================================================" 'Cyan'
    Out-Flash ("  Flash complete in {0:N1}s - full data in csv\ + raw\" -f $sw.Elapsed.TotalSeconds) 'Cyan'
    Out-Flash "==============================================================" 'Cyan'

    $flashTxt = Join-Path $CaseDir 'flash_summary.txt'
    $script:FlashLines | Set-Content -LiteralPath $flashTxt -Encoding UTF8
    Save-Rows -Name 'flash_process_scored' -Rows $scored
    Save-Rows -Name 'flash_ioc_hits' -Rows $iocHits
    Save-Rows -Name 'flash_public_connections' -Rows $ext
}

function Get-UserProfileList {
    $rows = @()
    try {
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($k in (Get-ChildItem $pl -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if ($p.ProfileImagePath -and $k.PSChildName -match '^S-1-5-21-') {
                $rows += [pscustomobject]@{ Sid = $k.PSChildName; Path = "$($p.ProfileImagePath)"; User = (Split-Path "$($p.ProfileImagePath)" -Leaf) }
            }
        }
    } catch { }
    return $rows
}

function ConvertTo-Rot13 {
    # v2.54: true ROT13 - the old version only rotated lowercase, so the uppercase letters of
    # encoded UserAssist names stayed garbled in every userassist.csv ever written
    param([string]$s)
    ($s.ToCharArray() | ForEach-Object {
        $c = [int]$_
        if ($c -ge 65 -and $c -le 90) { [char](65 + (($c - 65 + 13) % 26)) }
        elseif ($c -ge 97 -and $c -le 122) { [char](97 + (($c - 97 + 13) % 26)) }
        else { $_ }
    }) -join ''
}

function Get-LevenshteinDistance {
    # v2.81: classic edit distance (two-row DP, no transposition op) - caller lowercases
    param([string]$A, [string]$B)
    if ($a.Length -eq 0) { return $b.Length }
    if ($b.Length -eq 0) { return $a.Length }
    $prev = New-Object 'int[]' ($b.Length + 1)
    $cur  = New-Object 'int[]' ($b.Length + 1)
    for ($j = 0; $j -le $b.Length; $j++) { $prev[$j] = $j }
    for ($i = 1; $i -le $a.Length; $i++) {
        $cur[0] = $i
        for ($j = 1; $j -le $b.Length; $j++) {
            $cost = if ($a[$i-1] -ceq $b[$j-1]) { 0 } else { 1 }
            $m = $prev[$j] + 1                                        # deletion
            if ($cur[$j-1] + 1 -lt $m) { $m = $cur[$j-1] + 1 }        # insertion
            if ($prev[$j-1] + $cost -lt $m) { $m = $prev[$j-1] + $cost } # substitution
            $cur[$j] = $m
        }
        $tmp = $prev; $prev = $cur; $cur = $tmp
    }
    return $prev[$b.Length]
}

function Get-UserAssistRows {
    # v2.54: enumerate the UserAssist GUID subkeys dynamically - the old hardcoded Win7-era
    # GUID list was brace-less and never matched the real {guid} keys, so this was always empty
    $rows = @()
    try {
        $uaKind = @{
            '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}' = 'executable'
            '{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}' = 'executable'
            '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}' = 'shortcut'
            '{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}' = 'shortcut'
            '{F2A1CB5A-E3AB-4A3B-9DDC-DF1D2F65C0E1}' = 'muicache'
            '{B267E3AD-A825-4F92-B35C-9FBF72F7E4D6}' = 'muicache'
        }
        $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
        foreach ($sid in $sids) {
            $user = $sid.PSChildName
            $uaRoot = "Registry::HKEY_USERS\$user\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            if (-not (Test-Path $uaRoot)) { continue }
            foreach ($g in @(Get-ChildItem $uaRoot -ErrorAction SilentlyContinue)) {
                $k = "$($g.PSPath)\Count"
                if (-not (Test-Path $k)) { continue }
                $kind = $uaKind[$g.PSChildName]; if (-not $kind) { $kind = 'other' }
                $prop = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if (-not $prop) { continue }
                foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    $name = ConvertTo-Rot13 "$($p.Name)"
                    $count = ''; $last = ''
                    try {
                        $v = $p.Value
                        if ($v -is [byte[]] -and $v.Length -ge 68) {
                            $count = [BitConverter]::ToInt32($v, 4)
                            $ft = [BitConverter]::ToInt64($v, 60)
                            if ($ft -gt 0) { $last = [DateTime]::FromFileTime($ft) }
                        }
                    } catch { }
                    $rows += [pscustomobject]@{ User = $user; Guid = $g.PSChildName; Kind = $kind; Entry = $name; RunCount = $count; LastRun = $last }
                }
            }
        }
    } catch { }
    return $rows
}

function Get-RegKeyLastWrite {
    # v2.83 (R47): PS 5.1's registry provider does not expose LastWriteTime (that arrived in
    # PS7) - P/Invoke RegQueryInfoKey instead. Returns $null on any failure so callers
    # degrade to an empty timestamp instead of crashing the module.
    param([string]$KeyPath)
    try {
        if (-not $script:OphiraRegLwt) {
            try {
                $script:OphiraRegLwt = Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Win32.SafeHandles;
    public static class OphiraRegLwt {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegQueryInfoKey(SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcbClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    }
'@ -PassThru -ErrorAction Stop
            } catch { $script:OphiraRegLwt = 'failed' }
        }
        if ($script:OphiraRegLwt -is [type]) {
            $k = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
            $ft = [long]0
            $rc = [OphiraRegLwt]::RegQueryInfoKey($k.Handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ft)
            if ($rc -eq 0 -and $ft -gt 0) { return [DateTime]::FromFileTime($ft) }
        }
    } catch { }
    return $null
}

function Get-RadarRows {
    # v2.83 (R47): RADAR heap-leak DiagnosedApplications - Windows memory diagnostics recorded
    # these apps crossing the heap threshold, so the KEY LastWriteTime is proof the binary
    # executed on or before it. Server-friendly execution evidence where Prefetch is disabled.
    $rows = @()
    try {
        $radarRoot = 'HKLM:\SOFTWARE\Microsoft\RADAR\Heap Leak Detection\DiagnosedApplications'
        if (Test-Path $radarRoot) {
            foreach ($k in @(Get-ChildItem $radarRoot -ErrorAction SilentlyContinue)) {
                $lwt = $null
                try { $lwt = Get-RegKeyLastWrite $k.PSPath } catch { }
                $rows += [pscustomobject]@{ Application = $k.PSChildName; KeyLastWrite = "$lwt" }
            }
        }
    } catch { }
    return $rows
}

function Get-AppSwitchedRows {
    # v2.83 (R48): Explorer FeatureUsage\AppSwitched - taskbar focus-switch COUNTERS per app.
    # Count-only (no timestamps, no MRU order): context for what the interactive user actually
    # switched to - an interactive attacker session shows here too.
    $rows = @()
    try {
        foreach ($sid in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' })) {
            $fu = "$($sid.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
            if (-not (Test-Path $fu)) { continue }
            $prop = Get-ItemProperty -Path $fu -ErrorAction SilentlyContinue
            if (-not $prop) { continue }
            foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $rows += [pscustomobject]@{ User = $sid.PSChildName; App = $p.Name; SwitchCount = $p.Value }
            }
        }
    } catch { }
    return $rows
}

function Get-EsentNtdsRows {
    # v2.83 (R46): ESENT 325/326 rows mentioning ntds.dit - the AD database was opened by
    # something. Legit: VSS/wbengine backup engines. Theft prep (ntdsutil IFM, custom tooling)
    # logs the same event class - hence the BackupPattern flag; the verdict only weights the
    # non-backup shape.
    param($Start)
    $rows = @()
    try {
        $ev = @(Get-FilteredEvents -LogName 'Application' -Ids @(325, 326) -Start $Start -MaxMsg 300)
        foreach ($e in $ev) {
            if ("$($e.Message)" -notmatch '(?i)ntds') { continue }
            $backup = [bool]("$($e.Message)" -match '(?i)wbengine|volume shadow|vss|backup')
            $rows += [pscustomobject]@{ Time = $e.TimeCreated; EventId = $e.Id; BackupPattern = $backup; Message = "$($e.Message)" }
        }
    } catch { }
    return $rows
}

function Get-TaskDeletionRows {
    # v2.83 (R45): TaskScheduler 4699 - a task was DELETED. Deleting the registry keys + XML
    # does not unload an already-loaded task until reboot, so deletions pair with TaskCache
    # anomalies (scheduled_taskcache.csv) for the disappearing-task anti-forensics trick.
    param($Start)
    $rows = @()
    try {
        $ev = @(Get-FilteredEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Ids @(4699) -Start $Start -MaxMsg 200)
        foreach ($e in $ev) {
            $task = ''; $user = ''
            if ("$($e.Message)" -match 'deleted task\s+"?([^"\r\n]+?)"?\s+for user\s+"?([^"\r\n]+?)"?\.?\s*$') { $task = $Matches[1]; $user = $Matches[2] }
            elseif ("$($e.Message)" -match '"([^"]+)"') { $task = $Matches[1] }
            $rows += [pscustomobject]@{ Time = $e.TimeCreated; TaskName = $task; User = $user; Message = "$($e.Message)" }
        }
    } catch { }
    return $rows
}

function Invoke-NativeTool {
    param([string]$ExePath, [string[]]$ToolArgs, [string]$WorkingDir = '', [switch]$QuietLog, [switch]$CaptureOut)
    $out = ''; $err = ''
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExePath
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.Arguments = (@($ToolArgs) | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' '
        if ($WorkingDir) { $psi.WorkingDirectory = $WorkingDir }
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        $null = $p.Start()
        $tOut = $p.StandardOutput.ReadToEndAsync()
        $tErr = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $out = "$($tOut.Result)"
        $err = "$($tErr.Result)"
        if (-not $QuietLog) {
            foreach ($block in @($out, $err)) {
                if ($block) {
                    ($block -split "`r?`n") | Select-Object -Last 40 | Where-Object { $_ } | ForEach-Object {
                        Write-CaseLog "      $(($_ -replace ([char]27 + '\[[0-9;]*m'), ''))" 'DarkGray' -NoConsole:($script:Verbosity -lt 2)
                    }
                }
            }
        }
        if ($CaptureOut) { return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out; StdErr = $err } }
        return $p.ExitCode
    } catch {
        Write-CaseLog "      native tool launch failed: $($_.Exception.Message)" 'DarkYellow'
        return -1
    }
}

function Get-DotNetRelease {
    # Endpoint .NET inventory - EZ parsers need .NET 4.x; SQLECmd needs the .NET 9 desktop runtime.
    $parts = @()
    try {
        $r = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release
        $v = '4.6+'
        foreach ($k in @(533320, 528040, 461808, 461308, 460798, 394802)) {
            if ($r -ge $k) { $v = @{ 533320 = '4.8.1'; 528040 = '4.8'; 461808 = '4.7.2'; 461308 = '4.7.1'; 460798 = '4.7'; 394802 = '4.6.2' }[$k]; break }
        }
        $parts += ".NET Framework $v (release $r)"
    } catch { $parts += '.NET Framework: not detected' }
    $nine = $false
    try {
        $dn = Get-Command dotnet.exe -ErrorAction SilentlyContinue
        if ($dn) { $nine = @((& dotnet.exe --list-runtimes 2>$null) | Where-Object { "$_" -match 'WindowsDesktop\.App 9\.' }).Count -gt 0 }
    } catch { }
    $parts += if ($nine) { '.NET 9 desktop runtime: present' } else { '.NET 9 desktop runtime: absent' }
    return ($parts -join '; ')
}

function Invoke-BrowserIocXref {
    # Cross-checks parsed browser history against the IOC domain list (module 8.7 and -Mode Parse).
    $iocs = Get-IocList
    if (-not $iocs -or $iocs.Domains.Count -eq 0) { return }
    $hist = Import-CaseCsv 'browser_history'
    $hits = @()
    foreach ($r in $hist) {
        $u = "$($r.URL)"
        if (-not $u) { continue }
        $hm = [regex]::Match($u, '^(?i)https?://([^/:]+)')
        if (-not $hm.Success) { continue }
        $host2 = $hm.Groups[1].Value.ToLower()
        foreach ($k in $iocs.Domains.Keys) {
            if ($host2 -eq $k -or $host2.EndsWith(".$k")) {
                $hits += [pscustomobject]@{ Indicator = $k; Host = $host2; URL = $u; Title = "$($r.URLTitle)"; Match = 'browser-history' }
                break
            }
        }
    }
    Save-Rows -Name 'ioc_hits_browser' -Rows $hits
    if (@($hits).Count -gt 0) { Write-CaseLog "    BROWSER IOC HITS: $(@($hits).Count) domain(s) from your IOC list in browser history -> csv\ioc_hits_browser.csv" 'Red' }
}

function Get-ParseNeeds {
    # For every expected artifact that is missing, say WHY and how to finish it
    # (endpoint-only source vs analyst-side re-parse via -Mode Parse).
    $dn = Get-DotNetRelease
    $nineOk = "$dn" -match '9 desktop runtime: present'
    $caps = @(
        @{ Artifact = 'amcache.csv';            Parser = 'AmcacheParser'; Net = 'net4'; Input = 'registry\Amcache.hve'; Live = $false }
        @{ Artifact = 'recyclebin.csv';         Parser = 'RBCmd';         Net = 'net4'; Input = 'recyclebin';           Live = $false }
        @{ Artifact = 'prefetch_parsed.csv';    Parser = 'PECmd';         Net = 'net4'; Input = 'prefetch';             Live = $false }
        @{ Artifact = 'lnk_parsed.csv';         Parser = 'LECmd';         Net = 'net4'; Input = 'recent';               Live = $false }
        @{ Artifact = 'jumplist_parsed*.csv';   Parser = 'JLECmd';        Net = 'net4'; Input = 'jumplists';            Live = $false }
        @{ Artifact = 'browser_history.csv';    Parser = 'SQLECmd';       Net = 'net9'; Input = 'browser';              Live = $false }
        @{ Artifact = 'srum_usage.csv';         Parser = 'SrumECmd';      Net = 'net9'; Input = 'sru\SRUDB.dat';        Live = $false }
        @{ Artifact = 'execution_timeline.csv'; Parser = 'chainsaw';      Net = 'none'; Input = 'registry\SYSTEM.hiv';  Live = $false }
        @{ Artifact = 'hayabusa_timeline.csv';  Parser = 'hayabusa';      Net = 'none'; Input = 'evtx';                 Live = $false }
        @{ Artifact = 'shellbags.csv';          Parser = 'SBECmd';        Net = 'net4'; Input = 'live C:\Users';        Live = $true }
        @{ Artifact = 'mft_recent.csv';         Parser = 'MFTECmd';       Net = 'net4'; Input = 'live volume (admin)';  Live = $true }
        @{ Artifact = 'recentfilecache.csv';    Parser = 'AppCompatParser'; Net = 'net4'; Input = 'extras\appcompat';   Live = $false; AbsentNote = ' (RecentFileCache.bcf is often absent on current Win11 builds)' }
        @{ Artifact = 'shimcache.csv';          Parser = 'AppCompatParser'; Net = 'net4'; Input = 'registry\SYSTEM.hiv'; Live = $false; CoveredBy = 'execution_timeline.csv' }
    )
    $rows = @()
    # v2.60: the case's own preset tells "module skipped" (Quick) apart from "the endpoint
    # genuinely lacks the file" (Standard/Full ran the collecting module and found nothing)
    $casePreset = ''
    try { $casePreset = "$((Get-Content -LiteralPath (Join-Path (Split-Path -Parent $RawDir) 'case.json') -Raw -ErrorAction Stop | ConvertFrom-Json).Preset)" } catch { }
    foreach ($c in $caps) {
        if (Test-CaseCsv $c.Artifact) { continue }
        # v2.60: an artifact whose data another CSV already carries is finished - don't demand a standalone parse
        if ($c.ContainsKey('CoveredBy') -and (Test-CaseCsv $c.CoveredBy)) { continue }
        if ($c.Live) { $how = 'endpoint-only source - rerun collection elevated on the host' }
        elseif (-not (Test-Path (Join-Path $RawDir $c.Input))) {
            if ($casePreset -eq 'Quick') { $how = 'module skipped on the endpoint (Quick preset) - rerun collection with a deeper preset' }
            else { $how = "raw evidence not collected - the source was not present on this endpoint$("$($c.AbsentNote)")" }
        }
        elseif (@(Get-ChildItem -LiteralPath (Join-Path $RawDir $c.Input) -Recurse -File -ErrorAction SilentlyContinue).Count -eq 0) {
            # v2.60: collected but empty (recycle bin was empty at collection) - Parse can never finish this
            $how = 'input was collected but empty on the endpoint (e.g. the recycle bin was empty at collection) - nothing to parse'
        }
        elseif ($c.Net -eq 'net9' -and -not $nineOk) { $how = 'endpoint lacks .NET 9 - run on analyst PC: Ophira.ps1 -Mode Parse -Path <case>' }
        else {
            $how = 'tool was missing on endpoint - run on analyst PC: Ophira.ps1 -Mode Parse -Path <case>'
            # v2.58: if the parser is missing from the kit too, -Mode Parse cannot finish this -
            # say so instead of sending the analyst into a Parse loop that changes nothing
            $toolExe = $null
            try {
                $td = Get-ToolsDir
                if ($td) { $toolExe = @(Get-ChildItem -LiteralPath $td -Recurse -Filter "$($c.Parser).exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1) }
            } catch { }
            if (-not $toolExe) { $how = "parser tool missing from the kit - run Ophira.ps1 -Mode Setup first (downloads $($c.Parser)), then re-run -Mode Parse -Path <case>" }
        }
        $rows += [pscustomobject]@{ Artifact = $c.Artifact; Parser = $c.Parser; DotNet = $c.Net; RawInput = $c.Input; HowToFinish = $how }
    }
    # v2.57: the plaso deep-timeline TODO lives right next to the generated results so the
    # analyst does not forget the optional log2timeline pass (until plaso.csv exists)
    $plasoCaseRoot = Split-Path -Parent $RawDir
    $plasoIn = Join-Path $plasoCaseRoot 'plaso.csv'
    if ((Test-Path -LiteralPath $RawDir) -and -not (Test-Path -LiteralPath $plasoIn) -and (@(Get-ChildItem -LiteralPath $RawDir -ErrorAction SilentlyContinue).Count -gt 0)) {
        $rows += [pscustomobject]@{ Artifact = 'supertimeline.csv (deeper: plaso)'; Parser = 'log2timeline.py + psort'; DotNet = 'python (analyst PC)'; RawInput = 'raw\ (entire folder)'; HowToFinish = "analyst PC: log2timeline.py <case>\raw  ->  psort.py <storage> --output-format l2tcsv -w plaso.csv  ->  drop plaso.csv in the case root  ->  re-run Ophira.ps1 -Mode Parse -Path <case> to merge it into the master timeline" }
    }
    Save-Rows -Name 'parse_needed' -Rows $rows
    if ($rows.Count -gt 0) { Write-CaseLog "    $($rows.Count) artifact(s) unfinished on endpoint - see csv\parse_needed.csv (-Mode Parse completes most of them analyst-side)" 'Yellow' }
}

function Find-AdsOnPe {
    # v2.62: alternate data streams on executable files - a non-Zone.Identifier ADS on a PE is a
    # classic stager/stash spot (payload rides next to the binary). Only EXISTING on-disk files
    # can be stream-scanned (mft_recent is a birth inventory, not a live listing).
    param([string[]]$Paths, [int]$MaxChecks = 120)
    $out = New-Object System.Collections.Generic.List[object]
    $checked = 0
    foreach ($p in $Paths) {
        if ($checked -ge $MaxChecks) { break }
        if ("$p" -notmatch '\.(exe|dll|sys)$') { continue }
        if (-not (Test-Path -LiteralPath "$p" -PathType Leaf)) { continue }
        $checked++
        try {
            foreach ($st in (Get-Item -LiteralPath "$p" -Stream * -ErrorAction Stop)) {
                $sn = "$($st.Stream)"
                if ($sn -eq ':$DATA' -or $sn -match '(?i)Zone\.Identifier') { continue }
                if ([long]$st.Length -le 0) { continue }
                $null = $out.Add([pscustomobject]@{ Path = "$p"; Stream = $sn; Length = "$($st.Length)" })
            }
        } catch { }
    }
    return $out.ToArray()
}

function Test-WebshellContent {
    # v2.62: webshell content heuristics (NOT signatures - every hit is "verify against baseline",
    # rendered report-only medium). Returns the matched heuristics, @() when clean.
    param([string]$Content)
    $hits = @()
    if ("$Content" -match '(?i)eval\s*\(\s*Request') { $hits += 'eval(Request)' }
    if ("$Content" -match '(?i)ExecuteGlobal|Execute\s*\(\s*Request') { $hits += 'execute(Request)' }
    if ("$Content" -match '(?i)(cmd|shell)\s*\.\s*exe?\s*/c|cmd\s*/c') { $hits += 'shell exec' }
    if ("$Content" -match '[A-Za-z0-9+/]{300,}={0,2}') { $hits += 'long base64 blob' }
    if ("$Content" -match '(?i)Process\.Start|WScript\.Shell') { $hits += 'process start' }
    return $hits
}

$script:SharedFunctions = @(
    'Get-KitRoot', 'Get-ToolsDir', 'Copy-LockedFile', 'Get-LogStart', 'Get-IocList', 'Test-TrustedPublisher',
    'Get-CaseCsvPath', 'Test-CaseCsv', 'Get-CaseCsvFullPath',
    'Save-Rows', 'Out-RawText', 'Invoke-ExeCapture', 'Invoke-NativeTool', 'Get-WmiOrCim', 'Convert-WmiDate', 'Get-InvariantDate',
    'Test-IsPublicIp', 'Test-IsUserWritablePath', 'Get-SignatureInfo', 'Get-SysmonState',
    'Get-UserProfileList', 'Get-UserAssistRows', 'ConvertTo-Rot13', 'Get-FilteredEvents', 'Export-Evtx',
    'Import-CaseCsv', 'Invoke-BrowserIocXref', 'Get-EventDataRows', 'Get-IisW3cRows', 'Get-StartupInfoRows', 'Get-WerReportRows', 'Test-SigmaSelfNoise', 'Remove-SigmaDuplicateEvents', 'Get-IpCloudClass', 'Get-LocalAdminMembers',
    'Find-AdsOnPe', 'Test-WebshellContent', 'Test-IsAdmin', 'Out-Flash', 'Get-DotNetRelease', 'Get-LevenshteinDistance',
    'Get-RegKeyLastWrite', 'Get-RadarRows', 'Get-AppSwitchedRows', 'Get-EsentNtdsRows', 'Get-TaskDeletionRows'
)

$script:ModuleWorkerText = @'
param($PreambleText, $ModuleDef)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$err = ''
# v2.65 (C5): a poisoned preamble must fail this ONE module, not kill the worker - the
# dispatcher paths only see the returned Error field, and both log it identically.
try { Invoke-Expression $PreambleText } catch { $err = 'preamble failed: ' + $_.Exception.Message }
if (-not $err) {
    try {
        $sb = [scriptblock]::Create($ModuleDef.RunText)
        & $sb
    } catch { $err = $_.Exception.Message }
}
$sw.Stop()
# v2.69 (F1): the record carries what the module saved (path + rows) so the pooled dispatcher
# can render the RUN detail line with real numbers; guarded for poisoned preambles.
$saved = @()
if ($null -ne $script:SavedArtifacts) { $saved = $script:SavedArtifacts.ToArray() }
return [pscustomobject]@{ Id = $ModuleDef.Id; Name = $ModuleDef.Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Error = $err; Saved = $saved }
'@

function New-WorkerPreamble {
    param([string]$WorkerLog)
    $sb = New-Object System.Text.StringBuilder
    foreach ($fn in $script:SharedFunctions) {
        $def = Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue
        if ($def) {
            [void]$sb.AppendLine("function $fn {")
            [void]$sb.AppendLine($def.Definition)
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
    }
    $seed = @{
        CaseDir  = $CaseDir;  CsvDir = $CsvDir;  RawDir = $RawDir;  MemDir = $MemDir
        Computer = $Computer; Preset = $Preset; KitRoot = (Get-KitRoot)
    }
    foreach ($k in $seed.Keys) {
        $lit = "'" + ("$($seed[$k])" -replace "'", "''") + "'"
        [void]$sb.AppendLine("`$$k = $lit")
    }
    # v2.58: the sortment map is DATA, not a function - worker runspaces never received it,
    # so Save-Rows -> Get-CaseCsvPath indexed a null array and EVERY pooled module died with
    # "Cannot index into a null array" (advanced-mode collections broken since v2.42; the
    # SimpleUI front-screen path ran modules inline in-process and masked it completely)
    $mapLit = (@($script:CsvCatMap.Keys | Sort-Object | ForEach-Object { "    '{0}' = '{1}'" -f $_, "$($script:CsvCatMap[$_])" }) -join "`r`n")
    [void]$sb.AppendLine("`$script:CsvCatMap = @{`r`n$mapLit`r`n}")
    [void]$sb.AppendLine("`$script:LogHours = $($LogHours)")
    [void]$sb.AppendLine("`$script:LogStartDT = $(if ($script:LogStartDT) { "[datetime]'" + $script:LogStartDT.ToString('o') + "'" } else { '$null' })")
    [void]$sb.AppendLine("`$script:LogEndDT = $(if ($script:LogEndDT) { "[datetime]'" + $script:LogEndDT.ToString('o') + "'" } else { '$null' })")
    [void]$sb.AppendLine("`$script:SimpleUI = `$$([bool]$script:SimpleUI)")
    # v2.65: seed the branch-state pooled workers actually read (v2.58-class gap): Verbosity
    # gates the Invoke-NativeTool tail (-NoConsole), Sysmon/IsAdmin/EndpointAdmin/HostRole gate
    # module paths, FlashLines backs Out-Flash. The Write-CaseLog override below stays file-only
    # regardless of Verbosity - workers still never write the console.
    [void]$sb.AppendLine("`$script:Verbosity = $([int]$script:Verbosity)")
    [void]$sb.AppendLine("`$Sysmon = `$$([bool]$Sysmon)")
    [void]$sb.AppendLine("`$IsAdmin = `$$([bool]$IsAdmin)")
    [void]$sb.AppendLine("`$script:EndpointAdmin = $(if ($null -ne $script:EndpointAdmin) { "`$$([bool]$script:EndpointAdmin)" } else { '$null' })")
    $roleLit = "'" + ("$script:HostRole" -replace "'", "''") + "'"
    [void]$sb.AppendLine("`$script:HostRole = $roleLit")
    [void]$sb.AppendLine('$script:FlashLines = New-Object System.Collections.Generic.List[string]')
    # v2.69 (F1): fresh artifact-save list per worker - Save-Rows records into it, the result
    # record hands it back to the pooled dispatcher for the RUN detail line
    [void]$sb.AppendLine('$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]')
    $wl = $WorkerLog -replace "'", "''"
    $override = "function Write-CaseLog { param([string]`$Message,[string]`$Color = 'Gray',[switch]`$NoConsole) Add-Content -LiteralPath '$wl' -Value (`"[{0}] {1}`" -f (Get-Date -Format 'HH:mm:ss'), `$Message) -Encoding UTF8 } "
    [void]$sb.AppendLine($override)
    return $sb.ToString()
}

function Invoke-ModuleBatch {
    param([object[]]$Batch, [int]$Workers = 4)
    $results = @()
    if (-not $Batch -or $Batch.Count -eq 0) { return $results }
    # v2.65 (C8): no Count==1 shortcut - advanced-mode singleton phases exercise the SAME
    # pooled dispatcher as full batches (the shortcut hid worker/pool-only failures from every
    # small batch - the v2.58 masking class). -Sequential keeps the synchronous inline
    # dispatcher; the SimpleUI front-screen path never reaches this function (see
    # Invoke-SelectedModules: it returns inline before phases are built).
    if ($Sequential) {
        foreach ($m in $Batch) {
            $wlog = Join-Path $CaseDir ("worker_{0}.log" -f $m.Id)
            $pre = New-WorkerPreamble -WorkerLog $wlog
            $md = @{ Id = $m.Id; Name = $m.Name; RunText = $m.Run.ToString() }
            $ps = [powershell]::Create()
            $null = $ps.AddScript($script:ModuleWorkerText).AddArgument($pre).AddArgument($md)
            # v2.65 (C5): mirror the parallel EndInvoke path - a synchronous worker failure is
            # logged and skipped, never propagated (it used to crash the whole inline batch).
            try {
                # v2.65 (C8): filter to the result record before First 1 - a module that leaks
                # pipeline output must not shadow the result (a leak comes first in the stream)
                $r = @($ps.Invoke()) | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['Error'] -and $_.PSObject.Properties['Seconds'] } | Select-Object -First 1
                if ($r) {
                    $results += $r
                    if ($r.Error) { Write-CaseLog ("Module {0} ({1}) ERROR: {2}" -f $r.Id, $r.Name, $r.Error) 'Red' }
                    else { Write-CaseLog ("Module {0} ({1}) done in {2:N1}s [inline]" -f $r.Id, $r.Name, $r.Seconds) 'DarkGray' -NoConsole }
                }
            } catch { Write-CaseLog ("Module {0} worker failed: {1}" -f $m.Id, $_.Exception.Message) 'Red' }
            $ps.Dispose()
            Merge-WorkerLog $wlog
        }
        return $results
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, $Workers)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($m in $Batch) {
        $wlog = Join-Path $CaseDir ("worker_{0}.log" -f $m.Id)
        $ps = [powershell]::Create()
        $null = $ps.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog $wlog)).AddArgument(@{ Id = $m.Id; Name = $m.Name; RunText = $m.Run.ToString() })
        $ps.RunspacePool = $pool
        $null = $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Module = $m; Log = $wlog })
    }
    while ($jobs.Count -gt 0) {
        $doneIdx = @()
        for ($i = 0; $i -lt $jobs.Count; $i++) {
            if ($jobs[$i].Handle.IsCompleted) { $doneIdx += $i }
        }
        foreach ($i in ($doneIdx | Sort-Object -Descending)) {
            $j = $jobs[$i]
            try {
                # v2.65 (C8): same result-record filter as the inline dispatcher (leak must not shadow)
                $r = @($j.PS.EndInvoke($j.Handle)) | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['Error'] -and $_.PSObject.Properties['Seconds'] } | Select-Object -First 1
                if ($r) {
                    $results += $r
                    if ($r.Error) { Write-CaseLog ("Module {0} ({1}) ERROR: {2}" -f $r.Id, $r.Name, $r.Error) 'Red' }
                    else { Write-CaseLog ("Module {0} ({1}) done in {2:N1}s" -f $r.Id, $r.Name, $r.Seconds) 'DarkGray' -NoConsole }
                }
            } catch { Write-CaseLog ("Module {0} worker failed: {1}" -f $j.Module.Id, $_.Exception.Message) 'Red' }
            $j.PS.Dispose()
            Merge-WorkerLog $j.Log
            $jobs.RemoveAt($i)
        }
        if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 300 }
    }
    $pool.Close()
    $pool.Dispose()
    return $results
}

function Merge-WorkerLog {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        try {
            $lines = Get-Content -LiteralPath $Path
            if ($lines) { Add-Content -LiteralPath $CaseLog -Value $lines -Encoding UTF8 }
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

$script:Modules = @(
    [pscustomobject]@{ Id = '1.1'; Cat = 'VOLATILE'; Name = 'Processes (path, cmdline, company, parent, flags)'; Default = $true; Quick = $true;
        Run = {
            $rows = Get-ProcessInventory
            Save-Rows -Name 'processes' -Rows $rows
            $flagged = @($rows | Where-Object { $_.Flags })
            Save-Rows -Name 'processes_flagged' -Rows $flagged
            $kitRoot = Get-KitRoot
            $script:CollectorPids = @($rows | Where-Object { $_.Path -and $_.Path -like "$kitRoot*" } | ForEach-Object { [int]"$($_.PID)" } | Sort-Object -Unique)
            $script:KitPaths = @($kitRoot, $CaseDir, (Join-Path $env:TEMP 'opencode')) | Where-Object { $_ }
        } }
    [pscustomobject]@{ Id = '1.2'; Cat = 'VOLATILE'; Name = 'Full process SHA256 hashing (slower)'; Default = $false; Quick = $false;
        Run = {
            $rows = Get-ProcessInventory | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) } | Select-Object -ExpandProperty Path -Unique
            $hashed = foreach ($p in $rows) {
                try {
                    $h = Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop
                    [pscustomobject]@{ Path = $p; SHA256 = $h.Hash }
                } catch { [pscustomobject]@{ Path = $p; SHA256 = 'ERROR' } }
            }
            Save-Rows -Name 'process_hashes' -Rows $hashed
        } }
    [pscustomobject]@{ Id = '1.3'; Cat = 'VOLATILE'; Name = 'Network connections (TCP/UDP with process map)'; Default = $true; Quick = $true;
        Run = {
            $rows = Get-ConnectionTable
            Save-Rows -Name 'connections' -Rows $rows
            $ext = @($rows | Where-Object { $_.Public -and $_.State -match 'Established|SynSent' })
            Save-Rows -Name 'connections_public_established' -Rows $ext
        } }
    [pscustomobject]@{ Id = '1.4'; Cat = 'VOLATILE'; Name = 'DNS cache + ARP table'; Default = $true; Quick = $true;
        Run = {
            Save-Rows -Name 'dns_cache' -Rows (Get-DnsCacheRows)
            Save-Rows -Name 'arp_table' -Rows (Get-ArpRows)
        } }
    [pscustomobject]@{ Id = '1.5'; Cat = 'VOLATILE'; Name = 'Logon sessions (quser/qwinsta/klist raw)'; Default = $true; Quick = $true;
        Run = {
            Invoke-ExeCapture -SubDir 'sessions' -Name 'quser.txt' -Exe quser.exe -Arguments ''
            Invoke-ExeCapture -SubDir 'sessions' -Name 'qwinsta.txt' -Exe qwinsta.exe -Arguments ''
            Invoke-ExeCapture -SubDir 'sessions' -Name 'klist.txt' -Exe klist.exe -Arguments ''
            $sess = Get-WmiOrCim -Class Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, Authentication
            Save-Rows -Name 'logon_sessions' -Rows $sess
        } }
    [pscustomobject]@{ Id = '1.6'; Cat = 'VOLATILE'; Name = 'Kernel drivers'; Default = $true; Quick = $false;
        Run = {
            $d = Get-WmiOrCim -Class Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode
            Save-Rows -Name 'drivers' -Rows $d
            Save-Rows -Name 'drivers_flagged' -Rows @($d | Where-Object { Test-IsUserWritablePath "$($_.PathName)" })
            Invoke-ExeCapture -SubDir 'drivers' -Name 'driverquery_v.csv' -Exe driverquery.exe -Arguments '/v /fo csv'
        } }
    [pscustomobject]@{ Id = '1.7'; Cat = 'VOLATILE'; Name = 'Svchost masquerade audit (live -k groups vs registered ServiceDlls)'; Default = $true; Quick = $true;
        Run = {
            # Live svchost -k groups must exist in HKLM:\...\Svchost, and every service in a
            # registered group must carry a ServiceDll. Anything else is a masquerade/persistence
            # tell (svchost.exe is the favorite disguise because it is always running anyway).
            $rows = New-Object System.Collections.Generic.List[object]
            $grpMap = @{}
            $svk = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' -ErrorAction SilentlyContinue
            if ($svk) {
                foreach ($p in ($svk.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    $grpMap["$($p.Name)"] = @($p.Value)
                }
            }
            $svcDll = @{}
            foreach ($g in @($grpMap.Keys)) {
                foreach ($svc in $grpMap[$g]) {
                    $s = "$svc"
                    if ($s -and -not $svcDll.ContainsKey($s)) {
                        # $null = no Parameters key at all (stock Windows does this, e.g. nsi - not a tell)
                        $dll = $null
                        $parKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$s\Parameters"
                        if (Test-Path -LiteralPath $parKey) {
                            $dll = ''
                            try { $dll = "$((Get-ItemProperty -Path $parKey -Name ServiceDll -ErrorAction Stop).ServiceDll)" } catch { }
                        }
                        $svcDll[$s] = $dll
                    }
                }
            }
            $procs = @()
            try { $procs = @(Get-WmiOrCim -Class Win32_Process | Where-Object { "$($_.Name)" -match '(?i)^svchost\.exe$' }) } catch { }
            $seen = @{}
            foreach ($p in $procs) {
                $grp = ''
                if ("$($p.CommandLine)" -match '\-k\s+(\S+)') { $grp = $Matches[1] }
                if (-not $grp) { continue }
                if (-not $grpMap.ContainsKey($grp)) {
                    $key = "UnregisteredGroup|$grp"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $null = $rows.Add([pscustomobject]@{ Type = 'UnregisteredGroup'; Group = $grp; Service = ''; PID = $p.ProcessId; Path = ''; Detail = "svchost running with -k $grp but that group is not registered in the Svchost registry key (masquerade tell)" })
                    continue
                }
                foreach ($svc in $grpMap[$grp]) {
                    $dll = $svcDll["$svc"]
                    if ($null -eq $dll) { continue }
                    if (-not $dll) {
                        $key = "ServiceDllMissing|$grp|$svc"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $null = $rows.Add([pscustomobject]@{ Type = 'ServiceDllMissing'; Group = $grp; Service = "$svc"; PID = ''; Path = ''; Detail = "service in group '$grp' has a Parameters key but no ServiceDll value (broken or tampered registration)" })
                        continue
                    }
                    if ("$dll" -notmatch '(?i)\\(System32|SysWOW64)\\') {
                        $key = "OutOfPathServiceDll|$svc"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $null = $rows.Add([pscustomobject]@{ Type = 'OutOfPathServiceDll'; Group = $grp; Service = "$svc"; PID = ''; Path = $dll; Detail = "ServiceDll outside System32 - svchost-hosted persistence in a user-writable location" })
                    }
                }
            }
            # unregistered loaded modules (live; needs elevation - degrades silently without)
            $regDlls = @{}
            foreach ($v in $svcDll.Values) {
                if (-not $v) { continue }
                $lf = ''
                try { $lf = (Split-Path "$v" -Leaf).ToLower() } catch { }
                if ($lf) { $regDlls[$lf] = $true }
            }
            foreach ($p in $procs) {
                if (-not $p.ProcessId -or $seen.Count -gt 40) { continue }
                $mods = $null
                try { $mods = (Get-Process -Id $p.ProcessId -ErrorAction Stop).Modules } catch { continue }
                foreach ($m in $mods) {
                    $lf = ''
                    try { $lf = "$($m.FileName)" } catch { continue }
                    if (-not $lf) { continue }
                    $leaf = ''
                    try { $leaf = (Split-Path $lf -Leaf).ToLower() } catch { continue }
                    if (-not $leaf -or $regDlls.ContainsKey($leaf)) { continue }
                    if ("$lf" -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }
                    $sig = Get-SignatureInfo -Path $lf
                    if ($sig -and "$($sig.Signer)" -match 'Microsoft') { continue }
                    $key = "UnregisteredModule|$lf"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $null = $rows.Add([pscustomobject]@{ Type = 'UnregisteredModule'; Group = ''; Service = ''; PID = $p.ProcessId; Path = $lf; Detail = "unsigned/non-Microsoft DLL loaded inside svchost that is not a registered ServiceDll" })
                    if ($seen.Count -gt 40) { break }
                }
            }
            Save-Rows -Name 'svchost_audit' -Rows $rows.ToArray()
            $hot = @($rows | Where-Object { "$($_.Type)" -match 'UnregisteredGroup|OutOfPathServiceDll' }).Count
            if ($rows.Count -gt 0) {
                Write-CaseLog "    svchost audit: $($rows.Count) finding(s) ($hot high-tell) -> csv\svchost_audit.csv" $(if ($hot -gt 0) { 'Red' } else { 'Yellow' })
            } else {
                Write-CaseLog '    svchost audit: all live -k groups registered, ServiceDlls in place' 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '2.1'; Cat = 'PERSISTENCE'; Name = 'Autoruns (Run keys + startup folders)'; Default = $true; Quick = $true;
        Run = {
            $rows = @()
            $runPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            )
            foreach ($rp in $runPaths) {
                if (Test-Path $rp) {
                    $prop = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
                    foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $rows += [pscustomobject]@{ Location = $rp; Hive = 'HKLM'; User = ''; Name = $p.Name; Value = "$($p.Value)" }
                    }
                }
            }
            try {
                $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
                foreach ($sid in $sids) {
                    foreach ($sub in @('Run', 'RunOnce')) {
                        $k = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\$sub"
                        if (Test-Path $k) {
                            $prop = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                            foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                                $rows += [pscustomobject]@{ Location = $k; Hive = 'HKU'; User = $sid.PSChildName; Name = $p.Name; Value = "$($p.Value)" }
                            }
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'autoruns_runkeys' -Rows $rows
            $startups = @()
            $dirs = @()
            try {
                $dirs += [Environment]::GetFolderPath('CommonStartup')
                $dirs += [Environment]::GetFolderPath('Startup')
            } catch { }
            foreach ($d in ($dirs | Where-Object { $_ -and (Test-Path $_) })) {
                Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $s = Get-SignatureInfo -Path $_.FullName
                    $startups += [pscustomobject]@{ Folder = $d; File = $_.Name; Created = $_.CreationTime; SigStatus = if ($s) { $s.Status } else { '' }; Signer = if ($s) { $s.Signer } else { '' } }
                }
            }
            Save-Rows -Name 'autoruns_startup_folders' -Rows $startups
        } }
    [pscustomobject]@{ Id = '2.2'; Cat = 'PERSISTENCE'; Name = 'Services (with odd-path flags)'; Default = $true; Quick = $true;
        Run = {
            $s = Get-WmiOrCim -Class Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName, ProcessId
            foreach ($row in $s) {
                $exe = ''
                try { if ($row.PathName) { $exe = ($row.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1' } } catch { }
                $row | Add-Member -NotePropertyName Flags -NotePropertyValue ($(if (Test-IsUserWritablePath $row.PathName) { 'USER-WRITABLE-PATH;' }) + $(if ($exe -and (Test-Path -LiteralPath $exe) -eq $false) { 'BINARY-MISSING;' })) -Force
            }
            Save-Rows -Name 'services' -Rows $s
            Save-Rows -Name 'services_flagged' -Rows @($s | Where-Object { $_.Flags })
        } }
    [pscustomobject]@{ Id = '2.3'; Cat = 'PERSISTENCE'; Name = 'Scheduled tasks (non-MS authors flagged)'; Default = $true; Quick = $true;
        Run = {
            if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                Invoke-ExeCapture -SubDir 'tasks' -Name 'schtasks_all.csv' -Exe schtasks.exe -Arguments '/query /fo csv /v'
                return
            }
            $rows = @()
            foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                $actions = ($t.Actions | ForEach-Object { $a = "$($_.Execute) $($_.Arguments)".Trim(); $a }) -join ' || '
                $triggers = (@($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ';')
                $author = ''
                try { $author = $t.Author } catch { }
                $flags = @()
                if ($author -and $author -notmatch '(?i)microsoft') { $flags += 'NON-MS-AUTHOR' }
                if ($actions -match '(?i)powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|curl|wget') { $flags += 'SUSPICIOUS-INTERPRETER' }
                if (Test-IsUserWritablePath $actions) { $flags += 'USER-WRITABLE-PATH' }
                $rows += [pscustomobject]@{
                    Name = $t.TaskName; Path = $t.TaskPath; Author = $author; State = $t.State
                    Actions = $actions; Triggers = $triggers; RunAs = $t.Principal.UserId
                    Flags = ($flags -join ';')
                }
            }
            # v2.83 (R45): TaskCache registry side - ghost/hidden-task checks. Deleting the
            # Tree key + Tasks key + XML does NOT unload an already-loaded task until reboot,
            # and deleting the SD value HIDES the task from schtasks/GUI while it keeps
            # running. Tasks\{guid} with no Tree\GID link or missing SD = tamper signal.
            $tcRows = New-Object System.Collections.Generic.List[object]
            try {
                $tcRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
                $treeGids = @{}
                if (Test-Path "$tcRoot\Tree") {
                    foreach ($k in @(Get-ChildItem "$tcRoot\Tree" -Recurse -ErrorAction SilentlyContinue)) {
                        $gid = ''
                        try { $gid = "$($k.GetValue('GID'))".Trim() } catch { }
                        if ($gid) { $treeGids[$gid.ToLower()] = $true }
                        $tp = ($k.Name -replace '^.*TaskCache\\Tree', '')
                        $null = $tcRows.Add([pscustomobject]@{ Kind = 'tree'; TaskPath = $tp; Guid = $gid; SdPresent = ''; Flags = '' })
                    }
                }
                if (Test-Path "$tcRoot\Tasks") {
                    foreach ($k in @(Get-ChildItem "$tcRoot\Tasks" -ErrorAction SilentlyContinue)) {
                        $sd = $false
                        try { $sd = ($null -ne $k.GetValue('SD')) } catch { }
                        $tflags = @()
                        if (-not $sd) { $tflags += 'SD-MISSING (hidden from schtasks/GUI)' }
                        if (-not $treeGids.ContainsKey($k.PSChildName.ToLower())) { $tflags += 'ORPHANED (no Tree link)' }
                        $null = $tcRows.Add([pscustomobject]@{ Kind = 'tasks'; TaskPath = ''; Guid = $k.PSChildName; SdPresent = $sd; Flags = ($tflags -join ';') })
                    }
                }
            } catch { }
            Save-Rows -Name 'scheduled_taskcache' -Rows $tcRows.ToArray()
            Save-Rows -Name 'scheduled_tasks' -Rows $rows
            Save-Rows -Name 'scheduled_tasks_flagged' -Rows @($rows | Where-Object { $_.Flags })
        } }
    [pscustomobject]@{ Id = '2.4'; Cat = 'PERSISTENCE'; Name = 'WMI event subscriptions'; Default = $true; Quick = $false;
        Run = {
            $filters = Get-WmiOrCim -Class '__EventFilter' -Namespace 'root\subscription'
            $consumers = @()
            foreach ($cn in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'LogFileEventConsumer')) {
                try {
                    $c = Get-CimInstance -Namespace 'root\subscription' -ClassName $cn -ErrorAction Stop
                    foreach ($x in $c) {
                        $cmd = ''
                        try { $cmd = $x.CommandLineTemplate } catch { }
                        if (-not $cmd) { try { $cmd = $x.ScriptText } catch { } }
                        if (-not $cmd) { try { $cmd = $x.Text } catch { } }
                        $consumers += [pscustomobject]@{ Type = $cn; Name = $x.Name; Payload = $cmd }
                    }
                } catch { }
            }
            $bindings = @()
            try { $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop } catch { }
            Save-Rows -Name 'wmi_event_filters' -Rows $filters
            Save-Rows -Name 'wmi_event_consumers' -Rows $consumers
            Save-Rows -Name 'wmi_bindings' -Rows $bindings
        } }
    [pscustomobject]@{ Id = '2.6'; Cat = 'PERSISTENCE'; Name = 'ASEP deep sweep (IFEO, AppInit, Winlogon, COM hijacks, netsh, LSA, StartupApproved, Active Setup, screensaver, Office/PS profiles, print/time, browser ext)'; Default = $true; Quick = $false;
        Run = {
            $asepList = New-Object System.Collections.Generic.List[object]
            function Add-Asep([string]$Category, [string]$Location, [string]$Name, [string]$Value, [string[]]$Flags) {
                $asepList.Add([pscustomobject]@{ Category = $Category; Location = $Location; Name = $Name; Value = $Value; Flags = ($Flags -join ';') })
            }
            $flagFor = {
                param([string]$v)
                $f = @()
                if ($v -and (Test-IsUserWritablePath $v)) { $f += 'user-path' }
                return $f
            }
            # IFEO: any Debugger value (incl. accessibility sticky-keys backdoors)
            foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
                if (Test-Path $hive) {
                    foreach ($k in (Get-ChildItem -Path $hive -ErrorAction SilentlyContinue)) {
                        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                        foreach ($vn in @('Debugger', 'GlobalFlag', 'MonitorProcess', 'SilentProcessExit')) {
                            $v = $null; try { $v = $p.$vn } catch { }
                            if ("$v") { Add-Asep 'IFEO' $k.PSPath $vn "$v" (& $flagFor "$v") }
                        }
                    }
                }
            }
            # AppInit_DLLs (32/64)
            foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
                $p = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue
                if ($p) {
                    $v = "$($p.AppInit_DLLs)"
                    if ($v.Trim()) { Add-Asep 'AppInit_DLLs' $hive 'AppInit_DLLs' $v ((& $flagFor $v) + 'nondefault') }
                }
            }
            # Winlogon core values (Shell/Userinit/Taskman/AppSetup replaced or appended)
            $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
            if ($wl) {
                foreach ($vn in @('Shell', 'Userinit', 'Taskman', 'AppSetup')) {
                    $v = $null; try { $v = $wl.$vn } catch { }
                    if (-not "$v") { continue }
                    $ok = $false
                    $entries = @("$v" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    if ($vn -eq 'Shell') { $ok = ($entries -contains 'explorer.exe') }
                    elseif ($vn -eq 'Userinit') { $ok = (@($entries | Where-Object { $_ -notmatch '(?i)userinit\.exe$' }).Count -eq 0) }
                    $f = @()
                    if (-not $ok) { $f += 'nondefault' }
                    $f += (& $flagFor "$v")
                    if ($f.Count -gt 0) { Add-Asep 'Winlogon' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' $vn "$v" $f }
                }
            }
            # WinlogonNotify DLLs
            $notify = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
            if (Test-Path $notify) {
                foreach ($k in (Get-ChildItem -Path $notify -ErrorAction SilentlyContinue)) {
                    $v = "$((Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).DLLName)"
                    if ($v) { Add-Asep 'WinlogonNotify' $k.PSPath 'DLLName' $v (& $flagFor $v) }
                }
            }
            # netsh helper DLLs
            $netsh = 'HKLM:\SOFTWARE\Microsoft\Netsh'
            if (Test-Path $netsh) {
                foreach ($k in (Get-ChildItem -Path $netsh -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $v = "$($prop.Value)"
                        if ($v -match '\.dll') { Add-Asep 'NetshHelper' $k.PSPath $prop.Name $v (& $flagFor $v) }
                    }
                }
            }
            # LSA security/authentication packages (DLL list values)
            $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
            if ($lsa) {
                foreach ($vn in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
                    $v = $null; try { $v = $lsa.$vn } catch { }
                    if ("$v") {
                        $f = @()
                        foreach ($dll in @("$v" -split '[,; ]+' | Where-Object { $_ })) { if (Test-IsUserWritablePath $dll) { $f += "user-path($dll)" } }
                        Add-Asep 'LsaPackages' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' $vn "$v" $f
                    }
                }
            }
            # HKCU COM InprocServer32 entries (per-user COM hijack suspects)
            try {
                $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
                foreach ($sid in $sids) {
                    $clsidRoot = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Classes\CLSID"
                    if (-not (Test-Path $clsidRoot)) { continue }
                    foreach ($clsid in (Get-ChildItem -Path $clsidRoot -ErrorAction SilentlyContinue | Select-Object -First 4000)) {
                        $ips = "$($clsid.PSPath)\InprocServer32"
                        if (Test-Path $ips) {
                            $v = "$((Get-ItemProperty -Path $ips -ErrorAction SilentlyContinue).'(default)')"
                            if ($v -and $v -notmatch '^[Hh]ttp') {
                                $f = & $flagFor $v
                                if ($f) { Add-Asep 'ComHijack-HKCU' $ips "$($clsid.PSChildName)" $v $f }
                            }
                        }
                    }
                }
            } catch { }
            # StartupApproved stamps (enabled/disabled per autorun entry)
            foreach ($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved')) {
                if (-not (Test-Path $root)) { continue }
                $hiveName = if ($root -like 'HKCU:*') { 'HKCU' } else { 'HKLM' }
                foreach ($sub in @('Run', 'RunOnce', 'StartupFolder')) {
                    $k = "$root\$sub"
                    if (-not (Test-Path $k)) { continue }
                    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $bytes = $null; try { $bytes = $prop.Value } catch { }
                        $state = 'unknown'
                        if ($bytes -is [byte[]] -and $bytes.Count -gt 0) {
                            if (@(2, 3) -contains $bytes[0]) { $state = 'enabled' } elseif (@(6, 7, 13) -contains $bytes[0]) { $state = 'disabled' }
                        }
                        Add-Asep 'StartupApproved' $k $prop.Name $state @()
                    }
                }
            }
            # Custom shim databases (SDB) - classic persistence, rare legit (v2.23 KAPE parity)
            foreach ($sdb in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB', 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom')) {
                if (-not (Test-Path $sdb)) { continue }
                foreach ($k in (Get-ChildItem -Path $sdb -Recurse -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    $v = ''
                    if ($p -and $p.PSObject.Properties['FullPath']) { $v = "$($p.FullPath)" }
                    if (-not $v) { foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) { if ("$($prop.Value)" -match '\.sdb$') { $v = "$($prop.Value)"; break } } }
                    if ($v) { Add-Asep 'Sdb' $k.PSPath $k.PSChildName $v (& $flagFor $v) }
                }
            }
            # ---- v2.62 detection-surface extension (all read-only; new categories are
            # report-visible, only user-path/nondefault values join the verdict signal -
            # same FP doctrine as the COM-hijack exclusion above) ----
            $userProfiles = @(Get-UserProfileList)
            $fsUsers = @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)
            # Active Setup StubPath (runs per-user at every logon - classic stager spot)
            foreach ($asRoot in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components')) {
                if (-not (Test-Path $asRoot)) { continue }
                foreach ($k in (Get-ChildItem -Path $asRoot -ErrorAction SilentlyContinue)) {
                    $v = "$((Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).StubPath)"
                    if ($v) { Add-Asep 'ActiveSetup' $k.PSPath "StubPath ($($k.PSChildName))" $v (& $flagFor $v) }
                }
            }
            # Screensaver executable (per-user; a .scr on a logon path)
            foreach ($up in $userProfiles) {
                $dp = Get-ItemProperty -Path "Registry::HKEY_USERS\$($up.Sid)\Control Panel\Desktop" -ErrorAction SilentlyContinue
                $sv = $null; if ($dp) { $sv = $dp.PSObject.Properties['SCRNSAVE.EXE'] }
                if ($sv -and "$($sv.Value)") { Add-Asep 'Screensaver' "HKU\$($up.Sid)\Control Panel\Desktop" 'SCRNSAVE.EXE' "$($sv.Value)" (& $flagFor "$($sv.Value)") }
            }
            # Office add-ins / startup templates (WLL/XLL/dotm/xlam in the dirs Word/Excel autorun)
            foreach ($u in $fsUsers) {
                foreach ($od in @((Join-Path $u.FullName 'AppData\Roaming\Microsoft\Word\Startup'), (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Excel\XLSTART'))) {
                    foreach ($f in (Get-ChildItem -LiteralPath $od -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '(?i)^\.(wll|xll|dotm|xlam)$' } | Select-Object -First 20)) {
                        Add-Asep 'OfficeAddin' $f.FullName $f.Name "modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" @('user-path')
                    }
                }
            }
            # Outlook client-side rules (existence-only, observational - no verdict weight)
            foreach ($up in $userProfiles) {
                $rk = "Registry::HKEY_USERS\$($up.Sid)\Software\Microsoft\Windows Messaging Subsystem\Rules"
                if (Test-Path $rk) {
                    $n = @(Get-ChildItem -Path $rk -ErrorAction SilentlyContinue).Count
                    if ($n -gt 0) { Add-Asep 'OutlookRules' $rk "$n rule subkey(s)" 'existence - review rule actions for auto-run/forward abuse' @('observational') }
                }
            }
            # Chromium browser extensions (report-visible; 'new-in-window' when the version dir appeared in-window)
            $extWin = (Get-Date).AddHours(-$(if ($script:LogHours -gt 0) { $script:LogHours } else { 168 }))
            foreach ($u in $fsUsers) {
                foreach ($bRoot in @((Join-Path $u.FullName 'AppData\Local\Google\Chrome\User Data\Default\Extensions'), (Join-Path $u.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\Extensions'))) {
                    if (-not (Test-Path -LiteralPath $bRoot)) { continue }
                    foreach ($ext in (Get-ChildItem -LiteralPath $bRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 60)) {
                        $ver = @(Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1)[0]
                        if (-not $ver) { continue }
                        $nm = $ext.Name
                        $mf = Join-Path $ver.FullName 'manifest.json'
                        if (Test-Path -LiteralPath $mf) { try { $j = Get-Content -LiteralPath $mf -Raw -ErrorAction Stop | ConvertFrom-Json; if ($j.name) { $nm = "$($j.name)" } } catch { } }
                        $f = @()
                        try { if ($ver.CreationTime -gt $extWin) { $f += 'new-in-window' } } catch { }
                        Add-Asep 'BrowserExt' $ext.FullName $nm "$($ext.Name) v$($ver.Name)" $f
                    }
                }
            }
            # PowerShell profiles (user-profile scripts auto-run in every PS session).
            # v2.64 skeleton gate: a <=200-byte profile containing none of the suspicious
            # keywords is a default shell put there by the PS installer - report-visible only
            # (no user-path flag, so it cannot ride the persistence verdict signal). Size alone
            # is NOT the gate: big-but-benign files keep the flag, keyword content keeps it too.
            # The same basename under BOTH Documents\WindowsPowerShell (5.1) and Documents\PowerShell
            # (7+) is ONE profile, not two persistence hits - one row, both paths in Location.
            $psSkeletonKw = @('Invoke-Expression', 'IEX ', 'DownloadString', 'DownloadFile', 'FromBase64String', 'EncodedCommand', 'Start-Process', 'Net.WebClient', '-Hidden', 'WScript.Shell')
            foreach ($u in $fsUsers) {
                $ppByBase = @{}
                foreach ($pp in @((Join-Path $u.FullName 'Documents\WindowsPowerShell\profile.ps1'), (Join-Path $u.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'), (Join-Path $u.FullName 'Documents\PowerShell\profile.ps1'), (Join-Path $u.FullName 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'))) {
                    if (-not (Test-Path -LiteralPath $pp -PathType Leaf)) { continue }
                    $b = [IO.Path]::GetFileName($pp)
                    if (-not $ppByBase.ContainsKey($b)) { $ppByBase[$b] = New-Object System.Collections.Generic.List[object] }
                    $ppByBase[$b].Add((Get-Item -LiteralPath $pp))
                }
                foreach ($b in $ppByBase.Keys) {
                    $fis = $ppByBase[$b].ToArray()
                    $locs = @($fis | ForEach-Object { $_.FullName })
                    $sizes = @($fis | ForEach-Object { $_.Length } | Sort-Object -Unique)
                    $val = "$(($(($sizes | Select-Object -First 2) | ForEach-Object { "$_ bytes" }) -join ' / '))"
                    $skeleton = $true
                    foreach ($fi in $fis) {
                        if ($fi.Length -gt 200) { $skeleton = $false; break }
                        $content = ''
                        try { $content = (Get-Content -LiteralPath $fi.FullName -Raw -ErrorAction Stop) } catch { $skeleton = $false; break }
                        foreach ($kw in $psSkeletonKw) { if ($content -match [regex]::Escape($kw)) { $skeleton = $false; break } }
                        if (-not $skeleton) { break }
                    }
                    Add-Asep 'PsProfile' ($locs -join ' | ') $b $val $(if ($skeleton) { @() } else { @('user-path') })
                }
            }
            foreach ($pp in @((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\profile.ps1'), (Join-Path $env:ProgramFiles 'PowerShell\7\profile.ps1'))) {
                if (Test-Path -LiteralPath $pp -PathType Leaf) { $fi = Get-Item -LiteralPath $pp; Add-Asep 'PsProfile' $pp $fi.Name "$($fi.Length) bytes" (& $flagFor $pp) }
            }
            # Print processors + monitors (driver DLL values)
            foreach ($pEnv in @('Windows x64', 'Windows NT x86')) {
                foreach ($pp2 in @("HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\$pEnv\Print Processors", "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\$pEnv\Print Monitors")) {
                    foreach ($k in (Get-ChildItem -Path $pp2 -ErrorAction SilentlyContinue)) {
                        $v = "$((Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).Driver)"
                        if ($v) { Add-Asep ($(if ($pp2 -match 'Processors') { 'PrintProcessor' } else { 'PrintMonitor' })) $k.PSPath 'Driver' $v (& $flagFor $v) }
                    }
                }
            }
            # W32Time time providers (DllName - rare legit additions)
            $tp = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
            if (Test-Path $tp) {
                foreach ($k in (Get-ChildItem -Path $tp -ErrorAction SilentlyContinue)) {
                    $v = "$((Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).DllName)"
                    if ($v) { Add-Asep 'TimeProvider' $k.PSPath 'DllName' $v (& $flagFor $v) }
                }
            }
            $rows = $asepList.ToArray()
            Save-Rows -Name 'asep_sweep' -Rows $rows
            $hot = @($rows | Where-Object { $_.Flags -match 'user-path|nondefault' })
            if ($hot.Count -gt 0) {
                Write-CaseLog "    ASEP sweep: $($rows.Count) entries, $($hot.Count) UNCOMMON/USER-PATH (IFEO/AppInit/COM/netsh/LSA) -> csv\asep_sweep.csv" 'Red'
                foreach ($h in ($hot | Select-Object -First 5)) { Write-CaseLog "      [$($h.Category)] $($h.Name) = $($h.Value)" 'Red' }
            } else {
                Write-CaseLog "    ASEP sweep: $($rows.Count) entries, none flagged" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '3.1'; Cat = 'NETWORK MAP'; Name = 'Passive map (interfaces, routes, SMB, creds, proxy)'; Default = $true; Quick = $true;
        Run = {
            $net = @()
            try {
                if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
                    foreach ($i in (Get-NetIPConfiguration)) {
                        $net += [pscustomobject]@{
                            Interface = $i.InterfaceAlias; Description = $i.InterfaceDescription
                            IPv4 = (@($i.IPv4Address | ForEach-Object { $_.IPAddress }) -join ',')
                            Gateway = (@($i.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ',')
                            DNS = (@($i.DNSServer | ForEach-Object { $_.ServerAddresses }) -join ',')
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'net_interfaces' -Rows $net
            $routes = @()
            try {
                if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
                    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.DestinationPrefix -notmatch '^(127\.|169\.254|224\.|255\.255|0\.0\.0\.0)' } |
                        Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex -Unique)
                }
            } catch { }
            Save-Rows -Name 'net_reachable_subnets' -Rows $routes
            $hosted = @(); $mounts = @(); $active = @()
            try { if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { $hosted = @(Get-SmbShare | Select-Object Name, Path, Description, ScopeName) } } catch { }
            try { if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) { $mounts = @(Get-SmbMapping | Select-Object LocalPath, RemotePath, Status) } } catch { }
            try { if (Get-Command Get-SmbConnection -ErrorAction SilentlyContinue) { $active = @(Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName, ShareName, UserName, NumOpens) } } catch { }
            Save-Rows -Name 'smb_hosted_shares' -Rows $hosted
            Save-Rows -Name 'smb_mounted_shares' -Rows $mounts
            Save-Rows -Name 'smb_active_connections' -Rows $active
            Invoke-ExeCapture -SubDir 'net' -Name 'cmdkey_list.txt' -Exe cmdkey.exe -Arguments '/list'
            $ck = @()
            $raw = & cmdkey.exe /list 2>$null
            $cur = $null
            foreach ($l in ($raw | ForEach-Object { "$_" })) {
                if ($l -match 'Target:(?:(Domain|Legacy)Type=)?(.+)') {
                    if ($cur) { $ck += $cur }
                    $cur = [pscustomobject]@{ Target = ($Matches[2].Trim()); Type = $Matches[1]; User = '' }
                } elseif ($l -match 'User:\s*(.+)' -and $cur) { $cur.User = $Matches[1].Trim() }
            }
            if ($cur) { $ck += $cur }
            Save-Rows -Name 'saved_credentials' -Rows $ck
            Invoke-ExeCapture -SubDir 'net' -Name 'net_use.txt' -Exe net.exe -Arguments 'use'
            Invoke-ExeCapture -SubDir 'net' -Name 'net_share.txt' -Exe net.exe -Arguments 'share'
            Invoke-ExeCapture -SubDir 'net' -Name 'ipconfig_all.txt' -Exe ipconfig.exe -Arguments '/all'
            Invoke-ExeCapture -SubDir 'net' -Name 'route_print.txt' -Exe route.exe -Arguments 'print'
            Invoke-ExeCapture -SubDir 'net' -Name 'arp_a.txt' -Exe arp.exe -Arguments '-a'
            Invoke-ExeCapture -SubDir 'net' -Name 'netstat_ano.txt' -Exe netstat.exe -Arguments '-ano'
            $proxy = @()
            foreach ($hive in @('HKLM', 'HKCU')) {
                foreach ($p in @("${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings")) {
                    try {
                        $v = Get-ItemProperty -Path $p -ErrorAction Stop
                        $proxy += [pscustomobject]@{
                            Key = $hive; ProxyEnable = $v.ProxyEnable; ProxyServer = $v.ProxyServer
                            AutoConfigURL = $v.AutoConfigURL
                        }
                    } catch { }
                }
            }
            Save-Rows -Name 'proxy_settings' -Rows $proxy
            $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            if (Test-Path $hosts) { Out-RawText -SubDir 'net' -Name 'hosts.txt' -Text (Get-Content -LiteralPath $hosts) }
        } }
    [pscustomobject]@{ Id = '3.2'; Cat = 'NETWORK MAP'; Name = 'ACTIVE probes - generates outbound traffic'; Default = $false; Quick = $false;
        Run = {
            $r = @()
            $gw = $null
            try {
                $gws = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
                $gw = $gws.NextHop
            } catch { }
            if ($gw) {
                $ok = $false
                try { $ok = [bool](Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { }
                $r += [pscustomobject]@{ Check = 'Gateway'; Target = $gw; Result = $ok }
            }
            foreach ($t in @('1.1.1.1', '8.8.8.8')) {
                $ok = $false
                try { $ok = [bool](Test-Connection -ComputerName $t -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { }
                $r += [pscustomobject]@{ Check = 'Internet-ICMP'; Target = $t; Result = $ok }
            }
            try {
                $http = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                $r += [pscustomobject]@{ Check = 'Internet-HTTP'; Target = 'msftconnecttest.com'; Result = ($http.StatusCode -eq 200) }
            } catch {
                $r += [pscustomobject]@{ Check = 'Internet-HTTP'; Target = 'msftconnecttest.com'; Result = $false }
            }
            try {
                $dnsr = Resolve-DnsName -Name 'www.microsoft.com' -ErrorAction Stop | Select-Object -First 1
                $r += [pscustomobject]@{ Check = 'DNS-Resolve'; Target = 'www.microsoft.com'; Result = ($null -ne $dnsr) }
            } catch {
                $r += [pscustomobject]@{ Check = 'DNS-Resolve'; Target = 'www.microsoft.com'; Result = $false }
            }
            Save-Rows -Name 'net_active_probes' -Rows $r
        } }
    [pscustomobject]@{ Id = '3.3'; Cat = 'NETWORK MAP'; Name = 'Firewall profiles + firewall log copy'; Default = $true; Quick = $false;
        Run = {
            $prof = @()
            try {
                if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                    foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                        $prof += [pscustomobject]@{
                            Profile = $p.Name; Enabled = $p.Enabled
                            InboundDefault = $p.DefaultInboundAction; OutboundDefault = $p.DefaultOutboundAction
                            LogFileName = "$($p.LogFileName)"; LogMaxKB = $p.LogMaxSizeKilobytes
                        }
                    }
                } else {
                    $raw = (& netsh.exe advfirewall show allprofiles 2>$null | Where-Object { $_ }) -join "`r`n"
                    if ($raw) { Out-RawText -SubDir 'net' -Name 'firewall_profiles_netsh.txt' -Text $raw }
                }
            } catch { }
            Save-Rows -Name 'firewall_profiles' -Rows $prof
            $dst = Join-Path $RawDir 'firewall'
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $copied = 0
            foreach ($logPath in @("$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log", "$env:SystemRoot\System32\LogFiles\Firewall\domainfw.log", "$env:SystemRoot\System32\LogFiles\Firewall\privatefw.log", "$env:SystemRoot\System32\LogFiles\Firewall\publicfw.log")) {
                if (Test-Path -LiteralPath $logPath) {
                    try { Copy-Item -LiteralPath $logPath -Destination $dst -Force -ErrorAction Stop; $copied++ } catch { }
                }
            }
            Write-CaseLog "    firewall: $($prof.Count) profile row(s), $copied log file(s) -> raw\firewall\" 'Gray'
        } }
    [pscustomobject]@{ Id = '4.1'; Cat = 'LOGS'; Name = 'Security log (auth events + evtx export)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ids = @(4624, 4625, 4648, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4735, 4756, 4688, 4698, 5140, 5145, 1102)
            $ev = Get-FilteredEvents -LogName 'Security' -Ids $ids -Start $start
            Save-Rows -Name 'security_events' -Rows $ev
            $auth = @($ev | Where-Object { @(4624, 4625) -contains $_.Id } | ForEach-Object {
                $msg = "$($_.Message)"
                # 4624/4625: the logon account/session live in the New Logon section - anchor after it
                # (Subject Logon ID is the caller's, and a Linked Logon ID may trail New Logon).
                # Messages arrive whitespace-COLLAPSED (no newlines), so captures must be bounded
                # by the next field label - unbounded captures swallow the rest of the message.
                $nlIdx = $msg.IndexOf('New Logon')
                $after = if ($nlIdx -ge 0) { $msg.Substring($nlIdx) } else { $msg }
                $acct = ''; $dom = ''; $subject = ''
                if ($after -match 'Account Name:\s+(.*?)\s+Account Domain:\s+(.*?)\s+Logon ID:') { $acct = $Matches[1].Trim(); $dom = $Matches[2].Trim() }
                if ($msg -match 'Account Name:\s+(.*?)\s+Account Domain:\s+(.*?)\s+Logon ID:') { $subject = $Matches[1].Trim() }
                $ip = if ($msg -match 'Source Network Address:\s+(\S+)') { $Matches[1] } else { '' }
                $lt = if ($msg -match 'Logon Type:\s+(\d+)') { $Matches[1] } else { '' }
                $lid = if ($after -match 'Logon ID:\s+(0x[0-9A-Fa-f]+)') { $Matches[1] } else { '' }
                [pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Account = $acct; AccountDomain = $dom; SubjectAccount = $subject; SourceIp = $ip; LogonType = $lt; LogonId = $lid }
            })
            # account management EIDs (R6 account lifecycle) - TargetUserName-style EventData
            $acctEv = Get-EventDataRows -LogName 'Security' -Id @(4720, 4722, 4724, 4726, 4728, 4732, 4735, 4756) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; SourceIp = 'IpAddress'; LogonType = ''; LogonId = '' })
            $auth = @($auth + $acctEv)
            Save-Rows -Name 'security_auth_events' -Rows $auth
            $brute = @($auth | Where-Object { $_.EventId -eq 4625 } | Group-Object SourceIp |
                Where-Object { $_.Count -ge 5 } | Sort-Object Count -Descending |
                ForEach-Object { [pscustomobject]@{ SourceIp = $_.Name; FailedLogons = $_.Count } })
            Save-Rows -Name 'security_bruteforce_candidates' -Rows $brute
            $sum = @($auth | Group-Object Account, SourceIp | Sort-Object Count -Descending | Select-Object -First 100 |
                ForEach-Object { [pscustomobject]@{ AccountSource = $_.Name; Count = $_.Count } })
            Save-Rows -Name 'security_auth_summary' -Rows $sum
            # v2.20 structured parses (fields need audit policy: 4688 cmdline needs "Include Command Line")
            $procEv = Get-EventDataRows -LogName 'Security' -Id @(4688) -Start $start -Cap 4000 -Fields ([ordered]@{ Account = 'SubjectUserName'; LogonId = 'SubjectLogonId'; NewProcess = 'NewProcessName'; CommandLine = 'CommandLine'; ParentProcess = 'ParentProcessName'; NewProcessId = 'NewProcessId'; CreatorPid = 'ProcessId' })
            Save-Rows -Name 'security_proc_events' -Rows $procEv
            if ($procEv.Count -gt 0) { Write-CaseLog "    4688 process creations: $($procEv.Count) (empty CommandLine = cmdline audit off)" 'Gray' }
            $taskEv = Get-EventDataRows -LogName 'Security' -Id @(4698) -Start $start -Cap 500 -Fields ([ordered]@{ Account = 'SubjectUserName'; TaskName = 'TaskName'; TaskContent = 'TaskContent' })
            foreach ($t in $taskEv) {
                $cmd = ''
                if ("$($t.TaskContent)" -match '<Command>([^<]+)</Command>') { $cmd = $Matches[1] }
                $t | Add-Member -NotePropertyName Command -NotePropertyValue $cmd -Force
                $t.PSObject.Properties.Remove('TaskContent')
            }
            Save-Rows -Name 'security_task_install' -Rows $taskEv
            if ($taskEv.Count -gt 0) { Write-CaseLog "    4698 scheduled task installs: $($taskEv.Count)" 'Gray' }
            $shareEv = Get-EventDataRows -LogName 'Security' -Id @(5140, 5145) -Start $start -Cap 8000 -Fields ([ordered]@{ Account = 'SubjectUserName'; LogonId = 'SubjectLogonId'; ShareName = 'ShareName'; RelativeTargetName = 'RelativeTargetName'; SourceIp = 'IpAddress'; AccessList = 'AccessList' })
            Save-Rows -Name 'security_share_access' -Rows $shareEv
            if ($shareEv.Count -ge 8000) { Write-CaseLog "    share access: capped at 8000 rows - wide file-share activity (file server?)" 'DarkGray' }
            # v2.83 (R45): task DELETIONS from the TaskScheduler operational log + evtx export
            $tsDel = @(Get-TaskDeletionRows $start)
            Save-Rows -Name 'task_deletions' -Rows $tsDel
            if ($tsDel.Count -gt 0) { Write-CaseLog "    scheduled task DELETIONS (4699): $($tsDel.Count)" 'Yellow' }
            Export-Evtx -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FileName 'TaskScheduler_Operational.evtx'
            Export-Evtx -LogName 'Security' -FileName 'Security.evtx'
        } }
    [pscustomobject]@{ Id = '4.2'; Cat = 'LOGS'; Name = 'PowerShell operational log (4104 script blocks)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4104, 400, 600) -Start $start -MaxMsg 2000
            Save-Rows -Name 'powershell_events' -Rows $ev
            Export-Evtx -LogName 'Microsoft-Windows-PowerShell/Operational' -FileName 'PowerShell_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '4.3'; Cat = 'LOGS'; Name = 'Sysmon logs (auto-skips if not installed)'; Default = $true; Quick = $false;
        Run = {
            if (-not (Get-SysmonState)) { Write-CaseLog "    Sysmon not present - skipping" 'DarkGray'; return }
            $start = Get-LogStart
            $ids = @(1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25, 26)
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids $ids -Start $start
            Save-Rows -Name 'sysmon_events' -Rows $ev
            $net = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3 }
                if ($start) { $filter.StartTime = $start }
                $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in $raw) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $net += [pscustomobject]@{
                        Time = $e.TimeCreated; Image = $d['Image']; DestIp = $d['DestinationIp']
                        DestPort = $d['DestinationPort']; Protocol = $d['Protocol']
                        ProcessGuid = $d['ProcessGuid']; ProcessId = $d['ProcessId']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_network' -Rows $net
            $dns = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 22 }
                if ($start) { $filter.StartTime = $start }
                $rawD = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in $rawD) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $dns += [pscustomobject]@{
                        Time = $e.TimeCreated; Image = $d['Image']; QueryName = $d['QueryName']
                        QueryResults = $d['QueryResults']; ProcessId = $d['ProcessId']; ProcessGuid = $d['ProcessGuid']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_dns' -Rows $dns
            # EID 7: image loads - the DLL side-load data source
            $img = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 7 }
                if ($start) { $filter.StartTime = $start }
                $rawI = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in ($rawI | Select-Object -First 3000)) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $img += [pscustomobject]@{
                        Time = $e.TimeCreated; Process = $d['Image']; Dll = $d['ImageLoaded']
                        Signed = $d['Signed']; Signature = $d['Signature']; Company = $d['Company']; Description = $d['Description']
                        ProcessId = $d['ProcessId']; ProcessGuid = $d['ProcessGuid']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_image_load' -Rows $img
            if ($img.Count -gt 0) { Write-CaseLog "    sysmon image loads: $($img.Count) (DLL side-load data source)" 'Gray' }
            # v2.20: EID 10 process access (LSASS-access data source), EID 13 registry (UAC-bypass/persistence), EID 2 file time (timestomping)
            $pa = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(10) -Start $start -Cap 3000 -Fields ([ordered]@{ SourceImage = 'SourceImage'; TargetImage = 'TargetImage'; GrantedAccess = 'GrantedAccess'; CallTrace = 'CallTrace' })
            Save-Rows -Name 'sysmon_process_access' -Rows $pa
            if ($pa.Count -ge 3000) { Write-CaseLog "    EID 10 process access: capped at 3000 - widen the Sysmon ProcessAccess filter" 'DarkGray' }
            $reg = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(13) -Start $start -Cap 5000 -Fields ([ordered]@{ EventType = 'EventType'; TargetObject = 'TargetObject'; Image = 'Image'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_registry' -Rows $reg
            $ft = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(2) -Start $start -Cap 1000 -Fields ([ordered]@{ Image = 'Image'; TargetFilename = 'TargetFilename'; CreationUtcTime = 'CreationUtcTime'; PreviousCreationUtcTime = 'PreviousCreationUtcTime'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_file_time' -Rows $ft
            if ($ft.Count -gt 0) { Write-CaseLog "    EID 2 file creation-time changes: $($ft.Count) (timestomping data source)" 'Yellow' }
            # v2.27: EID 1 process create - OriginalFileName vs Image feeds the renamed-LOLBIN at-rest rule
            $pc = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(1) -Start $start -Cap 5000 -Fields ([ordered]@{ Image = 'Image'; OriginalFileName = 'OriginalFileName'; CommandLine = 'CommandLine'; User = 'User'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'; ParentImage = 'ParentImage'; ParentProcessGuid = 'ParentProcessGuid' })
            Save-Rows -Name 'sysmon_proc_create' -Rows $pc
            # v2.43: EID 11 file create + EID 23/26 file delete (26 = FileDeleteDetected, the
            # no-archive variant hosts emit instead of 23) - the per-instance
            # "what files did this process drop / clean up" sources (ProcessGuid joins into Focus)
            $fc = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(11) -Start $start -Cap 5000 -Fields ([ordered]@{ Image = 'Image'; TargetFilename = 'TargetFilename'; CreationUtcTime = 'CreationUtcTime'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'; Hashes = 'Hashes' })
            Save-Rows -Name 'sysmon_file_create' -Rows $fc
            if ($fc.Count -ge 5000) { Write-CaseLog "    EID 11 file creates: capped at 5000 - busy box or noisy filter" 'DarkGray' }
            $fdel = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(23, 26) -Start $start -Cap 2000 -Fields ([ordered]@{ Image = 'Image'; TargetFilename = 'TargetFilename'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'; Hashes = 'Hashes'; Archived = 'Archived' })
            Save-Rows -Name 'sysmon_file_delete' -Rows $fdel
            if ($fdel.Count -gt 0) { Write-CaseLog "    EID 23/26 file deletions: $($fdel.Count) (anti-forensics / cleanup evidence)" 'Yellow' }
            # v2.48: EID 8 CreateRemoteThread - the cross-process injection edge (R28, Focus INJECT)
            $crt = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(8) -Start $start -Cap 2000 -Fields ([ordered]@{ SourceImage = 'SourceImage'; TargetImage = 'TargetImage'; SourceProcessGuid = 'SourceProcessGuid'; TargetProcessGuid = 'TargetProcessGuid'; NewThreadId = 'NewThreadId'; StartModule = 'StartModule'; StartFunction = 'StartFunction'; User = 'User' })
            Save-Rows -Name 'sysmon_remote_thread' -Rows $crt
            if ($crt.Count -gt 0) { Write-CaseLog "    EID 8 remote threads: $($crt.Count) (cross-process injection data source)" 'Yellow' }
            # v2.48: EID 17/18 named pipes created/connected - SMB-beacon C2 channel data (R29).
            # EventId (17=PipeCreated / 18=PipeConnected) comes from Get-EventDataRows itself.
            $pipe = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(17, 18) -Start $start -Cap 2000 -Fields ([ordered]@{ Image = 'Image'; PipeName = 'PipeName'; EventType = 'EventType'; User = 'User'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_pipes' -Rows $pipe
            if ($pipe.Count -gt 0) { Write-CaseLog "    EID 17/18 named pipes: $($pipe.Count)" 'Gray' }
            # v2.50: EID 25 ProcessTampering - Sysmon itself flags hollowing/herpaderp image swaps
            # (near-zero FP: no heuristics involved) -> R30, Focus TAMPER chip
            $tam = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(25) -Start $start -Cap 1000 -Fields ([ordered]@{ Image = 'Image'; Type = 'Type'; FileVersion = 'FileVersion'; Description = 'Description'; Product = 'Product'; User = 'User'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_proc_tamper' -Rows $tam
            if ($tam.Count -gt 0) { Write-CaseLog "    EID 25 process tampering: $($tam.Count) (image swap / hollowing detected by Sysmon)" 'Red' }
            # v2.50: EID 9 RawAccessRead - raw volume reads via \\.\ = credential theft from locked
            # hives / anti-forensics -> R31
            $raw = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(9) -Start $start -Cap 1000 -Fields ([ordered]@{ Image = 'Image'; Device = 'Device'; User = 'User'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_raw_access' -Rows $raw
            if ($raw.Count -gt 0) { Write-CaseLog "    EID 9 raw volume access: $($raw.Count) (direct \\.\ reads - credential-theft / anti-forensics lead)" 'Yellow' }
            # v2.50: EID 19/20/21 WMI filter/consumer/binding - permanent subscription persistence
            # (the classic APT mechanism) -> R32, per-instance persistence join
            $wmi = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(19, 20, 21) -Start $start -Cap 1000 -Fields ([ordered]@{ Image = 'Image'; Name = 'Name'; Query = 'Query'; Destination = 'Destination'; Consumer = 'Consumer'; Filter = 'Filter'; User = 'User'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid' })
            Save-Rows -Name 'sysmon_wmi' -Rows $wmi
            if ($wmi.Count -gt 0) { Write-CaseLog "    EID 19/20/21 WMI subscriptions: $($wmi.Count) (permanent event persistence)" 'Yellow' }
            Export-Evtx -LogName 'Microsoft-Windows-Sysmon/Operational' -FileName 'Sysmon_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '4.4'; Cat = 'LOGS'; Name = 'RDP logs (LocalSessionManager + ConnectionManager)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev1 = Get-FilteredEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids @(21, 22, 24, 25, 39, 40) -Start $start -MaxMsg 300
            Save-Rows -Name 'rdp_localsession' -Rows $ev1
            Export-Evtx -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -FileName 'RDP_LocalSessionManager.evtx'
            $ev2 = Get-FilteredEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Ids @(1149) -Start $start -MaxMsg 300
            Save-Rows -Name 'rdp_connections' -Rows $ev2
            Export-Evtx -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FileName 'RDP_ConnectionManager.evtx'
            # v2.30: RDP bitmap cache - screen fragments of what INBOUND RDP sessions displayed
            $rcSrc = Join-Path $env:LOCALAPPDATA 'Microsoft\Terminal Server Client\Cache'
            if (Test-Path $rcSrc) {
                $rcDst = Join-Path $RawDir 'rdp_cache'
                New-Item -ItemType Directory -Path $rcDst -Force | Out-Null
                $nBmc = 0
                foreach ($f in @(Get-ChildItem -LiteralPath $rcSrc -Filter '*.bmc' -File -ErrorAction SilentlyContinue)) {
                    try { Copy-Item -LiteralPath $f.FullName -Destination $rcDst -Force -ErrorAction Stop; $nBmc++ } catch { }
                }
                if ($nBmc -gt 0) { Write-CaseLog "    RDP bitmap cache: $nBmc file(s) -> raw\rdp_cache (screen fragments of inbound RDP sessions; view with RdpCacheStudio)" 'Gray' }
            }
        } }
    [pscustomobject]@{ Id = '4.5'; Cat = 'LOGS'; Name = 'System log (service installs 7045, changes 7040)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'System' -Ids @(7045, 7040, 104, 6005, 6006) -Start $start
            Save-Rows -Name 'system_events' -Rows $ev
            $svc = @($ev | Where-Object { $_.Id -eq 7045 } | ForEach-Object {
                $msg = "$($_.Message)"
                $name = if ($msg -match 'Service Name:\s+(.+)') { $Matches[1].Split("`n")[0].Trim() } else { '' }
                $file = if ($msg -match 'File Name:\s+(.+)') { $Matches[1].Split("`n")[0].Trim() } else { '' }
                [pscustomobject]@{ Time = $_.TimeCreated; Service = $name; Binary = $file; Type = 'NewService' }
            })
            Save-Rows -Name 'system_new_services' -Rows $svc
        } }
    [pscustomobject]@{ Id = '4.6'; Cat = 'LOGS'; Name = 'Detection pack: hayabusa Sigma timeline + logon summary (needs tools\hayabusa)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $h = $null
            if ($tDir) { $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1 }
            if (-not $h) { Write-CaseLog "    hayabusa not in tools\ - skipping (or run: -Mode Setup / -Mode Links)" 'DarkGray'; return }
            $evtxDir = Join-Path $RawDir 'evtx'
            if (-not (Test-Path $evtxDir)) { Write-CaseLog "    no evtx exported - skipping" 'DarkGray'; return }
            $out = Get-CaseCsvFullPath 'hayabusa_timeline'
            $html = Get-CaseCsvFullPath 'hayabusa_report'
            $hayArgs = @('dfir-timeline', '-p', 'verbose', '-d', "$evtxDir", '-o', "$out", '-H', "$html", '-q', '-w', '-U', '-C', '-K', '-m', 'low', '-E')
            $huntNote = 'full range'
            if ($script:LogStartDT) {
                $hayArgs += @('--start-timeline', $script:LogStartDT.ToString('yyyy-MM-dd HH:mm:ss'))
                if ($script:LogEndDT) { $hayArgs += @('--end-timeline', $script:LogEndDT.ToString('yyyy-MM-dd HH:mm:ss')) }
                $huntNote = "from $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm'))$(if ($script:LogEndDT) { " to $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm'))" })"
                # v2.64: worker-seeded script var - an unscoped read here is only
                # value-correct via inline dynamic scoping, not by construction
            } elseif ($script:LogHours -gt 0) { $hayArgs += @('--time-offset', "$($script:LogHours)h"); $huntNote = "last $($script:LogHours)h" }
            Write-CaseLog "    hayabusa dfir-timeline Sigma hunt ($huntNote)..." 'Cyan'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs $hayArgs -WorkingDirectory $h.DirectoryName
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    hayabusa: $n timeline rows (level>=low) in csv\hayabusa_timeline.csv" $(if ($n -gt 0) { 'Yellow' } else { 'Gray' })
            } else { Write-CaseLog "    hayabusa timeline produced no output" 'DarkYellow' }
            Write-CaseLog "    hayabusa logon-summary..." 'Cyan'
            $lsPrefix = (Get-CaseCsvFullPath 'logon_summary') -replace '\.csv$', ''
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs @('logon-summary', '-d', "$evtxDir", '-o', "$lsPrefix", '-q', '-C', '-K') -WorkingDirectory $h.DirectoryName
            $ps64 = Get-CaseCsvFullPath 'ps_decoded_commands'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs @('extract-base64', '-d', "$evtxDir", '-o', "$ps64", '-q', '-C', '-K', '-U') -WorkingDirectory $h.DirectoryName
            if (Test-Path $ps64) {
                $n64 = @(Get-Content -LiteralPath $ps64 | Select-Object -Skip 1).Count
                if ($n64 -gt 0) { Write-CaseLog "    extract-base64: $n64 encoded/obfuscated command(s) recovered -> csv\ps_decoded_commands.csv" 'Yellow' }
                else { Remove-Item -LiteralPath $ps64 -Force -ErrorAction SilentlyContinue }
            }
        } }
    [pscustomobject]@{ Id = '4.7'; Cat = 'LOGS'; Name = 'YARA scan of flagged/user-path binaries (needs tools\yara)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $yr = $null
            if ($tDir) { $yr = Get-ChildItem -Path $tDir -Recurse -Filter 'yr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if (-not $yr) { Write-CaseLog "    yr.exe not in tools\ - skipping (run Setup, tool 'yara')" 'DarkGray'; return }
            $rulesDir = Join-Path $yr.DirectoryName 'rules'
            if (-not (Test-Path -LiteralPath $rulesDir)) { Write-CaseLog "    no rules\ folder next to yr.exe - skipping" 'DarkGray'; return }
            $ruleFiles = @(Get-ChildItem -LiteralPath $rulesDir -Recurse -File -Include '*.yar', '*.yara' -ErrorAction SilentlyContinue)
            if ($ruleFiles.Count -eq 0) { Write-CaseLog "    rules\ contains no .yar files - skipping" 'DarkGray'; return }

            $seen = @{}
            $targets = New-Object System.Collections.Generic.List[string]
            foreach ($src in @('flash_process_scored', 'processes_flagged', 'services_flagged', 'scheduled_tasks_flagged', 'autoruns_runkeys', 'autoruns_startup_folders', 'drivers_flagged', 'amcache')) {
                $f = Get-CaseCsvFullPath $src
                if (-not (Test-Path -LiteralPath $f)) { continue }
                try { $rows = @(Import-Csv -LiteralPath $f -ErrorAction Stop) } catch { continue }
                foreach ($r in $rows) {
                    $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
                    foreach ($mm in [regex]::Matches($line, '(?i)(?:[a-z]:\\|\\\\)[^\s'',\|]+\.(?:exe|dll|scr|com|ps1|bat|cmd|vbs|js|hta|jar)')) {
                        $p2 = $mm.Value
                        if (-not $seen.ContainsKey($p2.ToLower())) {
                            $seen[$p2.ToLower()] = $true
                            if (Test-Path -LiteralPath $p2 -PathType Leaf) { $targets.Add($p2) }
                        }
                    }
                }
            }
            $maxScan = 200
            if ($targets.Count -eq 0) { Write-CaseLog "    no on-disk candidate files found - nothing to scan" 'Gray'; Save-Rows -Name 'yara_hits' -Rows @(); Save-Rows -Name 'yara_scanned' -Rows @(); return }
            $scanList = @($targets | Select-Object -First $maxScan)
            Write-CaseLog "    yara: scanning $($scanList.Count) candidate file(s) with $($ruleFiles.Count) rule file(s)..." 'Cyan'
            if ($targets.Count -gt $maxScan) { Write-CaseLog "    (capped at $maxScan of $($targets.Count) candidates)" 'DarkYellow' }

            $hits = New-Object System.Collections.Generic.List[object]
            $scanned = New-Object System.Collections.Generic.List[object]
            $failed = 0
            foreach ($f2 in $scanList) {
                $res = Invoke-NativeTool -ExePath $yr.FullName -ToolArgs @('scan', '-m', '--output-format=ndjson', $rulesDir, $f2) -WorkingDirectory $yr.DirectoryName -QuietLog -CaptureOut
                if ($res -isnot [pscustomobject] -or $res.ExitCode -ne 0) {
                    $failed++
                    if ($failed -eq 1 -and $res -is [pscustomobject] -and $res.StdErr) { Write-CaseLog "    yr.exe error: $(($res.StdErr -split '\r?\n' | Where-Object { $_ } | Select-Object -First 1))" 'DarkYellow' }
                    continue
                }
                $hitRules = @()
                if ($res.StdOut) {
                    foreach ($ln in ($res.StdOut -split "`r?`n" | Where-Object { $_ -match '^\s*\{' })) {
                        try { $j = $ln | ConvertFrom-Json } catch { continue }
                        if (@($j.rules).Count -gt 0) {
                            foreach ($ru in @($j.rules)) {
                                $meta = @{}
                                if ($ru.meta) { foreach ($kv in @($ru.meta)) { $meta["$($kv[0])"] = "$($kv[1])" } }
                                $sev = if ($meta['severity']) { $meta['severity'] } else { 'unknown' }
                                $hits.Add([pscustomobject]@{
                                    Severity = $sev
                                    Rule = "$($ru.identifier)"
                                    Description = "$($meta['description'])"
                                    File = $f2
                                })
                                $hitRules += "$($ru.identifier)"
                            }
                        }
                    }
                }
                $sha = ''
                try { $fi = Get-Item -LiteralPath $f2 -ErrorAction Stop; if ($fi.Length -lt 200MB) { $sha = (Get-FileHash -LiteralPath $f2 -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } } catch { }
                $scanned.Add([pscustomobject]@{ File = $f2; SHA256 = $sha; Hits = $hitRules.Count; Rules = ($hitRules -join ';') })
            }
            Save-Rows -Name 'yara_hits' -Rows $hits.ToArray()
            Save-Rows -Name 'yara_scanned' -Rows $scanned.ToArray()
            $hitArr = $hits.ToArray()
            $hi = @($hitArr | Where-Object { "$($_.Severity)" -match '^(high|critical)$' }).Count
            if ($hitArr.Count -gt 0) {
                Write-CaseLog "    YARA: $($hitArr.Count) hit(s) on $($scanned.Count) scanned file(s) ($hi high/crit) - csv\yara_hits.csv" $(if ($hi -gt 0) { 'Red' } else { 'Yellow' })
                foreach ($h2 in ($hitArr | Select-Object -First 10)) {
                    Write-CaseLog ("      [{0}] {1}  {2}" -f $h2.Severity, $h2.Rule, $h2.File) $(if ("$($h2.Severity)" -match '^(high|critical)$') { 'Red' } else { 'Yellow' })
                }
            } else {
                Write-CaseLog "    yara: no hits on $($scanned.Count) scanned file(s)$(if ($failed) { " ($failed scan failures)" } else { '' })" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.8'; Cat = 'LOGS'; Name = 'C2 beaconing analysis (needs Sysmon network events)'; Default = $true; Quick = $false;
        Run = {
            $f = Join-Path $CsvDir 'sysmon_network.csv'
            if (-not (Test-Path -LiteralPath $f)) { $f = Get-CaseCsvFullPath 'sysmon_network' }
            $fd = Join-Path $CsvDir 'sysmon_dns.csv'
            if (-not (Test-Path -LiteralPath $fd)) { $fd = Get-CaseCsvFullPath 'sysmon_dns' }
            if (-not (Test-Path -LiteralPath $f) -and -not (Test-Path -LiteralPath $fd)) { Write-CaseLog "    no sysmon_network.csv / sysmon_dns.csv (no Sysmon / module 4.3 skipped) - beaconing not analyzable" 'DarkGray'; return }
            $all = @()
            try {
                foreach ($r in @(Import-Csv -LiteralPath $f -ErrorAction Stop)) {
                    $t = $null
                    try { $t = [datetime]"$($r.Time)" } catch { }
                    if ($t) { $all += [pscustomobject]@{ T = $t; Kind = 'net'; Key = "net|$($r.Image)|$($r.DestIp)|$($r.DestPort)"; Image = "$($r.Image)"; Ip = "$($r.DestIp)"; Port = "$($r.DestPort)"; Domain = '' } }
                }
            } catch { }
            try {
                foreach ($r in @(Import-Csv -LiteralPath $fd -ErrorAction Stop)) {
                    $t = $null
                    try { $t = [datetime]"$($r.Time)" } catch { }
                    if ($t) {
                        $dom = ("$($r.QueryName)" -replace '\.$', '').ToLower()
                        $rip = ''
                        foreach ($m in [regex]::Matches("$($r.QueryResults)", '\b\d{1,3}(\.\d{1,3}){3}\b')) { if (Test-IsPublicIp $m.Value) { $rip = $m.Value; break } }
                        $all += [pscustomobject]@{ T = $t; Kind = 'dns'; Key = "dns|$($r.Image)|$dom"; Image = "$($r.Image)"; Ip = $rip; Port = ''; Domain = $dom }
                    }
                }
            } catch { }
            if ($all.Count -lt 15) { Write-CaseLog "    too few Sysmon network/DNS events ($($all.Count)) for beaconing analysis" 'Gray'; Save-Rows -Name 'beacon_candidates' -Rows @(); Save-Rows -Name 'dns_beacon_candidates' -Rows @(); return }
            $flagged = @{}
            $fps = Join-Path $CsvDir 'flash_process_scored.csv'
            if (-not (Test-Path -LiteralPath $fps)) { $fps = Get-CaseCsvFullPath 'flash_process_scored' }
            if (Test-Path -LiteralPath $fps) {
                try { foreach ($fr in @(Import-Csv -LiteralPath $fps)) { if ("$($fr.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($fr.Path)") { $flagged["$($fr.Path)".ToLower()] = $true } } } catch { }
            }
            $out = @()
            $outDns = @()
            foreach ($g in ($all | Group-Object Key)) {
                if ($g.Count -lt 15) { continue }
                $ev = @($g.Group | Sort-Object T)
                $span = ($ev[-1].T - $ev[0].T).TotalMinutes
                if ($span -lt 15) { continue }
                $deltas = @()
                for ($i = 1; $i -lt $ev.Count; $i++) {
                    $d = ($ev[$i].T - $ev[$i - 1].T).TotalSeconds
                    if ($d -gt 0 -and $d -le 3600) { $deltas += $d }
                }
                if ($deltas.Count -lt 10) { continue }
                $sortedD = @($deltas | Sort-Object)
                $median = $sortedD[[int][math]::Floor($sortedD.Count / 2)]
                $mean = ($deltas | Measure-Object -Average).Average
                $variance = (($deltas | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum) / $deltas.Count
                $jitter = if ($mean -gt 0) { [math]::Round([math]::Sqrt($variance) / $mean, 2) } else { 9.99 }
                $inBand = @($deltas | Where-Object { $_ -ge ($median * 0.5) -and $_ -le ($median * 1.5) }).Count
                $reg = [math]::Round($inBand / $deltas.Count, 2)
                if ($reg -lt 0.6) { continue }
                $img = "$($ev[0].Image)"; $ip = "$($ev[0].Ip)"
                $isPub = Test-IsPublicIp $ip
                $flags = @()
                if ($isPub) { $flags += 'public-ip' }
                if (Test-IsUserWritablePath $img) { $flags += 'user-path' }
                if ($flagged.ContainsKey($img.ToLower())) { $flags += 'flagged-process' }
                $sev = 'low'; $rk = 1
                if ($reg -ge 0.7 -and ($isPub -or ($flags -contains 'user-path'))) { $sev = 'medium'; $rk = 2 }
                if ($reg -ge 0.85 -and $g.Count -ge 30 -and $isPub) { $sev = 'high'; $rk = 3 }
                if ($ev[0].Kind -eq 'dns') {
                    $outDns += [pscustomobject]@{
                        Severity = $sev; Rank = $rk; Process = $img; Domain = $ev[0].Domain; ResolvedIp = $ip
                        Events = $g.Count; SpanMin = [math]::Round($span, 0); MedianIntervalSec = [math]::Round($median, 0)
                        Jitter = $jitter; Regularity = $reg; Flags = ($flags -join ';')
                    }
                } else {
                    $out += [pscustomobject]@{
                        Severity = $sev; Rank = $rk; Process = $img; RemoteIp = $ip; Port = "$($ev[0].Port)"
                        Events = $g.Count; SpanMin = [math]::Round($span, 0); MedianIntervalSec = [math]::Round($median, 0)
                        Jitter = $jitter; Regularity = $reg; Flags = ($flags -join ';')
                    }
                }
            }
            $out2 = @($out | Sort-Object Rank, Regularity -Descending)
            Save-Rows -Name 'beacon_candidates' -Rows $out2
            $outD2 = @($outDns | Sort-Object Rank, Regularity -Descending)
            Save-Rows -Name 'dns_beacon_candidates' -Rows $outD2
            $bh = @($out2 | Where-Object { "$($_.Severity)" -eq 'high' }).Count
            $bm = @($out2 | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
            $dh = @($outD2 | Where-Object { "$($_.Severity)" -eq 'high' }).Count
            $dm = @($outD2 | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
            if ($out2.Count -gt 0 -or $outD2.Count -gt 0) {
                Write-CaseLog "    beaconing: $($out2.Count) connection pattern(s) ($bh high, $bm medium), $($outD2.Count) DNS pattern(s) ($dh high, $dm medium)" $(if ($bh + $dh -gt 0) { 'Red' } else { 'Yellow' })
                foreach ($b in ($out2 | Select-Object -First 4)) {
                    Write-CaseLog ("      [{0}] {1} -> {2}:{3} every ~{4}s x{5} (reg {6}, jitter {7}) {8}" -f $b.Severity, (Split-Path $b.Process -Leaf), $b.RemoteIp, $b.Port, $b.MedianIntervalSec, $b.Events, $b.Regularity, $b.Jitter, $b.Flags) $(if ("$($b.Severity)" -eq 'high') { 'Red' } else { 'Yellow' })
                }
                foreach ($b in ($outD2 | Select-Object -First 4)) {
                    Write-CaseLog ("      [{0}] {1} -> DNS {2} every ~{3}s x{4} (reg {5}) {6}" -f $b.Severity, (Split-Path $b.Process -Leaf), $b.Domain, $b.MedianIntervalSec, $b.Events, $b.Regularity, $b.Flags) $(if ("$($b.Severity)" -eq 'high') { 'Red' } else { 'Yellow' })
                }
            } else {
                Write-CaseLog "    beaconing: no periodic outbound patterns detected in Sysmon network/DNS events" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.9'; Cat = 'LOGS'; Name = 'Kerberos + directory events (DC: 4768/4769/4771/4776, 4662 DCSync, 5136 changes)'; Default = $false; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ker = @()
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4768) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'TargetUserName'; Service = 'ServiceName'; IpAddress = 'IpAddress'; PreAuth = 'PreAuthType'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4769) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'TargetUserName'; Service = 'ServiceName'; IpAddress = 'IpAddress'; TicketEnc = 'TicketEncryptionType'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4771) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; IpAddress = 'IpAddress'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4776) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; Workstation = 'WorkstationName' })
            Save-Rows -Name 'security_kerberos' -Rows $ker
            $ds = @()
            $ds += Get-EventDataRows -LogName 'Security' -Id @(4662) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'SubjectUserName'; Object = 'ObjectName'; OpType = 'OperationType'; Properties = 'Properties' })
            $ds += Get-EventDataRows -LogName 'Security' -Id @(5136) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'SubjectUserName'; ObjectDN = 'ObjectDN'; OpType = 'OperationType'; Attribute = 'AttributeLDAPDisplayName'; Value = 'AttributeValue' })
            Save-Rows -Name 'security_ds_access' -Rows $ds
            if ($ker.Count -eq 0 -and $ds.Count -eq 0) {
                Write-CaseLog "    no Kerberos/DS events - not a DC, or 'Audit Directory Service Access' audit policy off" 'DarkGray'
            } else {
                Write-CaseLog "    Kerberos events: $($ker.Count), directory-service events: $($ds.Count)" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.10'; Cat = 'LOGS'; Name = 'Application log (crashes 1000/1001/1002, MSI installs 1033/11707/11724) + evtx export'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Application' -Ids @(1000, 1001, 1002, 1004, 1033, 11707, 11724) -Start $start -MaxMsg 300
            Save-Rows -Name 'application_events' -Rows $ev
            if ($ev.Count -gt 0) {
                Write-CaseLog "    application events: $($ev.Count) (crashes/installs - crashed attacker tools show up here) -> csv\application_events.csv" 'Gray'
            }
            # v2.83 (R46): ESENT 325/326 mentioning ntds.dit - the AD database was opened
            Save-Rows -Name 'esent_ntds' -Rows (Get-EsentNtdsRows $start)
            Export-Evtx -LogName 'Application' -FileName 'Application.evtx'
        } }
    [pscustomobject]@{ Id = '5.1'; Cat = 'ARTIFACTS'; Name = 'Prefetch files'; Default = $true; Quick = $false;
        Run = {
            $pf = Join-Path $env:SystemRoot 'Prefetch'
            if (-not (Test-Path $pf)) { Write-CaseLog "    Prefetch directory absent (disabled?)" 'DarkGray'; return }
            $files = @(Get-ChildItem -Path $pf -Filter '*.pf' -ErrorAction SilentlyContinue)
            $dest = Join-Path $RawDir 'prefetch'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $copied = 0
            foreach ($f in $files) {
                try { Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop; $copied++ } catch { }
            }
            Save-Rows -Name 'prefetch_index' -Rows ($files | Select-Object Name, Length, CreationTime, LastWriteTime)
            Write-CaseLog "    Copied $copied of $($files.Count) prefetch files" 'Gray'
            $tDir = Get-ToolsDir
            $peExe = $null
            if ($tDir) { $peExe = Get-ChildItem -Path $tDir -Recurse -Filter 'PECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if ($peExe -and $copied -gt 0) {
                Write-CaseLog "    PECmd: parsing prefetch (run counts + times)..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $peExe.FullName -ToolArgs @('-d', $dest, '--csv', $CsvDir, '--csvf', 'prefetch_parsed.csv')
                $pp = Join-Path $CsvDir 'prefetch_parsed.csv'
                if (-not (Test-Path -LiteralPath $pp)) { $pp = Get-CaseCsvFullPath 'prefetch_parsed' }
                if (Test-Path -LiteralPath $pp) {
                    $n = @(Get-Content -LiteralPath $pp | Select-Object -Skip 1).Count
                    Write-CaseLog "    prefetch parsed: $n entries -> csv\prefetch_parsed.csv" 'Gray'
                } else { Write-CaseLog "    PECmd produced no output" 'DarkYellow' }
            }
        } }
    [pscustomobject]@{ Id = '5.2'; Cat = 'ARTIFACTS'; Name = 'Registry hives (SYSTEM/SOFTWARE/SAM/SECURITY/Amcache) + UserAssist'; Default = $true; Quick = $false;
        Run = {
            $dest = Join-Path $RawDir 'registry'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            foreach ($hive in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) {
                $out = Join-Path $dest "$hive.hiv"
                & reg.exe save "HKLM\$hive" "$out" /y 2>&1 | Out-Null
                $saved = Test-Path $out
                if ($saved) { $saved = ((Get-Item $out -ErrorAction SilentlyContinue).Length -gt 0) }
                if ($LASTEXITCODE -ne 0 -or -not $saved) {
                    if (Test-Path $out) { Remove-Item $out -Force -ErrorAction SilentlyContinue }
                    Write-CaseLog "    reg save $hive failed (admin needed)" 'DarkYellow'
                }
            }
            $amc = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
            if (Test-Path $amc) {
                $out = Join-Path $dest 'Amcache.hve'
                try { Copy-Item -LiteralPath $amc -Destination $out -Force -ErrorAction Stop }
                catch { & esentutl.exe /y "$amc" /d "$out" 2>&1 | Out-Null }
            }
            Save-Rows -Name 'userassist' -Rows (Get-UserAssistRows)
            # v2.83 (R47/R48): RADAR heap-leak execution evidence + AppSwitched counters
            Save-Rows -Name 'radar_exec' -Rows (Get-RadarRows)
            Save-Rows -Name 'appswitched' -Rows (Get-AppSwitchedRows)
        } }
    [pscustomobject]@{ Id = '5.3'; Cat = 'ARTIFACTS'; Name = 'SRUM database (larger, uses VSS copy)'; Default = $true; Quick = $false;
        Run = {
            $sru = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
            if (-not (Test-Path $sru)) { return }
            $dest = Join-Path $RawDir 'sru'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $out = Join-Path $dest 'SRUDB.dat'
            $null = Copy-LockedFile -Source $sru -Dest $out
        } }
    [pscustomobject]@{ Id = '5.4'; Cat = 'ARTIFACTS'; Name = 'Execution history (chainsaw: shimcache+amcache timeline, evtx gaps)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $cs = $null
            if ($tDir) { $cs = Get-ChildItem -Path $tDir -Recurse -Filter 'chainsaw*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if (-not $cs) { Write-CaseLog "    chainsaw not in tools\ - skipping (or run: -Mode Setup / -Mode Links)" 'DarkGray'; return }
            $regDir = Join-Path $RawDir 'registry'
            $sys = Join-Path $regDir 'SYSTEM.hiv'
            $amc = Join-Path $regDir 'Amcache.hve'
            $sft = Join-Path $regDir 'SOFTWARE.hiv'
            if (-not (Test-Path $sys)) { Write-CaseLog "    registry hives not saved (enable module 5.2) - skipping" 'DarkGray'; return }
            $out = Get-CaseCsvFullPath 'execution_timeline'
            $amArgs = @()
            if (Test-Path $amc) { $amArgs = @('-a', $amc) }
            Write-CaseLog "    chainsaw: shimcache/amcache execution timeline..." 'Cyan'
            # v2.53: chainsaw requires -r with insertion-time patterns (known-good installers whose
            # timestamps legitimately match insertion) - without it the analysis warns and emits nothing
            $scPat = Join-Path $cs.DirectoryName 'shimcache_patterns.txt'
            $patArgs = @()
            if (Test-Path -LiteralPath $scPat) { $patArgs = @('-r', $scPat) }
            $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs (@('analyse', 'shimcache', $sys) + $amArgs + $patArgs + @('-o', $out))
            if (-not (Test-Path $out) -and $amArgs.Count -gt 0) {
                # chainsaw aborts the amcache-enriched run when the Amcache hive has entries it
                # cannot resolve (observed on real hives) - retry shimcache-only, same coverage
                Write-CaseLog "    chainsaw: amcache enrichment aborted (unresolvable amcache entry) - retrying shimcache-only" 'DarkYellow'
                $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs (@('analyse', 'shimcache', $sys) + $patArgs + @('-o', $out))
            }
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    execution timeline: $n entries in csv\execution_timeline.csv" 'Gray'
            } else { Write-CaseLog "    chainsaw shimcache analysis failed" 'DarkYellow' }
            # v2.59: SRUM parsing moved analyst-side (module 5.3 saves raw\sru\SRUDB.dat; SrumECmd in
            # -Mode Parse produces the deep usage + network-connection tables - chainsaw's shallower
            # pass never ran in practice and would have split the schema story for one artifact)
            $evtxDir = Join-Path $RawDir 'evtx'
            if (Test-Path $evtxDir) {
                $anDir = Join-Path $RawDir 'analysis'
                if (-not (Test-Path $anDir)) { New-Item -ItemType Directory -Path $anDir -Force | Out-Null }
                Write-CaseLog "    chainsaw: evtx gap detection (tamper check)..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs @('analyse', 'gaps', $evtxDir, '-q', '-o', (Join-Path $anDir 'evtx_gaps.txt'))
            }
        } }
    [pscustomobject]@{ Id = '5.5'; Cat = 'ARTIFACTS'; Name = 'NTFS forensics: MFT recent-file inventory + USN write bursts (needs tools\MFTECmd + admin)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $mftExe = Get-ChildItem -Path $tDir -Recurse -Filter 'MFTECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $mftExe) { Write-CaseLog "    MFTECmd not in tools\ - skipping (run Setup)" 'DarkGray'; return }
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_ntfs_" + (Get-Date -Format 'HHmmss'))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            try {
                $exeExt = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jar', '.hta', '.scr', '.msi', '.py', '.wsf', '.lnk')
                # v2.60: the recency window follows the case's log window ($script:LogHours is
                # seeded into workers) but never shrinks below the 30-day default
                $mftDays = 30
                try { $lh = if ($script:LogHours -gt 0) { $script:LogHours } elseif ($LogHours -gt 0) { $LogHours } else { 0 }; if ($lh -gt 0) { $mftDays = [Math]::Max(30, [int][double]($lh / 24)) } } catch { }
                $cutoff = (Get-Date).AddDays(-$mftDays)
                $ransomExt = @('.locked', '.locky', '.crypt', '.crypto', '.enc', '.encrypted', '.enc1', '.cry', '.cerber', '.wallet', '.onion', '.aes', '.rsa', '.mallox', '.pha', '.devos', '.mkp', '.faust', '.elh', '.ransom', '.payform', '.locked1')
                $keepFull = {
                    # Full preset only: preserve the unfiltered parser output for analyst-side work (skips when disk is tight).
                    param($srcCsv, $outName)
                    $root = [IO.Path]::GetPathRoot($CaseDir).TrimEnd('\')
                    $free = 0
                    try { $free = (Get-PSDrive -Name ($root.TrimEnd(':')) -ErrorAction Stop).Free } catch { }
                    if ($free -lt 10GB) { Write-CaseLog "    Full preset: under 10GB free on $root - skipping full NTFS preservation" 'DarkYellow'; return }
                    $an = Join-Path $RawDir 'analysis'
                    if (-not (Test-Path $an)) { New-Item -ItemType Directory -Path $an -Force | Out-Null }
                    Copy-Item -LiteralPath $srcCsv -Destination (Join-Path $an $outName) -Force
                    Write-CaseLog "    Full preset: preserved $outName -> raw\analysis\ (full $([math]::Round((Get-Item -LiteralPath $srcCsv).Length / 1MB, 1)) MB)" 'Gray'
                }
                $keep = New-Object System.Collections.Generic.List[object]
                $mftTotal = 0
                $bursts = @()
                $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Free -ne $null })
                foreach ($d in $drives) {
                    $dl = "$($d.Name):"
                    $isNtfs = $true
                    try { $v = Get-Volume -DriveLetter $d.Name -ErrorAction Stop; if ("$($v.FileSystem)" -and "$($v.FileSystem)" -ne 'NTFS') { $isNtfs = $false } } catch { }
                    if (-not $isNtfs) { Write-CaseLog "    drive $dl not NTFS - skipped" 'DarkGray'; continue }
                    $dlLower = $d.Name.ToLower()

                    # ---- $MFT per drive: keep only executable-ish files in user paths or created recently ----
                    Write-CaseLog "    MFTECmd: parsing live `$MFT on $dl..." 'Cyan'
                    $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$($d.Root)`$MFT", '--csv', $tmp, '--csvf', "mft_full.csv")
                    $mftFull = Join-Path $tmp 'mft_full.csv'
                    if (Test-Path -LiteralPath $mftFull) {
                        $hdr = @((Get-Content -LiteralPath $mftFull -First 1) -split ',' | ForEach-Object { $_.Trim(' "') })
                        $colOf = {
                            param([string]$pattern)
                            @($hdr | Where-Object { $_ -match $pattern } | Select-Object -First 1)[0]
                        }
                        $cName = & $colOf '^FileName$'; $cParent = & $colOf 'ParentPath'; $cExt = & $colOf '^Extension$'
                        $cCreated = & $colOf 'Created'; $cMod = & $colOf 'LastModified'; $cSize = & $colOf 'FileSize'; $cEntry = & $colOf 'EntryNumber'
                        $cCreated30 = & $colOf 'Created0x30'
                        Import-Csv -LiteralPath $mftFull | ForEach-Object {
                            $mftTotal++
                            $name = "$($_.$cName)"
                            if (-not $name) { return }
                            $ext = ("$($_.$cExt)").ToLower()
                            if ($exeExt -notcontains $ext) { return }
                            $parent = "$($_.$cParent)"
                            $path = if ($parent) { "$(Join-Path $dl ($parent -replace '^\.\\?', ''))\$name" } else { "$dl\$name" }
                            $userPath = Test-IsUserWritablePath $path
                            $created = $null; try { $created = [datetime]"$($_.$cCreated)" } catch { }
                            $recent = ($created -and $created -ge $cutoff)
                            if (-not ($userPath -or $recent)) { return }
                            $flags = @('exec'); if ($userPath) { $flags += 'user-path' }; if ($recent) { $flags += 'recent' }
                            $keep.Add([pscustomobject]@{ Drive = $dl; Entry = "$($_.$cEntry)"; Created = "$($_.$cCreated)"; CreatedFN = $(if ($cCreated30) { "$($_.$cCreated30)" } else { '' }); LastModified = "$($_.$cMod)"; Size = "$($_.$cSize)"; Name = $name; Path = $path; Flags = ($flags -join ';') })
                        }
                        if ("$Preset" -eq 'Full') { & $keepFull $mftFull "mft_full_$($d.Name).csv" }
                        Remove-Item -LiteralPath $mftFull -Force -ErrorAction SilentlyContinue
                    } else { Write-CaseLog "    MFT parse on $dl produced no output (not elevated?)" 'DarkYellow' }

                    # ---- USN journal per drive: per-minute write bursts + ransomware-extension check ----
                    Write-CaseLog "    MFTECmd: reading live USN journal on $dl..." 'Cyan'
                    $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$($d.Root)`$Extend\`$J", '--csv', $tmp, '--csvf', 'usn_full.csv')
                    $usnFull = Join-Path $tmp 'usn_full.csv'
                    if (Test-Path -LiteralPath $usnFull) {
                        $uHdr = @((Get-Content -LiteralPath $usnFull -First 1) -split ',' | ForEach-Object { $_.Trim(' "') })
                        $uCol = {
                            param([string]$pattern)
                            @($uHdr | Where-Object { $_ -match $pattern } | Select-Object -First 1)[0]
                        }
                        $tCol = & $uCol 'time'; $rCol = & $uCol 'reason'; $nCol = & $uCol 'sourcefile|^file'
                        if ($tCol -and $rCol) {
                            # ponytail: >=1000 write-reason events/min across >=100 distinct files = burst window (heuristic; big installs/updates can trigger too)
                            $min = @{}
                            Import-Csv -LiteralPath $usnFull | ForEach-Object {
                                $reason = "$($_.$rCol)"
                                $isWrite = ($reason -match 'DataExtend|Truncate|BasicInfoChange')
                                $isNew = ($reason -match 'FileCreate|RenameNewName')
                                if (-not $isWrite -and -not $isNew) { return }
                                $t = $null; try { $t = [datetime]"$($_.$tCol)" } catch { }
                                if (-not $t) { return }
                                $k = $t.ToString('yyyy-MM-dd HH:mm')
                                if (-not $min.ContainsKey($k)) { $min[$k] = @{ Events = 0; Files = @{}; Ext = @{} } }
                                if ($isWrite) { $min[$k].Events++ }
                                if ($nCol) {
                                    $f = "$($_.$nCol)"
                                    if ($f) {
                                        if (-not $min[$k].Files.ContainsKey($f)) { $min[$k].Files[$f] = $true }
                                        if ($isNew) {
                                            $fe = [IO.Path]::GetExtension($f).ToLower()
                                            if ($fe -and $ransomExt -contains $fe) { $min[$k].Ext[$fe] = $true }
                                        }
                                    }
                                }
                            }
                            foreach ($k in @($min.Keys | Sort-Object)) {
                                if ($min[$k].Events -ge 1000 -and $min[$k].Files.Count -ge 100) {
                                    $bursts += [pscustomobject]@{ WindowStart = $k; Drive = $dl; WriteEvents = $min[$k].Events; DistinctFiles = $min[$k].Files.Count; RansomExt = (($min[$k].Ext.Keys | Sort-Object) -join ';') }
                                }
                            }
                        }
                        if ("$Preset" -eq 'Full') { & $keepFull $usnFull "usn_full_$($d.Name).csv" }
                        Remove-Item -LiteralPath $usnFull -Force -ErrorAction SilentlyContinue
                    }
                }
                $out5 = $keep.ToArray()
                if ($out5.Count -gt 5000) { $out5 = $out5[0..4999] }
                Save-Rows -Name 'mft_recent' -Rows $out5
                Write-CaseLog "    MFT: $mftTotal entries scanned across $($drives.Count) drive(s), $($keep.Count) executable/user-path/recent kept -> csv\mft_recent.csv" 'Gray'
                # v2.62: alternate data streams on executables that still exist on disk
                # (mft_recent is the birth inventory - only on-disk files can be stream-scanned)
                $adsRows = @(Find-AdsOnPe -Paths @($keep | ForEach-Object { "$($_.Path)" }))
                Save-Rows -Name 'ads_findings' -Rows $adsRows
                if ($adsRows.Count -gt 0) {
                    Write-CaseLog "    ADS: $($adsRows.Count) non-Zone.Identifier stream(s) on executables - POSSIBLE PAYLOAD STASH -> csv\ads_findings.csv" 'Yellow'
                    foreach ($a in ($adsRows | Select-Object -First 4)) { Write-CaseLog "      $($a.Path) :: $($a.Stream) ($($a.Length) bytes)" 'Yellow' }
                } else { Write-CaseLog "    ADS: no non-Zone.Identifier streams on checked executables" 'Gray' }
                Save-Rows -Name 'usn_write_bursts' -Rows $bursts
                if (@($bursts).Count -gt 0) {
                    Write-CaseLog "    USN: $(@($bursts).Count) mass-modification window(s) >=1000 writes/min - POSSIBLE RANSOMWARE -> csv\artifacts\usn_write_bursts.csv" 'Red'
                    foreach ($b in @($bursts | Select-Object -First 5)) { Write-CaseLog "      $($b.WindowStart) [$($b.Drive)]: $($b.WriteEvents) writes over $($b.DistinctFiles) files$(if ("$($b.RansomExt)") { " RANSOM-EXT: $($b.RansomExt)" })" 'Red' }
                } else { Write-CaseLog "    USN journal analyzed - no mass-modification windows" 'Gray' }
            } finally {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        } }
    [pscustomobject]@{ Id = '6.1'; Cat = 'DEFENDER'; Name = 'Defender detections, exclusions, status'; Default = $true; Quick = $true;
        Run = {
            $status = @(); $threats = @(); $prefs = @()
            try {
                if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                    $s = Get-MpComputerStatus -ErrorAction Stop
                    $status += [pscustomobject]@{
                        AMServiceEnabled = $s.AMServiceEnabled; AntispywareEnabled = $s.AntispywareEnabled
                        RealTimeProtection = $s.RealTimeProtectionEnabled; IOfficeAntiVirus = $s.IoavProtectionEnabled
                        AntivirusSigAgeDays = if ($s.AntivirusSignatureAge -ne $null) { $s.AntivirusSignatureAge } else { '' }
                        QuickScanAge = $s.QuickScanAge; FullScanAge = $s.FullScanAge; LastQuickScan = $s.QuickScanStartTime
                    }
                }
            } catch { }
            try {
                if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
                    $threats = @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatName, SeverityID, IsActive, Resources)
                }
            } catch { }
            try {
                if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
                    $p = Get-MpPreference -ErrorAction Stop
                    $prefs += [pscustomobject]@{
                        ExclusionPath = (@($p.ExclusionPath) -join ';')
                        ExclusionProcess = (@($p.ExclusionProcess) -join ';')
                        ExclusionExtension = (@($p.ExclusionExtension) -join ';')
                        DisableRealtime = $p.DisableRealtimeMonitoring
                        SubmitSamplesConsent = $p.SubmitSamplesConsent
                    }
                }
            } catch { }
            Save-Rows -Name 'defender_status' -Rows $status
            Save-Rows -Name 'defender_threats' -Rows $threats
            Save-Rows -Name 'defender_preferences' -Rows $prefs
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids @(1116, 1117, 5001, 5007) -Start $start -MaxMsg 500
            Save-Rows -Name 'defender_events' -Rows $ev
            $dconf = @($ev | Where-Object { @(5001, 5007) -contains $_.Id } | ForEach-Object {
                [pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Detail = ("$($_.Message)" -replace '\s+', ' ').Trim() }
            })
            Save-Rows -Name 'defender_config_events' -Rows $dconf
            # v2.55: parse historical 1116 detections with threat name + path + time.
            # Get-MpThreat only reports the current threat catalog (drops resolved detections);
            # 1116 events are point-in-time and survive. Merge both into defender_threats.
            $d1116 = @($ev | Where-Object { "$($_.Id)" -eq '1116' } | ForEach-Object {
                $msg = "$($_.Message)"
                $tn = ''; $sev = ''; $pth = ''
                # v2.70: real WIN11 1116 messages carry 'Name: <value> ID: <n>' - the old
                # 'Threat Name:' pattern alone captured nothing, so ThreatName came out empty and
                # the verdict rendered bare ' @ <date>' stamps. Lazy capture up to ' ID: <n>';
                # graceful empty when no name dialect is present (never invent a name).
                if ($msg -match '(?i)Threat Name:\s*(.+)') { $tn = $Matches[1].Trim() }
                elseif ($msg -match '(?i)\bName:\s*(.+?)\s+ID:\s+\d') { $tn = $Matches[1].Trim() }
                if ($msg -match '(?i)Severity:\s*(\w+)') { $sev = $Matches[1].Trim() }
                if ($msg -match '(?i)Path:\s*(.+?)(?:\s*\(|$)') { $pth = $Matches[1].Trim() }
                [pscustomobject]@{ ThreatName = $tn; Severity = $sev; ResourcePath = $pth; DetectedUTC = $_.TimeCreated; Source = 'evtx-history' }
            })
            $liveThreats = @(Import-CaseCsv 'defender_threats' | ForEach-Object {
                $_ | Add-Member -NotePropertyName DetectedUTC -NotePropertyValue $null -Force
                $_ | Add-Member -NotePropertyName ResourcePath -NotePropertyValue "$($_.Resources)" -Force
                $_ | Add-Member -NotePropertyName Source -NotePropertyValue 'live-catalog' -Force
                $_
            })
            $merged = New-Object System.Collections.Generic.List[object]
            $seenThreat = @{}
            foreach ($t in @($d1116) + @($liveThreats)) {
                $tk = "$($t.ThreatName)|$($t.ResourcePath)"
                if ($seenThreat.ContainsKey($tk)) {
                    if ($t.Source -eq 'evtx-history') { $merged.RemoveAt($seenThreat[$tk]); $merged.Add($t); $seenThreat[$tk] = $merged.Count - 1 }
                    continue
                }
                $seenThreat[$tk] = $merged.Count
                $merged.Add($t)
            }
            Save-Rows -Name 'defender_threats' -Rows $merged.ToArray()
            Export-Evtx -LogName 'Microsoft-Windows-Windows Defender/Operational' -FileName 'Defender_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '7.1'; Cat = 'MEMORY'; Name = 'RAM capture via winpmem (needs tools\winpmem, LARGE output)'; Default = $false; Quick = $false;
        Run = {
            $tool = $null
            $tDir = Get-ToolsDir
            if ($tDir) {
                $tool = Get-ChildItem -Path $tDir -Recurse -Filter '*winpmem*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if (-not $tool) {
                Write-CaseLog "    winpmem not found in tools\ folder" 'Yellow'
                if ($script:NoMenu) { Write-CaseLog "    Memory capture skipped (non-interactive -NoMenu)" 'Yellow'; return }
                $url = Read-Host "    Paste winpmem download URL (or press Enter to skip)"
                if ($url) {
                    try {
                        # v2.60: Get-KitRoot (worker-seeded) instead of $BaseDir (top-level only - this would die in a worker runspace)
                        $tDir = Join-Path (Get-KitRoot) 'tools'
                        New-Item -ItemType Directory -Path $tDir -Force | Out-Null
                        $dest = Join-Path $tDir 'winpmem_downloaded.exe'
                        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
                        $tool = Get-Item $dest
                    } catch { Write-CaseLog "    Download failed: $($_.Exception.Message)" 'Red'; return }
                } else { return }
            }
            if ($script:NoMenu) { Write-CaseLog "    Memory capture skipped (non-interactive -NoMenu)" 'Yellow'; return }
            $confirm = Read-Host "    Capture full RAM to disk? This can take several minutes and RAM-size disk space [y/N]"
            if ($confirm -notmatch '^[Yy]') { Write-CaseLog "    Memory capture skipped by user" 'Gray'; return }
            New-Item -ItemType Directory -Path $MemDir -Force | Out-Null
            $dump = Join-Path $MemDir 'physmem.raw'
            Write-CaseLog "    Capturing memory with $($tool.Name) ..." 'Cyan'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $tool.FullName "$dump" 2>&1 | ForEach-Object { Write-CaseLog "      $_" 'DarkGray' }
            $sw.Stop()
            if (Test-Path $dump) {
                $gb = [math]::Round((Get-Item $dump).Length / 1GB, 1)
                Write-CaseLog "    Memory captured: $gb GB in $([int]$sw.Elapsed.TotalSeconds)s" 'Green'
                $vol = Get-ChildItem -Path $tDir -Recurse -Filter 'vol.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($vol) {
                    $anDir = Join-Path $RawDir 'memory-analysis'
                    New-Item -ItemType Directory -Path $anDir -Force | Out-Null
                    foreach ($plugin in @('windows.pslist.PsList', 'windows.cmdline.CmdLine', 'windows.svcscan.SvcScan')) {
                        $pn = ($plugin -split '\.')[-1]
                        Write-CaseLog "    vol3 quick pass: $pn" 'Cyan'
                        & $vol.FullName -f $dump -r json $plugin 2>$null | Set-Content -LiteralPath (Join-Path $anDir "$pn.json") -Encoding UTF8
                    }
                    Write-CaseLog "    vol3: malfind (injected-code regions)..." 'Cyan'
                    $mfCsv = Join-Path $CsvDir 'memory_malfind.csv'
                    if (-not (Test-Path -LiteralPath $mfCsv)) { $mfCsv = Get-CaseCsvFullPath 'memory_malfind' }
                    & $vol.FullName -f $dump -r csv windows.malfind.Malfind 2>$null | Set-Content -LiteralPath $mfCsv -Encoding UTF8
                    $mfN = 0
                    try { $mfN = @(Import-Csv -LiteralPath $mfCsv -ErrorAction Stop).Count } catch { $mfN = 0 }
                    if ($mfN -gt 0) {
                        Write-CaseLog "    MALFIND: $mfN suspicious memory region(s) -> csv\memory_malfind.csv" 'Red'
                        & $vol.FullName -f $dump -r csv windows.netscan.NetScan 2>$null | Set-Content -LiteralPath (Get-CaseCsvFullPath 'memory_netscan') -Encoding UTF8
                    } else {
                        Write-CaseLog "    vol3 malfind: no suspicious regions" 'Gray'
                        Remove-Item -LiteralPath $mfCsv -Force -ErrorAction SilentlyContinue
                        "# no entries" | Set-Content -LiteralPath $mfCsv -Encoding UTF8
                    }
                }
            } else {
                Write-CaseLog "    Memory capture FAILED" 'Red'
            }
        } }
    [pscustomobject]@{ Id = '7.2'; Cat = 'MEMORY'; Name = 'Live memory triage - minidumps of flagged processes + YARA (opt-in, admin, budgeted)'; Default = $false; Quick = $false;
        Run = {
            $cands = @()
            foreach ($r in (Import-CaseCsv 'flash_process_scored')) {
                if ("$($r.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($r.Path)" -and "$($r.PID)") { $cands += [pscustomobject]@{ PID = [int]$r.PID; Path = "$($r.Path)"; Name = "$($r.Name)"; Verdict = "$($r.Verdict)" } }
            }
            $cands = @($cands | Sort-Object -Property @{e = { if ($_.Verdict -eq 'HIGH') { 0 } else { 1 } } } | Select-Object -First 10)
            if ($cands.Count -eq 0) { Write-CaseLog '    no flagged processes - live memory triage skipped' 'Gray'; return }
            $root = [IO.Path]::GetPathRoot($CaseDir).TrimEnd('\')
            $free = 0
            try { $free = (Get-PSDrive -Name ($root.TrimEnd(':')) -ErrorAction Stop).Free } catch { }
            if ($free -lt 10GB) { Write-CaseLog "    under 10GB free on $root - live memory triage skipped" 'Yellow'; return }
            $tDir = Get-ToolsDir
            $yr = $null
            $rulesDir = $null
            if ($tDir) {
                $yr = Get-ChildItem -Path $tDir -Recurse -Filter 'yr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                $rulesDir = Join-Path $tDir 'yara\rules'
            }
            $dmpDir = Join-Path $RawDir 'minidumps'
            New-Item -ItemType Directory -Path $dmpDir -Force | Out-Null
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class OphiraDump {
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);
}
'@ -ErrorAction SilentlyContinue
            $critical = @('lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'svchost', 'windefend', 'msmpeng')
            $rows = @()
            $used = 0L
            foreach ($c in $cands) {
                if ($used -ge 2GB) { Write-CaseLog '    dump budget (2GB) reached - stopping' 'Yellow'; break }
                $pn = ($c.Name -replace '\.exe$', '').ToLower()
                if ($critical -contains $pn) { Write-CaseLog "    skip $($c.Name) (security-critical process)" 'DarkYellow'; continue }
                try {
                    $proc = Get-Process -Id $c.PID -ErrorAction Stop
                    if ($proc.PrivateMemorySize64 -gt 1.5GB) { Write-CaseLog "    skip $($c.Name) (private memory > 1.5GB)" 'DarkYellow'; continue }
                    $outFile = Join-Path $dmpDir "$($c.Name)_$($c.PID).dmp"
                    $ok = $false
                    $fs = [IO.File]::Create($outFile)
                    try {
                        $ok = [OphiraDump]::MiniDumpWriteDump($proc.Handle, [uint32]$c.PID, $fs.SafeFileHandle.DangerousGetHandle(), [uint32]0x26, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
                    } finally { $fs.Close() }
                    if (-not $ok -or -not (Test-Path -LiteralPath $outFile)) { Write-CaseLog "    dump failed: $($c.Name)" 'DarkYellow'; continue }
                    $used += (Get-Item -LiteralPath $outFile).Length
                    $hits = ''
                    if ($yr -and (Test-Path $rulesDir)) {
                        $res = Invoke-NativeTool -ExePath $yr.FullName -ToolArgs @('scan', '-m', '--output-format=ndjson', $rulesDir, $outFile) -WorkingDirectory $yr.DirectoryName -CaptureOut
                        if ($res -and $res.ExitCode -eq 0 -and $res.StdOut) {
                            $hits = (@($res.StdOut | ForEach-Object { try { ($_ | ConvertFrom-Json).rule } catch { } }) | Where-Object { $_ } | Sort-Object -Unique) -join ';'
                        }
                    }
                    $rows += [pscustomobject]@{ Process = $c.Name; PID = $c.PID; Path = $c.Path; Verdict = $c.Verdict; Dump = "raw\minidumps\$([IO.Path]::GetFileName($outFile))"; DumpMB = [math]::Round((Get-Item -LiteralPath $outFile).Length / 1MB, 1); YaraHits = $hits }
                    Write-CaseLog "    minidump: $($c.Name) ($([math]::Round((Get-Item -LiteralPath $outFile).Length / 1MB, 1)) MB)$(if ($hits) { " YARA: $hits" })" $(if ($hits) { 'Red' } else { 'Gray' })
                } catch { Write-CaseLog "    cannot dump $($c.Name): $($_.Exception.Message)" 'DarkYellow' }
            }
            Save-Rows -Name 'memory_live_scan' -Rows $rows
            if ($rows.Count -gt 0) { Write-CaseLog "    live memory triage: $($rows.Count) dump(s), $([math]::Round($used / 1MB, 0)) MB total -> raw\minidumps + csv\memory_live_scan.csv" 'Cyan' }
        } }
[pscustomobject]@{ Id = '8.1'; Cat = 'CONTEXT'; Name = 'Attacker activity (console history, RDP targets, recycle bin)'; Default = $true; Quick = $true;
        Run = {
            $profiles = Get-UserProfileList
            $dest = Join-Path $RawDir 'useractivity'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $hist = @()
            foreach ($p in $profiles) {
                foreach ($rel in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')) {
                    $f = Join-Path $p.Path $rel
                    if (Test-Path -LiteralPath $f) {
                        $udir = Join-Path $dest $p.User
                        if (-not (Test-Path $udir)) { New-Item -ItemType Directory -Path $udir -Force | Out-Null }
                        try { Copy-Item -LiteralPath $f -Destination (Join-Path $udir 'ConsoleHost_history.txt') -Force -ErrorAction Stop } catch { }
                        $hist += [pscustomobject]@{ User = $p.User; File = $f; KB = [math]::Round((Get-Item -LiteralPath $f).Length / 1KB, 1); LastWrite = (Get-Item -LiteralPath $f).LastWriteTime }
                    }
                }
            }
            Save-Rows -Name 'powershell_console_history' -Rows $hist
            foreach ($h in $hist) { Write-CaseLog "    history: $($h.User) ($($h.KB) KB, $($h.LastWrite))" 'Gray' }
            $rdp = @()
            try {
                foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' })) {
                    $base = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Terminal Server Client\Servers"
                    if (Test-Path $base) {
                        foreach ($srv in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                            $hint = (Get-ItemProperty -Path $srv.PSPath -ErrorAction SilentlyContinue).UsernameHint
                            $rdp += [pscustomobject]@{ User = $sid.PSChildName; TargetServer = $srv.PSChildName; UsernameHint = "$hint"; LastWrite = $srv.Name -replace '.*\\', '' }
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'rdp_client_targets' -Rows $rdp
            $rbRows = @()
            $rbDest = Join-Path $RawDir 'recyclebin'
            New-Item -ItemType Directory -Path $rbDest -Force | Out-Null
            foreach ($drv in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Free -ne $null })) {
                $rb = Join-Path $drv.Root '$Recycle.Bin'
                if (Test-Path -LiteralPath $rb) {
                    $files = Get-ChildItem -LiteralPath $rb -Recurse -Filter '$I*' -File -ErrorAction SilentlyContinue
                    foreach ($f in $files) {
                        $sidDir = Split-Path $f.DirectoryName -Leaf
                        $rbRows += [pscustomobject]@{ Drive = $drv.Name; OwnerSid = $sidDir; File = $f.Name; Bytes = $f.Length; Deleted = $f.LastWriteTime }
                        $sub = Join-Path $rbDest "$($drv.Name)_$sidDir"
                        if (-not (Test-Path $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                        try { Copy-Item -LiteralPath $f.FullName -Destination $sub -Force -ErrorAction Stop } catch { }
                    }
                }
            }
            Save-Rows -Name 'recyclebin_index' -Rows $rbRows
        } }
    [pscustomobject]@{ Id = '8.2'; Cat = 'CONTEXT'; Name = 'User registry saves (NTUSER.DAT + UsrClass.dat, all profiles)'; Default = $true; Quick = $false;
        Run = {
            $dest = Join-Path $RawDir 'registry\users'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $saved = 0
            foreach ($p in (Get-UserProfileList)) {
                $nt = Join-Path $p.Path 'NTUSER.DAT'
                $uc = Join-Path $p.Path 'AppData\Local\Microsoft\Windows\UsrClass.dat'
                $loaded = Test-Path "Registry::HKEY_USERS\$($p.Sid)"
                $loadedCls = Test-Path "Registry::HKEY_USERS\$($p.Sid)_Classes"
                if (Test-Path -LiteralPath $nt) {
                    $out = Join-Path $dest "$($p.User)_NTUSER.DAT"
                    $ok = $false
                    if ($loaded) { & reg.exe save "HKU\$($p.Sid)" "$out" /y 2>&1 | Out-Null; $ok = ($LASTEXITCODE -eq 0) }
                    if (-not $ok) { try { Copy-Item -LiteralPath $nt -Destination $out -Force -ErrorAction Stop; $ok = $true } catch { } }
                    # v2.52: guarded stat - on detonation boxes AV real-time protection sometimes
                    # quarantines the freshly saved hive between Test-Path and Get-Item (TOCTOU);
                    # report it instead of crashing the expression
                    $fi = $null
                    if ($ok -and (Test-Path -LiteralPath $out)) { $fi = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue }
                    if ($fi -and $fi.Length -gt 0) { $saved++ }
                    elseif (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
                    elseif ($ok) { Write-CaseLog "    saved hive vanished after save (AV quarantine suspected): $out" 'DarkYellow' }
                }
                if (Test-Path -LiteralPath $uc) {
                    $out = Join-Path $dest "$($p.User)_UsrClass.dat"
                    $ok = $false
                    if ($loadedCls) { & reg.exe save "HKU\$($p.Sid)_Classes" "$out" /y 2>&1 | Out-Null; $ok = ($LASTEXITCODE -eq 0) }
                    if (-not $ok) { try { Copy-Item -LiteralPath $uc -Destination $out -Force -ErrorAction Stop; $ok = $true } catch { } }
                    $fi = $null
                    if ($ok -and (Test-Path -LiteralPath $out)) { $fi = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue }
                    if ($fi -and $fi.Length -gt 0) { $saved++ }
                    elseif (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
                    elseif ($ok) { Write-CaseLog "    saved hive vanished after save (AV quarantine suspected): $out" 'DarkYellow' }
                }
            }
            Write-CaseLog "    saved $saved user hive files to raw\registry\users\" 'Gray'
        } }
    [pscustomobject]@{ Id = '8.3'; Cat = 'CONTEXT'; Name = 'Coverage & context (Sysmon config, task XML, BITS, domain info)'; Default = $true; Quick = $true;
        Run = {
            $cDir = Join-Path $RawDir 'context'
            New-Item -ItemType Directory -Path $cDir -Force | Out-Null
            foreach ($svc in @('Sysmon64', 'Sysmon')) {
                $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Parameters"
                if (Test-Path $k) {
                    & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$svc\Parameters" (Join-Path $cDir "${svc}_Parameters.reg") /y 2>&1 | Out-Null
                    break
                }
            }
            try {
                $tDir = Join-Path $RawDir 'tasks'
                New-Item -ItemType Directory -Path $tDir -Force | Out-Null
                if (Get-Command Export-ScheduledTask -ErrorAction SilentlyContinue) {
                    $n = 0
                    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                        try {
                            $safe = ($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_'
                            if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 150) }
                            Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Set-Content -LiteralPath (Join-Path $tDir "$safe.xml") -Encoding UTF8
                            $n++
                        } catch { }
                    }
                    Write-CaseLog "    exported $n task XMLs to raw\tasks\" 'Gray'
                }
            } catch { }
            $bits = @()
            try {
                if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
                    $bits = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, OwnerAccount, JobState, TransferType, @{n = 'Files'; e = { @($_.Files) -join ';' } })
                }
            } catch { }
            Save-Rows -Name 'bits_jobs' -Rows $bits
            $cs = Get-WmiOrCim -Class Win32_ComputerSystem
            $roleMap = @('Standalone Workstation', 'Member Workstation', 'Standalone Server', 'Member Server', 'Backup Domain Controller', 'Primary Domain Controller')
            $dom = @()
            if ($cs) {
                $dom += [pscustomobject]@{
                    Name = $cs.Name; Domain = $cs.Domain; PartOfDomain = $cs.PartOfDomain
                    DomainRole = if ($cs.DomainRole -ne $null) { $roleMap[[int]$cs.DomainRole] } else { '' }
                    LoggedUser = $cs.UserName
                }
            }
            Save-Rows -Name 'domain_info' -Rows $dom
            # local administrators (account entities + rogue-admin hunting)
            # v2.60: CIM first, resolved by the language-neutral Administrators SID (S-1-5-32-544) -
            # both net.exe output AND the group NAME are localized on non-English Windows, which is
            # why this parse used to return zero members there. net.exe parser stays as fallback.
            $la = @()
            try {
                $lgm = $null
                try {
                    $admGroup = Get-LocalGroup -ErrorAction Stop | Where-Object { "$($_.SID)" -eq 'S-1-5-32-544' } | Select-Object -First 1
                    if ($admGroup) { $lgm = @(Get-LocalGroupMember -Group $admGroup -ErrorAction Stop) }
                } catch { }
                if ($lgm -and $lgm.Count -gt 0) {
                    $machineRx = "^$([regex]::Escape($env:COMPUTERNAME))\\"
                    foreach ($m in $lgm) { $la += [pscustomobject]@{ Group = 'Administrators'; Member = ("$($m.Name)" -replace $machineRx, '') } }
                    Write-CaseLog "    local admins: $($la.Count) member(s) (CIM)" 'Gray'
                } else {
                    foreach ($member in (Get-LocalAdminMembers @(& net.exe localgroup administrators 2>$null))) {
                        $la += [pscustomobject]@{ Group = 'Administrators'; Member = "$member" }
                    }
                    if ($la.Count -gt 0) { Write-CaseLog "    local admins: $($la.Count) member(s)" 'Gray' }
                }
            } catch { }
            Save-Rows -Name 'local_admins' -Rows $la
            if ($cs -and $cs.PartOfDomain) {
                Invoke-ExeCapture -SubDir 'context' -Name 'nltest_dsgetdc.txt' -Exe nltest.exe -Arguments "/dsgetdc:$env:USERDOMAIN"
                Invoke-ExeCapture -SubDir 'context' -Name 'nltest_trusts.txt' -Exe nltest.exe -Arguments '/domain_trusts'
            }
        } }
    [pscustomobject]@{ Id = '8.4'; Cat = 'CONTEXT'; Name = 'EZ forensic parsers (AmcacheParser + RBCmd, needs tools\)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $amcExe = Get-ChildItem -Path $tDir -Recurse -Filter 'AmcacheParser*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $rbExe = Get-ChildItem -Path $tDir -Recurse -Filter 'RBCmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $amcHive = Join-Path $RawDir 'registry\Amcache.hve'
            if ($amcExe -and (Test-Path $amcHive)) {
                Write-CaseLog "    AmcacheParser: historical execution inventory..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $amcExe.FullName -ToolArgs @('-f', $amcHive, '--csv', $CsvDir, '--csvf', 'amcache.csv')
                $amcCsv = Join-Path $CsvDir 'amcache.csv'
                if (-not (Test-Path -LiteralPath $amcCsv)) { $amcCsv = Get-CaseCsvFullPath 'amcache' }
                if (-not (Test-Path $amcCsv)) {
                    # AmcacheParser 2026+ writes split CSVs (amcache_UnassociatedFileEntries etc.) - merge the
                    # file-entry family back into amcache.csv so the IOC xref / hunt / timeline consumers work.
                    # The freshly written split CSVs AND the merged output can carry a transient real-time AV
                    # lock (v2.52 hive-stat class of flake), so each single-try op below gets a small bounded
                    # retry (-ErrorAction Stop makes lock errors catchable under both EAP=Stop and Continue)
                    # before the catch logs an honest failure.
                    # v2.74: scan the mapped folder too - the sortment sweep folders earlier runs'
                    # split CSVs, and a re-parse must still find them (flat-first contract intact)
                    $parts = @(Get-ChildItem -Path @($CsvDir, (Join-Path $CsvDir 'artifacts')) -Filter 'amcache_*.csv' -ErrorAction SilentlyContinue | Where-Object {
                        $hdr = $null
                        for ($i = 0; $i -lt 3; $i++) {
                            try { $hdr = Get-Content -LiteralPath $_.FullName -First 1 -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 250 }
                        }
                        "$hdr" -match '^"?ApplicationName'
                    })
                    if ($parts.Count -eq 0) { $parts = @(Get-ChildItem -Path @($CsvDir, (Join-Path $CsvDir 'artifacts')) -Filter 'amcache_DriveBinaries.csv' -File -ErrorAction SilentlyContinue) }
                    if ($parts.Count -gt 0) {
                        try {
                            $rows = @()
                            foreach ($p in $parts) {
                                $pr = $null
                                for ($i = 0; $i -lt 3; $i++) {
                                    try { $pr = @(Import-Csv -LiteralPath $p.FullName -ErrorAction Stop); break } catch { Start-Sleep -Milliseconds 250 }
                                }
                                if ($null -eq $pr) { throw "split CSV unreadable after retries: $(Split-Path -Leaf $p.FullName)" }
                                $rows += $pr
                            }
                            $ok = $false
                            for ($i = 0; $i -lt 3; $i++) {
                                try { $rows | Export-Csv -LiteralPath $amcCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; $ok = $true; break } catch { Start-Sleep -Milliseconds 250 }
                            }
                            if (-not $ok) { throw "could not write merged amcache.csv after retries" }
                            Write-CaseLog "    amcache: $($rows.Count) entries (merged $($parts.Count) split CSVs)" 'Gray'
                        } catch { Write-CaseLog "    amcache split-CSV merge failed: $($_.Exception.Message)" 'DarkYellow' }
                    }
                }
                if (Test-Path $amcCsv) {
                    $n = @(Get-Content -LiteralPath $amcCsv | Select-Object -Skip 1).Count
                    Write-CaseLog "    amcache: $n entries in csv\amcache.csv" 'Gray'
                    $iocs = Get-IocList
                    if ($iocs -and $iocs.Sha1.Count -gt 0) {
                        try {
                            $rows = Import-Csv -LiteralPath $amcCsv
                            $sha1Col = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '^sha1$' } | Select-Object -First 1)
                            $nameCol = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match 'ApplicationName|SourceSimpleName|^Name$' } | Select-Object -First 1)
                            $hits = @()
                            foreach ($r in $rows) {
                                $sv = "$($r.$sha1Col)".ToUpper() -replace '[^A-F0-9]', ''
                                if ($sv -and $iocs.Sha1.ContainsKey($sv)) {
                                    $hits += [pscustomobject]@{ Indicator = $sv; Application = "$($r.$nameCol)"; SourceFile = "$($r.SourceFile)"; Match = 'amcache-SHA1' }
                                }
                            }
                            Save-Rows -Name 'ioc_hits_amcache' -Rows $hits
                            if ($hits.Count) { Write-CaseLog "    AMCACHE IOC HITS: $($hits.Count) (csv\ioc_hits_amcache.csv)" 'Red' }
                        } catch { Write-CaseLog "    amcache IOC xref failed: $($_.Exception.Message)" 'DarkYellow' }
                    }
                } else { Write-CaseLog "    AmcacheParser produced no output (and no split CSVs to merge)" 'DarkYellow' }
            }
            $rbSrc = Join-Path $RawDir 'recyclebin'
            if ($rbExe -and (Test-Path $rbSrc) -and @(Get-ChildItem -LiteralPath $rbSrc -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
                Write-CaseLog "    RBCmd: recycle bin parse..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $rbExe.FullName -ToolArgs @('-d', $rbSrc, '-q', '--csv', $CsvDir, '--csvf', 'recyclebin.csv')
            }
        } }
    [pscustomobject]@{ Id = '8.5'; Cat = 'CONTEXT'; Name = 'LNK + Jump Lists (raw save + parse via tools\LECmd/JLECmd)'; Default = $true; Quick = $false;
        Run = {
            $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
            $recDst = Join-Path $RawDir 'recent'
            New-Item -ItemType Directory -Path $recDst -Force | Out-Null
            $nLnk = 0
            if (Test-Path -LiteralPath $recent) {
                foreach ($f in @(Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
                    try { Copy-Item -LiteralPath $f.FullName -Destination $recDst -Force -ErrorAction Stop; $nLnk++ } catch { }
                }
            }
            $jlDst = Join-Path $RawDir 'jumplists'
            New-Item -ItemType Directory -Path $jlDst -Force | Out-Null
            $nJl = 0
            foreach ($sub in @('AutomaticDestinations', 'CustomDestinations')) {
                $d = Join-Path $recent $sub
                $subDst = Join-Path $jlDst $sub
                New-Item -ItemType Directory -Path $subDst -Force | Out-Null
                if (Test-Path -LiteralPath $d) {
                    foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) {
                        try { Copy-Item -LiteralPath $f.FullName -Destination $subDst -Force -ErrorAction Stop; $nJl++ } catch { }
                    }
                }
            }
            Write-CaseLog "    saved $nLnk recent LNK + $nJl jump list files to raw\" 'Gray'
            $tDir = Get-ToolsDir
            if (-not $tDir) { return }
            $leExe = Get-ChildItem -Path $tDir -Recurse -Filter 'LECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $jlExe = Get-ChildItem -Path $tDir -Recurse -Filter 'JLECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($leExe -and $nLnk -gt 0) {
                Write-CaseLog "    LECmd: parsing recent LNK files..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $leExe.FullName -ToolArgs @('-d', $recDst, '--csv', $CsvDir, '--csvf', 'lnk_parsed.csv')
                $lp = Join-Path $CsvDir 'lnk_parsed.csv'
                if (-not (Test-Path -LiteralPath $lp)) { $lp = Get-CaseCsvFullPath 'lnk_parsed' }
                if (Test-Path -LiteralPath $lp) { Write-CaseLog "    LNK parsed -> csv\lnk_parsed.csv" 'Gray' } else { Write-CaseLog "    LECmd produced no output" 'DarkYellow' }
            }
            if ($jlExe -and $nJl -gt 0) {
                Write-CaseLog "    JLECmd: parsing jump lists..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $jlExe.FullName -ToolArgs @('-d', $jlDst, '--csv', $CsvDir, '--csvf', 'jumplist_parsed.csv')
                $jlCsv = Get-ChildItem -Path $CsvDir -Filter 'jumplist_parsed*.csv' -ErrorAction SilentlyContinue
                if ($jlCsv) { Write-CaseLog "    jump lists parsed -> $(@($jlCsv | ForEach-Object { $_.Name }) -join ', ')" 'Gray' } else { Write-CaseLog "    JLECmd produced no output" 'DarkYellow' }
            }
        } }
    [pscustomobject]@{ Id = '8.6'; Cat = 'CONTEXT'; Name = 'Certificate store inventory (T1553 root-trust abuse)'; Default = $true; Quick = $false;
        Run = {
            $rows = @()
            $stores = @(
                @{ Path = 'Cert:\LocalMachine\Root'; Store = 'LocalMachine\Root' }
                @{ Path = 'Cert:\LocalMachine\CA'; Store = 'LocalMachine\CA' }
                @{ Path = 'Cert:\LocalMachine\TrustedPublisher'; Store = 'LocalMachine\TrustedPublisher' }
                @{ Path = 'Cert:\CurrentUser\Root'; Store = 'CurrentUser\Root' }
            )
            $cutoff = (Get-Date).AddDays(-90)
            foreach ($st in $stores) {
                try {
                    foreach ($c in (Get-ChildItem -Path $st.Path -ErrorAction SilentlyContinue)) {
                        $flags = @()
                        if ($c.NotBefore -and $c.NotBefore -ge $cutoff) { $flags += 'recently-added' }
                        if ($c.Subject -and $c.Issuer -and ("$($c.Subject)" -eq "$($c.Issuer)")) { $flags += 'self-signed' }
                        if ($st.Store -eq 'CurrentUser\Root') { $flags += 'user-store' }
                        $rows += [pscustomobject]@{
                            Store = $st.Store; Thumbprint = $c.Thumbprint; Subject = "$($c.Subject)"
                            Issuer = "$($c.Issuer)"; NotBefore = $c.NotBefore; NotAfter = $c.NotAfter
                            HasPrivateKey = $c.HasPrivateKey; Flags = ($flags -join ';')
                        }
                    }
                } catch { }
            }
            Save-Rows -Name 'certificates' -Rows $rows
            $hot = @($rows | Where-Object { $_.Flags -match 'recently-added' -and $_.Flags -match 'self-signed' })
            if ($hot.Count -gt 0) {
                Write-CaseLog "    certificates: $($rows.Count) inventoried, $($hot.Count) RECENT + SELF-SIGNED (verify: enterprise root CAs are self-signed by design) -> csv\certificates.csv" 'Yellow'
            } else {
                Write-CaseLog "    certificates: $($rows.Count) inventoried -> csv\certificates.csv" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.7'; Cat = 'CONTEXT'; Name = 'Browser artifacts raw save (Chrome/Edge History + Downloads, per profile)'; Default = $true; Quick = $false;
        Run = {
            $dst = Join-Path $RawDir 'browser'
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $inv = @()
            $browsers = @(
                @{ Name = 'chrome'; Root = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data' }
                @{ Name = 'edge';   Root = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data' }
            )
            foreach ($b in $browsers) {
                if (-not (Test-Path -LiteralPath $b.Root)) { continue }
                $profileDirs = @()
                $prof = Join-Path $b.Root 'Default'
                if (Test-Path -LiteralPath $prof) { $profileDirs += 'Default' }
                try {
                    $profileDirs += @(Get-ChildItem -LiteralPath $b.Root -Directory -Filter 'Profile *' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                } catch { }
                foreach ($pd in $profileDirs) {
                    foreach ($file in @('History', 'Downloads', 'Preferences', 'Bookmarks', 'Login Data')) {
                        $src = Join-Path $b.Root "$pd\$file"
                        if (-not (Test-Path -LiteralPath $src)) { continue }
                        $sub = Join-Path $dst "$($b.Name)_$pd"
                    if (-not (Test-Path -LiteralPath $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                    foreach ($rootFile in @('Local State')) {
                        $rs = Join-Path $b.Root $rootFile
                        if (Test-Path -LiteralPath $rs) { Copy-Item -LiteralPath $rs -Destination (Join-Path $sub $rootFile) -Force -ErrorAction SilentlyContinue }
                    }
                    $outFile = Join-Path $sub $file
                        $ok = $false
                        try { Copy-Item -LiteralPath $src -Destination $outFile -Force -ErrorAction Stop; $ok = $true } catch { }
                        if (-not $ok) { $ok = Copy-LockedFile -Source $src -Dest $outFile }
                        if ($ok) { $inv += [pscustomobject]@{ Browser = $b.Name; Profile = $pd; File = $file; Bytes = (Get-Item -LiteralPath $outFile).Length } }
                    }
                }
            }
            Save-Rows -Name 'browser_files' -Rows $inv
            $mb = [math]::Round((($inv | Measure-Object Bytes -Sum).Sum) / 1MB, 1)
            Write-CaseLog "    browser: $($inv.Count) file(s) ($mb MB) saved to raw\browser\ (SQLite parsed offline)" 'Gray'
            # ---- parse the copied SQLite DBs (SQLECmd; .NET 9 on target needed - degrades gracefully) ----
            $tDir = Get-ToolsDir
            $sqlExe = $null
            if ($tDir) { $sqlExe = Get-ChildItem -Path $tDir -Recurse -Filter 'SQLECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if ($sqlExe -and @($inv | Where-Object { $_.File -eq 'History' }).Count -gt 0) {
                Write-CaseLog "    SQLECmd: parsing browser history/downloads..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $sqlExe.FullName -ToolArgs @('-d', $dst, '--csv', $CsvDir)
                $merge = {
                    param([string]$glob, [string]$name)
                    $files = @(Get-ChildItem -Path $CsvDir -Filter $glob -File -ErrorAction SilentlyContinue)
                    $all = @()
                    foreach ($f2 in $files) {
                        try { $all += @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { }
                    }
                    if ($all.Count -gt 0) { Save-Rows -Name $name -Rows $all }
                    foreach ($f2 in $files) { Remove-Item -LiteralPath $f2.FullName -Force -ErrorAction SilentlyContinue }
                    return $all.Count
                }
                $nH = & $merge '*ChromiumBrowser_HistoryVisits_*.csv' 'browser_history'
                $nD = & $merge '*ChromiumBrowser_Downloads_*.csv' 'browser_downloads'
                $nK = & $merge '*ChromiumBrowser_KeywordSearches_*.csv' 'browser_searches'
                Get-ChildItem -Path $CsvDir -Filter 'SQLite.Interop.dll' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-CaseLog "    browser parsed: $nH visits, $nD downloads, $nK searches -> csv\browser_*.csv" 'Gray'
                Invoke-BrowserIocXref
            } elseif (-not $sqlExe) {
                Write-CaseLog "    SQLECmd not in tools\ - browser DBs left as raw copies (parse at HQ or run Setup)" 'DarkGray'
            }
        } }
    [pscustomobject]@{ Id = '8.8'; Cat = 'CONTEXT'; Name = 'ShellBags - folder browsing history (needs tools\SBECmd, admin)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $sbe = Get-ChildItem -Path $tDir -Recurse -Filter 'SBECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $sbe) { Write-CaseLog "    SBECmd not in tools\ - skipping (run Setup)" 'DarkGray'; return }
            # v2.54: parse the case's own saved hives (module 8.2) + staged live hives for uncovered
            # users only. The old recursive `-d C:\Users` swept EVERY .DAT under user profiles - stale
            # case copies in Temp included - and SBECmd's per-hive output names never matched the
            # shellbags*.csv expectation, so shellbags.csv never built and raw tool outputs leaked
            # into csv\ (showing as empty NTUSER rows in the evidence index).
            $savedDir = Join-Path $RawDir 'registry\users'
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_sbe_" + (Get-Date -Format 'HHmmss'))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            $runs = @()
            $coveredUsers = New-Object 'System.Collections.Generic.HashSet[string]'
            if (Test-Path $savedDir) {
                $runs += $savedDir
                foreach ($f in @(Get-ChildItem -LiteralPath $savedDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)ntuser|usrclass' })) {
                    $null = $coveredUsers.Add((($f.BaseName -replace '(?i)_(ntuser\.dat|usrclass\.dat)$', '')).ToLower())
                }
            }
            $stage = Join-Path $tmp 'stage'
            New-Item -ItemType Directory -Path $stage -Force | Out-Null
            foreach ($p in @(Get-ChildItem -Path "$env:SystemDrive\Users\*\NTUSER.DAT", "$env:SystemDrive\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction SilentlyContinue)) {
                $u2 = $p.Directory.Name
                if ("$($p.Name)" -match '(?i)usrclass') { try { $u2 = $p.Directory.Parent.Parent.Parent.Parent.Name } catch { } }
                if ($coveredUsers.Contains("$u2".ToLower())) { continue }
                try { Copy-Item -LiteralPath $p.FullName -Destination (Join-Path $stage $p.Name) -Force -ErrorAction Stop } catch { }
            }
            if (@(Get-ChildItem -LiteralPath $stage -File -ErrorAction SilentlyContinue).Count -gt 0) { $runs += $stage }
            if ($runs.Count -eq 0) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue; Write-CaseLog "    no user hives available (module 8.2 saves them first)" 'DarkGray'; return }
            Write-CaseLog "    SBECmd: parsing ShellBags from $($runs.Count) hive source(s)..." 'Cyan'
            $ri = 0
            foreach ($r2 in $runs) {
                $ri++
                # per-run output dir: --dedupe always names the file Deduplicated.csv, a second
                # run would overwrite the first run's results
                $null = Invoke-NativeTool -ExePath $sbe.FullName -ToolArgs @('-d', $r2, '--csv', "$tmp\r$ri", '--dedupe')
            }
            # merge ALL outputs regardless of SBECmd's per-hive naming
            $rows = @()
            foreach ($o in @(Get-ChildItem -LiteralPath $tmp -Filter '*.csv' -File -Recurse -ErrorAction SilentlyContinue)) {
                $rows += @(Import-Csv -LiteralPath $o.FullName -ErrorAction SilentlyContinue)
            }
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Save-Rows -Name 'shellbags' -Rows $rows
            if ($rows.Count -gt 0) { Write-CaseLog "    shellbags: $($rows.Count) folder-access entries -> csv\shellbags.csv" 'Gray' }
            else { Write-CaseLog "    SBECmd produced no output (not elevated? no profiles?)" 'DarkYellow' }
        } }
    [pscustomobject]@{ Id = '8.9'; Cat = 'CONTEXT'; Name = 'Security posture audit (LSA, SMBv1, RDP, PS logging, UAC, Defender, BitLocker)'; Default = $true; Quick = $true;
        Run = {
            $rows = New-Object System.Collections.Generic.List[object]
            function Add-Posture([string]$Check, [string]$Status, [string]$Detail) {
                $rows.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
            }
            $rp = {
                param([string]$path, [string]$prop)
                try { $v = (Get-ItemProperty -Path $path -ErrorAction Stop).$prop; if ($null -ne $v) { return "$v" } } catch { }
                return $null
            }
            # LSA Protection (credential theft / mimikatz resistance)
            $ppl = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
            if ($ppl -eq '1') { Add-Posture 'LSA Protection (RunAsPPL)' 'GOOD' 'Credential guard for LSASS enabled' }
            else { Add-Posture 'LSA Protection (RunAsPPL)' 'BAD' 'LSASS runs unprotected - credential dumping (mimikatz) is easier; set RunAsPPL=1' }
            # NTLM LAN Manager auth level
            $lm = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
            if ($null -eq $lm) { Add-Posture 'NTLM compatibility level' 'WARN' 'Default level in place - verify NTLMv1 is rejected (level 5)' }
            elseif ([int]$lm -ge 5) { Add-Posture 'NTLM compatibility level' 'GOOD' "Level $lm - NTLMv1 refused" }
            else { Add-Posture 'NTLM compatibility level' 'BAD' "Level $lm - weak NTLMv1/LM responses allowed" }
            # SMBv1
            $smb1 = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
            $mrx = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10' 'Start'
            if ($smb1 -eq '1' -or $mrx -eq '0') { Add-Posture 'SMBv1 protocol' 'BAD' 'SMBv1 enabled - EternalBlue/WannaCry-class exposure; disable it' }
            else { Add-Posture 'SMBv1 protocol' 'GOOD' 'SMBv1 disabled/absent' }
            # RDP + NLA
            $rdp = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
            if ($rdp -eq '0') {
                $nla = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
                if ($nla -eq '0') { Add-Posture 'RDP' 'BAD' 'RDP enabled WITHOUT Network Level Authentication - brute-force friendly' }
                else { Add-Posture 'RDP' 'WARN' "RDP enabled with NLA - verify firewall scope + account lockout" }
            } else { Add-Posture 'RDP' 'GOOD' 'RDP disabled' }
            # PowerShell script-block logging
            $sbl = & $rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
            if ($sbl -eq '1') { Add-Posture 'PowerShell script-block logging' 'GOOD' 'EID 4104 capture enabled' }
            else { Add-Posture 'PowerShell script-block logging' 'BAD' 'Script-block logging off - PowerShell attacks leave little evidence; enable via GPO' }
            # UAC
            $lua = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            $cpb = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
            if ($lua -eq '0') { Add-Posture 'UAC' 'BAD' 'UAC disabled entirely' }
            elseif ($cpb -eq '0') { Add-Posture 'UAC' 'WARN' 'UAC elevation without prompt (silent admin)' }
            else { Add-Posture 'UAC' 'GOOD' 'UAC enabled with prompts' }
            # Defender posture
            try {
                if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
                    $mp = Get-MpPreference -ErrorAction Stop
                    $exs = @(@($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ })
                    if (@($exs).Count -gt 0) { Add-Posture 'Defender exclusions' 'WARN' "$(@($exs).Count) exclusion(s) configured - attackers add these; review: $(@($exs | Select-Object -First 3) -join ', ')" }
                    else { Add-Posture 'Defender exclusions' 'GOOD' 'No exclusions' }
                    if ($mp.DisableRealtimeMonitoring) { Add-Posture 'Defender real-time protection' 'BAD' 'Real-time protection DISABLED' }
                }
            } catch { }
            $wd = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
            if ($wd -and $wd.StartType -eq 'Disabled') { Add-Posture 'Defender service' 'BAD' 'WinDefend service is Disabled' }
            # BitLocker (OS volume)
            try {
                $bl = & manage-bde.exe -status C: 2>$null | Where-Object { $_ -match 'Protection Status' } | Select-Object -First 1
                if ("$bl" -match 'On') { Add-Posture 'BitLocker (OS volume)' 'GOOD' 'Protection on' }
                elseif ("$bl" -match 'Off') { Add-Posture 'BitLocker (OS volume)' 'WARN' 'Disk not encrypted - offline tampering/theft exposure' }
            } catch { }
            # audit policy coverage (no auditing = silent intrusion)
            try {
                $ap = & auditpol.exe '/get' '/category:*' '/r' 2>$null | ConvertFrom-Csv
                $badAudit = @($ap | Where-Object { $_.'Inclusion Setting' -match '^(No Auditing)$' })
                if (@($ap).Count -gt 0) {
                    if ($badAudit.Count -ge 6) { Add-Posture 'Audit policy' 'BAD' "$($badAudit.Count) of $($ap.Count) categories have NO auditing - intrusion leaves no trace" }
                    elseif ($badAudit.Count -gt 0) { Add-Posture 'Audit policy' 'WARN' "$($badAudit.Count) categories without auditing: $((@($badAudit | Select-Object -First 4 | ForEach-Object { $_.'Subcategory' })) -join ', ')" }
                    else { Add-Posture 'Audit policy' 'GOOD' 'All categories auditing' }
                }
            } catch { }
            # WinRM trusted hosts
            $th = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN' 'TrustedHosts'
            if ("$th" -match '\*' -or "$th" -match '[^0-9a-fA-F:\.].*,.*') { Add-Posture 'WinRM TrustedHosts' 'WARN' "Broad trust list: $th" }
            Save-Rows -Name 'posture' -Rows $rows.ToArray()
            $bad = @($rows.ToArray() | Where-Object { $_.Status -eq 'BAD' }).Count
            $warn = @($rows.ToArray() | Where-Object { $_.Status -eq 'WARN' }).Count
            if ($bad -gt 0) { Write-CaseLog "    posture: $($rows.Count) checks - $bad BAD, $warn WARN -> csv\posture.csv (see report hardening recommendations)" 'Yellow' }
            else { Write-CaseLog "    posture: $($rows.Count) checks - no critical findings, $warn warn -> csv\posture.csv" 'Gray' }
        } }
    [pscustomobject]@{ Id = '8.10'; Cat = 'CONTEXT'; Name = 'LOLDrivers hash check - malicious/vulnerable driver xref (needs tools\loldrivers)'; Default = $true; Quick = $false;
        Run = {
            $lolDir = Join-Path (Get-ToolsDir) 'loldrivers'
            $malFile = Join-Path $lolDir 'samples_malicious.sha256'
            $vulFile = Join-Path $lolDir 'samples_vulnerable.sha256'
            if (-not (Test-Path $malFile) -and -not (Test-Path $vulFile)) { Write-CaseLog "    tools\loldrivers datasets missing - skipping (run: -Mode Setup)" 'DarkGray'; return }
            $malSet = @{}
            if (Test-Path $malFile) { foreach ($h in (Get-Content $malFile -ErrorAction SilentlyContinue)) { $hl = "$h".Trim().ToLower(); if ($hl) { $malSet[$hl] = $true } } }
            $vulSet = @{}
            if (Test-Path $vulFile) { foreach ($h in (Get-Content $vulFile -ErrorAction SilentlyContinue)) { $hl = "$h".Trim().ToLower(); if ($hl) { $vulSet[$hl] = $true } } }
            $drvRows = @(Import-CaseCsv 'drivers')
            if ($drvRows.Count -eq 0) { Write-CaseLog "    no drivers.csv (module 1.6 skipped) - nothing to check" 'DarkGray'; return }
            $hits = @()
            $checked = 0
            foreach ($dr in $drvRows) {
                if ($checked -ge 600) { break }
                $p = "$($dr.PathName)" -replace '^\\{1,2}\?\?\\', ''
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
                $hash = $null
                try { $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { continue }
                $checked++
                $status = ''
                if ($malSet.ContainsKey($hash)) { $status = 'malicious' }
                elseif ($vulSet.ContainsKey($hash)) { $status = 'vulnerable' }
                if ($status) { $hits += [pscustomobject]@{ Status = $status; Name = "$($dr.Name)"; DisplayName = "$($dr.DisplayName)"; Path = $p; SHA256 = $hash } }
            }
            Save-Rows -Name 'loldrivers_hits' -Rows $hits
            $mal = @($hits | Where-Object { $_.Status -eq 'malicious' }).Count
            $vul = @($hits | Where-Object { $_.Status -eq 'vulnerable' }).Count
            if ($hits.Count -gt 0) {
                Write-CaseLog "    LOLDrivers: $mal MALICIOUS, $vul vulnerable driver(s) on disk ($checked hashed) -> csv\loldrivers_hits.csv" $(if ($mal -gt 0) { 'Red' } else { 'Yellow' })
            } else {
                Write-CaseLog "    LOLDrivers: $checked drivers hashed - no malicious/vulnerable matches" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.11'; Cat = 'CONTEXT'; Name = 'Host history extras (BAM/DAM last-exec, USB devices, Office MRU, UAL raw)'; Default = $true; Quick = $false;
        Run = {
            # BAM/DAM: per-user background execution tracking (survives Prefetch deletion)
            $bam = @()
            foreach ($svc in @('bam', 'dam')) {
                $base = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$svc\State\UserSettings"
                if (-not (Test-Path $base)) { continue }
                foreach ($sid in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                    $t = $sid.LastWriteTime
                    foreach ($v in (Get-ItemProperty -LiteralPath $sid.PSPath -ErrorAction SilentlyContinue).PSObject.Properties) {
                        if (@('Version', 'SequenceNumber') -contains $v.Name -or $v.Name -match '^PS') { continue }
                        if ("$($v.Value)" -and "$($v.Value)" -notmatch '^(Version|SequenceNumber)$') {
                            $bam += [pscustomobject]@{ Source = $svc.ToUpper(); Sid = $sid.PSChildName; Executable = "$($v.Value)"; LastWrite = $t }
                        }
                    }
                }
            }
            Save-Rows -Name 'bam_lastexec' -Rows $bam
            if ($bam.Count -gt 0) { Write-CaseLog "    BAM/DAM: $($bam.Count) last-exec entries -> csv\bam_lastexec.csv" 'Gray' }
            # USB storage devices (every USB device ever connected)
            $usbs = @()
            $usbBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
            if (Test-Path $usbBase) {
                foreach ($dev in (Get-ChildItem $usbBase -ErrorAction SilentlyContinue)) {
                    foreach ($inst in (Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue)) {
                        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -ErrorAction SilentlyContinue
                        $usbs += [pscustomobject]@{ DeviceKey = $dev.PSChildName; FriendlyName = "$($ip.FriendlyName)"; Serial = $(if ($ip.ParentIdPrefix) { "$($ip.ParentIdPrefix)" } else { $inst.PSChildName }); LastWrite = $inst.LastWriteTime }
                    }
                }
            }
            Save-Rows -Name 'usb_devices' -Rows $usbs
            $sap = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
            if (Test-Path $sap) {
                $d = Join-Path $RawDir 'usb'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                Copy-Item -LiteralPath $sap -Destination (Join-Path $d 'setupapi.dev.log') -Force -ErrorAction SilentlyContinue
            }
            if ($usbs.Count -gt 0) { Write-CaseLog "    USB: $($usbs.Count) storage device(s) on record -> csv\usb_devices.csv" 'Gray' }
            # Office File MRU (recent documents per user)
            $mru = @()
            foreach ($sid in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' })) {
                foreach ($ver in @('16.0', '15.0')) {
                    foreach ($app in @('Word', 'Excel', 'PowerPoint')) {
                        $k = "$($sid.PSPath)\Software\Microsoft\Office\$ver\$app\File MRU"
                        if (-not (Test-Path $k)) { continue }
                        $t = (Get-Item $k).LastWriteTime
                        foreach ($v in (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).PSObject.Properties) {
                            if ($v.Name -notmatch '^Item \d+' -or $v.Value -isnot [byte[]]) { continue }
                            $ascii = [Text.Encoding]::ASCII.GetString($v.Value)
                            if ($ascii -match '(?i)([a-z]:\\[^\x00-\x1f]+?\.(docx?|xlsx?|pptx?|pdf|rtf))') {
                                $mru += [pscustomobject]@{ Sid = $sid.PSChildName; App = $app; Document = $Matches[1]; LastWrite = $t }
                            }
                        }
                    }
                }
            }
            Save-Rows -Name 'office_mru' -Rows $mru
            if ($mru.Count -gt 0) { Write-CaseLog "    Office MRU: $($mru.Count) recent document(s)" 'Gray' }
            # User Access Logs (SMB/RDP source history - ESE format, preserved raw for analyst)
            $sum = Join-Path $env:SystemRoot 'System32\LogFiles\Sum'
            if (Test-Path $sum) {
                $d = Join-Path $RawDir 'ual'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                $mts = @(Get-ChildItem $sum -Filter '*.mts' -File -ErrorAction SilentlyContinue)
                $mts | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                Save-Rows -Name 'ual_files' -Rows @($mts | Select-Object Name, Length, LastWriteTime)
                Write-CaseLog "    UAL: $($mts.Count) .mts file(s) copied to raw\ual (ESE - analyst-side parse)" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.12'; Cat = 'CONTEXT'; Name = 'Web server artifacts (IIS/HTTPERR logs raw + W3C parse, app pool config, webshell content scan)'; Default = $false; Quick = $false;
        Run = {
            $copied = 0
            foreach ($src in @(@('web\iis', "$env:SystemDrive\inetpub\logs\LogFiles"), @('web\httperr', "$env:SystemRoot\System32\LogFiles\HTTPERR"))) {
                if (-not (Test-Path $src[1])) { continue }
                $d = Join-Path $RawDir $src[0]
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                $logs = @(Get-ChildItem -LiteralPath $src[1] -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20)
                foreach ($f in $logs) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $d $f.Name) -Force -ErrorAction SilentlyContinue; $copied++ }
            }
            $ahc = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
            if (Test-Path $ahc) {
                $d = Join-Path $RawDir 'web'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                Copy-Item -LiteralPath $ahc -Destination (Join-Path $d 'applicationHost.config') -Force -ErrorAction SilentlyContinue
                $copied++
            }
            $req = Get-IisW3cRows -Path "$env:SystemDrive\inetpub\logs\LogFiles" -Cap 10000
            $norm = @($req | Where-Object { "$($_.'cs-method')" } | ForEach-Object {
                [pscustomobject]@{
                    Time = ("$($_.date) $($_.time)").Trim(); Method = "$($_.'cs-method')"; Uri = "$($_.'cs-uri-stem')"
                    Query = "$($_.'cs-uri-query')"; Status = "$($_.'sc-status')"; ClientIp = "$($_.'c-ip')"; UserAgent = "$($_.'cs(User-Agent)')"
                }
            })
            Save-Rows -Name 'iis_requests' -Rows $norm
            $anom = New-Object System.Collections.Generic.List[object]
            foreach ($g in (@($norm | Where-Object { $_.Status -eq '500' } | Group-Object ClientIp | Where-Object { $_.Count -ge 10 }))) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'server-errors'; Detail = "$($g.Count) x HTTP 500 from $($g.Name)"; Sample = ((@($g.Group | Select-Object -First 3 | ForEach-Object { $_.Uri })) -join ' | ') })
            }
            foreach ($r in (@($norm | Where-Object { $_.Uri -match '(?i)(\.\./|%2e%2e|%00|/cmd\.|webshell|\.jsp;|eval\()' }) | Select-Object -First 20)) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'suspicious-uri'; Detail = "$($_.Uri) (status $($_.Status))"; Sample = "query=$($_.Query) ip=$($_.ClientIp) ua=$($_.UserAgent)" })
            }
            foreach ($r in (@($norm | Where-Object { $_.Method -eq 'POST' -and $_.Status -match '^2' -and $_.Uri -match '(?i)(upload|filemanager|editor|import)' }) | Select-Object -First 20)) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'post-to-upload-path'; Detail = "$($_.Uri) (status $($_.Status))"; Sample = "ip=$($_.ClientIp) ua=$($_.UserAgent)" })
            }
            $noUa = @($norm | Where-Object { -not $_.UserAgent -and $_.Method -eq 'POST' })
            if ($noUa.Count -ge 10) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'headless-posts'; Detail = "$($noUa.Count) POST requests with no User-Agent"; Sample = ((@($noUa | Select-Object -First 3 | ForEach-Object { $_.Uri })) -join ' | ') })
            }
            Save-Rows -Name 'iis_anomalies' -Rows $anom.ToArray()
            # v2.62: webshell content scan (this module is opt-in WebServer/Full; heuristics,
            # NOT signatures - every hit renders report-only medium "verify against baseline")
            $wsRows = New-Object System.Collections.Generic.List[object]
            $wsRoots = @("$env:SystemDrive\inetpub\wwwroot")
            $ahcRaw = Join-Path $RawDir 'web\applicationHost.config'
            if (Test-Path -LiteralPath $ahcRaw) {
                try { foreach ($m3 in ([regex]::Matches((Get-Content -LiteralPath $ahcRaw -Raw -ErrorAction Stop), 'physicalPath="([^"]+)"'))) {
                    $p4 = $m3.Groups[1].Value -replace '%SystemDrive%', $env:SystemDrive
                    if ($p4 -and (Test-Path -LiteralPath $p4)) { $wsRoots += $p4 }
                } } catch { }
            }
            $wsRoots = @($wsRoots | Sort-Object -Unique)
            $wsCand = @(Get-ChildItem -Path $wsRoots -Recurse -File -Include '*.aspx', '*.jsp', '*.php', '*.ashx', '*.asmx' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 300)
            foreach ($wf in $wsCand) {
                if ($wf.Length -gt 2MB) { continue }
                try { $wc = Get-Content -LiteralPath $wf.FullName -Raw -ErrorAction Stop } catch { continue }
                $wh = @(Test-WebshellContent -Content $wc)
                if ($wh.Count -gt 0) { $null = $wsRows.Add([pscustomobject]@{ Path = $wf.FullName; Modified = $wf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Size = $wf.Length; Matches = ($wh -join '; ') }) }
            }
            Save-Rows -Name 'webshell_candidates' -Rows $wsRows.ToArray()
            if ($wsRows.Count -gt 0) {
                Write-CaseLog "    webshell scan: $($wsRows.Count) of $($wsCand.Count) script file(s) match heuristics - VERIFY AGAINST BASELINE -> csv\webshell_candidates.csv" 'Yellow'
            } elseif ($wsCand.Count -gt 0) { Write-CaseLog "    webshell scan: $($wsCand.Count) script file(s) clean" 'Gray' }
            if ($norm.Count -gt 0) {
                Write-CaseLog "    IIS: $($norm.Count) parsed request(s), $($anom.Count) anomaly row(s), $copied log file(s) -> raw\web\" 'Gray'
            } elseif ($copied -gt 0) {
                Write-CaseLog "    IIS: $copied log file(s) copied raw (no W3C fields parsed - check format)" 'Gray'
            } else {
                Write-CaseLog "    IIS: no logs found (no IIS role or logs elsewhere)" 'DarkGray'
            }
        } }
    [pscustomobject]@{ Id = '8.13'; Cat = 'CONTEXT'; Name = 'Host extras (StartupInfo launches, WER crash reports, QuickAssist, PCA, RecentFileCache, MOF, local GPO, WSL dotfiles)'; Default = $true; Quick = $false;
        Run = {
            $siPath = "$env:SystemRoot\System32\WDI\LogFiles\StartupInfo"
            if (Test-Path $siPath) {
                $si = Get-StartupInfoRows -Path $siPath
                Save-Rows -Name 'startup_info' -Rows $si
                if ($si.Count -gt 0) { Write-CaseLog "    StartupInfo: $($si.Count) app-launch record(s) (per-session, survives Prefetch deletion)" 'Gray' }
                $d = Join-Path $RawDir 'extras\startupinfo'
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Get-ChildItem -LiteralPath $siPath -Filter '*.xml' -File -ErrorAction SilentlyContinue | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
            }
            $werRows = @()
            foreach ($w in @("$env:ProgramData\Microsoft\Windows\WER")) {
                if (Test-Path $w) { $werRows += @(Get-WerReportRows -Path $w) }
            }
            $udirs = @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|Default User|All Users' })
            foreach ($u in $udirs) {
                $w = Join-Path $u.FullName 'AppData\Local\Microsoft\Windows\WER'
                if (Test-Path $w) { $werRows += @(Get-WerReportRows -Path $w) }
            }
            Save-Rows -Name 'wer_reports' -Rows $werRows
            if ($werRows.Count -gt 0) { Write-CaseLog "    WER: $($werRows.Count) crash report(s) -> csv\wer_reports.csv (crashed attacker tools leave these)" 'Gray' }
            $d = Join-Path $RawDir 'extras'
            foreach ($pair in @(@('quickassist', "$env:SystemDrive\Users\*\AppData\Local\Temp\QuickAssist"), @('remotehelp', "$env:SystemDrive\Users\*\AppData\Local\Temp\RemoteHelp"))) {
                $srcs = @(Get-ChildItem -Path $pair[1] -Directory -ErrorAction SilentlyContinue)
                foreach ($s in $srcs) {
                    $dd = Join-Path $d $pair[0]
                    New-Item -ItemType Directory -Path $dd -Force | Out-Null
                    Copy-Item -LiteralPath $s.FullName -Destination (Join-Path $dd $s.Name) -Recurse -Force -ErrorAction SilentlyContinue
                    Write-CaseLog "    $($pair[0]): remote-support session artifacts copied (AitM/scam tradecraft marker) -> raw\extras\$($pair[0])" 'Yellow'
                }
            }
            foreach ($pair in @(@('pca', "$env:SystemRoot\appcompat\pca", '*'), @('mof', "$env:SystemRoot\System32\wbem\MOF", '*.mof'))) {
                if (-not (Test-Path $pair[1])) { continue }
                $dd = Join-Path $d $pair[0]
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Get-ChildItem -LiteralPath $pair[1] -Filter $pair[2] -File -ErrorAction SilentlyContinue | Copy-Item -Destination $dd -Force -ErrorAction SilentlyContinue
            }
            $rfc = "$env:SystemRoot\AppCompat\Programs\RecentFileCache.bcf"
            if (Test-Path $rfc) {
                $dd = Join-Path $d 'appcompat'
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Copy-Item -LiteralPath $rfc -Destination $dd -Force -ErrorAction SilentlyContinue
            }
            foreach ($g in @("$env:SystemRoot\System32\GroupPolicy", "$env:SystemRoot\System32\GroupPolicyUsers")) {
                if (-not (Test-Path $g)) { continue }
                $dd = Join-Path $d ("gpo\" + (Split-Path $g -Leaf))
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                $files = @(Get-ChildItem -LiteralPath $g -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 300)
                foreach ($f in $files) {
                    $rel = ''
                    try { $rel = $f.FullName.Substring($g.Length).TrimStart('\') } catch { }
                    $pd = Join-Path $dd $(if ($rel) { Split-Path $rel -Parent } else { '' })
                    if ($pd -and -not (Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force | Out-Null }
                    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pd $f.Name) -Force -ErrorAction SilentlyContinue
                }
            }
            $hist = @(Get-ChildItem -Path "$env:SystemDrive\Users\*\AppData\Local\Packages\*\LocalState\rootfs\home" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\.(bash_history|sh_history|profile|bashrc)$' } | Select-Object -First 20)
            foreach ($h in $hist) {
                $dd = Join-Path $d 'wsl'
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Copy-Item -LiteralPath $h.FullName -Destination (Join-Path $dd ("wsl_" + $h.Name)) -Force -ErrorAction SilentlyContinue
            }
            Write-CaseLog "    host extras copied -> raw\extras\ (startupinfo/wer-source/quickassist/pca/mof/appcompat/gpo/wsl)" 'Gray'
        } }
    [pscustomobject]@{ Id = '8.14'; Cat = 'CONTEXT'; Name = 'Server logs raw (DNS/DHCP audit logs, SYSVOL policies)'; Default = $true; Quick = $false;
        Run = {
            $inv = @()
            foreach ($pair in @(@('dns', "$env:SystemRoot\System32\DNS"), @('dhcp', "$env:SystemRoot\System32\dhcp"))) {
                if (-not (Test-Path $pair[1])) { continue }
                $files = @(Get-ChildItem -LiteralPath $pair[1] -Filter '*.log' -File -ErrorAction SilentlyContinue)
                if ($files.Count -eq 0) { continue }
                $d = Join-Path $RawDir ("server\" + $pair[0])
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                $files | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                foreach ($f in $files) { $inv += [pscustomobject]@{ Type = $pair[0].ToUpper(); File = $f.Name; SizeMB = [math]::Round($f.Length / 1MB, 2); LastWrite = $f.LastWriteTime } }
                Write-CaseLog "    $($pair[0]): $($files.Count) audit log file(s) -> raw\server\$($pair[0])" 'Gray'
            }
            $sysvol = "$env:SystemRoot\SYSVOL\domain\Policies"
            if (Test-Path $sysvol) {
                $d = Join-Path $RawDir 'server\sysvol'
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                $files = @(Get-ChildItem -LiteralPath $sysvol -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 400)
                foreach ($f in $files) {
                    $rel = ''
                    try { $rel = $f.FullName.Substring($sysvol.Length).TrimStart('\') } catch { }
                    $pd = Join-Path $d $(if ($rel) { Split-Path $rel -Parent } else { '' })
                    if ($pd -and -not (Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force | Out-Null }
                    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pd $f.Name) -Force -ErrorAction SilentlyContinue
                }
                $inv += [pscustomobject]@{ Type = 'SYSVOL'; File = "$($files.Count) policy file(s)"; SizeMB = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB, 2); LastWrite = '' }
                Write-CaseLog "    SYSVOL: $($files.Count) policy file(s) (GPO persistence surface) -> raw\server\sysvol" 'Gray'
            }
            # NTDS.dit is deliberately NEVER touched (file or data) by policy
            Save-Rows -Name 'server_logs' -Rows $inv
        } }
    [pscustomobject]@{ Id = '8.15'; Cat = 'CONTEXT'; Name = 'Credential exposure sweep (auto-logon, WLAN keys, DPAPI vault, LSASS dumps, browser Login Data)'; Default = $true; Quick = $false;
        Run = {
            $rows = @()
            # auto-logon: user name + whether a plaintext password value exists (value itself NOT copied to csv)
            $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
            if ($wl -and "$($wl.DefaultUserName)") {
                $hasPw = -not [string]::IsNullOrEmpty("$($wl.DefaultPassword)")
                $rows += [pscustomobject]@{ Item = 'Auto-logon (Winlogon)'; Detail = "user '$($wl.DefaultUserName)', cached password: $(if ($hasPw) { 'PRESENT' } else { 'absent' })"; Risk = $(if ($hasPw) { 'HIGH' } else { 'LOW' }) }
            }
            # WLAN profiles - keys captured into raw\wifi (evidence, analyst material)
            $wifiProfiles = @()
            try {
                foreach ($l in (& netsh.exe wlan show profiles 2>$null | ForEach-Object { "$_" })) {
                    if ($l -match 'All User Profile\s*:\s*(.+)$') { $wifiProfiles += $Matches[1].Trim() }
                }
            } catch { }
            foreach ($p in $wifiProfiles) {
                try {
                    $d = (& netsh.exe wlan show profile name="$p" key=clear 2>$null | ForEach-Object { "$_" }) -join "`n"
                    $auth = ''; if ($d -match 'Authentication\s*:\s*(\S+)') { $auth = $Matches[1] }
                    $hasKey = $d -match 'Key Content\s*:\s*(\S)'
                    Out-RawText -SubDir 'wifi' -Name ("wlan_" + ($p -replace '[^\w\.-]', '_') + ".txt") -Text ($d -split "`n")
                    $rows += [pscustomobject]@{ Item = "WLAN profile '$p'"; Detail = "auth $auth, key $(if ($hasKey) { 'CAPTURED -> raw\wifi' } else { 'not stored' })"; Risk = 'LOW' } # v2.64: dead ternary collapsed (both branches LOW)
                } catch { }
            }
            # DPAPI vault + protect blobs (analyst-side decryption) per user
            $vaultCount = 0
            foreach ($u in (@(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|All Users' }))) {
                foreach ($sub in @('AppData\Local\Microsoft\Credentials', 'AppData\Roaming\Microsoft\Credentials', 'AppData\Local\Microsoft\Protect')) {
                    $src = Join-Path $u.FullName $sub
                    if (-not (Test-Path $src)) { continue }
                    $files = @(Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction SilentlyContinue)
                    if ($files.Count -eq 0) { continue }
                    $d = Join-Path $RawDir "vault\$($u.Name)\$([IO.Path]::GetFileName($sub))"
                    New-Item -ItemType Directory -Path $d -Force | Out-Null
                    $files | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                    $vaultCount += $files.Count
                }
            }
            if ($vaultCount -gt 0) { $rows += [pscustomobject]@{ Item = 'DPAPI vault blobs'; Detail = "$vaultCount credential/protect blob(s) -> raw\vault (analyst-side decrypt)"; Risk = 'MEDIUM' } }
            # LSASS dump hunt - shallow, fast, well-known drop spots (recorded, never copied)
            $dmpRoots = @("$env:TEMP", "$env:SystemRoot\Temp", "$env:ProgramData")
            foreach ($u in (@(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|All Users' }))) {
                $dmpRoots += @((Join-Path $u.FullName 'AppData\Local\Temp'), (Join-Path $u.FullName 'Documents'), (Join-Path $u.FullName 'Desktop'))
            }
            $dmp = @()
            foreach ($root in $dmpRoots) {
                if (-not $root -or -not (Test-Path $root)) { continue }
                try { $dmp += @(Get-ChildItem -LiteralPath $root -Filter '*.dmp' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)lsass|dump' }) } catch { }
                if (@($dmp).Count -ge 10) { break }
            }
            foreach ($f in (($dmp | Sort-Object FullName -Unique) | Select-Object -First 10)) {
                $rows += [pscustomobject]@{ Item = 'Possible credential dump on disk'; Detail = "$($f.FullName) ($([math]::Round($f.Length / 1MB, 1)) MB)"; Risk = 'HIGH' }
            }
            Save-Rows -Name 'credential_sweep' -Rows $rows
            $hot = @($rows | Where-Object { "$($_.Risk)" -eq 'HIGH' }).Count
            if ($rows.Count -gt 0) {
                Write-CaseLog "    credential sweep: $($rows.Count) finding(s) ($hot HIGH) -> csv\credential_sweep.csv" $(if ($hot -gt 0) { 'Red' } else { 'Gray' })
            } else {
                Write-CaseLog '    credential sweep: no exposure findings (no auto-logon, no WLAN keys, no vault blobs, no dumps)' 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.16'; Cat = 'CONTEXT'; Name = 'Remote access sweep (tunnel tools, RA services, RDP ServiceDll, SSH keys, RA logs)'; Default = $true; Quick = $false;
        Run = {
            # Evidence surface for hunt rules R23-R26 (csv\remote_access.csv): tunnels and
            # remote-access tools as services, RDP ServiceDll tamper, SSH authorized_keys,
            # RA tool install/log dirs (logs preserved to raw\ra_logs - vendors rotate them fast).
            $ra = New-Object System.Collections.Generic.List[object]
            # NOTE: keep in sync with $tunPat/$raPat in New-HuntFindings (R23-R26)
            $tunPat = '(?i)(^|[^a-z0-9])(ngrok|cloudflared|tailscaled?|chisel|ligolo|frpc|frps|gost|revsocks)([^a-z0-9]|$)'
            $raPat = '(?i)(^|[^a-z0-9])(anydesk|screenconnect|connectwisecontrol|teamviewer|rustdesk)([^a-z0-9]|$)'

            # 1) one service enumeration: tunnel + RA tool matches, sshd presence
            $svcs = @()
            try { $svcs = @(Get-WmiOrCim -Class Win32_Service) } catch { }
            foreach ($s in $svcs) {
                $blob = "$($s.Name) $($s.DisplayName) $($s.PathName)"
                $kind = ''
                if ($blob -match $tunPat) { $kind = 'Tunnel service' } elseif ($blob -match $raPat) { $kind = 'RA tool service' }
                if (-not $kind) { continue }
                $state = "$($s.State)"
                $null = $ra.Add([pscustomobject]@{
                    Type = $kind; Name = "$($s.Name)"; State = $(if ($state -eq 'Running') { 'running' } else { $state })
                    Path = "$($s.PathName)"; Detail = "display '$($s.DisplayName)' | start $($s.StartMode) | account $($s.StartName)"
                })
            }
            if (@($svcs | Where-Object { "$($_.Name)" -eq 'sshd' }).Count -gt 0) {
                $sshState = "$(@($svcs | Where-Object { "$($_.Name)" -eq 'sshd' })[0].State)"
                $null = $ra.Add([pscustomobject]@{ Type = 'SSH server'; Name = 'sshd'; State = $sshState; Path = "$env:SystemRoot\System32\OpenSSH"; Detail = 'OpenSSH server present - authorized_keys below are live trust anchors' })
            }

            # 2) RDP ServiceDll tamper (RDPWrap-class): the registered DLL must be termsrv.dll
            try {
                $svcDll = "$((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters' -Name ServiceDll -ErrorAction Stop).ServiceDll)"
                if ($svcDll -and $svcDll -notmatch '(?i)\\termsrv\.dll$') {
                    $null = $ra.Add([pscustomobject]@{ Type = 'RDP ServiceDll tamper'; Name = 'TermService'; State = 'tampered'; Path = $svcDll; Detail = 'ServiceDll is not termsrv.dll - RDPWrap-class hijack (multi-session RDP on non-server)' })
                }
            } catch { }

            # 3) authorized_keys: programdata ssh + per-profile .ssh (non-empty = planted trust)
            $akSeen = @()
            $pdSsh = Join-Path $env:ProgramData 'ssh'
            if (Test-Path $pdSsh) { $akSeen += @(Get-ChildItem -LiteralPath $pdSsh -Filter '*authorized_keys*' -File -ErrorAction SilentlyContinue | ForEach-Object { @{ File = $_; Tag = 'programdata' } }) }
            foreach ($u in @(Get-UserProfileList)) {
                $sshDir = Join-Path "$($u.Path)" '.ssh'
                if (Test-Path $sshDir) { $akSeen += @(Get-ChildItem -LiteralPath $sshDir -Filter '*authorized_keys*' -File -ErrorAction SilentlyContinue | ForEach-Object { @{ File = $_; Tag = "$($u.User -replace '[^\w]', '_')" } }) }
            }
            foreach ($ak in $akSeen) {
                $f = $ak.File
                $keyLines = @()
                $readable = $true
                try { $keyLines = @(Get-Content -LiteralPath $f.FullName -ErrorAction Stop | Where-Object { "$($_)" -and "$($_.Trim())" -notmatch '^(#|$)' }) } catch { $readable = $false }
                $sha = ''
                try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                $state = if (-not $readable) { 'unreadable (access denied)' } elseif ($keyLines.Count -gt 0) { "populated ($($keyLines.Count) key line(s))" } else { 'empty/comments-only' }
                $null = $ra.Add([pscustomobject]@{
                    Type = 'SSH authorized_keys'; Name = $f.Name; State = $state; Path = $f.FullName
                    Detail = "profile $($ak.Tag)$(if ($sha) { " | sha256 $sha" })$(if ($keyLines.Count -gt 0) { ' | content -> raw\ra_logs' })"
                })
                if ($keyLines.Count -gt 0) {
                    try { Out-RawText -SubDir 'ra_logs' -Name ("authorized_keys_" + $ak.Tag + "_" + $f.Name + ".txt") -Text (@(Get-Content -LiteralPath $f.FullName) | ForEach-Object { "$_" }) } catch { }
                }
            }

            # 4) RA tool data dirs under ProgramData - preserve logs/configs to raw\ra_logs
            foreach ($d in @(Get-ChildItem $env:ProgramData -Directory -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -match $raPat })) {
                $files = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 20MB -and "$($_.Name)" -match '(?i)\.(log|trace|txt|xml|conf|config|ad)$|connections' } | Select-Object -First 40)
                if ($files.Count -gt 0) {
                    $dest = Join-Path $RawDir ("ra_logs\" + ($d.Name -replace '[^\w]', '_'))
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    $files | Copy-Item -Destination $dest -Force -ErrorAction SilentlyContinue
                }
                $null = $ra.Add([pscustomobject]@{
                    Type = 'RA tool data dir'; Name = $d.Name; State = 'present'; Path = $d.FullName
                    Detail = "$(if ($files.Count -gt 0) { "$($files.Count) evidence file(s) -> raw\ra_logs\$($d.Name -replace '[^\w]', '_')" } else { 'no retained logs' })"
                })
            }

            Save-Rows -Name 'remote_access' -Rows $ra.ToArray()
            $notable = @($ra | Where-Object { "$($_.Type)" -match 'Tunnel|tamper|SSH server|authorized_keys' -or "$($_.State)" -match 'running|tampered' }).Count
            if ($ra.Count -gt 0) {
                Write-CaseLog "    remote access sweep: $($ra.Count) row(s) ($notable notable) -> csv\remote_access.csv" $(if ($notable -gt 0) { 'Yellow' } else { 'Gray' })
            } else {
                Write-CaseLog '    remote access sweep: no tunnels, RA tools, RDP tamper or SSH keys found' 'Gray'
            }
        } }
)

function Get-FilteredEvents {
    param([string]$LogName, [int[]]$Ids, $Start, [int]$MaxMsg = 500)
    try {
        $filter = @{ LogName = $LogName; Id = $Ids }
        if ($Start) { $filter.StartTime = $Start }
        if ($script:LogEndDT) { $filter.EndTime = $script:LogEndDT }
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $events) { return @() }
        $rows = foreach ($e in $events) {
            $msg = ''
            try { $msg = ($e.Message -replace '\s+', ' '); if ($msg.Length -gt $MaxMsg) { $msg = $msg.Substring(0, $MaxMsg) + '...' } } catch { }
            [pscustomobject]@{ TimeCreated = $e.TimeCreated; Id = $e.Id; Provider = $e.ProviderName; Level = $e.LevelDisplayName; Message = $msg }
        }
        return $rows
    } catch { return @() }
}

function Export-Evtx {
    param([string]$LogName, [string]$FileName)
    try {
        $dir = Join-Path $RawDir 'evtx'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $dest = Join-Path $dir $FileName
        & wevtutil.exe epl $LogName "$dest" /ow:true 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $mb = [math]::Round((Get-Item $dest -ErrorAction SilentlyContinue).Length / 1MB, 1)
            Write-CaseLog "    evtx: $FileName ($mb MB)" 'Gray'
        } else {
            Write-CaseLog "    evtx export failed: $LogName" 'DarkYellow'
        }
    } catch { Write-CaseLog "    evtx export error: $LogName" 'DarkYellow' }
}

function Get-EventDataRows {
    # Structured EventData extraction for security/sysmon event IDs (XML fields, newest-first, capped).
    param([string]$LogName, [int[]]$Id, $Fields, $Start, [int]$Cap = 3000)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $filter = @{ LogName = $LogName; Id = $Id }
        if ($Start) { $filter.StartTime = $Start }
        if ($script:LogEndDT) { $filter.EndTime = $script:LogEndDT }
        $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $raw) { return @() }
        foreach ($e in ($raw | Select-Object -First $Cap)) {
            $d = @{}
            try {
                $x = [xml]$e.ToXml()
                $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            } catch { }
            $o = [ordered]@{ Time = $e.TimeCreated; EventId = $e.Id }
            foreach ($k in $Fields.Keys) { $o[$k] = "$($d[$Fields[$k]])" }
            $null = $rows.Add([pscustomobject]$o)
        }
    } catch { }
    return $rows.ToArray()
}

function Get-IisW3cRows {
    # Minimal IIS W3C log parser: fields from the #Fields directive, newest files first, rows capped.
    param([string]$Path, [int]$Cap = 10000)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10)) {
            $fields = $null
            foreach ($line in (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
                if ($line -match '^#Fields:\s*(.+)$') { $fields = ($Matches[1] -split '\s+'); continue }
                if (-not $fields -or $line -match '^#') { continue }
                $p = $line -split ' '
                if ($p.Count -lt $fields.Count) { continue }
                $o = [ordered]@{ }
                for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $p[$i] }
                $null = $rows.Add([pscustomobject]$o)
                if ($rows.Count -ge $Cap) { return $rows.ToArray() }
            }
        }
    } catch { }
    return $rows.ToArray()
}

function Get-StartupInfoRows {
    # StartupInfo XMLs (System32\WDI\LogFiles\StartupInfo\*.xml): per-session user app launches.
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
            $x = $null
            try { $x = [xml](Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) } catch { continue }
            $apps = @()
            try { $apps = @($x.SelectNodes('//*[local-name()="Application"]')) } catch { }
            foreach ($a in $apps) {
                $p2 = $a.Attributes.GetNamedItem('Path')
                if (-not $p2) { continue }
                $cnt = $a.Attributes.GetNamedItem('ExecutionCount')
                $lt = $a.Attributes.GetNamedItem('LastExecutionTime')
                $null = $rows.Add([pscustomobject]@{ File = $f.Name; App = "$($p2.Value)"; Count = $(if ($cnt) { "$($cnt.Value)" } else { '' }); LastRun = $(if ($lt) { "$($lt.Value)" } else { '' }) })
            }
        }
    } catch { }
    return $rows.ToArray()
}

function Get-WerReportRows {
    # Report.wer text files (UTF-16 key=value): faulting app/module + event time (FILETIME ticks).
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter 'Report.wer' -File -Recurse -ErrorAction SilentlyContinue)) {
            $kv = @{}
            try {
                foreach ($line in (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
                    if ($line -match '^([A-Za-z0-9\[\]\.]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
                }
            } catch { continue }
            $app = ''
            foreach ($k in @('AppPath', 'TargetAppPath', 'Sig[0].Value')) { if ($kv.ContainsKey($k) -and $kv[$k]) { $app = $kv[$k]; break } }
            $mod = ''
            foreach ($k in @('FaultingModule', 'Sig[1].Value', 'Sig[3].Value')) { if ($kv.ContainsKey($k) -and $kv[$k]) { $mod = $kv[$k]; break } }
            $t = ''
            if ($kv.ContainsKey('EventTime') -and $kv['EventTime']) {
                try { $t = [datetime]::FromFileTimeUtc([long]$kv['EventTime']).ToString('s') } catch { }
            }
            $rel = $f.FullName
            try { $rel = $f.FullName.Substring($Path.Length).TrimStart('\') } catch { }
            $null = $rows.Add([pscustomobject]@{ Time = $t; App = $app; Module = $mod; File = $rel })
        }
    } catch { }
    return $rows.ToArray()
}

function Get-PresetSelection {
    param([string]$P)
    $sel = @{}
    foreach ($m in $script:Modules) { $sel[$m.Id] = $false }
    switch ($P) {
        'Flash' { }
        'Quick' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Quick } }
        'Standard' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
        'Full' {
            foreach ($m in $script:Modules) { $sel[$m.Id] = (@('3.2', '7.1') -notcontains $m.Id) }
        }
        default { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
    }
    if ($IncludeMemory) { $sel['7.1'] = $true }
    # v2.21 role packs: explicit DC/WebServer presets force role modules on; Standard/Full auto-enable on the detected role
    $rolePack = ''
    if ($P -eq 'DC') { $rolePack = '4.9' }
    elseif ($P -eq 'WebServer') { $rolePack = '8.12' }
    elseif (($P -eq 'Standard' -or $P -eq 'Full') -and $script:HostRole -ne 'Workstation') {
        $rolePack = if ($script:HostRole -eq 'DC') { '4.9' } else { '8.12' }
    }
    if ($rolePack -and $sel.ContainsKey($rolePack)) { $sel[$rolePack] = $true }
    return $sel
}

function Show-Menu {
    param([hashtable]$Selection)
    $cats = ($script:Modules | Group-Object Cat | ForEach-Object { $_.Name })
    $range = Get-LogRangeText
    $count = 0
    $byId = @{}
    $script:Modules | ForEach-Object { $byId[$_.Id] = $count; $count++ }
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  OPHIRA v$ScriptVersion   |   $Computer   |   Role: $script:HostRole   |   Log range: $range" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        $n = 0
        foreach ($cat in $cats) {
            Write-Host ""
            Write-Host ("  {0}" -f $cat) -ForegroundColor White
            foreach ($m in ($script:Modules | Where-Object { $_.Cat -eq $cat })) {
                $mark = if ($Selection[$m.Id]) { '[X]' } else { '[ ]' }
                $color = if ($Selection[$m.Id]) { 'Yellow' } else { 'Gray' }
                $note = if (@('3.2') -contains $m.Id) { '  <-- ACTIVE traffic' } elseif ($m.Id -eq '7.1') { '  <-- GB-size' } else { '' }
                Write-Host ("   $mark {0,-4} {1}{2}" -f $m.Id, $m.Name, $note) -ForegroundColor $color
            }
        }
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  <id>  toggle item (e.g. 4.1)   |  <cat#> toggle whole category (e.g. 4)" -ForegroundColor White
        Write-Host "  all | none | T=change log range | R=RUN | Q=quit (no collection)" -ForegroundColor White
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Command"
        switch -Regex ($inp) {
            '^(?i)all$' { foreach ($m in $script:Modules) { $Selection[$m.Id] = $true } }
            '^(?i)none$' { foreach ($m in $script:Modules) { $Selection[$m.Id] = $false } }
            '^(?i)t$' {
                $script:LogStartDT = $null
                $script:LogEndDT = $null
                if ($LogHours -eq 168) { $script:LogHours = 24 }
                elseif ($LogHours -eq 24) { $script:LogHours = 720 }
                elseif ($LogHours -eq 720) { $script:LogHours = 0 }
                else { $script:LogHours = 168 }
                $range = Get-LogRangeText
            }
            '^(?i)r$' { return $Selection }
            '^(?i)q$' { return $null }
            '^(?i)\d+\.\d+$' {
                if ($Selection.ContainsKey($inp.ToUpper())) { $Selection[$inp.ToUpper()] = -not $Selection[$inp.ToUpper()] }
                elseif ($Selection.ContainsKey($inp)) { $Selection[$inp] = -not $Selection[$inp] }
            }
            '^(?i)\d$' {
                foreach ($m in ($script:Modules | Where-Object { $_.Id -like "$inp.*" })) { $Selection[$m.Id] = -not ($Selection[$m.Id]) }
            }
            default { }
        }
    }
}

function Invoke-SelectedModules {
    param([hashtable]$Selection)
    $selected = @($script:Modules | Where-Object { $Selection[$_.Id] })
    $total = $selected.Count
    $done = 0
    $script:ModuleTimings = @()
    $phaseOf = {
        param($m)
        if ($m.Cat -eq 'VOLATILE') { 'A' }
        elseif (@('7.1', '7.2', '4.7', '4.8') -contains $m.Id) { 'CI' }
        elseif (@('4.6', '5.4', '5.5', '8.4') -contains $m.Id) { 'C' }
        else { 'B' }
    }
    $runInline = {
        param($m)
        $script:Progress++
        if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host "" }
        Write-CaseLog ("[{0}/{1}] Module {2}: {3}" -f $script:Progress, $total, $m.Id, $m.Name) 'Cyan'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        # v2.69 (F1): capture this module's artifact saves for the RUN detail line (printed
        # AFTER the run with real numbers; the [x/y] line above stays as the instant feedback)
        $script:SavedArtifacts.Clear()
        try {
            & $m.Run
            $sw.Stop()
            $script:ModuleTimings += [pscustomobject]@{ Id = $m.Id; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Mode = 'inline' }
            Write-CaseLog ("    done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) 'DarkGreen'
            Write-RunDetail -Id $m.Id -Name $m.Name -Seconds $sw.Elapsed.TotalSeconds -Saved $script:SavedArtifacts.ToArray()
        } catch {
            $sw.Stop()
            $script:ModuleTimings += [pscustomobject]@{ Id = $m.Id; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Mode = 'inline' }
            Write-CaseLog ("    ERROR: {0}" -f $_.Exception.Message) 'Red'
            # v2.69 (F1): failed modules still get their detail line (ERROR + elapsed; the
            # Saved argument is accepted for signature symmetry but the ERROR text wins)
            Write-RunDetail -Id $m.Id -Name $m.Name -Seconds $sw.Elapsed.TotalSeconds -ErrMsg $_.Exception.Message -Saved $script:SavedArtifacts.ToArray()
        }
    }
    if ($Sequential -or $script:SimpleUI) {
        $script:Progress = 0
        if ($script:SimpleUI) {
            $friendly = @{
                'VOLATILE'    = 'Checking what is running right now'
                'PERSISTENCE' = 'Checking how malware could survive a reboot'
                'NETWORK MAP' = 'Mapping network connections'
                'LOGS'        = 'Reviewing Windows security logs'
                'ARTIFACTS'   = 'Preserving forensic evidence'
                'CONTEXT'     = 'Collecting attacker activity traces'
                'DEFENDER'    = 'Checking antivirus history'
                'MEMORY'      = 'Capturing memory (the long step)'
            }
            $cats = @($selected | Group-Object Cat | ForEach-Object { $_.Name })
            $step = 0
            $swAll = [System.Diagnostics.Stopwatch]::StartNew()
            foreach ($cat in $cats) {
                $step++
                Write-Host ""
                Write-Host ("  Step {0}/{1}: {2}..." -f $step, $cats.Count, $friendly[$cat]) -ForegroundColor Cyan
                foreach ($m in ($selected | Where-Object { $_.Cat -eq $cat })) { & $runInline $m }
            }
            $swAll.Stop()
            Write-Host ""
            Write-Host ("  All steps finished in {0:N0} seconds. Packaging results..." -f $swAll.Elapsed.TotalSeconds) -ForegroundColor Cyan
        } else {
            foreach ($m in $selected) { & $runInline $m }
        }
        return
    }
    $phases = @{
        A = @($selected | Where-Object { (& $phaseOf $_) -eq 'A' })
        B = @($selected | Where-Object { (& $phaseOf $_) -eq 'B' })
        C = @($selected | Where-Object { (& $phaseOf $_) -eq 'C' })
        CI = @($selected | Where-Object { (& $phaseOf $_) -eq 'CI' })
    }
    $script:Progress = 0
    if ($phases.A.Count -gt 0) {
        Write-Host "`n--- Phase A: volatile (sequential, order of volatility) ---" -ForegroundColor Cyan
        foreach ($m in $phases.A) { & $runInline $m }
    }
    if ($phases.B.Count -gt 0) {
        Write-Host "`n--- Phase B: collection (parallel): $(($phases.B.Id) -join ' ') ---" -ForegroundColor Cyan
        $script:Progress += 0
        $r = Invoke-ModuleBatch -Batch $phases.B -Workers 4
        # v2.69 (F1): per-module RUN detail after the batch - records carry Saved from the worker
        foreach ($x in @($r | Sort-Object { [version]$_.Id })) {
            $script:ModuleTimings += [pscustomobject]@{ Id = $x.Id; Seconds = $x.Seconds; Mode = 'parallel' }
            Write-RunDetail -Id $x.Id -Name $x.Name -Seconds $x.Seconds -ErrMsg "$($x.Error)" -Saved $x.Saved
        }
        $script:Progress += $phases.B.Count
    }
    if ($phases.C.Count -gt 0) {
        Write-Host "`n--- Phase C: heavy analytics (parallel): $(($phases.C.Id) -join ' ') ---" -ForegroundColor Cyan
        $r = Invoke-ModuleBatch -Batch $phases.C -Workers 4
        foreach ($x in @($r | Sort-Object { [version]$_.Id })) {
            $script:ModuleTimings += [pscustomobject]@{ Id = $x.Id; Seconds = $x.Seconds; Mode = 'parallel' }
            Write-RunDetail -Id $x.Id -Name $x.Name -Seconds $x.Seconds -ErrMsg "$($x.Error)" -Saved $x.Saved
        }
        $script:Progress += $phases.C.Count
    }
    if ($phases.CI.Count -gt 0) {
        Write-Host "`n--- Phase CI: interactive (memory) ---" -ForegroundColor Cyan
        foreach ($m in $phases.CI) { & $runInline $m }
    }
}

function ConvertTo-HtmlEsc {
    param([string]$s)
    if ($null -eq $s) { return '' }
    # v2.80 (I4): single quote escaped too - New-VtLink interpolates into SINGLE-quoted href
    # attributes, so the escaper must cover both quote styles. '&' runs first and the entities
    # emitted here contain no quotes, so the chain stays double-escape-safe.
    return ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;')
}

function New-VtLink {
    # v2.67 (B1): file paths and executable/document filenames no longer become VT search
    # links - the old dotted-suffix test matched ANY dotted filename (OneDrive.exe rendered
    # as a VT link in real reports). Hashes, IPv4 addresses and real domains still link.
    # ponytail: '.com'/'.zip' stay domain-only (real TLDs); a bare 'file.com' filename links too.
    param([string]$Indicator, [string]$Label = '')
    $i = ConvertTo-HtmlEsc $Indicator
    $lbl = if ($Label) { ConvertTo-HtmlEsc $Label } else { $i }
    $isPathy = ("$Indicator") -match '[\\/]' -or ("$Indicator") -match '\s'
    $isExeName = ("$Indicator") -match '\.(exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|jar|scr|pif|hta|msi|msp|mst|cpl|drv|ocx|lnk|mui|tmp|dat|log|txt|doc|docx|xls|xlsx|pdf|zip|7z|rar|gz|iso|img|bin)$'
    if (-not $isPathy -and -not $isExeName -and ($Indicator -match '^[a-fA-F0-9]{32,64}$' -or $Indicator -match '^(\d{1,3}\.){3}\d{1,3}$' -or $Indicator -match '\.[a-z]{2,}$')) {
        return "<a target='_blank' href='https://www.virustotal.com/gui/search/$i'>VT&nearr;</a>"
    }
    return $lbl
}

# v2.67 (B5): blank CSV cells must not abort New-HtmlReport - one non-numeric/overflowing
# cell (e.g. a 5-billion SRUM counter) used to throw mid-render and silently drop an entire
# report block (the leads try/catch swallowed it whole). Blank/whitespace means "no data" -
# return the caller's default; anything unparsable degrades to it too.
function ConvertTo-SafeInt {
    param([string]$Value, [int]$Default = 0)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    try { return [int]$Value } catch { return $Default }
}

function ConvertTo-SafeDbl {
    param([string]$Value, [double]$Default = 0)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    try { return [double]$Value } catch { return $Default }
}

function Get-SectionAnchorForSource {
    # v2.56: maps an artifact/source name to the report section that shows its evidence,
    # so entity cards and evidence rows can link "this row came from X" straight to X.
    # v2.67 (B2): entity evidence uses CATEGORY tokens (svc-persist, 4688-exec, ...) the
    # artifact-name regex never matched - almost every chip rendered dead. Exact-match
    # vocabulary first (plain hash lookup; artifact names still fall through to the switch
    # unchanged). Token targets verified against the rendered report: 4688 / share-access rows
    # render only in the supertimeline weave (iis_anomalies renders nowhere - its underlying
    # iis_requests rows render in the weave); SRUM's "Top network consumers" table
    # renders inside the entities section, not network.
    # v2.67 (B4): memory_live_scan renders in the hunt section (live memory triage table), not
    # the snapshot - exact entry wins over the generic ^(entities_|memory_) arm. memory_netscan
    # stays unmapped (CSV-only, never rendered - honest grey chip); memory_malfind keeps snapshot.
    param([string]$Source)
    $catMap = @{
        'running' = 'processes'; 'hash' = 'processes'; 'verdict' = 'processes'
        '4688-exec' = 'timeline'; 'share-staging' = 'timeline'; 'web-anomaly' = 'timeline'
        'beacon' = 'beacons'; 'conn' = 'network'; 'srum-usage' = 'entities'
        'svc-persist' = 'persistence'; 'task-persist' = 'persistence'; 'autorun-persist' = 'persistence'
        'mft-created' = 'filesystem'; 'loldriver' = 'drivers'; 'ioc' = 'ioc'; 'yara' = 'yara'
        'sigma' = 'sigma'; 'hunt' = 'hunt'
        'memory_live_scan' = 'hunt'; 'memory_netscan' = ''
    }
    if ($catMap.ContainsKey("$Source")) { return $catMap["$Source"] }
    switch -Regex ("$Source") {
        '^(hayabusa|sigma)'                            { 'sigma'; break }
        '^yara'                                        { 'yara'; break }
        '^(beacon_candidates|dns_beacon_candidates)'   { 'beacons'; break }
        '^(hunt_findings)'                             { 'hunt'; break }
        '^(ioc_hits|flash_ioc_hits)'                   { 'ioc'; break }
        '^(flash_process_scored|processes|process_hashes|sysmon_proc_create|sysmon_proc_tamper)' { 'processes'; break }
        '^(security_auth|bruteforce|rdp_|logon)'       { 'logons'; break }
        '^(autoruns|asep|services|scheduled_task|task_deletions|esent_ntds)' { 'persistence'; break }
        '^(radar_exec|appswitched)'                    { 'snapshot'; break }
        '^(mft_recent|usn_write_bursts|prefetch|shellbags|sysmon_file)' { 'filesystem'; break }
        '^(flash_public_connections|connections|sysmon_network|srum_|net_)' { 'network'; break }
        '^(sysmon_dns|dns_)'                           { 'beacons'; break }
        '^(loldrivers|drivers)'                        { 'drivers'; break }
        '^(supertimeline|execution_timeline|shimcache|amcache|bam|userassist|recentfilecache)' { 'timeline'; break }
        '^(entities_|memory_)'                         { 'snapshot'; break }
        default { '' }
    }
}

function ConvertTo-CaseFileLink {
    # v2.56: render a case file path as a clickable link (falls back to plain text when the
    # file does not exist - a report may be copied off the analyst box).
    # v2.66 (B2): hrefs are case-RELATIVE - absolute file:///E:/ hrefs were dead in an emailed
    # report, leaked the analyst's disk layout, and broke when the case folder moved. The report
    # sits at the case root, so children resolve to csv/..., raw/... with forward slashes. The
    # visible label text and the file-exists link-vs-plain-text decision are unchanged; anything
    # outside the case root (or a missing case root) degrades to plain text - never an absolute path.
    param([string]$Path, [string]$Text = '')
    $txt = if ($Text) { $Text } else { $Path }
    if (-not "$Path" -or -not (Test-Path -LiteralPath $Path)) { return (ConvertTo-HtmlEsc $txt) }
    $rel = ''
    try {
        $full = [IO.Path]::GetFullPath("$Path")
        if ("$CaseDir") {
            $root = [IO.Path]::GetFullPath("$CaseDir").TrimEnd('\', '/')
            if ($root -and $full.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) {
                $rel = $full.Substring($root.Length + 1) -replace '\\', '/'
                if (Test-Path -LiteralPath $full -PathType Container) { $rel += '/' } # keep the old file:/// dir semantics (trailing slash)
            }
        }
    } catch { }
    if (-not $rel) { return (ConvertTo-HtmlEsc $txt) }
    return "<a href='$rel'>$(ConvertTo-HtmlEsc $txt)</a>"
}

function Get-LvlRank {
    # Top-level (was nested in New-HtmlReport): also used by New-SigmaRuleLogs and fleet reporting.
    param([string]$l)
    switch -Regex ("$l") { 'crit' { 5; break } 'high' { 4; break } 'med' { 3; break } 'low' { 2; break } default { 1 } }
}

function Get-SafeRuleKey {
    # Filesystem/js-safe key for a Sigma rule name - the exact charset/sanitize the per-rule
    # CSV filenames have always used ('unnamed_rule' fallback, 80-char truncate).
    param([string]$Name)
    $safe = ("$Name" -replace '[^A-Za-z0-9\._-]+', '_') -replace '^_+|_+$', ''
    if (-not $safe) { $safe = 'unnamed_rule' }
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
    return $safe
}

function Get-SafeRuleKeyMap {
    # raw rule name -> collision-free safe key. Two distinct rule names can sanitize to the
    # same key (collisions merged drill-downs / overwrote per-rule CSVs); colliding names get
    # a deterministic _2/_3 suffix, unique names keep today's key. All scopes that share a
    # name universe (report drills/leads/ATT&CK + New-SigmaRuleLogs per-rule CSVs) must build
    # their map from the SAME rows so keys stay consistent across report and CSVs.
    param($Rows, [string]$NameCol)
    $map = @{}
    $byKey = @{}
    foreach ($nm in @($Rows | ForEach-Object { "$($_.$NameCol)" } | Sort-Object -Unique)) {
        $k = Get-SafeRuleKey $nm
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[string] }
        $null = $byKey[$k].Add($nm)
    }
    foreach ($k in ($byKey.Keys | Sort-Object)) {
        $i = 1
        foreach ($nm in $byKey[$k].ToArray()) {
            $cand = $k
            if ($i -gt 1) { $cand = "${k}_$i" }
            while ($map.ContainsValue($cand)) { $i++; $cand = "${k}_$i" }
            $map[$nm] = $cand
            $i++
        }
    }
    return $map
}

function Resolve-SafeRuleKey {
    param($Map, [string]$Name)
    $n = "$Name"
    if ($Map -and $Map.ContainsKey($n)) { return $Map[$n] }
    return Get-SafeRuleKey $n
}

function Get-TacticLabel {
    param([string]$abbr)
    $tacticNames = @{
        'Recon' = 'Reconnaissance'; 'ResDevDev' = 'Resource Development'; 'InitAccess' = 'Initial Access'
        'Exec' = 'Execution'; 'Persis' = 'Persistence'; 'PrivEsc' = 'Privilege Escalation'
        'DefEvade' = 'Defense Evasion'; 'CredAccess' = 'Credential Access'; 'Disc' = 'Discovery'
        'LatMov' = 'Lateral Movement'; 'Collect' = 'Collection'; 'C2' = 'Command and Control'
        'Exfil' = 'Exfiltration'; 'Impact' = 'Impact'; 'ImpairC2' = 'Impair Command and Control'; 'ImpairProc' = 'Impair Process'
    }
    $a = "$abbr".Trim()
    if ($tacticNames.ContainsKey($a)) { return $tacticNames[$a] }
    return $a
}

function Split-TagList {
    param([string]$s)
    if (-not "$s") { return @() }
    return @([regex]::Split("$s", '[^A-Za-z0-9.\-]+') | Where-Object { $_ -and $_.Length -gt 1 })
}

function Test-SigmaSelfNoise {
    # v2.55: a Sigma row is self-noise when it fired on Ophira's own collection activity -
    # our PIDs (captured at collection start) or our kit/case paths in the event text.
    # Never filter by process name alone (powershell.exe is both the attacker's and our tool).
    param($row)
    if ($null -eq $row) { return $false }
    $pidName = @($row.PSObject.Properties.Name | Where-Object { $_ -match '^processid$' } | Select-Object -First 1)
    if ($pidName -and $script:CollectorPids) {
        $rowPid = 0
        try { $rowPid = [int]"$($row.$pidName)" } catch { $rowPid = 0 }
        if ($rowPid -gt 0 -and @($script:CollectorPids) -contains $rowPid) { return $true }
    }
    $text = "$($row.Details) $($row.ExtraFieldInfo) $($row.CommandLine) $($row.Payload)"
    if ($script:KitPaths) {
        foreach ($kp in @($script:KitPaths)) {
            if ($kp -and $text.IndexOf($kp, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }
    return $false
}

function Remove-SigmaDuplicateEvents {
    # v2.55: two Sigma rules can fire on the SAME event (e.g. both 4648-explicit-logon rules
    # match every EID 4648). Dedupe by RecordID so one event counts once across all rules.
    param([object[]]$rows)
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rows)) {
        $rid = "$($r.RecordID)"
        if (-not $rid) { $out.Add($r); continue }
        $key = "$($r.Computer)|$rid"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $out.Add($r)
    }
    return $out.ToArray()
}

function Import-CaseCsv {
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $f = Join-Path $CsvDir $Name
    if (-not (Test-Path -LiteralPath $f)) { $f = Join-Path $CsvDir (Get-CaseCsvPath $Name) }
    # v2.65: -LiteralPath (case paths can carry [ ] wildcard chars) and the whole read inside
    # the try - a file locked by another process yields @(), it never kills the caller.
    # Asymmetry with Test-CaseCsv is intentional (see there). A Save-Rows failure marker
    # ("FAILED: <reason>", whole file) is not a parseable CSV: return @() and warn honestly.
    try {
        if (Test-Path -LiteralPath $f) {
            $first = Get-Content -LiteralPath $f -First 1
            if ("$first" -match '^FAILED:') {
                Write-CaseLog ("    csv\{0}: artifact FAILED to save during collection - {1}" -f $Name, ("$first" -replace '^(?i)FAILED:\s*', '')) 'DarkYellow'
                return @()
            }
            if ("$first" -notmatch '^#') { return @(Import-Csv -LiteralPath $f) }
        }
    } catch { return @() }
    return @()
}

function Get-CleanCheckSummary {
    # v2.61: the negative-evidence half of "is it infected?". A clean verdict is only defensible
    # if the report shows WHICH checks produced it - every engine that ran and found nothing
    # renders as "check - N examined, 0 flagged" (count included only where the data carries one).
    # Checks WITH findings are omitted here: they already render as verdict signals + sections.
    # Report-side only - reads existing CSVs, no new collection, works on old cases via -Mode Parse.
    # v2.63: -HayRows lets the report pass its already-imported Sigma rows so the big CSV is read
    # once per run; absent (external callers) the CSV is imported here as before.
    param([object[]]$HayRows = $null)
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param([string]$check, [string]$detail) $out.Add([pscustomobject]@{ Check = $check; Detail = $detail }) }

    # Sigma: total events vs critical/high (same dedupe + self-noise filter as the verdict/report)
    if ($null -ne $HayRows) { $hay = @($HayRows) } else { $hay = @(Import-CaseCsv 'hayabusa_timeline') }
    if ($hay.Count -gt 0) {
        if (Get-Command Remove-SigmaDuplicateEvents -ErrorAction SilentlyContinue) {
            $hay = @(Remove-SigmaDuplicateEvents $hay | Where-Object { -not (Test-SigmaSelfNoise $_) })
        }
        $flags = @($hay | Where-Object { "$($_.Level)" -match '^(crit|high)$' })
        if ($flags.Count -eq 0) { & $add 'Sigma rule scan' "$($hay.Count) events scanned, 0 critical/high detections" }
    }
    # YARA
    $ySc = @(Import-CaseCsv 'yara_scanned')
    if ($ySc.Count -gt 0 -and @(Import-CaseCsv 'yara_hits').Count -eq 0) { & $add 'YARA scan' "$($ySc.Count) binaries scanned, 0 matched" }
    # IOC feed cross-referenced across every surface
    $iHit = 0
    foreach ($s in @('flash_ioc_hits', 'ioc_hits_amcache', 'ioc_hits_dns', 'ioc_hits_network', 'ioc_hits_mft', 'ioc_hits_hash', 'ioc_hits_browser')) { $iHit += @(Import-CaseCsv $s).Count }
    $feed = $null
    try { $feed = Get-IocList } catch { }
    if ($feed) {
        $feedN = $feed.Hashes.Count + $feed.Ips.Count + $feed.Domains.Count + $feed.Names.Count
        if ($iHit -eq 0 -and $feedN -gt 0) { & $add 'IOC feed cross-reference' "$feedN indicators checked across live system, amcache, DNS, network, MFT, hashes and browser history - 0 matches" }
    }
    # Beaconing (only meaningful when network telemetry exists at all - v2.64: presence-based,
    # same inputs the verdict's beacon checks depend on: live connections + Sysmon DNS telemetry.
    # Both absent = no sensor = claiming "no beacons" would overstate health.)
    if (((Test-CaseCsv 'flash_public_connections') -or (Test-CaseCsv 'sysmon_dns')) -and @(Import-CaseCsv 'beacon_candidates').Count -eq 0 -and @(Import-CaseCsv 'dns_beacon_candidates').Count -eq 0) {
        & $add 'Beacon detection' 'no periodic-callback candidates in network or DNS telemetry'
    }
    # Technique hunt (the engine always writes the CSV during regen - row absence = 0 findings)
    if ((Test-CaseCsv 'hunt_findings') -and @(Import-CaseCsv 'hunt_findings').Count -eq 0) { & $add 'Technique hunt rules' '0 detections (renamed binaries, side-loads, download-exec, LSASS access, persistence abuse...)' }
    if ((Test-CaseCsv 'usn_write_bursts') -and @(Import-CaseCsv 'usn_write_bursts').Count -eq 0) { & $add 'Mass file modification scan' 'USN journal analyzed, 0 ransomware-like write bursts' }
    if ((Test-CaseCsv 'loldrivers_hits') -and @(@(Import-CaseCsv 'loldrivers_hits') | Where-Object { "$($_.Status)" -eq 'malicious' }).Count -eq 0) { & $add 'Loaded driver check' '0 drivers matching the malicious-driver hash feed' }
    # Brute force (only meaningful with logon telemetry)
    $auth = @(Import-CaseCsv 'security_auth_events')
    if ($auth.Count -gt 0 -and @(Import-CaseCsv 'security_bruteforce_candidates').Count -eq 0) { & $add 'Brute-force analysis' "$($auth.Count) logon events analyzed, 0 brute-force source candidates" }
    # Log integrity: v2.64 - SAME predicate as the verdict's tamper count (EventId 1102/104,
    # Meaning 'clear' fallback). The old Detail-based filter read a column logging_gaps
    # doesn't have, so real clear events never suppressed this row. v2.80: 'stop' dropped from
    # the Meaning fallback - benign 6006 'Event logging STOPPED (shutdown)' rows are not tamper
    # events and must not suppress this clean attestation.
    $gaps = @(Import-CaseCsv 'logging_gaps')
    if ((Test-CaseCsv 'logging_gaps') -and @($gaps | Where-Object { "$($_.EventId)" -match '^(1102|104)$' -or "$($_.Meaning)" -match 'clear' }).Count -eq 0) { & $add 'Log integrity' 'no security log clear events found' }
    # Credential exposure: v2.64 - same ^high$ filter the verdict's credential signal keys on
    # (case-insensitive exact match; a MEDIUM-only sweep is still a clean row)
    if ((Test-CaseCsv 'credential_sweep') -and @(@(Import-CaseCsv 'credential_sweep') | Where-Object { "$($_.Risk)" -match '(?i)^high$' }).Count -eq 0) { & $add 'Credential exposure sweep' 'no HIGH-risk exposure (auto-logon secrets, LSASS dumps on disk, key material)' }
    if ((Test-CaseCsv 'svchost_audit') -and @(Import-CaseCsv 'svchost_audit').Count -eq 0) { & $add 'svchost masquerade audit' 'every running svchost instance runs from System32' }
    if ((Test-CaseCsv 'wmi_event_consumers') -and @(Import-CaseCsv 'wmi_event_consumers').Count -eq 0) { & $add 'WMI event subscriptions' 'no permanent persistence subscriptions' }
    if ((Test-CaseCsv 'ads_findings') -and @(Import-CaseCsv 'ads_findings').Count -eq 0) { & $add 'ADS scan' 'no non-Zone.Identifier streams on checked executables' }
    if ((Test-CaseCsv 'webshell_candidates') -and @(Import-CaseCsv 'webshell_candidates').Count -eq 0) { & $add 'Webshell content scan' 'script files scanned, 0 heuristic matches' }
    return $out.ToArray()
}

function New-HtmlReport {
    # v2.67 (B5): fixture harnesses rehydrate this function without the standalone safe-cast
    # helpers - define function-scoped fallbacks when they are missing (no-op in the full script)
    if (-not (Get-Command ConvertTo-SafeInt -ErrorAction SilentlyContinue)) {
        function ConvertTo-SafeInt { param([string]$Value, [int]$Default = 0) if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }; try { return [int]$Value } catch { return $Default } }
        function ConvertTo-SafeDbl { param([string]$Value, [double]$Default = 0) if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }; try { return [double]$Value } catch { return $Default } }
    }
    $scored = @(Import-CaseCsv 'flash_process_scored.csv')
    $iocHits = @(Import-CaseCsv 'flash_ioc_hits.csv')
    $hayRows = @(Import-CaseCsv 'hayabusa_timeline.csv')
    # v2.80 (T4/M6): unfiltered copy - the rule-key map must cover the same name universe
    # New-SigmaRuleLogs names the per-rule CSVs from (raw CSV, no dedupe/noise filtering)
    $hayRaw = $hayRows
    # v2.63: supertimeline read ONCE here - glance/entity/master views below derive from $tlRows
    $tlRows = @(Import-CaseCsv 'supertimeline')
    # v2.55: dedupe events matched by multiple rules + drop self-noise (our own collection activity)
    if (Get-Command Remove-SigmaDuplicateEvents -ErrorAction SilentlyContinue) {
        $hayRows = @(Remove-SigmaDuplicateEvents $hayRows | Where-Object { -not (Test-SigmaSelfNoise $_) })
    }
    $execRows = @(Import-CaseCsv 'execution_timeline.csv')
    $brute = @(Import-CaseCsv 'security_bruteforce_candidates.csv')
    $pubConns = @(Import-CaseCsv 'flash_public_connections.csv')
    $connDns = @(Import-CaseCsv 'connections_dns.csv')
    $amcHits = @(Import-CaseCsv 'ioc_hits_amcache.csv')
    $yaraHits = @(Import-CaseCsv 'yara_hits.csv')
    $beacons = @(Import-CaseCsv 'beacon_candidates.csv')
    $dnsBeacons = @(Import-CaseCsv 'dns_beacon_candidates.csv')
    $huntRows = @(Import-CaseCsv 'hunt_findings.csv')
    $liveScan = @(Import-CaseCsv 'memory_live_scan.csv')
    $lolHits = @(Import-CaseCsv 'loldrivers_hits.csv')
    $psCmds = @(Import-CaseCsv 'ps_decoded_commands.csv')
    $entB = @(Import-CaseCsv 'entities_binaries.csv')
    $entA = @(Import-CaseCsv 'entities_accounts.csv')
    $entR = @(Import-CaseCsv 'entities_remotes.csv')
    $srumRows = @(Import-CaseCsv 'srum_usage.csv')
    $usnBursts = @(Import-CaseCsv 'usn_write_bursts.csv')
    $mftRecent = @(Import-CaseCsv 'mft_recent.csv')
    $pfParsed = @(Import-CaseCsv 'prefetch_parsed.csv')
    $authSum = @(Import-CaseCsv 'security_auth_summary.csv')
    $authEv = @(Import-CaseCsv 'security_auth_events.csv')
    $runKeys = @(Import-CaseCsv 'autoruns_runkeys.csv')
    $tasksFlag = @(Import-CaseCsv 'scheduled_tasks_flagged.csv')
    # v2.83: ghost/hidden tasks + ntds access + execution-evidence extras
    $taskCacheRows = @(Import-CaseCsv 'scheduled_taskcache.csv')
    $taskCacheAnom = @($taskCacheRows | Where-Object { "$($_.Flags)" })
    $taskDel = @(Import-CaseCsv 'task_deletions.csv')
    $esentRows = @(Import-CaseCsv 'esent_ntds.csv')
    $scExec = @(Import-CaseCsv 'shimcache_exec.csv')
    $radarRows = @(Import-CaseCsv 'radar_exec.csv')
    $aswRows = @(Import-CaseCsv 'appswitched.csv')
    $svcFlag = @(Import-CaseCsv 'services_flagged.csv')
    $wmiBind = @(Import-CaseCsv 'wmi_bindings.csv')
    $deltaRows = @(Import-CaseCsv 'delta_new.csv')
    $gapRows = @(Import-CaseCsv 'logging_gaps.csv')
    $asepRows = @(Import-CaseCsv 'asep_sweep.csv')
    $certs = @(Import-CaseCsv 'certificates.csv')
    $asepHot = @($asepRows | Where-Object { $_.Flags -match 'user-path|nondefault' })
    $defStatus = @(Import-CaseCsv 'defender_status.csv')
    $defThreats = @(Import-CaseCsv 'defender_threats.csv')
    $savedCreds = @(Import-CaseCsv 'saved_credentials.csv')
    $rdpTgt = @(Import-CaseCsv 'rdp_client_targets.csv')
    $bitsJobs = @(Import-CaseCsv 'bits_jobs.csv')
    $posture = @(Import-CaseCsv 'posture.csv')
    $memMfR = @(Import-CaseCsv 'memory_malfind.csv')
    $browserIocR = @(Import-CaseCsv 'ioc_hits_browser.csv')
    # v2.78: reads hoisted here from mid-section bodies - their row counts feed the nav
    $secAll = @(Import-CaseCsv 'security_events')
    $chains = @(Import-CaseCsv 'process_chains')
    $sessAct = @(Import-CaseCsv 'session_activity')
    $credSweep = @(Import-CaseCsv 'credential_sweep')
    $postureBad = @($posture | Where-Object { $_.Status -eq 'BAD' })

    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
.nav{position:sticky;top:0;background:#0f1115ee;border-bottom:1px solid #2a2f3a;padding:8px 0;z-index:9}
.nav a{color:#8ab4f8;font-size:12px;text-decoration:none;margin-right:14px}
.mkey{position:sticky;top:33px;z-index:5;background:#0f1115;border-bottom:1px solid #2a2f3a;padding:3px 0;font-size:11px;color:#7d8590}
.mkey i{display:inline-block;width:9px;height:9px;border-radius:2px;border:1px solid;margin:0 3px 0 10px;vertical-align:middle}
.chips{margin:16px 0}.chip{display:inline-block;padding:6px 14px;border-radius:16px;margin-right:8px;font-size:14px;font-weight:600}
.card{background:#181b21;border:1px solid #2a2f3a;border-radius:8px;padding:14px;margin:10px 0}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:700;margin-right:8px}
.HIGH{background:#5c1a1e;color:#ff8789}.MEDIUM{background:#5c470f;color:#ffce6b}.LOW{background:#1d3a26;color:#7ee2a8}.INFO{background:#243447;color:#9ec1f0}
.ev{display:inline-block;background:#232833;border:1px solid #333b49;border-radius:4px;padding:2px 8px;margin:3px 4px 0 0;font-size:11px;color:#aab4c3}
.path{font-family:Consolas,monospace;font-size:12px;color:#8ab4f8;word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #2a2f3a;padding:6px 10px;text-align:left}
th{background:#1d222c;color:#8ab4f8}tr:nth-child(even){background:#151920}
details{margin:10px 0;padding:6px 10px;background:#151920;border:1px solid #2a2f3a;border-radius:6px}summary{cursor:pointer;padding:4px 0}
.crit{color:#ff8789;font-weight:700}.high{color:#ffb35c}.med{color:#ffce6b}.low{color:#9ec1f0}.info{color:#7d8590}
a{color:#8ab4f8} .foot{margin-top:40px;color:#565e6b;font-size:11px}
.vbanner{border-radius:10px;padding:18px 22px;margin:18px 0;border:2px solid}
.v4{background:#2a0f12;border-color:#a33}.v3{background:#2a150f;border-color:#b33}.v2{background:#2a220f;border-color:#b93}.v1{background:#0f2418;border-color:#3a5}.v0{background:#1c1c22;border-color:#666}
.vtitle{font-size:24px;font-weight:800;margin:0 0 4px}
.vowner{font-size:14px;margin:6px 0 0}
.confwrap{background:#1d222c;border-radius:8px;height:18px;margin-top:12px;position:relative;overflow:hidden}
.confbar{height:18px}
.conftext{position:absolute;left:10px;top:1px;font-size:12px;font-weight:700;color:#d7dce3}
.sig{display:inline-block;background:#232833;border:1px solid #333b49;border-radius:6px;padding:6px 10px;margin:3px 6px 3px 0;font-size:12px}
.donow{background:#3a2a10;border:1px solid #b93;border-radius:8px;padding:10px 14px;margin-top:12px;font-size:13px;color:#ffd57a}
.lead{background:#181b21;border:1px solid #2a2f3a;border-left:4px solid #666;border-radius:8px;padding:12px 16px;margin:10px 0}
.lead-crit{border-left-color:#e05252;background:#221418}
.lead-med{border-left-color:#c9a227;background:#211d12}
.leadtitle{font-size:15px;font-weight:700;color:#e8ecf2}
.leadclass{font-size:12px;font-weight:400;color:#9aa6b6;margin-left:8px}
.chip{display:inline-block;background:#243447;color:#9ec1f0;border-radius:10px;padding:2px 10px;margin:2px 4px 2px 0;font-size:11px}
.chip.chipdead{background:#232833;color:#7d8590;border:1px solid #333b49}
.cov-ok{color:#7ee2a8}.cov-miss{color:#ff8789}
.tac{display:inline-block;padding:5px 12px;border-radius:14px;margin:3px 6px 3px 0;font-size:12px;font-weight:600;background:#243447;color:#9ec1f0}
.tac.hi{background:#5c1a1e;color:#ff8789}.tac.md{background:#5c470f;color:#ffce6b}
pre.ioc{background:#181b21;border:1px solid #2a2f3a;border-radius:8px;padding:12px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all}
.rec{background:#181b21;border-left:4px solid #8ab4f8;border-radius:6px;padding:10px 14px;margin:8px 0}
details{margin:6px 0}summary{cursor:pointer;color:#8ab4f8;font-size:13px}
td.clip{cursor:copy}
.clip.open{word-break:break-all}
.swall{background:#232833;border:1px solid #333b49;color:#9ec1f0;border-radius:4px;padding:1px 8px;cursor:pointer;font-size:11px;margin-top:3px}
#copied{position:fixed;bottom:14px;right:14px;background:#1d3a26;color:#7ee2a8;padding:8px 14px;border-radius:6px;display:none;z-index:99;font-size:12px;font-weight:700}
.sbar{margin:8px 0}.sbar input,.sbar select{background:#181b21;border:1px solid #2a2f3a;color:#d7dce3;padding:4px 8px;border-radius:4px;font-size:12px}
.pgr{margin:6px 0}.pgr button{background:#232833;border:1px solid #333b49;color:#9ec1f0;border-radius:4px;padding:2px 10px;cursor:pointer;margin-left:4px}
tr.techrow{cursor:pointer}
@media print{body{background:#fff;color:#111;font-size:11px}.nav,#copied,.sbar,.pgr,.mkey,button{display:none!important}h1,h2{color:#111;border-color:#999}pre.ioc{background:#f4f4f4;color:#111;border-color:#bbb}table{font-size:10px}th{background:#eee;color:#111}tr:nth-child(even){background:#fafafa}.vbanner,.lead,.rec{background:#fafafa}.meta,.foot{color:#444}a{color:#111;text-decoration:none}.swall{display:none!important}}
</style>
'@

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira - $(ConvertTo-HtmlEsc $Computer)</title>$css</head><body>")
    $null = $sb.AppendLine("<h1>OPHIRA COMPROMISE ASSESSMENT REPORT</h1>")
    # v2.77: ONE case.json read drives the elevation label AND the provenance line (collector
    # tool, preset, log window). Per-field fallback: an old case without case.json (or without
    # a given field) just omits that segment - the header never lies about what it knows.
    $caseMeta = $null
    try { $caseMeta = Get-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    $caseAdmin = $null
    if ($caseMeta) { $caseAdmin = $caseMeta.AdminElevated }
    # v2.63: no AdminElevated in case.json -> 'unknown'; NEVER live-probe at render time
    # (the analyst box's elevation is not the endpoint's - the v2.55 bug class)
    $elevLabel = if ($null -ne $caseAdmin) { if ($caseAdmin) { 'yes' } else { 'NO' } } else { 'unknown' }
    # v2.66 (B14): blank identity slots rendered as "Case:  |" - same fallback pattern as the
    # elevation fix above (never live-probe, never leave an empty slot)
    # v2.77: an empty CaseID falls back to the case FOLDER name - the collected folder is the
    # de-facto case identity when no operator CaseID was ever entered (was a bare 'unknown')
    $caseLbl = if ("$($script:CurrentCaseID)") { "$($script:CurrentCaseID)" }
               elseif ($caseMeta -and "$($caseMeta.CaseID)") { "$($caseMeta.CaseID)" }
               else { Split-Path -Path $CaseDir -Leaf }
    $analystLbl = if ("$($script:CurrentAnalyst)") { "$($script:CurrentAnalyst)" } else { 'not recorded' }
    # v2.66 (B13): ONE dialect for Ophira's own generated stamps - yyyy-MM-dd HH:mm + ' UTC'.
    # Raw evidence strings (event timestamps copied from CSVs into table cells) stay as-is.
    # v2.77 (provenance): the header separates WHO collected from WHO rendered (case.json Tool
    # is the collector's version, not the renderer's) and shows the Preset + log window.
    $provSegs = New-Object System.Collections.Generic.List[string]
    $provSegs.Add("Host: $(ConvertTo-HtmlEsc $Computer)")
    $provSegs.Add("Case: $(ConvertTo-HtmlEsc $caseLbl)")
    $provSegs.Add("Analyst: $(ConvertTo-HtmlEsc $analystLbl)")
    if ($caseMeta -and "$($caseMeta.Tool)") { $provSegs.Add("Collected by $(ConvertTo-HtmlEsc $caseMeta.Tool)") }
    $provSegs.Add("Rendered by Ophira v$ScriptVersion")
    if ($caseMeta -and "$($caseMeta.Preset)") { $provSegs.Add("Preset $(ConvertTo-HtmlEsc $caseMeta.Preset)") }
    if ($caseMeta) {
        if ("$($caseMeta.LogStart)" -and "$($caseMeta.LogEnd)") {
            # v2.77 fix: the case.json writer stores ISO round-trip stamps ('2026-09-01T08:00:00.0000000Z'),
            # which PS 5.1's ConvertFrom-Json auto-coerces into LOCAL-Kind DateTimes - stringifying
            # them rendered the analyst box's locale dialect ('9/1/2026 10:00:00 AM') mislabeled UTC.
            # Parse BOTH shapes (coerced DateTime or plain string) and render the one generated-stamp
            # dialect as UTC; text that cannot be parsed stays verbatim (same rule as the hunt cells).
            $provWin = @()
            $provD = [datetime]::MinValue
            foreach ($provPk in @('LogStart', 'LogEnd')) {
                $provRaw = $caseMeta.$provPk
                if ($provRaw -is [datetime]) {
                    $provWin += $provRaw.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
                } elseif ([datetime]::TryParse("$provRaw", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$provD)) {
                    $provWin += $provD.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
                } else {
                    $provWin += "$provRaw"
                }
            }
            $provSegs.Add("Window $(ConvertTo-HtmlEsc ($provWin -join ' - ')) UTC")
        } else {
            $provH = ConvertTo-SafeInt "$($caseMeta.LogHours)"
            if ($provH -gt 0) { $provSegs.Add("Window last $provH h") }
        }
    }
    $provSegs.Add("Sysmon: $(if ($Sysmon) { 'yes' } else { 'no' })")
    $provSegs.Add("Elevated: $elevLabel")
    $null = $sb.AppendLine("<div class='meta'>$($provSegs -join ' &nbsp;|&nbsp; ')</div>")
    # v2.66: nav order mirrors the actual rendered section order (B1) - it promised Leads before
    # Verdict and Timeline before Snapshot/Drivers/Hunt/Entities; the document is the truth standard.
    # v2.78: nav row counts - computed ONLY from data already imported above plus a few reads
    # HOISTED here from the section bodies (leads, $sigAlerts, the IOC indicator block,
    # credential_sweep, focus_terms.json) so no CSV is read twice. (none) marks a section that
    # will render zero rows - same empty-state honesty as the sections themselves. Accepted
    # edge: an ATT&CK row carrying tactics but no T-tags counts as (none) while the tactic
    # chips still render (hayabusa always emits both). verdict/recommendations/evidence
    # always render - no count.
    $certHot = @($certs | Where-Object { $_.Flags -match 'recently-added' -and $_.Flags -match 'self-signed' })
    $sigAlerts = @($hayRows | Where-Object { (Get-LvlRank "$($_.Level)") -ge 3 })
    $attkTech = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $hayRows) { foreach ($tg in (Split-TagList "$($r.MitreTags)")) { if ($tg -match '^T\d{4}') { $null = $attkTech.Add($tg) } } }
    $focusDirP = Join-Path (Split-Path -Parent $CsvDir) 'focus'
    $ft = $null
    if (Test-Path -LiteralPath (Join-Path $focusDirP 'focus_terms.json')) {
        try { $ft = Get-Content -LiteralPath (Join-Path $focusDirP 'focus_terms.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    }
    try {
        if (Test-CaseCsv 'leads') { $leads = @(Import-CaseCsv 'leads') } else { $leads = @(Get-TriageLeads) }
    } catch { $leads = @() }
    $iocBlock = New-Object System.Collections.Generic.List[string]
    foreach ($h in $iocHits) { if ("$($h.Indicator)") { $iocBlock.Add("ioc-$("$($h.Type)".ToLower())  $($h.Indicator)") } }
    foreach ($h in $amcHits) { if ("$($h.Indicator)") { $iocBlock.Add("sha1  $($h.Indicator)") } }
    foreach ($b in $brute) { if ("$($b.SourceIp)") { $iocBlock.Add("ip  $($b.SourceIp)") } }
    foreach ($b in ($beacons | Where-Object { "$($_.Severity)" -match '^(high|medium)$' -and "$($_.RemoteIp)" })) { $iocBlock.Add("ip  $($b.RemoteIp)") }
    foreach ($b in ($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(high|medium)$' -and "$($_.Domain)" })) {
        $iocBlock.Add("domain  $($b.Domain)")
        if ("$($b.ResolvedIp)") { $iocBlock.Add("ip  $($b.ResolvedIp)") }
    }
    $yaraScanned = @(Import-CaseCsv 'yara_scanned.csv')
    foreach ($y in ($yaraScanned | Where-Object { "$($_.Hits)" -match '^\d+$' -and [int]$_.Hits -gt 0 -and "$($_.SHA256)" })) { $iocBlock.Add("sha256  $($y.SHA256)") }
    foreach ($h in (Import-CaseCsv 'ioc_hits_dns')) { $iocBlock.Add("domain  $($h.Query)"); if ("$($h.Resolved)") { $iocBlock.Add("ip  $(("$($h.Resolved)" -split '[,;]')[0].Trim())") } }
    foreach ($h in (Import-CaseCsv 'ioc_hits_network')) { $iocBlock.Add("ip  $($h.RemoteIp)") }
    foreach ($h in (Import-CaseCsv 'ioc_hits_hash')) { $iocBlock.Add("sha256  $($h.Hash)") }
    $iocUnique = @($iocBlock.ToArray() | Sort-Object -Unique)
    $covNav = 0
    if ($script:Verdict -and $script:Verdict.Coverage) { $covNav = @($script:Verdict.Coverage).Count }
    # logons: 4648/4672 rows render from $secAll - count them too (one pass, in-memory)
    $secNav = @($secAll | Where-Object { "$($_.Id)" -eq '4648' -or "$($_.EventId)" -eq '4648' -or "$($_.Id)" -eq '4672' -or "$($_.EventId)" -eq '4672' }).Count
    # entities: only rows the section actually lists (multi-source binaries, active accounts/
    # remotes); SRUM renders whenever rows exist (column probe never fails on real rows)
    $entNav = @($entB | Where-Object { (ConvertTo-SafeInt $_.CatCount) -ge 2 }).Count +
        @($entA | Where-Object { (ConvertTo-SafeInt $_.Logons) -gt 0 -or (ConvertTo-SafeInt $_.Failed) -gt 0 -or "$($_.RdpOutTargets)" -or (ConvertTo-SafeDbl $_.ConsoleHistoryKB) -gt 0 }).Count +
        @($entR | Where-Object { (ConvertTo-SafeInt $_.Connections) -gt 0 -or "$($_.Beacon)" -or (ConvertTo-SafeInt $_.FailedLogons) -gt 0 -or (ConvertTo-SafeInt $_.RdpOutCount) -gt 0 }).Count +
        $srumRows.Count + $chains.Count + $sessAct.Count
    $nCount = @{
        leads = $leads.Count
        coverage = $covNav + $gapRows.Count
        attack = $attkTech.Count
        tactics = $sigAlerts.Count
        ioc = $iocUnique.Count
        yara = $yaraHits.Count
        processes = $scored.Count
        sigma = $hayRows.Count
        logons = $authEv.Count + $authSum.Count + $brute.Count + $secNav
        persistence = $tasksFlag.Count + $svcFlag.Count + $wmiBind.Count + $runKeys.Count + $asepHot.Count + $certHot.Count + $taskCacheAnom.Count + $taskDel.Count + $esentRows.Count
        filesystem = $usnBursts.Count + $pfParsed.Count + $mftRecent.Count
        beacons = $beacons.Count + $dnsBeacons.Count
        network = $pubConns.Count
        drivers = $lolHits.Count
        hunt = $huntRows.Count + $liveScan.Count
        entities = $entNav
        snapshot = $defStatus.Count + $defThreats.Count + $credSweep.Count + $savedCreds.Count + $rdpTgt.Count + $bitsJobs.Count + $memMfR.Count + $browserIocR.Count + $posture.Count + $radarRows.Count + $aswRows.Count
        timeline = $tlRows.Count
        focus = if ($ft) { ConvertTo-SafeInt "$($ft.HitCount)" } else { 0 }
    }
    $nLabel = [ordered]@{
        verdict = 'Verdict'; leads = 'Leads'; coverage = 'Coverage'; attack = 'ATT&CK'; ioc = 'IOCs'
        tactics = 'Findings by tactic'; yara = 'YARA'; processes = 'Processes'; sigma = 'Sigma'
        logons = 'Logons'; persistence = 'Persistence'; filesystem = 'File system'; beacons = 'Beaconing'
        network = 'Network'; drivers = 'Drivers'; hunt = 'Hunt'; entities = 'Connections'
        snapshot = 'Snapshot'; timeline = 'Timeline'; focus = 'Focus'; recommendations = 'Recommendations'
        evidence = 'Evidence index'
    }
    $navParts = New-Object System.Collections.Generic.List[string]
    foreach ($nk in $nLabel.Keys) {
        $nl2 = ConvertTo-HtmlEsc $nLabel[$nk]
        if ($nCount.ContainsKey($nk)) {
            $nc2 = [int]$nCount[$nk]
            $nl2 = "$nl2 $(if ($nc2 -gt 0) { "($nc2)" } else { '(none)' })"
        }
        $navParts.Add("<a href='#$nk'>$nl2</a>")
    }
    $null = $sb.AppendLine("<div class='nav'>$($navParts -join '')</div>")

    # ---------- assessment at a glance (v2.61: the banner answers "infected or not?") ----------
    $null = $sb.AppendLine("<a name='verdict'></a><h2>Assessment at a glance</h2>")
    if ($script:Verdict) {
        $v = $script:Verdict
        # v2.77: the weighted percent and the raw source fraction stop colliding - the banner
        # shows both (92% weighted AND 24/29 sources, 5 missing) instead of one number that
        # reads as both. Weights stay verdict-weight semantics; the coverage table column is
        # renamed Importance to keep the two vocabularies apart.
        $covMiss = [Math]::Max(0, $v.CoverageSourcesTotal - $v.CoverageSourcesCollected)
        # v2.68 (B11): bar width and bar label read ONE rounded integer - the verdict math already
        # Round()s the percent, but deriving both from a single value keeps the bar and the text
        # agreeing even if the provenance ever turns fractional (old: [int] truncated the bar)
        # v2.77 fix: the banner TEXT reads the same rounded value (one number on the banner, not
        # '95.6% weighted' beside a bar labeled '96% weighted')
        $confPct = [math]::Min(100, [int][math]::Round($v.ConfidencePercent))
        $null = $sb.AppendLine("<div class='vbanner v$($v.LevelRank)'>")
        $null = $sb.AppendLine("<p class='vtitle'>$(ConvertTo-HtmlEsc $v.Level)</p>")
        $null = $sb.AppendLine("<p class='vowner'>$(ConvertTo-HtmlEsc $v.OwnerLine) &nbsp; Evidence coverage: $confPct% weighted ($($v.CoverageSourcesCollected)/$($v.CoverageSourcesTotal) sources, $covMiss missing) - how much of the case was collected, not a probability of compromise</p>")
        $null = $sb.AppendLine("<div class='confwrap'><div class='confbar' style='width:$confPct%;background:#b93'></div><div class='conftext'>$confPct% weighted ($($v.CoverageSourcesCollected)/$($v.CoverageSourcesTotal) sources, $covMiss missing)</div></div>")
        # v2.61: what the level means - and what it does NOT mean
        $vmean = @{
            4 = 'Multiple independent high-confidence indicators agree - treat this host as compromised until proven otherwise.'
            3 = 'Strong evidence of malicious activity - respond as an incident. This is not yet proof of full compromise.'
            2 = 'Real anomalies exist, but each has plausible benign explanations - investigate before this host returns to service.'
            1 = 'The checks below ran and found nothing. This is not a guarantee: the clean-check list shows exactly what was verified, and the caveats show what could not be.'
            0 = 'Too little evidence was collected to draw any conclusion - recollect with a deeper preset if the host allows it.'
        }
        if ($vmean[[int]$v.LevelRank]) { $null = $sb.AppendLine("<p class='vowner' style='font-style:italic'>$(ConvertTo-HtmlEsc $vmean[[int]$v.LevelRank])</p>") }
        # v2.45: rank-specific first actions - the 30-minute decision starts here
        $donow = @{
            4 = 'Isolate the host from the network NOW. Capture RAM before any reboot. Treat every credential used on this host as compromised and start scoping other hosts.'
            3 = 'Isolate or network-restrict this host and preserve volatile evidence (RAM) before any reboot. Work the leads below top-down; verify each against the cited evidence.'
            2 = 'Enough suspicious evidence exists to justify a closer look before this host returns to service - work the leads below (or review the Sigma findings and process scores if no lead met the threshold).'
        }
        # v2.78: the do-now block jumps straight to the Recommendations section (anchor exists)
        if ($donow[[int]$v.LevelRank]) { $null = $sb.AppendLine("<div class='donow'><b>Do now:</b> $(ConvertTo-HtmlEsc $donow[[int]$v.LevelRank]) <a href='#recommendations'>-&gt; full Recommendations</a></div>") }
        # report-accuracy task 2: weight-0 signals carry no verdict weight - they leave the
        # contributing list and render in a separate 'Noted' group below it, so a [w0] row can
        # no longer read as evidence sitting between real [w1]+ rows. Both groups share one row
        # renderer (badge class, anchor resolution, ConvertTo-HtmlEsc escaping unchanged).
        # v2.77: one deterministic order for both groups - Weight desc, Count desc, Name asc
        # (the Add-Signal insertion order no longer decides prominence); the weight-0 'Noted'
        # group still renders last.
        $vSigOrder = @($v.Signals | Sort-Object -Property @{ e = 'Weight'; Descending = $true }, @{ e = 'Count'; Descending = $true }, @{ e = 'Signal'; Descending = $false })
        $vContrib = @($vSigOrder | Where-Object { $_.Weight -ge 1 })
        $vNoted = @($vSigOrder | Where-Object { $_.Weight -eq 0 })
        $sigRow = {
            param($s)
            $wcol = if ($s.Weight -ge 4) { 'crit' } elseif ($s.Weight -ge 3) { 'high' } elseif ($s.Weight -ge 2) { 'med' } else { 'info' }
            # v2.77: plain-language rank labels replace the [wN] chips (verdict.json keeps the
            # integer weights; this is a render-side label only)
            $wlab = if ($s.Weight -ge 4) { 'near-certain' } elseif ($s.Weight -ge 3) { 'strong' } elseif ($s.Weight -ge 2) { 'corroborating' } elseif ($s.Weight -ge 1) { 'context' } else { 'noted' }
            $anc = ''
            if ("$($s.Signal)" -match '^YARA') { $anc = 'yara' }
            elseif ("$($s.Signal)" -match '^Sigma') { $anc = 'sigma' }
            elseif ("$($s.Signal)" -match '^C2') { $anc = 'beacons' }
            elseif ("$($s.Signal)" -match '^Process anomaly') { $anc = 'processes' }
            elseif ("$($s.Signal)" -match '^IOC') { $anc = 'ioc' }
            elseif ("$($s.Signal)" -match '^Hunt technique') { $anc = 'hunt' }
            elseif ("$($s.Signal)" -match '^Uncommon persistence') { $anc = 'persistence' }
            elseif ("$($s.Signal)" -match '^Ransomware') { $anc = 'filesystem' }
            elseif ("$($s.Signal)" -match '^Memory malfind') { $anc = 'snapshot' }
            elseif ("$($s.Signal)" -match '^Known-malicious driver') { $anc = 'drivers' }
            elseif ("$($s.Signal)" -match '^Defender detection') { $anc = 'snapshot' }
            elseif ("$($s.Signal)" -match '^Security tooling') { $anc = 'coverage' }
            elseif ("$($s.Signal)" -match '^Brute') { $anc = 'logons' }
            elseif ("$($s.Signal)" -match '^Security posture gaps') { $anc = 'snapshot' } # v2.66: was a dead anchor - the posture table renders in the snapshot section
            elseif ("$($s.Signal)" -match '^Credential material exposure') { $anc = 'snapshot' } # v2.66: was a dead anchor - the credential sweep renders in the snapshot section
            # v2.77: the hunt signal counts RULES and FINDINGS - '(N fired) xM' read as two
            # different counts of the same thing; 'N rules / M findings' says both units.
            # verdict.json Signal/Count fields stay verbatim (render-side wording only).
            if ("$($s.Signal)" -match '^Hunt techniques \((\d+) fired\)$') {
                $sigTxt = "$(ConvertTo-HtmlEsc "Hunt techniques: $($Matches[1]) rules / $($s.Count) findings")$(if ("$($s.Detail)") { " - <span class='path'>$(ConvertTo-HtmlEsc $s.Detail)</span>" })"
            } else {
                $sigTxt = "$(ConvertTo-HtmlEsc $s.Signal) x$($s.Count)$(if ("$($s.Detail)") { " - <span class='path'>$(ConvertTo-HtmlEsc $s.Detail)</span>" })"
            }
            if ($anc) { return "<div class='sig'><span class='$wcol'>$wlab</span> <a href='#$anc' style='color:inherit'>$sigTxt</a></div>" }
            return "<div class='sig'><span class='$wcol'>$wlab</span> $sigTxt</div>"
        }
        if ($vContrib.Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:12px'><b>Contributing signals</b> (click a signal to jump to its evidence)</p>")
            foreach ($s in $vContrib) { $null = $sb.AppendLine((& $sigRow $s)) }
        } else {
            $null = $sb.AppendLine("<p style='margin-top:12px' class='meta'>No compromising signals were observed in the collected evidence.</p>")
        }
        if ($vNoted.Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:12px'><b>Noted</b> (no verdict weight - context, not evidence of compromise)</p>")
            foreach ($s in $vNoted) { $null = $sb.AppendLine((& $sigRow $s)) }
        }
        # v2.61: negative evidence - every check that ran and found NOTHING, with counts
        $clean = @()
        try { $clean = @(Get-CleanCheckSummary -HayRows $hayRows) } catch { }
        if ($clean.Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:14px'><b>Checked and clean</b> (a clean verdict is only as good as the checks behind it)</p>")
            foreach ($cc in $clean) {
                $null = $sb.AppendLine("<div class='sig'><span class='badge LOW'>clean</span> <b>$(ConvertTo-HtmlEsc $cc.Check)</b> - <span class='meta'>$(ConvertTo-HtmlEsc $cc.Detail)</span></div>")
            }
        }
        # v2.61: incident window from the master timeline
        # task 10 (display-window clamp): both the banner's evidence window and the master
        # timeline's sparkline render only the case's analysis window (LogHours), clamped to
        # [30d, 90d] (90d when LogHours is 0/unset) - stray decade-old amcache/MFT stamps no
        # longer stretch them into a 20-year span. Display only: supertimeline.csv,
        # -Mode Timeline and the newest-150 table keep every event.
        try { $tlLh = if ($script:LogHours -gt 0) { $script:LogHours } elseif ($LogHours -gt 0) { $LogHours } else { 0 } } catch { $tlLh = 0 }
        $tlWinDays = if ($tlLh -gt 0) { [Math]::Max(30, [Math]::Min([int][double]($tlLh / 24), 90)) } else { 90 }
        $tlCut = (Get-Date).Date.AddDays(-1 * $tlWinDays)
        $tlCutKey = $tlCut.ToString('yyyy-MM-dd')
        try {
            $tlGlance = @($tlRows | ForEach-Object { $tg = $null; try { $tg = [datetime]"$($_.Timestamp)" } catch { }; if ($tg) { $tg } })
            if ($tlGlance.Count -gt 1) {
                $tlSorted2 = @($tlGlance | Sort-Object)
                $tlIn2 = @($tlSorted2 | Where-Object { $_ -ge $tlCut })
                $tlClamp2 = ($tlIn2.Count -gt 0 -and $tlIn2.Count -lt $tlSorted2.Count)
                $days2 = @{}
                foreach ($t2 in $(if ($tlClamp2) { $tlIn2 } else { $tlSorted2 })) { $k2 = $t2.ToString('yyyy-MM-dd'); if (-not $days2.ContainsKey($k2)) { $days2[$k2] = 0 }; $days2[$k2]++ }
                $top2 = @($days2.Keys | Sort-Object { $days2[$_] } -Descending | Select-Object -First 1)[0]
                $tlFirst2 = if ($tlClamp2) { $tlIn2[0] } else { $tlSorted2[0] }
                $tlNote2 = if ($tlClamp2) { " + $($tlSorted2.Count - $tlIn2.Count) older event(s) before $tlCutKey (stray timestamps)." } else { '' }
                $null = $sb.AppendLine("<p class='meta' style='margin-top:10px'><b>Evidence window:</b> $($tlFirst2.ToString('yyyy-MM-dd HH:mm')) UTC to $($tlSorted2[$tlSorted2.Count - 1].ToString('yyyy-MM-dd HH:mm')) UTC ($($tlGlance.Count) events) - busiest day $top2 ($($days2[$top2]) events).$tlNote2 Full chronology: <a href='#timeline'>master timeline</a></p>")
            }
        } catch { }
        if (@($v.Caveats).Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:14px'><b>Could not check / what would change this verdict</b></p><ul>")
            foreach ($c in @($v.Caveats)) { $null = $sb.AppendLine("<li>$(ConvertTo-HtmlEsc $c)</li>") }
            $null = $sb.AppendLine("</ul>")
        }
        $null = $sb.AppendLine("</div>")
    } else {
        $null = $sb.AppendLine("<div class='vbanner v0'><p class='vtitle'>VERDICT UNAVAILABLE</p><p class='vowner'>The verdict engine did not run - review the raw sections below.</p></div>")
    }

    # v2.66 (B6/B7): which Sigma rules got a per-rule drill-down (top 12 by hit count). The
    # ATT&CK expansion and the sigma lead deep-link into those drill-downs, so the set is
    # resolved here - before the leads section renders.
    # v2.66 (B10): the shared 5000-row embed budget is spent in this same top-12 order, so
    # the walk happens here too: $drillTake holds each rule's embedded-row share. A rule with
    # a zero share gets no drill-down UI at all - so deep links must not target it either.
    # v2.80 (T4/M6): keys come from the shared collision-free map, built from the RAW hayabusa
    # rows so drill keys, lead hrefs, ATT&CK links and New-SigmaRuleLogs CSV filenames all
    # agree even when distinct rule names sanitize to the same key.
    $drillSafeNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $drillTake = @{}
    $safeRuleMap = @{}
    if ($hayRaw.Count -gt 0) {
        $nameColPre = $null
        foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
            if ($hayRaw[0].PSObject.Properties[$cand]) { $nameColPre = $cand; break }
        }
        if ($nameColPre) { $safeRuleMap = Get-SafeRuleKeyMap $hayRaw $nameColPre }
    }
    if ($hayRows.Count -gt 0) {
        $alertColPre = $null
        foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
            if ($hayRows[0].PSObject.Properties[$cand]) { $alertColPre = $cand; break }
        }
        if ($alertColPre) {
            $budgetWalk = 5000
            foreach ($g2 in ($hayRows | Group-Object $alertColPre | Sort-Object Count -Descending | Select-Object -First 12)) {
                $s2 = Resolve-SafeRuleKey $safeRuleMap $g2.Name
                $take2 = [Math]::Min($g2.Count, [Math]::Max(0, $budgetWalk))
                $budgetWalk -= $take2
                $drillTake[$s2] = $take2
                if ($take2 -gt 0) { $null = $drillSafeNames.Add($s2) }
            }
        }
    }
    # ---------- triage leads (v2.45: decide these first) ----------
    # The 30-minute TP/FP workflow: the strongest signals as ranked lead cards, pure evidence -
    # identity, why it was flagged, which evidence categories corroborate it, and the auto-built
    # correlation story one click away in the Focus section.
    # v2.71: the ranking is built ONCE by Invoke-RegenerateOutputs (Get-TriageLeads ->
    # csv\derived\leads.csv). This render reads the persisted rows; old cases / direct renders
    # without the file fall back to the same builder inline. The draft's BEST LEADS projects
    # the same list - one builder, one order, no second truth.
    try {
        # v2.78: $leads is imported up at the nav build (one read, its count feeds the nav)
        $null = $sb.AppendLine("<a name='leads'></a><h2>Triage leads - decide these first</h2>")
        if ($leads.Count -eq 0) {
            $null = $sb.AppendLine("<div class='meta'>No signal rose to lead level - nothing here demands a decision before the reference sections.</div>")
        } else {
            $entByPath = @{}
            foreach ($e2 in @(Import-CaseCsv 'entities_binaries')) { $entByPath["$($e2.Path)".ToLower()] = $e2 }
            $ftAll = $null
            try { $ftAll = Get-Content -LiteralPath (Join-Path (Join-Path (Split-Path -Parent $CsvDir) 'focus') 'focus_terms.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
            $n2 = 0
            # v2.71 task 8: ONE static Upgrade/Dismiss guidance line per lead card, keyed on the
            # Class prefix the shared builder writes (same strings as leads.csv's Class column).
            # Ordered patterns, first match wins - a multi-rule hunt lead keys on its first joined
            # rule. Classes with no entry (IOC hash = near-certain already, review:* = explicitly
            # not verdicts, YARA, lineage, anything future) render NO line. Render-local on
            # purpose: leads.csv keeps its 8-column shape and the draft projection is untouched.
            $leadUpg = @(
                @{ K = 'hunt rule: Renamed LOLBin*';             L = 'Upgrade if: the embedded identity is a known-malicious tool or the path is user-writable - Dismiss if: the path is a known test/canary or software-updater staging dir' },
                @{ K = 'hunt rule: Downloaded then executed*';   L = 'Upgrade if: the download came from a non-cloud unknown host or re-appears in persistence - Dismiss if: a signed installer from a known vendor path with plausible download history' },
                @{ K = 'hunt rule: Cross-process injection*';    L = 'Upgrade if: the target is LSASS or a system process - Dismiss if: both ends are the same protected process from one signer (self-injection noise)' },
                @{ K = 'hunt rule: Defender exclusion*';         L = 'Upgrade if: no installed software plausibly explains the change - Dismiss if: a management/AV agent made a documented configuration change' },
                @{ K = 'hunt rule: Defender real-time*';         L = 'Upgrade if: no installed software plausibly explains the change - Dismiss if: a management/AV agent made a documented configuration change' },
                @{ K = 'malicious process - correlation score*'; L = 'Upgrade if: unsigned AND user-path AND talking externally - Dismiss if: the signer and path check out as the vendor''s known install location' },
                @{ K = 'C2 beacon*';                             L = 'Upgrade if: the destination resolves to a hosting/previously-unseen ASN - Dismiss if: an OS/updater process with matching vendor telemetry' }
            )
            foreach ($ld in $leads) {
                $n2++
                $cls = if ($ld.Rank -eq 'crit') { 'lead lead-crit' } else { 'lead lead-med' }
                $null = $sb.AppendLine("<div class='$cls'><div class='leadtitle'>$n2. $(ConvertTo-HtmlEsc $ld.Title) <span class='leadclass'>$(ConvertTo-HtmlEsc $ld.Class)</span></div>")
                if ("$($ld.Ident)") { $null = $sb.AppendLine("<div class='path' style='word-break:break-all'>$(ConvertTo-HtmlEsc $ld.Ident)$(if ($ld.Extra) { " - $(ConvertTo-HtmlEsc $ld.Extra)" })</div>") }
                if ("$($ld.Why)") { $null = $sb.AppendLine("<div style='margin-top:4px'>$(ConvertTo-HtmlEsc $ld.Why)</div>") }
                # task 8: the one upgrade/dismiss line (absent for unmapped classes)
                $up2 = $null
                foreach ($up in $leadUpg) { if ("$($ld.Class)" -like $up.K) { $up2 = $up.L; break } }
                if ($up2) { $null = $sb.AppendLine("<div style='margin-top:4px' class='meta'>$(ConvertTo-HtmlEsc $up2)</div>") }
                $ent2 = $entByPath["$($ld.Ident)".ToLower()]
                if ($ent2 -and "$($ent2.Categories)") {
                    $chips = @("$($ent2.Categories)" -split ';' | Where-Object { $_ })
                    $null = $sb.AppendLine("<div style='margin-top:5px' class='meta'>corroborated by $($chips.Count) evidence categories:</div><div>")
                    # v2.67 (B2): lead-card chips link like entity chips - route through the
                    # anchor mapper; unmapped categories keep the grey/dead chip styling
                    foreach ($ch in $chips) {
                        $anch = Get-SectionAnchorForSource $ch
                        if ($anch) { $null = $sb.AppendLine("<a href='#$anch'><span class='chip'>$(ConvertTo-HtmlEsc $ch)</span></a>") }
                        else { $null = $sb.AppendLine("<span class='chip chipdead'>$(ConvertTo-HtmlEsc $ch)</span>") }
                    }
                    $null = $sb.AppendLine("</div>")
                }
                $focusHit = $false
                if ($ftAll -and "$($ftAll.Indicator)") {
                    $ind2 = "$($ftAll.Indicator)".ToLower()
                    if ("$($ld.Title)".ToLower().Contains($ind2) -or "$($ld.Ident)".ToLower().Contains($ind2)) { $focusHit = $true }
                }
                if ($focusHit) {
                    $null = $sb.AppendLine("<div style='margin-top:5px'><a href='#focus'>-> full correlation story (instances, activity graph, everything it did) in the Focus section</a></div>")
                } else {
                    # v2.66 (B7): when the target section hosts a filter this lead can drive,
                    # carry the entity into it (sigma drill-down = data-rule); sections without
                    # a filter keep the plain section-top jump as today.
                    $deepAttr = ''
                    if ($ld.Anchor -eq 'sigma' -and "$($ld.Rule)") {
                        $lsafe = Resolve-SafeRuleKey $safeRuleMap $ld.Rule
                        if ($lsafe -and $drillSafeNames.Contains($lsafe)) { $deepAttr = " data-rule='$lsafe'" }
                    }
                    $null = $sb.AppendLine("<div style='margin-top:5px'><a href='#$($ld.Anchor)'$deepAttr>-> evidence in the $(ConvertTo-HtmlEsc $ld.Anchor) section</a></div>")
                }
                $null = $sb.AppendLine("</div>")
            }
        }
    } catch { Write-CaseLog "    leads build failed: $($_.Exception.Message)" 'DarkYellow' }
    # ---------- narrative case draft (v2.31) ----------
    try {
        $draft = @(Get-CaseNarrative)
        if ($draft.Count -gt 0) {
            # v2.78: the draft collapses into a details block - it duplicated the banner near the
            # top of the page; case_draft.txt keeps shipping for the plain-text workflow
            $null = $sb.AppendLine("<a name='draft'></a><details><summary>Case draft (auto-written - paste into your report)</summary><div class='draft'>")
            foreach ($line in $draft) {
                $esc = ConvertTo-HtmlEsc $line
                if ($line -match '^[A-Z][A-Z ]+$') { $null = $sb.AppendLine("<p><b>$esc</b></p>") }
                elseif ($line -match '^ - ') { $null = $sb.AppendLine("<p style='margin:2px 0 2px 18px'>$esc</p>") }
                elseif ($line) { $null = $sb.AppendLine("<p>$esc</p>") }
            }
            $null = $sb.AppendLine("</div><div class='meta'>Plain-text copy: <b>case_draft.txt</b> in the case folder - starting point for your report, not a conclusion.</div></details>")
        }
    } catch { }

    # ---------- evidence coverage ----------
    $null = $sb.AppendLine("<a name='coverage'></a><h2>Evidence coverage & data quality</h2>")
    if ($script:Verdict -and @($script:Verdict.Coverage).Count -gt 0) {
        # v2.77: the column is 'Importance' - 'Weight' collided with verdict-weight vocabulary
        $null = $sb.AppendLine("<table><tr><th>Evidence source</th><th>Collected</th><th>Importance</th></tr>")
        foreach ($c in @($script:Verdict.Coverage)) {
            $mark = if ($c.Collected) { "<span class='cov-ok'>yes</span>" } else { "<span class='cov-miss'>NO</span>" }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.Source)</td><td>$mark</td><td>$($c.Weight)</td></tr>")
        }
        $covMissT = [Math]::Max(0, $script:Verdict.CoverageSourcesTotal - $script:Verdict.CoverageSourcesCollected)
        # v2.77 fix: same rounded integer the banner reads - one number across the report
        $covPctT = [math]::Min(100, [int][math]::Round($script:Verdict.ConfidencePercent))
        $null = $sb.AppendLine("</table><div class='meta'>Coverage: $covPctT% weighted ($($script:Verdict.CoverageSourcesCollected)/$($script:Verdict.CoverageSourcesTotal) sources, $covMissT missing) - missing sources narrow what can be ruled out.</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>Coverage data not available.</div>")
    }
    if ($gapRows.Count -gt 0) {
        # v2.66 (B15c): rows whose Time/Event cells are blank (chainsaw gap findings) get the raw
        # gaps output linked straight into the empty cells - never a blank cell to stare at
        $gapLink = ConvertTo-CaseFileLink (Join-Path $RawDir 'analysis\evtx_gaps.txt') 'raw\analysis\evtx_gaps.txt'
        $null = $sb.AppendLine("<h3>Logging continuity (check for tampering)</h3><table><tr><th>Time</th><th>Event</th><th>Meaning</th></tr>")
        foreach ($g in ($gapRows | Select-Object -First 25)) {
            if (-not "$($g.Time)" -and -not "$($g.EventId)") {
                $null = $sb.AppendLine("<tr><td colspan='2'>$gapLink</td><td>$(ConvertTo-HtmlEsc $g.Meaning)</td></tr>")
            } else {
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Time)</td><td>$($g.EventId)</td><td>$(ConvertTo-HtmlEsc $g.Meaning)</td></tr>")
            }
        }
        $null = $sb.AppendLine("</table>")
    }

    # ---------- summary chips ----------
    $high = @($scored | Where-Object Verdict -eq 'HIGH').Count
    $med = @($scored | Where-Object Verdict -eq 'MEDIUM').Count
    $low = @($scored | Where-Object Verdict -eq 'LOW').Count
    $hayCrit = @($hayRows | Where-Object { "$($_.Level)" -match 'crit' }).Count
    $hayHigh = @($hayRows | Where-Object { "$($_.Level)" -match '^high$' }).Count
    $null = $sb.AppendLine("<div class='chips'>" +
        "<span class='chip HIGH'>Proc HIGH: $high</span><span class='chip MEDIUM'>Proc MED: $med</span><span class='chip LOW'>Proc LOW: $low</span>" +
        "<span class='chip INFO'>IOC hits: $($iocHits.Count)</span><span class='chip INFO'>YARA hits: $($yaraHits.Count)</span><span class='chip INFO'>Sigma rows: $($hayRows.Count) (crit:$hayCrit high:$hayHigh)</span></div>")
    if ($deltaRows.Count -gt 0) {
        # v2.67 (B9): baseline unknown (re-parsed case, no previous-collection zip) -> no empty "()"
        $deltaLbl = if ("$($script:DeltaBaseline)") { " ($(ConvertTo-HtmlEsc $script:DeltaBaseline))" } else { '' }
        $null = $sb.AppendLine("<h2>NEW since previous collection$deltaLbl</h2><table><tr><th>Type</th><th>Item</th><th>Detail</th></tr>")
        foreach ($d in ($deltaRows | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $d.Type)</b></td><td>$(ConvertTo-HtmlEsc $d.Item)</td><td class='path'>$(ConvertTo-HtmlEsc $d.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    # ---------- MITRE ATT&CK ----------
    $null = $sb.AppendLine("<a name='attack'></a><h2>MITRE ATT&CK observed (from Sigma detections)</h2>")
    $techRows = New-Object System.Collections.Generic.List[object]
    $tacticCounts = @{}
    $tacticMaxRank = @{}
    foreach ($r in $hayRows) {
        # v2.68 (B12): a rule counts under EVERY tagged tactic (was: first tactic only - a
        # Disc,CredAccess rule vanished from the second chip). The technique table's Tactic
        # cell picks up the full label list through the join in the Tech row below.
        $tacs = @(Split-TagList "$($r.MitreTactics)")
        $tags = @(Split-TagList "$($r.MitreTags)")
        $rk = Get-LvlRank "$($r.Level)"
        foreach ($t in $tacs) {
            if (-not $tacticCounts.ContainsKey($t)) { $tacticCounts[$t] = 0; $tacticMaxRank[$t] = 0 }
            $tacticCounts[$t]++
            if ($rk -gt $tacticMaxRank[$t]) { $tacticMaxRank[$t] = $rk }
        }
        foreach ($tg in ($tags | Where-Object { $_ -match '^T\d{4}' })) {
            # v2.66 (B6): Eid/Rid ride along so the expansion can deep-link into the rule's
            # drill-down pre-filtered to the exact event (RecordID preferred, EID fallback)
            $techRows.Add([pscustomobject]@{ Tech = $tg; Tactic = ($tacs -join ','); Rank = $rk; Rule = "$($r.RuleTitle)"; Level = "$($r.Level)"; Last = "$($r.Timestamp)"; Eid = "$($r.EventID)"; Rid = $(if ($r.PSObject.Properties['RecordID']) { "$($r.RecordID)" } else { '' }) })
        }
    }
    if ($tacticCounts.Count -gt 0) {
        foreach ($tk in ($tacticCounts.Keys | Sort-Object)) {
            $cls = if ($tacticMaxRank[$tk] -ge 4) { 'hi' } elseif ($tacticMaxRank[$tk] -ge 3) { 'md' } else { '' }
            $null = $sb.AppendLine("<span class='tac $cls'>$(ConvertTo-HtmlEsc (Get-TacticLabel $tk)) : $($tacticCounts[$tk])</span>")
        }
        $null = $sb.AppendLine("")
    }
    $techGroups = @($techRows | Group-Object Tech | ForEach-Object {
        [pscustomobject]@{ Tech = $_.Name; Count = $_.Count; MaxRank = (@($_.Group | ForEach-Object { $_.Rank } | Measure-Object -Maximum).Maximum); Group = $_.Group }
    } | Sort-Object MaxRank, Count -Descending | Select-Object -First 60)
    if ($techGroups.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Technique</th><th>Tactic</th><th>Events</th><th>Max level</th><th>Example alert</th><th>Last seen</th></tr>")
        foreach ($g in $techGroups) {
            $best = @($g.Group | Sort-Object Rank -Descending | Select-Object -First 1)
            $lvlClass = switch -Regex ("$($best.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
            $tacLbl = (@(Split-TagList $best.Tactic | ForEach-Object { Get-TacticLabel $_ }) -join ', ')
            $safeTech = "$($g.Tech)" -replace '[^A-Za-z0-9_]', ''
            $null = $sb.AppendLine("<tr class='techrow' title='click to show/hide the matched events' onclick=""var r=document.getElementById('ev_$safeTech'); r.style.display=(r.style.display==='none'?'':'none');""><td><b>$($g.Tech)</b></td><td>$(ConvertTo-HtmlEsc $tacLbl)</td><td>$($g.Count)</td><td class='$lvlClass'>$(ConvertTo-HtmlEsc $best.Level)</td><td>$(ConvertTo-HtmlEsc $best.Rule)</td><td>$(ConvertTo-HtmlEsc $best.Last)</td></tr>")
            $null = $sb.AppendLine("<tr id='ev_$safeTech' style='display:none'><td colspan='6'><table>")
            $null = $sb.AppendLine("<tr><th>Time</th><th>Alert</th><th>Level</th></tr>")
            foreach ($e in (@($g.Group | Sort-Object { "$($_.Last)" } -Descending) | Select-Object -First 25)) {
                $evCls = switch -Regex ("$($e.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                # v2.66 (B6): same-rule drill-down deep link - opens the rule's browser with the
                # filter box pre-filled to this exact event (RecordID, else EID). Rules without
                # a rendered drill-down stay plain text - never a dead link.
                $safeRl = Resolve-SafeRuleKey $safeRuleMap $e.Rule
                $qv6 = if ("$($e.Rid)") { "$($e.Rid)" } else { "$($e.Eid)" }
                $alertCell = if ($safeRl -and $drillSafeNames.Contains($safeRl) -and "$($qv6)") { "<a href='#sigma' class='a-drill' data-rule='$safeRl' data-q=""$(ConvertTo-HtmlEsc $qv6)"" title='open the Sigma drill-down for this rule, pre-filtered'>$(ConvertTo-HtmlEsc $e.Rule)</a>" } else { ConvertTo-HtmlEsc $e.Rule }
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $e.Last)</td><td>$alertCell</td><td class='$evCls'>$(ConvertTo-HtmlEsc $e.Level)</td></tr>")
            }
            $extra = $g.Count - [Math]::Min(25, $g.Count)
            if ($extra -gt 0) { $null = $sb.AppendLine("<tr><td colspan='3' class='meta'>first 25 of $($g.Count) - all events: csv\hayabusa_timeline.csv (filter MitreTags = $($g.Tech)) | drill-downs below in the Sigma section</td></tr>") }
            $null = $sb.AppendLine("</table></td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Click a technique row to expand the matched events. Source: csv\hayabusa_timeline.csv (MitreTactics/MitreTags). Reference: <a target='_blank' href='https://attack.mitre.org/techniques/enterprise/'>attack.mitre.org</a></div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No ATT&CK-tagged detections in the analyzed window.</div>")
    }
    $noTelNote = @()
    if (-not (Test-Path (Join-Path $RawDir 'evtx'))) { $noTelNote += 'No event logs exported - Sigma/ATT&CK coverage is nil for this collection.' }
    if (-not $Sysmon) { $noTelNote += 'No Sysmon - injection, image-load and per-process network techniques (e.g. T1055, T1003.001 via Sysmon) are not visible in these logs.' }
    if ($noTelNote.Count -gt 0) {
        $null = $sb.AppendLine("<div class='card'><b>Cannot rule out (telemetry gaps):</b><ul>")
        foreach ($n in $noTelNote) { $null = $sb.AppendLine("<li>$(ConvertTo-HtmlEsc $n)</li>") }
        $null = $sb.AppendLine("</ul></div>")
    }

    # ---------- IOC section ----------
    $null = $sb.AppendLine("<a name='ioc'></a><h2>Indicators of compromise</h2>")
    if ($iocHits.Count -gt 0) {
        $null = $sb.AppendLine("<h3>IOC hits (live system) - investigate first</h3><table><tr><th>Type</th><th>Indicator</th><th>Where</th><th>Context</th><th></th></tr>")
        foreach ($h in $iocHits) {
            $null = $sb.AppendLine("<tr><td><b>$($(ConvertTo-HtmlEsc $h.Type))</b></td><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td class='path'>$(ConvertTo-HtmlEsc $h.Where)</td><td>$(ConvertTo-HtmlEsc $h.Context)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($amcHits.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Historical execution IOC hits (amcache SHA1) - near-certain TP evidence</h3><table><tr><th>SHA1</th><th>Application</th><th>Source</th><th></th></tr>")
        foreach ($h in $amcHits) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td>$(ConvertTo-HtmlEsc $h.Application)</td><td>$(ConvertTo-HtmlEsc $h.SourceFile)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    # v2.78: the indicator block ($iocBlock/$iocUnique) builds up at the nav - its count feeds
    # the nav; only the rendering stays here
    if ($iocUnique.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Copy-ready indicator list (defanged) <button onclick='copyIocAll(this)' style='background:#243447;color:#9ec1f0;border:1px solid #3a5a83;border-radius:10px;padding:2px 12px;font-size:12px;cursor:pointer;margin-left:8px'>copy all</button></h3><pre class='ioc' id='iocblock'>")
        foreach ($l in $iocUnique) {
            $dl = "$l" -replace '(?i)http', 'hxxp'
            if ($dl -notmatch '^sha') { $dl = $dl -replace '\.', '[.]' }
            $null = $sb.AppendLine((ConvertTo-HtmlEsc $dl))
        }
        $null = $sb.AppendLine("</pre>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No indicators to export.</div>")
    }
    if (Test-CaseCsv 'ioc_export') {
        $null = $sb.AppendLine("<div class='meta'><b>Fleet memory:</b> this case exported $(@(Import-CaseCsv 'ioc_export').Count) high-confidence indicator(s) to <span style='font-family:Consolas,monospace'>ioc_export.csv</span> + <span style='font-family:Consolas,monospace'>raw\analysis\ioc_export.txt</span> (drop that txt into <span style='font-family:Consolas,monospace'>tools\iocs\</span> - future collections xref them, hash/domain/IP) + a STIX 2.1 bundle (<span style='font-family:Consolas,monospace'>ioc_export_stix.json</span>) for MISP/OpenCTI.</div>")
    }

    # ---------- findings by tactic (med+ alerts) ----------
    $null = $sb.AppendLine("<a name='tactics'></a><h2>Findings by tactic (med+ Sigma alerts)</h2>")
    # v2.78: $sigAlerts computed up at the nav build (one pass, its count feeds the nav)
    if ($sigAlerts.Count -gt 0) {
        $byTactic = @{}
        foreach ($r in $sigAlerts) {
            $tacs = @(Split-TagList "$($r.MitreTactics)")
            if ($tacs.Count -eq 0) { $tacs = @('Other') }
            foreach ($t in ($tacs | Select-Object -First 2)) {
                if (-not $byTactic.ContainsKey($t)) { $byTactic[$t] = New-Object System.Collections.Generic.List[object] }
                $byTactic[$t].Add($r)
            }
        }
        # v2.66 (B12): shared text filter over the tactic blocks
        $null = $sb.AppendLine("<div class='sbar'><input id='tacf' data-secfilter='1' data-wrap='tacwrap' data-sel='div.tacblk' data-cnt='cnt_tac' placeholder='filter tactics / alerts...' style='width:340px'> <span class='meta' id='cnt_tac'></span></div>")
        $null = $sb.AppendLine("<div id='tacwrap'>")
        foreach ($tk in ($byTactic.Keys | Sort-Object)) {
            $rows = @($byTactic[$tk])
            $null = $sb.AppendLine("<div class='tacblk'><h3>$(ConvertTo-HtmlEsc (Get-TacticLabel $tk)) ($($rows.Count) events)</h3><details><summary>show alerts</summary><table><tr><th>Alert</th><th>Level</th><th>Hits</th><th>Last seen</th></tr>")
            foreach ($g in @($rows | Group-Object RuleTitle | Sort-Object Count -Descending | Select-Object -First 15)) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvlClass = switch -Regex ("$($best.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $last = (@($g.Group | ForEach-Object { "$($_.Timestamp)" } | Sort-Object -Descending | Select-Object -First 1) -join '')
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td class='$lvlClass'>$(ConvertTo-HtmlEsc $best.Level)</td><td>$($g.Count)</td><td>$(ConvertTo-HtmlEsc $last)</td></tr>")
            }
            $null = $sb.AppendLine("</table></details></div>")
        }
        $null = $sb.AppendLine("</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No medium+ severity Sigma alerts in the analyzed window.</div>")
    }

    # ---------- YARA ----------
    $null = $sb.AppendLine("<a name='yara'></a><h2>YARA findings</h2>")
    if ($yaraHits.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Rule</th><th>Description</th><th>File</th></tr>")
        foreach ($y in ($yaraHits | Sort-Object { Get-LvlRank "$($_.Severity)" } -Descending)) {
            $sevCls = switch -Regex ("$($y.Severity)") { 'crit|high' { 'crit'; break } 'med' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $y.Severity)</b></td><td>$(ConvertTo-HtmlEsc $y.Rule)</td><td>$(ConvertTo-HtmlEsc $y.Description)</td><td class='path'>$(ConvertTo-HtmlEsc $y.File)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Scanned binaries: csv\yara_scanned.csv</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No YARA hits (or YARA module not run).</div>")
    }

    # ---------- process verdicts ----------
    # v2.78: the top-30 cap is stated in the heading when truncation happened (an empty
    # section keeps the plain heading - the v2.66 empty-state meta below explains absence)
    $procTop = @($scored | Sort-Object { ConvertTo-SafeInt $_.Score } -Descending | Select-Object -First 30)
    $procCap = if ($scored.Count -gt $procTop.Count) { " - showing $($procTop.Count) of $($scored.Count)" } else { '' }
    $null = $sb.AppendLine("<a name='processes'></a><h2>Process verdicts (correlation scored)$(ConvertTo-HtmlEsc $procCap)</h2>")
    # v2.66 (B12): shared text filter (one generic JS function, bound per section via data-attrs)
    if ($procTop.Count -gt 0) {
        $null = $sb.AppendLine("<div class='sbar'><input id='procf' data-secfilter='1' data-wrap='procwrap' data-sel='div.card' data-cnt='cnt_proc' placeholder='filter processes (name / path / evidence)...' style='width:340px'> <span class='meta' id='cnt_proc'></span></div>")
        $null = $sb.AppendLine("<div id='procwrap'>")
        foreach ($p in $procTop) {
            $evs = ($p.Evidence -split ';' | Where-Object { $_ }) | ForEach-Object { "<span class='ev'>$(ConvertTo-HtmlEsc $_)</span>" }
            $null = $sb.AppendLine("<div class='card'><span class='badge $($p.Verdict)'>$($p.Verdict) &nbsp;$($p.Score)</span><b>$(ConvertTo-HtmlEsc $p.Name)</b> <span class='meta'>PID $(ConvertTo-HtmlEsc $p.PID)</span> $(New-VtLink $p.Name)<br><span class='path'>$(ConvertTo-HtmlEsc $p.Path)</span><br>$($evs -join ' ')</div>")
        }
        $null = $sb.AppendLine("</div>")
    } else {
        # v2.66 (B15a): an empty Processes section used to render as nothing but the heading -
        # say WHY it is empty, honestly distinguishing "did not run" from "ran, nothing scored"
        $procWhy = if (Test-CaseCsv 'flash_process_scored') { 'the scoring module ran but recorded no processes above the reporting threshold' } else { 'source CSV flash_process_scored.csv is absent - the process scoring module did not run in this collection' }
        $null = $sb.AppendLine("<div class='meta'>No scored processes to show - $procWhy.</div>")
    }

    if ($hayRows.Count -gt 0) {
        $alertCol = $null
        foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
            if ($hayRows[0].PSObject.Properties[$cand]) { $alertCol = $cand; break }
        }
        $null = $sb.AppendLine("<a name='sigma'></a><h2>Top Sigma detections (hayabusa)</h2>")
        if ($alertCol) {
            $groups = $hayRows | Group-Object $alertCol | Sort-Object Count -Descending | Select-Object -First 20
            $null = $sb.AppendLine("<table><tr><th>Alert</th><th>Hits</th><th>Max level</th><th>Last seen</th></tr>")
            foreach ($g in $groups) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvl = "$($best.Level)"
                $lvlClass = switch -Regex ($lvl) { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $last = (@($g.Group | ForEach-Object { "$($_.Timestamp)" } | Sort-Object -Descending | Select-Object -First 1) -join '')
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td>$($g.Count)</td><td class='$lvlClass'>$(ConvertTo-HtmlEsc $lvl)</td><td>$(ConvertTo-HtmlEsc $last)</td></tr>")
            }
            $null = $sb.AppendLine("</table>")
        }
        # per-rule drill-down: matched events per rule (shared 5000-row embed budget),
        # client-side search + pager + click-to-copy - rendered by the shared script at the end
        $ruleJs = New-Object System.Collections.Generic.List[string]
        if ($hayRows.Count -gt 0) {
            $drill = @($hayRows | Group-Object $alertCol | Sort-Object Count -Descending | Select-Object -First 12)
            foreach ($g in $drill) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvl = "$($best.Level)"
                $lvlClass = switch -Regex ($lvl) { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $safe = Resolve-SafeRuleKey $safeRuleMap $g.Name
                $csvLink = "csv\sigma_rules\$safe.csv"
                $csvFull = Join-Path $CsvDir "sigma_rules\$safe.csv"
                # v2.66 (B10): this rule's share of the embed budget (precomputed with drillSafeNames)
                $take = [int]$drillTake[$safe]
                $parts = New-Object System.Collections.Generic.List[string]
                foreach ($r in (@($g.Group | Sort-Object Timestamp) | Select-Object -First $take)) {
                    $d = ("$($r.Details)") -replace '\s+', ' '
                    if ($d.Length -gt 800) { $d = $d.Substring(0, 800) + '...' }
                    $lc = switch -Regex ("$($r.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                    # v2.66 (B6): RecordID rides in the embed so a deep-linked q=RecordID hits
                    $rid6 = if ($r.PSObject.Properties['RecordID']) { "$($r.RecordID)" } else { '' }
                    try { $parts.Add(([pscustomobject]@{ t = "$($r.Timestamp)"; c = "$($r.Computer)"; e = "$($r.EventID)"; l = "$($r.Level)"; lc = $lc; d = $d; rid = $rid6 } | ConvertTo-Json -Compress)) } catch { }
                }
                # v2.66 (B10): the summary tells the truth - the drill-down holds the embedded
                # share, the rule's total match count lives in the (always linked) per-rule CSV
                $trunc6 = if ($take -lt $g.Count) { ", showing $take of $($g.Count) embedded" } else { '' }
                $null = $sb.AppendLine("<details><summary><span class='$lvlClass'><b>$(ConvertTo-HtmlEsc $g.Name)</b></span> - $($g.Count) hit(s)$trunc6, max <span class='$lvlClass'>$(ConvertTo-HtmlEsc $lvl)</span> &nbsp;<span class='meta'>$(ConvertTo-CaseFileLink $csvFull $csvLink)</span></summary>") # v2.66: pointer was a bare span - same case-file link as the neighbors
                if ($take -le 0) {
                    # v2.66 (B10): budget exhausted before this rule - filter/pager controls over
                    # an empty table would lie; summary + per-rule CSV pointer stay
                    $null = $sb.AppendLine("<div class='meta'>Embed budget exhausted before this rule - its $($g.Count) matched event(s) are not browsable inline. The full untruncated list is in the per-rule CSV above.</div>")
                } else {
                    $null = $ruleJs.Add("'$safe':[$($parts -join ',')]")
                    $lvlOpts = (@($g.Group | ForEach-Object { "$($_.Level)" } | Sort-Object -Unique) | ForEach-Object { "<option>$(ConvertTo-HtmlEsc $_)</option>" }) -join ''
                    # v2.68 (B14): datalist EIDs come from the rule's FULL row set (was: the embedded
                    # share only - budget-truncated EIDs were missing from the filter autocomplete).
                    # Deduped EIDs are tiny (distinct event IDs of one rule), so no cap is needed.
                    $eidOpts = (@($g.Group | ForEach-Object { "$($_.EventID)" } | Sort-Object -Unique) | ForEach-Object { "<option>$(ConvertTo-HtmlEsc $_)</option>" }) -join ''
                    $null = $sb.AppendLine("<div class='sbar'>filter <input id='q_$safe' list='ed_$safe' oninput=""renderRule('$safe')"" style='width:260px' placeholder='text in details/time/host/EID/RecordID'> level <select id='l_$safe' onchange=""renderRule('$safe')""><option value='all'>all</option>$lvlOpts</select> page <select id='ps_$safe' onchange=""renderRule('$safe')""><option>50</option><option>100</option><option>200</option><option value='all'>all embedded</option></select> <datalist id='ed_$safe'>$eidOpts</datalist> <span class='meta'>click a detail = copy raw - double-click = expand</span><input type='hidden' id='p_$safe' value='1'></div><div id='b_$safe'></div>")
                }
                $null = $sb.AppendLine("</details>")
            }
            if ($drill.Count -gt 0) { $null = $sb.AppendLine("<div class='meta'>Expand a rule to browse its matched events (search + page + copy). Rules truncated by the shared embed budget say so in their summary line - the full untruncated text is always in the per-rule CSV. RecordID locates the exact record in the matching evtx under raw\evtx\.</div>") }
        }
        $null = $sb.AppendLine("<div class='meta'>Full timeline: csv\hayabusa_timeline.csv &nbsp;|&nbsp; per-rule event CSVs: csv\sigma_rules\ &nbsp;|&nbsp; hayabusa's own summary: csv\hayabusa_report.html</div>")
    }

    # ---------- recovered attacker commands ----------
    if ($psCmds.Count -gt 0) {
        $null = $sb.AppendLine("<a name='pscmds'></a><h2>Recovered attacker commands (base64/obfuscated PowerShell)</h2>")
        $null = $sb.AppendLine("<table><tr><th>Time</th><th>Source event</th><th>Decoded content</th></tr>")
        foreach ($c in ($psCmds | Select-Object -First 30)) {
            $t = if ($c.PSObject.Properties['Timestamp']) { $c.Timestamp } else { '' }
            $src = if ($c.PSObject.Properties['Channel']) { "$($c.Channel) / $($c.EventID)" } else { '' }
            $txt = ''
            foreach ($p in @('DecodedText', 'Payload', 'Details', 'Message')) {
                if ($c.PSObject.Properties[$p] -and "$($c.$p)") { $txt = "$($c.$p)"; break }
            }
            if (-not $txt) { $txt = ($c.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' ' }
            $txtShow = if ($txt.Length -gt 400) { $txt.Substring(0, 400) + '...' } else { $txt }
            $txtAttr = (ConvertTo-HtmlEsc $txt) -replace '"', '&quot;'
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t)</td><td>$(ConvertTo-HtmlEsc $src)</td><td class='path clip' title='click = copy raw - show all expands' data-full=""$txtAttr"">$(ConvertTo-HtmlEsc $txtShow)</td></tr>")
        }
        # v2.68 (B13): N == M must not imply hidden rows - "First 30" when 30 == total
        $psCap = if ($psCmds.Count -gt 30) { "First 30 of $($psCmds.Count)" } else { "All $($psCmds.Count)" }
        $null = $sb.AppendLine("</table><div class='meta'>$psCap recovered commands (hayabusa extract-base64 over the exported PowerShell event logs). Source: csv\ps_decoded_commands.csv</div>")
    }

    # ---------- logon & account analysis ----------
    $null = $sb.AppendLine("<a name='logons'></a><h2>Logon & account activity</h2>")
    $inter = @($authEv | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -match '^(2|10)$' } |
        ForEach-Object { [pscustomobject]@{ Who = "$(if ("$($_.AccountDomain)") { "$($_.AccountDomain)\" })$($_.Account) @ $(if ("$($_.SourceIp)") { $_.SourceIp } else { '-' })" } } |
        Group-Object Who | Sort-Object Count -Descending | Select-Object -First 15)
    if ($inter.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Interactive / RDP logons</h3><table><tr><th>Account @ Source</th><th>Logons</th></tr>")
        foreach ($g in $inter) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td><b>$($g.Count)</b></td></tr>") }
        $null = $sb.AppendLine("</table>")
    }
    if ($authSum.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Top account/source combinations (all auth events)</h3><details><summary>show top 25</summary><table><tr><th>Account @ Source</th><th>Events</th></tr>")
        foreach ($a in ($authSum | Select-Object -First 25)) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $a.AccountSource)</td><td>$($a.Count)</td></tr>") }
        $null = $sb.AppendLine("</table></details>")
    }
    # v2.55: explicit-credential logons (4648) - the strongest lateral-movement tell on a
    # workstation. Previously invisible: the section hard-filtered to 4624 only.
    # ($secAll imported up at the top - its 4648/4672 rows feed the nav logons count)
    $e4648 = @($secAll | Where-Object { "$($_.Id)" -eq '4648' -or "$($_.EventId)" -eq '4648' })
    if ($e4648.Count -gt 0) {
        $e4648g = @($e4648 | ForEach-Object {
            $tgt = "$($_.TargetDomainName)"; if (-not $tgt) { $tgt = "$($_.TargetServerName)" }
            if (-not $tgt) { $tgt = "$($_.TargetUserName)" }
            [pscustomobject]@{ Target = $tgt; Proc = "$($_.ProcessName)" }
        } | Group-Object Target, Proc | Sort-Object Count -Descending | Select-Object -First 10)
        $null = $sb.AppendLine("<h3>Explicit-credential logons (4648) - $([int]$e4648.Count) event(s)</h3>")
        $null = $sb.AppendLine("<div class='meta'>A process supplied explicit credentials (username/password) to authenticate - common in admin automation, but also the shape of credential-use-after-theft. Verify the source account and tool.</div>")
        $null = $sb.AppendLine("<table><tr><th>Target @ Process</th><th>Events</th></tr>")
        foreach ($g in $e4648g) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td><b>$($g.Count)</b></td></tr>") }
        $null = $sb.AppendLine("</table>")
    }
    $e4672 = @($secAll | Where-Object { "$($_.Id)" -eq '4672' -or "$($_.EventId)" -eq '4672' })
    if ($e4672.Count -gt 0) {
        $e4672g = @($e4672 | ForEach-Object {
            [pscustomobject]@{ Who = "$(if ("$($_.AccountDomain)") { "$($_.AccountDomain)\" })$($_.Account)" }
        } | Group-Object Who | Sort-Object Count -Descending | Select-Object -First 8)
        $null = $sb.AppendLine("<h3>Special privileges assigned (4672) - $([int]$e4672.Count) event(s)</h3>")
        $null = $sb.AppendLine("<table><tr><th>Account</th><th>Events</th></tr>")
        foreach ($g in $e4672g) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td><b>$($g.Count)</b></td></tr>") }
        $null = $sb.AppendLine("</table>")
    }
    if ($brute.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Brute-force candidates</h3><table><tr><th>Source IP</th><th>Failed logons</th><th>VT</th></tr>") # v2.66 (B15b): the VT-links column was an unnamed <th></th>
        foreach ($b in $brute) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $b.SourceIp)</td><td><b>$($b.FailedLogons)</b></td><td>$(New-VtLink $b.SourceIp)</td></tr>") }
        $null = $sb.AppendLine("</table>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No brute-force candidate sources (threshold: 5+ failed logons). Hayabusa logon summaries: csv\logon_summary* (if module 4.6 ran).</div>")
    }

    # ---------- persistence inventory ----------
    $null = $sb.AppendLine("<a name='persistence'></a><h2>Persistence inventory</h2>")
    $persAny = $false
    if ($tasksFlag.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Flagged scheduled tasks</h3><table><tr><th>Task</th><th>Actions</th><th>Flags</th></tr>")
        foreach ($t in ($tasksFlag | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $t.Actions)</td><td>$(ConvertTo-HtmlEsc $t.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($taskCacheAnom.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Task cache anomalies (ghost / hidden scheduled tasks)</h3><table><tr><th>Kind</th><th>Guid</th><th>Task path</th><th>SD present</th><th>Flags</th></tr>")
        foreach ($t4 in ($taskCacheAnom | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t4.Kind)</td><td class='path'>$(ConvertTo-HtmlEsc $t4.Guid)</td><td class='path'>$(ConvertTo-HtmlEsc $t4.TaskPath)</td><td>$(ConvertTo-HtmlEsc $t4.SdPresent)</td><td class='crit'>$(ConvertTo-HtmlEsc $t4.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Deleting a task's Tree key + Tasks key + XML does not unload an already-loaded task until reboot; deleting the SD value hides it from schtasks/GUI while it still runs. ORPHANED = Tasks\{guid} with no Tree\GID link. Source: csv\scheduled_taskcache.csv</div>")
    }
    if ($taskDel.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Scheduled task deletions (EID 4699)</h3><table><tr><th>Time</th><th>Task</th><th>User</th></tr>")
        foreach ($t5 in ($taskDel | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t5.Time)</td><td class='path'>$(ConvertTo-HtmlEsc $t5.TaskName)</td><td>$(ConvertTo-HtmlEsc $t5.User)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Deletion alone is normal ops - correlate with the TaskCache anomalies above and recent 4698 installs. Source: csv\task_deletions.csv</div>")
    }
    if ($esentRows.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>ntds.dit access (ESENT 325/326)</h3><table><tr><th>Time</th><th>Pattern</th><th>Event</th></tr>")
        foreach ($e5 in ($esentRows | Select-Object -First 25)) {
            $pat5 = if ("$($e5.BackupPattern)" -eq 'True') { 'backup-pattern (verify schedule)' } else { 'NON-BACKUP - possible AD database theft' }
            $cls5 = if ("$($e5.BackupPattern)" -eq 'True') { 'info' } else { 'crit' }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $e5.Time)</td><td class='$cls5'>$(ConvertTo-HtmlEsc $pat5)</td><td class='path'>$(ConvertTo-HtmlEsc $e5.Message)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Something opened the Active Directory database. VSS/wbengine backup engines are the benign pattern; ntdsutil IFM or custom tooling is credential-theft prep (T1003.003). Source: csv\esent_ntds.csv</div>")
    }
    if ($svcFlag.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Flagged services</h3><table><tr><th>Service</th><th>Binary</th><th>Flags</th></tr>")
        foreach ($s in ($svcFlag | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $s.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $s.PathName)</td><td>$(ConvertTo-HtmlEsc $s.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($wmiBind.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>WMI event subscriptions (rare on clean hosts - review each)</h3><table><tr><th>Binding</th></tr>")
        foreach ($w in ($wmiBind | Select-Object -First 25)) {
            $line = ($w.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($runKeys.Count -gt 0) {
        $persAny = $true
        $rkLbl = if ($runKeys.Count -gt 60) { "showing first 60 of $($runKeys.Count) entries" } else { "show $($runKeys.Count) entries" }
        $null = $sb.AppendLine("<h3>Run keys / startup entries</h3><details><summary>$rkLbl</summary><table><tr><th>Name</th><th>Command</th></tr>")
        foreach ($r in ($runKeys | Select-Object -First 60)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $r.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $r.Value)</td></tr>")
        }
        $null = $sb.AppendLine("</table></details>")
    }
    if ($asepHot.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Uncommon persistence mechanisms (IFEO / AppInit / Winlogon / netsh / LSA)</h3><table><tr><th>Category</th><th>Target</th><th>Setting</th><th>Value</th><th>Flags</th></tr>")
        foreach ($a in ($asepHot | Select-Object -First 40)) {
            $target = ''
            try { $target = Split-Path "$($a.Location)" -Leaf } catch { }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $a.Category)</td><td>$(ConvertTo-HtmlEsc $target)</td><td>$(ConvertTo-HtmlEsc $a.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $a.Value)</td><td>$(ConvertTo-HtmlEsc $a.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>These autostart extensibility points are rarely used by legitimate software (exception: OEM Winlogon Shell entries). Full inventory incl. per-user COM: csv\asep_sweep.csv</div>")
    }
    # v2.78: $certHot computed up at the nav build (its count feeds the nav)
    if ($certHot.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Recently added self-signed certificates (root trust)</h3><table><tr><th>Store</th><th>Subject</th><th>NotBefore</th><th>Flags</th></tr>")
        foreach ($c in ($certHot | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.Store)</td><td>$(ConvertTo-HtmlEsc $c.Subject)</td><td>$(ConvertTo-HtmlEsc $c.NotBefore)</td><td>$(ConvertTo-HtmlEsc $c.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Enterprise root CAs are self-signed by design - verify against the org's PKI. Malware adds root CAs to enable HTTPS interception. Full inventory: csv\certificates.csv</div>")
    }
    if (-not $persAny) { $null = $sb.AppendLine("<div class='meta'>No persistence entries captured (modules not run or nothing found).</div>") }

    # ---------- execution history ----------
    if ($execRows.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Execution history highlights (user-writable paths)</h2><table>")
        $shown = 0
        foreach ($r in $execRows) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
            if ($line -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\') {
                $ts = ($r.PSObject.Properties | Select-Object -First 1).Value
                $pathCol = @($r.PSObject.Properties | Where-Object { "$($_.Value)" -match '(?i)\\.*\.(exe|dll|ps1|bat|scr|js|vbs)' } | Select-Object -First 1)
                $pv = if ($pathCol) { "$($pathCol.Value)" } else { $line }
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $ts)</td><td class='path'>$(ConvertTo-HtmlEsc $pv)</td></tr>")
                $shown++
                if ($shown -ge 40) { break }
            }
        }
        # v2.68 (B13): same equals-cap honesty on the execution-history caption
        $execCap = if ($shown -lt $execRows.Count) { "First $shown of $($execRows.Count) entries" } else { "All $shown entries" }
        $null = $sb.AppendLine("</table><div class='meta'>$execCap - full: csv\execution_timeline.csv</div>")
    }

    # ---------- file system forensics ----------
    $null = $sb.AppendLine("<a name='filesystem'></a><h2>File-system evidence (MFT / USN journal / prefetch)</h2>")
    if ($usnBursts.Count -gt 0) {
        $null = $sb.AppendLine("<div class='sig'><b>Ransomware-style mass file modification detected</b> - $($usnBursts.Count) window(s) with 1000+ write events per minute:</div>")
        $null = $sb.AppendLine("<table><tr><th>Window start</th><th>Write events</th><th>Distinct files</th></tr>")
        foreach ($u in ($usnBursts | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td class='crit'><b>$(ConvertTo-HtmlEsc $u.WindowStart)</b></td><td>$($u.WriteEvents)</td><td>$($u.DistinctFiles)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Legitimate mass changes (system updates, builds, AV signature storms) also trigger this. Cross-check the window against process/Sigma findings. Source: csv\artifacts\usn_write_bursts.csv</div>")
    }
    if ($pfParsed.Count -gt 0) {
        $rcCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'runcount|^run' } | Select-Object -First 1)[0]
        $lrCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'lastrun' } | Select-Object -First 1)[0]
        $exCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'executable|^name$' } | Select-Object -First 1)[0]
        $null = $sb.AppendLine("<h3>Most-run programs (prefetch)</h3><table><tr><th>Executable</th><th>Run count</th><th>Last run</th></tr>")
        $sorted = $pfParsed
        if ($rcCol) { $sorted = @($pfParsed | Sort-Object @{e = { ConvertTo-SafeInt $_.$rcCol } } -Descending) }
        foreach ($p in ($sorted | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $p.$exCol)</td><td>$(ConvertTo-HtmlEsc $p.$rcCol)</td><td>$(ConvertTo-HtmlEsc $p.$lrCol)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Prefetch run counts = program execution evidence (Win8+ cap 1024 files). Source: csv\prefetch_parsed.csv</div>")
    }
    if ($mftRecent.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Recently created / user-path executables (MFT)</h3><table><tr><th>Created</th><th>Path</th><th>Size</th><th>Flags</th></tr>")
        $mftSorted = $mftRecent
        try { $mftSorted = @($mftRecent | Sort-Object Created -Descending) } catch { }
        $shownM = 0
        foreach ($mr in $mftSorted) {
            if ("$($mr.Flags)" -notmatch 'user-path') { continue }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $mr.Created)</td><td class='path'>$(ConvertTo-HtmlEsc $mr.Path)</td><td>$(ConvertTo-HtmlEsc $mr.Size)</td><td>$(ConvertTo-HtmlEsc $mr.Flags)</td></tr>")
            $shownM++
            if ($shownM -ge 25) { break }
        }
        $null = $sb.AppendLine("</table><div class='meta'>$($mftRecent.Count) executable/user-path/recent entries kept (user-path ones shown). Source: csv\mft_recent.csv</div>")
    }
    if ($usnBursts.Count -eq 0 -and $pfParsed.Count -eq 0 -and $mftRecent.Count -eq 0) {
        $null = $sb.AppendLine("<div class='meta'>No NTFS forensics data (tools\MFTECmd missing, not elevated, or modules skipped).</div>")
    }

    # ---------- C2 beaconing ----------
    $null = $sb.AppendLine("<a name='beacons'></a><h2>C2 beaconing candidates (periodic outbound patterns)</h2>")
    if ($beacons.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Process</th><th>Remote</th><th>Events</th><th>Span</th><th>Interval</th><th>Jitter</th><th>Regularity</th><th>Flags</th></tr>")
        foreach ($b in ($beacons | Select-Object -First 30)) {
            $sevCls = switch -Regex ("$($b.Severity)") { '^high$' { 'crit'; break } '^medium$' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $b.Severity)</b></td><td class='path'>$(ConvertTo-HtmlEsc $b.Process)</td><td>$(New-VtLink $b.RemoteIp):$(ConvertTo-HtmlEsc $b.Port)</td><td>$($b.Events)</td><td>$($b.SpanMin)min</td><td>~$(ConvertTo-HtmlEsc $b.MedianIntervalSec)s</td><td>$(ConvertTo-HtmlEsc $b.Jitter)</td><td>$(ConvertTo-HtmlEsc $b.Regularity)</td><td>$(ConvertTo-HtmlEsc $b.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Regularity = share of inter-arrival times within 0.5x-1.5x of the median. Legitimate updaters/telemetry also beacon - weigh process path, signer and destination. Source: csv\beacon_candidates.csv</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No periodic outbound connection patterns detected (or no Sysmon network events available - requires Sysmon event ID 3).</div>")
    }
    if ($dnsBeacons.Count -gt 0) {
        $null = $sb.AppendLine("<h3>DNS beaconing (periodic domain queries)</h3><table><tr><th>Severity</th><th>Process</th><th>Domain</th><th>Resolved (public)</th><th>Queries</th><th>Span</th><th>Interval</th><th>Regularity</th><th>Flags</th></tr>")
        foreach ($b in ($dnsBeacons | Select-Object -First 30)) {
            $sevCls = switch -Regex ("$($b.Severity)") { '^high$' { 'crit'; break } '^medium$' { 'med'; break } default { 'info' } }
            $ripCell = if ("$($b.ResolvedIp)") { New-VtLink $b.ResolvedIp } else { '-' }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $b.Severity)</b></td><td class='path'>$(ConvertTo-HtmlEsc $b.Process)</td><td>$(ConvertTo-HtmlEsc $b.Domain)</td><td>$ripCell</td><td>$($b.Events)</td><td>$($b.SpanMin)min</td><td>~$(ConvertTo-HtmlEsc $b.MedianIntervalSec)s</td><td>$(ConvertTo-HtmlEsc $b.Regularity)</td><td>$(ConvertTo-HtmlEsc $b.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Same periodicity math applied to Sysmon DNS queries (event ID 22) - catches C2 that hides behind domains instead of raw IPs. Source: csv\dns_beacon_candidates.csv</div>")
    }

    # ---------- network ----------
    $null = $sb.AppendLine("<a name='network'></a><h2>Public connections (live)</h2>")
    if ($pubConns.Count -gt 0) {
        # v2.56: one row per destination with connection count + every talking process
        $entLeaf = @{}
        foreach ($eb3 in $entB) { if ("$($eb3.Path)") { $entLeaf[(Split-Path "$($eb3.Path)" -Leaf).ToLower()] = $true } }
        $null = $sb.AppendLine("<table><tr><th>Remote</th><th>Provider</th><th>Resolved (DNS)</th><th>Conns</th><th>Talking processes</th><th></th></tr>")
        # v2.82: DNS-attributed connections - resolve column + provider upgrade from domain
        $domByIp = @{}
        foreach ($cd in $connDns) { if ("$($cd.RemoteAddress)" -and -not $domByIp.ContainsKey("$($cd.RemoteAddress)")) { $domByIp["$($cd.RemoteAddress)"] = $cd } }
        foreach ($cg in ($pubConns | Group-Object RemoteAddress, RemotePort | Sort-Object Count -Descending | Select-Object -First 25)) {
            $c = $cg.Group[0]
            $prov = Get-IpCloudClass "$($c.RemoteAddress)"
            $dAtt = $domByIp["$($c.RemoteAddress)"]
            $prov2 = if ($dAtt) { "$($dAtt.Provider)".Trim() } else { '' }
        if (-not $prov -and @('', 'unknown') -notcontains $prov2) { $prov = "$($dAtt.Provider)" }
            if (-not $prov) { $prov = 'non-cloud' }
            $domCell = ''
            if ($dAtt -and "$($dAtt.ResolvedDomain)") { $domCell = "$(ConvertTo-HtmlEsc $dAtt.ResolvedDomain)"; if ("$($dAtt.DnsChain)") { $domCell = "<span title='$(ConvertTo-HtmlEsc $dAtt.DnsChain)'>$domCell</span>" } }
            elseif ($dAtt) { $domCell = "<span class='meta'>no cache entry</span>" }
            $talkers = @($cg.Group | ForEach-Object { $leaf = if ("$($_.ProcessPath)") { Split-Path "$($_.ProcessPath)" -Leaf } else { "PID $($_.PID)" }; [pscustomobject]@{ Leaf = $leaf; Pid = "$($_.PID)" } } | Sort-Object Leaf -Unique)
            $talkerCells = @($talkers | ForEach-Object {
                $t = "$(ConvertTo-HtmlEsc $_.Leaf)"
                if ($entLeaf.ContainsKey("$($_.Leaf)".ToLower())) { $t = "<a href='#entities'>$t</a>" }
                if ("$($_.Pid)") { $t += " (PID $($_.Pid))" }
                $t
            })
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.RemoteAddress):$(ConvertTo-HtmlEsc $c.RemotePort)</td><td>$(ConvertTo-HtmlEsc $prov)</td><td>$domCell</td><td><b>$($cg.Count)</b></td><td>$($talkerCells -join ', ')</td><td>$(New-VtLink $c.RemoteAddress)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Provider source: IP range or resolved-domain suffix. 'no cache entry' = the resolver cache had expired by collection time (normal; Sysmon EID22 would give full coverage). Hover the resolved name for the full CNAME chain.</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No public IP connections at collection time.</div>")
    }

    # ---------- driver check ----------
    $null = $sb.AppendLine("<a name='drivers'></a><h2>Driver check (LOLDrivers)</h2>")
    if ($lolHits.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Status</th><th>Driver</th><th>Display name</th><th>Path</th><th>SHA256</th></tr>")
        foreach ($l in ($lolHits | Sort-Object { "$($_.Status)" -eq 'malicious' } -Descending | Select-Object -First 25)) {
            $stCls = if ("$($l.Status)" -eq 'malicious') { 'crit' } else { 'med' }
            $null = $sb.AppendLine("<tr><td class='$stCls'><b>$(ConvertTo-HtmlEsc $l.Status)</b></td><td>$(ConvertTo-HtmlEsc $l.Name)</td><td>$(ConvertTo-HtmlEsc $l.DisplayName)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Path)</td><td class='path'>$(ConvertTo-HtmlEsc $l.SHA256)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'><b>malicious</b> = hash matches a driver known to be used in attacks (BYOVD / kernel exploits). <b>vulnerable</b> = known-exploitable driver that attackers can abuse for privilege escalation - replace it. Source: csv\loldrivers_hits.csv (datasets: loldrivers.io)</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No malicious/vulnerable driver matches (or tools\loldrivers datasets missing - run -Mode Setup, needs admin + module 1.6).</div>")
    }

    # ---------- hunt findings ----------
    # v2.76: honest default view - high/medium stay in the main table, low/info collapse into
    # a details block (nothing deleted; the case draft + verdict keep counting ALL findings)
    $mainRows = @($huntRows | Where-Object { "$($_.Severity)" -eq 'high' -or "$($_.Severity)" -eq 'medium' })
    $lowRows = @($huntRows | Where-Object { "$($_.Severity)" -ne 'high' -and "$($_.Severity)" -ne 'medium' })
    $hiN = @($mainRows | Where-Object { "$($_.Severity)" -eq 'high' }).Count
    $medN = @($mainRows | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
    $null = $sb.AppendLine("<a name='hunt'></a><h2>Hunt technique findings - $hiN high / $medN medium / $($lowRows.Count) informational</h2>")
    if ($huntRows.Count -gt 0) {
        $huntRowHtml = {
            param($h2)
            $sevCls = switch -Regex ("$($h2.Severity)") { 'high' { 'crit'; break } 'medium' { 'med'; break } default { 'info' } }
            # v2.77: leading-stamp normalization ONLY - a locale stamp that OPENS the evidence
            # cell ('10/12/2026 7:43:01 AM: ...') renders in the one Ophira stamp dialect; a
            # date anywhere after the leading stamp (quoted command lines, embedded evidence
            # text) stays verbatim, and text the regex matches but cannot parse stays verbatim.
            $ev2 = "$($h2.Evidence)"
            $lm = [regex]::Match($ev2, '^(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}(?::\d{2})?(?: [AP]M)?)(\s*:)')
            if ($lm.Success) {
                $ld = [datetime]::MinValue
                if ([datetime]::TryParse($lm.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$ld)) {
                    $ev2 = $ld.ToString('yyyy-MM-dd HH:mm') + $ev2.Substring($lm.Groups[1].Length)
                }
            }
            "<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $h2.Severity)</b></td><td>$(ConvertTo-HtmlEsc $h2.Rule)</td><td>$(ConvertTo-HtmlEsc $h2.Attck)</td><td class='path'>$(ConvertTo-HtmlEsc $h2.Entity)</td><td class='path'>$(ConvertTo-HtmlEsc $ev2)</td></tr>"
        }
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Rule</th><th>ATT&amp;CK</th><th>Entity</th><th>Evidence</th></tr>")
        foreach ($h2 in ($mainRows | Sort-Object { switch -Regex ("$($_.Severity)") { 'high' { 0 } 'medium' { 1 } default { 2 } } })) {
            $null = $sb.AppendLine((& $huntRowHtml $h2))
        }
        $null = $sb.AppendLine("</table><div class='meta'>High-severity rules are high-precision (version-info renames, side-loaded system DLLs, downloads staged outside Downloads, LSASS access, Office-to-interpreter chains, proxy-execution LOLBin command lines, admin-share staging, Defender tamper, DCSync, password spray, injection into LSASS or from user-writable paths, C2-style named pipes) and contribute to the verdict. Medium rules are report-only leads (download-exec with missing/uncheckable signature, UAC bypass pattern, future-birth / execution-predates-birth timestamps, Kerberoasting/AS-REP patterns, web anomalies, privilege-boundary injection without a privilege tell). Low rows (extracted-archive birth-attribute skew, discovery command storms, protected-pair injection) are collapsed below as context. Verify against the cited raw evidence. Source: csv\hunt_findings.csv</div>")
        if ($lowRows.Count -gt 0) {
            $null = $sb.AppendLine("<details><summary>Low / informational findings ($($lowRows.Count))</summary><table><tr><th>Severity</th><th>Rule</th><th>ATT&amp;CK</th><th>Entity</th><th>Evidence</th></tr>")
            foreach ($h2 in $lowRows) {
                $null = $sb.AppendLine((& $huntRowHtml $h2))
            }
            $null = $sb.AppendLine("</table></details>")
        }
        if ($Sysmon -and @(Import-CaseCsv 'sysmon_process_access').Count -eq 0 -and @(Import-CaseCsv 'sysmon_remote_thread').Count -eq 0 -and @(Import-CaseCsv 'sysmon_pipes').Count -eq 0) {
            $null = $sb.AppendLine("<div class='meta'><b>Sysmon config gap:</b> Sysmon is running but no ProcessAccess (EID 10) / remote-thread (EID 8) / named-pipe (EID 17/18) telemetry arrived - the endpoint's own Sysmon config does not capture it, so the LSASS/injection/pipe rules above run blind. Ophira never touches the endpoint; if widening the coverage matters, the Sysmon owner can extend their config (or stock Sysmon defaults capture all of these) and you collect again.</div>")
        }
    } else {
        $null = $sb.AppendLine("<div class='meta'>No hunt findings - all techniques clean.</div>")
    }

    # ---------- hour-of-day execution histogram (v2.81 T3 - the R38 data, report-side) ----------
    # Recomputed from the same csvs hunt rule R38 reads: same column probes, same src|leaf
    # first-seen dedupe, hour from the first-seen timestamp. Inlined (not a helper) so report
    # renders stay self-contained; locals all $h38-prefixed to keep this huge function's scope
    # clean. Pure div bars - no JS/canvas - chrome via existing classes (card/meta), geometry
    # inline (same class+inline split as the coverage bar), so dark theme + print both hold.
    $h38Seen = @{}
    $h38Counts = @{}   # hour 0-23 -> distinct first-seen binary count
    $h38Leaves = @{}   # hour 0-23 -> List[string] of the leaf names (tooltip evidence)
    foreach ($h38Src in @('amcache', 'prefetch_parsed', 'security_proc_events', 'sysmon_proc_create')) {
        foreach ($h38Row in @(Import-CaseCsv $h38Src)) {
            try {
                $h38Raw = $null
                foreach ($h38Col in @('Path', 'Executable', 'FullPath', 'Name', 'ApplicationName')) {
                    $h38P = $h38Row.PSObject.Properties[$h38Col]
                    if ($h38P -and $h38P.Value) { $h38Raw = "$($h38P.Value)".Trim(); break }
                }
                if (-not $h38Raw) { continue }
                $h38Leaf = (Split-Path $h38Raw -Leaf).ToLower()
                if (-not $h38Leaf) { continue }
                $h38Ts = $null
                foreach ($h38Pn in (@($h38Row.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$|lastrun|^time' })) {
                    $h38Dt = Get-InvariantDate "$($h38Row.$h38Pn)"
                    if ($h38Dt -gt [datetime]::MinValue) { $h38Ts = $h38Dt; break }
                }
                if (-not $h38Ts) { continue }
                $h38Key = "$h38Src|$h38Leaf"
                if ($h38Seen.ContainsKey($h38Key)) { continue }
                $h38Seen[$h38Key] = $true
                $h38H = $h38Ts.Hour
                if (-not $h38Counts.ContainsKey($h38H)) { $h38Counts[$h38H] = 0; $h38Leaves[$h38H] = New-Object System.Collections.Generic.List[string] }
                # same leaf first-seen by a second source in the same hour = one distinct binary
                if (-not $h38Leaves[$h38H].Contains($h38Leaf)) { $h38Counts[$h38H]++; $null = $h38Leaves[$h38H].Add($h38Leaf) }
            } catch { }
        }
    }
    $h38Total = 0
    foreach ($h38N in $h38Counts.Values) { $h38Total += $h38N }
    if ($h38Total -gt 0) {
        $h38Max = 1
        foreach ($h38N in $h38Counts.Values) { if ($h38N -gt $h38Max) { $h38Max = $h38N } }
        $h38Cells = New-Object System.Text.StringBuilder
        for ($h38H = 0; $h38H -le 23; $h38H++) {
            $h38N = 0
            if ($h38Counts.ContainsKey($h38H)) { $h38N = $h38Counts[$h38H] }
            $h38Bar = [Math]::Max(1, [int][Math]::Round(64 * $h38N / $h38Max))
            $h38Names = ''
            if ($h38Leaves.ContainsKey($h38H)) { $h38Names = ': ' + (@($h38Leaves[$h38H].ToArray()) -join ', ') }
            $h38Tip = ConvertTo-HtmlEsc ("{0:00}:00 - {1} first-seen{2}" -f $h38H, $h38N, $h38Names)
            $null = $h38Cells.Append("<div style='display:inline-block;margin-right:2px;text-align:center'><div style='height:64px;width:18px;position:relative'><div style='position:absolute;bottom:0;left:0;width:18px;height:${h38Bar}px;background:#4d8fd1' title='$h38Tip'></div></div><div style='font-size:10px;color:#7d8590'>$('{0:00}' -f $h38H)</div></div>")
        }
        $null = $sb.AppendLine("<div class='card'><b>Execution first-seen by hour of day</b> <span class='meta'>(sources: amcache + prefetch_parsed + 4688 + Sysmon EID1; first-seen per binary, deduped across sources - hour is local time; hover a bar for its binaries; tallest bar = $h38Max)</span><div style='margin-top:8px'>$($h38Cells.ToString())</div></div>")
    }

    if ($liveScan.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Live memory triage (flagged-process minidumps)</h3><table><tr><th>Process</th><th>PID</th><th>Verdict</th><th>Dump</th><th>MB</th><th>YARA hits in memory</th></tr>")
        foreach ($l in $liveScan) {
            $hCls = if ("$($l.YaraHits)") { 'crit' } else { 'info' }
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $l.Process)</td><td>$(ConvertTo-HtmlEsc $l.PID)</td><td>$(ConvertTo-HtmlEsc $l.Verdict)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Dump)</td><td>$($l.DumpMB)</td><td class='$hCls'><b>$(ConvertTo-HtmlEsc $l.YaraHits)</b></td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Minidumps contain unpacked/injected code - YARA hits here mean the pattern lives in MEMORY even if disk scans missed it. Dumps ship in raw\minidumps\ and open in Volatility. Source: csv\memory_live_scan.csv</div>")
    }

    # ---------- connections: correlated entities ----------
    $null = $sb.AppendLine("<a name='entities'></a><h2>Connections - correlated entities</h2>")
    $null = $sb.AppendLine("<div class='meta'>Each entity below joins evidence from multiple independent sources (processes, execution history, persistence, network, SRUM usage, YARA, Sigma...) into one story. More categories touching one binary = stronger signal. Full data: csv\entities_binaries.csv / entities_accounts.csv / entities_remotes.csv</div>")
    $entAll = @($entB | Where-Object { (ConvertTo-SafeInt $_.CatCount) -ge 2 } | Sort-Object { ConvertTo-SafeInt $_.CatCount } -Descending)
    $entTop = @($entAll | Select-Object -First 12)
    if ($entTop.Count -gt 0) {
        if ($entAll.Count -gt $entTop.Count) {
            $ebLbl = "csv\$(Get-CaseCsvPath 'entities_binaries')"
            $ebLink = ConvertTo-CaseFileLink (Join-Path $CsvDir (Get-CaseCsvPath 'entities_binaries')) $ebLbl
            $null = $sb.AppendLine("<div class='meta'>Showing the top $($entTop.Count) of <b>$($entAll.Count)</b> multi-source binaries - full list: $ebLink</div>")
        }
        # master-timeline context for the top cards: rows within +/-30 min of the entity's first seen
        # (supertimeline Timestamps are UTC wall-clock per the weave contract - compare raw ticks
        # against the converted $fs below; do NOT re-shift either side)
        $tlPre = @()
        try {
            $tlPre = @($tlRows | ForEach-Object { $t = Get-InvariantDate $_.Timestamp; if ($t -gt [datetime]::MinValue) { [pscustomobject]@{ T = $t; Row = $_ } } })
        } catch { }
        # v2.66 (B12): shared text filter over the entity cards
        $null = $sb.AppendLine("<div class='sbar'><input id='entf' data-secfilter='1' data-wrap='entwrap' data-sel='details' data-cnt='cnt_ent' placeholder='filter entities (name / path / evidence)...' style='width:340px'> <span class='meta' id='cnt_ent'></span></div>")
        $null = $sb.AppendLine("<div id='entwrap'>")
        foreach ($e in $entTop) {
            $vCls = switch -Regex ("$($e.Verdict)") { 'HIGH' { 'crit'; break } 'MEDIUM' { 'med'; break } default { 'info' } }
            $vTxt = if ("$($e.Verdict)") { ", verdict <span class='$vCls'>$($e.Verdict)</span>" } else { '' }
            $null = $sb.AppendLine("<details><summary><b>$(ConvertTo-HtmlEsc $e.Name)</b> - <span class='high'>$($e.CatCount) evidence categories</span>$vTxt</summary>")
            $null = $sb.AppendLine("<table><tr><th>Path</th><th>First seen</th><th>Last seen</th><th>Signer</th><th>Hashes</th></tr>")
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $e.Path)</td><td>$(ConvertTo-HtmlEsc $e.FirstSeen)</td><td>$(ConvertTo-HtmlEsc $e.LastSeen)</td><td>$(ConvertTo-HtmlEsc $e.Signer)</td><td class='path'>$(ConvertTo-HtmlEsc $e.Hashes)</td></tr></table>")
            # v2.56: "appears in" chips - each category links to the section carrying its evidence
            # v2.66 (B8): unmapped categories render as grey/dead chips (informational, not
            # broken); chip order is name-sorted via Sort-Object -Unique (stable across renders)
            $entSrcs = @(("$($e.Evidence)" -split ' \| ') | ForEach-Object { ("$_" -split ': ', 2)[0] } | Sort-Object -Unique)
            if ($entSrcs.Count -gt 0) {
                $null = $sb.AppendLine("<div style='margin:4px 0'>appears in:")
                foreach ($src2 in $entSrcs) {
                    $anc2 = Get-SectionAnchorForSource $src2
                    if ($anc2) { $null = $sb.AppendLine("<a href='#$anc2'><span class='chip'>$(ConvertTo-HtmlEsc $src2)</span></a>") }
                    else { $null = $sb.AppendLine("<span class='chip chipdead'>$(ConvertTo-HtmlEsc $src2)</span>") }
                }
                $null = $sb.AppendLine("</div>")
            }
            if ("$($e.Bytes)") { $null = $sb.AppendLine("<div class='meta'>SRUM network usage history: $(ConvertTo-HtmlEsc $e.Bytes)</div>") }
            $null = $sb.AppendLine("<table><tr><th>Source</th><th>Detail</th></tr>")
            foreach ($ev in (("$($e.Evidence)" -split ' \| ') | Select-Object -First 14)) {
                $parts = "$ev" -split ': ', 2
                $srcAnc = Get-SectionAnchorForSource $parts[0]
                $srcCell = if ($srcAnc) { "<a href='#$srcAnc'><b>$(ConvertTo-HtmlEsc $parts[0])</b></a>" } else { "<b>$(ConvertTo-HtmlEsc $parts[0])</b>" }
                # v2.66 (B8): the Detail cell links to the section too when the source is mapped
                $det6 = ($parts[1..($parts.Length-1)] -join ': ')
                $detCell = if ($srcAnc) { "<a href='#$srcAnc'>$(ConvertTo-HtmlEsc $det6)</a>" } else { ConvertTo-HtmlEsc $det6 }
                $null = $sb.AppendLine("<tr><td>$srcCell</td><td class='path'>$detCell</td></tr>")
            }
            $null = $sb.AppendLine("</table>")
            # +/-30 min context window around first seen, pulled from the master timeline
            $fs = Get-InvariantDate $e.FirstSeen
            if ($fs -gt [datetime]::MinValue) { $fs = $fs.ToUniversalTime() } else { $fs = $null }
            if ($fs -and $tlPre.Count -gt 0) {
                $lo = $fs.AddMinutes(-30); $hi = $fs.AddMinutes(30)
                $ctx = @($tlPre | Where-Object { $_.T -ge $lo -and $_.T -le $hi } | Select-Object -First 15)
                if ($ctx.Count -gt 0) {
                    $stLbl = "csv\$(Get-CaseCsvPath 'supertimeline')"
                    $stLink = ConvertTo-CaseFileLink (Join-Path $CsvDir (Get-CaseCsvPath 'supertimeline')) $stLbl
                    $null = $sb.AppendLine("<div class='meta'><b>Context: everything else happening &plusmn;30 min around first seen $($fs.ToString('yyyy-MM-dd HH:mm')) UTC</b> (full window: $stLink - build a per-entity dossier with <b>-Mode Focus -ProcessName $($e.Name)</b>)</div>")
                    $null = $sb.AppendLine("<table><tr><th>Time</th><th>Type</th><th>Actor</th><th>Detail</th></tr>")
                    foreach ($c2 in $ctx) {
                        $r2 = $c2.Row
                        $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $r2.Timestamp)</td><td>$(ConvertTo-HtmlEsc $r2.Type)</td><td>$(ConvertTo-HtmlEsc $r2.Actor)</td><td class='path'>$(ConvertTo-HtmlEsc ("$($r2.Entity) $($r2.Detail)".Trim()))</td></tr>")
                    }
                    $null = $sb.AppendLine("</table>")
                }
            }
            $null = $sb.AppendLine("</details>")
        }
        $null = $sb.AppendLine("</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No multi-source binary correlations in this case (a binary must appear in 2+ independent evidence sources to be listed here).</div>")
    }
    if ($entA.Count -gt 0 -and @($entA | Where-Object { (ConvertTo-SafeInt $_.Logons) -gt 0 -or (ConvertTo-SafeInt $_.Failed) -gt 0 -or "$($_.RdpOutTargets)" -or (ConvertTo-SafeDbl $_.ConsoleHistoryKB) -gt 0 }).Count -gt 0) {
        $null = $sb.AppendLine("<h3>Account activity</h3><table><tr><th>Account</th><th>Logons</th><th>Failed</th><th>Logon types</th><th>Source IPs</th><th>RDP out to</th><th>Console hist</th></tr>")
        foreach ($a2 in ($entA | Select-Object -First 10)) {
            $fCls = if ((ConvertTo-SafeInt $a2.Failed) -ge 5) { 'crit' } elseif ((ConvertTo-SafeInt $a2.Failed) -gt 0) { 'med' } else { 'info' }
            $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $a2.Account)</b></td><td>$($a2.Logons)</td><td class='$fCls'>$($a2.Failed)</td><td>$(ConvertTo-HtmlEsc $a2.LogonTypes)</td><td>$(ConvertTo-HtmlEsc $a2.Sources)</td><td class='path'>$(ConvertTo-HtmlEsc $a2.RdpOutTargets)</td><td>$($a2.ConsoleHistoryKB) KB</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($entR.Count -gt 0 -and @($entR | Where-Object { (ConvertTo-SafeInt $_.Connections) -gt 0 -or "$($_.Beacon)" -or (ConvertTo-SafeInt $_.FailedLogons) -gt 0 -or (ConvertTo-SafeInt $_.RdpOutCount) -gt 0 }).Count -gt 0) {
        $null = $sb.AppendLine("<h3>Remote endpoints</h3><table><tr><th>Remote</th><th>Public</th><th>Conns</th><th>Talkers</th><th>Beacon</th><th>Failed logons</th><th>RDP out</th></tr>")
        foreach ($e in ($entR | Select-Object -First 12)) {
            $bCls = switch -Regex ("$($e.Beacon)") { 'high' { 'crit'; break } 'medium' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $e.Remote) $(New-VtLink $e.Remote)</td><td>$(ConvertTo-HtmlEsc $e.Public)</td><td>$($e.Connections)</td><td class='path'>$(ConvertTo-HtmlEsc $e.Talkers)</td><td class='$bCls'>$(ConvertTo-HtmlEsc $e.Beacon)</td><td class='$(if ((ConvertTo-SafeInt $e.FailedLogons) -gt 0) { 'crit' } else { 'info' })'>$($e.FailedLogons)</td><td>$($e.RdpOutCount)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($srumRows.Count -gt 0) {
        $appCol = @($srumRows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)^(app|application|path|name|image)' } | Select-Object -First 1)[0]
        $numCols = @($srumRows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)byte|sent|recv' })
        if ($appCol -and $numCols.Count -gt 0) {
            $null = $sb.AppendLine("<h3>Top network consumers (SRUM - per-app history)</h3><table><tr><th>Application</th>$((($numCols | Select-Object -First 4) | ForEach-Object { "<th>$(ConvertTo-HtmlEsc $_)</th>" }) -join '')</tr>")
            $srumTop = $srumRows
            try {
                $srumTop = @($srumRows | Sort-Object -Property @{e = { $t = 0.0; foreach ($nc in ($numCols | Select-Object -First 4)) { $p2 = $_.PSObject.Properties[$nc]; if ($p2) { $t += (ConvertTo-SafeDbl $p2.Value) } }; $t }; Descending = $true } | Select-Object -First 12)
            } catch { }
            foreach ($s2 in $srumTop) {
                $cells = ($numCols | Select-Object -First 4) | ForEach-Object { $p2 = $s2.PSObject.Properties[$_]; "<td>$(ConvertTo-HtmlEsc $(if ($p2) { $p2.Value }))</td>" }
                $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $s2.$appCol)</td>$($cells -join '')</tr>")
            }
            $null = $sb.AppendLine("</table><div class='meta'>SRUM records ~30 days of per-application network/resource usage. High sustained upload from a user-path binary = exfiltration candidate. Source: csv\$(Get-CaseCsvPath 'srum_usage')</div>")
        }
    }
    # v2.21: process lineage + session-attributed activity ($chains/$sessAct imported at the top)
    if ($chains.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Process lineage (how flagged binaries got there)</h3><table><tr><th>Flagged binary</th><th>Hops</th><th>Ancestry chain</th></tr>")
        foreach ($c in ($chains | Sort-Object { ConvertTo-SafeInt $_.Steps } -Descending | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $c.Entity)</td><td>$($c.Steps)</td><td class='path'><b>$(ConvertTo-HtmlEsc $c.Chain)</b>$(if ("$($c.Evidence)") { "<br>$(ConvertTo-HtmlEsc $c.Evidence)" })</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Rebuilt from 4688 parent-child + live PPID map. A user-path binary whose ancestry runs through office/browser/interpreter processes is a phishing/exploit story; ancestry from services.exe with no matching install event is suspicious. Source: csv\$(Get-CaseCsvPath 'process_chains')</div>")
    }
    if ($sessAct.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Attributed activity (which session did what)</h3><table><tr><th>Time</th><th>Session account</th><th>Source IP</th><th>Type</th><th>Logon</th><th>Activity</th></tr>")
        foreach ($s2 in ($sessAct | Select-Object -First 30)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $s2.Time)</td><td><b>$(ConvertTo-HtmlEsc $s2.SessionAccount)</b></td><td>$(ConvertTo-HtmlEsc $s2.SourceIp)</td><td>$(ConvertTo-HtmlEsc $s2.Activity)</td><td>$(ConvertTo-HtmlEsc $s2.LogonType)</td><td class='path'>$(ConvertTo-HtmlEsc $s2.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>4624 LogonId joined to 4688/5145 SubjectLogonId: even service/shared accounts are tied back to the interactive/RDP/network session that created them. Source: csv\$(Get-CaseCsvPath 'session_activity')</div>")
    }

    # ---------- host snapshot ----------
    $null = $sb.AppendLine("<a name='snapshot'></a><h2>Host snapshot (AV state, stored credentials, outbound RDP)</h2>")
    $snapAny = $false
    if ($defStatus.Count -gt 0) {
        $snapAny = $true
        $d = $defStatus[0]
        $null = $sb.AppendLine("<div>Defender: RealTimeProtection <b>$(ConvertTo-HtmlEsc $d.RealTimeProtection)</b>, AMService <b>$(ConvertTo-HtmlEsc $d.AMServiceEnabled)</b>, signature age <b>$(ConvertTo-HtmlEsc $d.AntivirusSigAgeDays)</b> day(s)</div>")
    }
    if ($defThreats.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Defender detection history</h3><table><tr><th>Threat</th><th>Active</th><th>Resource</th></tr>")
        foreach ($t in ($defThreats | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t.ThreatName)</td><td>$(ConvertTo-HtmlEsc $t.IsActive)</td><td class='path'>$(ConvertTo-HtmlEsc "$($t.Resources)")</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    # v2.78: $credSweep imported up at the nav build (its count feeds the nav)
    if ($credSweep.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Credential exposure sweep</h3><table><tr><th>Risk</th><th>Item</th><th>Detail</th></tr>")
        foreach ($c3 in ($credSweep | Select-Object -First 12)) {
            $rCls = switch -Regex ("$($c3.Risk)") { 'HIGH' { 'crit'; break } 'MEDIUM' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$rCls'><b>$(ConvertTo-HtmlEsc $c3.Risk)</b></td><td>$(ConvertTo-HtmlEsc $c3.Item)</td><td class='path'>$(ConvertTo-HtmlEsc $c3.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>WLAN keys and DPAPI vault blobs ship under raw\ for analyst-side handling only - treat the case folder as sensitive material. Source: csv\credential_sweep.csv</div>")
    }
    if ($savedCreds.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Stored credentials on this host (lateral movement risk)</h3><table><tr><th>Entry</th></tr>")
        foreach ($c in ($savedCreds | Select-Object -First 15)) {
            $line = ($c.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Source: csv\saved_credentials.csv</div>")
    }
    if ($rdpTgt.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Outbound RDP targets (where users RDP'd to)</h3><table><tr><th>Entry</th></tr>")
        foreach ($r in ($rdpTgt | Select-Object -First 15)) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Source: csv\rdp_client_targets.csv - attacker RDP outbound shows lateral movement destinations.</div>")
    }
    if ($bitsJobs.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>BITS transfer jobs</h3><table><tr><th>Name</th><th>Owner</th><th>State</th><th>Files</th></tr>")
        foreach ($b in ($bitsJobs | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $b.DisplayName)</td><td>$(ConvertTo-HtmlEsc $b.OwnerAccount)</td><td>$(ConvertTo-HtmlEsc $b.JobState)</td><td class='path'>$(ConvertTo-HtmlEsc $b.Files)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>BITS is abused for stealthy persistence/download. Source: csv\bits_jobs.csv</div>")
    }
    if ($radarRows.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>RADAR diagnosed applications (execution evidence)</h3><table><tr><th>Application</th><th>Key last write (executed on or before)</th></tr>")
        foreach ($r6 in ($radarRows | Select-Object -First 20)) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $r6.Application)</td><td>$(ConvertTo-HtmlEsc $r6.KeyLastWrite)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Windows RADAR memory diagnostics recorded these apps crossing the heap threshold - the key's LastWriteTime is execution evidence that survives Prefetch deletion and works on servers with Prefetch disabled. Source: csv\radar_exec.csv</div>")
    }
    if ($aswRows.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>App focus switches (taskbar FeatureUsage)</h3><table><tr><th>User</th><th>App</th><th>Switches</th></tr>")
        foreach ($a3 in (@($aswRows | Sort-Object -Property @{Expression = { [int]($_.SwitchCount) }; Descending = $true } -ErrorAction SilentlyContinue) | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $a3.User)</td><td class='path'>$(ConvertTo-HtmlEsc $a3.App)</td><td>$(ConvertTo-HtmlEsc $a3.SwitchCount)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Counters only (no timestamps) - what the interactive user actually switched to. An interactive attacker session shows here too. Source: csv\appswitched.csv</div>")
    }
    if ($memMfR.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Memory analysis: malfind (possible code injection)</h3><table><tr><th>Process</th><th>PID</th><th>Protection</th></tr>")
        foreach ($m in ($memMfR | Select-Object -First 20)) {
            $null = $sb.AppendLine("<tr><td class='crit'>$(ConvertTo-HtmlEsc $m.Process)</td><td>$(ConvertTo-HtmlEsc $m.PID)</td><td>$(ConvertTo-HtmlEsc $m.Protection)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Malfind flags VAD regions with RWX attributes - verify with a full memory workup (false positives possible for legit packed software). Source: csv\memory_malfind.csv</div>")
    }
    if ($browserIocR.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Browser history IOC hits (visited IOC-listed domains)</h3><table><tr><th>Domain</th><th>URL</th><th>Title</th></tr>")
        foreach ($b2 in ($browserIocR | Select-Object -First 20)) {
            $null = $sb.AppendLine("<tr><td class='crit'>$(ConvertTo-HtmlEsc $b2.Indicator)</td><td class='path'>$(ConvertTo-HtmlEsc $b2.URL)</td><td>$(ConvertTo-HtmlEsc $b2.Title)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>A visit is not proof of compromise - but phishing/initial-access often starts here. Source: csv\ioc_hits_browser.csv</div>")
    }
    if ($posture.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Security posture (hardening audit)</h3><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>")
        $postureSorted = @($posture | Sort-Object @{e = { switch -Regex ("$($_.Status)") { 'BAD' { 0 } 'WARN' { 1 } default { 2 } } } })
        foreach ($p2 in $postureSorted) {
            $stCls = switch ("$($p2.Status)") { 'BAD' { 'crit' } 'WARN' { 'med' } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$stCls'><b>$(ConvertTo-HtmlEsc $p2.Status)</b></td><td>$(ConvertTo-HtmlEsc $p2.Check)</td><td>$(ConvertTo-HtmlEsc $p2.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Weak posture = attack path. BAD findings are listed in the recommendations below. Source: csv\posture.csv</div>")
    }
    if (-not $snapAny) { $null = $sb.AppendLine("<div class='meta'>No snapshot data captured (relevant modules skipped).</div>") }

    # ---------- timeline (v2.42: rendered chronology + filter, CSV stays the source of truth) ----------
    $tlAll = $tlRows
    $tlSources = @($tlAll | ForEach-Object { "$($_.Source)" } | Sort-Object -Unique)
    $null = $sb.AppendLine("<a name='timeline'></a><h2>Master timeline (gathered evidence chronology)</h2>")
    $null = $sb.AppendLine("<div class='card'>The full chronology lives in <b>csv\$(ConvertTo-HtmlEsc (Get-CaseCsvPath 'supertimeline'))</b> ($(ConvertTo-HtmlEsc $tlAll.Count) events from $($tlSources.Count) evidence sources - open it in Excel/Timeline Explorer and filter by Timestamp). Evidence sources woven: $(ConvertTo-HtmlEsc ($tlSources -join ', ')). Per-source row caps (200-5000 per source) keep the file bounded - when a cap bites, the NEWEST events of that source are kept, and the total file is capped at the newest 120,000 events. Scanner conclusions (Sigma detections, hunt findings, beacons) are intentionally NOT part of it - they have their own sections above. For windowed pivots with per-source/busiest-minute summaries run <b>-Mode Timeline</b>.</div>")
    if ($scExec.Count -gt 0) {
        $scNo = @($scExec | Where-Object { $_.Executed -eq 'no' })
        $scYes = @($scExec | Where-Object { $_.Executed -eq 'yes' })
        $null = $sb.AppendLine("<h3>Shimcache executed-flag (Win10+ records, decoded from the raw entry blob)</h3>")
        $null = $sb.AppendLine("<div class='meta'>$($scYes.Count) executed-flag / $($scNo.Count) not-executed-flag of $($scExec.Count) decoded entries. The flag is CONFIDENCE, not proof: a right-click context-menu open can set it without execution, and flag=0 is not evidence of non-execution. Only non-native binaries get shimcache entries at all on Win10+. Compare the not-executed rows against amcache/prefetch/BAM timestamps for timestamp-scrub detection. Source: csv\shimcache_exec.csv</div>")
        if ($scNo.Count -gt 0) {
            $null = $sb.AppendLine("<details><summary>$($scNo.Count) entries flagged NOT executed</summary><table><tr><th>Path</th><th>Last modified</th><th>Executed</th></tr>")
            foreach ($s3 in ($scNo | Select-Object -First 30)) {
                $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $s3.Path)</td><td>$(ConvertTo-HtmlEsc $s3.LastModified)</td><td>$(ConvertTo-HtmlEsc $s3.Executed)</td></tr>")
            }
            $null = $sb.AppendLine("</table></details>")
        }
    }
    if ($tlAll.Count -gt 0) {
        # v2.59: per-day activity sparkline - the case's shape at a glance before the newest-150 table
        # task 10: bars only for days inside the clamped display window ($tlCut from the banner
        # block); older events collapse into one caption note. Busiest-day pick = busiest INSIDE
        # the window (identical output when nothing predates the cutoff).
        $tlDays = @{}
        $tlOlder = 0
        foreach ($t in $tlAll) {
            $d = "$($t.Timestamp)"
            if ($d.Length -ge 10 -and $d -match '^\d{4}-\d{2}-\d{2}') {
                $k = $d.Substring(0, 10)
                if ($k -lt $tlCutKey) { $tlOlder++; continue }
                if (-not $tlDays.ContainsKey($k)) { $tlDays[$k] = 0 }
                $tlDays[$k]++
            }
        }
        $tlDayKeys = @($tlDays.Keys | Sort-Object)
        if ($tlDayKeys.Count -gt 120) { $tlDayKeys = @($tlDayKeys | Select-Object -Last 120) }
        if ($tlDayKeys.Count -gt 1) {
            $tlMax = ($tlDayKeys | ForEach-Object { $tlDays[$_] } | Measure-Object -Maximum).Maximum
            $tlTop = @($tlDayKeys | Sort-Object { $tlDays[$_] } -Descending | Select-Object -First 1)[0]
            $bw = 8; $tGap = 2; $sh = 60
            $bars = New-Object System.Text.StringBuilder
            $x = 0
            foreach ($k in $tlDayKeys) {
                $bh = [Math]::Max(2, [int][Math]::Round($sh * $tlDays[$k] / $tlMax))
                $fill = if ($k -eq $tlTop) { '#e0a93e' } else { '#4d8fd1' }
                $null = $bars.Append("<rect x='$x' y='$($sh - $bh)' width='$bw' height='$bh' fill='$fill'><title>$k : $($tlDays[$k]) event(s)</title></rect>")
                $x += $bw + $tGap
            }
            $sw = $x - $tGap
            $tlNote = if ($tlOlder -gt 0) { " + $tlOlder older event(s) before $tlCutKey (stray timestamps)" } else { '' }
            $null = $sb.AppendLine("<div class='card'><b>Activity per day</b> <span class='meta'>(busiest: $tlTop with $($tlDays[$tlTop]) events - hover a bar for its count; showing the last $($tlDayKeys.Count) day(s) with activity)$tlNote</span><svg viewBox='0 0 $sw $sh' width='100%' height='$sh' preserveAspectRatio='none' style='margin-top:6px'>$($bars.ToString())</svg></div>")
        }
    }
    if ($tlAll.Count -gt 0) {
        # task 11 (collector self-noise): the collector runs last before export, so a plain newest-150
        # pick leads with Ophira's own wevtutil evtx-export commands. Rows whose Detail/Entity carry
        # the case's raw\evtx\*.evtx export path, the case folder name, or a kit path (same vocabulary
        # as Test-SigmaSelfNoise, minus its sigma-specific PID logic) are skipped and replaced by the
        # next newest unsuppressed events. Display only: supertimeline.csv, the sparkline, the evidence
        # window and -Mode Timeline keep every event; the caption states the true numbers. On by
        # default, no toggle - the note explains it.
        $tlSorted = @($tlAll | Sort-Object { "$($_.Timestamp)" } -Descending)
        $tlShowL = New-Object System.Collections.Generic.List[object]
        $tlNoise = 0
        $tlCaseName = ''
        try { $tlCaseName = Split-Path -Leaf (Split-Path -Parent $CsvDir) } catch { }
        foreach ($t in $tlSorted) {
            if ($tlShowL.Count -ge 150) { break }
            $tlTxt = "$($t.Detail) $($t.Entity)"
            $tlHit = ($tlTxt.IndexOf('raw\evtx\', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and $tlTxt -match '\.evtx\b')
            if (-not $tlHit -and $tlCaseName) { $tlHit = $tlTxt.IndexOf($tlCaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
            if (-not $tlHit -and $script:KitPaths) {
                foreach ($kp in @($script:KitPaths)) {
                    if ($kp -and $tlTxt.IndexOf("$kp", [StringComparison]::OrdinalIgnoreCase) -ge 0) { $tlHit = $true; break }
                }
            }
            if ($tlHit) { $tlNoise++; continue }
            $null = $tlShowL.Add($t)
        }
        $tlShow = $tlShowL.ToArray()
        $tlCap = if ($tlNoise -gt 0) { "Newest $($tlShow.Count) of $($tlAll.Count) events (collector self-noise suppressed: $tlNoise rows)" } else { "Newest $($tlShow.Count) of $($tlAll.Count) events, newest first:" }
        $null = $sb.AppendLine("<div class='meta'>$tlCap</div>")
        # v2.66 (B11): text + source + from/to date filters compose (AND) - inline table only,
        # the full CSV / -Mode Timeline stay the pivoting surface
        $tlSrcOpts = (@($tlShow | ForEach-Object { "$($_.Source)" } | Where-Object { "$_" } | Sort-Object -Unique) | ForEach-Object { "<option>$(ConvertTo-HtmlEsc $_)</option>" }) -join ''
        $null = $sb.AppendLine("<div class='sbar'>filter <input id='tlf' placeholder='entity / detail / source / actor...' oninput='tlFilter()' style='width:240px'> source <select id='tls' onchange='tlFilter()'><option value=''>all sources</option>$tlSrcOpts</select> from <input type='date' id='tlfrom' onchange='tlFilter()'> to <input type='date' id='tlto' onchange='tlFilter()'> <span class='meta'>inline table only - full pivoting: -Mode Timeline</span></div>")
        $null = $sb.AppendLine("<table id='tlt'><thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Actor</th><th>Entity</th><th>Detail</th></tr></thead><tbody>")
        foreach ($t in $tlShow) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t.Timestamp)</td><td>$(ConvertTo-HtmlEsc $t.Source)</td><td>$(ConvertTo-HtmlEsc $t.Type)</td><td>$(ConvertTo-HtmlEsc $t.Actor)</td><td class='path'>$(ConvertTo-HtmlEsc $t.Entity)</td><td>$(ConvertTo-HtmlEsc $t.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</tbody></table><div class='meta' id='tlcount'></div>")
        # v2.66 (B11): substring AND source AND from/to date window (YYYY-MM-DD prefix compare)
        $null = $sb.AppendLine("<script>function tlFilter(){var q=document.getElementById('tlf').value.toLowerCase();var s=document.getElementById('tls').value;var f=document.getElementById('tlfrom').value;var t=document.getElementById('tlto').value;var n=0;var rs=document.querySelectorAll('#tlt tbody tr');for(var i=0;i<rs.length;i++){var c=rs[i].cells;var d=c[0].textContent.substring(0,10);var hit=rs[i].textContent.toLowerCase().indexOf(q)>=0&&(!s||c[1].textContent===s)&&(!f||d>=f)&&(!t||d<=t);rs[i].style.display=hit?'':'none';if(hit)n++;}document.getElementById('tlcount').textContent=(q||s||f||t)?('showing '+n+' matching of $($tlShow.Count) shown'):'';}</script>")
    }

    # ---------- focus dossier (v2.40: built by -Mode Focus / menu option 9) ----------
    # v2.78: $focusDirP/$ft resolved up at the nav build (its count feeds the nav)
    if ($ft) {
            $fHits = @()
            try { $fHits = @(Import-Csv -LiteralPath (Join-Path $focusDirP 'focus_hits.csv') -ErrorAction Stop) } catch { }
            $fInst = @()
            try { $fInst = @(Import-Csv -LiteralPath (Join-Path $focusDirP 'focus_instances.csv') -ErrorAction Stop) } catch { }
            $null = $sb.AppendLine("<a name='focus'></a><h2>Focus dossier - $(ConvertTo-HtmlEsc $ft.Indicator)</h2>")
            $degr = if ($ft.Degraded) { " <span class='med'>instance attribution degraded - no ProcessGuid captured in this case</span>" } else { '' }
            # v2.73: a windowed dossier says so in the embed too (old focus_terms.json without
            # TimeWindow renders exactly as before)
            $fWin = ''
            if ($ft.TimeWindow) {
                $fFrom = "$($ft.TimeWindow.From)"; $fTo = "$($ft.TimeWindow.To)"
                if ($fFrom -or $fTo) {
                    $fRow = 0; try { $fRow = [int]$ft.RowsOutsideWindow } catch { }
                    $fWin = " - time window: $(ConvertTo-HtmlEsc $fFrom) to $(ConvertTo-HtmlEsc $fTo) - $fRow row(s) outside window suppressed"
                }
            }
            $null = $sb.AppendLine("<div class='meta'>Focused on '<b>$(ConvertTo-HtmlEsc $ft.Indicator)</b>' ($($ft.Rounds) expansion round(s), $($ft.HitCount) evidence row(s), $($ft.InstanceCount) instance(s))$degr. Full dossier: $(ConvertTo-CaseFileLink (Join-Path $focusDirP 'focus_report.html') 'focus\focus_report.html') - activity chain: $(ConvertTo-CaseFileLink (Join-Path $focusDirP 'focus_chain.csv') 'focus\focus_chain.csv')$fWin</div>")
            # v2.56: the dossier's detection-surface banner travels in focus_terms.json - same verdict here as there
            if ("$($ft.VerdictHint)") {
                $fvCls = switch ("$($ft.VerdictHintCls)") { 'crit' { 'lead lead-crit' } 'med' { 'lead lead-med' } default { 'lead' } }
                $null = $sb.AppendLine("<div class='$fvCls' style='padding:6px 12px'><b>$(ConvertTo-HtmlEsc $ft.VerdictHint)</b> - $(ConvertTo-HtmlEsc $ft.VerdictHintTxt)</div>")
            }
            if (@($ft.Masquerade).Count -gt 0) {
                $null = $sb.AppendLine("<div class='lead lead-med' style='padding:6px 12px'><b>MASQUERADE WARNING:</b> the name appears at multiple paths - $(ConvertTo-HtmlEsc (@($ft.Masquerade) -join ', ')). Compare the entity groups below; only one of them is probably the real OS binary.</div>")
            }
            if (@($ft.Paths).Count -gt 0) {
                $null = $sb.AppendLine("<h3>Entity groups (path + hash keyed - same-name binaries at different paths are separate groups)</h3><table><tr><th>Path</th><th>Hash</th><th>Hits</th><th>First seen</th><th>Last seen</th></tr>")
                # v2.82: per-group hash from focus_terms.json EntityGroups - Hashes[0] on every
                # row was the same-hash bug; algo label (SHA256:/SHA1:) is baked into the value
                $egMap = @{}
                foreach ($eg in @($ft.EntityGroups)) { if ($eg -and "$($eg.Path)") { $egMap["$($eg.Path)"] = "$($eg.Hash)" } }
                foreach ($p in @($ft.Paths | Select-Object -First 20)) {
                    $g = @($fHits | Where-Object { "$($_.Detail)".ToLower().Contains("$p") })
                    $fs = ($g | Where-Object { "$($_.Time)" } | Sort-Object { "$($_.Time)" } | Select-Object -First 1).Time
                    $ls = ($g | Where-Object { "$($_.Time)" } | Sort-Object { "$($_.Time)" } | Select-Object -Last 1).Time
                    $hCell = if ($egMap.ContainsKey("$p")) { $egMap["$p"] } else { '' }
                    $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $p)</td><td class='path'>$(ConvertTo-HtmlEsc $hCell)</td><td>$($g.Count)</td><td>$(ConvertTo-HtmlEsc $fs)</td><td>$(ConvertTo-HtmlEsc $ls)</td></tr>")
                }
                $null = $sb.AppendLine("</table>")
            }
            if ($fInst.Count -gt 0) {
                # v2.56: instances with no captured parent get one from the 4688 process_chains rebuild
                $chainParent = @{}
                foreach ($ch in @(Import-CaseCsv 'process_chains')) {
                    if ("$($ch.Child)" -and "$($ch.Parent)") { $chainParent[(Split-Path "$($ch.Child)" -Leaf).ToLower()] = "$($ch.Parent)" }
                }
                $null = $sb.AppendLine("<h3>Instances</h3><table><tr><th>PID</th><th>ProcessGuid</th><th>Started</th><th>Image</th><th>Parent</th><th>User</th></tr>")
                foreach ($i in @($fInst | Select-Object -First 25)) {
                    $par = "$($i.Parent)"
                    if (-not $par -and $chainParent.ContainsKey((Split-Path "$($i.Image)" -Leaf).ToLower())) { $par = $chainParent[(Split-Path "$($i.Image)" -Leaf).ToLower()] }
                    $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $i.Pid)</td><td class='path'>$(ConvertTo-HtmlEsc $i.Guid)</td><td>$(ConvertTo-HtmlEsc $i.Started)</td><td class='path'>$(ConvertTo-HtmlEsc $i.Image)</td><td class='path'>$(ConvertTo-HtmlEsc $par)</td><td>$(ConvertTo-HtmlEsc $i.User)</td></tr>")
                }
                $null = $sb.AppendLine("</table><div class='meta'>Multiple instances of one name group per path+hash; a same-name binary at another path would appear as its own group (masquerade split).</div>")
            }
            if ($fHits.Count -gt 0) {
                # v2.56: aggregate table collapsed by default (it is the summary, the story is below), cap 30 + of N
                $fGroups = @($fHits | Group-Object Source | Sort-Object Count -Descending)
                $null = $sb.AppendLine("<details><summary><b>Evidence by artifact</b> - $($fGroups.Count) source(s)</summary><table><tr><th>Artifact</th><th>Rows</th></tr>")
                foreach ($g in ($fGroups | Select-Object -First 30)) {
                    $gAnc = Get-SectionAnchorForSource $g.Name
                    $gName = if ($gAnc) { "<a href='#$gAnc'>$(ConvertTo-HtmlEsc $g.Name)</a>" } else { "$(ConvertTo-HtmlEsc $g.Name)" }
                    $null = $sb.AppendLine("<tr><td>$gName</td><td>$($g.Count)</td></tr>")
                }
                if ($fGroups.Count -gt 30) { $null = $sb.AppendLine("<tr><td colspan='2' class='meta'>...and $($fGroups.Count - 30) more source(s)</td></tr>") }
                $null = $sb.AppendLine("</table></details>")
            }
            # v2.45: the full correlation story embedded - activity graph + per-instance joins
            # (from focus_instances_detail.json, written by the focus engine core)
            $fDetail = $null
            try { $fDetail = Get-Content -LiteralPath (Join-Path $focusDirP 'focus_instances_detail.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
            $hasGraph = $false
            if ($fDetail -and "$($fDetail.GraphSvg)") {
                $hasGraph = $true
                $null = $sb.AppendLine("<h3>Activity graph (parents -> instances -> children -> what they did)</h3>")
                $null = $sb.AppendLine("$($fDetail.GraphSvg)")
                $null = $sb.AppendLine("<div class='meta'>Chips per instance: INJECT/THREAD (cross-process remote threads), PIPE, drops/deletions, network / DNS / DLLs / file / registry / persistence / beacons. Full-size version: focus\focus_report.html</div>")
            }
            foreach ($cn3 in @($fDetail.CorrNotes)) {
                if (-not "$cn3") { continue }
                $null = $sb.AppendLine("<div class='lead lead-med' style='padding:6px 12px'><b>$(ConvertTo-HtmlEsc $cn3)</b></div>")
            }
            # v2.66 (B9): sticky mini-key - the graph's own color vocabulary travels with the
            # analyst through the per-instance tables (the full legend scrolls away with the graph)
            if ($hasGraph -and @($fDetail.Instances).Count -gt 0) {
                $null = $sb.AppendLine("<div class='mkey' id='focusminikey'>activity-graph key: <i style=""background:#1f2a3d;border-color:#3a5a83""></i>parent process <i style=""background:#3a1518;border-color:#a33""></i>focused instance <i style=""background:#33290f;border-color:#c93""></i>child process <i style=""background:#1f2a3d;border-color:#a33""></i>artifact chip (red border = INJECT/TAMPER)</div>")
            }
            # task 9 (focus embed cap): interesting-first - injection/tamper/beacon/persistence/
            # file-drop evidence embeds in full ahead of the cap; ordinary instances follow capped
            # at 15, heaviest evidence first (tie-break Pid then Guid). Presentation only -
            # focus_instances_detail.json / focus_report.html / the CSVs keep every instance.
            $fAllInst = New-Object System.Collections.Generic.List[object]
            foreach ($pd2 in @($fDetail.Instances)) { if ($pd2) { $null = $fAllInst.Add($pd2) } }
            $fEmbed = New-Object System.Collections.Generic.List[object]
            $fOrd = New-Object System.Collections.Generic.List[object]
            foreach ($pd2 in $fAllInst.ToArray()) {
                $fInt = $false
                foreach ($fk in @('CrtIn', 'CrtOut', 'Tamper', 'Beacon', 'Persist', 'FileCreate', 'FileDelete')) {
                    $fv = $pd2.$fk
                    if ($null -ne $fv -and @($fv).Count -gt 0) { $fInt = $true; break }
                }
                if ($fInt) { $null = $fEmbed.Add($pd2); continue }
                $fn = 0
                foreach ($fk in @('Children', 'CrtIn', 'CrtOut', 'Pipes', 'Tamper', 'RawDisk', 'Exec', 'Persist', 'Beacon', 'Net', 'Dns', 'Dll', 'Reg', 'File', 'FileCreate', 'FileDelete')) {
                    $fv = $pd2.$fk
                    if ($null -ne $fv) { $fn += @($fv).Count }
                }
                $null = $fOrd.Add([pscustomobject]@{ N = $fn; PidS = "$($pd2.Pid)"; GuidS = "$($pd2.Guid)"; P = $pd2 })
            }
            foreach ($ow in @($fOrd.ToArray() | Sort-Object -Property @{Expression = 'N'; Descending = $true }, 'PidS', 'GuidS' | Select-Object -First 15)) { $null = $fEmbed.Add($ow.P) }
            foreach ($pd2 in $fEmbed.ToArray()) {
                if (-not $pd2) { continue }
                $hdr2 = "Instance PID $($pd2.Pid)"
                if ("$($pd2.Guid)") { $hdr2 += " - $($pd2.Guid)" }
                if ("$($pd2.User)") { $hdr2 += " ($($pd2.User))" }
                # v2.56: each instance collapsed - the section lists every instance without burying the page
                $null = $sb.AppendLine("<details><summary><b>$(ConvertTo-HtmlEsc $hdr2)</b> - everything it did</summary>")
                if ("$($pd2.Respawn)") { $null = $sb.AppendLine("<div class='lead lead-med' style='padding:6px 12px'><b>$(ConvertTo-HtmlEsc $pd2.Respawn)</b></div>") }
                if (@($pd2.Lineage).Count -gt 1) { $null = $sb.AppendLine("<div class='meta'>Arrived via: $(ConvertTo-HtmlEsc (@($pd2.Lineage) -join ' <- '))</div>") }
                foreach ($secDef in @(
                    @('Child processes', 'Children', @('Time', 'Child', 'PID', 'User'), { param($x) @("$($x.Time)", "$($x.Image)", "$($x.ProcessId)", "$($x.User)") }),
                    @('Cross-process injection INTO this instance', 'CrtIn', @('Time', 'Injected by', 'Start function'), { param($x) @("$($x.Time)", "$($x.SourceImage)", "$($x.StartFunction)") }),
                    @('Remote threads created in other processes', 'CrtOut', @('Time', 'Target process', 'Start function'), { param($x) @("$($x.Time)", "$($x.TargetImage)", "$($x.StartFunction)") }),
                    @('Named pipes', 'Pipes', @('Event', 'Time', 'Pipe'), { param($x) @($(if ("$($x.EventId)" -eq '17') { 'created' } elseif ("$($x.EventId)" -eq '18') { 'connected' } else { "$($x.EventType)" }), "$($x.Time)", "$($x.PipeName)") }),
                    @('Process tampering (Sysmon EID 25)', 'Tamper', @('Time', 'Process', 'New image info'), { param($x) @("$($x.Time)", "$($x.Image)", "type=$($x.Type) fileVersion=$($x.FileVersion)") }),
                    @('Direct volume access', 'RawDisk', @('Time', 'Device'), { param($x) @("$($x.Time)", "$($x.Device)") }),
                    @('Execution artifacts (prefetch/amcache/BAM/shimcache)', 'Exec', @('Time', 'Artifact', 'Detail'), { param($x) @("$($x.Time)", "$($x.Kind)", "$($x.Detail)") }),
                    @('Persistence', 'Persist', @('Time', 'Mechanism', 'Detail'), { param($x) @("$($x.Time)", "$($x.Kind)", "$($x.Detail)") }),
                    @('C2 beaconing', 'Beacon', @('Kind', 'Destination', 'Pattern'), { param($x) @("$($x.Kind)", "$($x.Target)", "$($x.Detail)") }),
                    @('Network connections', 'Net', @('Time', 'Destination', 'Process'), { param($x) @("$($x.Time)", "$($x.DestIp):$($x.DestPort)", "$($x.Image)") }),
                    @('DNS queries', 'Dns', @('Time', 'Query', 'Process'), { param($x) @("$($x.Time)", "$($x.QueryName)", "$($x.Image)") }),
                    @('Loaded DLLs', 'Dll', @('Time', 'DLL', 'Process'), { param($x) @("$($x.Time)", "$($x.Dll)", "$($x.Image)") }),
                    @('Registry writes', 'Reg', @('Time', 'Key', 'Process'), { param($x) @("$($x.Time)", "$($x.TargetObject)", "$($x.Image)") }),
                    @('File timestamp events', 'File', @('Time', 'File', 'Change'), { param($x) @("$($x.Time)", "$($x.TargetFilename)", "$($x.CreationUtcTime) <- $($x.PreviousCreationUtcTime)") }),
                    @('Files dropped', 'FileCreate', @('Time', 'File', 'Hashes'), { param($x) @("$($x.Time)", "$($x.TargetFilename)", "$($x.Hashes)") }),
                    @('Files deleted (anti-forensics)', 'FileDelete', @('Time', 'File', 'Archived'), { param($x) @("$($x.Time)", "$($x.TargetFilename)", "$($x.Archived)") })
                )) {
                    $rows2 = @($pd2.($secDef[1]))
                    if ($rows2.Count -eq 0) { continue }
                    $null = $sb.AppendLine("<h4>$($secDef[0]) ($($rows2.Count))</h4><table><tr>$(@($secDef[2] | ForEach-Object { "<th>$_</th>" }) -join '')</tr>")
                    foreach ($x2 in @($rows2 | Select-Object -First 25)) {
                        $cells = & $secDef[3] $x2
                        $null = $sb.AppendLine("<tr>$(@($cells | ForEach-Object { "<td class='path'>$(ConvertTo-HtmlEsc $_)</td>" }) -join '')</tr>")
                    }
                    if ($rows2.Count -gt 25) { $null = $sb.AppendLine("<tr><td colspan='$($secDef[2].Count)' class='meta'>showing 25 of $($rows2.Count) - full table: $(ConvertTo-CaseFileLink (Join-Path $focusDirP 'focus_report.html') 'focus_report.html')</td></tr>") }
                    $null = $sb.AppendLine("</table>")
                }
                $null = $sb.AppendLine("</details>")
            }
            if ($fAllInst.Count -gt $fEmbed.Count) {
                $null = $sb.AppendLine("<div class='meta'>showing $($fEmbed.Count) of $($fAllInst.Count) instances - everything else: $(ConvertTo-CaseFileLink (Join-Path $focusDirP 'focus_report.html') 'focus\focus_report.html')</div>")
            }
    }

    # ---------- recommendations ----------
    $null = $sb.AppendLine("<a name='recommendations'></a><h2>Recommendations</h2>")
    $recs = New-Object System.Collections.Generic.List[string]
    if ($script:Verdict -and $script:Verdict.LevelRank -ge 3) {
        $recs.Add('Likely/confirmed compromise: preserve evidence (do not wipe yet), isolate the host from the network, and treat credentials used on it as suspect - rotate them.')
    }
    $gapTamperRec = @($gapRows | Where-Object { "$($_.EventId)" -match '^(1102|104)$' -or "$($_.Meaning)" -match '(?i)clear|overwrit| Audit log' } | Select-Object -First 1)
    if ($gapTamperRec) {
        $recs.Add('Security log clearing/stopping events were observed - determine who/what cleared them and when (csv\logging_gaps.csv, raw evtx).')
    } elseif ($gapRows.Count -gt 0) {
        $recs.Add('Chronological gaps detected in event logs - check collection completeness (csv\logging_gaps.csv). This is NOT evidence of log clearing.')
    }
    if ($brute.Count -gt 0) {
        $recs.Add('Brute-force sources observed - check whether any 4625 failure was followed by a 4624 success from the same IP (csv\security_auth_events.csv), and enforce account lockout policy.')
    }
    foreach ($pb in $postureBad) {
        $recs.Add("Hardening: $($pb.Check) - $($pb.Detail)")
    }
    # v2.58: 4688 disabled = hardening recommendation only (WARN posture row, never a verdict weight)
    foreach ($p4688 in @($posture | Where-Object { "$($_.Check)" -match '4688' -and "$($_.Status)" -ne 'GOOD' })) {
        $recs.Add("Hardening: 4688 process-creation auditing is disabled on this host - process lineage, session attribution and the 4688 hunt rules run blind. Enable via GPO: Advanced Audit Policy > Detailed Tracking > Audit Process Creation (success).")
    }
    if (-not $Sysmon) {
        $recs.Add('No Sysmon on this host - the conclusion is built from the execution-artifact spine (prefetch, amcache, BAM/DAM, shimcache, 4688, USN/$MFT, Defender history), and per-instance joins (network/DLL/file/registry/injection) are limited. Ophira never installs anything; if the Sysmon owner adds Sysmon with a broad community configuration, the next collection gains full process-precise telemetry.')
    }
    # v2.57: the deep-timeline TODO sits next to the generated results (until plaso.csv exists)
    $plasoRecP = Join-Path (Split-Path -Parent $CsvDir) 'plaso.csv'
    if (-not (Test-Path -LiteralPath $plasoRecP)) {
        $recs.Add("Deeper timeline available (optional, analyst-side): run plaso log2timeline.py against this case's raw\ folder, export psort l2tcsv as plaso.csv in the case root, then re-run Ophira.ps1 -Mode Parse - it merges into supertimeline.csv as Source 'plaso' rows (browser history, Jumplists, SRUM and other artifacts Ophira's own parsers do not cover).")
    }
    if (-not (Test-Path (Join-Path $RawDir 'evtx'))) {
        $recs.Add('Event logs were not exported (module 4.x skipped or access denied) - rerun elevated with the Standard preset for Sigma/ATT&CK coverage.')
    }
    # v2.63: unknown elevation never live-probes and never asserts the unverified
    # negative "ran WITHOUT admin rights" - the coverage table already lists gaps
    $recElev = if ($null -ne $caseAdmin) { -not $caseAdmin } else { $false }
    if ($recElev) {
        $recs.Add('This collection ran WITHOUT admin rights - rerun elevated to include registry hives, amcache, Security log and other key sources.')
    }
    if ($script:LogStartDT) {
        $recs.Add("Analysis window started at $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm')) UTC$(if ($script:LogEndDT) { " (ends $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm')) UTC)" }) - rerun with an earlier -LogStart/-LogWindow if the intrusion may be older.")
    } elseif ($LogHours -gt 0 -and $LogHours -le 168) {
        $recs.Add("Analysis window was only the last $([int]($LogHours/24)) day(s) - rerun with a wider window (e.g. -LogWindow 30d, -LogWindow 3m or 0 = all) if the intrusion may be older.")
    }
    if ($script:Verdict -and $script:Verdict.ConfidencePercent -lt 80) {
        $recs.Add('Evidence coverage was below 80% - address the missing sources in the coverage table before treating a clean verdict as final.')
    }
    if ($recs.Count -eq 0) { $recs.Add('No specific hardening actions indicated by this collection - keep collecting baselines (delta mode) at a regular cadence.') }
    foreach ($r in $recs.ToArray()) { $null = $sb.AppendLine("<div class='rec'>$(ConvertTo-HtmlEsc $r)</div>") }

    # ---------- evidence index ----------
    $null = $sb.AppendLine("<a name='evidence'></a><h2>Evidence index (everything this case contains)</h2>")
    $desc = @{
        'flash_process_scored'            = 'Live processes with anomaly scores - review HIGH verdicts and user-path binaries'
        'flash_ioc_hits'                  = 'Live processes/files matching your IOC list (tools\iocs.txt)'
        'flash_public_connections'        = 'Established connections to public IPs at collection time - map to processes'
        'processes'                       = 'Full live process inventory (parent/PID/command line)'
        'processes_flagged'               = 'Process inventory subset with anomaly flags'
        'process_hashes'                  = 'SHA256 hashes of live process binaries'
        'connections'                     = 'Full connection table (netstat) at collection time'
        'connections_public_established'  = 'ESTABLISHED public-IP connections - C2 candidates'
        'dns_cache'                       = 'DNS resolver cache - look up domains malware resolved recently'
    'scheduled_taskcache'             = 'TaskCache registry side (Tree + Tasks keys) - ghost/hidden-task cross-check; SD-MISSING/ORPHANED flags are tamper signals'
    'task_deletions'                  = 'EID 4699 scheduled task DELETIONS (TaskScheduler log) - pairs with TaskCache anomalies for the disappearing-task trick'
    'esent_ntds'                      = 'ESENT 325/326 events mentioning ntds.dit - the AD database was opened; BackupPattern=True rows are usually legit backups'
    'shimcache_exec'                  = 'Shimcache entries with the Win10+ executed-flag decoded (last 4 record bytes) - flag=0 is context, never proof of non-execution'
    'radar_exec'                      = 'RADAR heap-leak DiagnosedApplications - key LastWriteTime = executed on or before that time (server-friendly execution evidence)'
    'appswitched'                     = 'Explorer FeatureUsage AppSwitched counters - taskbar focus-switch counts per app (no timestamps; user-behavior context)'
        'connections_dns'                 = 'Public connections resolved via the DNS cache (CNAME chains walked) - what each remote IP actually was'
        'arp_table'                       = 'ARP cache - hosts on the local segment'
        'logon_sessions'                  = 'Active logon sessions (who is on the box right now)'
        'drivers'                          = 'Kernel drivers + paths'
        'drivers_flagged'                  = 'Drivers with user-writable binary paths'
        'autoruns_runkeys'                = 'Run/RunOnce/Winlogon autostart commands (all hives)'
        'autoruns_startup_folders'        = 'Startup folder items with signature status'
        'services'                        = 'All services + binary paths'
        'services_flagged'                = 'Services with user-writable or missing binaries'
        'scheduled_tasks'                 = 'All scheduled tasks with actions'
        'scheduled_tasks_flagged'         = 'Tasks with non-Microsoft authors or odd actions'
        'wmi_event_filters'               = 'WMI event filters (rare on clean hosts)'
        'wmi_event_consumers'             = 'WMI event consumers (command/script payloads)'
        'wmi_bindings'                    = 'WMI filter-to-consumer bindings = active WMI persistence'
        'asep_sweep'                      = 'Deep persistence sweep: IFEO/AppInit/Winlogon/COM/netsh/LSA/StartupApproved'
        'certificates'                    = 'Certificate store inventory - check recent self-signed roots (T1553)'
        'firewall_profiles'               = 'Firewall profile state + logging config'
        'net_interfaces'                  = 'Network interfaces + IPs'
        'net_reachable_subnets'           = 'Routes/reachable subnets'
        'smb_hosted_shares'               = 'Shares this host exposes'
        'smb_mounted_shares'              = 'Shares this host has mapped'
        'smb_active_connections'          = 'Live SMB sessions (both directions)'
        'saved_credentials'               = 'Stored credentials (cmdkey) - lateral movement risk'
        'proxy_settings'                  = 'WinHTTP/WinINET proxy + WPAD'
        'net_active_probes'               = 'Opt-in connectivity probes (module 3.2)'
        'security_events'                 = 'Security log events in window (raw)'
        'security_auth_events'            = 'Authentication events (4624/4625/4648...)'
        'security_bruteforce_candidates'  = 'Sources with 5+ failed logons'
        'security_auth_summary'           = 'Logon summary by account/type'
        'powershell_events'               = 'PowerShell 4104 script block logs'
        'sysmon_events'                   = 'Sysmon events in window (raw)'
        'sysmon_network'                  = 'Sysmon EID 3 network events - source for beaconing'
        'rdp_localsession'                = 'Local RDP session events (EID 21/22/24/25 - note: EID 59 rows in this channel are VMware session probes, not RDP)'
        'rdp_connections'                 = 'Inbound RDP connection events'
        'rdp_client_targets'              = 'Outbound RDP destinations (registry MRU)'
        'system_events'                   = 'System log events in window'
        'system_new_services'             = 'EID 7045 service installs - malware installs itself as services'
        'svchost_audit'                   = 'Live svchost -k groups vs registered ServiceDlls (masquerade audit: unregistered group, ServiceDll outside System32, unregistered loaded DLL)'
        'defender_status'                 = 'AV state at collection'
        'defender_threats'                = 'AV detections history'
        'defender_preferences'            = 'AV exclusions - attackers add exclusions'
        'defender_events'                 = 'Defender operational log'
        'powershell_console_history'      = 'Console history files per user - attacker commands'
        'recyclebin_index'                = 'Recycle bin $I files (what was deleted, by whom, when)'
        'bits_jobs'                       = 'BITS transfer jobs (stealth downloads)'
        'domain_info'                     = 'Domain role + logged user'
        'hayabusa_timeline'               = 'Sigma detection timeline with ATT&CK tags'
        'hayabusa_report'                 = 'hayabusa full report copy (all levels - the timeline keeps level>=low only)'
        'logon_summary*'                  = 'hayabusa logon summary - successful/failed logons per account (RDP reuse + spray patterns)'
        'amcache_*'                       = 'Amcache raw sub-parse (device containers/PnP, drive binaries, driver packages, shortcuts, unassociated file entries)'
        'yara_hits'                       = 'YARA rule matches on collected binaries'
        'yara_scanned'                    = 'Which files were YARA-scanned'
        'beacon_candidates'               = 'Periodic outbound patterns (C2 beaconing)'
        'dns_beacon_candidates'           = 'Periodic DNS domain queries (DNS C2 beaconing)'
        'sysmon_dns'                      = 'Sysmon DNS queries (EID 22) - domains each process resolved'
        'loldrivers_hits'                 = 'Driver hashes x LOLDrivers dataset (malicious/vulnerable drivers on disk)'
        'ps_decoded_commands'             = 'Base64/obfuscated PowerShell commands recovered from event logs'
        'execution_timeline'              = 'Shimcache/amcache program execution history'
        'amcache'                         = 'Amcache full parse (installed/executed programs + SHA1)'
        'ioc_hits_amcache'                = 'Amcache SHA1 x IOC list hits (historical execution)'
        'prefetch_index'                  = 'Prefetch files copied (index)'
        'prefetch_parsed'                 = 'Prefetch parse: run counts + last run times'
        'prefetch_parsed_Timeline'        = 'Prefetch parsed - timeline projection (one row per run time)'
        'userassist'                      = 'UserAssist GUI programs executed per user'
        'mft_recent'                      = 'MFT: recently created / user-path executables (both birth attributes: $Si Created + FILE_NAME CreatedFN - R22 timestamp-forgery checks)'
        'application_events'              = 'Application log: app crashes (1000/1001/1002) + MSI installs (1033/11707/11724) - crashed attacker tools'
        'startup_info'                    = 'StartupInfo per-session app launches (WDI XMLs) - execution evidence that survives Prefetch deletion'
        'wer_reports'                     = 'Windows Error Reporting crash reports (faulting app/module) - evidence of failed attacker tooling'
        'server_logs'                     = 'Inventory of copied server-role logs (DNS/DHCP audit, SYSVOL policies). NTDS.dit is never collected by policy'
        'registry_recmd'                  = 'RECmd batch registry deep-dive (persistence/execution/lateral keys across all saved hives) - analyst-side enrichment'
        'ioc_hits_dns'                    = 'IOC-listed domains observed in Sysmon DNS queries (feed-attributed)'
        'ioc_hits_network'                = 'IOC-listed IPs observed in historical connections (feed-attributed)'
        'ioc_hits_mft'                    = 'IOC-listed filenames found on disk ($MFT, exact name match)'
        'ioc_hits_hash'                   = 'IOC-listed binary hashes found in execution history (process_hashes - hits even if the file is gone)'
        'ioc_export'                      = 'Case indicators exported for fleet memory (HIGH verdicts/YARA/high beacons) - copy raw\analysis\ioc_export.txt into tools\iocs\ to arm future collections (STIX 2.1 bundle next to it for MISP/OpenCTI)'
        'credential_sweep'                = 'Credential exposure: auto-logon, WLAN keys (raw\wifi), DPAPI vault (raw\vault), LSASS dumps on disk'
        'remote_access'                   = 'Remote-access sweep: tunnels, RA tools (AnyDesk/TeamViewer class), SSH keys'
        'usn_write_bursts'                = 'USN journal: mass file-modification windows (ransomware)'
        'lnk_parsed'                      = 'LNK parse (Recent docs - what files were opened)'
        'jumplist_parsed*'                = 'Jump List parse (per-app recent files)'
        'shellbags'                       = 'ShellBags folder-browsing history - folder access incl. deleted/network/USB locations'
        'browser_files'                   = 'Collected browser profile files (browser, profile, file, size)'
        'browser_history'                 = 'Parsed browser history (URLs, titles, visit times)'
        'browser_downloads'               = 'Parsed browser downloads (files, sources, times)'
        'browser_searches'                = 'Browser search keywords'
        'ioc_hits_browser'                = 'IOC-listed domains observed in browser data'
        'posture'                         = 'Security hardening audit (LSA/SMBv1/RDP/PS logging/UAC/Defender/BitLocker)'
        'memory_malfind'                  = 'Volatility malfind - hidden/injected memory regions'
        'memory_netscan'                  = 'Volatility netscan - network artifacts found in RAM'
        'recyclebin'                      = 'RBCmd recycle bin parse (original paths + delete times)'
        'srum_usage'                      = 'SRUM: per-app network usage history over weeks (bytes sent/received per hour - SrumECmd deep parse, -Mode Parse)'
        'logging_gaps'                    = 'Log clear/stop events + evtx coverage gaps'
        'parse_needed'                    = 'Artifacts not finished on the endpoint + exactly how to finish them (-Mode Parse)'
        'hunt_findings'                   = 'Technique-based hunt detections (renamed binaries, side-loads, download-exec, LSASS access, Office chains, proxy-exec, share staging, UAC bypass, discovery storms, Defender tamper, timestomping, DCSync, Kerberoasting, spray, webshells)'
        'security_proc_events'            = '4688 process creations with parent + command line (needs cmdline audit) - Office chains, proxy-exec, discovery storms'
        'security_task_install'           = '4698 scheduled task installs with the task action - remote/atexec-style persistence'
        'security_share_access'           = '5140/5145 share access incl. admin-share writes - lateral movement + staging data source'
        'sysmon_process_access'           = 'Sysmon EID 10 ProcessAccess - LSASS credential-dump data source'
        'sysmon_proc_create'              = 'Sysmon EID 1 process create with OriginalFileName - renamed-binary at-rest evidence'
        'sysmon_registry'                 = 'Sysmon EID 13 RegistryEvent - UAC bypass / persistence data source'
        'sysmon_file_time'                = 'Sysmon EID 2 file creation-time changes - timestomping evidence'
        'sysmon_file_create'              = 'Sysmon EID 11 file creates - what each process dropped on disk (per-instance joins in Focus)'
        'sysmon_file_delete'              = 'Sysmon EID 23 file deletions - anti-forensics / cleanup evidence per process'
        'sysmon_remote_thread'            = 'Sysmon EID 8 remote threads - who injected into whom (R28 + Focus INJECT edges)'
        'sysmon_pipes'                    = 'Sysmon EID 17/18 named pipes created/connected - C2-style pipe channels (R29)'
        'sysmon_proc_tamper'              = 'Sysmon EID 25 process tampering - the OS itself flagged hollowing/image swap (R30)'
        'sysmon_raw_access'               = 'Sysmon EID 9 raw volume reads via \\.\ - locked-hive credential theft / anti-forensics (R31)'
        'ads_findings'                    = 'Non-Zone.Identifier alternate data streams on executables still on disk - payload stash/stager spot (R34)'
        'webshell_candidates'             = 'Web scripts matching content heuristics (eval(Request, base64 blobs, shell exec) - verify against source baseline (R35)'
        'sysmon_wmi'                      = 'Sysmon EID 19/20/21 WMI filter/consumer/binding registrations - permanent event persistence (R32)'
        'shimcache'                       = 'Shimcache/AppCompatCache (SYSTEM hive via AppCompatParser) - executed-from evidence that survives prefetch/amcache deletion (the no-Sysmon spine)'
        'defender_config_events'          = 'Defender 5001/5007 - real-time protection disabled / exclusion changes (tamper)'
        'security_kerberos'               = 'Kerberos events (DC: 4768/4769/4771/4776) - Kerberoasting/spray/AS-REP data source'
        'security_ds_access'              = 'Directory-service access (DC: 4662/5136) - DCSync + AD object changes'
        'iis_requests'                    = 'Parsed IIS W3C requests (web role) - what hit this server'
        'iis_anomalies'                   = 'IIS anomalies: error bursts, suspicious URIs, POSTs to upload paths, headless POSTs'
        'session_activity'                = '4624 LogonId x 4688/5145 joins - which logon session (human/IP) did what'
        'process_chains'                  = 'Ancestry chains for flagged binaries (4688 lineage + live PPID) - how it got there'
        'memory_live_scan'                = 'Flagged-process minidumps + YARA hits found in live memory'
        'sysmon_image_load'               = 'Sysmon DLL loads (EID 7) - side-load data source'
        'bam_lastexec'                    = 'BAM/DAM last-execution per user (survives Prefetch deletion)'
        'usb_devices'                     = 'Every USB storage device ever connected (serials + dates)'
        'office_mru'                      = 'Office recent documents per user'
        'ual_files'                       = 'User Access Logs copied raw (SMB/RDP source history - ESE)'
        'local_admins'                    = 'Local Administrators group members'
        'entities_binaries'               = 'Binaries joined across ALL evidence sources (execution/persistence/network/verdict...) with category counts'
        'entities_accounts'               = 'Accounts joined across logons/RDP/console history with failure counts'
        'entities_remotes'                = 'Remote endpoints joined across connections/beacons/brute-force/RDP targets'
        'delta_new'                       = 'Findings NEW since the previous collection'
        'supertimeline'                   = 'MASTER TIMELINE: gathered evidence woven chronologically (logons, 4688/5145, Kerberos, Sysmon, prefetch, $MFT births, browser, WER, StartupInfo - scanner outputs excluded by design) with Timestamp/Source/Type/Actor/Entity/Detail - filter to any timeframe in Excel/Timeline Explorer'
    }
    # v2.58: zero-row artifacts explain themselves - the honest-empty map (what condition
    # produced the empty, and whether empty is good, boring, or a blind spot to fix)
    $emptyWhy = @{
        'connections_dns'                 = 'no public connection matched a DNS resolver-cache entry - resolver TTLs typically expire before collection, and full attribution needs Sysmon EID22 DNS events'
        'security_proc_events'            = 'no 4688 events in the Security log - process-creation auditing appears disabled (see the hardening recommendation); lineage and session attribution run thin'
        'process_chains'                  = 'built from 4688 events - with process auditing disabled almost no lineage is recoverable'
        'session_activity'                = 'joins 4688/5145 events - nothing to join when process/share auditing is disabled'
        'rdp_localsession'                = 'no RDP session events (EID 21/22/24/25) in the window - EID 59 rows in this channel are VMware session probes, not RDP activity'
        'rdp_connections'                 = 'no inbound RDP connection events (EID 1149) in the window'
        'system_new_services'             = 'no EID 7045 service installs in the window'
        'security_task_install'           = 'no EID 4698 scheduled-task installs in the window'
        'security_share_access'           = 'no 5145 share-access events (share auditing disabled or no remote file access)'
        'security_bruteforce_candidates'  = 'no sources with 5+ failed logons (empty is good)'
        'usn_write_bursts'                = 'no mass file-modification windows in the USN journal (no ransomware-style burst - empty is good)'
        'yara_hits'                       = 'the bundled rules matched nothing in the scanned set - see yara_scanned.csv for what was scanned'
        'flash_ioc_hits'                  = 'no IOC feed matches on live processes/files'
        'drivers_flagged'                 = 'all drivers live in protected paths (empty is good)'
        'svchost_audit'                   = 'no svchost masquerade indicators - all -k groups registered with ServiceDlls in place (empty is good)'
        'wmi_event_consumers'             = 'no WMI event consumers on this host (rare persistence - empty is good)'
        'wmi_bindings'                    = 'no WMI filter-to-consumer bindings (empty is good)'
        'recyclebin_index'                = 'recycle bin empty at collection, or the RBCmd parser was unavailable - see parse_needed.csv'
        'local_admins'                    = 'Administrators group listing came back empty (localized net.exe output can do this on non-English Windows)'
        'office_mru'                      = 'no Office recent-document entries (Office not used or not installed)'
        'rdp_client_targets'              = 'this host never initiated outbound RDP'
        'remote_access'                   = 'no remote-access tools (AnyDesk/TeamViewer/ngrok-class) found (empty is good)'
        'server_logs'                     = 'no IIS/HTTP error logs on this host (workstation role)'
        'startup_info'                    = 'no StartupInfo evidence available'
        'ioc_export'                      = 'no high-confidence indicators met the export bar (HIGH verdicts / YARA-high / high beacons)'
        'smb_mounted_shares'              = 'no mapped drives at collection time'
        'smb_active_connections'          = 'no live SMB sessions at collection time'
        'userassist'                      = 'empty on cases collected before v2.54 (the parser had a GUID-matching bug) - re-collect to populate'
        # v2.67 (R1): every Save-Rows artifact that can render "0 rows" explains itself -
        # log sources (window/auditing), Sysmon classes (endpoint config enables specific EIDs),
        # Defender (service owned by third-party AV), tool-dependent parses, derived joins
        'application_events'              = 'no application crashes (1000/1001/1002) or MSI installs (1033/11707/11724) in the window - mostly good, though crashed attacker tooling would also have shown here'
        'powershell_events'               = 'no PowerShell operational events (4104 script blocks / 400 engine) in the window - script-block logging may be off (see posture), or PowerShell was simply not used'
        'security_events'                 = 'no Security-log events in the window - auditing may be minimal, or the log was cleared (a cleared Security log is itself a finding - see logging_gaps)'
        'security_auth_events'            = 'no logon events (4624/4625/4634/4647/4648) in the window - logon auditing may be disabled, or no sessions occurred'
        'security_auth_summary'           = 'joins the auth events - nothing to summarize when 4624/4625 rows are absent'
        'security_kerberos'               = 'no Kerberos ticket events (4768/4769/4771/4776) - normal off domain controllers; only DCs issue tickets (or the logon-auditing subcategories are off)'
        'security_ds_access'              = 'no directory-service events (4662/5136) - DC-only telemetry, normal on member servers and workstations (or the DS-audit subcategory is off)'
        'system_events'                   = 'no System-log events in the window - the System log is rarely this quiet; verify it was not cleared (see logging_gaps)'
        'wer_reports'                     = 'no Windows Error Reports under ProgramData or the user profiles - nothing crashed hard enough to record (mostly good)'
        'sysmon_events'                   = 'Sysmon is installed but produced no events in the window - the service was (re)started mid-window, the log rolled over, or the channel is genuinely empty (check raw\evtx\Sysmon_Operational.evtx)'
        'sysmon_network'                  = 'no Sysmon EID 3 network-connection events - EID 3 may be disabled in the endpoint Sysmon config, or nothing connected out in the window'
        'sysmon_dns'                      = 'no Sysmon EID 22 DNS-query events - EID 22 may be disabled in the endpoint Sysmon config, or no DNS lookups occurred'
        'sysmon_image_load'               = 'no Sysmon EID 7 image loads - EID 7 is noisy and often trimmed from endpoint configs, or nothing side-loaded in the window'
        'sysmon_process_access'           = 'no Sysmon EID 10 process-access events - EID 10 (the LSASS-access / injection data source) is not enabled in the endpoint Sysmon config'
        'sysmon_registry'                 = 'no Sysmon EID 13 registry-set events - EID 13 may be disabled in the endpoint config, or nothing wrote registry values in the window'
        'sysmon_file_time'                = 'no Sysmon EID 2 file-time events - nothing timestomped (empty is good), or EID 2 is disabled in the endpoint config'
        'sysmon_proc_create'              = 'no Sysmon EID 1 process-create events - EID 1 may be disabled in the endpoint config, or no process started in the window'
        'sysmon_file_create'              = 'no Sysmon EID 11 file-create events - EID 11 is noisy and often trimmed from endpoint configs, or nothing dropped files'
        'sysmon_file_delete'              = 'no Sysmon EID 23/26 file-delete events - stock Sysmon does not enable those IDs, or nothing was deleted (deletion telemetry is an anti-forensics data source)'
        'sysmon_remote_thread'            = 'no Sysmon EID 8 remote-thread events - EID 8 may be disabled in the endpoint config, or nothing injected cross-process (empty is good)'
        'sysmon_pipes'                    = 'no Sysmon EID 17/18 named-pipe events - those IDs may be disabled in the endpoint config, or no pipes were created/connected (SMB-beacon channel data)'
        'sysmon_proc_tamper'              = 'no Sysmon EID 25 process-tampering events - Sysmon saw no hollowing/image swaps (empty is good); needs Sysmon 13+ with EID 25 enabled'
        'sysmon_raw_access'               = 'no Sysmon EID 9 raw-volume-access events - nothing read \\.\ devices directly (empty is good), or EID 9 is disabled in the endpoint config'
        'sysmon_wmi'                      = 'no Sysmon EID 19/20/21 WMI-subscription events - no permanent-event persistence observed (empty is good), or those IDs are disabled in the endpoint config'
        'defender_status'                 = 'Get-MpComputerStatus unavailable or failed - a third-party AV owns the endpoint, or the Defender service is broken/removed'
        'defender_preferences'            = 'Get-MpPreference unavailable or failed - a third-party AV owns the endpoint (exclusions invisible to this collection), or the Defender service is broken'
        'defender_threats'                = 'no Defender threat detections on record - the live catalog and the 1116 event history both came back clean (empty is good)'
        'defender_events'                 = 'no Defender operational events (1116/1117 detections, 5001/5007 config changes) in the window - nothing detected, nothing toggled'
        'defender_config_events'          = 'no Defender config-change events (5001/5007) in the window - protection settings were not touched (empty is good)'
        'ads_findings'                    = 'no non-Zone.Identifier alternate data streams on the checked on-disk executables (empty is good)'
        'arp_table'                       = 'no ARP neighbors - the host is isolated/offline or the cache was just flushed (a just-booted host looks the same)'
        'autoruns_runkeys'                = 'no Run/RunOnce values in any hive - common on lean servers (empty is good); verify the sweep covered HKLM and every loaded user hive'
        'autoruns_startup_folders'        = 'no Startup-folder entries for any user (empty is good - most clean workstations look like this)'
        'bam_lastexec'                    = 'no BAM/DAM last-execution entries - the key is absent where SysMain never tracked user sessions, or no interactive session ran programs'
        'beacon_candidates'               = 'needs 15+ combined Sysmon network/DNS events in the window to run (telemetry too thin), or no regular-interval C2-style beacons found'
        'bits_jobs'                       = 'no BITS jobs at collection time (empty is good - BITS is a favorite malware transfer channel, so zero is the state you want)'
        'browser_files'                   = 'no browser profile data for the collecting user - server build, browsers never used, or profiles wiped'
        'connections_public_established'  = 'no established connections to public IPs at collection time (normal for an idle or internal-only host)'
        'credential_sweep'                = 'no credential-exposure findings - no auto-logon, no stored WLAN keys, no DPAPI vault blobs, no LSASS-dump-like files on disk (empty is good)'
        'delta_new'                       = 'nothing NEW since the previous collection (empty is good), or this is the first collection so there is no baseline to diff'
        'dns_beacon_candidates'           = 'needs 15+ combined Sysmon network/DNS events in the window to run (telemetry too thin), or no regular-interval DNS beacons found'
        'dns_cache'                       = 'resolver cache empty - flushed, just booted, or no name resolution since boot'
    'scheduled_taskcache'             = 'TaskCache keys not enumerable (needs admin) or the Schedule service store is empty - check the elevation caveats'
    'task_deletions'                  = 'no EID 4699 task deletions in the window (empty is good - bulk deletions are an anti-forensics tell)'
    'esent_ntds'                      = 'no ntds.dit access events - expected on non-DC hosts (ESENT only logs AD database opens on domain controllers)'
    'shimcache_exec'                  = 'shimcache parse pending (module 5.4 / chainsaw) or no Win10+ entries to decode - see parse_needed.csv'
    'radar_exec'                      = 'RADAR has no diagnosed apps - common on workstations (memory diagnostics mostly fire on servers)'
    'appswitched'                     = 'no AppSwitched counters - FeatureUsage absent for the profiles or no interactive GUI session history'
        'domain_info'                     = 'Win32_ComputerSystem returned nothing - the WMI repository may be damaged on this host (itself an IR-relevant condition; check collection.log for other WMI failures)'
        'entities_accounts'               = 'joins logons/RDP/console history per account - nothing to join when those sources are empty'
        'entities_binaries'               = 'joins execution/persistence/network/verdict evidence per binary - nothing to join when the underlying sources are empty'
        'entities_remotes'                = 'joins connections/beacons/brute-force/RDP targets per remote endpoint - nothing to join when those sources are empty'
        'flash_public_connections'        = 'no connections to public IPs during the flash triage window (internal-only traffic)'
        'hunt_findings'                   = 'no hunt-rule matches - every technique rule came back clean (empty is good)'
        'iis_anomalies'                   = 'joins the parsed IIS requests - nothing anomalous in them, or no IIS logs were collected'
        'iis_requests'                    = 'no IIS/HTTPERR logs found - the web-server role is absent, logs were purged, or they live on another volume (module 8.12 is opt-in WebServer/Full)'
        'ioc_hits_amcache'                = 'no IOC-feed SHA1s in the Amcache execution history (empty is good, or the Amcache parse is pending - see parse_needed.csv)'
        'ioc_hits_browser'                = 'no IOC-feed domains in the browser history (empty is good, or browser data was absent)'
        'ioc_hits_dns'                    = 'no IOC-feed domains among the Sysmon DNS queries (empty is good, or the Sysmon DNS source is empty)'
        'ioc_hits_hash'                   = 'no IOC-feed hashes in the process execution history (empty is good, or process_hashes is empty)'
        'ioc_hits_mft'                    = 'no IOC-feed filenames born on disk per the $MFT extract (empty is good, or mft_recent is empty)'
        'ioc_hits_network'                = 'no IOC-feed IPs among the Sysmon network destinations (empty is good, or the Sysmon network source is empty)'
        'loldrivers_hits'                 = 'every hashed on-disk driver is absent from the LOLDrivers malicious/vulnerable sets (empty is good)'
        'logging_gaps'                    = 'no log clears/stops/gaps - event logging was continuous across the window (empty is good)'
        'memory_live_scan'                = 'no processes were minidumped - the memory module was not selected, no flagged process qualified, or the dumps failed (see collection.log)'
        'mft_recent'                      = 'no $MFT entries kept - nothing born in the window on executable/user paths, or the MFTECmd parse did not run (see parse_needed.csv)'
        'parse_needed'                    = 'everything collected was parsed with the bundled tools - nothing is pending analyst-side completion (empty is good)'
        'leads'                           = 'ranked triage leads (report artifact - the one ranking behind the lead cards + the draft BEST LEADS, not evidence)'
        'powershell_console_history'      = 'no PSReadLine console history for any profile - the file only exists after interactive PowerShell console use (or history is disabled)'
        'prefetch_index'                  = 'the Prefetch directory exists but holds no .pf files - Prefetch is disabled (common on servers and SSD-tweaked builds) or was wiped'
        'processes_flagged'               = 'no processes tripped the suspicious-process heuristics (empty is good)'
        'registry_recmd'                  = 'no registry hardening recommendations triggered for this host (empty is good)'
        'saved_credentials'               = 'no stored credentials (cmdkey /list empty - nothing saved for RDP/terminal/web) - attackers add these, so empty is good'
        'scheduled_tasks_flagged'         = 'no scheduled tasks tripped the suspicious-task heuristics (empty is good)'
        'services_flagged'                = 'no services tripped the suspicious-service heuristics (empty is good)'
        'shellbags'                       = 'SBECmd produced nothing - the parser was unavailable on the endpoint (see parse_needed.csv), the session was not elevated, or the profiles have no Explorer history'
        'smb_hosted_shares'               = 'no hosted shares returned - the Server service may be stopped or Get-SmbShare failed (a normal host always exposes its admin shares, so empty is itself a config note)'
        'ual_files'                       = 'the UAL directory exists but holds no .mts files - User Access Logging recorded nothing (UAL is typically only active on domain-joined servers)'
        'usb_devices'                     = 'no USB storage device has EVER been connected on this install per USBSTOR (empty is good, but unusual on a workstation - verify this is not a stripped image)'
        'webshell_candidates'             = 'no script files in the web roots matched webshell heuristics (empty is good - every hit is worth a baseline check)'
        'wmi_event_filters'               = 'no WMI event filters registered (rare persistence mechanism - empty is good)'
        'yara_scanned'                    = 'the YARA scan ran but no candidate files existed to scan (missing yara.exe never produces this file - run -Mode Setup)'
    }
    # v2.67 (R1): sysmon partial-coverage mix - computed over the same rows the index renders
    $sysHas = 0; $sysZero = 0
    $null = $sb.AppendLine("<table><tr><th>Artifact</th><th>Rows</th><th>What it is / what to look for</th></tr>")
    foreach ($f in @(Get-ChildItem -Path $CsvDir -Filter '*.csv' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { @('sigma_rules', 'evtx_ecmd', 'recmd_out') -notcontains $_.Directory.Name } | Sort-Object Name)) {
        $rows = 0
        try {
            # v2.63: stream lines via ReadLines - some case CSVs are tens of MB, never load one just to count it
            $first = $null; $n = 0
            foreach ($line in [System.IO.File]::ReadLines($f.FullName)) { if ($null -eq $first) { $first = $line }; $n++ }
            if ($first -and $first -notmatch '^#') { $rows = $n - 1 }
        } catch { }
        $base = $f.BaseName
        # v2.67 (R1): track the sysmon has-rows/zero-row mix for the partial-coverage note
        if ($base -match '^sysmon_') { if ($rows -gt 0) { $sysHas++ } else { $sysZero++ } }
        $d = if ($desc.ContainsKey($base)) { $desc[$base] } else { '' }
        if (-not $d) {
            # v2.54: wildcard map keys (logon_summary*, amcache_*, jumplist_parsed*...) - raw
            # tool-output names otherwise render with an empty "what it is" cell
            foreach ($k in $desc.Keys) { if ($k.EndsWith('*') -and $base.StartsWith($k.TrimEnd('*'))) { $d = $desc[$k]; break } }
        }
        $rel = $f.FullName.Substring($CsvDir.Length).TrimStart('\')
        $evLbl = "csv\$rel"
        # v2.58: zero-row artifacts explain themselves instead of showing a naked 0
        $dTxt = $d
        if ($rows -eq 0) {
            # v2.65: a Save-Rows failure marker is not "empty" - the file's own FAILED line is
            # the explanation and outranks the static why-empty map (a failed yara_hits must
            # not claim "the rules matched nothing")
            $why = $null
            if ($first -and "$first" -match '^FAILED:') { $why = "artifact FAILED to save during collection: $(("$first" -replace '^(?i)FAILED:\s*', ''))" }
            if (-not $why) {
                # v2.68 (B18): the wildcard fallback here was dead - no $emptyWhy key is starred
                # (the starred keys belong to the $desc map, whose own lookup above stays live)
                $why = $emptyWhy[$base]
            }
            if ($why) { $dTxt = "$d <div class='meta' style='margin-top:4px'><b>why empty:</b> $(ConvertTo-HtmlEsc $why)</div>" }
        }
        $null = $sb.AppendLine("<tr><td>$(ConvertTo-CaseFileLink $f.FullName $evLbl)</td><td>$rows</td><td>$dTxt</td></tr>")
    }
    $null = $sb.AppendLine("</table>")
    # v2.67 (R1): some Sysmon classes present while others are empty = a config/coverage gap,
    # not proof of absence. One honest line beats fifteen individually-ambiguous zero rows.
    if ($sysHas -gt 0 -and $sysZero -gt 0) {
        $null = $sb.AppendLine("<div class='meta'><b>Sysmon partial coverage:</b> some Sysmon artifact classes have events while others are empty - the endpoint's Sysmon config does not enable every event ID Ophira reads (or that activity class genuinely did not occur in the window). Read the empty Sysmon classes as blind spots to widen, not as proof nothing happened.</div>")
    }
    $caseRoot = Split-Path -Parent $CsvDir
    $alsoIn = @()
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $CsvDir (Get-CaseCsvPath 'supertimeline')) "csv\$(Get-CaseCsvPath 'supertimeline')") (MASTER chronology - every artifact, filter by time)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'csv\evtx_ecmd') 'csv\evtx_ecmd\') (full event-log CSVs for deep-dives, when EvtxECmd ran in Parse mode)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'siem_export.ndjson') 'siem_export.ndjson') (Splunk/Elastic-ready records)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'case_draft.txt') 'case_draft.txt') (auto-written executive draft - edit into your report)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'verdict.json') 'verdict.json')"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'attack_layer.json') 'attack_layer.json') (MITRE ATT&amp;CK Navigator layer - load at navigator.mitre.org)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'case.json') 'case.json') (run metadata + module timings)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'raw') 'raw\') (evtx, registry hives, prefetch, recent/jumplists, browser DBs, firewall log, RDP bitmap cache tiles in raw\rdp_cache - reconstruct what inbound RDP sessions displayed with RdpCacheStudio)"
    $alsoIn += "$(ConvertTo-CaseFileLink (Join-Path $caseRoot 'collection.log') 'collection.log')"
    $null = $sb.AppendLine("<div class='meta'>Also in the case: $($alsoIn -join ', ')</div>")

    # shared client-side helpers: click-to-copy / double-click-expand + per-rule Sigma browsers
    $ruleJsText = ('{' + ($ruleJs -join ',') + '}') -replace '<', '\u003c'
    $null = $sb.AppendLine("<div id='copied'></div>")
    $null = $sb.AppendLine(@"
      <script>
      var RULES = $ruleJsText;
      function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
      function attr(s){return esc(s).replace(/"/g,'&quot;');}
      document.addEventListener('click',function(e){
        var t=e.target.closest?e.target.closest('.clip'):null;
        if(t){var f=t.getAttribute('data-full')||t.textContent;
          if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(f);}
          var n=document.getElementById('copied'); if(n){n.textContent='copied '+f.length+' chars to clipboard'; n.style.display='block'; setTimeout(function(){n.style.display='none';},1200);}
        }
      });
      document.addEventListener('dblclick',function(e){
        var t=e.target.closest?e.target.closest('.clip'):null;
        if(t){t.classList.toggle('open');}
      });
      // v2.66 (B6+B7): deep links into the per-rule Sigma drill-downs (ATT&CK expansion rows,
      // lead cards). Jump to the Sigma section via the href, then open that rule's drill-down,
      // pre-fill its text filter (data-q) and re-run it. No drill-down for the rule -> the
      // plain section-top anchor jump stands.
      document.addEventListener('click',function(e){
        var a=e.target.closest?e.target.closest('a[data-rule]'):null;
        if(!a)return;
        var id=a.getAttribute('data-rule');
        var inp=document.getElementById('q_'+id);
        if(!inp)return;
        var dd=inp.closest?inp.closest('details'):null;
        if(dd&&!dd.open)dd.setAttribute('open','open');
        var q=a.getAttribute('data-q')||'';
        if(q)inp.value=q;
        if(typeof renderRule==='function')renderRule(id);
      });
      function copyIocAll(btn){
        var p=document.getElementById('iocblock');
        if(!p)return;
        var f=p.textContent;
        if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(f);}
        btn.textContent='copied '+f.length+' chars';
        setTimeout(function(){btn.textContent='copy all';},1500);
      }
      function pgRule(id,delta){var p=document.getElementById('p_'+id);p.value=(parseInt(p.value)||1)+delta;renderRule(id);}
      function renderRule(id){
        var rows=RULES[id]||[];
        var q=((document.getElementById('q_'+id)||{}).value||'').toLowerCase();
        var lv=(document.getElementById('l_'+id)||{}).value||'all';
        var pg=parseInt((document.getElementById('p_'+id)||{}).value)||1;
        // v2.66 (B10): page-size jump - 50/100/200 or all embedded rows
        var psv=(document.getElementById('ps_'+id)||{}).value||'50';
        var per=(psv==='all')?Math.max(1,rows.length):(parseInt(psv)||50);
        var f=[],i;
        for(i=rows.length-1;i>=0;i--){var r=rows[i];
          if(lv!=='all'&&r.l!==lv)continue;
          // v2.66 (B6): EID + RecordID joined to the searched text so a deep-linked query hits the exact event
          if(q&&((r.d+' '+r.t+' '+r.c+' '+(r.e||'')+' '+(r.rid||'')).toLowerCase().indexOf(q)<0))continue;
          f.push(r);
        }
        var pages=Math.max(1,Math.ceil(f.length/per)); if(pg>pages)pg=pages; if(pg<1)pg=1;
        var pe=document.getElementById('p_'+id); if(pe)pe.value=pg;
        var h='<table><tr><th>Time</th><th>Computer</th><th>EID</th><th>Level</th><th>Event details - click = copy raw, show all = full text</th></tr>';
        for(i=(pg-1)*per;i<Math.min(pg*per,f.length);i++){var r2=f[i];
          var prev=r2.d.length>300?r2.d.substring(0,300)+'...':r2.d;
          h+='<tr><td>'+esc(r2.t)+'</td><td>'+esc(r2.c)+'</td><td>'+esc(r2.e)+'</td><td class="'+esc(r2.lc)+'">'+esc(r2.l)+'</td><td class="clip path" data-full="'+attr(r2.d)+'" title="click = copy raw">'+esc(prev)+'</td></tr>';
        }
        h+='</table>';
        var box=document.getElementById('b_'+id);
        if(box){box.innerHTML='<div class="pgr meta">'+f.length+' match(es), page '+pg+'/'+pages
          +'<button onclick="pgRule(\''+id+'\',-1)">prev</button><button onclick="pgRule(\''+id+'\',1)">next</button></div>'+h;}
      }
      Object.keys(RULES).forEach(function(k){renderRule(k);});
      // v2.66 (B12): one generic section filter (the timeline pattern) - filters any container's
      // items by substring and updates the section's count line. Bound per section below.
      function secFilter(box,wrap,sel,cnt){var q=document.getElementById(box).value.toLowerCase();var its=document.querySelectorAll('#'+wrap+' '+sel);var n=0;for(var i=0;i<its.length;i++){var hit=!q||its[i].textContent.toLowerCase().indexOf(q)>=0;its[i].style.display=hit?'':'none';if(hit)n++;}var c=document.getElementById(cnt);if(c)c.textContent=q?(n+' of '+its.length+' shown'):'';}
      document.querySelectorAll('input[data-secfilter]').forEach(function(b){b.addEventListener('input',function(){secFilter(b.id,b.getAttribute('data-wrap'),b.getAttribute('data-sel'),b.getAttribute('data-cnt'));});});
      // v2.53: visible show-all toggle on every truncated cell (full text rides data-full)
      document.querySelectorAll('td.clip[data-full]').forEach(function(t){
        var f=t.getAttribute('data-full')||'';
        if(f.length>t.textContent.length){
          var br=document.createElement('br'),b=document.createElement('button');
          b.className='swall';b.textContent='show all';
          b.addEventListener('click',function(e){e.stopPropagation();t.textContent=f;t.classList.add('open');});
          t.appendChild(br);t.appendChild(b);
        }
      });
      // v2.63: printing shows collapsed <details> content - open them for print, restore after
      var printClosed=[];
      window.addEventListener('beforeprint',function(){
        printClosed=[];
        document.querySelectorAll('details:not([open])').forEach(function(d){d.setAttribute('open','open');printClosed.push(d);});
      });
      window.addEventListener('afterprint',function(){
        printClosed.forEach(function(d){d.removeAttribute('open');});
        printClosed=[];
      });
      </script>
"@)
    $null = $sb.AppendLine("<div class='foot'>Generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC by Ophira v$ScriptVersion - all verdicts are correlation heuristics; verify against raw CSV/evtx evidence before acting.</div>") # v2.66 (B13): same stamp dialect as the banner; ToUniversalTime so the UTC label is true
    $null = $sb.AppendLine("</body></html>")
    $reportPath = Join-Path $CaseDir 'report.html'
    $sb.ToString() | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-CaseLog "    report: $reportPath" 'Cyan'
    return $reportPath
}

function New-SuperTimeline {
    # v2.24 MASTER TIMELINE: every artifact source woven into ONE chronological CSV with a
    # normalized schema (Timestamp, Source, Type, Actor, Entity, Detail) so the analyst can
    # open a single file and filter to any timeframe ("weird activity at 14:00" checks).
    # Per-source caps + a total cap keep the file bounded; per-source caps keep the NEWEST
    # events (head-counting used to keep the oldest while the total cap kept the newest,
    # silently dropping the newest evidence on busy cases); hayabusa sort-csv dedupes overlaps.
    $rows = New-Object System.Collections.Generic.List[object]
    $add = {
        param($ts, [string]$source, [string]$type, [string]$actor, [string]$entity, [string]$detail)
        if (-not $ts) { return }
        $iso = "$ts"
        $dt = Get-InvariantDate $ts
        if ($dt -gt [datetime]::MinValue) { $iso = $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }
        $d = ("$detail" -replace '\s+', ' ').Trim()
        if ($d.Length -gt 240) { $d = $d.Substring(0, 240) + '...' }
        $null = $rows.Add([pscustomobject]@{ Timestamp = $iso; Source = $source; Type = "$type"; Actor = "$actor"; Entity = "$entity"; Detail = $d })
    }
    $keepNewest = {
        # per-source cap: buffer all mapped rows, keep the NEWEST $cap by parsed timestamp
        param($buf, [int]$cap)
        # comma operator: survive PS one-level output unroll (a bare single-row return
        # would make the caller iterate the row's fields instead of the rows)
        if ($buf.Count -le $cap) { return ,$buf }
        ,@($buf | Sort-Object { Get-InvariantDate $_[0] } -Descending | Select-Object -First $cap)
    }
    $weave = {
        param([string]$name, [int]$cap, [scriptblock]$map)
        $buf = New-Object System.Collections.Generic.List[object]
        foreach ($r in (Import-CaseCsv $name)) {
            $m = $null
            try { $m = & $map $r } catch { }
            if ($m -and "$($m[0])") { $buf.Add(@("$($m[0])", $m[1], $m[2], $m[3], $m[4])) }
        }
        foreach ($m in (& $keepNewest $buf $cap)) { & $add $m[0] $name $m[1] $m[2] $m[3] $m[4] }
    }
    $leaf = { param($p) try { if ("$p") { (Split-Path "$p" -Leaf) } else { '' } } catch { "$p" } }

    # generic event-log CSVs (Get-FilteredEvents shape: TimeCreated/Id/Message)
    foreach ($name in @('security_events', 'powershell_events', 'sysmon_events', 'system_events', 'defender_events', 'rdp_localsession', 'rdp_connections', 'application_events')) {
        $buf = New-Object System.Collections.Generic.List[object]
        foreach ($r in (Import-CaseCsv $name)) {
            if (-not $r.PSObject.Properties['TimeCreated']) { continue }
            # v2.82: drop CDXML proxy boilerplate - EID 4104 'Creating Scriptblock text'
            # fragments for $__cmdletization_* code (Get-NetTCPSetting etc.) auto-logged by
            # CDXML cmdlets; hundreds of rows, zero investigative value in the timeline
            if ("$($r.Message)" -match '__cmdletization') { continue }
            $buf.Add(@("$($r.TimeCreated)", "EID $($r.Id)", '', '', "$($r.Message)"))
        }
        foreach ($m in (& $keepNewest $buf 5000)) { & $add $m[0] $name $m[1] $m[2] $m[3] $m[4] }
    }
    # structured security telemetry
    & $weave 'security_auth_events' 5000 { param($r) $t = $(if ("$($r.EventId)" -eq '4625') { 'failed logon' } else { 'logon' }); if ("$($r.LogonType)") { $t = "$t (type $($r.LogonType))" } @("$($r.Time)", $t, "$($r.Account)", "$($r.SourceIp)", "LogonId $($r.LogonId)") }
    & $weave 'security_proc_events' 5000 { param($r) @("$($r.Time)", 'process created (4688)', "$($r.Account)", (& $leaf $r.NewProcess), "parent $(& $leaf $r.ParentProcess) | $($r.CommandLine)") }
    & $weave 'security_share_access' 5000 { param($r) @("$($r.Time)", "share access (EID $($r.EventId))", "$($r.Account)", "$("$($r.ShareName)" -replace '^[\*\\\s]+', '')\$("$($r.RelativeTargetName)" -replace '\\', '/')", "from $($r.SourceIp) [$(("$($r.AccessList)" -replace '%%', ''))]") }
    & $weave 'security_task_install' 500 { param($r) @("$($r.Time)", 'scheduled task installed (4698)', "$($r.Account)", "$($r.TaskName)", "$($r.Command)") }
    & $weave 'task_deletions' 200 { param($r) @("$($r.Time)", 'scheduled task deleted (4699)', "$($r.User)", (& $leaf $r.TaskName), "$($r.Message)") }
    & $weave 'esent_ntds' 200 { param($r) @("$($r.Time)", 'ntds.dit accessed (ESENT 325/326)', '', '', "$(if ("$($r.BackupPattern)" -eq 'True') { 'backup-pattern' } else { 'NON-BACKUP - theft prep?' }) | $($r.Message)") }
    & $weave 'security_kerberos' 3000 { param($r) @("$($r.Time)", "kerberos (EID $($r.EventId))", "$($r.Account)", "$($r.IpAddress)", "svc=$($r.Service) enc=$($r.TicketEnc) preauth=$($r.PreAuth)") }
    & $weave 'security_ds_access' 3000 { param($r) @("$($r.Time)", "directory service (EID $($r.EventId))", "$($r.Account)", "$($r.Object)$("$($r.ObjectDN)")", "$("$($r.Properties)" -replace '\s+', ' ') | $($r.Attribute)=$($r.Value)") }
    & $weave 'defender_config_events' 500 { param($r) @("$($r.Time)", "defender config (EID $($r.EventId))", '', '', "$($r.Detail)") }
    # sysmon structured
    & $weave 'sysmon_network' 5000 { param($r) @("$($r.Time)", 'network connection (Sysmon 3)', (& $leaf $r.Image), "$($r.DestIp):$($r.DestPort)", "proto $($r.Protocol)") }
    & $weave 'sysmon_dns' 5000 { param($r) @("$($r.Time)", 'DNS query (Sysmon 22)', (& $leaf $r.Image), "$($r.QueryName)", "resolved $($r.QueryResults)") }
    & $weave 'sysmon_image_load' 3000 { param($r) @("$($r.Time)", 'image load (Sysmon 7)', (& $leaf $r.Process), (& $leaf $r.Dll), "signed=$($r.Signed) $($r.Signature)") }
    & $weave 'sysmon_proc_create' 5000 { param($r) @("$($r.Time)", 'process create (Sysmon 1)', (& $leaf $r.Image), '', $(if ("$($r.OriginalFileName)" -and ((Split-Path "$($r.Image)" -Leaf) -ne "$($r.OriginalFileName)")) { "ORIGINAL NAME: $($r.OriginalFileName) | $($r.CommandLine)" } else { "$($r.CommandLine)" })) }
    & $weave 'sysmon_process_access' 3000 { param($r) @("$($r.Time)", 'process access (Sysmon 10)', (& $leaf $r.SourceImage), (& $leaf $r.TargetImage), "granted=$($r.GrantedAccess) trace=$(("$($r.CallTrace)" -replace '\+.*', ''))") }
    & $weave 'sysmon_registry' 3000 { param($r) @("$($r.Time)", "registry event (Sysmon 13)", (& $leaf $r.Image), "$($r.TargetObject)", "$($r.EventType)") }
    & $weave 'sysmon_file_time' 1000 { param($r) @("$($r.Time)", 'file creation time changed (Sysmon 2)', (& $leaf $r.Image), (& $leaf $r.TargetFilename), "$($r.PreviousCreationUtcTime) -> $($r.CreationUtcTime)") }
    & $weave 'sysmon_file_create' 3000 { param($r) @("$($r.Time)", 'file created (Sysmon 11)', (& $leaf $r.Image), (& $leaf $r.TargetFilename), "$($r.TargetFilename)") }
    & $weave 'sysmon_file_delete' 1000 { param($r) @("$($r.Time)", 'file deleted (Sysmon 23)', (& $leaf $r.Image), (& $leaf $r.TargetFilename), 'deleted by process - anti-forensics / cleanup lead') }
    & $weave 'sysmon_remote_thread' 2000 { param($r) @("$($r.Time)", 'remote thread (Sysmon 8)', (& $leaf $r.SourceImage), (& $leaf $r.TargetImage), "$(& $leaf $r.SourceImage) injected a remote thread into $(& $leaf $r.TargetImage) - cross-process injection lead") }
    & $weave 'sysmon_pipes' 1000 { param($r) @("$($r.Time)", "pipe $(if ("$($r.EventId)" -eq '17') { 'created' } else { 'connected' }) (Sysmon $($r.EventId))", (& $leaf $r.Image), ("$($r.PipeName)"), "named pipe $($r.PipeName)") }
    & $weave 'sysmon_proc_tamper' 1000 { param($r) @("$($r.Time)", 'process tampering (Sysmon 25)', (& $leaf $r.Image), (& $leaf $r.Image), "image swapped in memory - hollowing/herpaderp detected by Sysmon (R30)") }
    & $weave 'sysmon_raw_access' 500 { param($r) @("$($r.Time)", 'raw volume access (Sysmon 9)', (& $leaf $r.Image), ("$($r.Device)"), "raw \\.\ read - locked-hive credential theft / anti-forensics lead (R31)") }
    # execution evidence
    $exec = Import-CaseCsv 'execution_timeline'
    if ($exec.Count -gt 0) {
        $tCol = ($exec[0].PSObject.Properties.Name | Select-Object -First 1)
        $buf = New-Object System.Collections.Generic.List[object]
        foreach ($r in $exec) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
            $buf.Add(@("$($r.$tCol)", 'shimcache/amcache entry', '', '', $line))
        }
        foreach ($m in (& $keepNewest $buf 3000)) { & $add $m[0] 'execution_timeline' $m[1] $m[2] $m[3] $m[4] }
    }
    $pfT = { param($r) $c = @($r.PSObject.Properties.Name | Where-Object { $_ -match '(?i)lastrun' } | Select-Object -First 1)[0]; if ($c) { "$($r.$c)" } else { '' } }
    $pfE = { param($r) $c = @($r.PSObject.Properties.Name | Where-Object { $_ -match '(?i)executable|^name$' } | Select-Object -First 1)[0]; if ($c) { "$($r.$c)" } else { '' } }
    & $weave 'prefetch_parsed' 2000 { param($r) $rc = ''; foreach ($pn in @($r.PSObject.Properties.Name)) { if ($pn -match '(?i)runcount|^run') { $rc = "$($r.$pn)"; break } } @((& $pfT $r), 'prefetch run', (& $leaf (& $pfE $r)), (& $pfE $r), "run count $rc") }
    & $weave 'amcache' 2000 {
        param($r)
        $t = $null
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$' })) {
            try { $t2 = Get-InvariantDate "$($r.$pn)"; if ($t2 -gt [datetime]::MinValue -and (-not $t -or $t2 -lt $t)) { $t = $t2 } } catch { }
        }
        $nm = ''; foreach ($pn in @('Name', 'ApplicationName', 'SourceSimpleName')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $nm = "$($p2.Value)"; break } }
        @($(if ($t) { $t.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }), 'amcache entry', $nm, $nm, "source $($r.SourceFile)")
    }
    & $weave 'mft_recent' 3000 { param($r) @("$($r.Created)", 'file created ($MFT $Si)', '', "$($r.Path)", "FILE_NAME birth $($r.CreatedFN) | $($r.Flags)") }
    & $weave 'usn_write_bursts' 200 { param($r) @("$($r.WindowStart)", 'mass file modification (USN burst)', '', "$($r.Drive)", "$($r.WriteEvents) writes / $($r.DistinctFiles) files$(if ("$($r.RansomExt)") { " RANSOM-EXT $($r.RansomExt)" })") }
    & $weave 'bam_lastexec' 2000 { param($r) @("$($r.LastWrite)", "last exec ($($r.Source))", (& $leaf $r.Executable), "$($r.Executable)", "sid $($r.Sid)") }
    & $weave 'startup_info' 1000 { param($r) @("$($r.LastRun)", 'app launch (StartupInfo)', (& $leaf $r.App), "$($r.App)", "count $($r.Count)") }
    & $weave 'wer_reports' 1000 { param($r) @("$($r.Time)", 'app crash (WER)', "$($r.App)", "$($r.Module)", "$($r.File)") }
    & $weave 'office_mru' 500 { param($r) @("$($r.LastWrite)", 'office document (MRU)', "$($r.App)", (& $leaf $r.Document), "$($r.Document)") }
    $anyT = {
        param($r, $fallback)
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)time|date' })) {
            if ("$($r.$pn)") { return "$($r.$pn)" }
        }
        $fallback
    }
    & $weave 'lnk_parsed' 1000 { param($r) @((& $anyT $r ''), 'LNK opened', '', (& $leaf $r.Target), "$($r.Path) -> $($r.Target)") }
    & $weave 'shellbags' 1000 { param($r) @((& $anyT $r ''), 'folder accessed (ShellBag)', '', (& $leaf ($r.PSObject.Properties['Path'].Value)), "$($r.PSObject.Properties['Path'].Value)") }
    & $weave 'recyclebin_index' 1000 { param($r) @((& $anyT $r ''), 'file deleted (recycle bin)', '', (& $leaf ($r.PSObject.Properties['OriginalPath'].Value)), "$($r.PSObject.Properties['OriginalPath'].Value)") }
    & $weave 'browser_history' 2000 {
        param($r)
        $u = ''; foreach ($pn in @('URL', 'Url', 'url')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $u = "$($p2.Value)"; break } }
        @((& $anyT $r ''), 'browser visit', '', $u, ("$($r.PSObject.Properties['Title'].Value)"))
    }
    & $weave 'browser_downloads' 1000 {
        param($r)
        $tp = ''; foreach ($pn in @('TargetFilePath', 'TargetPath', 'DownloadPath', 'FullPath', 'Path')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $tp = "$($p2.Value)"; break } }
        @((& $anyT $r ''), 'browser download', '', (& $leaf $tp), "$($r.PSObject.Properties['URL'].Value)")
    }
    # v2.59: SRUM per-app network history (deep SrumECmd parse) - zero-traffic usage rows are
    # skipped so the cap is spent on real events
    & $weave 'srum_usage' 2000 {
        param($r)
        $bs = 0L; $br = 0L
        try { $bs = [long]"$($r.BytesSent)" } catch { }
        try { $br = [long]"$($r.BytesReceived)" } catch { }
        if (($bs + $br) -le 0) { return $null }
        @("$($r.Timestamp)", 'app network usage (SRUM)', "$($r.User)", (& $leaf $r.Application), "sent $bs / recv $br bytes")
    }
    & $weave 'iis_requests' 1000 { param($r) @("$($r.Time)", "web request (IIS) $("$($r.Method)")", '', "$($r.ClientIp) -> $("$($r.Uri)")", "status $($r.Status) ua=$("$($r.UserAgent)")") }
    # scanner/derived outputs (hayabusa Sigma results, hunt findings, session attribution,
    # logging-gap analysis) are deliberately NOT woven here - the timeline is gathered
    # evidence only; conclusions live in their own report sections.

    if ($rows.Count -eq 0) { return }
    $sorted = @($rows | Sort-Object { Get-InvariantDate $_.Timestamp })
    if ($sorted.Count -gt 120000) { $sorted = @($sorted | Select-Object -Last 120000) }
    $out = Get-CaseCsvFullPath 'supertimeline'
    $sorted | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    # hayabusa sort-csv: dedupe same-event rows coming from overlapping/backup evtx (PS sort above already orders by time)
    $hS = Get-HayabusaExe
    if ($hS) { $null = Invoke-NativeTool -ExePath $hS.FullName -ToolArgs @('sort-csv', '-f', $out, '-o', $out, '-C', '-q', '-K') -WorkingDirectory $hS.DirectoryName -QuietLog }
    $nFinal = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
    Write-CaseLog "    MASTER TIMELINE: $($sorted.Count) evidence events, $nFinal after dedupe -> csv\$(Get-CaseCsvPath 'supertimeline') (filter by Timestamp in Excel/Timeline Explorer)" 'DarkGray'
}

function New-SigmaRuleLogs {
    # Per-rule rawlog CSVs: one file per matched Sigma rule under csv\sigma_rules\ (+ index.csv).
    $hay = Import-CaseCsv 'hayabusa_timeline'
    if ($hay.Count -eq 0) { return }
    $nameCol = if ($hay[0].PSObject.Properties['RuleTitle']) { 'RuleTitle' } elseif ($hay[0].PSObject.Properties['Alert']) { 'Alert' } else { return }
    # v2.80 (T4/M6): same collision-free key map the report renders with (raw $hay = same name
    # universe) so per-rule CSV filenames match drill keys/lead hrefs even on sanitize collisions
    $sigmaRuleMap = Get-SafeRuleKeyMap $hay $nameCol
    $dir = Join-Path $CsvDir 'sigma_rules'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $index = @()
    foreach ($g in ($hay | Group-Object $nameCol)) {
        $safe = Resolve-SafeRuleKey $sigmaRuleMap $g.Name
        $rows = @($g.Group | Sort-Object Timestamp)
        $rows | Select-Object Timestamp, Level, Computer, Channel, EventID, RecordID, RuleID, Details, ExtraFieldInfo |
            Export-Csv -LiteralPath (Join-Path $dir "$safe.csv") -NoTypeInformation -Encoding UTF8
        $best = @($rows | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
        $index += [pscustomobject]@{
            Rule = "$($g.Name)"
            Hits = $rows.Count
            MaxLevel = "$($best.Level)"
            LogCsv = "csv\sigma_rules\$safe.csv"
        }
    }
    $index | Sort-Object { Get-LvlRank "$($_.MaxLevel)" } -Descending |
        Export-Csv -LiteralPath (Join-Path $dir 'index.csv') -NoTypeInformation -Encoding UTF8
    Write-CaseLog "    sigma rule logs: $($index.Count) rule(s) -> csv\sigma_rules\ (per-rule event CSVs + index.csv)" 'DarkGray'
}

function New-EntityCorrelation {
    # Cross-source entity correlation (report-only): joins binaries, accounts and remote
    # endpoints across the case CSVs so one entity's story is readable in one place.
    # Missing sources contribute nothing - graceful by design.
    $CAP = 2000
    $rowsOf = {
        param([string]$name)
        try { return @((Import-CaseCsv $name) | Select-Object -First $CAP) } catch { return @() }
    }

    # ---------- binaries: keyed by full path, name fallback ----------
    $binsByPath = @{}
    $binsByName = @{}
    $binNew = {
        param([string]$raw)
        $p = ("$raw").Trim().Trim('"')
        # SRUM reports device-style paths - normalize to the drive letter (best effort: volume 3 is C: on the vast majority of systems)
        # ponytail: fixed harddiskvolume->C: mapping; per-volume letter resolution needs the mounteddevices hive
        $p = $p -replace '(?i)^\\device\\harddiskvolume\d+\\', 'C:\'
        if (-not $p) { return $null }
        $lk = $p.ToLower()
        $nk = Split-Path $lk -Leaf
        if (-not $nk) { $nk = $lk }
        if ($p.Contains('\') -and $binsByPath.ContainsKey($lk)) { return $binsByPath[$lk] }
        if (-not $p.Contains('\') -and $binsByName.ContainsKey($nk)) { return $binsByName[$nk] }
        $b = [pscustomobject]@{
            Path = $(if ($p.Contains('\')) { $p } else { "(name-only) $p" })
            Name = $nk
            Cats = New-Object System.Collections.Generic.List[string]
            Evidence = New-Object System.Collections.Generic.List[string]
            Hashes = New-Object System.Collections.Generic.List[string]
            Verdict = ''; Signer = ''; FirstSeen = ''; LastSeen = ''; Bytes = ''
        }
        $binsByPath[$lk] = $b
        if (-not $binsByName.ContainsKey($nk)) { $binsByName[$nk] = $b }
        return $b
    }
    $binAdd = {
        param($b, [string]$cat, [string]$detail, [string]$when)
        if (-not $b) { return }
        if ($b.Cats -notcontains $cat) { $b.Cats.Add($cat) }
        if ($detail) {
            $line = "$cat`: $detail"
            if ($b.Evidence.Count -lt 14 -and -not $b.Evidence.Contains($line)) { $b.Evidence.Add($line.Substring(0, [Math]::Min(220, $line.Length))) }
        }
        if ($when) {
            $t = $null
            try { $t = [datetime]$when } catch { }
            if ($t) {
                if (-not $b.FirstSeen -or $t -lt [datetime]$b.FirstSeen) { $b.FirstSeen = "$t" }
                if (-not $b.LastSeen -or $t -gt [datetime]$b.LastSeen) { $b.LastSeen = "$t" }
            }
        }
    }
    $binFromRow = {
        param($r)
        foreach ($pn in @('Binary', 'Image', 'ProcessPath', 'Process', 'Executable', 'Application', 'AppPath', 'App', 'NewProcess')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { return (& $binNew $p2.Value) }
        }
        # 'Path'/'PathName' are only trusted when they name a real binary (service/task rows abuse these for names)
        foreach ($pn in @('PathName', 'SourceFile', 'Path')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '\.(exe|dll|sys|ps1|bat|js|vbs|hta|com|ocx|drv)$') { return (& $binNew $p2.Value) }
        }
        foreach ($pn in @('Actions', 'Value', 'Details', 'Command')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '(?i)([a-z]:\\[^\s"|]+\.(exe|dll|sys|ps1|bat|js|vbs|hta))') { return (& $binNew $Matches[1]) }
        }
        foreach ($pn in @('Name', 'ExecutableName', 'FileName')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '\.(exe|dll|sys|ps1|bat|js|vbs|hta)$') { return (& $binNew $p2.Value) }
        }
        return $null
    }

    foreach ($r in (& $rowsOf 'flash_process_scored')) {
        $b = & $binFromRow $r
        if ($b) { $b.Verdict = "$($r.Verdict)"; $b.Signer = "$($r.Signer)"; & $binAdd $b 'verdict' "[$($r.Verdict) $($r.Score)] $($r.Evidence)" '' }
    }
    foreach ($r in (& $rowsOf 'processes')) { & $binAdd (& $binFromRow $r) 'running' "PID $($r.PID)" '' }
    foreach ($r in (& $rowsOf 'process_hashes')) { $b = & $binFromRow $r; if ($b) { $null = $b.Hashes.Add("$($r.SHA256)"); & $binAdd $b 'hash' "$($r.SHA256)" '' } }
    foreach ($src in @('services', 'services_flagged')) {
        foreach ($r in (& $rowsOf $src)) {
            $b = & $binFromRow $r
            $svcName = if ($r.PSObject.Properties['Service']) { "$($r.Service)" } elseif ($r.PSObject.Properties['Name']) { "$($r.Name)" } else { '' }
            & $binAdd $b 'svc-persist' "service $svcName" ''
        }
    }
    foreach ($r in (& $rowsOf 'scheduled_tasks_flagged')) { & $binAdd (& $binFromRow $r) 'task-persist' "task $($r.Name) (runas $($r.RunAs)) flags $($r.Flags)" '' }
    foreach ($src in @('autoruns_runkeys', 'asep_sweep')) {
        foreach ($r in (& $rowsOf $src)) { & $binAdd (& $binFromRow $r) 'autorun-persist' "$($r.Location) / $($r.Name)" '' }
    }
    foreach ($r in (& $rowsOf 'sysmon_network')) { & $binAdd (& $binFromRow $r) 'conn' "$($r.DestIp):$($r.DestPort)" "$($r.Time)" }
    foreach ($r in (& $rowsOf 'flash_public_connections')) { & $binAdd (& $binFromRow $r) 'conn' "public $($r.RemoteAddress):$($r.RemotePort)" '' }
    foreach ($r in (& $rowsOf 'beacon_candidates')) { & $binAdd (& $binFromRow $r) 'beacon' "[$($r.Severity)] -> $($r.RemoteIp):$($r.Port) every ~$($r.MedianIntervalSec)s" '' }
    foreach ($r in (& $rowsOf 'dns_beacon_candidates')) { & $binAdd (& $binFromRow $r) 'beacon' "[$($r.Severity)] DNS $($r.Domain) every ~$($r.MedianIntervalSec)s" '' }
    foreach ($r in (& $rowsOf 'srum_usage')) {
        $b = & $binFromRow $r
        if ($b) {
            $bt = (@($r.PSObject.Properties | Where-Object { $_.Name -match '(?i)byte|sent|recv|duration' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ')
            if ($bt) { $b.Bytes = if ($b.Bytes) { "$($b.Bytes); $bt" } else { $bt }
                if ($b.Bytes.Length -gt 300) { $b.Bytes = $b.Bytes.Substring(0, 300) + '...' } }
            & $binAdd $b 'srum-usage' $bt ''
        }
    }
    foreach ($r in (& $rowsOf 'yara_hits')) { & $binAdd (& $binFromRow $r) 'yara' "$($r.Rule)" '' }
    foreach ($r in (& $rowsOf 'loldrivers_hits')) { & $binAdd (& $binFromRow $r) 'loldriver' "$($r.Status)" '' }
    foreach ($r in (& $rowsOf 'mft_recent')) { & $binAdd (& $binFromRow $r) 'mft-created' $r.Created "$($r.Created)" }
    foreach ($r in (& $rowsOf 'ioc_hits_amcache')) { & $binAdd (& $binFromRow $r) 'ioc' "$($r.Indicator) (amcache $($r.SourceFile))" '' }
    foreach ($r in ((& $rowsOf 'hayabusa_timeline') | Where-Object { (Get-LvlRank "$($_.Level)") -ge 3 })) {
        if ("$($r.Details)" -match '(?i)([a-z0-9_\-]+\.(exe|dll|ps1|js|vbs|hta))') { & $binAdd (& $binNew $Matches[1]) 'sigma' "[$($r.Level)] $($r.RuleTitle)" "$($r.Timestamp)" }
    }
    # v2.21 structured telemetry joins: 4688 execution, admin-share staging, IIS anomalies
    foreach ($r in (& $rowsOf 'security_proc_events')) { & $binAdd (& $binFromRow $r) '4688-exec' "child of $($r.ParentProcess)" "$($r.Time)" }
    foreach ($r in (& $rowsOf 'security_share_access')) {
        $tn = "$($r.RelativeTargetName)"
        if ($tn -match '\.(exe|dll|ps1|bat|js|vbs|hta|msi)$') { & $binAdd (& $binNew $tn) 'share-staging' "$("$($r.ShareName)" -replace '^[\*\\\s]+', '') by $($r.Account) from $($r.SourceIp)" '' }
    }
    foreach ($r in (& $rowsOf 'iis_anomalies')) {
        if ("$($r.Sample)" -match '(?i)([a-z]:\\[^\s"|]+\.(exe|dll|ps1|aspx|jsp|ashx))') { & $binAdd (& $binNew $Matches[1]) 'web-anomaly' "[$($r.Kind)] $($r.Detail)" '' }
    }

    # ---------- accounts ----------
    $accts = @{}
    $acctGet = {
        param([string]$name)
        $a2 = ("$name").Trim()
        if (-not $a2 -or $a2 -match '^(-|\$|DWM-|UMFD-)$' -or @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON') -contains $a2) { return $null }
        $lk = $a2.ToLower()
        if (-not $accts.ContainsKey($lk)) {
            $accts[$lk] = [pscustomobject]@{
                Account = $a2; Logons = 0; Failed = 0
                Types = New-Object System.Collections.Generic.List[string]
                Sources = New-Object System.Collections.Generic.List[string]
                RdpTargets = New-Object System.Collections.Generic.List[string]
                ConsoleKB = 0.0; Created = ''
                Evidence = New-Object System.Collections.Generic.List[string]
            }
        }
        return $accts[$lk]
    }
    $acctFromRow = {
        param($r)
        foreach ($pn in @('Account', 'User', 'UserName', 'TargetUserName', 'SubjectUserName', 'RunAs')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { return (& $acctGet $p2.Value) }
        }
        return $null
    }
    $logonTypeNames = @{ 2 = 'interactive'; 3 = 'network'; 4 = 'batch'; 5 = 'service'; 7 = 'unlock'; 8 = 'net-cleartext'; 9 = 'new-creds'; 10 = 'rdp'; 11 = 'cached' }
    foreach ($r in (& $rowsOf 'security_auth_events')) {
        $a2 = & $acctFromRow $r
        if (-not $a2) { continue }
        if ("$($r.EventId)" -eq '4624') {
            $a2.Logons++
            $lt = $null
            try { $lt = [int]"$($r.LogonType)" } catch { }
            $tn = if ($lt -and $logonTypeNames.ContainsKey($lt)) { $logonTypeNames[$lt] } else { '' }
            if ($tn -and $a2.Types -notcontains $tn) { $null = $a2.Types.Add($tn) }
            if ($tn -eq 'rdp') { if ($a2.Evidence.Count -lt 14) { $a2.Evidence.Add("rdp-in logon at $($r.Time)") | Out-Null } }
        }
        if ("$($r.EventId)" -eq '4625') { $a2.Failed++; if ("$($r.SourceIp)" -and -not $a2.Sources.Contains("$($r.SourceIp)")) { $null = $a2.Sources.Add("$($r.SourceIp)") } }
    }
    foreach ($r in (& $rowsOf 'rdp_localsession')) {
        $a2 = & $acctFromRow $r
        if ($a2 -and $a2.Evidence.Count -lt 14 -and -not ($a2.Evidence | Where-Object { $_ -match '^rdp-session' })) { $a2.Evidence.Add("rdp-session: $($r.TimeCreated)") | Out-Null }
    }
    foreach ($r in (& $rowsOf 'rdp_client_targets')) {
        $a2 = & $acctFromRow $r
        if ($a2) {
            if (-not $a2.RdpTargets.Contains("$($r.TargetServer)")) { $null = $a2.RdpTargets.Add("$($r.TargetServer)") }
            $a2.Evidence.Add("rdp-out: $($r.TargetServer) (hint $($r.UsernameHint))") | Out-Null
        }
    }
    foreach ($r in (& $rowsOf 'powershell_console_history')) {
        $a2 = & $acctFromRow $r
        # v2.68: safe casts - one garbage KB cell must not abort entity building (v2.67 B5 class)
        if ($a2) { $a2.ConsoleKB = [math]::Round($a2.ConsoleKB + (ConvertTo-SafeDbl "$($r.KB)"), 1); $a2.Evidence.Add("console history: $($r.KB) KB (raw\useractivity\$($a2.Account))") | Out-Null }
    }
    # v2.21: Kerberos + directory-service + session-attributed activity evidence
    foreach ($r in (& $rowsOf 'security_kerberos')) {
        $a2 = & $acctFromRow $r
        if (-not $a2 -or $a2.Evidence.Count -ge 14) { continue }
        if ("$($r.EventId)" -eq '4769') { $null = $a2.Evidence.Add("kerberos TGS for $($r.Service) from $($r.IpAddress) (enc $($r.TicketEnc))") }
        elseif ("$($r.EventId)" -eq '4771') { $null = $a2.Evidence.Add("kerberos pre-auth FAILED from $($r.IpAddress)") }
    }
    foreach ($r in (& $rowsOf 'security_ds_access')) {
        $a2 = & $acctFromRow $r
        if ($a2 -and $a2.Evidence.Count -lt 14 -and "$($r.Properties)" -match '(?i)e3514235|1131f6a') { $null = $a2.Evidence.Add("directory replication access (4662 Get-Changes) on $($r.Object)") }
    }
    foreach ($r in (& $rowsOf 'session_activity')) {
        $pn = $r.PSObject.Properties['SessionAccount']
        if (-not $pn -or -not "$($pn.Value)") { continue }
        $a2 = & $acctGet "$($pn.Value)"
        if ($a2 -and $a2.Evidence.Count -lt 14) { $null = $a2.Evidence.Add("session activity [$($r.Activity)]: $($r.Detail)$(if ("$($r.SourceIp)") { " from $($r.SourceIp)" })") }
    }

    # ---------- remote endpoints ----------
    $rem = @{}
    $remGet = {
        param([string]$ip)
        $k = ("$ip").Trim().ToLower()
        if (-not $k) { return $null }
        if (-not $rem.ContainsKey($k)) {
            $rem[$k] = [pscustomobject]@{
                Remote = "$ip"; Public = (Test-IsPublicIp $ip); Conns = 0
                Talkers = New-Object System.Collections.Generic.List[string]
                Beacon = ''; Brute = 0; RdpOut = 0
                Evidence = New-Object System.Collections.Generic.List[string]
            }
        }
        return $rem[$k]
    }
    foreach ($r in (& $rowsOf 'sysmon_network')) {
        $e = & $remGet $r.DestIp
        if ($e) {
            $e.Conns++
            if ("$($r.Image)") { $leaf = Split-Path "$($r.Image)" -Leaf; if ($leaf -and -not $e.Talkers.Contains($leaf)) { $null = $e.Talkers.Add($leaf) } }
        }
    }
    foreach ($r in (& $rowsOf 'flash_public_connections')) {
        $e = & $remGet $r.RemoteAddress
        if ($e) {
            $e.Conns++
            if ("$($r.ProcessPath)") { $leaf = Split-Path "$($r.ProcessPath)" -Leaf; if ($leaf -and -not $e.Talkers.Contains($leaf)) { $null = $e.Talkers.Add($leaf) } }
        }
    }
    foreach ($r in (& $rowsOf 'beacon_candidates')) { $e = & $remGet $r.RemoteIp; if ($e) { $e.Beacon = "$($r.Severity)"; $e.Evidence.Add("beacon $($r.Severity) from $($r.Process)") | Out-Null } }
    foreach ($r in (& $rowsOf 'dns_beacon_candidates')) { $e = & $remGet $r.ResolvedIp; if ($e) { if (-not $e.Beacon) { $e.Beacon = "$($r.Severity)" }; $e.Evidence.Add("dns-beacon $($r.Severity) for $($r.Domain)") | Out-Null } }
    foreach ($r in (& $rowsOf 'security_bruteforce_candidates')) { $e = & $remGet $r.SourceIp; if ($e) { $e.Brute = ConvertTo-SafeInt "$($r.FailedLogons)"; $e.Evidence.Add("brute-force: $($r.FailedLogons) failed logons") | Out-Null } } # v2.68: safe cast (B5 class)
    foreach ($r in (& $rowsOf 'rdp_client_targets')) { $e = & $remGet $r.TargetServer; if ($e) { $e.RdpOut++; $e.Evidence.Add("rdp-out target (hint $($r.UsernameHint))") | Out-Null } }

    foreach ($r in (& $rowsOf 'hunt_findings')) {
        $ent = "$($r.Entity)"
        $b = $null
        if ($ent -match '^[a-z]:\\') { $b = & $binNew $ent } else { $b = & $binFromRow $r }
        if ($b) { & $binAdd $b 'hunt' "[$($r.Severity)] $($r.Rule): $($r.Evidence)" '' }
    }

    # ---------- emit ----------
    if ($env:OPHIRA_DBG_ENT) { foreach ($kv in $binsByPath.GetEnumerator()) { Write-Host ("DBG bin: {0} -> [{1}]" -f $kv.Key, ($kv.Value.Cats -join ",")) } }
    if ($env:OPHIRA_DBG_ENT) { foreach ($a2 in $accts.Values) { Write-Host ("DBG acct: {0} logons={1} failed={2}" -f $a2.Account, $a2.Logons, $a2.Failed) } }
    $binRows = @($binsByPath.Values | ForEach-Object {
        [pscustomobject]@{
            Categories = ($_.Cats -join ';'); CatCount = $_.Cats.Count; Name = $_.Name; Path = $_.Path
            Verdict = $_.Verdict; Signer = $_.Signer; FirstSeen = $_.FirstSeen; LastSeen = $_.LastSeen
            Hashes = (($_.Hashes | Select-Object -Unique | Select-Object -First 4) -join ';'); Bytes = $_.Bytes
            Evidence = ($_.Evidence -join ' | ')
        }
    } | Sort-Object @{e = 'CatCount'; Descending = $true }, @{e = { if ("$($_.Verdict)" -match 'HIGH') { 2 } elseif ("$($_.Verdict)" -match 'MEDIUM') { 1 } else { 0 } }; Descending = $true })
    Save-Rows -Name 'entities_binaries' -Rows $binRows

    $acctRows = @($accts.Values | ForEach-Object {
        $ev = ($_.Evidence | Select-Object -Unique | Select-Object -First 12) -join ' | '
        [pscustomobject]@{
            Account = $_.Account; Logons = $_.Logons; Failed = $_.Failed; LogonTypes = ($_.Types -join ';')
            Sources = ($_.Sources | Select-Object -Unique) -join ';'; RdpOutTargets = ($_.RdpTargets | Select-Object -Unique) -join ';'
            ConsoleHistoryKB = $_.ConsoleKB; Evidence = $ev
        }
    } | Sort-Object @{e = 'Failed'; Descending = $true }, @{e = 'Logons'; Descending = $true })
    Save-Rows -Name 'entities_accounts' -Rows $acctRows

    $remRows = @($rem.Values | ForEach-Object {
        [pscustomobject]@{
            Remote = $_.Remote; Public = $_.Public; Connections = $_.Conns
            Talkers = (($_.Talkers | Select-Object -Unique | Select-Object -First 6) -join ';')
            Beacon = $_.Beacon; FailedLogons = $_.Brute; RdpOutCount = $_.RdpOut
            Evidence = (($_.Evidence | Select-Object -Unique | Select-Object -First 10) -join ' | ')
        }
    } | Sort-Object @{e = 'Beacon'; Descending = $true }, @{e = 'FailedLogons'; Descending = $true }, @{e = 'Connections'; Descending = $true })
    Save-Rows -Name 'entities_remotes' -Rows $remRows

    $multi = @($binRows | Where-Object { $_.CatCount -ge 2 }).Count
    Write-CaseLog "    entity correlation: $($binRows.Count) binaries ($multi multi-source), $($acctRows.Count) accounts, $($remRows.Count) remotes -> csv\entities_*.csv" 'DarkGray'
}

function New-SessionAttribution {
    # v2.21: join 4624 logon sessions (LogonId -> account/source IP/logon type) to 4688/5140/5145
    # SubjectLogonId - attributes process creations and share writes to the human session that made them.
    $sess = @{}
    foreach ($r in ((Import-CaseCsv 'security_auth_events') | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonId)" })) {
        $sess["$($r.LogonId)"] = $r
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $s = $sess["$($r.LogonId)"]
        if (-not $s) { continue }
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + '...' }
        $null = $out.Add([pscustomobject]@{ Time = $r.Time; SessionAccount = "$($s.Account)"; SourceIp = "$($s.SourceIp)"; LogonType = "$($s.LogonType)"; Activity = 'process'; Detail = "$($r.NewProcess) $cmd".Trim() })
    }
    foreach ($r in (Import-CaseCsv 'security_share_access')) {
        $s = $sess["$($r.LogonId)"]
        if (-not $s) { continue }
        $sh = "$($r.ShareName)" -replace '^[\*\\\s]+', ''
        $srcIp = "$($r.SourceIp)"
        if (-not $srcIp -or $srcIp -eq '-') { $srcIp = "$($s.SourceIp)" }
        $null = $out.Add([pscustomobject]@{ Time = $r.Time; SessionAccount = "$($s.Account)"; SourceIp = $srcIp; LogonType = "$($s.LogonType)"; Activity = 'share'; Detail = "$sh -> $($r.RelativeTargetName)" })
    }
    $rows = @($out.ToArray() | Sort-Object Time)
    Save-Rows -Name 'session_activity' -Rows $rows
    $n = $rows.Count
    if ($n -gt 0) {
        Write-CaseLog "    session attribution: $n activity row(s) joined to logon sessions (4624 LogonId x 4688/5145) -> csv\session_activity.csv" 'Gray'
    } else {
        Write-CaseLog "    session attribution: no joins (4624 without LogonId in this case, or no 4688/5145 activity)" 'DarkGray'
    }
}

function New-ProcessChains {
    # v2.21: reconstruct parent->child ancestry for flagged processes from 4688 lineage + live PPID map.
    # Chains answer "how did this get here": explorer.exe -> winword.exe -> powershell.exe -> beacon.exe.
    $edges = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $c = ''; $p = ''
        try { $c = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        try { $p = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        if (-not $c -or -not $p -or $c -eq $p) { continue }
        if (-not $edges.ContainsKey($c)) { $edges[$c] = New-Object System.Collections.Generic.List[object] }
        $null = $edges[$c].Add([pscustomobject]@{ Parent = $p; ParentPath = "$($r.ParentProcess)"; Time = "$($r.Time)"; Cmd = "$($r.CommandLine)"; Src = '4688' })
    }
    $pidMap = @{}
    $live = @(Import-CaseCsv 'processes')
    foreach ($r in $live) { if ("$($r.PID)") { $pidMap["$($r.PID)"] = $r } }
    foreach ($r in $live) {
        $c = ''
        try { $c = (Split-Path "$($r.Path)" -Leaf).ToLower() } catch { }
        if (-not $c -or -not "$($r.PPID)" -or -not $pidMap.ContainsKey("$($r.PPID)")) { continue }
        $par = $pidMap["$($r.PPID)"]
        $p = ''
        try { $p = (Split-Path "$($par.Path)" -Leaf).ToLower() } catch { }
        if (-not $p -or $c -eq $p) { continue }
        if (-not $edges.ContainsKey($c)) { $edges[$c] = New-Object System.Collections.Generic.List[object] }
        $null = $edges[$c].Add([pscustomobject]@{ Parent = $p; ParentPath = "$($par.Path)"; Time = ''; Cmd = "$($par.Path)"; Src = 'live' })
    }
    if ($edges.Count -eq 0) { Write-CaseLog '    process lineage: no parent-child edges (4688 off, no live map)' 'DarkGray'; return }

    $flagged = New-Object System.Collections.Generic.List[string]
    foreach ($r in ((Import-CaseCsv 'flash_process_scored') | Where-Object { "$($_.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($_.Path)" })) {
        $null = $flagged.Add("$($r.Path)")
    }
    foreach ($r in ((Import-CaseCsv 'hunt_findings') | Where-Object { "$($_.Severity)" -eq 'high' })) {
        $e = "$($r.Entity)"
        if ($e -match '^[a-z]:\\' -or $e -match '\.(exe|dll|ps1|bat|js|vbs)$') { $null = $flagged.Add($e) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    $seenChains = @{}
    foreach ($f in (@($flagged | Select-Object -Unique) | Select-Object -First 40)) {
        $leaf = ''
        try { $leaf = (Split-Path $f -Leaf).ToLower() } catch { }
        if (-not $leaf -or -not $edges.ContainsKey($leaf)) { continue }
        # walk ancestors, widest evidence per hop, cap depth 8
        $steps = New-Object System.Collections.Generic.List[string]
        $notes = New-Object System.Collections.Generic.List[string]
        $cur = $leaf
        $depth = 0
        $visited = @{}
        while ($edges.ContainsKey($cur) -and $depth -lt 8) {
            if ($visited.ContainsKey($cur)) { break }
            $visited[$cur] = $true
            $e = $edges[$cur][0]
            $null = $steps.Insert(0, $e.Parent)
            if ("$($e.Cmd)" -or "$($e.Time)") { $null = $notes.Insert(0, "$($e.Parent): $(if ("$($e.Cmd)") { "$($e.Cmd)" } else { '?' })$(if ("$($e.Time)") { " @ $($e.Time)" })") }
            $cur = $e.Parent
            $depth++
        }
        $null = $steps.Add($leaf)
        $chain = $steps -join ' -> '
        if ($steps.Count -lt 2 -or $seenChains.ContainsKey($chain)) { continue }
        $seenChains[$chain] = $true
        $null = $out.Add([pscustomobject]@{ Entity = $f; Steps = $steps.Count; Chain = $chain; Evidence = (($notes | Select-Object -First 8) -join ' | ') })
    }
    Save-Rows -Name 'process_chains' -Rows $out.ToArray()
    if ($out.Count -gt 0) {
        Write-CaseLog "    process lineage: $($out.Count) ancestry chain(s) for flagged binaries -> csv\process_chains.csv" 'Gray'
    } else {
        Write-CaseLog '    process lineage: flagged binaries have no parent edges in this case' 'DarkGray'
    }
}

function New-ShimcacheExec {
    # v2.83 (R44): Win10+ shimcache entries carry a 4-byte executed flag as the last bytes of
    # the record blob (01 00 00 00 = executed). Zimmerman/13Cubed caveats kept honest: only
    # non-native binaries are tracked on Win10+, a right-click context-menu open can set the
    # flag WITHOUT execution, and flag=0 is NOT proof of non-execution - this is a confidence
    # column, never a verdict weight.
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Import-CaseCsv 'execution_timeline')) {
        if ("$($r.'Entry Type')" -ne 'ShimcacheFileEntry') { continue }
        $raw = "$($r.'Raw Entry')"
        if (-not $raw -or $raw.Length -lt 8) { continue }
        try {
            $j = $raw | ConvertFrom-Json
            $path = ''
            if ($j.entry_type -and $j.entry_type.File) { $path = "$($j.entry_type.File.path)" }
            if (-not $path) { continue }
            $exec = ''
            $p2 = $j.PSObject.Properties['executed']
            if ($p2 -and $null -ne $p2.Value) { $exec = if ($p2.Value) { 'yes' } else { 'no' } }
            $data = $j.data
            if (-not $exec -and $data) {
                $b = @($data)
                if ($b.Count -ge 4) {
                    $n = $b.Count
                    $v = $b[$n - 4] + $b[$n - 3] * 256 + $b[$n - 2] * 65536 + $b[$n - 1] * 16777216
                    if ($v -eq 1) { $exec = 'yes' } elseif ($v -eq 0) { $exec = 'no' }
                }
            }
            $null = $out.Add([pscustomobject]@{
                Path = $path
                LastModified = "$($j.last_modified_ts)"
                Executed = $exec
                ControlSet = "$($j.controlset)"
                CachePosition = "$($j.cache_entry_position)"
                Signature = "$($j.signature)"
            })
        } catch { }
    }
    Save-Rows -Name 'shimcache_exec' -Rows $out.ToArray()
    $yes = @($out | Where-Object { $_.Executed -eq 'yes' }).Count
    $no = @($out | Where-Object { $_.Executed -eq 'no' }).Count
    Write-CaseLog "    shimcache exec flags: $($out.Count) Win10+ entries ($yes executed-flag, $no not-executed-flag) -> csv\shimcache_exec.csv" 'DarkGray'
}

function New-ConnectionDns {
    # v2.82: attribute public connections to hostnames via the collected DNS cache
    # (dns_cache.csv Entry/Data/Type). Walks CNAME chains alias -> target -> A record so an
    # IP shows the real domain plus the alias path; the leftmost name is what the process
    # actually queried. Rows keep ResolvedDomain empty when the cache holds nothing for the
    # IP (TTLs expire fast - absence is normal, Sysmon EID22 would be the complete source).
    # Derived csv - rebuilt on every regen, feeds the report network table + the lead builder.
    $pub = @(Import-CaseCsv 'flash_public_connections')
    foreach ($c2 in (Import-CaseCsv 'connections_public_established')) {
        $k2 = "$($c2.RemoteAddress)|$($c2.RemotePort)|$($c2.PID)|$($c2.ProcessPath)"
        if (-not (@($pub | Where-Object { "$($_.RemoteAddress)|$($_.RemotePort)|$($_.PID)|$($_.ProcessPath)" -eq $k2 }).Count)) { $pub += $c2 }
    }
    if ($pub.Count -eq 0) { Write-CaseLog '    connection attribution: no public connections in this case' 'DarkGray'; return }
    $dns = @(Import-CaseCsv 'dns_cache')
    $aByIp = @{}; $aliasOf = @{}
    foreach ($r in $dns) {
        $t = "$($r.Type)".Trim().ToUpper()
        if ($t -eq '1') { $t = 'A' } elseif ($t -eq '5') { $t = 'CNAME' } elseif ($t -eq '28') { $t = 'AAAA' }
        $e = ("$($r.Entry)" -replace '\\.$', '').Trim()
        $d = ("$($r.Data)" -replace '\\.$', '').Trim()
        if (-not $e -or -not $d) { continue }
        if ($t -eq 'A' -or $t -eq 'AAAA') { if (-not $aByIp.ContainsKey($d)) { $aByIp[$d] = $e } }
        elseif ($t -eq 'CNAME') { if (-not $aliasOf.ContainsKey($d)) { $aliasOf[$d] = $e } }
    }
    $byIp = @{}
    foreach ($ip in @($aByIp.Keys)) {
        $host1 = $aByIp[$ip]
        $chain = New-Object System.Collections.Generic.List[string]
        $chain.Add($host1)
        # the A owner is the chain's END; the name the process queried sits UPSTREAM
        # (target side of CNAME rows) - walk aliases backwards, leftmost = original query
        $cur = $host1; $hops = 0
        while ($aliasOf.ContainsKey($cur) -and $hops -lt 5) {
            $cur = $aliasOf[$cur]
            $chain.Insert(0, $cur)
            $hops++
        }
        $prov = ''
        foreach ($cn in $chain) { $prov = Get-DomainProvider $cn; if ($prov) { break } }
        $byIp[$ip] = @{ Domain = $chain[0]; Chain = (@($chain) + $ip) -join ' -> '; DomainProvider = $prov }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $pub) {
        $ip = "$($c.RemoteAddress)"; if (-not $ip) { continue }
        $att = $byIp[$ip]
        $prov = Get-IpCloudClass $ip
        $chainTxt = ''
        if ($att) {
            $chainTxt = "$($att.Chain)"
            if (-not $prov) { $prov = "$($att.DomainProvider)" }
        }
        if (-not $prov) { $prov = 'unknown' }
        $pn = try { if ("$($c.ProcessPath)") { Split-Path "$($c.ProcessPath)" -Leaf } else { '' } } catch { '' }
        if (-not $pn) { $pn = "PID $($c.PID)" }
        $null = $rows.Add([pscustomobject]@{
            Process = $pn; PID = "$($c.PID)"; RemoteAddress = $ip; RemotePort = "$($c.RemotePort)"; State = "$($c.State)"
            ResolvedDomain = $(if ($att) { "$($att.Domain)" } else { '' })
            DnsChain = $chainTxt
            Provider = $prov
        })
    }
    Save-Rows -Name 'connections_dns' -Rows $rows.ToArray()
    $nDom = @($rows | Where-Object { "$($_.ResolvedDomain)" }).Count
    Write-CaseLog "    connection attribution: $($rows.Count) public connection(s), $nDom resolved via DNS cache (CNAME chains walked) -> csv\connections_dns.csv" 'Gray'
}

function New-IocHits {
    # v2.26: xref the structured case telemetry against the IOC feeds (iocs.txt + tools\iocs\).
    # Historical DNS queries + network connections + $MFT dropped-filename exact matches.
    $iocs = Get-IocList
    if (-not $iocs) { return }
    $feedOf = { param($k) $f = $iocs.Feed[$k]; if ($f) { $f } else { 'iocs.txt' } }
    $dns = @()
    foreach ($r in (Import-CaseCsv 'sysmon_dns')) {
        $q = "$($r.QueryName)".ToLower()
        if (-not $q) { continue }
        foreach ($k in $iocs.Domains.Keys) {
            if ($q -eq $k -or $q.EndsWith(".$k")) {
                $dns += [pscustomobject]@{ Indicator = $k; Feed = (& $feedOf $k); Query = $q; Process = "$($r.Image)"; Resolved = "$($r.QueryResults)"; Match = 'dns-query' }
                break
            }
        }
    }
    Save-Rows -Name 'ioc_hits_dns' -Rows $dns
    if (@($dns).Count -gt 0) { Write-CaseLog "    DNS IOC HITS: $(@($dns).Count) query/queries to known-bad domain(s) -> csv\ioc_hits_dns.csv" 'Red' }
    $net = @()
    foreach ($r in (Import-CaseCsv 'sysmon_network')) {
        $ip = "$($r.DestIp)"
        if (-not $ip -or -not $iocs.Ips.ContainsKey($ip)) { continue }
        $net += [pscustomobject]@{ Indicator = $ip; Feed = (& $feedOf $ip); RemoteIp = $ip; Port = "$($r.DestPort)"; Process = "$($r.Image)"; Match = 'network-connection' }
    }
    Save-Rows -Name 'ioc_hits_network' -Rows $net
    if (@($net).Count -gt 0) { Write-CaseLog "    NETWORK IOC HITS: $(@($net).Count) connection(s) to known-bad IP(s) -> csv\ioc_hits_network.csv" 'Red' }
    $mft = @()
    if ($iocs.Names.Count -gt 0) {
        foreach ($r in (Import-CaseCsv 'mft_recent')) {
            $nm = "$($r.Name)".ToLower()
            if (-not $nm -or -not $iocs.Names.ContainsKey($nm)) { continue }
            $mft += [pscustomobject]@{ Indicator = $nm; Feed = (& $feedOf $nm); Path = "$($r.Path)"; Created = "$($r.Created)"; Match = 'mft-filename' }
        }
    }
    Save-Rows -Name 'ioc_hits_mft' -Rows $mft
    if (@($mft).Count -gt 0) { Write-CaseLog "    FILENAME IOC HITS: $($mft.Count) known-bad filename(s) on disk -> csv\ioc_hits_mft.csv" 'Red' }
    # v2.49: feed hashes x execution history (process_hashes) - a hash from a previous case
    # (ioc_export feedback loop) or an external feed hits any host where that exact binary
    # ever executed, even if the file is gone
    $hh = @()
    if ($iocs.Hashes.Count -gt 0) {
        foreach ($r in (Import-CaseCsv 'process_hashes')) {
            $hit = ''
            foreach ($hn in @('SHA256', 'SHA1', 'MD5')) {
                $p2 = $r.PSObject.Properties[$hn]
                if ($p2 -and "$($p2.Value)") {
                    $hv = "$($p2.Value)".ToUpper()
                    if ($iocs.Hashes.ContainsKey($hv)) { $hit = $hv; break }
                }
            }
            if (-not $hit) { continue }
            $hh += [pscustomobject]@{ Indicator = $hit; Feed = (& $feedOf $hit); Path = "$($r.Path)"; Process = "$($r.Name)"; Hash = $hit; Match = 'execution-hash' }
        }
    }
    Save-Rows -Name 'ioc_hits_hash' -Rows $hh
    if (@($hh).Count -gt 0) { Write-CaseLog "    HASH IOC HITS: $($hh.Count) known-bad binary hash(es) in execution history -> csv\ioc_hits_hash.csv" 'Red' }
}

function New-CaseIocExport {
    # v2.49: case -> fleet memory. High-confidence case indicators exported in the exact
    # tools\iocs feed dialect, so dropping raw\analysis\ioc_export.txt into tools\iocs\
    # arms every future collection with what this case found. Conservative on purpose -
    # fleet-feed material only: HIGH process verdicts (hash via process_hashes), YARA-hit
    # binaries, high-severity beacons. Medium rows are leads, not feed material.
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $feeds = $null
    try { $feeds = Get-IocList } catch { }
    $add = {
        param([string]$kind, [string]$value, [string]$why, [string]$detail)
        $v = "$value".Trim()
        if (-not $v) { return }
        if ($kind -eq 'domain') { $v = $v.ToLower() }
        if ($feeds) {
            if ($kind -eq 'sha256' -and $feeds.Hashes.ContainsKey($v.ToUpper())) { return }
            if ($kind -eq 'ip' -and $feeds.Ips.ContainsKey($v)) { return }
            if ($kind -eq 'domain' -and $feeds.Domains.ContainsKey($v)) { return }
        }
        $key = "$kind|$($v.ToLower())"
        if (-not $seen.Add($key)) { return }
        $null = $out.Add([pscustomobject]@{ Kind = $kind; Value = $v; Source = $why; Detail = $detail })
    }
    $hashByPath = @{}
    foreach ($r in (Import-CaseCsv 'process_hashes')) {
        $p = "$($r.Path)".ToLower()
        $h5 = "$($r.SHA256)".ToUpper()
        if ($p -and $h5 -and -not $hashByPath[$p]) { $hashByPath[$p] = $h5 }
    }
    foreach ($r in (Import-CaseCsv 'flash_process_scored')) {
        if ("$($r.Verdict)" -ne 'HIGH') { continue }
        $hash = $hashByPath["$($r.Path)".ToLower()]
        if ($hash) { & $add 'sha256' $hash 'HIGH process verdict' "$($r.Name) @ $($r.Path)" }
    }
    foreach ($r in (Import-CaseCsv 'yara_hits')) {
        $hash = $hashByPath["$($r.Binary)".ToLower()]
        if ($hash) { & $add 'sha256' $hash "YARA $($r.Rule)" "$($r.Detail)" }
    }
    foreach ($r in (Import-CaseCsv 'beacon_candidates')) {
        if ("$($r.Severity)" -ne 'high' -or -not "$($r.RemoteIp)") { continue }
        & $add 'ip' "$($r.RemoteIp)" 'high C2 beacon' "$($r.Process) port $($r.Port), ~$($r.MedianIntervalSec)s interval"
    }
    foreach ($r in (Import-CaseCsv 'dns_beacon_candidates')) {
        if ("$($r.Severity)" -ne 'high' -or -not "$($r.Domain)") { continue }
        & $add 'domain' "$($r.Domain)" 'high DNS beacon' "$($r.Process), ~$($r.MedianIntervalSec)s interval"
    }
    Save-Rows -Name 'ioc_export' -Rows $out.ToArray()
    if ($out.Count -gt 0) {
        $an = Join-Path $RawDir 'analysis'
        New-Item -ItemType Directory -Path $an -Force | Out-Null
        $txt = New-Object System.Collections.Generic.List[string]
        $null = $txt.Add("# case IOC export ($Computer / $($script:CurrentCaseID)) - copy into tools\iocs\ (or merge into iocs.txt) to arm future collections")
        foreach ($r in $out) { $null = $txt.Add("$($r.Value) # $($r.Kind) - $($r.Source): $($r.Detail)") }
        Set-Content -LiteralPath (Join-Path $an 'ioc_export.txt') -Value $txt.ToArray() -Encoding UTF8
        # v2.51: STIX 2.1 bundle - the same indicators in the team-tool dialect (MISP/OpenCTI)
        try {
            $objects = New-Object System.Collections.Generic.List[object]
            $created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            foreach ($r in $out) {
                $pat = ''
                if ($r.Kind -eq 'sha256') { $pat = "[file:hashes.'SHA-256' = '$($r.Value)']" }
                elseif ($r.Kind -eq 'ip') { $pat = "[ipv4-addr:value = '$($r.Value)']" }
                else { $pat = "[domain-name:value = '$($r.Value)']" }
                $null = $objects.Add([ordered]@{
                    type = 'indicator'; spec_version = '2.1'; id = "indicator--$([guid]::NewGuid())"
                    created = $created; modified = $created
                    name = "Ophira $($r.Kind) - $($r.Source)"
                    description = "$($r.Source): $($r.Detail) (case $($script:CurrentCaseID) / $Computer)"
                    labels = @('malicious-activity'); pattern = $pat; pattern_type = 'stix'; valid_from = $created
                })
            }
            $bundle = [ordered]@{ type = 'bundle'; id = "bundle--$([guid]::NewGuid())"; objects = $objects.ToArray() }
            $bundle | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $an 'ioc_export_stix.json') -Encoding UTF8
            Write-CaseLog "      STIX 2.1 bundle -> raw\analysis\ioc_export_stix.json (import into MISP/OpenCTI)" 'Gray'
        } catch { }
        Write-CaseLog "    case IOC export: $($out.Count) indicator(s) -> csv\ioc_export.csv + raw\analysis\ioc_export.txt" 'Yellow'
        Write-CaseLog "      fleet memory: copy ioc_export.txt into tools\iocs\ on your analyst machine - future collections xref it" 'Gray'
    }
}

function New-HuntFindings {
    # Hunt techniques ported from Velociraptor-style detection logic + APT TTPs.
    # Findings feed the report, entity correlation and (R1-R4) the verdict.
    $out = New-Object System.Collections.Generic.List[object]
    $find = {
        param([string]$rule, [string]$sev, [string]$entity, [string]$evidence, [string]$attack)
        $null = $out.Add([pscustomobject]@{ Found = (Get-Date).ToUniversalTime().ToString('o'); Rule = $rule; Severity = $sev; Entity = $entity; Attck = $attack; Evidence = $evidence })
    }

    # v2.79 trace: one line per rule - inputs in / findings out - plus the gate decision on
    # skipped rules. The case log ALWAYS carries these; the console shows them at -LogLevel
    # Verbose only (36 lines per hunt run is too chatty for Normal). Written straight to the
    # log on the quiet path instead of Write-CaseLog -NoConsole: harnesses stub Write-CaseLog
    # without that switch. Controller-side only (Invoke-RegenerateOutputs), so $CaseLog exists.
    # Placement hazard: call $trace LAST in each rule block - a $find placed after a rule's
    # $trace rolls its findings into the NEXT rule's count (the 34-block test cannot catch it).
    $trState = @{ Base = 0 }
    $trace = {
        param([string]$Id, [string]$Label, [string]$Inputs)
        $tN = $out.Count - $trState.Base
        $tSev = ''
        if ($tN -gt 0) {
            $tSev = ' (' + ((@($out.GetRange($trState.Base, $tN) | Group-Object Severity | Sort-Object Name) | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ') + ')'
        }
        $trState.Base = $out.Count
        $tMsg = "$Id $Label`: $Inputs -> $tN finding$(if ($tN -eq 1) { '' } else { 's' })$tSev"
        if ($script:Verbosity -ge 2) { Write-CaseLog $tMsg 'DarkGray' }
        else { try { Add-Content -LiteralPath $CaseLog -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $tMsg) -Encoding UTF8 } catch { } }
    }

    # ---------- R1: renamed LOLBin (version-info identity vs filename, BinaryRename port) ----------
    $lolBins = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wmic.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'net.exe', 'net1.exe', 'netsh.exe', 'wevtutil.exe', 'psexec.exe', 'psexec64.exe', 'msiexec.exe', 'installutil.exe', 'schtasks.exe', 'curl.exe', 'wget.exe', '7z.exe', 'winrar.exe')
    $r1Seen = @{}
    $r1In = @((Import-CaseCsv 'processes') | Select-Object -First 400)
    foreach ($r in $r1In) {
        $p = "$($r.Path)"
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
        $leaf = $null
        try { $leaf = (Split-Path $p -Leaf).ToLower() } catch { continue }
        if (-not $leaf -or $r1Seen.ContainsKey($p.ToLower())) { continue }
        $r1Seen[$p.ToLower()] = $true
        $vi = $null
        try { $vi = (Get-Item -LiteralPath $p -ErrorAction Stop).VersionInfo } catch { continue }
        $internal = "$($vi.InternalName)"; $original = "$($vi.OriginalFilename)"
        $identities = @($internal, $original) | Where-Object { $_ } | ForEach-Object { (($_ -replace '\.mui$', '') -replace '\.exe$', '').ToLower().Trim() }
        $idHit = @($identities | Where-Object { $lolBins -contains ($_ + '.exe') })
        if ($idHit.Count -gt 0 -and ($leaf -replace '\.exe$', '') -ne $idHit[0]) {
            & $find 'Renamed LOLBin (version-info mismatch)' 'high' $p "file '$leaf' but embedded identity '$($idHit[0])' (internal=$internal; original=$original)" 'T1036.003'
        }
    }
    & $trace 'R1' 'renamed LOLBin (live)' "processes (first 400): $($r1In.Count) rows"

    # ---------- R1b: renamed LOLBin at rest - Sysmon EID1 OriginalFileName vs executed Image name ----------
    # catches copies that already exited (live R1 only sees running processes); winupd.exe-class
    $r1bSeen = @{}
    $r1bIn = @(Import-CaseCsv 'sysmon_proc_create')
    foreach ($r in $r1bIn) {
        $orig = "$($r.OriginalFileName)".ToLower().Trim()
        if (-not $orig) { continue }
        $img = "$($r.Image)"
        $leaf = ''
        try { $leaf = (Split-Path $img -Leaf).ToLower() } catch { continue }
        if (-not $leaf) { continue }
        $origBase = $orig -replace '\.exe$', ''
        $leafBase = $leaf -replace '\.exe$', ''
        if ($lolBins -notcontains "$origBase.exe" -or $leafBase -eq $origBase) { continue }
        $key = "$leaf|$origBase"
        if ($r1bSeen.ContainsKey($key)) { continue }
        $r1bSeen[$key] = $true
        $cmd = "$($r.CommandLine)"
        if ($cmd.Length -gt 120) { $cmd = $cmd.Substring(0, 120) + '...' }
        & $find 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'high' $img "executed as '$leaf' but embedded identity '$origBase'$(if ($cmd) { " | cmd: $cmd" })" 'T1036.003'
    }
    & $trace 'R1b' 'renamed LOLBin at rest' "sysmon_proc_create: $($r1bIn.Count) rows"

    # ---------- R2: DLL side-load live - proxy DLL loaded from user-writable path (Sysmon EID 7) ----------
    $proxyDlls = @('version.dll', 'winmm.dll', 'dbghelp.dll', 'd3d9.dll', 'd3d10.dll', 'd3d11.dll', 'dxgi.dll', 'cryptsp.dll', 'winhttp.dll', 'ualapi.dll', 'wlanapi.dll', 'wbemcomn.dll', 'actxprxy.dll', 'msdtcprx.dll', 'tspkg.dll', 'ntlmshared.dll', 'mfc42.dll', 'msvcp60.dll')
    $r2In = @(Import-CaseCsv 'sysmon_image_load')
    foreach ($r in $r2In) {
        $dll = "$($r.Dll)"
        if (-not $dll) { continue }
        $leaf = ''
        try { $leaf = (Split-Path $dll -Leaf).ToLower() } catch { continue }
        if (-not $leaf) { continue }
        if ($proxyDlls -contains $leaf -and (Test-IsUserWritablePath $dll)) {
            & $find 'DLL side-load - proxy DLL in user-writable path' 'high' $dll "loaded by $($r.Process) (signed=$($r.Signed); sig=$($r.Signature))" 'T1574.002'
        } elseif ($proxyDlls -contains $leaf -and "$($r.Signed)" -eq 'false' -and $dll -notmatch '(?i)\\windows\\') {
            & $find 'DLL side-load - unsigned proxy DLL outside Windows' 'medium' $dll "loaded by $($r.Process) from $dll" 'T1574.002'
        }
    }
    & $trace 'R2' 'DLL side-load (live)' "sysmon_image_load: $($r2In.Count) rows"

    # ---------- R3: same proxy-DLL/binary name in system dir AND user dir (static side-load) ----------
    $namePaths = @{}
    $r3In = 0
    foreach ($src in @('amcache', 'mft_recent', 'sysmon_image_load')) {
        $r3Rows = @(Import-CaseCsv $src); $r3In += $r3Rows.Count
        foreach ($r in $r3Rows) {
            $p = $null
            if ($src -eq 'sysmon_image_load') { $p = "$($r.Dll)" } else {
                foreach ($pn in @('Path', 'Name')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)" -match '\.(dll|exe)$') { $p = "$($p2.Value)"; break } }
            }
            if (-not $p) { continue }
            $leaf = ''
            try { $leaf = (Split-Path $p -Leaf).ToLower() } catch { continue }
            if (-not $leaf -or $proxyDlls -notcontains $leaf) { continue }
            if (-not $namePaths.ContainsKey($leaf)) { $namePaths[$leaf] = New-Object System.Collections.Generic.List[string] }
            $null = $namePaths[$leaf].Add($p)
        }
    }
    foreach ($kv in $namePaths.GetEnumerator()) {
        # v2.80 (F8): drive-agnostic - the C:-only form missed multi-boot/D: system dirs
        $inSys = @($kv.Value | Where-Object { $_ -match '(?i)^[a-z]:\\windows\\(system32|syswow64|sysnative)\\' })
        $inUser = @($kv.Value | Where-Object { Test-IsUserWritablePath $_ })
        if ($inSys.Count -gt 0 -and $inUser.Count -gt 0) {
            & $find 'DLL side-load - planted system DLL name in user path' 'high' $kv.Key "system: $($inSys[0]) | user: $($inUser[0])$(if ($inUser.Count -gt 1) { ' (+' + ($inUser.Count - 1) + ' more)' })" 'T1574.002'
        }
    }
    & $trace 'R3' 'DLL side-load (static, system+user dirs)' "amcache+mft_recent+sysmon_image_load: $r3In rows"

    # ---------- R4: downloaded then executed (v2.76 precision rework) ----------
    # v2.76: match execution evidence by normalized FULL path (parent+leaf); the leaf-only key
    # remains solely for the fallback that fires when the download row carries no directory
    # (bare filename or URL). Leaf matching a full-path download produced false leads whenever
    # an unrelated binary elsewhere shared the leaf name (the 7-Zip case). Findings dedupe per
    # target path (Chromium can carry the same download twice).
    $execPaths = @{}
    $execLeaves = @{}
    $r4Exec = 0
    foreach ($src in @('amcache', 'prefetch_parsed', 'execution_timeline', 'processes')) {
        $r4Src = @(Import-CaseCsv $src); $r4Exec += $r4Src.Count
        foreach ($r in $r4Src) {
                    foreach ($pn in @('Path', 'Executable', 'FullPath', 'Name', 'App')) {
                $p2 = $r.PSObject.Properties[$pn]
                if ($p2 -and "$($p2.Value)") {
                    $ev = "$($p2.Value)".ToLower().Trim()
                    $n = ''
                    try { $n = (Split-Path $ev -Leaf) } catch { $n = $ev }
                    if ($n -match '\.(exe|dll|ps1|bat|js|hta|scr|msi|lnk|vbs)$') {
                        $execLeaves[$n] = $true
                        $ed = ''
                        try { $ed = (Split-Path $ev -Parent) } catch { $ed = '' }
                        if ($ed) { $execPaths[($ev -replace '/', '\')] = $true }
                    }
                    break
                }
            }
        }
    }
    $r4Seen = @{}
    $r4Dl = @(Import-CaseCsv 'browser_downloads')
    foreach ($r in $r4Dl) {
        $tp = ''
        foreach ($pn in @('TargetFilePath', 'TargetPath', 'DownloadPath', 'FullPath', 'Path', 'URL')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $tp = "$($p2.Value)"; break }
        }
        if (-not $tp) { continue }
        $n = ''
        try { $n = (Split-Path $tp -Leaf).ToLower() } catch { $n = $tp.ToLower() }
        if (-not $n -or $n -notmatch '\.(exe|dll|ps1|bat|js|hta|scr|msi|lnk|vbs)$') { continue }
        $r4Key = $tp.ToLower().Trim() -replace '/', '\'
        if ($r4Seen.ContainsKey($r4Key)) { continue }
        # leaf fallback only when the download row has no directory (drive/UNC prefix absent)
        $r4Dir = ($tp -match '^[A-Za-z]:\\|^\\\\')
        $r4Hit = if ($r4Dir) { $execPaths.ContainsKey($r4Key) } else { $execLeaves.ContainsKey($n) }
        if (-not $r4Hit) { continue }
        $r4Seen[$r4Key] = $true
        # severity: outside a Downloads folder = high (staged/renamed); in Downloads unsigned =
        # high; in Downloads signed OR signature not checkable (file gone on parse mode) = medium;
        # no-directory download row = medium (leaf match only - Test-Path would probe the
        # analyst's CWD, so there is nothing honest to signature-check on disk).
        # v2.80 (F5): HashMismatch = content altered AFTER the signed build (classic
        # defense-evasion tell, never softened to 'unverifiable') - high outside Downloads,
        # medium inside; the signature is probed wherever the file is present on disk.
        $r4Sev = 'high'; $r4Why = ''
        $r4Sig = $null
        if ($r4Dir -and (Test-Path -LiteralPath $tp)) {
            try { $r4Sig = Get-AuthenticodeSignature -LiteralPath $tp } catch { $r4Sig = $null }
        }
        $r4Status = if ($r4Sig) { "$($r4Sig.Status)" } else { '' }
        if (-not $r4Dir) {
            $r4Why = 'signature not checkable (download row carries no directory)'; $r4Sev = 'medium'
        } elseif ($r4Status -eq 'HashMismatch') {
            $r4Why = 'binary MODIFIED after signing'
            if ($tp -match '(?i)\\downloads\\') { $r4Sev = 'medium' }
        } elseif ($tp -notmatch '(?i)\\downloads\\') {
            $r4Why = 'staged outside a Downloads folder (renamed or relayed payload)'
        } elseif (-not $r4Sig) {
            $r4Why = 'signature not checkable (file no longer present)'; $r4Sev = 'medium'
        } elseif ($r4Status -eq 'NotSigned') {
            $r4Why = 'unsigned binary in Downloads'
        } else {
            $r4Why = "signed ($r4Status)"; $r4Sev = 'medium'
        }
        & $find 'Downloaded then executed' $r4Sev $tp "'$n' downloaded via browser and later appears in execution evidence ($r4Why)" 'T1105/T1204.002'
    }
    & $trace 'R4' 'downloaded then executed' "browser_downloads: $($r4Dl.Count) rows x exec evidence (4 sources): $r4Exec rows"

    # ---------- R5: USB execution trail (report-only) ----------
    $usb = @(Import-CaseCsv 'usb_devices')
    if ($usb.Count -gt 0) {
        $nonC = @()
        # v2.45: skip the kit's own raw copies (values pointing into the case folder are the
        # parser's .lnk preserves, not user USB activity on a non-C: drive)
        foreach ($src in @('lnk_parsed', 'shellbags')) {
            foreach ($r in (Import-CaseCsv $src)) {
                foreach ($p2 in $r.PSObject.Properties) {
                    $v = "$($p2.Value)"
                    if (($CaseDir -and $v -match [regex]::Escape($CaseDir)) -or $v -match '(?i)\\OPHIRA_[^\\]*\\raw\\') { continue }
                    if ($v -match '(?i)^([d-z]):\\' -and $Matches[1].ToUpper() -ne 'C:') { $nonC += "$($src.Substring(0, 3))/$($p2.Name): $v"; break }
                }
                if ($nonC.Count -ge 3) { break }
            }
            if ($nonC.Count -ge 3) { break }
        }
        if ($nonC.Count -gt 0) {
            & $find 'USB execution trail' 'info' "$($usb.Count) USB device(s) on record" "non-C: drive references: $(($nonC | Select-Object -First 3) -join ' | ')" 'T1091'
        }
        & $trace 'R5' 'USB execution trail' "usb_devices: $($usb.Count) rows + lnk_parsed/shellbags scan"
    } else {
        & $trace 'R5' 'USB execution trail' 'gate: usb_devices empty or missing - skipped'
    }

    # ---------- R6: account created + privileged group change in window (report-only) ----------
    $auth = @(Import-CaseCsv 'security_auth_events')
    $created = @($auth | Where-Object { "$($_.EventId)" -eq '4720' } | ForEach-Object { "$($_.Account)" } | Sort-Object -Unique)
    $grpAdds = @($auth | Where-Object { @('4728', '4732', '4756') -contains "$($_.EventId)" })
    if ($created.Count -gt 0 -and $grpAdds.Count -gt 0) {
        & $find 'Account lifecycle - created + group change' 'info' (($created | Select-Object -First 5) -join ', ') "$($created.Count) account creation(s) + $($grpAdds.Count) privileged-group change(s) in window" 'T1136/T1098'
    }
    & $trace 'R6' 'account lifecycle (created + group change)' "security_auth_events: $($auth.Count) rows, 4720: $($created.Count), group-adds: $($grpAdds.Count)"

    # ---------- R7: RDP logon from public internet IP (report-only) ----------
    $rdpPub = @($auth | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -eq '10' -and (Test-IsPublicIp "$($_.SourceIp)") })
    foreach ($g in ($rdpPub | Group-Object SourceIp)) {
        $accts = (@($g.Group | ForEach-Object { "$($_.Account)" } | Sort-Object -Unique | Select-Object -First 4)) -join ', '
        & $find 'RDP logon from public internet IP' 'medium' "$($g.Name)" "$($g.Count) RDP logon(s): $accts" 'T1021.001'
    }
    & $trace 'R7' 'RDP logon from public IP' "security_auth_events: $($auth.Count) rows, RDP-public 4624s: $($rdpPub.Count)"

    # ---------- R8: LSASS access - non-system process opened lsass.exe (Sysmon EID 10) ----------
    $lsassOk = @('csrss.exe', 'lsm.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'svchost.exe', 'lsass.exe', 'lsaiso.exe', 'msmpeng.exe', 'nissrv.exe', 'mssense.exe', 'sense.exe', 'sgrmbroker.exe', 'wmiprvse.exe', 'vssvc.exe', 'dfsr.exe', 'dfsrs.exe', 'taskhostw.exe', 'sihost.exe', 'spoolsv.exe')
    $lsassHits = @{}
    $r8In = @(Import-CaseCsv 'sysmon_process_access')
    foreach ($r in $r8In) {
        $tgt = "$($r.TargetImage)"
        if ($tgt -notmatch '(?i)\\lsass\.exe$') { continue }
        $src = "$($r.SourceImage)"
        $leaf = ''
        try { $leaf = (Split-Path $src -Leaf).ToLower() } catch { }
        # v2.80 (F7): leaf-name match alone let name-spoofed copies (C:\Users\Public\svchost.exe)
        # open lsass unchallenged - allowlisted names only count when the SourceImage really
        # lives in a Windows system dir (same drive-agnostic pattern as the R3 inSys filter).
        if (-not $leaf) { continue }
        if ($lsassOk -contains $leaf -and "$src" -match '(?i)^[a-z]:\\windows\\(system32|syswow64|sysnative)\\') { continue }
        if (-not $lsassHits.ContainsKey($src)) { $lsassHits[$src] = New-Object System.Collections.Generic.List[string] }
        $null = $lsassHits[$src].Add("granted=$($r.GrantedAccess) @ $($r.Time)")
    }
    foreach ($kv in ($lsassHits.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10)) {
        & $find 'LSASS access - non-system process opened lsass.exe' 'high' $kv.Key "$($kv.Value.Count) handle event(s): $($kv.Value[0])" 'T1003.001'
    }
    & $trace 'R8' 'LSASS access (Sysmon EID 10)' "sysmon_process_access: $($r8In.Count) rows, non-system openers: $($lsassHits.Count)"

    # ---------- R9: Office app spawned interpreter (4688 parent-child chain) ----------
    $officeApps = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'onenote.exe', 'onenotem.exe')
    $interpreters = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'installutil.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'msxsl.exe')
    $r9Seen = @{}
    $r9In = @(Import-CaseCsv 'security_proc_events')
    foreach ($r in $r9In) {
        $par = ''; $kid = ''
        try { $par = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        try { $kid = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if (-not $par -or -not $kid -or $officeApps -notcontains $par -or $interpreters -notcontains $kid) { continue }
        $k = "$par>$kid"
        if ($r9Seen.ContainsKey($k)) { $r9Seen[$k]++ ; continue }
        $r9Seen[$k] = 1
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) + '...' }
        & $find 'Office app spawned interpreter' 'high' "$par -> $kid" "$($r.Time): $cmd" 'T1566.001/T1059'
    }
    & $trace 'R9' 'Office app spawned interpreter' "security_proc_events: $($r9In.Count) rows"

    # ---------- R10: proxy-execution LOLBin command lines (4688 CommandLine; needs cmdline audit) ----------
    $r10Seen = @{}
    $r10In = @(Import-CaseCsv 'security_proc_events')
    foreach ($r in $r10In) {
        $cmd = "$($r.CommandLine)".Trim()
        if ($cmd.Length -lt 8) { continue }
        $low = $cmd.ToLower()
        $hit = ''
        $sev = 'high'
        if ($low -match '(-enc\b|-encodedcommand\b|frombase64string)') { $hit = 'encoded command' }
        elseif ($low -match 'certutil\.exe.+\s(-urlcache|-decode|-decodehex)') { $hit = 'certutil download/decode' }
        elseif ($low -match 'mshta\.exe.*(https?://|vbscript:|javascript:)') { $hit = 'mshta remote/script URL' }
        elseif ($low -match 'rundll32\.exe.*(javascript:|comsvcs\.dll,?\s*minidump)') { $hit = 'rundll32 script/minidump' }
        elseif ($low -match 'regsvr32(\.exe)?\s+/i:/?(https?|file):') { $hit = 'regsvr32 remote scriplet' }
        elseif ($low -match 'bitsadmin(\.exe)?\s+(/transfer|/create)') { $hit = 'bitsadmin download'; $sev = 'medium' }
        elseif ($low -match 'msiexec(\.exe)?.*https?://') { $hit = 'msiexec remote package'; $sev = 'medium' }
        elseif ($low -match 'wmic(\.exe)?.*\sprocess\s+call\s+create') { $hit = 'wmic process create'; $sev = 'medium' }
        if (-not $hit) { continue }
        $key = "$hit|$low"
        if ($r10Seen.ContainsKey($key)) { continue }
        $r10Seen[$key] = $true
        if ($r10Seen.Count -gt 20) { break }
        & $find "LOLBin proxy-execution - $hit" $sev "$($r.NewProcess)" "$($r.Time): $(if ($cmd.Length -gt 220) { $cmd.Substring(0, 220) + '...' } else { $cmd })" 'T1218'
    }
    & $trace 'R10' 'proxy-execution LOLBin command lines' "security_proc_events: $($r10In.Count) rows"

    # ---------- R11: UAC bypass pattern - ms-settings shell\open\command writes (Sysmon EID 13) ----------
    $r11Seen = @{}
    $r11In = @(Import-CaseCsv 'sysmon_registry')
    foreach ($r in $r11In) {
        $to = "$($r.TargetObject)"
        if ($to -notmatch '(?i)\\ms-settings\\shell\\open\\command') { continue }
        $k = $to -replace '^HKEY_USERS\\[^\\]+', 'HKCU'
        if ($r11Seen.ContainsKey($k)) { continue }
        $r11Seen[$k] = $true
        & $find 'UAC bypass pattern - ms-settings command hijack' 'medium' $to "registry write by $($r.Image) (fodhelper/eventvwr technique)" 'T1548.002'
    }
    & $trace 'R11' 'UAC bypass pattern (ms-settings)' "sysmon_registry: $($r11In.Count) rows"

    # ---------- R12: executable written via admin share (5145 WriteData/Append on ADMIN$/x$) ----------
    $r12Seen = @{}
    $r12In = @(Import-CaseCsv 'security_share_access')
    foreach ($r in $r12In) {
        if ("$($r.EventId)" -ne '5145') { continue }
        $share = ("$($r.ShareName)" -replace '^[\*\\\s]+', '')
        if ($share -notmatch '(?i)^admin\$' -and $share -notmatch '(?i)^[a-z]\$$') { continue }
        $tn = "$($r.RelativeTargetName)"
        if ($tn -notmatch '(?i)\.(exe|dll|ps1|bat|cmd|hta|js|vbs|vbe|jse|scr|psm1|jar|msi)$') { continue }
        if ("$($r.AccessList)" -notmatch '%%4415|%%4416') { continue }
        $k = "$($r.Account)|$share|$tn"
        if ($r12Seen.ContainsKey($k)) { continue }
        $r12Seen[$k] = $true
        & $find 'Admin-share executable staging' 'high' "$($r.SourceIp)" "'$tn' written on \\$share by $($r.Account) at $($r.Time)" 'T1021.002'
    }
    & $trace 'R12' 'admin-share executable staging (5145)' "security_share_access: $($r12In.Count) rows"

    # ---------- R13: discovery command storm (4688 recon-tool burst per account) ----------
    $discBins = @('whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'systeminfo.exe', 'ipconfig.exe', 'quser.exe', 'qwinsta.exe', 'tasklist.exe', 'netstat.exe', 'nslookup.exe', 'arp.exe', 'route.exe', 'klist.exe', 'wmic.exe', 'dsquery.exe', 'adfind.exe', 'csvde.exe', 'ldifde.exe', 'tree.exe')
    $discByAcct = @{}
    $r13In = @(Import-CaseCsv 'security_proc_events')
    foreach ($r in $r13In) {
        $leaf = ''
        try { $leaf = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if ($discBins -notcontains $leaf) { continue }
        $a = "$($r.Account)"; if (-not $a) { $a = '(unknown)' }
        if (-not $discByAcct.ContainsKey($a)) { $discByAcct[$a] = New-Object System.Collections.Generic.List[string] }
        $null = $discByAcct[$a].Add($leaf)
    }
    foreach ($kv in ($discByAcct.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 5)) {
        $distinct = @($kv.Value | Sort-Object -Unique).Count
        if ($kv.Value.Count -lt 15 -and $distinct -lt 6) { continue }
        $tools = ($kv.Value | Sort-Object -Unique | Select-Object -First 8) -join ', '
        # v2.76: the storm is inherently low-specificity (Ophira's own collection runs the same
        # binaries); machine/system accounts are almost certainly the collector itself.
        $discAcct = $kv.Key
        if ($discAcct -match '\$$' -or $discAcct -match '(?i)(^|\\)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
            & $find 'Discovery command storm' 'low' $discAcct "$($kv.Value.Count) recon commands ($distinct distinct): $tools - machine/system context - likely its own collection tooling" 'T1087/T1082'
        } else {
            & $find 'Discovery command storm' 'low' $discAcct "$($kv.Value.Count) recon commands ($distinct distinct): $tools" 'T1087/T1082'
        }
    }
    $r13Cmds = 0; foreach ($v in $discByAcct.Values) { $r13Cmds += $v.Count }
    & $trace 'R13' 'discovery command storm' "$($discByAcct.Count) accounts x $r13Cmds cmds (security_proc_events: $($r13In.Count) rows)"

    # ---------- R14: Defender tamper - real-time protection off / exclusion change (5001/5007) ----------
    $dcfg = @(Import-CaseCsv 'defender_config_events')
    $rtOff = @($dcfg | Where-Object { "$($_.EventId)" -eq '5001' })
    if ($rtOff.Count -gt 0) {
        & $find 'Defender real-time protection DISABLED' 'high' $Computer "$($rtOff.Count) disable event(s), last at $($rtOff[-1].Time) - tamper or manual change" 'T1562.001'
    }
    foreach ($e in (@($dcfg | Where-Object { "$($_.EventId)" -eq '5007' -and "$($_.Detail)" -match '(?i)exclusion' }) | Select-Object -First 3)) {
        & $find 'Defender exclusion configuration changed' 'high' $Computer "$($e.Time): $($e.Detail)" 'T1562.001'
    }
    & $trace 'R14' 'Defender tamper (5001/5007)' "defender_config_events: $($dcfg.Count) rows"

    # ---------- R15: timestomping - creation time changed (Sysmon EID 2) ----------
    # v2.76: archive copy/extract tools legitimately preserve packed timestamps on copy/extract
    # (the WIN11 case's whole EID2 log was explorer.exe preserving archive times) - skip them.
    # Dedupe per target path BEFORE the 10-row cap; remaining images stay medium.
    $r15Seen = @{}
    $r15In = @(Import-CaseCsv 'sysmon_file_time')
    foreach ($r in $r15In) {
        $r15Img = ''
        try { $r15Img = (Split-Path "$($r.Image)" -Leaf).ToLower() } catch { $r15Img = "$($r.Image)".ToLower() }
        if ($r15Img -eq 'explorer.exe' -or $r15Img -eq 'rar.exe' -or $r15Img -eq 'robocopy.exe' -or $r15Img -eq 'xcopy.exe' -or $r15Img -like '7z*.exe' -or $r15Img -like 'winrar*.exe' -or $r15Img -eq 'msiexec.exe') { continue }
        $r15Key = "$($r.TargetFilename)".ToLower().Trim()
        if (-not $r15Key -or $r15Seen.ContainsKey($r15Key)) { continue }
        $r15Seen[$r15Key] = $true
        if ($r15Seen.Count -gt 10) { break }
        & $find 'File creation time changed (timestomping candidate)' 'medium' "$($r.TargetFilename)" "by $($r.Image): $($r.PreviousCreationUtcTime) -> $($r.CreationUtcTime)" 'T1070.006'
    }
    & $trace 'R15' 'timestomping (Sysmon EID 2)' "sysmon_file_time: $($r15In.Count) rows"

    # ---------- R16: DCSync - replication Get-Changes by a user account (4662) ----------
    $dcSeen = @{}
    $r16In = @(Import-CaseCsv 'security_ds_access')
    foreach ($r in ($r16In | Where-Object { "$($_.Properties)" -match '(?i)e3514235-4b06-11d1-ab04-00c04fc2dcd2|1131f6a[ad]-' -and "$($_.Account)" -notmatch '\$$' })) {
        $a = "$($r.Account)"
        if (-not $a -or $dcSeen.ContainsKey($a)) { continue }
        $dcSeen[$a] = $true
        if ($dcSeen.Count -gt 10) { break }
        & $find 'DCSync - replication access by user account' 'high' $a "4662 Get-Changes on $($r.Object) at $($r.Time)" 'T1003.006'
    }
    & $trace 'R16' 'DCSync (4662 Get-Changes)' "security_ds_access: $($r16In.Count) rows"

    # ---------- R17: Kerberoasting pattern - RC4 TGS burst per source (4769) ----------
    $ker = @(Import-CaseCsv 'security_kerberos')
    $tgs = @($ker | Where-Object { "$($_.EventId)" -eq '4769' -and "$($_.TicketEnc)" -eq '0x17' })
    foreach ($g in ($tgs | Group-Object IpAddress)) {
        $svc = @(@($g.Group | ForEach-Object { "$($_.Service)" }) | Sort-Object -Unique)
        if ($svc.Count -ge 10) {
            & $find 'Kerberoasting pattern - RC4 TGS burst' 'medium' "$($g.Name)" "$($g.Count) TGS requests for $($svc.Count) distinct SPNs over RC4" 'T1558.003'
        }
    }
    & $trace 'R17' 'Kerberoasting (RC4 TGS burst)' "security_kerberos: $($ker.Count) rows, RC4 TGS: $($tgs.Count)"

    # ---------- R18: AS-REP roast pattern - TGT without pre-auth (4768 PreAuthType 0) ----------
    $asrepSeen = @{}
    foreach ($r in (@($ker | Where-Object { "$($_.EventId)" -eq '4768' -and "$($_.PreAuth)" -eq '0' }) | Select-Object -First 5)) {
        $a = "$($r.Account)"
        if ($asrepSeen.ContainsKey($a)) { continue }
        $asrepSeen[$a] = $true
        & $find 'AS-REP roast pattern - TGT requested without pre-auth' 'medium' $a "from $($r.IpAddress) at $($r.Time)" 'T1558.004'
    }
    & $trace 'R18' 'AS-REP roast (no pre-auth TGT)' "security_kerberos: $($ker.Count) rows"

    # ---------- R19: password spray - many distinct accounts failing from one source (4771/4625) ----------
    $sprayFails = @()
    $sprayFails += (@($ker | Where-Object { "$($_.EventId)" -eq '4771' }) | ForEach-Object { [pscustomobject]@{ Account = "$($_.Account)"; Ip = "$($_.IpAddress)" } })
    $sprayFails += (@(Import-CaseCsv 'security_auth_events') | Where-Object { "$($_.EventId)" -eq '4625' } | ForEach-Object { [pscustomobject]@{ Account = "$($_.Account)"; Ip = "$($_.SourceIp)" } })
    foreach ($g in ($sprayFails | Where-Object { $_.Ip -and $_.Ip -ne '-' -and $_.Ip -ne '::1' -and $_.Account } | Group-Object Ip)) {
        $accts = @(@($g.Group | ForEach-Object { $_.Account }) | Sort-Object -Unique)
        if ($accts.Count -ge 10) {
            & $find 'Password spray - many accounts from one source' 'high' "$($g.Name)" "$($g.Count) failures across $($accts.Count) accounts: $(($accts | Select-Object -First 5) -join ', ')" 'T1110.003'
        }
    }
    & $trace 'R19' 'password spray (4771/4625)' "kerberos 4771: $(@($ker | Where-Object { "$($_.EventId)" -eq '4771' }).Count) + auth 4625: $(@($auth | Where-Object { "$($_.EventId)" -eq '4625' }).Count) rows"

    # ---------- R20: web server spawned interpreter (4688: w3wp/tomcat/httpd parent) ----------
    $webParents = @('w3wp.exe', 'tomcat8.exe', 'tomcat9.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe')
    $webKids = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'csc.exe', 'vbc.exe', 'msbuild.exe', 'curl.exe', 'net.exe')
    $r20Seen = @{}
    $r20In = @(Import-CaseCsv 'security_proc_events')
    foreach ($r in $r20In) {
        $par = ''; $kid = ''
        try { $par = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        try { $kid = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if (-not $par -or -not $kid -or $webParents -notcontains $par -or $webKids -notcontains $kid) { continue }
        $k = "$par>$kid"
        if ($r20Seen.ContainsKey($k)) { $r20Seen[$k]++ ; continue }
        $r20Seen[$k] = 1
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) + '...' }
        & $find 'Web server spawned interpreter' 'high' "$par -> $kid" "$($r.Time): $cmd" 'T1505.003'
    }
    & $trace 'R20' 'web server spawned interpreter' "security_proc_events: $($r20In.Count) rows"

    # ---------- R21: web traffic anomalies (report-only leads from the IIS parse) ----------
    $r21In = @(@(Import-CaseCsv 'iis_anomalies') | Where-Object { @('suspicious-uri', 'post-to-upload-path', 'headless-posts') -contains $_.Kind })
    foreach ($r in ($r21In | Select-Object -First 5)) {
        & $find 'Web traffic anomaly' 'medium' "$($r.Kind)" "$($r.Detail) - $($r.Sample)" 'T1190'
    }
    & $trace 'R21' 'web traffic anomalies (IIS)' "iis_anomalies matched kinds: $($r21In.Count) rows"

    # ---------- R22: timestamp anomalies (MFT birth attributes x execution evidence) ----------
    # v2.76: lookups keyed by FULL path (FullPath column when present, Path fallback) - the old
    # leaf-name key matched an OS MpCmdRun.exe against a same-leaf execution row from elsewhere.
    # Three-way split (was one medium "Timestamp forgery indicators"):
    #   future file birth        - $MFT $Si birth after collection time (+1d margin) - medium
    #   execution predates birth - amcache evidence predates the claimed birth by >24h - medium
    #   birth attribute skew     - $Si vs FILE_NAME birth disagree by >90 days - low (normal for
    #                              extracted archives: Wireshark/Sysinternals keep packed times)
    # Sysmon EID 2 events for the same full path corroborate the skew check. Medium rules emit
    # before the low rows so a downstream cap cannot crowd them out.
    $mftByPath = @{}
    $r22Mft = @(Import-CaseCsv 'mft_recent')
    foreach ($r in $r22Mft) {
        $fp = ''
        foreach ($pn in @('FullPath', 'Path')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $fp = ("$($p2.Value)".ToLower().Trim() -replace '/', '\'); break }
        }
        if ($fp -and -not $mftByPath.ContainsKey($fp)) { $mftByPath[$fp] = $r }
    }
    $amcByPath = @{}
    $r22Amc = @(Import-CaseCsv 'amcache')
    foreach ($r in $r22Amc) {
        $fp = ''
        foreach ($pn in @('FullPath', 'Path')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $fp = ("$($p2.Value)".ToLower().Trim() -replace '/', '\'); break }
        }
        if (-not $fp) { continue }
        $t = $null
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$' })) {
            try { $t2 = [datetime]"$($r.$pn)"; if ($t2 -and (-not $t -or $t2 -lt $t)) { $t = $t2 } } catch { }
        }
        if (-not $amcByPath.ContainsKey($fp) -or ($t -and $amcByPath[$fp].T -and $t -lt $amcByPath[$fp].T)) { $amcByPath[$fp] = @{ T = $t; Src = 'amcache' } }
    }
    $eid2ByPath = @{}
    $r22Eid2 = @(Import-CaseCsv 'sysmon_file_time')
    foreach ($r in $r22Eid2) {
        $fp = ''
        foreach ($pn in @('FullPath', 'TargetFilename')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $fp = ("$($p2.Value)".ToLower().Trim() -replace '/', '\'); break }
        }
        if ($fp) { $eid2ByPath[$fp] = $true }
    }
    $now = (Get-Date).ToUniversalTime()
    # v2.44 FP exclusions (verified on a clean dev box): Windows servicing stages binaries in
    # WinSxS\Temp\InFlight (FILE_NAME birth = staging time, $Si = original catalog time - the
    # skew is legitimate), browser updaters re-create binaries under \updated\ / versioned
    # \Application\<ver>\ dirs (amcache remembers the OLD file - "ran before it existed" is the
    # updater, not timestomping), Store VFS lives under WindowsApps, and .lnk copies keep their
    # original $Si (870-day "skews" on Start-Menu shortcuts are normal). The skew and
    # ran-before-born checks therefore run on PE files outside those paths only; future-birth
    # stays unconditional.
    $tfSkipRe = '(?i)\\WinSxS\\Temp\\InFlight\\|\\WinSxS\\Backup\\|\\WindowsApps\\|\\(Mozilla Firefox|Mozilla Thunderbird|Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser)\\(updated|Application\\[0-9][0-9.]*\\)'
    $tfPeRe = '(?i)\.(exe|dll|sys|ocx|scr|cpl)$'
    $tfAnoms = New-Object System.Collections.Generic.List[object]
    foreach ($kv in (@($mftByPath.GetEnumerator()) | Select-Object -First 200)) {
        $tfPath = "$($kv.Key)"; $tfShow = ''
        foreach ($pn in @('Path', 'FullPath')) {
            $p2 = $kv.Value.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $tfShow = "$($p2.Value)"; break }
        }
        if (-not $tfShow) { $tfShow = $tfPath }
        $birth = $null; try { $birth = [datetime]"$($kv.Value.Created)" } catch { }
        if (-not $birth) { continue }
        $attrOk = ($tfPath -notmatch $tfSkipRe) -and ($tfPath -match $tfPeRe)
        $bfn = $null
        if ($attrOk -and "$($kv.Value.CreatedFN)") { try { $bfn = [datetime]"$($kv.Value.CreatedFN)" } catch { } }
        $am = $amcByPath[$tfPath]
        $future = (($birth - $now).TotalDays -gt 1)
        $ran = ($attrOk -and $am -and $am.T -and (($birth - $am.T).TotalDays -gt 1))
        $skew = ($attrOk -and $bfn -and ([math]::Abs(($birth - $bfn).TotalDays) -gt 90))
        if (-not ($future -or $ran -or $skew)) { continue }
        $null = $tfAnoms.Add([pscustomobject]@{ Key = $tfPath; Show = $tfShow; Row = $kv.Value; Birth = $birth; Bfn = $bfn; Am = $am; Future = $future; Ran = $ran; Skew = $skew })
    }
    $tfMed = 0
    foreach ($an in $tfAnoms.ToArray()) {
        $hit = $false
        if ($an.Future) {
            $hit = $true
            & $find 'Timestamp anomaly - future file birth' 'medium' "$($an.Show)" "birth '$($an.Row.Created)' is in the future (backdated or clock-skewed)" 'T1070.006'
        }
        if ($an.Ran) {
            $hit = $true
            & $find 'Timestamp anomaly - execution predates birth' 'medium' "$($an.Show)" "execution evidence ($($an.Am.Src)) at $($an.Am.T.ToString('s')) predates claimed birth $($an.Row.Created) (ran before it existed)" 'T1070.006'
        }
        if ($hit) { $tfMed++; if ($tfMed -ge 40) { break } }
    }
    $tfLow = 0
    foreach ($an in ($tfAnoms.ToArray() | Where-Object { $_.Skew })) {
        $ev = "birth attributes disagree: `$Si $($an.Row.Created) vs FILE_NAME $($an.Row.CreatedFN) ($([math]::Abs([math]::Round(($an.Birth - $an.Bfn).TotalDays))) day skew - classic backdated `$Si)"
        if ($eid2ByPath.ContainsKey($an.Key)) { $ev += ' | Sysmon EID 2 file-creation-time changes observed for this file' }
        & $find 'Timestamp anomaly - birth attribute skew' 'low' "$($an.Show)" $ev 'T1070.006'
        $tfLow++
        if ($tfLow -ge 40) { break }
    }
    & $trace 'R22' 'timestamp anomalies (MFT x execution)' "mft_recent: $($r22Mft.Count) + amcache: $($r22Amc.Count) + sysmon_file_time: $($r22Eid2.Count) rows"

    # ---------- R23-R26: tunnel & remote-access pack (csv\remote_access.csv + collected sources) ----------
    # R23 tunnel binary active - high when running/installed/service-installed, medium when only on disk
    # R24 RA-tool service - medium (dual-use: legitimate remote support is common)
    # R25 RDP ServiceDll tamper - high (RDPWrap-class)
    # R26 non-empty authorized_keys - high (planted SSH trust anchor)
    # NOTE: keep $tunPat/$raPat in sync with module 8.16
    $tunPat = '(?i)(^|[^a-z0-9])(ngrok|cloudflared|tailscaled?|chisel|ligolo|frpc|frps|gost|revsocks)([^a-z0-9]|$)'
    $raPat = '(?i)(^|[^a-z0-9])(anydesk|screenconnect|connectwisecontrol|teamviewer|rustdesk)([^a-z0-9]|$)'
    $raActive = @{}
    $raIn = 0
    $raRows = @(Import-CaseCsv 'processes'); $raIn += $raRows.Count
    foreach ($r in $raRows) {
        $leaf = ''
        try { $leaf = (Split-Path "$($r.Path)" -Leaf) } catch { continue }
        if (-not $leaf -or "$leaf" -notmatch $tunPat) { continue }
        $key = "$leaf".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.Path)" "tunnel tool running as process '$leaf' (pid $($r.PID))" 'T1572'
        if ($raActive.Count -gt 10) { break }
    }
    $raRows = @(Import-CaseCsv 'services'); $raIn += $raRows.Count
    foreach ($r in $raRows) {
        $blob = "$($r.Name) $($r.DisplayName) $($r.PathName)"
        if ("$blob" -notmatch $tunPat) { continue }
        $key = "$($r.Name)".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.PathName)" "tunnel tool installed as service '$($r.Name)' (state $($r.State))" 'T1572'
        if ($raActive.Count -gt 10) { break }
    }
    $raRows = @(Import-CaseCsv 'system_new_services'); $raIn += $raRows.Count
    foreach ($r in $raRows) {
        $blob = "$($r.Service) $($r.Binary)"
        if ("$blob" -notmatch $tunPat) { continue }
        $key = "$($r.Service)".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.Binary)" "tunnel tool service '$($r.Service)' installed at $($r.Time) (7045)" 'T1543.003'
        if ($raActive.Count -gt 10) { break }
    }
    foreach ($src in @('mft_recent', 'amcache')) {
        $raRows = @(Import-CaseCsv $src); $raIn += $raRows.Count
        foreach ($r in $raRows) {
            $lf = ''
            foreach ($pn in @('Path', 'Name', 'ApplicationName')) {
                $p2 = $r.PSObject.Properties[$pn]
                if ($p2 -and "$($p2.Value)") { try { $lf = (Split-Path "$($p2.Value)" -Leaf) } catch { $lf = "$($p2.Value)" }; break }
            }
            if (-not $lf -or "$lf" -notmatch $tunPat) { continue }
            $key = "$lf".ToLower()
            if ($raActive.ContainsKey($key)) { continue }
            $raActive[$key] = $true
            & $find 'Remote-access tunnel tool on disk' 'medium' "$lf" "tunnel tool name present in $src (file evidence only - not seen running/installed)" 'T1572'
            if ($raActive.Count -gt 20) { break }
        }
    }
    $raSvcSeen = @{}
    $raRows = @(Import-CaseCsv 'services'); $raIn += $raRows.Count
    foreach ($r in $raRows) {
        $blob = "$($r.Name) $($r.DisplayName) $($r.PathName)"
        if ("$blob" -notmatch $raPat) { continue }
        $key = "$($r.Name)".ToLower()
        if ($raSvcSeen.ContainsKey($key)) { continue }
        $raSvcSeen[$key] = $true
        & $find 'Remote-access tool present' 'medium' "$($r.PathName)" "remote-access tool installed as service '$($r.Name)' (state $($r.State)) - dual-use, verify support expectation" 'T1219'
        if ($raSvcSeen.Count -gt 10) { break }
    }
    $raRows = @(Import-CaseCsv 'remote_access'); $raIn += $raRows.Count
    foreach ($r in $raRows) {
        if ("$($r.Type)" -eq 'RA tool service' -or "$($r.Type)" -eq 'RA tool data dir') {
            $key = "$($r.Name)".ToLower()
            if (-not $raSvcSeen.ContainsKey($key)) {
                $raSvcSeen[$key] = $true
                & $find 'Remote-access tool present' 'medium' "$($r.Path)" "remote-access tool $($r.Type.ToLower()) '$($r.Name)' ($($r.State)) - dual-use, verify support expectation" 'T1219'
            }
        }
        if ("$($r.Type)" -eq 'RDP ServiceDll tamper') {
            & $find 'RDP ServiceDll tamper' 'high' "$($r.Path)" "TermService ServiceDll replaced: $($r.Path) - $($r.Detail)" 'T1112'
        }
        if ("$($r.Type)" -eq 'SSH authorized_keys' -and "$($r.State)" -match 'populated') {
            & $find 'SSH authorized_keys present' 'high' "$($r.Path)" "$($r.Name) is $($r.State) - planted SSH trust anchor ($($r.Detail))" 'T1098.004'
        }
    }
    & $trace 'R23-26' 'remote-access pack (tunnels/RA tools/RDP/SSH)' "6 sources: $raIn rows scanned"

    # ---------- R27: svchost masquerade (module 1.7 audit xref) ----------
    $svchN = 0
    $r27In = @(Import-CaseCsv 'svchost_audit')
    foreach ($r in $r27In) {
        $sev = if ("$($r.Type)" -match 'UnregisteredGroup|OutOfPathServiceDll') { 'high' } else { 'medium' }
        $ent = if ("$($r.Path)") { "$($r.Path)" } elseif ("$($r.Service)") { "svchost -k $($r.Group) / $($r.Service)" } else { "svchost -k $($r.Group)" }
        & $find 'Svchost masquerade indicator' $sev $ent "$($r.Type): $($r.Detail)" 'T1036.005'
        $svchN++
        if ($svchN -ge 20) { break }
    }
    & $trace 'R27' 'svchost masquerade (1.7 audit xref)' "svchost_audit: $($r27In.Count) rows"

    # ---------- R28: cross-process injection (Sysmon EID 8 CreateRemoteThread) ----------
    # v2.76 severity ladder (first match wins): target '<unknown process>' -> low;
    # source AND target both under \Windows\ and target not lsass -> low (protected pair,
    # e.g. dwm -> csrss); target lsass OR source/target in a user-writable path -> high;
    # any other cross-boundary pair -> medium. One finding per source->target pair.
    $r28Seen = @{}
    $r28In = @(Import-CaseCsv 'sysmon_remote_thread')
    foreach ($r in $r28In) {
        $src = "$($r.SourceImage)"; $tgt = "$($r.TargetImage)"
        if (-not $src -or -not $tgt) { continue }
        if ($src.ToLower() -eq $tgt.ToLower()) { continue }
        $key = "$src->$tgt".ToLower()
        if ($r28Seen.ContainsKey($key)) { continue }
        $r28Seen[$key] = $true
        if ($r28Seen.Count -gt 20) { break }
        $fn = "$($r.StartFunction)"; $mod = "$($r.StartModule)"
        $ev = "$($r.Time): $src -> $tgt"
        if ($fn -and $fn -ne '-') { $ev += " ($fn$(if ($mod -and $mod -ne '-') { " @ $mod" }))" }
        if ($tgt -eq '<unknown process>') {
            $sev = 'low'
            $ev += " - target '<unknown process>' (unattributed, low signal)"
        } elseif (($src -match '(?i)\\windows\\') -and ($tgt -match '(?i)\\windows\\') -and ($tgt -notmatch '(?i)\\lsass\.exe$')) {
            $sev = 'low'
            $ev += ' - both processes under \Windows\ (protected Windows pair)'
        } elseif (($tgt -match '(?i)\\lsass\.exe$') -or (Test-IsUserWritablePath $src) -or (Test-IsUserWritablePath $tgt)) {
            $sev = 'high'
            if ($tgt -match '(?i)\\lsass\.exe$') { $ev += ' - lsass target: credential-dump tell' }
            elseif (Test-IsUserWritablePath $src) { $ev += ' - source in user-writable path' }
            else { $ev += ' - target in user-writable path' }
        } else {
            $sev = 'medium'
            $ev += ' - cross-boundary remote thread (no privilege context, review)'
        }
        & $find 'Cross-process injection (remote thread)' $sev "$src -> $tgt" $ev 'T1055'
    }
    & $trace 'R28' 'cross-process injection (Sysmon EID 8)' "sysmon_remote_thread: $($r28In.Count) rows"

    # ---------- R29: C2-style named pipes (Sysmon EID 17/18) ----------
    # Known C2 pipe families = high; any pipe created by a process in a user-writable path = medium.
    # (Sysmon logs PipeName without the \\.\pipe\ prefix; families match anywhere in the name)
    # v2.80 (F4): separate dedupe tables + caps per class - the old shared counter let 40+
    # medium rows exhaust the loop (break) before older HIGH C2-pipe rows were ever classified.
    $r29SeenHi = @{}
    $r29SeenMed = @{}
    $c2PipePat = '(?i)msagent_[0-9a-f]|mssecsms|pipy_[0-9a-f]|postex_[0-9a-f]|status_[0-9a-f]{4}'
    $r29In = @(Import-CaseCsv 'sysmon_pipes')
    foreach ($r in $r29In) {
        $pipe = "$($r.PipeName)"
        if (-not $pipe) { continue }
        $verb = 'seen'
        if ("$($r.EventId)" -eq '17') { $verb = 'created' } elseif ("$($r.EventId)" -eq '18') { $verb = 'connected' }
        if ($pipe -match $c2PipePat) {
            if ($r29SeenHi.ContainsKey($pipe.ToLower())) { continue }
            $r29SeenHi[$pipe.ToLower()] = $true
            if ($r29SeenHi.Count -gt 20) { continue }
            & $find 'C2-style named pipe (known C2 family)' 'high' $pipe "pipe '$pipe' $verb by $($r.Image) - Cobalt Strike-class SMB beacon channel" 'T1095'
            continue
        }
        if ("$($r.EventId)" -ne '17') { continue }
        if (Test-IsUserWritablePath "$($r.Image)") {
            $key = "$pipe|$($r.Image)".ToLower()
            if ($r29SeenMed.ContainsKey($key)) { continue }
            $r29SeenMed[$key] = $true
            if ($r29SeenMed.Count -gt 40) { continue }
            & $find 'Named pipe created from user-writable path' 'medium' $pipe "pipe '$pipe' created by $($r.Image) - review (C2 channels and stagers often live here)" 'T1095'
        }
    }
    & $trace 'R29' 'C2-style named pipes (Sysmon EID 17/18)' "sysmon_pipes: $($r29In.Count) rows"

    # ---------- R30: process image tampering (Sysmon EID 25 - hollowing / herpaderp) ----------
    # Sysmon fires this itself on an in-memory image swap: near-zero FP, no heuristics.
    $r30N = 0
    $r30In = @(Import-CaseCsv 'sysmon_proc_tamper')
    foreach ($r in $r30In) {
        $r30N++
        & $find 'Process image tampering (hollowing)' 'high' "$($r.Image)" "Sysmon EID 25 at $($r.Time): image of $(& { param($i) try { Split-Path $i -Leaf } catch { $i } } $r.Image) (pid $($r.ProcessId)) was swapped in memory$(if ("$($r.Type)") { " (type $($r.Type))" }) - classic hollowing/herpaderp" 'T1055.012'
        if ($r30N -ge 20) { break }
    }
    & $trace 'R30' 'process image tampering (Sysmon EID 25)' "sysmon_proc_tamper: $($r30In.Count) rows"

    # ---------- R31: direct volume access (Sysmon EID 9 RawAccessRead) ----------
    # Raw \\.\ reads bypass file auditing: locked-hive credential theft (SAM/NTDS) or anti-forensics.
    $r31Seen = @{}
    $r31In = @(Import-CaseCsv 'sysmon_raw_access')
    foreach ($r in $r31In) {
        $img = "$($r.Image)"
        if (-not $img) { continue }
        $key = "$img|$($r.Device)".ToLower()
        if ($r31Seen.ContainsKey($key)) { continue }
        $r31Seen[$key] = $true
        if ($r31Seen.Count -gt 20) { break }
        if (Test-IsUserWritablePath $img) {
            & $find 'Direct volume access (raw \\.\ read)' 'high' $img "$($r.Time): $img read $($r.Device) raw - locked-hive credential theft / anti-forensics lead" 'T1006'
        } else {
            & $find 'Direct volume access (raw \\.\ read)' 'medium' $img "$($r.Time): $img read $($r.Device) raw - verify expectation (backup/AV tools do this legitimately)" 'T1006'
        }
    }
    & $trace 'R31' 'direct volume access (Sysmon EID 9)' "sysmon_raw_access: $($r31In.Count) rows"

    # ---------- R32: WMI permanent event subscription (Sysmon EID 19/20/21) ----------
    # Filter+consumer+binding registration = the classic APT persistence; deduped per name.
    $r32Seen = @{}
    $r32In = @(Import-CaseCsv 'sysmon_wmi')
    foreach ($r in $r32In) {
        $nm = if ("$($r.Name)") { "$($r.Name)" } elseif ("$($r.Consumer)") { "$($r.Consumer)" } else { "$($r.Filter)" }
        if (-not $nm) { continue }
        $key = $nm.ToLower()
        if ($r32Seen.ContainsKey($key)) { continue }
        $r32Seen[$key] = $true
        if ($r32Seen.Count -gt 20) { break }
        $detail = "$($r.Time): WMI subscription '$nm' registered by $($r.Image)"
        if ("$($r.Query)") { $detail += " | filter query: $($r.Query)" }
        if ("$($r.Destination)") { $detail += " | consumer dest: $($r.Destination)" }
        & $find 'WMI event subscription persistence' 'high' $nm "$detail - verify the consumer payload (legit software uses this rarely)" 'T1546.003'
    }
    & $trace 'R32' 'WMI event subscription (Sysmon EID 19/20/21)' "sysmon_wmi: $($r32In.Count) rows"

    # ---------- R33: Sysmon configuration change (EID 16 - cannot be filtered) ----------
    # Someone retuning/disabling Sysmon mid-incident is anti-forensics; the raw CSV carries it.
    $r33In = @(Import-CaseCsv 'sysmon_events')
    foreach ($r in $r33In) {
        if ("$($r.Id)" -ne '16') { continue }
        & $find 'Sysmon configuration changed' 'high' 'Sysmon' "$($r.TimeCreated): Sysmon service configuration change observed - anti-forensics tell (T1562.001); compare the copied config snapshot in raw\context with the endpoint's expectations" 'T1562.001'
        break
    }
    & $trace 'R33' 'Sysmon configuration change (EID 16)' "sysmon_events: $($r33In.Count) rows"

    # ---------- R34: alternate data streams on executables (v2.62 - stager/stash spot) ----------
    # Non-Zone.Identifier ADS on a PE = payload riding next to a signed binary; inspect with dir /r.
    $r34In = @(Import-CaseCsv 'ads_findings')
    foreach ($r in $r34In) {
        & $find 'ADS on executable file' 'medium' "$($r.Path)" "non-Zone.Identifier alternate data stream '$($r.Stream)' ($($r.Length) bytes) on an executable - inspect with dir /r (T1564.004)" 'T1564.004'
    }
    & $trace 'R34' 'ADS on executables' "ads_findings: $($r34In.Count) rows"

    # ---------- R35: webshell content heuristics (v2.62 - report-only medium, verify vs baseline) ----------
    $r35In = @(Import-CaseCsv 'webshell_candidates')
    foreach ($r in $r35In) {
        & $find 'Webshell content heuristics' 'medium' (Split-Path "$($r.Path)" -Leaf) "$($r.Path) modified $($r.Modified) matches webshell heuristics ($($r.Matches)) - verify against the source-control/deployment baseline" 'T1505.003'
    }
    & $trace 'R35' 'webshell content heuristics' "webshell_candidates: $($r35In.Count) rows"

    # ---------- R36: Levenshtein masquerade (v2.81 - lookalike names of system binaries) ----------
    $r36Crit = @('svchost.exe', 'csrss.exe', 'lsass.exe', 'winlogon.exe', 'wininit.exe', 'smss.exe', 'explorer.exe', 'rundll32.exe', 'regsvr32.exe', 'dllhost.exe', 'conhost.exe', 'taskhostw.exe', 'spoolsv.exe', 'mshta.exe', 'msiexec.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'dwm.exe')
    $r36Hits = New-Object System.Collections.Generic.List[object]
    $r36Seen = @{}
    $r36In = 0
    $r36SysRe = '(?i)^[a-z]:\\windows\\(system32|syswow64|sysnative)\\'
    foreach ($r36Src in @('amcache', 'prefetch_parsed', 'processes', 'bam_lastexec')) {
        $r36Rows = @(Import-CaseCsv $r36Src)
        $r36In += $r36Rows.Count
        foreach ($r in $r36Rows) {
            try {
                $r36Raw = $null
                foreach ($r36Col in @('Path', 'Executable', 'FullPath', 'Name', 'App', 'ApplicationName')) {
                    $r36P = $r.PSObject.Properties[$r36Col]
                    if ($r36P -and $r36P.Value) { $r36Raw = "$($r36P.Value)".Trim(); break }
                }
                if (-not $r36Raw) { continue }
                $r36Leaf = (Split-Path $r36Raw -Leaf).ToLower()
                if ($r36Leaf -match '\.dll$') { continue }
                if ($r36Leaf -notmatch '\.[a-z0-9]+$') { continue }
                $r36Key = "$r36Src|$r36Leaf"
                if ($r36Seen.ContainsKey($r36Key)) { continue }
                $r36Seen[$r36Key] = $true
                if ($r36Crit -contains $r36Leaf) { continue }
                $r36Best = 99; $r36Near = $null
                foreach ($c in $r36Crit) {
                    $d = Get-LevenshteinDistance $r36Leaf $c
                    if ($d -lt $r36Best) { $r36Best = $d; $r36Near = $c }
                    if ($r36Best -le 1) { break }
                }
                if ($r36Best -ge 1 -and $r36Best -le 2) {
                    $null = $r36Hits.Add(@{ Src = $r36Src; Leaf = $r36Leaf; Path = $r36Raw; Crit = $r36Near; Dist = $r36Best })
                }
            } catch { }
        }
    }
    $r36Emitted = 0
    foreach ($h in $r36Hits.ToArray()) {
        if ($r36Emitted -ge 12) { break }
        $r36Path = "$($h.Path)"
        # v2.82: deterministic probing - amcache/mft device paths resolve to their Windows
        # form (focus-engine convention), and a bare name must NOT probe against the
        # analyst's current directory (that CWD lottery flipped severities between runs)
        if ($r36Path -match '(?i)^\\device\\harddiskvolume\d+(\\.*)$') { $r36Path = "C:$($Matches[1])" }
        $r36Bare = ($r36Path -notmatch '[\\/]')
        $r36Sig = $null
        if (-not $r36Bare -and (Test-Path -LiteralPath $r36Path -ErrorAction SilentlyContinue)) {
            try { $r36Sig = Get-AuthenticodeSignature -LiteralPath $r36Path } catch { $r36Sig = $null }
        }
        $r36Sys = ($r36Path -match $r36SysRe)
        if ($r36Sys -and $r36Sig -and "$($r36Sig.Status)" -eq 'Valid') { continue } # signed copy in a system dir = the real binary
        $r36SigTxt = if ($r36Bare) { 'no executable path in evidence (name-only match)' } elseif ($r36Sig) { "signature $($r36Sig.Status)" } else { 'signature uncheckable (file missing or no signature data)' }
        $r36Sev = if ($r36Bare) { 'low' } elseif ((Test-IsUserWritablePath $r36Path) -or -not $r36Sig) { 'high' } else { 'low' }
        & $find 'Lookalike system binary (Levenshtein near-name)' $r36Sev $r36Path "near '$($h.Crit)' (distance $($h.Dist)), $r36Path, $r36SigTxt" 'T1036.005'
        $r36Emitted++
    }
    & $trace 'R36' 'lookalike system binary (Levenshtein near-name)' "amcache+prefetch_parsed+processes+bam_lastexec: $r36In rows -> $($r36Hits.Count) near-name hits -> $r36Emitted emitted"

    # ---------- R37: ShimCache temporal correlation (v2.81 - report-only, NO verdict signal) ----------
    # Module 5.4 exports chainsaw's shimcache as execution_timeline: 0-numbered summary row(s)
    # plus 1..N cache entries in insertion order. (a) A cache entry whose last_modified_ts is
    # OLDER than the previous entry's = order violation (timestomping or cache manipulation).
    # (b) An entry executed from a user-writable path that no other execution source
    # (amcache/prefetch/BAM) ever saw = scrub survivor - possible cache scrubbing around it.
    # Both report-only by design: temporal order noise is real but low-precision.
    $r37In = @(Import-CaseCsv 'execution_timeline')
    $r37Entries = New-Object System.Collections.Generic.List[object]
    foreach ($r in $r37In) {
        if ("$($r.'Entry Type')" -ne 'ShimcacheFileEntry') { continue }
        $r37Path = "$($r.'File Path')".Trim()
        if (-not $r37Path) { continue }
        # sanity guard: rows without a usable position are summary/malformed - unusable by either sub-rule
        $r37Ten = 0
        if (-not [int]::TryParse("$($r.'Timeline Entry Number')", [ref]$r37Ten)) { continue }
        # last_modified_ts lives only inside the Raw Entry JSON - regex beats per-row ConvertFrom-Json on 5.1
        $r37Ts = $null
        $r37M = [regex]::Match("$($r.'Raw Entry')", '(?i)"last_modified_ts"\s*:\s*"([^"]+)"')
        if ($r37M.Success) {
            $r37Dt = [datetime]::MinValue
            if ([datetime]::TryParse($r37M.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$r37Dt)) { $r37Ts = $r37Dt }
        }
        $null = $r37Entries.Add(@{ Path = $r37Path; Ts = $r37Ts })
    }
    # (a) unparseable timestamps are skipped WITHOUT updating the baseline (a broken row must not
    # become the comparison point - the chain simply bridges over it to the last good entry)
    $r37Viol = 0
    $r37Prev = $null
    foreach ($e in $r37Entries.ToArray()) {
        if ($null -eq $e.Ts) { continue }
        if ($null -ne $r37Prev -and $e.Ts -lt $r37Prev) { $r37Viol++ }
        $r37Prev = $e.Ts
    }
    if ($r37Viol -gt 0) {
        & $find 'ShimCache order violation' 'low' 'execution_timeline' "ShimCache order violation: $r37Viol out-of-order entries (timestomping or cache manipulation)" 'T1070.006'
    }
    & $trace 'R37' 'ShimCache order violation' "execution_timeline: $($r37In.Count) rows -> $($r37Entries.Count) entries -> $r37Viol out-of-order"
    # (b) distinct paths (first occurrence keeps original case for the report entity); a path is
    # corroborated when its FULL path or its LEAF name appears in any other execution source
    $r37Seen = @{}
    $r37Paths = New-Object System.Collections.Generic.List[string]
    foreach ($e in $r37Entries.ToArray()) {
        $r37Key = "$($e.Path)".ToLower()
        if ($r37Seen.ContainsKey($r37Key)) { continue }
        $r37Seen[$r37Key] = $true
        $null = $r37Paths.Add($e.Path)
    }
    $r37Full = @{}
    $r37Leaf = @{}
    foreach ($r37Src in @('amcache', 'prefetch_parsed', 'bam_lastexec')) {
        foreach ($r in @(Import-CaseCsv $r37Src)) {
            foreach ($pn in @($r.PSObject.Properties.Name)) {
                if ($pn -notmatch '(?i)path|executable|app|fullname|application') { continue }
                $r37Val = "$($r.$pn)".Trim()
                if (-not $r37Val) { continue }
                $r37Full[$r37Val.ToLower()] = $true
                try { $r37Leaf[(Split-Path $r37Val -Leaf).ToLower()] = $true } catch { }
            }
        }
    }
    $r37Surv = New-Object System.Collections.Generic.List[string]
    foreach ($p in $r37Paths.ToArray()) {
        if (-not (Test-IsUserWritablePath $p)) { continue }
        if ($r37Full.ContainsKey($p.ToLower())) { continue }
        $pLeaf = ''
        try { $pLeaf = (Split-Path $p -Leaf).ToLower() } catch { }
        if ($pLeaf -and $r37Leaf.ContainsKey($pLeaf)) { continue }
        $null = $r37Surv.Add($p)
    }
    $r37Emit = [Math]::Min(6, $r37Surv.Count)
    for ($i = 0; $i -lt $r37Emit; $i++) {
        & $find 'ShimCache scrub survivor' 'medium' $r37Surv[$i] 'executed (ShimCache) but absent from all execution corroboration sources - possible cache scrubbing' 'T1070.006'
    }
    & $trace 'R37' 'ShimCache scrub survivor' "corroboration amcache+prefetch_parsed+bam_lastexec: $($r37Paths.Count) paths -> $($r37Surv.Count) survivors -> $r37Emit emitted"

    # ---------- R38: execution hour-of-day stacking (v2.81 - report-only, NO verdict signal) ----------
    # First-seen hour-of-day per distinct binary (deduped on src|leaf; a src|leaf only becomes
    # seen once a row with a usable timestamp carries it, so broken timestamps never poison the
    # slot). Off-hours bursts (20:00-06:59) and mass .exe staging inside one hour are timing
    # tells for hands-on-keyboard / staging activity - timing alone is low-precision, so both
    # stay low / report-only. The report's hour histogram recomputes the same buckets itself.
    $r38Seen = @{}
    $r38All = @{}   # hour -> @{ leaf = $true } - every first-seen binary (burst counter)
    $r38Exe = @{}   # hour -> @{ leaf = $true } - .exe only (mass-staging counter)
    $r38In = 0
    foreach ($r38Src in @('amcache', 'prefetch_parsed', 'security_proc_events', 'sysmon_proc_create')) {
        $r38Rows = @(Import-CaseCsv $r38Src)
        $r38In += $r38Rows.Count
        foreach ($r in $r38Rows) {
            try {
                $r38Raw = $null
                foreach ($r38Col in @('Path', 'Executable', 'FullPath', 'Name', 'ApplicationName')) {
                    $r38P = $r.PSObject.Properties[$r38Col]
                    if ($r38P -and $r38P.Value) { $r38Raw = "$($r38P.Value)".Trim(); break }
                }
                if (-not $r38Raw) { continue }
                $r38Leaf = (Split-Path $r38Raw -Leaf).ToLower()
                if (-not $r38Leaf) { continue }
                $r38Ts = $null
                foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$|lastrun|^time' })) {
                    $r38Dt = Get-InvariantDate "$($r.$pn)"
                    if ($r38Dt -gt [datetime]::MinValue) { $r38Ts = $r38Dt; break }
                }
                if (-not $r38Ts) { continue }
                $r38Key = "$r38Src|$r38Leaf"
                if ($r38Seen.ContainsKey($r38Key)) { continue }
                $r38Seen[$r38Key] = $true
                $r38H = $r38Ts.Hour
                if (-not $r38All.ContainsKey($r38H)) { $r38All[$r38H] = @{}; $r38Exe[$r38H] = @{} }
                $r38All[$r38H][$r38Leaf] = $true
                if ($r38Leaf.EndsWith('.exe')) { $r38Exe[$r38H][$r38Leaf] = $true }
            } catch { }
        }
    }
    $r38Burst = 0
    foreach ($r38H in @(0..23)) {
        if (-not $r38All.ContainsKey($r38H)) { continue }
        if ($r38H -lt 20 -and $r38H -ge 7) { continue }
        $r38N = $r38All[$r38H].Count
        if ($r38N -lt 8) { continue }
        $r38Win = '{0:00}:00-{0:00}:59' -f $r38H
        & $find 'Off-hours execution burst' 'low' $r38Win "$r38N distinct binaries first seen $r38Win (off-hours window 20:00-06:59)" ''
        $r38Burst++
    }
    $r38Stage = 0
    foreach ($r38H in @(0..23)) {
        if (-not $r38Exe.ContainsKey($r38H)) { continue }
        $r38N = $r38Exe[$r38H].Count
        if ($r38N -lt 10) { continue }
        $r38Win = '{0:00}:00-{0:00}:59' -f $r38H
        & $find 'Mass binary staging' 'low' $r38Win "$r38N first-seen .exe binaries staged $r38Win" ''
        $r38Stage++
    }
    & $trace 'R38' 'execution hour-of-day stacking' "amcache+prefetch_parsed+security_proc_events+sysmon_proc_create: $r38In rows -> $($r38Seen.Count) first-seen binaries -> $r38Burst off-hours burst + $r38Stage staging findings"

    # ---------- R45: TaskCache tamper - hidden/orphaned scheduled tasks (v2.83) ----------
    $r45In = @(Import-CaseCsv 'scheduled_taskcache')
    foreach ($r in $r45In) {
        $r45Flags = "$($r.Flags)"
        if (-not $r45Flags) { continue }
        $r45G = "$($r.Guid)"
        if ($r45Flags -match 'SD-MISSING') {
            & $find 'Hidden scheduled task (TaskCache SD value stripped)' 'high' "Tasks\$r45G" "no SD value - invisible to schtasks/GUI but still runs (deleted Tree+XML does not unload a loaded task until reboot)" 'T1053.005'
        } elseif ($r45Flags -match 'ORPHANED') {
            & $find 'Orphaned scheduled task cache entry' 'medium' "Tasks\$r45G" "no Tree\GID link - deleted from the UI but still in TaskCache, or planted" 'T1053.005'
        }
    }
    & $trace 'R45' 'TaskCache ghost/hidden tasks' "scheduled_taskcache: $($r45In.Count) keys"

    # ---------- R46: ntds.dit access via ESENT 325/326 (v2.83) ----------
    $r46In = @(Import-CaseCsv 'esent_ntds')
    foreach ($r in $r46In) {
        # BackupPattern arrives from Export-Csv as the STRING 'True'/'False' - 'False' is
        # truthy in PS, so compare text, never boolean-coerce
        if ("$($r.BackupPattern)" -eq 'True') {
            & $find 'ntds.dit accessed (backup-pattern ESENT)' 'low' "$($r.Time)" "ESENT $($r.EventId) with backup engine pattern - verify the backup schedule covers this host" 'T1003.003'
        } else {
            & $find 'ntds.dit accessed (ESENT 325/326)' 'high' "$($r.Time)" "non-backup pattern - possible AD database theft prep (ntdsutil IFM / custom tooling): $($r.Message)" 'T1003.003'
        }
    }
    & $trace 'R46' 'ESENT ntds.dit access' "esent_ntds: $($r46In.Count) rows"

    Save-Rows -Name 'hunt_findings' -Rows $out.ToArray()
    $hi = @($out | Where-Object { $_.Severity -eq 'high' }).Count
    if ($out.Count -gt 0) {
        Write-CaseLog "    hunt findings: $($out.Count) ($hi high) -> csv\hunt_findings.csv" $(if ($hi -gt 0) { 'Red' } else { 'Yellow' })
        foreach ($f in ($out | Where-Object { $_.Severity -eq 'high' } | Select-Object -First 4)) { Write-CaseLog "      [$($f.Severity)] $($f.Rule) - $($f.Entity)" 'Red' }
    } else {
        Write-CaseLog '    hunt findings: none - all techniques clean' 'Gray'
    }
}

function New-LoggingGaps {
    $rows = @()
    $meanings = @{ 6005 = 'Event logging STARTED'; 6006 = 'Event logging STOPPED (shutdown)'; 104 = 'Event log CLEARED'; 1102 = 'Security audit log CLEARED' }
    foreach ($name in @('system_events', 'security_events')) {
        foreach ($r in (Import-CaseCsv $name)) {
            if (@(6005, 6006, 104, 1102) -contains $r.Id) {
                $rows += [pscustomobject]@{ Time = $r.TimeCreated; EventId = $r.Id; Meaning = $meanings[[int]$r.Id]; Source = $name; Message = $r.Message }
            }
        }
    }
    $gapsFile = Join-Path $RawDir 'analysis\evtx_gaps.txt'
    if ((Test-Path $gapsFile) -and (Get-Item $gapsFile).Length -gt 0) {
        $rows += [pscustomobject]@{ Time = ''; EventId = ''; Meaning = 'chronological gaps detected in evtx (see raw\analysis\evtx_gaps.txt)'; Source = 'chainsaw'; Message = '' }
    }
    Save-Rows -Name 'logging_gaps' -Rows $rows
    $bad = @($rows | Where-Object { @(104, 1102) -contains $_.EventId })
    if ($bad.Count -gt 0) { Write-CaseLog "    LOGGING GAPS: $($bad.Count) clear/down events - check csv\logging_gaps.csv" 'Red' }
}

function New-SiemExport {
    $lines = New-Object System.Collections.Generic.List[string]
    $base = @{ host = $Computer; tool = "Ophira v$ScriptVersion"; caseid = $script:CurrentCaseID }
    foreach ($p in (Import-CaseCsv 'flash_process_scored')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'proc_verdict'; $o['host'] = $base.host; $o['name'] = $p.Name; $o['verdict'] = $p.Verdict; $o['score'] = [int]$p.Score; $o['path'] = $p.Path; $o['evidence'] = $p.Evidence; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($h in ((Import-CaseCsv 'flash_ioc_hits') + (Import-CaseCsv 'ioc_hits_amcache'))) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'ioc_hit'; $o['host'] = $base.host; $o['type'] = $h.Type; $o['indicator'] = $h.Indicator; $o['where'] = $h.Where; $o['application'] = $h.Application; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'security_bruteforce_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'bruteforce'; $o['host'] = $base.host; $o['src_ip'] = $b.SourceIp; $o['failures'] = [int]$b.FailedLogons; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
        if ("$($r.Level)" -match 'crit|^high$') {
            $rule = if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } else { $r.Alert }
            $o = [ordered]@{}; $o['ts'] = "$($r.Timestamp)"; $o['kind'] = 'sigma_alert'; $o['host'] = $base.host; $o['level'] = $r.Level; $o['rule'] = $rule; $o['eventid'] = $r.EventID; $o['details'] = $r.Details; $o['caseid'] = $base.caseid
            $lines.Add(($o | ConvertTo-Json -Compress))
        }
    }
    foreach ($d in (Import-CaseCsv 'delta_new')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'delta_new'; $o['host'] = $base.host; $o['type'] = $d.Type; $o['item'] = $d.Item; $o['detail'] = $d.Detail; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'beacon_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'beacon'; $o['host'] = $base.host; $o['severity'] = $b.Severity; $o['process'] = $b.Process; $o['dest_ip'] = $b.RemoteIp; $o['dest_port'] = $b.Port; $o['interval_sec'] = $b.MedianIntervalSec; $o['regularity'] = $b.Regularity; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'dns_beacon_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'dns_beacon'; $o['host'] = $base.host; $o['severity'] = $b.Severity; $o['process'] = $b.Process; $o['domain'] = $b.Domain; $o['resolved_ip'] = $b.ResolvedIp; $o['interval_sec'] = $b.MedianIntervalSec; $o['regularity'] = $b.Regularity; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($l in (Import-CaseCsv 'loldrivers_hits')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'loldriver'; $o['host'] = $base.host; $o['status'] = $l.Status; $o['driver'] = $l.Name; $o['path'] = $l.Path; $o['sha256'] = $l.SHA256; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($u in (Import-CaseCsv 'usn_write_bursts')) {
        $o = [ordered]@{}; $o['ts'] = "$($u.WindowStart)"; $o['kind'] = 'mass_modification'; $o['host'] = $base.host; $o['write_events'] = [int]"$($u.WriteEvents)"; $o['distinct_files'] = [int]"$($u.DistinctFiles)"; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($m in (Import-CaseCsv 'memory_malfind')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'malfind'; $o['host'] = $base.host; $o['process'] = $m.Process; $o['pid'] = $m.PID; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'ioc_hits_browser')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'browser_ioc'; $o['host'] = $base.host; $o['indicator'] = $b.Indicator; $o['url'] = $b.URL; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($h in (Import-CaseCsv 'hunt_findings')) {
        if (@('high', 'medium') -notcontains "$($h.Severity)") { continue }
        $o = [ordered]@{}; $o['ts'] = "$($h.Found)"; $o['kind'] = 'hunt_finding'; $o['host'] = $base.host; $o['severity'] = $h.Severity; $o['rule'] = $h.Rule; $o['entity'] = $h.Entity; $o['attack'] = $h.Attck; $o['evidence'] = $h.Evidence; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    if ($script:Verdict) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'verdict'; $o['host'] = $base.host; $o['level'] = $script:Verdict.Level; $o['rank'] = $script:Verdict.LevelRank; $o['confidence'] = $script:Verdict.ConfidencePercent; $o['signals'] = @($script:Verdict.Signals).Count; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    if ($lines.Count -eq 0) { return }
    $out = Join-Path $CaseDir 'siem_export.ndjson'
    $lines | Set-Content -LiteralPath $out -Encoding UTF8
    Write-CaseLog "    siem export: $($lines.Count) records -> siem_export.ndjson" 'DarkGray'
}

function New-AttackLayer {
    # MITRE ATT&CK Navigator layer (https://navigator.mitre.org) from hayabusa MitreTags
    $tech = @{}
    foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
        foreach ($m in [regex]::Matches("$($r.MitreTags)", 'T\d{4}(?:\.\d{3})?')) {
            $k = $m.Value
            if (-not $tech.ContainsKey($k)) { $tech[$k] = 0 }
            $tech[$k]++
        }
    }
    if ($tech.Count -eq 0) { return }
    $techniques = @($tech.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ techniqueID = $_; score = $tech[$_]; comment = "$($tech[$_]) Sigma detection(s)" } })
    $layer = [pscustomobject]@{
        name        = "Ophira - $Computer$(if ($script:CurrentCaseID) { " ($($script:CurrentCaseID))" })"
        domain      = 'enterprise-attack'
        description = "Ophira v$ScriptVersion Sigma detections (hayabusa MitreTags)"
        versions    = @{ navigator = '4.9'; layer = '4.5' }
        techniques  = $techniques
        layout      = @{ layout = 'side'; aggregateFunction = 'sum' }
    }
    $layer | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'attack_layer.json') -Encoding UTF8
    Write-CaseLog "    ATT&CK Navigator layer: $($tech.Count) techniques -> attack_layer.json" 'DarkGray'
}

function Invoke-DeltaCompare {
    param([string]$Path)
    $baseline = $null
    if ($Path) {
        if (Test-Path -LiteralPath $Path) { $baseline = Get-Item -LiteralPath $Path }
        else { Write-CaseLog "    delta: -DeltaPath not found ($Path)" 'DarkYellow'; return }
    } else {
        $root = Get-KitRoot
        $cands = @(Get-ChildItem -Path $root -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $StartTime.AddSeconds(-5) } | Sort-Object LastWriteTime -Descending)
        if ($cands.Count -eq 0) {
            $cands = @(Get-ChildItem -Path $root -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $CaseName -and (Test-Path (Join-Path $_.FullName 'case.json')) } | Sort-Object LastWriteTime -Descending)
        }
        if ($cands.Count -gt 0) { $baseline = $cands[0] }
    }
    if (-not $baseline) { Write-CaseLog "    delta: no previous collection found - this run becomes the baseline for next time" 'DarkGray'; return }
    $prevDir = $baseline.FullName
    $tmp = $null
    if ($baseline -is [System.IO.FileInfo]) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("delta_" + $baseline.BaseName)
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($baseline.FullName, $tmp)
            $prevDir = $tmp
        } catch { Write-CaseLog "    delta: cannot extract baseline" 'DarkYellow'; return }
    }
    $prevCsv = {
        param($n)
        $f = Join-Path $prevDir "csv\$n"
        if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) { try { return @(Import-Csv $f) } catch { return @() } }
        return @()
    }
    $prevCutoff = $null
    $prevCaseJson = Join-Path $prevDir 'case.json'
    if (Test-Path $prevCaseJson) { try { $pc = Get-Content $prevCaseJson -Raw | ConvertFrom-Json; $prevCutoff = [datetime]$pc.StartedUTC } catch { } }
    $new = @()
    $prevProcPaths = @{}
    foreach ($r in (& $prevCsv 'processes.csv')) { if ($r.Path) { $prevProcPaths["$($r.Path)".ToLower()] = $true } }
    foreach ($r in (Import-CaseCsv 'processes_flagged')) {
        if ($r.Path -and -not $prevProcPaths.ContainsKey("$($r.Path)".ToLower())) {
            $new += [pscustomobject]@{ Type = 'NewFlaggedProcess'; Item = $r.Name; Detail = "$($r.Path) [$($r.Flags)]" }
        }
    }
    $prevTasks = @{}
    foreach ($r in (& $prevCsv 'scheduled_tasks.csv')) { $prevTasks["$($r.Path)$($r.Name)"] = $true }
    foreach ($r in (Import-CaseCsv 'scheduled_tasks_flagged')) {
        if (-not $prevTasks.ContainsKey("$($r.Path)$($r.Name)")) { $new += [pscustomobject]@{ Type = 'NewFlaggedTask'; Item = $r.Name; Detail = "$($r.Actions)" } }
    }
    $prevSvc = @{}
    foreach ($r in (& $prevCsv 'services.csv')) { $prevSvc["$($r.Name)"] = $true }
    foreach ($r in (Import-CaseCsv 'services_flagged')) {
        if (-not $prevSvc.ContainsKey("$($r.Name)")) { $new += [pscustomobject]@{ Type = 'NewFlaggedService'; Item = $r.Name; Detail = "$($r.PathName)" } }
    }
    $prevAuto = @{}
    foreach ($r in (& $prevCsv 'autoruns_runkeys.csv')) { $prevAuto["$($r.Name)=$($r.Value)"] = $true }
    foreach ($r in (Import-CaseCsv 'autoruns_runkeys')) {
        if (-not $prevAuto.ContainsKey("$($r.Name)=$($r.Value)")) { $new += [pscustomobject]@{ Type = 'NewAutorun'; Item = $r.Name; Detail = "$($r.Value)" } }
    }
    if ($prevCutoff) {
        foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
            if ("$($r.Level)" -match 'crit|^high$') {
                $ts = $null
                try { $ts = [datetime]::Parse("$($r.Timestamp)", [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
                if ($ts -and $ts -gt $prevCutoff) {
                    $rule = if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } else { $r.Alert }
                    $new += [pscustomobject]@{ Type = 'NewSigmaAlert'; Item = "$rule"; Detail = "$($r.Timestamp) [$($r.Level)]" }
                }
            }
        }
    }
    Save-Rows -Name 'delta_new' -Rows $new
    $script:DeltaCount = $new.Count
    $script:DeltaBaseline = $baseline.Name
    Write-CaseLog "    delta: $($new.Count) NEW findings vs $($baseline.Name)" $(if ($new.Count -gt 0) { 'Yellow' } else { 'Gray' })
    if ($tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-CompromiseVerdict {
    # Correlates all case findings into one verdict + coverage-weighted confidence.
    # Levels (rank): 4=COMPROMISED 3=LIKELY COMPROMISED 2=SUSPICIOUS 1=NO EVIDENCE OF COMPROMISE 0=INCONCLUSIVE
    $iocLive = Import-CaseCsv 'flash_ioc_hits'
    $iocAmc = Import-CaseCsv 'ioc_hits_amcache'
    $yara = Import-CaseCsv 'yara_hits'
    $hay = Import-CaseCsv 'hayabusa_timeline'
    # v2.55: same dedupe + self-noise filter as the report so verdict and report agree
    if (Get-Command Remove-SigmaDuplicateEvents -ErrorAction SilentlyContinue) {
        $hay = @(Remove-SigmaDuplicateEvents $hay | Where-Object { -not (Test-SigmaSelfNoise $_) })
    }
    $proc = Import-CaseCsv 'flash_process_scored'
    $def = Import-CaseCsv 'defender_threats'
    $gaps = Import-CaseCsv 'logging_gaps'
    $brute = Import-CaseCsv 'security_bruteforce_candidates'
    $beacons = Import-CaseCsv 'beacon_candidates'
    $dnsBeacons = Import-CaseCsv 'dns_beacon_candidates'
    $lol = Import-CaseCsv 'loldrivers_hits'
    $usnBursts = Import-CaseCsv 'usn_write_bursts'
    $asep = Import-CaseCsv 'asep_sweep'
    $memMf = Import-CaseCsv 'memory_malfind'
    $browserIoc = Import-CaseCsv 'ioc_hits_browser'
    # v2.83 (R45/R46): TaskCache tamper + ntds.dit access
    $taskCache = Import-CaseCsv 'scheduled_taskcache'
    $esentNtds = Import-CaseCsv 'esent_ntds'

    $levelNames = @{ 4 = 'COMPROMISED'; 3 = 'LIKELY COMPROMISED'; 2 = 'SUSPICIOUS'; 1 = 'NO EVIDENCE OF COMPROMISE'; 0 = 'INCONCLUSIVE' }

    $signals = New-Object System.Collections.Generic.List[object]
    # v2.79 trace: one line per signal added / coverage category missing - the case log ALWAYS
    # carries them, the console shows them at -LogLevel Verbose only. Quiet path writes the log
    # directly instead of Write-CaseLog -NoConsole: harnesses stub Write-CaseLog without that
    # switch. Controller-side only (Invoke-RegenerateOutputs), so $CaseLog exists.
    $logQ = {
        param([string]$Msg)
        if ($script:Verbosity -ge 2) { Write-CaseLog $Msg 'DarkGray' }
        else { try { Add-Content -LiteralPath $CaseLog -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg) -Encoding UTF8 } catch { } }
    }
    function Add-Signal([string]$name, [int]$floor, [int]$count, [string]$detail) {
        if ($count -gt 0) {
            $signals.Add([pscustomobject]@{ Signal = $name; Weight = $floor; Count = $count; Detail = $detail })
            $vMsg = "verdict signal: $name (floor $floor x $count) - $("$detail" -replace '\s+', ' ')".Trim()
            if ($vMsg.Length -gt 180) { $vMsg = $vMsg.Substring(0, 177) + '...' }
            & $logQ $vMsg
        }
    }

    # v2.41 FP fix: Defender-channel sigma rows are excluded here - they are already covered
    # by the dedicated 'Defender detection history' signal (floor 2). Counting them twice let
    # ONE old Defender alert declare LIKELY COMPROMISED on clean systems (sigma-crit floor 3
    # + defender-history floor 2 double-counting the same underlying event).
    $hayNonDef = @($hay | Where-Object { "$($_.Channel)" -notmatch '(?i)^defender' })
    $hayCrit = @($hayNonDef | Where-Object { "$($_.Level)" -match 'crit' })
    $hayHigh = @($hayNonDef | Where-Object { "$($_.Level)" -match '^high$' })
    $hayHighRules = @($hayHigh | Group-Object RuleTitle).Count
    # v2.41 FP fix: a critical signal only reaches floor 3 (LIKELY COMPROMISED) when a STORM of
    # independent critical rules fires (>=3 events from >=2 distinct rules - real incidents trip
    # many rules at once). A single noisy crit rule (1-2 events, 1 rule) demotes to floor 2
    # SUSPICIOUS - visible, weighty, but not a compromise declaration on its own.
    $hayCritRules = @($hayCrit | Group-Object RuleTitle).Count
    $critFloor = if ($hayCrit.Count -ge 3 -and $hayCritRules -ge 2) { 3 } else { 2 }
    # v2.44 FP fix: same storm gate for high - one rule can never carry verdict weight at any
    # level. 196 events from ONE high rule is one noisy signature (e.g. 4648-explicit-logon
    # firing on an admin workstation's every remote PowerShell), not an incident. Multi-rule
    # corroboration (>=3 events from >=2 rules) earns floor 2; single-rule highs stay
    # report-only (weight 0 row keeps the story visible in the verdict).
    $highFloor = if ($hayHigh.Count -ge 3 -and $hayHighRules -ge 2) { 2 } else { 0 }
    # v2.64: score honesty - rows kept, gate applied at the signal (corroboration vars defined there)
    $procHighRows = @($proc | Where-Object { "$($_.Verdict)" -eq 'HIGH' })
    $procMed = @($proc | Where-Object { "$($_.Verdict)" -eq 'MEDIUM' }).Count
    $yaraHi = @($yara | Where-Object { "$($_.Severity)" -match '^(high|critical)$' }).Count
    $yaraMed = @($yara | Where-Object { "$($_.Severity)" -match '^medium$' }).Count
    # v2.80 FP fix: Meaning fallback is 'clear' ONLY - the old 'clear|stop' also matched benign
    # 6006 'Event logging STOPPED (shutdown)' rows, adding a phantom weight-2 tamper signal on
    # nearly every host. Real clears stay covered by EventId 1102/104 + the 'clear' Meaning.
    $gapTamper = @($gaps | Where-Object { "$($_.EventId)" -match '^(1102|104)$' -or "$($_.Meaning)" -match 'clear' }).Count
    $beaconHi = @($beacons | Where-Object { "$($_.Severity)" -match '^high$' }).Count
    $beaconMed = @($beacons | Where-Object { "$($_.Severity)" -match '^medium$' }).Count
    $dnsHi = @($dnsBeacons | Where-Object { "$($_.Severity)" -match '^high$' }).Count
    $dnsMed = @($dnsBeacons | Where-Object { "$($_.Severity)" -match '^medium$' }).Count
    # v2.83 (R45/R46): SD-stripped = strong anti-forensics; orphaned = suspicious; ntds only
    # weights the non-backup shape (VSS/wbengine rows are usually scheduled backups)
    $tcHidden = @($taskCache | Where-Object { "$($_.Flags)" -match 'SD-MISSING' })
    $tcOrphan = @($taskCache | Where-Object { "$($_.Flags)" -match 'ORPHANED' })
    $ntdsTheft = @($esentNtds | Where-Object { "$($_.BackupPattern)" -ne 'True' })
    $ntdsBackup = @($esentNtds | Where-Object { "$($_.BackupPattern)" -eq 'True' })
    $lolMal = @($lol | Where-Object { $_.Status -eq 'malicious' }).Count
    # v2.55: posture gaps + credential exposure now carry verdict weight (previously report-only).
    # v2.64: imported BEFORE the hunt filter so the EcsConfigs exclusion can cross-check posture.
    $posture = Import-CaseCsv 'posture'
    $postureBad = @($posture | Where-Object { "$($_.Status)" -eq 'BAD' })
    $credSweep = Import-CaseCsv 'credential_sweep'
    $hunt = Import-CaseCsv 'hunt_findings'
    $huntHi = @($hunt | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Rule)" -match 'Renamed LOLBin|side-load|Downloaded then executed|LSASS access|Office app spawned|proxy-execution|Admin-share|Defender (real-time|exclusion)|DCSync|Password spray|Web server spawned|Remote-access tunnel|ServiceDll tamper|authorized_keys|Svchost masquerade|Cross-process injection|C2-style named pipe|image tampering|Direct volume access|WMI event subscription|Sysmon configuration changed|Lookalike system binary' })
    # v2.64: EcsConfigs-only 5007 exclusion - Features\EcsConfigs is Defender's tamper-protected,
    # platform-managed cloud-config key (rewritten on every engine sync), NOT a user-set exclusion.
    # A 'Defender exclusion configuration changed' finding that only touches EcsConfigs paths is
    # dropped from the VERDICT input unless posture says real exclusions exist (the 'Defender
    # exclusions' check is WARN/BAD). The report keeps all hunt findings - this is verdict-input
    # honesty only.
    $postureExclusions = @($posture | Where-Object { "$($_.Check)" -match '(?i)Defender exclusion' -and "$($_.Status)" -ne 'GOOD' }).Count -gt 0
    $huntHi = @($huntHi | Where-Object {
        $hd = "$($_.Evidence)" # v2.64: hunt rows carry no Detail column - read Evidence only (the old Detail-prefix read was always empty)
        if ("$($_.Rule)" -notmatch '(?i)Defender exclusion' -or $hd -notmatch 'EcsConfigs' -or $postureExclusions) { return $true }
        # keep UNLESS every Defender registry path the finding mentions lives under EcsConfigs
        # (assumption: real 5007 value pairs are always separated by ' = '/'New value:'/'Old value:'
        # - two paths joined by a bare space would merge into one span)
        # v2.68 (B8): real 5007 Evidence is the whitespace-normalized event Detail (module 6.2
        # writes "$($e.Time): $($e.Detail)"), e.g. "Old value: HKLM\SOFTWARE\Microsoft\Windows
        # Defender\Diagnostics\LastKnownGoodPlatformLocation = C:\ProgramData\Microsoft\Windows
        # Defender\Platform\4.18.26080.4-0 New value: Default\..." and "New value:
        # HKLM\...\Windows Defender\Exclusions\Paths\C:\Program Files\Bad\svc.exe = 0x1". Paths
        # carry spaces/dots/colons/parens, so the capture runs from 'Windows Defender\' through
        # whole tokens INCLUDING single spaces, and stops only at a space that begins a message
        # separator (' = value', 'New value:', 'Old value:') or at ; | quotes. The old [\w\\]+
        # class truncated at the first colon ('...\Paths\C'), losing everything after 'C:' in a
        # quoted exclusion VALUE. The EcsConfigs decision reads only whether the capture's path
        # prefix passes through '\EcsConfigs\' - no space can precede that segment inside a
        # Defender path, so the span cannot flip the drop/keep outcome on real shapes.
        $hp = @([regex]::Matches($hd, '(?i)Windows Defender\\(?:[^\s;|''"]+|\s(?![=])(?!New value:)(?!Old value:))*') | ForEach-Object { $_.Value })
        -not (@($hp).Count -gt 0 -and @($hp | Where-Object { $_ -notmatch '\\EcsConfigs\\' }).Count -eq 0)
    })
    $usnBurstN = @($usnBursts).Count
    $rExt = ((@($usnBursts) | Where-Object { "$($_.RansomExt)" } | ForEach-Object { "$($_.RansomExt)" } | Sort-Object -Unique) -join ',')
    # ponytail: COM hijacks + StartupApproved excluded from the signal (per-user COM has many legit users, e.g. Teams/OneDrive); they stay report-visible
    $asepHotN = @($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' }).Count
    # v2.60 fix: module 8.15 writes Item/Detail/Risk - the old Severity/Description filter matched
    # nothing, so this floor-2 signal had silently never fired on any case
    $credMed = @($credSweep | Where-Object { "$($_.Risk)" -match '(?i)^high$' })

    Add-Signal 'IOC hit - historical execution (amcache SHA1)' 4 @($iocAmc).Count "near-certain true positive evidence"
    Add-Signal 'YARA hit - high/critical rule' 4 $yaraHi (($yara | Where-Object { "$($_.Severity)" -match '^(high|critical)$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - highly regular callbacks' 3 $beaconHi (($beacons | Where-Object { "$($_.Severity)" -match '^high$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp):$($_.Port) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'C2 DNS beaconing - highly regular domain queries' 3 $dnsHi (($dnsBeacons | Where-Object { "$($_.Severity)" -match '^high$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.Domain) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'Known-malicious driver on disk (LOLDrivers)' 2 $lolMal (($lol | Where-Object { $_.Status -eq 'malicious' } | Select-Object -First 3 | ForEach-Object { "$($_.Name): $($_.Path)" }) -join '; ')
    Add-Signal 'Security posture gaps' 1 @($postureBad).Count (($postureBad | ForEach-Object { "$($_.Check): $($_.Detail)" }) -join '; ') # v2.64: was $_.Setting - that column never existed, the detail lost the check name
    Add-Signal 'Credential material exposure' 2 @($credMed).Count (($credMed | Select-Object -First 3 | ForEach-Object { "$($_.Item): $($_.Detail)" }) -join '; ')
    # v2.70: the name reports WHICH fired - "Hunt techniques (N fired)" where N is the count of
    # DISTINCT rules in the (unchanged) $huntHi input - and the detail dedupes rule names with
    # per-rule counts (count desc, name asc), capped at 3 with a '+N more' suffix (Defender shape).
    # Count stays total events (verdict Count contract unchanged); zero findings still add nothing.
    $huntHiRules = @($huntHi | Group-Object Rule | Sort-Object @{Expression = 'Count'; Descending = $true }, Name)
    Add-Signal "Hunt techniques ($($huntHiRules.Count) fired)" 2 $huntHi.Count ((($huntHiRules | Select-Object -First 3 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; ') + $(if ($huntHiRules.Count -gt 3) { "; +$($huntHiRules.Count - 3) more" }))
    Add-Signal 'Ransomware-like mass file modification (USN journal)' 3 $usnBurstN ((($usnBursts | Select-Object -First 3 | ForEach-Object { "$($_.WindowStart): $($_.WriteEvents) writes / $($_.DistinctFiles) files" }) -join '; ') + $(if ($rExt) { " - RANSOM EXTENSIONS: $rExt" }))
    Add-Signal 'Uncommon persistence mechanism (IFEO/AppInit/Winlogon/netsh/LSA)' 2 $asepHotN (($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' } | Select-Object -First 3 | ForEach-Object { "$($_.Category): $($_.Name) = $($_.Value)" }) -join '; ')
    Add-Signal 'Memory malfind indicators (injected code regions)' 2 @($memMf).Count (($memMf | Select-Object -First 3 | ForEach-Object { "$($_.Process)($($_.PID))" }) -join '; ')
    Add-Signal 'IOC domain observed in browser history' 2 @($browserIoc).Count (($browserIoc | Select-Object -First 3 | ForEach-Object { $_.Indicator }) -join '; ')
    $dnsIoc = @(Import-CaseCsv 'ioc_hits_dns')
    $netIoc = @(Import-CaseCsv 'ioc_hits_network')
    Add-Signal 'IOC hit - known-bad DNS query / historical connection' 2 ($dnsIoc.Count + $netIoc.Count) ((@($dnsIoc | Select-Object -First 3 | ForEach-Object { $_.Query }) + @($netIoc | Select-Object -First 2 | ForEach-Object { $_.RemoteIp })) -join '; ')
    $mftIoc = @(Import-CaseCsv 'ioc_hits_mft')
    Add-Signal 'IOC hit - known-bad filename on disk ($MFT)' 2 @($mftIoc).Count (($mftIoc | Select-Object -First 3 | ForEach-Object { $_.Path }) -join '; ')
    $hashIoc = @(Import-CaseCsv 'ioc_hits_hash')
    Add-Signal 'IOC hit - known-bad binary hash in execution history' 2 @($hashIoc).Count (($hashIoc | Select-Object -First 3 | ForEach-Object { "$($_.Process) ($($_.Path))" }) -join '; ')
    Add-Signal 'IOC hit - live system' 3 @($iocLive).Count (($iocLive | Select-Object -First 3 | ForEach-Object { $_.Indicator }) -join '; ')
    Add-Signal 'Sigma detection - critical' $critFloor $hayCrit.Count (($hayCrit | Select-Object -First 3 | ForEach-Object { $_.RuleTitle }) -join '; ')
    Add-Signal 'YARA hit - medium rule' 2 $yaraMed (($yara | Where-Object { "$($_.Severity)" -match '^medium$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - periodic callbacks' 2 $beaconMed (($beacons | Where-Object { "$($_.Severity)" -match '^medium$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'C2 DNS beaconing - periodic domain queries' 2 $dnsMed (($dnsBeacons | Where-Object { "$($_.Severity)" -match '^medium$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.Domain) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'Sigma detection - high' $highFloor $hayHigh.Count "$($hayHigh.Count) events from $hayHighRules distinct rules$(if ($highFloor -eq 0 -and $hayHigh.Count -gt 0) { ' - single-rule storm carries no verdict weight (see -Mode Tune)' })"
    # v2.55: volume signal - a single med/low rule with >=100 deduped events is a storm worth
    # naming (usually admin automation, sometimes real). Floor 0 = visible, no verdict weight.
    $hayStorm = @($hay | Group-Object RuleTitle | Where-Object { $_.Count -ge 100 -and @($_.Group | Where-Object { (Get-LvlRank "$($_.Level)") -le 2 } | Select-Object -First 1) } | Sort-Object Count -Descending)
    Add-Signal 'Sigma volume signal' 0 @($hayStorm).Count (($hayStorm | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count) events - review sample, then tune if benign)" }) -join '; ')
    # v2.64: score honesty for the HIGH signal. The correlation score needs 8+ before a HIGH
    # verdict carries weight 2 alone; a sub-8 HIGH (observed: score 6 on a signed-by-nobody proxy
    # client - unsigned + one public connection) only counts when the SAME verdict pass
    # corroborates it (YARA hit, IOC hit, beacon candidate, weight-carrying Sigma crit/high, or
    # hunt high). Demoted rows stay visible at weight 1 with the reason in the detail.
    $procHighStrong = @($procHighRows | Where-Object { $s = 0; [void][int]::TryParse("$($_.Score)", [ref]$s); $s -ge 8 })
    $procHighWeak = @($procHighRows | Where-Object { $s = 0; [void][int]::TryParse("$($_.Score)", [ref]$s); $s -lt 8 })
    # Sigma corroboration uses the verdict's own storm gates: single-rule high storms carry weight 0
    # and must not corroborate; crit rows always carry weight.
    $procCorroborated = (@($yara).Count -gt 0) -or (@($iocLive).Count -gt 0) -or (@($iocAmc).Count -gt 0) -or (@($browserIoc).Count -gt 0) -or (@($dnsIoc).Count -gt 0) -or (@($netIoc).Count -gt 0) -or (@($mftIoc).Count -gt 0) -or (@($hashIoc).Count -gt 0) -or (@($beacons).Count -gt 0) -or (@($dnsBeacons).Count -gt 0) -or ($hayCrit.Count -gt 0) -or ($highFloor -gt 0) -or ($huntHi.Count -gt 0)
    $procHighCount = if ($procCorroborated) { $procHighRows.Count } else { $procHighStrong.Count }
    $procHighFloor = if ($procHighCount -gt 0) { 2 } else { 1 }
    $procHighCount = if ($procHighCount -gt 0) { $procHighCount } else { $procHighWeak.Count }
    $procHighDetail = (@($procHighStrong | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; ')
    if ($procCorroborated) { $procHighDetail = (@($procHighRows | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; ') }
    elseif ($procHighWeak.Count -gt 0) { if ($procHighDetail) { $procHighDetail += '; ' }; $procHighDetail += "$($procHighWeak.Count) sub-score-8 HIGH demoted - no corroboration (YARA/IOC/beacon/Sigma/hunt)" }
    Add-Signal 'Process anomaly verdict HIGH' $procHighFloor $procHighCount $procHighDetail
    # v2.60 FP fix: weight honesty for Defender detections. The live catalog is current, and
    # 1116 history inside the log window is fresh - both keep weight 2. Only explicitly-tagged
    # evtx-history (v2.55+ merge) outside the window drops to weight 1 report-only, so an old
    # cleaned detection can no longer ride the two-weight-2-signals escalation to LIKELY
    # COMPROMISED. Schema-less rows (pre-v2.55 cases) default fresh - legacy behavior preserved.
    $defWinCutoff = (Get-Date).AddHours(-$(if ($LogHours -gt 0) { $LogHours } else { 168 }))
    $defFresh = New-Object System.Collections.Generic.List[object]
    $defStale = New-Object System.Collections.Generic.List[object]
    foreach ($t in $def) {
        $fresh = $true
        if ("$($t.Source)" -eq 'evtx-history') {
            $fresh = $false
            try { $fresh = ([datetime]"$($t.DetectedUTC)") -gt $defWinCutoff } catch { }
        }
        # v2.64: dateless inactive live-catalog remnant - Source 'live-catalog' with NO detection
        # time, an INACTIVE threat and NO resource is the leftover of an already-cleaned detection
        # (observed on the live case: a months-old Trojan stayed 'fresh' -> weight 2 forever).
        # Genuinely schema-less rows (pre-v2.55 cases: no Source column at all) keep the fresh default.
        elseif ("$($t.Source)" -eq 'live-catalog' -and -not "$($t.DetectedUTC)" -and "$($t.IsActive)" -match '^false$' -and -not "$($t.Resources)") {
            $fresh = $false
        }
        if ($fresh) { $defFresh.Add($t) } else { $defStale.Add($t) }
    }
    # v2.70: nameless rows (empty ThreatName + a date - the pre-v2.70 1116 parse output) contribute
    # NOTHING to the detail, so bare ' @ <date>' fragments are impossible; stamps normalize to
    # 'yyyy-MM-dd HH:mm' (raw string kept when the stamp fails to parse).
    # v2.70 (task 4): nameless rows are filtered BEFORE the 3-entry window and the '+N more'
    # suffix counts NAMED rows only - an all-nameless list renders an empty detail, never a
    # bare '; +N more' headless tail.
    $defDetail = { param($list) $named = @($list | Where-Object { "$($_.ThreatName)".Trim() })
        ((@($named | Select-Object -First 3 | ForEach-Object {
            $ts = "$($_.DetectedUTC)".Trim()
            if ($ts) { $d = [datetime]::MinValue; if ([datetime]::TryParse($ts, [ref]$d)) { $ts = $d.ToString('yyyy-MM-dd HH:mm') } }
            "$($_.ThreatName)".Trim() + "$(if ("$($_.SeverityID)") { ' (sev ' + $_.SeverityID + ')' })$(if ($ts) { " @ $ts" })"
        }) -join '; ') + $(if ($named.Count -gt 3) { "; +$($named.Count - 3) more" })) }
    Add-Signal 'Defender detection - active or in log window' 2 $defFresh.Count (& $defDetail $defFresh)
    Add-Signal 'Defender detection - stale history (resolved / outside log window)' 1 $defStale.Count (& $defDetail $defStale)
    Add-Signal 'Security tooling tampering / log clearing' 2 $gapTamper "log cleared or security service stopped"
    Add-Signal 'Hidden scheduled task (TaskCache SD stripped)' 3 $tcHidden.Count (($tcHidden | Select-Object -First 3 | ForEach-Object { "Tasks\$($_.Guid)" }) -join '; ')
    Add-Signal 'Orphaned TaskCache entries (no Tree link)' 2 $tcOrphan.Count (($tcOrphan | Select-Object -First 3 | ForEach-Object { "Tasks\$($_.Guid)" }) -join '; ')
    Add-Signal 'ntds.dit accessed - non-backup pattern (ESENT 325/326)' 3 $ntdsTheft.Count (($ntdsTheft | Select-Object -First 2 | ForEach-Object { "$($_.Time)" }) -join '; ')
    Add-Signal 'ntds.dit accessed - backup pattern (verify schedule)' 0 $ntdsBackup.Count "ESENT events matching backup engines - confirm the backup window covers them"
    Add-Signal 'Process anomaly verdict MEDIUM' 1 $procMed "unsigned/user-path binaries worth review"
    Add-Signal 'Brute-force source(s) seen' 0 @($brute).Count "failed logon sources - check for follow-up success"

    # coverage: weighted evidence sources actually collected
    $cov = New-Object System.Collections.Generic.List[object]
    function Add-Cov([string]$name, [bool]$present, [int]$weight) {
        $cov.Add([pscustomobject]@{ Source = $name; Collected = $present; Weight = $weight })
        if (-not $present) { & $logQ "verdict coverage miss: $name (weight $weight)" }
    }
    $evtxDir = Join-Path $RawDir 'evtx'
    Add-Cov 'Volatile process inventory' (Test-CaseCsv 'flash_process_scored') 12
    Add-Cov 'Live network connections' (Test-CaseCsv 'flash_public_connections') 8
    $pers = (Test-CaseCsv 'autoruns_runkeys') -or (Test-CaseCsv 'services') -or (Test-CaseCsv 'scheduled_tasks')
    Add-Cov 'Persistence surface (autoruns/services/tasks)' $pers 15
    Add-Cov 'Event log export' (Test-Path $evtxDir) 20
    Add-Cov 'Sigma detection timeline' (Test-CaseCsv 'hayabusa_timeline') 10
    Add-Cov 'Historical execution (amcache)' (Test-CaseCsv 'amcache') 12
    Add-Cov 'Prefetch execution history' (Test-CaseCsv 'prefetch_index') 8
    Add-Cov 'USN journal (file modification history)' (Test-CaseCsv 'usn_write_bursts') 10
    Add-Cov 'MFT file timeline (filtered)' (Test-CaseCsv 'mft_recent') 8
    Add-Cov 'ASEP deep sweep (IFEO/AppInit/COM/netsh/LSA)' (Test-CaseCsv 'asep_sweep') 5
    Add-Cov 'Browser history artifacts' (Test-CaseCsv 'browser_files') 4
    Add-Cov 'Defender status' (Test-CaseCsv 'defender_status') 5
    Add-Cov 'YARA binary scan' (Test-CaseCsv 'yara_scanned') 5
    Add-Cov 'DNS query telemetry (Sysmon EID 22)' (Test-CaseCsv 'sysmon_dns') 4
    Add-Cov 'Entity correlation' (Test-CaseCsv 'entities_binaries') 3
    Add-Cov 'Hunt rules' (Test-CaseCsv 'hunt_findings') 3
    Add-Cov 'Svchost masquerade audit' (Test-CaseCsv 'svchost_audit') 2
    Add-Cov 'Remote access sweep (tunnels/RA tools/SSH keys)' (Test-CaseCsv 'remote_access') 2
    Add-Cov 'Structured telemetry (4688 / Sysmon 2-13)' ((Test-CaseCsv 'security_proc_events') -or (Test-CaseCsv 'sysmon_process_access') -or (Test-CaseCsv 'sysmon_file_create')) 3
    Add-Cov 'Injection/pipe telemetry (Sysmon 8/17/18)' ((Test-CaseCsv 'sysmon_remote_thread') -or (Test-CaseCsv 'sysmon_pipes')) 2
    Add-Cov 'Execution artifact spine (prefetch/amcache/BAM/shimcache)' ((Test-CaseCsv 'prefetch_index') -or (Test-CaseCsv 'amcache') -or (Test-CaseCsv 'bam_lastexec') -or (Test-CaseCsv 'shimcache')) 3
    Add-Cov 'Kerberos/DS telemetry (DC role)' ((Test-CaseCsv 'security_kerberos') -or (Test-CaseCsv 'security_ds_access')) 3
    Add-Cov 'Web telemetry (IIS)' (Test-CaseCsv 'iis_requests') 2
    Add-Cov 'Session attribution + process lineage' ((Test-CaseCsv 'session_activity') -or (Test-CaseCsv 'process_chains')) 2
    Add-Cov 'Host extras (WER/StartupInfo/QuickAssist/GPO)' ((Test-CaseCsv 'wer_reports') -or (Test-CaseCsv 'startup_info')) 2
    $iocsLoaded = $false
    try { $iocsLoaded = ($null -ne (Get-IocList)) } catch { }
    Add-Cov 'IOC feeds loaded (iocs.txt/STIX/MISP)' $iocsLoaded 2
    Add-Cov 'LOLDrivers driver hash check' (Test-CaseCsv 'loldrivers_hits') 3
    Add-Cov 'Sysmon telemetry (bonus)' ([bool]$Sysmon) 5
    Add-Cov 'RAM capture (bonus)' (Test-Path $MemDir) 3
    # v2.64: coverage as an honest fraction - the denominator is the TOTAL possible weight
    # (collected + not), so a case missing sources reads <100% instead of the old capped sum
    # that hit 100% with 8 of 32 sources missing. N/M source counts ride the verdict object
    # (CoverageSourcesCollected/Total) next to the percent.
    $covTotal = 0
    foreach ($c in $cov) { $covTotal += $c.Weight }
    $covGot = 0
    foreach ($c in $cov) { if ($c.Collected) { $covGot += $c.Weight } }
    $covN = @($cov | Where-Object { $_.Collected }).Count
    $covM = $cov.Count
    # v2.80 (T4/I2): $null EndpointAdmin (analyst-side Parse of a package - the flag was never
    # set) is UNKNOWN, not non-elevated: do not Test-IsAdmin the ANALYST's token, do not apply
    # the -15 penalty or the endpoint "NOT elevated" caveat; say the status is unknown instead.
    $isAdminRun = $true
    $endpointAdminUnknown = ($null -eq $script:EndpointAdmin)
    if (-not $endpointAdminUnknown) { $isAdminRun = [bool]$script:EndpointAdmin }
    # v2.68 (B7): CoveragePercentUnadjusted is the fraction BEFORE the non-elevated -15 weight
    # correction - same Round/Max math, same 0..100 clamps applied to both values. Elevated runs
    # have no correction so the two properties are identical there by design; on non-elevated
    # runs Unadjusted >= Confidence and the gap is exactly the -15-weight fraction (v2.64 shipped
    # both properties reading the corrected value - the "Unadjusted" label lied).
    $covUnadj = 0
    if ($covTotal -gt 0) { $covUnadj = [Math]::Round(100 * [Math]::Max(0, $covGot) / $covTotal) }
    if ($covUnadj -gt 100) { $covUnadj = 100 }
    if ($covUnadj -lt 0) { $covUnadj = 0 }
    # v2.55: non-elevated runs under-collect - the -15 correction applies to the collected sum
    # AFTER both sums (net = covGot - 15), then the fraction is taken.
    $covNet = $covGot
    if (-not $isAdminRun) { $covNet -= 15 }
    $coverageRaw = 0
    if ($covTotal -gt 0) { $coverageRaw = [Math]::Round(100 * [Math]::Max(0, $covNet) / $covTotal) }
    if ($coverageRaw -gt 100) { $coverageRaw = 100 }
    if ($coverageRaw -lt 0) { $coverageRaw = 0 }

    # verdict level
    $rank = 0
    foreach ($s in $signals) { if ($s.Weight -gt $rank) { $rank = $s.Weight } }
    $distinctStrong = @($signals | Where-Object { $_.Weight -ge 2 }).Count
    # v2.64: escalation to LIKELY needs >=3 distinct weight-2 signals when nothing weight-3+
    # exists - two weak weight-2s (stored WiFi + a posture gap) must not declare compromise
    if ($rank -eq 2 -and $distinctStrong -ge 3) { $rank = 3 }
    if ($rank -eq 0) {
        if ($coverageRaw -lt 40) { $rank = 0 } else { $rank = 1 }
    }

    # caveats = what would change this verdict
    $caveats = New-Object System.Collections.Generic.List[string]
    if (-not $isAdminRun) { $caveats.Add('Run was NOT elevated - several sources are incomplete or missing') }
    if ($endpointAdminUnknown) { $caveats.Add('Endpoint elevation status unknown (parsed package) - coverage may reflect missing elevated sources') }
    if (-not $Sysmon) { $caveats.Add('No Sysmon on host - process injection / image-load / per-process network telemetry were not available') }
    if (Test-Path $evtxDir) {
        if ($script:LogStartDT) { $caveats.Add("Event-log analysis covered $(Get-LogRangeText) only - activity outside that window not assessed") }
        elseif ($LogHours -gt 0) { $caveats.Add("Event-log analysis covered only the last $([int]($LogHours/24)) days - older activity not assessed") }
    }
    if (-not (Test-Path $MemDir)) { $caveats.Add('No RAM capture - fileless / in-memory-only malware is not covered') }
    if (-not (Test-CaseCsv 'prefetch_index')) { $caveats.Add('Prefetch unavailable - program execution history limited') }
    if (-not (Test-CaseCsv 'amcache')) { $caveats.Add('Amcache unavailable - historical execution inventory missing') }
    if (-not (Test-Path $evtxDir)) { $caveats.Add('Event logs not exported - Sigma detection could not run') }
    # v2.55: 4688 auditing off = the whole process-lineage / session-attribution /
    # Office-chain detection layer is blind. Say it plainly instead of empty CSVs.
    # 4688 can live in the filtered export OR the full EvtxECmd conversion - check both.
    if (Test-Path $evtxDir) {
        $has4688 = $false
        foreach ($s4688 in @('security_events', 'evtx_ecmd/Security')) {
            $r4688 = @(Import-CaseCsv $s4688)
            if ($r4688.Count -eq 0) { continue }
            $idCol = ($r4688[0].PSObject.Properties.Name | Where-Object { $_ -match '^(eventid|id)$' } | Select-Object -First 1)
            if ($idCol -and @($r4688 | Where-Object { "$($_.$idCol)" -eq '4688' } | Select-Object -First 1)) { $has4688 = $true; break }
        }
        if (-not $has4688) { $has4688 = (@(Import-CaseCsv 'security_proc_events').Count -gt 0) }
        if (-not $has4688) {
            $caveats.Add('Process-creation auditing (4688) is NOT enabled on this host - no process lineage, no session attribution and no parent-child detections were possible. Enable: auditpol /set /subcategory:"Process Creation" /success:enable (and consider Sysmon)')
        } elseif (@(Import-CaseCsv 'security_proc_events').Count -eq 0) {
            $caveats.Add('4688 events exist but command-line capture is NOT enabled - detections that need process command lines (encoded PowerShell, proxy execution) ran blind. Enable the "Include command line in process creation events" policy')
        }
    }
    if ($rank -eq 0) { $caveats.Add('Too little evidence was collected to draw a conclusion') }

    $ownerLines = @{
        4 = 'Strong signs of MALICIOUS ACTIVITY were found on this computer.'
        3 = 'Several suspicious findings - malicious activity is LIKELY.'
        2 = 'Some SUSPICIOUS items were found - the IR team will check them.'
        1 = 'No signs of compromise were found.'
        0 = 'Not enough data could be collected to tell for sure.'
    }

    $counts = [pscustomobject]@{
        IocLive = @($iocLive).Count; IocAmcache = @($iocAmc).Count; YaraHigh = $yaraHi; YaraMedium = $yaraMed
        SigmaCritical = $hayCrit.Count; SigmaHigh = $hayHigh.Count; ProcessHigh = $procHighRows.Count; ProcessMedium = $procMed
        DefenderDetections = @($def).Count; TamperEvents = $gapTamper; BruteForceSources = @($brute).Count
        BeaconHigh = $beaconHi; BeaconMedium = $beaconMed
        DnsBeaconHigh = $dnsHi; DnsBeaconMedium = $dnsMed; LolDriversMalicious = $lolMal
        HuntHighPrecision = $huntHi.Count; HuntTotal = @($hunt).Count
    }

    return [pscustomobject]@{
        Level = $levelNames[$rank]
        LevelRank = $rank
        ConfidencePercent = $coverageRaw
        OwnerLine = $ownerLines[$rank]
        Signals = $signals.ToArray()
        Caveats = $caveats.ToArray()
        Coverage = $cov.ToArray()
        CoveragePercentUnadjusted = $covUnadj
        CoverageSourcesCollected = $covN
        CoverageSourcesTotal = $covM
        Counts = $counts
        GeneratedUTC = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-TriageLeads {
    # v2.71: ONE triage-lead builder, two consumers. Invoke-RegenerateOutputs persists the
    # ranked list to csv\derived\leads.csv; New-HtmlReport renders those rows (inline fallback
    # on old cases / direct renders) and the draft's BEST LEADS projects the hunt-source rows.
    # Source blocks are the ones New-HtmlReport used through v2.70, moved verbatim (same CSV
    # reads, same per-source caps, same per-entity hunt dedupe).
    # Ranking key, crit leads first: (1) corroboration category count desc (entities_binaries
    # Categories ';' fields for the lead's Ident, case-insensitive, 0 when unresolvable - the
    # same resolution the lead-card chips use at render time), (2) stable source priority
    # HIGH process > YARA > beacon > hunt > IOC > chain, (3) Title, (4) Class - fully
    # deterministic. Med leads keep source-block order (sigma > med proc > public conn) after
    # the crits. Cap stays 8, crit-first.
    if (-not (Get-Command ConvertTo-SafeInt -ErrorAction SilentlyContinue)) {
        function ConvertTo-SafeInt { param([string]$Value, [int]$Default = 0) if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }; try { return [int]$Value } catch { return $Default } }
        function ConvertTo-SafeDbl { param([string]$Value, [double]$Default = 0) if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }; try { return [double]$Value } catch { return $Default } }
    }
    $hayRows = @(Import-CaseCsv 'hayabusa_timeline.csv')
    if (Get-Command Remove-SigmaDuplicateEvents -ErrorAction SilentlyContinue) {
        $hayRows = @(Remove-SigmaDuplicateEvents $hayRows | Where-Object { -not (Test-SigmaSelfNoise $_) })
    }
    $pubConns = @(Import-CaseCsv 'flash_public_connections.csv')
    # corroboration categories per entity path - the same map the render resolves for its chips
    $catCnt = @{}
    foreach ($e2 in @(Import-CaseCsv 'entities_binaries')) {
        if ("$($e2.Categories)") {
            $c2 = @("$($e2.Categories)" -split ';' | Where-Object { "$($_)".Trim() }).Count
            $k2 = "$($e2.Path)".ToLower()
            if (-not $catCnt.ContainsKey($k2) -or $c2 -gt $catCnt[$k2]) { $catCnt[$k2] = $c2 }
        }
    }
    $srcPri = @{ 'crit|processes' = 0; 'crit|yara' = 1; 'crit|beacons' = 2; 'crit|hunt' = 3; 'crit|ioc' = 4; 'crit|entities' = 5; 'med|sigma' = 6; 'med|processes' = 7; 'med|network' = 8 }
    $leads = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Import-CaseCsv 'flash_process_scored' | Where-Object { "$($_.Verdict)" -eq 'HIGH' -and "$($_.Name)" } | Sort-Object { ConvertTo-SafeInt $_.Score } -Descending | Select-Object -First 3)) {
        $leads.Add([pscustomobject]@{ Rank = 'crit'; Title = "$($p.Name) (PID $($p.PID))"; Class = "malicious process - correlation score $($p.Score)"; Why = "$($p.Evidence)"; Ident = "$($p.Path)"; Extra = "signer: $(if ("$($p.Signer)") { $p.Signer } else { 'NONE' })"; Anchor = 'processes' })
    }
    foreach ($y in @(Import-CaseCsv 'yara_hits' | Where-Object { "$($_.File)" } | Select-Object -First 3)) {
        $rk = if ("$($y.Severity)" -match '^(high|critical)$') { 'crit' } else { 'med' }
        $leads.Add([pscustomobject]@{ Rank = $rk; Title = (Split-Path "$($y.File)" -Leaf); Class = "YARA $($y.Severity): $($y.Rule)"; Why = "$($y.Description)"; Ident = "$($y.File)"; Extra = ''; Anchor = 'yara' })
    }
    foreach ($b in @(Import-CaseCsv 'beacon_candidates' | Where-Object { "$($_.Severity)" -match '^high$' } | Select-Object -First 2)) {
        $leads.Add([pscustomobject]@{ Rank = 'crit'; Title = "$($b.Process) -> $($b.RemoteIp):$($b.Port)"; Class = 'C2 beacon (regular callbacks)'; Why = "$($b.Events) connections over $($b.SpanMin) min, median interval ~$($b.MedianIntervalSec)s, regularity $([math]::Round((ConvertTo-SafeDbl $b.Regularity), 2))"; Ident = "$($b.RemoteIp)"; Extra = ''; Anchor = 'beacons' })
    }
    # v2.70 (task 4): hunt leads collapse per ENTITY (case-insensitive) BEFORE the window -
    # one card per entity, rules joined (' + '), ATT&CK tags '/'-joined, evidence from the
    # first row. Only within-source dedupe: other lead sources are untouched.
    $hfEnts = New-Object System.Collections.Generic.List[object]
    $hfSeen = @{}
    foreach ($h1 in @(Import-CaseCsv 'hunt_findings' | Where-Object { "$($_.Severity)" -eq 'high' })) {
        $hk = "$($h1.Entity)".ToLower()
        if ($hfSeen.ContainsKey($hk)) {
            $hg = $hfSeen[$hk]
            if ("$($h1.Rule)" -and @($hg.Rules.ToArray()) -notcontains "$($h1.Rule)") { $null = $hg.Rules.Add("$($h1.Rule)") }
            if ("$($h1.Attck)" -and @($hg.Tags.ToArray()) -notcontains "$($h1.Attck)") { $null = $hg.Tags.Add("$($h1.Attck)") }
        } else {
            $hg = [pscustomobject]@{ Entity = "$($h1.Entity)"; Evidence = "$($h1.Evidence)"; Rules = (New-Object System.Collections.Generic.List[string]); Tags = (New-Object System.Collections.Generic.List[string]) }
            if ("$($h1.Rule)") { $null = $hg.Rules.Add("$($h1.Rule)") }
            if ("$($h1.Attck)") { $null = $hg.Tags.Add("$($h1.Attck)") }
            $hfSeen[$hk] = $hg
            $null = $hfEnts.Add($hg)
        }
        if ($hfEnts.Count -ge 2) { break }
    }
    foreach ($hg in $hfEnts) {
        $leads.Add([pscustomobject]@{ Rank = 'crit'; Title = "$($hg.Entity)"; Class = "hunt rule: $(($hg.Rules.ToArray()) -join ' + ')"; Why = "$($hg.Evidence)"; Ident = "$($hg.Entity)"; Extra = "ATT&CK $(($hg.Tags.ToArray()) -join '/')"; Anchor = 'hunt' })
    }
    foreach ($io in @(Import-CaseCsv 'ioc_hits_amcache' | Select-Object -First 2)) {
        $leads.Add([pscustomobject]@{ Rank = 'crit'; Title = "$($io.Application)"; Class = 'IOC hash match (known-bad binary ran on this host)'; Why = "SHA1 $($io.Indicator) matched the IOC feed"; Ident = "$($io.SourceFile)"; Extra = ''; Anchor = 'ioc' })
    }
    # v2.55: medium-weight lead sources - a case can be SUSPICIOUS without any HIGH/YARA/beacon
    $hayMed = @($hayRows | Where-Object { "$($_.Level)" -match '^(medium|high|crit)$' })
    if ($hayMed.Count -ge 20) {
        $hayTop = @($hayMed | Group-Object RuleTitle | Sort-Object Count -Descending | Select-Object -First 3)
        # v2.66 (B7): Rule = the noisiest rule, so the lead link can open that drill-down
        $leads.Add([pscustomobject]@{ Rank = 'med'; Title = "Sigma storm: $([int]$hayMed.Count) detection rows"; Class = "review: sigma volume spike"; Why = (($hayTop | ForEach-Object { "$($_.Name) ($($_.Count) hits)" }) -join '; '); Ident = ''; Extra = ''; Anchor = 'sigma'; Rule = "$($hayTop[0].Name)" })
    }
    foreach ($ch2 in @(Import-CaseCsv 'process_chains' | Where-Object { "$($_.Child)" } | Select-Object -First 2)) {
        $leads.Add([pscustomobject]@{ Rank = 'crit'; Title = "$($ch2.Parent) -> $($ch2.Child)"; Class = "process lineage: spawned child process"; Why = "$($ch2.Evidence)"; Ident = "$($ch2.Child)"; Extra = ''; Anchor = 'entities' })
    }
    foreach ($pm in @(Import-CaseCsv 'flash_process_scored' | Where-Object { "$($_.Verdict)" -eq 'MEDIUM' -and "$($_.Name)" -and (ConvertTo-SafeInt $_.Score) -ge 4 } | Sort-Object { ConvertTo-SafeInt $_.Score } -Descending | Select-Object -First 2)) {
        $leads.Add([pscustomobject]@{ Rank = 'med'; Title = "$($pm.Name) (PID $($pm.PID))"; Class = "review: medium process score $($pm.Score)"; Why = "$($pm.Evidence)"; Ident = "$($pm.Path)"; Extra = "signer: $(if ("$($pm.Signer)") { $pm.Signer } else { 'NONE' })"; Anchor = 'processes' })
    }
    # v2.82: the unknown-provider lead consults the DNS-attributed connections - an IP whose
    # resolved domain belongs to a known provider is no longer "unknown"; a genuinely unknown
    # IP keeps the lead and shows the resolved domain (if any) so the analyst has a start.
    $domByIpL = @{}
    foreach ($cd in @(Import-CaseCsv 'connections_dns')) {
        if ("$($cd.RemoteAddress)" -and -not $domByIpL.ContainsKey("$($cd.RemoteAddress)")) { $domByIpL["$($cd.RemoteAddress)"] = $cd }
    }
    foreach ($pc in @($pubConns | Where-Object { "$($_.RemoteAddress)" -and -not (Get-IpCloudClass "$($_.RemoteAddress)") } | Group-Object RemoteAddress, RemotePort | ForEach-Object { $_.Group[0] } | Select-Object -First 2)) {
        $attr = $domByIpL["$($pc.RemoteAddress)"]
        if ($attr -and " $($attr.Provider)".Trim() -ne 'unknown') { continue }
        $pn = if ("$($pc.ProcessPath)") { Split-Path "$($pc.ProcessPath)" -Leaf } else { "PID $($pc.PID)" }
        $why = 'established connection to unknown provider (not Microsoft/AWS/Google/Cloudflare/Akamai) - verify destination ownership and purpose'
        if ($attr -and "$($attr.ResolvedDomain)") { $why += " - DNS cache resolved it to '$($attr.ResolvedDomain)' (ownership still unverified)" }
        $leads.Add([pscustomobject]@{ Rank = 'med'; Title = "$pn -> $($pc.RemoteAddress):$($pc.RemotePort)"; Class = "review: outbound to non-cloud public IP"; Why = $why; Ident = "$($pc.RemoteAddress)"; Extra = ''; Anchor = 'network' })
    }
    # rank: crit-first, crits by corroboration desc then source priority then Title/Class
    # (deterministic); med leads by source priority only. Dedupe + cap as before.
    # Uniform 8-column shape so Export-Csv cannot drop the sigma Rule column when the first
    # lead carries no Rule property.
    return [System.Collections.Generic.List[object]]@(
        @($leads | Sort-Object @{ e = { if ("$($_.Rank)" -eq 'crit') { 0 } else { 1 } } },
                @{ e = { $cc = 0; if ("$($_.Rank)" -eq 'crit' -and $catCnt.ContainsKey("$($_.Ident)".ToLower())) { $cc = $catCnt["$($_.Ident)".ToLower()] }; $cc }; Descending = $true },
                @{ e = { $k3 = "$($_.Rank)|$($_.Anchor)"; if ($srcPri.ContainsKey($k3)) { $srcPri[$k3] } else { 9 } } },
                @{ e = { "$($_.Title)" } },
                @{ e = { "$($_.Class)" } } | Group-Object Title, Class | ForEach-Object { $_.Group[0] } | Select-Object -First 8 | ForEach-Object {
                [pscustomobject]@{ Rank = "$($_.Rank)"; Title = "$($_.Title)"; Class = "$($_.Class)"; Why = "$($_.Why)"; Ident = "$($_.Ident)"; Extra = "$($_.Extra)"; Anchor = "$($_.Anchor)"; Rule = "$($_.Rule)" }
            })
    )
}

function Get-CaseNarrative {
    # Plain-language executive draft built from the verdict + hunt findings (v2.31).
    # Written to case_draft.txt and rendered under the verdict in report.html - a starting
    # draft for the analyst's report, not a conclusion. Deterministic template, no filler.
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("CASE DRAFT - $Computer ($script:HostRole) - collected $($StartTime.ToString('yyyy-MM-dd HH:mm')) local, Ophira v$ScriptVersion")
    $L.Add("")
    if (-not $script:Verdict) { $L.Add("The verdict engine did not run - this draft has no assessment. Review the evidence sections."); return $L.ToArray() }
    $v = $script:Verdict
    $L.Add("ASSESSMENT: $($v.Level) (evidence coverage $($v.ConfidencePercent)% of expected sources - $($v.CoverageSourcesCollected)/$($v.CoverageSourcesTotal) sources, not a probability of compromise). $($v.OwnerLine)")
    $L.Add("")
    $strong = @($v.Signals | Where-Object { $_.Weight -ge 3 })
    $notable = @($v.Signals | Where-Object { $_.Weight -eq 2 })
    if ($strong.Count -gt 0 -or $notable.Count -gt 0) {
        $L.Add("WHAT THE EVIDENCE SHOWS")
        foreach ($s in $strong) {
            $d = if ("$($s.Detail)") { " ($($s.Detail))" } else { '' }
            $L.Add(" - $($s.Signal) x$($s.Count)$d")
        }
        foreach ($s in $notable) {
            $d = if ("$($s.Detail)") { " ($($s.Detail))" } else { '' }
            $L.Add(" - Also seen: $($s.Signal) x$($s.Count)$d")
        }
    } else {
        $L.Add("WHAT THE EVIDENCE SHOWS: no compromising signals in the collected evidence.")
    }
    $L.Add("")
    # v2.71: BEST LEADS is a projection of the ONE shared lead list (csv\derived\leads.csv,
    # built + persisted by the regen via Get-TriageLeads): hunt-source rows, report ranking,
    # cap 5, same line format. With no leads.csv (old case, direct render) the block is
    # skipped - the draft never rebuilds a second ranking.
    $leadRows = @()
    if (Test-CaseCsv 'leads') { $leadRows = @(Import-CaseCsv 'leads' | Where-Object { "$($_.Anchor)" -eq 'hunt' }) }
    if ($leadRows.Count -gt 0) {
        $L.Add("BEST LEADS (high-severity hunt detections - verify against cited evidence)")
        foreach ($ld in @($leadRows | Select-Object -First 5)) {
            $L.Add(" - [$(("$($ld.Extra)") -replace '^ATT&CK ', '')] $(("$($ld.Class)") -replace '^hunt rule: ', '') on $($ld.Title): $($ld.Why)")
        }
        $L.Add("")
    }
    $missing = @($v.Coverage | Where-Object { -not $_.Collected })
    if ($missing.Count -gt 0) {
        $L.Add("WHAT THIS ASSESSMENT COULD NOT SEE")
        $L.Add(" - Evidence sources not collected: " + (($missing | ForEach-Object { $_.Source }) -join ', '))
        $L.Add(" - Absence of findings in these areas is NOT proof of absence.")
        $L.Add("")
    }
    try {
        $ftPath = Join-Path (Split-Path -Parent $CsvDir) 'focus\focus_terms.json'
        if (Test-Path -LiteralPath $ftPath) {
            $ft2 = $null
            try { $ft2 = Get-Content -LiteralPath $ftPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
            if ($ft2) {
                $L.Add("FOCUSED ANALYSIS: a focus dossier was built for '$($ft2.Indicator)' - $($ft2.HitCount) evidence row(s) across $(@($ft2.SourcesHit.PSObject.Properties).Count) artifact source(s), $($ft2.InstanceCount) instance(s), $($ft2.Rounds) expansion round(s). Full activity chain and per-instance detail: focus\focus_report.html")
                $L.Add("")
            }
        }
    } catch { }
    if (@($v.Caveats).Count -gt 0) {
        $L.Add("CAVEATS")
        foreach ($c in @($v.Caveats)) { $L.Add(" - $c") }
        $L.Add("")
    }
    $L.Add("(Machine-generated starting draft - verify every lead against the cited evidence, then rewrite in your own words.)")
    # v2.70 (task 4): one generated stamp dialect - locale timestamps embedded in signal details /
    # lead evidence (e.g. '10/12/2026 7:43:01 AM') rewrite to 'yyyy-MM-dd HH:mm'. Only the matched
    # stamp substring is rewritten (the rest of a quoted cmdline stays verbatim); text the regex
    # matches but [datetime] cannot parse is left untouched.
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($ln in $L) {
        $null = $out.Add([regex]::Replace($ln, '\b\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}(?::\d{2})?(?: [AP]M)?\b', { param($m) $dd = [datetime]::MinValue; if ([datetime]::TryParse($m.Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dd)) { $dd.ToString('yyyy-MM-dd HH:mm') } else { $m.Value } }))
    }
    return $out.ToArray()
}

function ConvertFrom-SrumCsv {
    # v2.59: normalize one SrumECmd NetworkUsages CSV into the case schema - 'Application'
    # matches the entity binFromRow list and the report's top-consumer column patterns, so
    # both consumers work without schema branches. Returns @() on missing/unreadable input.
    # (SrumECmd's NetworkConnections table is deliberately NOT imported: on the real schema
    # every row carries an opaque AppId with no ExeInfo - 3k rows, zero attribution.)
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $raw = @()
    try { $raw = @(Import-Csv -LiteralPath $Path -ErrorAction Stop) } catch { return @() }
    @($raw | ForEach-Object { [pscustomobject]@{ Timestamp = "$($_.Timestamp)"; Application = "$($_.ExeInfo)"; User = "$($_.UserName)"; BytesSent = "$($_.BytesSent)"; BytesReceived = "$($_.BytesReceived)"; InterfaceType = "$($_.InterfaceType)" } })
}

function Import-PlasoTimeline {
    # v2.57: analyst-side plaso deep-timeline import. The analyst runs plaso's
    # log2timeline.py against the case's raw\ folder on their own box (Ophira never ships
    # a Python runtime), exports psort's l2tcsv as plaso.csv in the case root, and this
    # merges it into supertimeline.csv as Source 'plaso' rows. Idempotent: re-import
    # replaces prior plaso rows instead of doubling. Returns -1 when there is no
    # plaso.csv (silent no-op), else the number of rows merged.
    param([string]$CaseRoot)
    $plasoPath = Join-Path $CaseRoot 'plaso.csv'
    if (-not (Test-Path -LiteralPath $plasoPath)) { return -1 }
    # resolve supertimeline.csv the same way the script does (sortment map: csv\derived\ on
    # current cases, flat in the case root on pre-2.42 cases and bare fixture dirs)
    $stPath = $null
    if (Get-Command Get-CaseCsvFullPath -ErrorAction SilentlyContinue) { $stPath = Get-CaseCsvFullPath 'supertimeline' }
    if (-not ($stPath -and (Test-Path -LiteralPath $stPath))) {
        $stPath = $null
        foreach ($cand in @((Join-Path $CaseRoot 'supertimeline.csv'), (Join-Path (Join-Path $CaseRoot 'csv\derived') 'supertimeline.csv'))) {
            if (Test-Path -LiteralPath $cand) { $stPath = $cand; break }
        }
    }
    if (-not $stPath) { $stPath = Join-Path $CaseRoot 'supertimeline.csv' }
    $rows = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $stPath) {
        foreach ($r in @(Import-Csv -LiteralPath $stPath)) {
            if ("$($r.Source)" -eq 'plaso') { continue }
            $rows.Add($r)
        }
    }
    $n = 0
    foreach ($p in @(Import-Csv -LiteralPath $plasoPath)) {
        $ts = ''
        try {
            $d = [datetime]::ParseExact("$($p.date) $($p.time)", 'MM/dd/yyyy HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
            $ts = $d.ToString('yyyy-MM-dd HH:mm:ss')
        } catch { continue }
        $typ = if ("$($p.sourcetype)") { "$($p.sourcetype)" } elseif ("$($p.format)") { "$($p.format)" } else { "$($p.source)" }
        $rows.Add([pscustomobject]@{ Timestamp = $ts; Source = 'plaso'; Type = $typ; Actor = "$($p.host)"; Entity = "$($p.filename)"; Detail = "$($p.desc)" })
        $n++
    }
    if ($n -eq 0) { return 0 }
    $sorted = @($rows | Sort-Object { $_.Timestamp })
    if ($sorted.Count -gt 120000) { $sorted = @($sorted | Select-Object -Last 120000) }
    $sorted | Export-Csv -LiteralPath $stPath -NoTypeInformation -Encoding UTF8
    return $n
}

function Invoke-RegenerateOutputs {
    # Shared by New-Package and -Mode Parse: rebuilds every derived artifact from csv\
    # (supertimeline, gaps, parse_needed, verdict.json, SIEM export, ATT&CK layer, report.html).
    param([pscustomobject]$Case)
    # v2.79 regen step summary: every derived-artifact producer is timed; its Save-Rows outputs
    # (delta of $script:SavedArtifacts) or a step-set note become one RUN-detail-shaped line in
    # the end-of-run summary block. Steps set $rgInfo['note'] for non-Save-Rows outputs.
    $rgSteps = New-Object System.Collections.Generic.List[object]
    $rgStart = Get-Date
    $rgStep = {
        param([string]$Name, [string]$Producer, [scriptblock]$Sb)
        $rgInfo = @{}
        $rgBefore = 0
        if ($null -ne $script:SavedArtifacts) { $rgBefore = $script:SavedArtifacts.Count }
        $rgSw = [System.Diagnostics.Stopwatch]::StartNew()
        try { & $Sb } catch { $rgInfo['note'] = 'FAILED'; Write-CaseLog "    $Name failed: $($_.Exception.Message)" 'DarkYellow' }
        $rgSw.Stop()
        if (-not $rgInfo['note']) {
            $rgSaved = @()
            if ($null -ne $script:SavedArtifacts) {
                for ($rgI = $rgBefore; $rgI -lt $script:SavedArtifacts.Count; $rgI++) { $rgSaved += $script:SavedArtifacts[$rgI] }
            }
            if ($rgSaved.Count -eq 1) {
                $rgOne = $rgSaved[0]
                $rgInfo['note'] = if ((ConvertTo-SafeInt "$($rgOne.Rows)") -lt 0) { "$($rgOne.Path) FAILED" } else { "$($rgOne.Path) $($rgOne.Rows) rows" }
            } elseif ($rgSaved.Count -gt 1) {
                $rgRows = 0; $rgBad = 0
                foreach ($rgS in $rgSaved) { if ((ConvertTo-SafeInt "$($rgS.Rows)") -lt 0) { $rgBad++ } else { $rgRows += (ConvertTo-SafeInt "$($rgS.Rows)") } }
                $rgInfo['note'] = "$($rgSaved.Count) csv, $rgRows rows$(if ($rgBad -gt 0) { ", $rgBad FAILED" })"
            } else {
                $rgInfo['note'] = '(no csv)'
            }
        }
        $rgSteps.Add([pscustomobject]@{ Name = $Name; Producer = $Producer; Note = "$($rgInfo['note'])"; Seconds = $rgSw.Elapsed.TotalSeconds })
    }

    # v2.58: remove v2.53-era SBECmd orphan strays - the old module 8.8 leaked per-hive
    # outputs (e.g. Aryan_NTUSER.csv, 0_Aryan_Aryan_UsrClass.csv) into the csv root, and
    # cases collected before the v2.54 fix keep carrying them as nameless 0-row unknowns
    # in the evidence index. shellbags.csv (the merged artifact) is never matched.
    foreach ($orphan in @(Get-ChildItem -LiteralPath $script:CsvDir -File -Filter '*.csv' -ErrorAction SilentlyContinue)) {
        if ($orphan.Name -match '^\d{0,3}.*_(NTUSER|UsrClass)\.csv$') {
            Remove-Item -LiteralPath $orphan.FullName -Force -ErrorAction SilentlyContinue
            Write-CaseLog "    removed v2.53 shellbag orphan: $($orphan.Name)" 'DarkYellow'
        }
    }
    # v2.74 sortment completion sweep: the EZ native tools write --csv $CsvDir --csvf <name>
    # straight into the csv ROOT (PECmd/AmcacheParser/JLECmd split families, usn_write_bursts
    # from pre-map cases), so the analyst opened csv\ to a wall the v2.42 sortment never
    # caught. One pass BEFORE anything reads the csvs: every ROOT file whose name resolves
    # through the map moves into its category folder. Root-only enumeration means already-
    # foldered files are never touched; a destination that already exists is left alone (the
    # flat-first read contract keeps it authoritative); a locked file logs and skips - regen
    # never crashes on tidying. Idempotent: the second run finds nothing mapped left in root.
    foreach ($loose in @(Get-ChildItem -LiteralPath $script:CsvDir -File -Filter '*.csv' -ErrorAction SilentlyContinue)) {
        try {
            $rel = Get-CaseCsvPath $loose.BaseName
            if ($rel -notmatch '\\') { continue }
            $dest = Join-Path $script:CsvDir $rel
            if (Test-Path -LiteralPath $dest) { continue }
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Move-Item -LiteralPath $loose.FullName -Destination $dest -ErrorAction Stop
            Write-CaseLog "    sortment: moved $($loose.Name) -> csv\$($rel.Substring(0, $rel.IndexOf('\')))\" 'DarkGray'
        } catch { Write-CaseLog "    sortment: could not move $($loose.Name) ($($_.Exception.Message)) - left flat in csv root" 'DarkYellow' }
    }
    & $rgStep 'supertimeline' 'New-SuperTimeline' { New-SuperTimeline }
    # v2.57: merge an analyst-dropped plaso deep-timeline (plaso.csv in the case root)
    & $rgStep 'plaso import' 'Import-PlasoTimeline' {
        $plasoN = Import-PlasoTimeline (Split-Path -Parent $script:CsvDir)
        if ($plasoN -ge 0) { $rgInfo['note'] = "$plasoN row(s) merged"; Write-CaseLog "    plaso import: $plasoN row(s) merged into the master timeline (Source 'plaso')" 'Cyan' }
    }
    & $rgStep 'sigma rule logs' 'New-SigmaRuleLogs' { New-SigmaRuleLogs }
    & $rgStep 'hunt findings' 'New-HuntFindings' { New-HuntFindings }
    & $rgStep 'IOC xref' 'New-IocHits' { New-IocHits }
    & $rgStep 'IOC export' 'New-CaseIocExport' { New-CaseIocExport }
    & $rgStep 'entity correlation' 'New-EntityCorrelation' { New-EntityCorrelation }
    & $rgStep 'session attribution' 'New-SessionAttribution' { New-SessionAttribution }
    & $rgStep 'process lineage' 'New-ProcessChains' { New-ProcessChains }
    & $rgStep 'connection attribution' 'New-ConnectionDns' { New-ConnectionDns }
    & $rgStep 'shimcache exec flags' 'New-ShimcacheExec' { New-ShimcacheExec }
    & $rgStep 'logging gaps' 'New-LoggingGaps' { New-LoggingGaps }
    & $rgStep 'parse-needed' 'Get-ParseNeeds' { Get-ParseNeeds }
    # v2.58: evidence-based 4688 check - the Security log is readable but zero 4688 rows were
    # parsed, so process-creation auditing is disabled. WARN posture row + hardening rec ONLY -
    # deliberately NOT a verdict weight (a missing log is a hardening gap, not compromise evidence).
    try {
        $authN = @(Import-CaseCsv 'security_auth_events').Count
        $procN = @(Import-CaseCsv 'security_proc_events').Count
        if ($authN -gt 0 -and $procN -eq 0) {
            $postPath = Get-CaseCsvFullPath 'posture'
            $post = @(); if (Test-Path -LiteralPath $postPath) { $post = @(Import-Csv -LiteralPath $postPath) }
            if (-not @($post | Where-Object { "$($_.Check)" -match '4688' }).Count) {
                $post += [pscustomobject]@{ Check = 'Process-creation auditing (4688)'; Status = 'WARN'; Detail = 'The Security log is readable but contains no 4688 events - process auditing is disabled, so process lineage and session attribution run blind. Enable via GPO: Advanced Audit Policy > Detailed Tracking > Audit Process Creation (success).' }
                $post | Export-Csv -LiteralPath $postPath -NoTypeInformation -Encoding UTF8
                Write-CaseLog "    posture: 4688 process-creation auditing appears DISABLED - hardening recommendation added (report-only, no verdict weight)" 'Yellow'
            }
        }
    } catch { }
    $script:Verdict = $null
    & $rgStep 'verdict' 'Get-CompromiseVerdict' {
        $script:Verdict = Get-CompromiseVerdict
        if ($script:Verdict) {
            $script:Verdict | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'verdict.json') -Encoding UTF8
            if ($Case) {
                $Case | Add-Member -NotePropertyName Verdict -NotePropertyValue ([pscustomobject]@{
                    Level = $script:Verdict.Level
                    ConfidencePercent = $script:Verdict.ConfidencePercent
                    SignalCount = $script:Verdict.Signals.Count
                    CaveatCount = $script:Verdict.Caveats.Count
                }) -Force
            }
            $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
            Write-CaseLog "    VERDICT: $($script:Verdict.Level) (evidence coverage $($script:Verdict.ConfidencePercent)%, $($script:Verdict.CoverageSourcesCollected)/$($script:Verdict.CoverageSourcesTotal) sources) - $($script:Verdict.Signals.Count) signal(s), $($script:Verdict.Caveats.Count) caveat(s) -> verdict.json" $vColor
            $rgInfo['note'] = "verdict.json - $($script:Verdict.Level)"
        }
    }
    # v2.45 auto-correlation: when the scoring calls a process malicious (HIGH) - or a YARA-high
    # / live IOC fires - the focus dossier builds itself so the case ships with the "everything
    # it did" story pre-assembled. Skipped when the analyst already focused something manually
    # (their pick wins) and on clean cases with no seed (zero cost there).
    try {
        $focusTermsP = Join-Path (Join-Path $CaseDir 'focus') 'focus_terms.json'
        if (-not (Test-Path -LiteralPath $focusTermsP)) {
            $seed = $null; $seedWhy = ''; $seedLeaf = $null
            $hiProc = @(Import-CaseCsv 'flash_process_scored' | Where-Object { "$($_.Verdict)" -eq 'HIGH' -and "$($_.Name)" } | Sort-Object { ([int]"$($_.Score)") } -Descending)
            if ($hiProc.Count -gt 0) { $seed = "$($hiProc[0].Name)"; $seedWhy = "malicious process score $($hiProc[0].Score)" }
            if (-not $seed) {
                $yh = @(Import-CaseCsv 'yara_hits' | Where-Object { "$($_.Severity)" -match '^(high|critical)$' -and "$($_.File)" } | Select-Object -First 1)
                if ($yh) { $seed = (Split-Path "$($yh[0].File)" -Leaf); $seedWhy = "YARA $($yh[0].Severity) hit" }
            }
            if (-not $seed) {
                $il = @(Import-CaseCsv 'flash_ioc_hits' | Where-Object { "$($_.Indicator)" } | Select-Object -First 1)
                if ($il) { $seed = "$($il[0].Indicator)"; $seedWhy = 'live IOC hit' }
            }
            # v2.53: verdict-driven fallbacks - a case that fired on hunt rules or beaconing
            # (no HIGH process / YARA / IOC) used to ship with NO correlation story at all.
            # Seed the strongest remaining signal so the report always carries the graph.
            if (-not $seed) {
                $hf = @(Import-CaseCsv 'hunt_findings' | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Entity)" -match '(?i)\.(exe|sys|dll)$' } | Select-Object -First 1)
                if ($hf) {
                    # v2.71: seed the Entity AS-IS - the focus core classifies path seeds itself
                    # (HarddiskVolume normalization + lowercase). Stripping to the leaf seeded the
                    # OS process name (e.g. svchost.exe) and buried the one malicious instance
                    # under every legit one. The leaf is kept only as the zero-hit fallback below.
                    $seed = "$($hf[0].Entity)"
                    if ($seed.Contains('\')) { try { $seedLeaf = (Split-Path $seed -Leaf) } catch { } }
                    $seedWhy = "hunt rule '$($hf[0].Rule)'"
                }
            }
            if (-not $seed) {
                $bc = @(Import-CaseCsv 'beacon_candidates' | Sort-Object { switch ("$($_.Severity)") { 'high' { 0 } 'medium' { 1 } default { 2 } } } | Select-Object -First 1)
                if ($bc) {
                    if ("$($bc[0].Process)") { $seed = "$($bc[0].Process)"; try { $seed = (Split-Path $seed -Leaf) } catch { } }
                    elseif ("$($bc[0].RemoteIp)") { $seed = "$($bc[0].RemoteIp):$($bc[0].Port)" }
                    if ($seed) { $seedWhy = "C2 beacon candidate ($($bc[0].Severity))" }
                }
            }
            if (-not $seed) {
                $db = @(Import-CaseCsv 'dns_beacon_candidates' | Sort-Object { switch ("$($_.Severity)") { 'high' { 0 } 'medium' { 1 } default { 2 } } } | Select-Object -First 1)
                if ($db -and "$($db[0].Domain)") { $seed = "$($db[0].Domain)"; $seedWhy = "DNS beacon candidate ($($db[0].Severity))" }
            }
            if ($seed) {
                Write-CaseLog "    auto-focus: $seedWhy on '$seed' -> building the dossier (focus\focus_report.html)" 'Cyan'
                try { Invoke-FocusCore -Indicator $seed -Meta ([pscustomobject]@{ Computer = "$Computer"; CaseID = "$($script:CurrentCaseID)" }) | Out-Null } catch { Write-CaseLog "    auto-focus core failed: $($_.Exception.Message)" 'DarkYellow' }
                # v2.71: a path seed that matched nothing (or a failed core run) wrote no dossier -
                # re-seed ONCE with the leaf name (pre-v2.71 behavior) so the case still ships a story
                if ($seedLeaf -and -not (Test-Path -LiteralPath $focusTermsP)) {
                    Write-CaseLog "    auto-focus: path seed '$seed' matched nothing - fallback re-seed with leaf name '$seedLeaf'" 'Yellow'
                    try { Invoke-FocusCore -Indicator $seedLeaf -Meta ([pscustomobject]@{ Computer = "$Computer"; CaseID = "$($script:CurrentCaseID)" }) | Out-Null } catch { Write-CaseLog "    auto-focus fallback failed: $($_.Exception.Message)" 'DarkYellow' }
                }
            }
        }
    } catch { Write-CaseLog "    auto-focus failed: $($_.Exception.Message)" 'DarkYellow' }
    # v2.71: triage leads built ONCE and persisted to csv\derived\leads.csv - the report
    # renders these rows and the draft's BEST LEADS projects the same list (one builder,
    # one ranking). Empty result -> no file (v2.75 fix: a stale ranking from a previous
    # parse is deleted so it can't keep serving), both consumers degrade gracefully.
    & $rgStep 'triage leads' 'Get-TriageLeads' {
        $leadExport = @(Get-TriageLeads)
        $leadP = Get-CaseCsvFullPath 'leads'
        if ($leadExport.Count -gt 0) { $leadExport | Export-Csv -LiteralPath $leadP -NoTypeInformation -Encoding UTF8 }
        elseif (Test-Path -LiteralPath $leadP) { Remove-Item -LiteralPath $leadP -Force; Write-CaseLog "    leads: stale ranking removed - this parse ranked zero leads" 'DarkYellow' }
        $rgInfo['note'] = "$($leadExport.Count) lead(s) -> csv\$(Get-CaseCsvPath 'leads')"
    }
    & $rgStep 'case draft' 'Get-CaseNarrative' {
        Get-CaseNarrative | Set-Content -LiteralPath (Join-Path $CaseDir 'case_draft.txt') -Encoding UTF8
        $rgInfo['note'] = 'case_draft.txt'
    }
    & $rgStep 'siem export' 'New-SiemExport' {
        New-SiemExport
        $p = Join-Path $CaseDir 'siem_export.ndjson'
        $rgInfo['note'] = if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).LastWriteTime -ge $rgStart)) { 'siem_export.ndjson' } else { '(no records)' }
    }
    & $rgStep 'ATT&CK layer' 'New-AttackLayer' {
        New-AttackLayer
        $p = Join-Path $CaseDir 'attack_layer.json'
        $rgInfo['note'] = if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).LastWriteTime -ge $rgStart)) { 'attack_layer.json' } else { '(no techniques)' }
    }
    & $rgStep 'report' 'New-HtmlReport' {
        New-HtmlReport | Out-Null
        $rgInfo['note'] = 'report.html'
    }
    # v2.74 (Task 15): analyst-first entry point - one plain-language file at the case root
    # saying what the verdict is, what the folders mean and which files to open first.
    # Rebuilt on every regen (idempotent overwrite); the top-file list is existence-checked
    # and never invents entries. Written LAST so everything it names already exists - or
    # is honestly absent from the list.
    try {
        $shL = New-Object System.Collections.Generic.List[string]
        $shL.Add("OPHIRA CASE - $Computer$(if ("$script:CurrentCaseID") { "  (case $script:CurrentCaseID)" })")
        $shL.Add("")
        if ($script:Verdict) {
            $vS = $script:Verdict
            $shL.Add("ASSESSMENT: $($vS.Level) (evidence coverage $($vS.ConfidencePercent)% of expected sources - $($vS.CoverageSourcesCollected)/$($vS.CoverageSourcesTotal) sources, not a probability of compromise). $($vS.OwnerLine)")
        } else {
            $shL.Add("ASSESSMENT: no verdict could be computed - review the sections in report.html directly.")
        }
        $shL.Add("")
        $shL.Add("START HERE: open report.html (double-click it) - the full assessment in plain language.")
        $shL.Add("")
        $shL.Add("WHERE THINGS LIVE")
        foreach ($fm in @(
                @('csv\volatile\', 'what was running when we arrived'),
                @('csv\persistence\', 'what survives reboots (services, scheduled tasks, run keys)'),
                @('csv\network\', 'the network as this machine saw it'),
                @('csv\logs\', 'event-log evidence (sign-ins, PowerShell, Sysmon, detections)'),
                @('csv\artifacts\', 'execution forensics (prefetch, amcache, recent files)'),
                @('csv\defender\', 'antivirus status, preferences and detections'),
                @('csv\memory\', 'RAM analysis findings (when memory was captured)'),
                @('csv\context\', 'host context (USB history, domain, certificates)'),
                @('csv\derived\', "Ophira's cross-references (master timeline, leads, entities)"),
                @('focus\', 'deep-dive dossier on the flagged entity'),
                @('raw\', 'the untouched original evidence'))) {
            $shL.Add("  $($fm[0]) = $($fm[1])")
        }
        $shL.Add("")
        $shL.Add("TOP FILES TO OPEN (in this order)")
        $iS = 0
        foreach ($t in @(
                @('report.html', (Join-Path $CaseDir 'report.html'), 'the full assessment - start here'),
                @('csv\derived\supertimeline.csv', (Join-Path $script:CsvDir 'derived\supertimeline.csv'), 'everything in time order - open in Excel/Timeline Explorer'),
                @('focus\focus_report.html', (Join-Path $CaseDir 'focus\focus_report.html'), 'deep dive on the flagged entity'),
                @('case_draft.txt', (Join-Path $CaseDir 'case_draft.txt'), 'plain-language first draft for your report'),
                @('csv\derived\leads.csv', (Join-Path $script:CsvDir 'derived\leads.csv'), 'ranked triage leads'))) {
            if (Test-Path -LiteralPath $t[1]) { $iS++; $shL.Add("  $iS. $($t[0]) - $($t[2])") }
        }
        $shL.Add("")
        $shL.Add("Everything else: collection.log (what ran) and csv\parse_needed.csv (what still needs the endpoint). Generated by Ophira v$ScriptVersion.")
        $shL.ToArray() | Set-Content -LiteralPath (Join-Path $CaseDir 'ANALYST-START-HERE.txt') -Encoding UTF8
    } catch { Write-CaseLog "    analyst start-here failed: $($_.Exception.Message)" 'DarkYellow' }
    # v2.79: end-of-run summary block - one RUN-detail-shaped line per derived artifact:
    # step name, producer function, output note (Save-Rows delta or step-set), elapsed.
    # Console-visible at Normal (it IS the parse run feedback, like the per-module lines);
    # the case log always carries it.
    if ($rgSteps.Count -gt 0) {
        $rgTotal = 0
        foreach ($rgS in $rgSteps) { $rgTotal += $rgS.Seconds }
        Write-CaseLog ("  regen summary: {0} steps in {1:N1}s" -f $rgSteps.Count, $rgTotal) 'Cyan'
        foreach ($rgS in $rgSteps) {
            $rgNm = "$($rgS.Name)"
            if ($rgNm.Length -gt 24) { $rgNm = $rgNm.Substring(0, 21) + '...' }
            $rgDots = '.' * [math]::Max(1, 26 - $rgNm.Length)
            Write-CaseLog ("    [regen] {0} {1} {2} -> {3} in {4:N1}s" -f $rgNm, $rgDots, $rgS.Producer, $rgS.Note, $rgS.Seconds) $(if ($rgS.Note -eq 'FAILED') { 'DarkYellow' } else { 'DarkGray' })
        }
    }
}

function New-CaseManifest {
    # v2.80 (T4/I3): shared manifest writer (New-Package + Parse-mode repack) so a repacked
    # zip never ships stale per-file hashes. Writes manifest.txt for -ForDir: caller header
    # lines + SCRIPT self-hash + TOOLS AVAILABLE + one SHA256 line per file (the manifest
    # itself and *.zip excepted - the zip hash is appended by the caller after compression).
    param([string]$ForDir, [string[]]$HeaderLines)
    # v2.82: canonicalize to the LONG path first - a caller may pass an 8.3 path (CI runners
    # expose TEMP as C:\Users\RUNNER~1\... while Get-ChildItem FullName returns the long
    # C:\Users\<name>\...), and the Substring below would then cut mid-path (root cause of
    # the CI-only I3 manifest failure: rows like 'se\\evidence.csv').
    try { $ForDir = (Get-Item -LiteralPath $ForDir).FullName } catch { }
    $manifest = @()
    foreach ($l in $HeaderLines) { $manifest += $l }
    $manifest += ""
    try {
        $selfHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        $manifest += "SCRIPT: Ophira v$ScriptVersion  SHA256: $selfHash"
    } catch { $manifest += "SCRIPT: Ophira v$ScriptVersion  (self-hash unavailable)" }
    $tDirM = Get-ToolsDir
    if ($tDirM) {
        $toolExes = Get-ChildItem -Path $tDirM -Recurse -File -Include 'hayabusa*.exe', 'chainsaw*.exe', 'vol.exe', '*winpmem*.exe', 'AmcacheParser*.exe', 'RBCmd*.exe', 'yr.exe' -ErrorAction SilentlyContinue
        if ($toolExes) {
            $manifest += "TOOLS AVAILABLE:"
            foreach ($exe in $toolExes) {
                $th = ''
                try { $th = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.Substring(0, 16) } catch { }
                $manifest += "  $($exe.Name)  [$th...]"
            }
        }
    }
    $manifest += ""
    $manifest += "{0,-70} {1,12} SHA256" -f "File", "SizeBytes"
    $files = Get-ChildItem -LiteralPath $ForDir -Recurse -File | Where-Object { $_.Name -ne 'manifest.txt' -and $_.Name -notmatch '\.zip$' }
    foreach ($f in ($files | Sort-Object FullName)) {
        $h = ''
        try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { $h = 'HASH-ERROR' }
        $rel = $f.FullName.Substring($ForDir.Length + 1)
        $manifest += "{0,-70} {1,12} {2}" -f $rel, $f.Length, $h
    }
    $manifest | Set-Content -LiteralPath (Join-Path $ForDir 'manifest.txt') -Encoding UTF8
}

function New-Package {
    if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host "" }
    Write-CaseLog "Packaging case folder..." 'Cyan'
    $os = Get-WmiOrCim -Class Win32_OperatingSystem
    $case = [pscustomobject]@{
        Tool = "Ophira v$ScriptVersion"
        CaseID = $script:CurrentCaseID
        Analyst = $script:CurrentAnalyst
        Computer = $Computer
        Preset = $Preset
        StartedUTC = $StartTime.ToUniversalTime().ToString('o')
        Role = $script:HostRole
        FinishedUTC = (Get-Date).ToUniversalTime().ToString('o')
        OS = if ($os) { $os.Caption + ' ' + $os.Version } else { '' }
        Owner = $env:USERNAME
        AdminElevated = (Test-IsAdmin)
        SysmonPresent = (Get-SysmonState)
        LogHours = $LogHours
        LogStart = $(if ($script:LogStartDT) { $script:LogStartDT.ToUniversalTime().ToString('o') } else { '' })
        LogEnd = $(if ($script:LogEndDT) { $script:LogEndDT.ToUniversalTime().ToString('o') } else { '' })
        DotNet = (Get-DotNetRelease)
        OutputFolder = $CaseDir
    }
    if ($script:ModuleTimings) {
        $case | Add-Member -NotePropertyName ModuleTimings -NotePropertyValue $script:ModuleTimings -Force
        $case | Add-Member -NotePropertyName ModuleSecondsTotal -NotePropertyValue ([math]::Round((($script:ModuleTimings | Measure-Object Seconds -Sum).Sum), 1)) -Force
    }
    $case | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8

    try { Invoke-DeltaCompare -Path $DeltaPath } catch { Write-CaseLog "    delta failed: $($_.Exception.Message)" 'DarkYellow' }
    Invoke-RegenerateOutputs -Case $case
    if ($script:Verdict) { $case | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8 }

    $manifest = @()
    $manifest += "Ophira v$ScriptVersion evidence manifest + chain of custody"
    $manifest += "CaseID: $($script:CurrentCaseID)  Analyst: $($script:CurrentAnalyst)"
    $manifest += "Host: $Computer  Collected: $($StartTime.ToString('u'))  Packaged: $((Get-Date).ToUniversalTime().ToString('u'))"
    $manifest += "Scope: every file in this folder is SHA256-hashed below (the manifest itself excepted - hash it after zip)."
    $manifest += "Custody: the case zip is the evidence unit; keep the hash of the zip with your case notes."
    New-CaseManifest -ForDir $CaseDir -HeaderLines $manifest

    $zipPath = "$CaseDir.zip"
    $zipped = $false
    try {
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            $items = Get-ChildItem -LiteralPath $CaseDir | Where-Object { $_.Name -ne 'memory' } | ForEach-Object { $_.FullName }
            if ($items) {
                Compress-Archive -Path $items -DestinationPath $zipPath -CompressionLevel Fastest -Force
                $zipped = $true
            }
        }
    } catch { Write-CaseLog "Zip failed: $($_.Exception.Message)" 'Yellow' }

    $zipHash = ''
    if ($zipped -and (Test-Path $zipPath)) {
        $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value ""
        Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "PACKAGE SHA256 ($([IO.Path]::GetFileName($zipPath))): $zipHash"
    }
    if (Test-Path $MemDir) {
        Get-ChildItem -LiteralPath $MemDir -Recurse -File | ForEach-Object {
            $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "MEMORY SHA256 ($($_.Name)): $h"
        }
    }

    $shareResult = ''
    $script:ShareOk = $false
    if ($SharePath -and $zipped -and (Test-Path $zipPath)) {
        try {
            if (-not (Test-Path $SharePath)) { throw "share path not reachable: $SharePath" }
            Copy-Item -LiteralPath $zipPath -Destination $SharePath -Force -ErrorAction Stop
            $shareResult = "copied to $SharePath"
            $script:ShareOk = $true
            Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "UPLOADED TO: $SharePath at $(Get-Date -Format u)"
        } catch { $shareResult = "SHARE COPY FAILED: $($_.Exception.Message)" }
    }
    $script:FinalZipPath = if ($zipped -and (Test-Path $zipPath)) { $zipPath } else { (Join-Path $CaseDir 'report.html') }

    $sizeAll = [math]::Round((Get-ChildItem -LiteralPath $CaseDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
    $zipSize = if ($zipped) { [math]::Round((Get-Item $zipPath).Length / 1MB, 1) } else { 0 }
    if (-not $script:SimpleUI) {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  COLLECTION COMPLETE" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Case folder : $CaseDir  ($sizeAll MB)"
        if (Test-Path (Join-Path $CaseDir 'report.html')) { Write-Host "  Report      : $CaseDir\report.html  <-- open this first" -ForegroundColor Cyan }
        if ($zipped) { Write-Host "  Package     : $zipPath  ($zipSize MB)" -ForegroundColor White }
        if ($zipHash) { Write-Host "  Zip SHA256  : $zipHash" -ForegroundColor White }
        if ($shareResult) { Write-Host "  Share copy  : $shareResult" -ForegroundColor $(if ($shareResult -match 'FAILED') { 'Red' } else { 'Green' }) }
        Write-Host "  Memory dump : $(if (Test-Path $MemDir) { "$MemDir (NOT in zip - send separately)" } else { 'not captured' })"
        if ($script:Verdict) {
            $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
            Write-Host "  VERDICT     : $($script:Verdict.Level)  (evidence coverage $($script:Verdict.ConfidencePercent)%, $($script:Verdict.CoverageSourcesCollected)/$($script:Verdict.CoverageSourcesTotal) sources)  - details: report.html / verdict.json" $vColor
        }
        Write-Host ""
        Write-Host "  Send the ZIP file (and memory dump if captured) to the analyst." -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Green
    }
}

function Show-RoleGate {
    # v2.53 front screen: two choices, not a role quiz. [1] Run = the full guided
    # collection (the owner-handoff experience); [2] Advanced mode = the responder menu.
    # ROLE= in ophira.config.txt still short-circuits (owner -> run, responder -> advanced).
    if ($script:OphiraRole -eq 'responder') { return 'advanced' }
    if ($script:OphiraRole -eq 'owner') { return 'run' }
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "   ___  ___  ___ _  _ ___ _____ _   ___ ___   " -ForegroundColor Cyan
        Write-Host "  | _ \/ _ \| __| \| | _ \_   _/_\ | _ \ _ \ " -ForegroundColor Cyan
        Write-Host "  |  _/ (_) | _|| .\` |  _/ | |/ _ \|   /  _/" -ForegroundColor Cyan
        Write-Host "  |_|  \___/|___|_|\_|_|   |_/_/ \_\_|_\_|_\ " -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  Ophira v$ScriptVersion  -  single-script Windows IR toolkit" -ForegroundColor White
        Write-Host "  READ-ONLY: collects evidence, never changes the system" -ForegroundColor DarkGray
        Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What do you want to do?" -ForegroundColor White
        Write-Host ""
        Write-Host "   [1]  Run - check this PC now" -ForegroundColor Yellow
        Write-Host "        Collects everything automatically (about 5 minutes)," -ForegroundColor DarkGray
        Write-Host "        then shows the result and where the report is." -ForegroundColor DarkGray
        Write-Host "        Send the result file to the IR team - they read the report." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   [2]  Advanced mode" -ForegroundColor Yellow
        Write-Host "        Full menu: remote PCs, fleet analyze, focus engine, parsing," -ForegroundColor DarkGray
        Write-Host "        timeline, live watch, canary, tools." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   [Q]  Quit" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Choose 1, 2 or Q"
        switch -Regex ($inp) {
            '^(?i)1$' { return 'run' }
            '^(?i)2$' { return 'advanced' }
            '^(?i)q$' { exit 0 }
            default { }
        }
    }
}

function Show-TaskMenu {
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  OPHIRA v$ScriptVersion   |   $($env:COMPUTERNAME)   |   RESPONDER" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What do you want to do?" -ForegroundColor White
        Write-Host ""
        Write-Host "   [1]  Collect evidence on THIS PC" -ForegroundColor Yellow
        Write-Host "   [2]  Push & run on REMOTE PCs (WinRM)" -ForegroundColor Yellow
        Write-Host "   [3]  Analyze collected results (fleet report)" -ForegroundColor Yellow
        Write-Host "   [4]  Setup / download companion tools" -ForegroundColor Yellow
        Write-Host "   [5]  Update detection rules (hayabusa)" -ForegroundColor Yellow
        Write-Host "   [6]  Tune Sigma rules (reduce false positives)" -ForegroundColor Yellow
        Write-Host "   [7]  Tool links" -ForegroundColor Yellow
        Write-Host "   [8]  Finish a collected case (parse evidence analyst-side)" -ForegroundColor Yellow
        Write-Host "   [9]  Focus on one entity (build its activity chain from a case)" -ForegroundColor Yellow
        # v2.68 (B16): the Process dossier existed only as -Mode Process CLI - no menu key reached it
        Write-Host "   [P]  Process dossier (deep-dive one process in a case)" -ForegroundColor Yellow
        Write-Host "   [T]  Timeline pivot (filter the master timeline to a window)" -ForegroundColor Yellow
        Write-Host "   [W]  Watch this PC live (rolling diff while a sample detonates)" -ForegroundColor Yellow
        Write-Host "   [C]  Detection canary (self-test the pipeline on this PC)" -ForegroundColor Yellow
        # v2.69 (F2): the flags-only help gap - one key renders the full help (modes, examples)
        Write-Host "   [H]  Help (what the modes and flags do, with examples)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   [Q]  Quit" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Command"
        switch -Regex ($inp) {
            '^(?i)1$' { return 'Collect' }
            '^(?i)2$' { return 'Deploy' }
            '^(?i)3$' { return 'Analyze' }
            '^(?i)4$' { return 'Setup' }
            '^(?i)5$' { return 'UpdateRules' }
            '^(?i)6$' { return 'Tune' }
            '^(?i)7$' { return 'Links' }
            '^(?i)8$' { return 'Parse' }
            '^(?i)9$' { return 'Focus' }
            '^(?i)p$' { return 'Process' }
            '^(?i)t$' { return 'Timeline' }
            '^(?i)w$' { return 'Watch' }
            '^(?i)c$' { return 'Canary' }
            '^(?i)h$' { return 'Help' }
            '^(?i)q$' { return $null }
            default { }
        }
    }
}

function Invoke-SetupWizard {
    Write-Host ""
    Write-Host "=== Setup companion tools ===" -ForegroundColor Cyan
    Write-Host "Tools live in tools\ subfolders. Available:" -ForegroundColor Gray
    Write-Host "  winpmem  hayabusa  volatility3  chainsaw  AmcacheParser  RBCmd  MFTECmd  PECmd  LECmd  JLECmd  SBECmd  SQLECmd  SrumECmd  loldrivers  yara" -ForegroundColor White
    Write-Host "ENTER = walk through all tools (confirm each download)," 
    Write-Host "or give a comma-separated list (e.g. hayabusa,winpmem)."
    $inp = (Read-Host "Tools [all]").Trim()
    $wanted = $null
    if ($inp) { $wanted = $inp }
    Invoke-SetupMode -Wanted $wanted
    # IOC feed drop-folder: gitignored (per-engagement), created so analysts see where feeds go
    $iocDir = Join-Path (Get-ToolsDir) 'iocs'
    if (-not (Test-Path $iocDir)) {
        New-Item -ItemType Directory -Path $iocDir -Force | Out-Null
        @(
            'Ophira IOC feeds - drop files here, every collection xrefs them offline (no API keys).',
            '',
            'Accepted formats:',
            '  - STIX 2.x bundle JSON  (indicators: domain-name, ipv4-addr, url, file:hashes.sha256/sha1/md5, file name)',
            '  - MISP JSON export      (Attribute type: domain, ip-dst, sha256, sha1, md5, filename)',
            '  - iocs.txt - plain text, one indicator per line (# starts a comment)',
            '',
            'Hits appear in csv\\ioc_hits_*.csv and the report IOC section with feed attribution.'
        ) | Set-Content -LiteralPath (Join-Path $iocDir 'README.txt') -Encoding UTF8
        Write-Host "  IOC feed folder ready: tools\iocs (drop STIX/MISP JSON or iocs.txt there)" -ForegroundColor Green
    }
}

function Invoke-UpdateRulesMode {
    $tDir = Get-ToolsDir
    $h = $null
    if ($tDir) { $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1 }
    if (-not $h) { Write-Host "hayabusa not found in tools\ - run Setup first" -ForegroundColor Red; return $false }
    $rulesDir = Join-Path $h.DirectoryName 'rules'
    $confirm = Read-Host "Replace hayabusa detection rules with the latest from hayabusa-rules? [Y/n]"
    if ($confirm -match '^[Nn]') { return $true }
    $bak = $null
    if (Test-Path $rulesDir) {
        $bak = "$rulesDir.bak"
        if (Test-Path $bak) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
        Move-Item -LiteralPath $rulesDir -Destination $bak -Force
    }
    try {
        Write-Host "Downloading latest rules from hayabusa-rules..." -ForegroundColor Cyan
        $zip = Join-Path ([IO.Path]::GetTempPath()) 'hayabusa-rules.zip'
        Invoke-WebRequest -Uri 'https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip' -OutFile $zip -UseBasicParsing -ErrorAction Stop
        $ex = Join-Path ([IO.Path]::GetTempPath()) 'hayabusa-rules-extract'
        if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $ex -Force -ErrorAction Stop
        $inner = Get-ChildItem $ex -Directory | Select-Object -First 1
        if (-not $inner) { throw 'archive layout unexpected' }
        Move-Item -LiteralPath $inner.FullName -Destination $rulesDir -Force -ErrorAction Stop
        Remove-Item $zip, $ex -Recurse -Force -ErrorAction SilentlyContinue
        $n = @(Get-ChildItem $rulesDir -Recurse -Filter '*.yml' -ErrorAction SilentlyContinue).Count
        if ($n -eq 0) { throw 'no rule files found after extract' }
        if ($bak -and (Test-Path $bak)) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
        Apply-ShippedRuleTuning -HayabusaExe $h
        Write-Host "Rules updated ($n rule files). (Chainsaw Sigma rules: git pull in tools\chainsaw\sigma)" -ForegroundColor Green
        return $true
    } catch {
        if ($bak -and (Test-Path $bak)) { Move-Item -LiteralPath $bak -Destination $rulesDir -Force }
        Write-Host "Rules update FAILED ($($_.Exception.Message)) - previous rules restored." -ForegroundColor Red
        return $false
    }
}

function Find-SigmaRuleFile {
    # Locates a rule's .yml in the bundled hayabusa rules by its RuleID GUID (first match wins).
    param([string]$RuleId, $HayabusaExe)
    if (-not $RuleId -or -not $HayabusaExe) { return $null }
    $rulesDir = Join-Path $HayabusaExe.DirectoryName 'rules'
    if (-not (Test-Path $rulesDir)) { return $null }
    $hit = Get-ChildItem -Path $rulesDir -Recurse -Filter '*.yml' -File -ErrorAction SilentlyContinue |
        Select-String -Pattern ([regex]::Escape($RuleId)) -List -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.Path }
    return $null
}

function Apply-ShippedRuleTuning {
    # v2.45: physically rewrite rule levels from the shipped tuning list (ophira-level-tuning.txt
    # next to the hayabusa exe). hayabusa 4.x does NOT read level_tuning.txt at scan time - it is
    # only an input for `hayabusa level-tuning`, which rewrites the rule yml files. We do the same
    # rewrite here (deterministic, no subprocess quirks) after Setup and after every
    # -Mode UpdateRules, because a rules refresh replaces the whole rules folder and resets levels.
    # Format per line: <rule-guid>,<informational|low|medium|high|critical>[ # comment]
    param($HayabusaExe)
    if (-not $HayabusaExe) { return }
    $tune = Join-Path $HayabusaExe.DirectoryName 'ophira-level-tuning.txt'
    if (-not (Test-Path -LiteralPath $tune)) { return }
    $entries = @()
    foreach ($line in @(Get-Content -LiteralPath $tune -ErrorAction SilentlyContinue)) {
        if ("$line" -match '^([0-9a-fA-F-]{36}),(informational|low|medium|high|critical)\b') {
            $entries += [pscustomobject]@{ Id = $Matches[1]; Level = $Matches[2] }
        }
    }
    if ($entries.Count -eq 0) { return }
    $rulesDir = Join-Path $HayabusaExe.DirectoryName 'rules'
    if (-not (Test-Path $rulesDir)) { return }
    $applied = 0
    foreach ($y in @(Get-ChildItem -Path $rulesDir -Recurse -Filter '*.yml' -File -ErrorAction SilentlyContinue)) {
        $raw = $null
        try { $raw = [IO.File]::ReadAllText($y.FullName) } catch { continue }
        if (-not $raw) { continue }
        $newRaw = $raw
        foreach ($e in $entries) {
            if (-not $newRaw.Contains($e.Id)) { continue }
            $newRaw = $newRaw -replace "(?m)^level: \w+(\s*)$", "level: $($e.Level)`$1"
        }
        if ($newRaw -ne $raw) {
            try { [IO.File]::WriteAllText($y.FullName, $newRaw); $applied++ } catch { }
        }
    }
    if ($applied -gt 0) { Write-Host "  shipped rule tuning applied to $applied rule file(s)" -ForegroundColor DarkGray }
}

function Invoke-TuneMode {
    # Sigma FP feedback loop: shows top-hit rules from the most recent case timeline,
    # writes picks into hayabusa's native exclude_rules.txt / level_tuning.txt.
    $h = Get-HayabusaExe
    if (-not $h) { Write-Host "hayabusa not found in tools\ - run Setup first" -ForegroundColor Red; return $false }
    $cfgDir = Join-Path $h.DirectoryName 'rules\config'
    if (-not (Test-Path $cfgDir)) { Write-Host "hayabusa rule config not found: $cfgDir" -ForegroundColor Red; return $false }
    $kit = Get-KitRoot
    $cand = @(Get-ChildItem -Path $kit -Recurse -Filter 'hayabusa_timeline.csv' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $tl = $null
    if ($cand.Count -eq 1) { $tl = $cand[0].FullName }
    elseif ($cand.Count -gt 1) {
        Write-Host ""
        Write-Host "  Found $($cand.Count) hayabusa timelines (newest first):" -ForegroundColor White
        for ($i = 0; $i -lt [Math]::Min(9, $cand.Count); $i++) { Write-Host ("   [{0}] {1}" -f ($i + 1), $cand[$i].FullName) }
        $sel = (Read-Host "  Which case? [1]").Trim()
        if (-not $sel) { $sel = '1' }
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le [Math]::Min(9, $cand.Count)) { $tl = $cand[[int]$sel - 1].FullName }
    }
    if (-not $tl) { $tl = (Read-Host "  Path to hayabusa_timeline.csv").Trim(' " ') }
    if (-not $tl -or -not (Test-Path -LiteralPath $tl)) { Write-Host "No timeline available - run a collection first (or enter a path)." -ForegroundColor Red; return $false }
    Write-Host "  Loading $([IO.Path]::GetFileName($tl)) ..." -ForegroundColor Gray
    $rows = @(Import-Csv -LiteralPath $tl)
    if ($rows.Count -eq 0) { Write-Host "Timeline is empty - nothing to tune." -ForegroundColor Yellow; return $true }
    $groups = @($rows | Group-Object RuleID, RuleTitle, Level | Sort-Object Count -Descending | Select-Object -First 25)
    Write-Host ""
    Write-Host "  Top noisy rules (by hit count):" -ForegroundColor White
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $g = $groups[$i]
        Write-Host ("   [{0,2}] x{1,-7} {2,-14} {3}" -f ($i + 1), $g.Count, "$($g.Group[0].Level)", "$($g.Group[0].RuleTitle)")
    }
    Write-Host ""
    Write-Host "  E = exclude (rule never fires again)   D = demote to informational (stays visible, loses verdict weight)" -ForegroundColor DarkGray
    Write-Host "  V = view the rule's .yml in Notepad    ED = edit the rule's .yml in Notepad (changes apply on the next run)" -ForegroundColor DarkGray
    $pick = (Read-Host "  Rule numbers to tune (comma-separated), A = all shown, ENTER = cancel").Trim()
    if (-not $pick) { Write-Host "Cancelled." -ForegroundColor Gray; return $true }
    $idx = @()
    if ($pick -match '^a$') { $idx = @(1..$groups.Count) }
    else { foreach ($p in ($pick -split ',')) { $pt = $p.Trim(); if ($pt -match '^\d+$' -and [int]$pt -ge 1 -and [int]$pt -le $groups.Count) { $idx += [int]$pt } } }
    if ($idx.Count -eq 0) { Write-Host "No valid selection." -ForegroundColor Yellow; return $true }
    $exPath = Join-Path $cfgDir 'exclude_rules.txt'
    $lvPath = Join-Path $cfgDir 'level_tuning.txt'
    $nEx = 0
    $nLv = 0
    foreach ($i in $idx) {
        $g = $groups[$i - 1]
        $rid = "$($g.Group[0].RuleID)"
        $title = "$($g.Group[0].RuleTitle)"
        $lvl = "$($g.Group[0].Level)"
        $act = (Read-Host "  [$title - $lvl] E / D / V=iew rule / ED=it rule / S=kip").Trim()
        if (-not $rid) { continue }
        if ($act -match '^e$') {
            Add-Content -LiteralPath $exPath -Value ("{0} # `"{1}`" (Ophira Tune {2})" -f $rid, $title, (Get-Date -Format 'yyyy-MM-dd')) -Encoding UTF8
            $nEx++
        } elseif ($act -match '^d$') {
            if (-not (Test-Path $lvPath)) { Set-Content -LiteralPath $lvPath -Value 'id,new_level' -Encoding UTF8 }
            Add-Content -LiteralPath $lvPath -Value ("{0},informational # `"{1}`" - Originally {2} (Ophira Tune {3})" -f $rid, $title, $lvl, (Get-Date -Format 'yyyy-MM-dd')) -Encoding UTF8
            $nLv++
        } elseif ($act -match '^(v|ed)$') {
            Write-Host "  locating rule file (searching bundled rules for RuleID)..." -ForegroundColor Gray
            $rf = Find-SigmaRuleFile -RuleId $rid -HayabusaExe $h
            if (-not $rf) {
                Write-Host "  rule file not found in tools\hayabusa\rules - bundled rules may predate this rule (try -Mode UpdateRules)" -ForegroundColor Yellow
            } elseif ($act -match '^ed$') {
                Write-Host "  $rf" -ForegroundColor Gray
                Write-Host "  Notepad will open - save your edit and close it to continue." -ForegroundColor Yellow
                Write-Host "  NOTE: manual rule edits are discarded when rules are refreshed via -Mode UpdateRules." -ForegroundColor Yellow
                Start-Process notepad.exe $rf -Wait | Out-Null
                Write-Host "  edit saved (applies on the next collection/run)" -ForegroundColor Green
            } else {
                Start-Process notepad.exe $rf | Out-Null
                Write-Host "  opened in Notepad: $rf" -ForegroundColor Gray
            }
        }
    }
    Write-Host ""
    Write-Host "Tune done: $nEx excluded, $nLv demoted (written into tools\hayabusa rules\config)." -ForegroundColor $(if ($nEx + $nLv -gt 0) { 'Green' } else { 'Gray' })
    Write-Host "These settings travel with Deploy (-PushTools) to every host. Re-run a collection to see the effect." -ForegroundColor Gray
    return $true
}

function Open-CaseSession {
    # Loads a case folder/zip and adopts its identity into $script: session vars
    # (shared by -Mode Parse and -Mode Process). Returns the case metadata or $null.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { Write-Host "  Path not found: $Path" -ForegroundColor Red; return $null }
    $tmp = $null
    $caseDirP = $Path
    if ((Test-Path -LiteralPath $Path -PathType Leaf) -and $Path -match '\.zip$') {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_open_" + (Get-Date -Format 'HHmmss'))
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [IO.Compression.ZipFile]::ExtractToDirectory($Path, $tmp)
        } catch { Write-Host "  cannot extract zip: $($_.Exception.Message)" -ForegroundColor Red; return $null }
        $caseDirP = $tmp
    }
    $meta = $null
    $cj = Join-Path $caseDirP 'case.json'
    if (Test-Path $cj) { try { $meta = Get-Content $cj -Raw | ConvertFrom-Json } catch { } }
    if (-not $meta) { Write-Host "  case.json not found - not an Ophira case folder?" -ForegroundColor Red; if ($tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }; return $null }
    $script:CaseDir = $caseDirP
    $script:CsvDir = Join-Path $caseDirP 'csv'
    $script:RawDir = Join-Path $caseDirP 'raw'
    $script:MemDir = Join-Path $caseDirP 'memory'
    $script:CaseLog = Join-Path $caseDirP 'collection.log'
    $script:Computer = "$($meta.Computer)"
    $script:CurrentCaseID = "$($meta.CaseID)"
    $script:CurrentAnalyst = "$($meta.Analyst)"
    $script:LogHours = $(if ($meta.LogHours) { [int]$meta.LogHours } else { 168 })
    $script:LogStartDT = $null
    $script:LogEndDT = $null
    try { if ("$($meta.LogStart)") { $script:LogStartDT = [datetime]$meta.LogStart } } catch { }
    try { if ("$($meta.LogEnd)") { $script:LogEndDT = [datetime]$meta.LogEnd } } catch { }
    $script:Sysmon = [bool]$meta.SysmonPresent
    # v2.67 (B3): legacy (pre-v2.55) case.json records AdminElevated as null (unknown) -
    # [bool]$null collapsed it to $false, so the verdict took the non-admin -15 coverage
    # penalty and claimed "Run was NOT elevated" while the report banner showed
    # 'Elevated: unknown' from the same metadata. Tri-state: null (or missing property,
    # which reads as $null on a ConvertFrom-Json object in PS 5.1) stays null - the
    # verdict's coverage math falls back to live Test-IsAdmin for a null value.
    $rawAdmin = $meta.AdminElevated
    $script:EndpointAdmin = if ($null -ne $rawAdmin) { [bool]$rawAdmin } else { $null }
    # v2.67 (B9): per-case reset - a re-parsed case without a previous-collection baseline
    # must not render "NEW since previous collection ()" or inherit the prior case's
    # baseline name from script scope.
    $script:DeltaBaseline = ''
    $script:DeltaCount = 0
    $st = $null
    try { $st = [datetime]"$($meta.StartedUTC)" } catch { }
    if (-not $st) { $st = Get-Date }
    $script:StartTime = $st
    $script:OpenCaseTmp = $tmp
    return $meta
}

function Invoke-ParseMode {
    # Analyst-side completion: run THIS kit's parsers over a case's raw\ evidence and
    # regenerate everything the endpoint couldn't finish (tool missing, .NET gap, skipped module).
    # Only reads raw\ inputs - never touches the analyst's own system state as evidence.
    param([string]$Path)
    Write-Host ""
    Write-Host "=== Finish a collected case (analyst-side parsing) ===" -ForegroundColor Cyan
    if (-not $Path) { $Path = (Read-Host "  Case folder or OPHIRA_*.zip path").Trim(' "') }
    $meta = Open-CaseSession -Path $Path
    if (-not $meta) { return $false }
    $caseDirP = $script:CaseDir
    $tmp = $script:OpenCaseTmp
    $cj = Join-Path $caseDirP 'case.json'
    Add-Content -LiteralPath $script:CaseLog -Encoding UTF8 -Value ("[{0}] === analyst parse session (Ophira v{1}) ===" -f (Get-Date -Format 'HH:mm:ss'), $ScriptVersion)
    Write-Host "  Case: $($meta.Computer)  collected $($meta.StartedUTC)  ($($meta.Tool))" -ForegroundColor Gray
    $before = @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue).Count

    # 1) modules that read ONLY raw\ evidence - reuse the real module code verbatim
    foreach ($id in @('4.6', '5.4', '8.4')) {
        $m = $script:Modules | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if ($m) {
            Write-Host "  module ${id}: $($m.Name)" -ForegroundColor Cyan
            try { & $m.Run } catch { Write-Host "    failed: $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }

    # 2) parse-only halves of the copy+parse modules (their raw inputs ship inside the zip)
    $tDir = Get-ToolsDir
    $findTool = {
        param($filter)
        if ($tDir) { Get-ChildItem -Path $tDir -Recurse -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
    }
    $runTool = {
        param($exe, $toolArgs, $label)
        if (-not $exe) { Write-Host "  $label - tool not in tools\ (run -Mode Setup)" -ForegroundColor DarkYellow; return }
        Write-Host "  $label..." -ForegroundColor Cyan
        $null = Invoke-NativeTool -ExePath $exe.FullName -ToolArgs $toolArgs -WorkingDirectory $exe.DirectoryName
    }
    $pfDst = Join-Path $script:RawDir 'prefetch'
    if ((Test-Path $pfDst) -and -not (Test-CaseCsv 'prefetch_parsed')) {
        $pfOut = Get-CaseCsvFullPath 'prefetch_parsed'
        & $runTool (& $findTool 'PECmd*.exe') @('-d', $pfDst, '--csv', (Split-Path $pfOut -Parent), '--csvf', 'prefetch_parsed.csv') 'PECmd: prefetch run counts'
    }
    $recDst = Join-Path $script:RawDir 'recent'
    if ((Test-Path $recDst) -and -not (Test-CaseCsv 'lnk_parsed')) {
        $lnkOut = Get-CaseCsvFullPath 'lnk_parsed'
        & $runTool (& $findTool 'LECmd*.exe') @('-d', $recDst, '--csv', (Split-Path $lnkOut -Parent), '--csvf', 'lnk_parsed.csv') 'LECmd: recent LNK files'
    }
    $jlDst = Join-Path $script:RawDir 'jumplists'
    # v2.74: the wildcard Test-CaseCsv name covers the flat-root splits AND the mapped folder
    # (post-sortment sweep) - the old root-only glob re-ran JLECmd after the sweep had foldered them
    if ((Test-Path $jlDst) -and -not (Test-CaseCsv 'jumplist_parsed*')) {
        $jlOut = Get-CaseCsvFullPath 'jumplist_parsed'
        & $runTool (& $findTool 'JLECmd*.exe') @('-d', $jlDst, '--csv', (Split-Path $jlOut -Parent), '--csvf', 'jumplist_parsed.csv') 'JLECmd: jump lists'
    }
    # v2.50: shimcache (AppCompatCache in the collected SYSTEM hive) - "executed from" evidence
    # that survives prefetch/amcache deletion; the no-Sysmon spine's deepest artifact
    $sysHiv = Join-Path (Join-Path $script:RawDir 'registry') 'SYSTEM.hiv'
    if ((Test-Path $sysHiv) -and -not (Test-CaseCsv 'shimcache')) {
        $shOut = Get-CaseCsvFullPath 'shimcache'
        & $runTool (& $findTool 'AppCompatParser*.exe') @('-f', $sysHiv, '--csv', (Split-Path $shOut -Parent), '--csvf', 'shimcache.csv') 'AppCompatParser: shimcache (SYSTEM hive)'
    }
    # RecentFileCache (raw-copied by 8.13, never parsed before v2.50)
    $rfcSrc = Join-Path (Join-Path $script:RawDir 'extras') 'appcompat\RecentFileCache.bcf'
    if ((Test-Path $rfcSrc) -and -not (Test-CaseCsv 'recentfilecache')) {
        $rfcOut = Get-CaseCsvFullPath 'recentfilecache'
        & $runTool (& $findTool 'AppCompatParser*.exe') @('-f', $rfcSrc, '--csv', (Split-Path $rfcOut -Parent), '--csvf', 'recentfilecache.csv') 'AppCompatParser: RecentFileCache'
    }
    $brDst = Join-Path $script:RawDir 'browser'
    if ((Test-Path $brDst) -and -not (Test-CaseCsv 'browser_history')) {
        $sqlExe = & $findTool 'SQLECmd*.exe'
        if ($sqlExe) {
            & $runTool $sqlExe @('-d', $brDst, '--csv', $script:CsvDir) 'SQLECmd: browser history/downloads'
            $merge = {
                param([string]$glob, [string]$name)
                $files = @(Get-ChildItem -Path $script:CsvDir -Filter $glob -File -ErrorAction SilentlyContinue)
                $all = @()
                foreach ($f2 in $files) { try { $all += @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { } }
                if ($all.Count -gt 0) { Save-Rows -Name $name -Rows $all }
                foreach ($f2 in $files) { Remove-Item -LiteralPath $f2.FullName -Force -ErrorAction SilentlyContinue }
            }
            & $merge '*ChromiumBrowser_HistoryVisits_*.csv' 'browser_history'
            & $merge '*ChromiumBrowser_Downloads_*.csv' 'browser_downloads'
            & $merge '*ChromiumBrowser_KeywordSearches_*.csv' 'browser_searches'
            Get-ChildItem -Path $script:CsvDir -Filter 'SQLite.Interop.dll' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Invoke-BrowserIocXref
        }
    }
    # v2.59: SRUM deep parse - module 5.3 saves the locked SRUDB.dat raw; SrumECmd's per-app
    # usage table (bytes sent/received per hour over ~30 days) is the analyst-side completion
    # (net9 like SQLECmd - collected on the endpoint, parsed here, never shipped)
    $sruDb = Join-Path $script:RawDir 'sru\SRUDB.dat'
    if ((Test-Path -LiteralPath $sruDb) -and -not (Test-CaseCsv 'srum_usage')) {
        $sruExe = & $findTool 'SrumECmd*.exe'
        if ($sruExe) {
            $sruSoft = Join-Path (Join-Path $script:RawDir 'registry') 'SOFTWARE.hiv'
            $sruArgs = @('-f', $sruDb)
            if (Test-Path -LiteralPath $sruSoft) { $sruArgs += @('-r', $sruSoft) }
            $sruTmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_srum_" + (Get-Date -Format 'HHmmss'))
            New-Item -ItemType Directory -Path $sruTmp -Force | Out-Null
            & $runTool $sruExe ($sruArgs + @('--csv', $sruTmp)) 'SrumECmd: SRUM per-app network usage'
            $f3 = @(Get-ChildItem -Path $sruTmp -Filter '*NetworkUsages_Output.csv' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($f3.Count -gt 0) {
                $rows3 = @(ConvertFrom-SrumCsv -Path $f3[0].FullName)
                if ($rows3.Count -gt 0) { Save-Rows -Name 'srum_usage' -Rows $rows3; Write-Host "  SRUM: $($rows3.Count) row(s) -> csv\$(Get-CaseCsvPath 'srum_usage')" -ForegroundColor Gray }
            }
            Remove-Item -LiteralPath $sruTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    # RECmd batch registry deep-dive over saved hives (v2.25; v2.53: .reb format - RECmd 2.x
    # rejects the old flat .bn batches with a YAML syntax error, so the deep-dive was silently dead)
    $regDir2 = Join-Path $script:RawDir 'registry'
    if (Test-Path $regDir2) {
        $reExe = & $findTool 'RECmd*.exe'
        $bn = $null
        try { $bn = Join-Path (Get-KitRoot) 'tools\recmd\ophira-registry.reb' } catch { }
        if ($reExe -and $bn -and (Test-Path $bn) -and -not (Test-CaseCsv 'registry_recmd')) {
            Write-Host "  RECmd: batch registry deep-dive..." -ForegroundColor Cyan
            $outDir = Join-Path $script:CsvDir 'recmd_out'
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            $hives = @(Get-ChildItem -LiteralPath $regDir2 -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(hiv|hive|dat)$' })
            foreach ($h in $hives) {
                $null = Invoke-NativeTool -ExePath $reExe.FullName -ToolArgs @('--bn', $bn, '-f', $h.FullName, '--csv', $outDir, '--csvf', "$($h.BaseName).csv") -WorkingDirectory $reExe.DirectoryName
            }
            $all = @()
            foreach ($f2 in @(Get-ChildItem -Path $outDir -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
                try { $rows2 = @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { continue }
                foreach ($r2 in $rows2) {
                    # v2.53: RECmd 2.x renamed the output columns (KeyPath/ValueName/ValueType/
                    # ValueData/LastWriteTimestamp - the 1.x names had spaces); accept both
                    $kp2 = "$($r2.'Key Path')"; if (-not $kp2) { $kp2 = "$($r2.KeyPath)" }
                    $vn2 = "$($r2.'Value Name')"; if (-not $vn2) { $vn2 = "$($r2.ValueName)" }
                    $vt2 = "$($r2.'Value Type')"; if (-not $vt2) { $vt2 = "$($r2.ValueType)" }
                    $vd2 = "$($r2.'Value')"; if (-not $vd2) { $vd2 = "$($r2.ValueData)" }
                    $lw2 = "$($r2.'Last Write Timestamp')"; if (-not $lw2) { $lw2 = "$($r2.LastWriteTimestamp)" }
                    $all += [pscustomobject]@{ Hive = $f2.BaseName; KeyPath = $kp2; ValueName = $vn2; ValueType = $vt2; Value = ($vd2 -replace '\s+', ' '); LastWrite = $lw2 }
                }
            }
            Save-Rows -Name 'registry_recmd' -Rows $all
            Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
            if ($all.Count -gt 0) { Write-Host "  RECmd: $($all.Count) registry value(s) via batch -> csv\registry_recmd.csv" -ForegroundColor Gray }
        }
    }
    # EvtxECmd: FULL evtx->CSV conversion for timeframe deep-dives (v2.25)
    $evSrc = Join-Path $script:RawDir 'evtx'
    if (Test-Path $evSrc) {
        $evExe = & $findTool 'EvtxECmd*.exe'
        if ($evExe -and -not (Test-Path (Join-Path $script:CsvDir 'evtx_ecmd'))) {
            Write-Host "  EvtxECmd: full evtx->CSV conversion..." -ForegroundColor Cyan
            $outDir = Join-Path $script:CsvDir 'evtx_ecmd'
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            $n2 = 0
            foreach ($ev in @(Get-ChildItem -LiteralPath $evSrc -Filter '*.evtx' -File -ErrorAction SilentlyContinue)) {
                $null = Invoke-NativeTool -ExePath $evExe.FullName -ToolArgs @('-f', $ev.FullName, '--csv', $outDir, '--csvf', "$($ev.BaseName).csv") -WorkingDirectory $evExe.DirectoryName
                $n2++
            }
            if ($n2 -gt 0) { Write-Host "  EvtxECmd: $n2 log file(s) fully converted -> csv\evtx_ecmd\ (filter EventTime for deep-dives)" -ForegroundColor Gray }
        }
    }

    # 3) regenerate everything derived from csv\
    Invoke-RegenerateOutputs -Case $meta
    try {
        $meta | Add-Member -NotePropertyName AnalystParsedUTC -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
        $meta | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $cj -Encoding UTF8
    } catch { }

    $after = @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue).Count
    Write-Host ""
    Write-Host "Done: $before -> $after CSVs. Regenerated report.html / verdict.json / supertimeline.csv / siem_export.ndjson." -ForegroundColor Green
    Write-Host "csv\parse_needed.csv lists anything that still needs the ORIGINAL endpoint (live-only sources)." -ForegroundColor Gray
    # v2.57: the analyst TODO next to the generated results - don't forget the plaso deep-timeline pass
    $plasoCsvP = Join-Path (Split-Path -Parent $script:CsvDir) 'plaso.csv'
    if (-not (Test-Path -LiteralPath $plasoCsvP)) {
        Write-Host "deep-timeline (optional): log2timeline.py <case>\raw  ->  psort l2tcsv as plaso.csv in the case root  ->  re-run -Mode Parse to merge it into supertimeline.csv" -ForegroundColor DarkCyan
    }

    # v2.74: [O] opens the freshly rebuilt report - offered only when a human picked this
    # flow (menu-driven Parse prompts for the path; CLI -ParsePath runs are unattended).
    # Before the re-pack so the temp copy of a zip-parsed case still exists to open.
    if (-not $PSBoundParameters.ContainsKey('Path') -and -not $NoMenu) { & $script:OfferOpenReport -Dir $caseDirP -Prompt:$true }

    # 4) re-pack if the input was a zip
    if ($tmp) {
        try {
            # v2.80 (T4/I3): regenerate manifest.txt BEFORE re-zipping - the zip content changed
            # (derived outputs rebuilt), stale endpoint hashes would lie. Keep the endpoint's
            # original collection header lines, note the analyst-side refresh, refresh hashes,
            # and append the PACKAGE SHA256 of the new zip after compression (same convention
            # as New-Package).
            $mfPath = Join-Path $caseDirP 'manifest.txt'
            $mfHdr = @()
            if (Test-Path -LiteralPath $mfPath) {
                $origMf = @(Get-Content -LiteralPath $mfPath)
                $mfCut = [Array]::IndexOf($origMf, '')
                if ($mfCut -gt 0) { $mfHdr = @($origMf | Select-Object -First $mfCut) }
            }
            $mfHdr += "ANALYST-PARSED: Ophira v$ScriptVersion re-processed this package at $((Get-Date).ToUniversalTime().ToString('u')) - per-file hashes below were refreshed analyst-side; the PACKAGE SHA256 line appended after re-zipping is the hash of THIS package."
            New-CaseManifest -ForDir $caseDirP -HeaderLines $mfHdr
            $items = Get-ChildItem -LiteralPath $caseDirP | Where-Object { $_.Name -ne 'memory' } | ForEach-Object { $_.FullName }
            Compress-Archive -Path $items -DestinationPath $Path -CompressionLevel Fastest -Force
            $rpZipHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            Add-Content -LiteralPath $mfPath -Encoding UTF8 -Value ""
            Add-Content -LiteralPath $mfPath -Encoding UTF8 -Value "PACKAGE SHA256 ($([IO.Path]::GetFileName($Path))): $rpZipHash"
            Write-Host "Repacked: $Path" -ForegroundColor Green
        } catch { Write-Host "repack failed ($($_.Exception.Message)) - parsed files remain in $caseDirP" -ForegroundColor Yellow }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $true
}

function Invoke-SeedIocsMode {
    # v2.51: arm the fleet feed with one indicator without hand-editing iocs.txt.
    # Validates the format, dedupes against the existing list, appends with attribution.
    param([string]$Value)
    $tDir = Get-ToolsDir
    if (-not $tDir) { Write-Host "  tools\ not found - run from the kit root" -ForegroundColor Red; return $false }
    if (-not $Value) { $Value = (Read-Host "  Indicator (hash / IP / domain)").Trim() }
    $v = "$Value".Trim()
    $kind = ''
    if ($v -match '^[a-fA-F0-9]{32,64}$') { $kind = 'hash'; $v = $v.ToUpper() }
    elseif ($v -match '^(\d{1,3}\.){3}\d{1,3}$') { $kind = 'ip' }
    elseif ($v -match '^(?=.{4,253}$)[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z]{2,}$') { $kind = 'domain'; $v = $v.ToLower() }
    if (-not $kind) { Write-Host "  '$v' does not look like a hash / IP / domain" -ForegroundColor Red; return $false }
    $f = Join-Path $tDir 'iocs.txt'
    if (Test-Path -LiteralPath $f) {
        $dup = @(Get-Content -LiteralPath $f | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ -eq $v })
        if ($dup.Count -gt 0) { Write-Host "  '$v' is already in iocs.txt - nothing to do" -ForegroundColor Yellow; return $true }
    }
    Add-Content -LiteralPath $f -Value "$v # seeded $(Get-Date -Format u) by $env:USERNAME ($kind)" -Encoding UTF8
    Write-Host "  added: $v ($kind) -> $f" -ForegroundColor Green
    Write-Host "  future collections xref it: flash IOC check, DNS queries, connections, MFT filenames, execution hashes" -ForegroundColor Gray
    return $true
}

function Invoke-WatchMode {
    # v2.51: live detonation monitor - a read-only rolling diff of what changed on THIS PC
    # since the last tick: new processes, new external connections, new autoruns (Run keys +
    # auto services), new Defender detections. Analyst-side situational awareness while a
    # sample detonates; no case is written, the host is only sampled like the volatile phase.
    param([int]$Interval = 15)
    if ($Interval -lt 3) { $Interval = 3 }
    Write-Host ""
    Write-Host "=== Watch mode - live diff every ${Interval}s (Ctrl+C to stop) ===" -ForegroundColor Cyan
    if (-not (Test-IsAdmin)) { Write-Host "  not elevated: command lines of other users' processes hidden, connection attribution limited" -ForegroundColor DarkYellow }
    $defOk = $true
    try { $null = Get-MpThreatDetection -ErrorAction Stop } catch { $defOk = $false; Write-Host "  Defender detections not readable on this host - that channel is skipped" -ForegroundColor DarkYellow }
    Write-Host "  tick 1 is the baseline (nothing is 'new' yet) - detonate AFTER it prints" -ForegroundColor Gray
    Write-Host ""
    $state = @{ Proc = @{}; Net = @{}; Auto = @{}; DefCount = -1 }
    $privRe = '^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|::1$|fe80:|fc|fd|ff)'
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $stamp = { Get-Date -Format 'HH:mm:ss' }
    $sample = {
        $out = @{ Proc = @{}; Net = @{}; Auto = @{}; DefCount = $state.DefCount; ProcRows = @{} }
        foreach ($p in @(Get-CimInstance Win32_Process -Property ProcessId, Name, CommandLine, ParentProcessId -ErrorAction SilentlyContinue)) {
            $k = "$($p.ProcessId)"
            $out.Proc[$k] = $true
            $out.ProcRows[$k] = $p
        }
        $conns = @()
        try {
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { "$($_.RemoteAddress)" -and -not ("$($_.RemoteAddress)" -match $privRe) })
        } catch {
            foreach ($l in (& netstat.exe -ano 2>$null)) {
                if ($l -notmatch '^\s*(TCP)\s+\S+:(\d+)\s+(\S+):(\S+)\s+ESTABLISHED\s+(\d+)') { continue }
                $rip = $Matches[3]; $rport = $Matches[4]; $opid = $Matches[5]
                if ($rip -match $privRe) { continue }
                $conns += [pscustomobject]@{ RemoteAddress = $rip; RemotePort = $rport; OwningProcess = $opid }
            }
        }
        foreach ($c in $conns) {
            $k = $c.RemoteAddress.ToLower() + ':' + $c.RemotePort + ':' + $c.OwningProcess
            $out.Net[$k] = $true
        }
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            foreach ($vp in @(Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue).PSObject.Properties) {
                if ("$($vp.Name)" -match '^PS') { continue }
                $out.Auto[("$rk|$($vp.Name)".ToLower())] = "$($vp.Name)=$($vp.Value)"
            }
        }
        foreach ($s in @(Get-CimInstance Win32_Service -Property Name, State, PathName -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue)) {
            $out.Auto[("svc|$($s.Name)".ToLower())] = "service $($s.Name) [$($s.State)] $($s.PathName)"
        }
        if ($defOk) {
            try { $out.DefCount = @(Get-MpThreatDetection -ErrorAction Stop).Count } catch { }
        }
        return $out
    }
    try {
        $tick = 0
        while ($true) {
            $tick++
            $cur = & $sample
            if ($tick -eq 1) {
                $state.Proc = $cur.Proc; $state.Net = $cur.Net; $state.Auto = $cur.Auto; $state.DefCount = $cur.DefCount
                Write-Host ("  baseline: {0} process(es), {1} external connection(s), {2} autorun row(s), Defender detections: {3}" -f $cur.Proc.Count, $cur.Net.Count, $cur.Auto.Count, $cur.DefCount) -ForegroundColor Gray
            } else {
                $new = 0
                foreach ($k in $cur.Proc.Keys) {
                    if ($state.Proc.ContainsKey($k)) { continue }
                    $p = $cur.ProcRows[$k]
                    $parent = ''
                    try { $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -Property Name -ErrorAction Stop; if ($pp) { $parent = "$($pp.Name)" } } catch { }
                    $new++
                    Write-Host ("  {0} [PROC]   {1} (pid {2}) <- {3} | {4}" -f (& $stamp), $p.Name, $p.ProcessId, $(if ($parent) { $parent } else { "ppid $($p.ParentProcessId)" }), $p.CommandLine) -ForegroundColor Yellow
                }
                foreach ($k in $cur.Net.Keys) {
                    if ($state.Net.ContainsKey($k)) { continue }
                    $parts = $k -split ':'
                    $pn = ''
                    $pkey = $parts[-1]
                    if ($cur.ProcRows.ContainsKey($pkey)) { $pn = "$($cur.ProcRows[$pkey].Name)" }
                    $new++
                    Write-Host ("  {0} [NET]    {1}:{2} <- {3} (pid {4})" -f (& $stamp), ($parts[0..($parts.Count - 3)] -join ':'), $parts[$parts.Count - 2], $(if ($pn) { $pn } else { 'unknown' }), $pkey) -ForegroundColor Cyan
                }
                foreach ($k in $cur.Auto.Keys) {
                    if ($state.Auto.ContainsKey($k)) { continue }
                    $new++
                    Write-Host ("  {0} [AUTORUN] {1}" -f (& $stamp), $cur.Auto[$k]) -ForegroundColor Red
                }
                if ($cur.DefCount -gt $state.DefCount -and $state.DefCount -ge 0) {
                    $new++
                    Write-Host ("  {0} [DEFEND] detection count {1} -> {2}" -f (& $stamp), $state.DefCount, $cur.DefCount) -ForegroundColor Red
                    try { foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3)) { Write-Host ("            {0}: {1}" -f $d.ProcessName, ($d.ThreatID)) } } catch { }
                }
                $state.Proc = $cur.Proc; $state.Net = $cur.Net; $state.Auto = $cur.Auto; $state.DefCount = $cur.DefCount
                if ($new -eq 0) { Write-Host ("  {0}  tick {1}: nothing new" -f (& $stamp), $tick) -ForegroundColor DarkGray }
            }
            Start-Sleep -Seconds $Interval
        }
    } finally {
        Write-Host ""
        Write-Host "  watch ended after $tick tick(s) - run the collection now to capture everything seen" -ForegroundColor Cyan
    }
}

function Invoke-FocusEngine {
    # Analyst-side focus dossier: seed with a process name, PID, path fragment or hash and
    # iteratively expand the entity set across every collected CSV (name -> path -> hash ->
    # parent/child -> DLL -> network) until the activity chain closes. Writes focus\ inside
    # the case folder: focus_terms.json, focus_hits.csv, focus_chain.csv, focus_report.html.
    # Replaces the old flat process_pivot grep (v2.40).
    # Multi-instance handling: entity groups are keyed by normalized path + hash, so several
    # live/historical instances of one name group together while a same-name binary at a
    # different path (masquerade) splits into its own group. Instances are listed per
    # PID/ProcessGuid where the collectors captured them; name-level artifacts
    # (prefetch/amcache/autoruns/yara) stay in the shared view.
    param([string]$Path, [string]$Indicator, [string]$After, [string]$Before)
    Write-Host ""
    Write-Host "=== Focus engine (build one entity's activity chain) ===" -ForegroundColor Cyan
    # v2.73 wizard: no typed path demanded any more - the case that is already on this PC
    # (kit root) is picked up automatically; with none, a Quick collection is offered right
    # here so menu [9] just works on the box the responder is sitting on. -Path keeps CLI
    # parity (-Mode Focus/-Process -ParsePath ...) and skips the wizard entirely.
    $meta = $null
    if (-not $Path) {
        $retrying = $false
        while (-not $meta) {
            $kit = Get-KitRoot
            $cands = @(Get-ChildItem -Path $kit -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer -or ("$($_.Name)" -match '\.zip$') } |
                Sort-Object Name -Descending)
            if ($cands.Count -eq 0) {
                Write-Host "  scanned for cases in: $kit" -ForegroundColor Gray
                if ($script:NoMenu) {
                    # unattended runs never prompt for a collection - name the CLI way out instead
                    Write-Host "  No case found on this PC. Point at one with: .\Ophira.ps1 -Mode Focus -ParsePath <case folder or OPHIRA_*.zip> -ProcessName <indicator>" -ForegroundColor Yellow
                    return $false
                }
                $yn = (Read-Host "  No case found on this PC. Run a Quick collection now (~1-2 min), then focus? [Y/n]").Trim()
                if ($yn.StartsWith('n', [StringComparison]::OrdinalIgnoreCase)) {
                    Write-Host "  ok - point at a case yourself with: .\Ophira.ps1 -Mode Focus -ParsePath <case folder or OPHIRA_*.zip> -ProcessName <indicator>" -ForegroundColor Gray
                    return $false
                }
                # the menu [1] collect arm relaunches a child powershell with -Mode Collect +
                # preset args; this wizard uses the same relaunch shape as -Mode Canary phase 3
                # (Start-Process -Wait + before/after OPHIRA_* dir diff) because it RETURNS the
                # fresh case folder path so the wizard can open it and continue focusing
                Write-Host "  collecting (Quick preset, ~1-2 min)..." -ForegroundColor Cyan
                $before0 = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue)
                $cmd0 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode Collect -NoMenu -NoElevate -Preset Quick -OutputPath `"$kit`""
                try {
                    if (Test-IsAdmin) { $null = Start-Process -FilePath 'powershell.exe' -ArgumentList $cmd0 -Wait -WindowStyle Hidden }
                    else { $null = Start-Process -FilePath 'powershell.exe' -ArgumentList $cmd0 -Wait -Verb RunAs }
                } catch {
                    Write-Host "  collection did not start ($($_.Exception.Message))" -ForegroundColor Red
                    return $false
                }
                $fresh = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue |
                    Where-Object { $before0 -notcontains $_ } | Sort-Object Name -Descending | Select-Object -First 1)
                if (-not $fresh) { Write-Host "  collection produced no case folder under $kit - see its collection.log" -ForegroundColor Red; return $false }
                Write-Host "  collection done" -ForegroundColor Gray
                continue  # auto-detect again: the fresh case is the only/newest candidate
            }
            if ($cands.Count -eq 1 -and -not $retrying) {
                $Path = $cands[0].FullName
                Write-Host "  using case: $($cands[0].Name)" -ForegroundColor Gray
            } else {
                Write-Host "  candidate cases (newest first):" -ForegroundColor Gray
                for ($ci = 0; $ci -lt $cands.Count; $ci++) { Write-Host ("   [{0}] {1}" -f ($ci + 1), $cands[$ci].Name) }
                while ($true) {
                    $pick = (Read-Host "  case number (Enter = 1, the newest)").Trim()
                    if (-not $pick) { $pick = '1' }
                    $pickN = 0
                    if ([int]::TryParse($pick, [ref]$pickN) -and $pickN -ge 1 -and $pickN -le $cands.Count) { $Path = $cands[$pickN - 1].FullName; break }
                    Write-Host "  pick 1-$($cands.Count)" -ForegroundColor Yellow
                }
            }
            $meta = Open-CaseSession -Path $Path
            if (-not $meta) {
                # not a crash: say so and re-prompt the numbered list (Enter then re-picks the newest)
                $failedName = $Path
                try { $lf0 = (Split-Path $Path -Leaf); if ($lf0) { $failedName = $lf0 } } catch { }
                Write-Host "  could not open '$failedName' - pick again" -ForegroundColor Red
                $retrying = $true
            }
        }
    } else {
        $meta = Open-CaseSession -Path $Path
        if (-not $meta) { return $false }
    }
    if (-not $Indicator) { $Indicator = (Read-Host "  Name, PID, path, hash, IP, ip:port or port").Trim() }
    if (-not $Indicator) { Write-Host "  no indicator given" -ForegroundColor Red; return $false }
    # v2.73 optional time window, v2.75 fix: prompted only in the interactive auto-detect
    # flow (-Path unbound = menu [9] wizard); -Path callers (CLI -ParsePath, menu [P]) never
    # prompt - -After/-Before set the window directly, both bounds blank = everything
    if (-not $PSBoundParameters.ContainsKey('Path') -and -not $After -and -not $Before) {
        $After = (Read-Host "  From (yyyy-MM-dd [HH:mm], blank = all)").Trim()
        $d0 = [datetime]::MinValue
        if ($After -and -not [datetime]::TryParse($After, [ref]$d0)) {
            Write-Host "  not a date: '$After'" -ForegroundColor Yellow
            $After = (Read-Host "  From (yyyy-MM-dd [HH:mm], blank = all)").Trim()
            if ($After -and -not [datetime]::TryParse($After, [ref]$d0)) {
                Write-Host "  still not a date - proceeding without the from-bound" -ForegroundColor Yellow
                $After = ''
            }
        }
        $Before = (Read-Host "  To (blank = all)").Trim()
        if ($Before -and -not [datetime]::TryParse($Before, [ref]$d0)) {
            Write-Host "  not a date: '$Before'" -ForegroundColor Yellow
            $Before = (Read-Host "  To (blank = all)").Trim()
            if ($Before -and -not [datetime]::TryParse($Before, [ref]$d0)) {
                Write-Host "  still not a date - proceeding without the to-bound" -ForegroundColor Yellow
                $Before = ''
            }
        }
    }
    return (Invoke-FocusCore -Indicator $Indicator -Meta ([pscustomobject]@{ Computer = "$($meta.Computer)"; CaseID = "$($meta.CaseID)" }) -After $After -Before $Before)
}

function Invoke-FocusCore {
    # Focus engine core (v2.45 split) - runs inside an already-open case session
    # ($script:CaseDir/$script:CsvDir set). Called by Invoke-FocusEngine (analyst-side) and by
    # the auto-focus trigger in Invoke-RegenerateOutputs: when the scoring calls a process
    # malicious (HIGH) - or a YARA-high/IOC fires - the dossier builds itself, so every case
    # ships with the "everything it did" story pre-assembled. Also persists
    # focus\focus_instances_detail.json (per-instance joins + activity graph SVG) for the
    # main report's Focus section embed.
    param([string]$Indicator, [pscustomobject]$Meta, [string]$After, [string]$Before)
    $meta = $Meta
    if (-not $meta) { $meta = [pscustomobject]@{ Computer = "$($script:Computer)"; CaseID = "$($script:CurrentCaseID)" } }
    $focusDir = Join-Path $script:CaseDir 'focus'
    New-Item -ItemType Directory -Path $focusDir -Force | Out-Null
    # v2.73 optional time window on the EVIDENCE rows (focus_hits + focus_chain): a row inside
    # [after, before] stays, out-of-window rows are dropped, and rows with NO parseable time
    # are KEPT when no window is set (today's behavior, byte-identical) but DROPPED AND
    # COUNTED when one is - the analyst asked for a window, undated rows cannot prove
    # membership. The expansion term graph is NOT windowed (names/paths/hashes stay whole).
    $afterDT = $null; $beforeDT = $null; $winDropped = 0
    if ("$After") { try { $afterDT = [datetime]$After } catch { Write-Host "  ignoring -After '$After' (not a date)" -ForegroundColor Yellow } }
    if ("$Before") { try { $beforeDT = [datetime]$Before } catch { Write-Host "  ignoring -Before '$Before' (not a date)" -ForegroundColor Yellow } }
    Write-Host "  Case: $($meta.Computer)  indicator: $Indicator" -ForegroundColor Gray

    # OS-infra process names: matched as evidence, but never seeded as new expansion terms
    # (otherwise the chain explodes into everything that ever had explorer.exe as a parent).
    $guard = '^(?i)(explorer|cmd|conhost|svchost|services|lsass|smss|winlogon|csrss|dllhost|runtimebroker|taskhostw|wmiprvse|sihost|ctfmon|fontdrvhost|audiodg|dwm|dwm\.screenclip|searchapp|searchindexer|searchhost|spoolsv|msmpeng|nissrv|wudfhost|memcompression|system|idle|werfault|werfaultsecure|backgroundtaskhost|applicationframehost|textinputhost|startmenuexperiencehost|shellexperiencehost|smartscreen|securityhealthservice|securityhealthsystray|logonui|nx |\d+)\.(exe|sys)$'
    $nameCols = '^(?i)(Name|Process|Image|Application|NewProcess|ParentProcess|Dll|ImageLoaded|SourceImage|TargetImage|OriginalFileName|Binary|Executable|Service|Driver)$'
    $pathCols = '^(?i)(Path|ImagePath|FullPath|Application|Image|Process|NewProcess|ParentProcess|TargetFilename|ImageLoaded|Dll|SourceImage|ExecutablePath|Binary|ProcessPath)$'
    $hashCols = '^(?i)(SHA256|SHA1|MD5|Hashes|Hash)$'
    $pidCols = '^(?i)(PID|PPID|ProcessId|NewProcessId|ParentProcessId|CreatorPid)$'
    $ipCols = '^(?i)(DestIp|DestinationIp|SourceIp|RemoteIp|IpAddress|IP)$'
    $portCols = '^(?i)(DestPort|DestinationPort|RemotePort|LocalPort|SourcePort|Port)$'
    $guidRe = '^(?i)ProcessGuid$'

    # ---- seed terms -------------------------------------------------------
    $names = New-Object System.Collections.Generic.List[string]
    $paths = New-Object System.Collections.Generic.List[string]
    $hashes = New-Object System.Collections.Generic.List[string]
    $pids = New-Object System.Collections.Generic.List[string]
    $guids = New-Object System.Collections.Generic.List[string]
    $ips = New-Object System.Collections.Generic.List[string]
    $ports = New-Object System.Collections.Generic.List[string]
    $ind = "$Indicator".Trim().ToLower()
    if ($ind -match '^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$') {
        $hashes.Add($ind)
    } elseif ($ind -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$') {
        # v2.53: ip:port seed - the "I know the C2 endpoint, whose machine talked to it" pivot
        $ips.Add($Matches[1]); $ports.Add($Matches[2])
    } elseif ($ind -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $ips.Add($ind)
    } elseif ($ind -match '^\d{1,10}$') {
        # v2.53: a bare number is a PID, a port, or both - seed as all candidates
        # (whichever has data in this case wins; the other simply matches nothing)
        $pids.Add($ind)
        $pids.Add(('0x{0:x}' -f ([int64]$ind)))
        if ([int64]$ind -ge 1 -and [int64]$ind -le 65535) { $ports.Add($ind) }
    } elseif ($ind.Contains('\')) {
        $paths.Add((("$ind" -replace '(?i)^\\device\\harddiskvolume\d+', 'C:' -replace '/', '\').ToLower()))
    } else {
        $names.Add($ind)
    }

    $addName = {
        param([string]$v)
        $x = "$v".Trim().ToLower()
        if ($x.Length -lt 4 -or $x.Length -gt 260) { return }
        if ($x -match $guard) { return }
        if (-not $names.Contains($x) -and $names.Count -lt 60) { $names.Add($x) }
    }
    $addPath = {
        param([string]$v)
        $x = ("$v" -replace '(?i)^\\device\\harddiskvolume\d+', 'C:' -replace '/', '\').ToLower()
        if ($x.Length -lt 5 -or -not $x.Contains('\')) { return }
        if (-not $paths.Contains($x) -and $paths.Count -lt 60) { $paths.Add($x) }
    }
    $addHash = {
        param([string]$v)
        $x = "$v".Trim().ToLower()
        if ($x -notmatch '^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$') { return }
        if (-not $hashes.Contains($x) -and $hashes.Count -lt 12) { $hashes.Add($x) }
    }
    $addIp = {
        # network pivot: remote IPs from matched rows pull in beacon/connection evidence
        # that never carries the process name itself
        param([string]$v)
        $x = "$v".Trim().ToLower()
        if ($x -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return }
        if ($x -match '^(0\.0\.0\.0|255\.255\.255\.255|22[4-9]\.|2[3-5]\d\.)') { return }
        if (-not $ips.Contains($x) -and $ips.Count -lt 20) { $ips.Add($x) }
    }
    $addPort = {
        param([string]$v)
        $x = "$v".Trim()
        if ($x -notmatch '^\d{1,5}$') { return }
        if ([int]$x -lt 1 -or [int]$x -gt 65535) { return }
        if (-not $ports.Contains($x) -and $ports.Count -lt 10) { $ports.Add($x) }
    }

    # hash seed -> resolve to the binary's path/name so one hash pulls the whole story
    foreach ($hn in @('process_hashes.csv', 'entities_binaries.csv', 'amcache.csv')) {
        if ($hashes.Count -eq 0 -or ($names.Count -gt 0 -and $paths.Count -gt 0)) { break }
        $f = Join-Path $script:CsvDir $hn
        if (-not (Test-Path -LiteralPath $f)) { $f = Join-Path $script:CsvDir (Get-CaseCsvPath $hn) }
        if (-not (Test-Path $f)) { continue }
        foreach ($r in @(Import-Csv -LiteralPath $f -ErrorAction SilentlyContinue)) {
            $rowTxt = ("$($r.Path) $($r.Image) $($r.FullPath) $($r.Application) $($r.Name) $($r.SHA256) $($r.Hash) $($r.Hashes)").ToLower()
            $hitH = $false
            foreach ($h in $hashes) { if ($rowTxt.Contains($h)) { $hitH = $true; break } }
            if (-not $hitH) { continue }
            foreach ($pv in (@("$($r.Path)", "$($r.Image)", "$($r.FullPath)", "$($r.Application)") | Where-Object { "$_" -match '[\\/]|\S+\.\w+$' })) { & $addPath "$pv" }
            & $addName "$($r.Name)"
        }
    }
    # PID seed -> resolve to the image path/name (live snapshot first, then history)
    foreach ($src in @('processes.csv', 'sysmon_proc_create.csv', 'security_proc_events.csv')) {
        if ($pids.Count -eq 0 -or ($paths.Count -gt 0)) { break }
        $f = Join-Path $script:CsvDir $src
        if (-not (Test-Path -LiteralPath $f)) { $f = Join-Path $script:CsvDir (Get-CaseCsvPath $src) }
        if (-not (Test-Path $f)) { continue }
        foreach ($r in @(Import-Csv -LiteralPath $f -ErrorAction SilentlyContinue)) {
            $vp = @("$($r.PID)", "$($r.ProcessId)", "$($r.NewProcessId)") | Where-Object { $_ -and ($pids.Contains($_.ToLower())) }
            if (-not $vp) { continue }
            & $addPath "$($r.Path)"; & $addPath "$($r.Image)"; & $addPath "$($r.NewProcess)"
            & $addName "$($r.Name)"; & $addName "$($r.Image)"; & $addName "$($r.NewProcess)"
            if ($src -eq 'sysmon_proc_create' -and "$($r.ProcessGuid)") { $guids.Add("$($r.ProcessGuid)".ToLower()) }
        }
    }

    # OS-infra seed warning: a name like svchost.exe matches every service host that ever
    # ran - valid, but the dossier drowns. Say so up front instead of looking broken.
    if ($names.Count -gt 0 -and $paths.Count -eq 0 -and $hashes.Count -eq 0 -and $pids.Count -eq 0 -and $ips.Count -eq 0 -and $ports.Count -eq 0) {
        foreach ($nm0 in $names) {
            if ("$nm0" -match $guard) {
                Write-Host "  note: '$nm0' is an OS infrastructure name - it matches every instance of that host. The scan continues, but for one specific instance seed with its PID, full path or SHA256 instead." -ForegroundColor Yellow
            }
        }
    }

    # ---- iterative scan ---------------------------------------------------
    $files = @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { @('sigma_rules', 'evtx_ecmd', 'recmd_out') -notcontains $_.Directory.Name -and $_.BaseName -notmatch '^(focus_|process_pivot|supertimeline|parse_needed|leads)' } | Sort-Object Name)
    $cache = @{}
    $hits = New-Object System.Collections.Generic.List[object]
    $hitKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    # v2.73: dropped (out-of-window/undated) rows are re-visited every scan round - dedupe
    # the suppressed count by the same key the hits use
    $dropKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $instances = New-Object System.Collections.Generic.List[object]
    $instKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $sourcesHit = @{}

    $matchRow = {
        # returns the matched-on descriptor or $null
        param($r)
        foreach ($p in $r.PSObject.Properties) {
            $v = "$($p.Value)"
            if (-not $v -or $v -eq '@{') { continue }
            $vl = $v.ToLower()
            foreach ($h in $hashes) { if ($vl.Contains($h)) { return "hash $h" } }
            if ("$($p.Name)" -match $pidCols) {
                foreach ($pd in $pids) { if ($vl -eq $pd) { return "pid $pd" } }
            }
            if ("$($p.Name)" -match $portCols) {
                foreach ($pr in $ports) { if ($vl -eq $pr) { return "port $pr" } }
            }
            foreach ($pn in $names) { if ($vl.Contains($pn)) { return "name $pn" } }
            foreach ($pt in $paths) { if ($vl.Contains($pt)) { return "path $pt" } }
            foreach ($ip in $ips) { if ($vl -eq $ip) { return "ip $ip" } }
        }
        return $null
    }

    # v2.53: pre-lowercased row blobs per file - built once at load, the round loop only
    # regex-matches them (building blobs + calling matchRow per row every round is what made
    # the engine look hung on real-size cases)
    $blobCache = @{}
    $scanSkipped = New-Object System.Collections.Generic.List[string]
    for ($round = 1; $round -le 4; $round++) {
        $termCount = $names.Count + $paths.Count + $hashes.Count + $ports.Count + $pids.Count
        if ($termCount -eq 0) { break }
        # one alternation regex over all current terms; PIDs/ports ride \b-boundaries -
        # over-matched rows are re-checked exactly inside matchRow (column-exact)
        $qp = New-Object System.Collections.Generic.List[string]
        foreach ($t in $names) { $qp.Add([regex]::Escape($t)) }
        foreach ($t in $paths) { $qp.Add([regex]::Escape($t)) }
        foreach ($t in $hashes) { $qp.Add([regex]::Escape($t)) }
        foreach ($t in $ips) { $qp.Add([regex]::Escape($t)) }
        foreach ($lst in @($pids, $ports)) {
            if ($lst.Count -gt 0) { $qp.Add('\b(' + ((@($lst) | ForEach-Object { [regex]::Escape("$_") }) -join '|') + ')\b') }
        }
        if ($qp.Count -eq 0) { break }
        $quickRe = New-Object System.Text.RegularExpressions.Regex(($qp.ToArray() -join '|'), ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled))
        $newHits = 0
        foreach ($f in $files) {
            if (-not $cache.ContainsKey($f.BaseName)) {
                $rr = @()
                if ($f.Length -gt 40MB) {
                    $scanSkipped.Add("$($f.BaseName) ($([math]::Round($f.Length / 1MB)) MB - too large for the focus scan; query it directly or use the supertimeline)")
                } else {
                    if ($f.Length -gt 1MB) { Write-Host "  loading $($f.Name) ($([math]::Round($f.Length / 1KB)) KB)..." -ForegroundColor DarkGray }
                    try { $rr = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { }
                }
                $cache[$f.BaseName] = $rr
                $bb = New-Object 'System.Collections.Generic.List[string]'
                foreach ($r in $rr) {
                    $b = ''
                    foreach ($p in $r.PSObject.Properties) { $v = "$($p.Value)"; if ($v) { $b += $v; $b += ' ' } }
                    $bb.Add($b.ToLower())
                }
                $blobCache[$f.BaseName] = $bb.ToArray()
            }
            if ($hits.Count -ge 5000) { break }
            $rr = $cache[$f.BaseName]
            if ($rr.Count -eq 0) { continue }
            $src = $f.BaseName
            $bl = $blobCache[$f.BaseName]
            for ($ri = 0; $ri -lt $rr.Count; $ri++) {
                if (-not $quickRe.IsMatch($bl[$ri])) { continue }
                $r = $rr[$ri]
                $on = & $matchRow $r
                if (-not $on) { continue }
                # expansion: pull new entity terms out of the matched row
                foreach ($p in $r.PSObject.Properties) {
                    $nm = "$($p.Name)"; $v = "$($p.Value)"
                    if (-not $v) { continue }
                    if ($nm -match $guidRe) { $gl = $v.ToLower(); if (-not $guids.Contains($gl)) { $guids.Add($gl) } }
                    if ($nm -match $hashCols) { & $addHash $v }
                    if ($nm -match $pathCols) { & $addPath $v }
                    if ($nm -match $nameCols) { & $addName $v }
                    if ($nm -match $ipCols) { & $addIp $v }
                    if ($nm -match $portCols) { & $addPort $v }
                }
                # instance record from the identity sources
                if ($src -eq 'processes' -or $src -eq 'sysmon_proc_create' -or $src -eq 'security_proc_events') {
                    $iPid = ''; $iGuid = ''; $iParent = ''; $iUser = ''; $iStart = ''; $iImg = ''
                    if ($src -eq 'processes') {
                        $iPid = "$($r.PID)"; $iParent = "PPID $($r.PPID)"; $iStart = "$($r.Created)"; $iImg = "$($r.Path)"
                    } elseif ($src -eq 'sysmon_proc_create') {
                        $iPid = "$($r.ProcessId)"; $iGuid = "$($r.ProcessGuid)"; $iStart = "$($r.Time)"; $iImg = "$($r.Image)"; $iParent = "$($r.ParentImage)"; $iUser = "$($r.User)"
                    } else {
                        $iPid = "$($r.NewProcessId)"; $iStart = "$($r.Time)"; $iImg = "$($r.NewProcess)"; $iParent = "$($r.ParentProcess)"; $iUser = "$($r.Account)"
                    }
                    # v2.47: normalize hex PIDs for the dedup key - 4688 records NewProcessId as
                    # hex (0x15f4) while Sysmon/the live snapshot use decimal (5620); canonical
                    # form is decimal so both sources collapse onto one instance
                    $iPidN = $iPid
                    if ("$iPidN" -match '^0x([0-9a-fA-F]+)$') { try { $iPidN = "$([convert]::ToInt64($Matches[1], 16))" } catch { } }
                    $ik = "$iPidN|$iImg".ToLower()
                    if (($iPid -or $iGuid) -and $instKeys.Add($ik) -and $instances.Count -lt 400) {
                        $instances.Add([pscustomobject]@{ Pid = $iPid; Guid = $iGuid; Started = $iStart; Image = $iImg; Parent = $iParent; User = $iUser; Source = $src })
                    } elseif ($instances.Count -gt 0 -and $instances.Count -lt 400) {
                        # same instance seen in another source -> enrich the existing row
                        # (sysmon rows carry guid/user/parent, the live snapshot carries PPID)
                        foreach ($ex in $instances) {
                            $exPidN = "$($ex.Pid)"
                            if ("$exPidN" -match '^0x([0-9a-fA-F]+)$') { try { $exPidN = "$([convert]::ToInt64($Matches[1], 16))" } catch { } }
                            if ("$exPidN|$($ex.Image)".ToLower() -eq $ik) {
                                if ($iGuid -and -not "$($ex.Guid)") { $ex | Add-Member -NotePropertyName Guid -NotePropertyValue $iGuid -Force }
                                if ($iUser -and -not "$($ex.User)") { $ex | Add-Member -NotePropertyName User -NotePropertyValue $iUser -Force }
                                if ($iParent -and -not "$($ex.Parent)") { $ex | Add-Member -NotePropertyName Parent -NotePropertyValue $iParent -Force }
                                if ($iStart -and -not "$($ex.Started)") { $ex | Add-Member -NotePropertyName Started -NotePropertyValue $iStart -Force }
                                break
                            }
                        }
                    }
                }
                # hit record (deduped across rounds)
                $detail = ''
                foreach ($p in $r.PSObject.Properties) {
                    $v = "$($p.Value)"
                    if ($v -and $v -ne '@{') { $detail += "$($p.Name)=$v | " }
                }
                if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + '...' }
                $t = ''
                foreach ($tc in @('Time', 'TimeCreated', 'Timestamp', 'Started', 'LastWrite')) {
                    if ($r.PSObject.Properties[$tc] -and "$($r.$tc)") { $t = "$($r.$tc)"; break }
                }
                # v2.73: the window filters the hit record only - expansion terms and the
                # instance record above were already taken from this row (term graph stays whole)
                if ($afterDT -or $beforeDT) {
                    $rt = $null
                    if ($t) { try { $rt = [datetime]$t } catch { } }
                    if (-not $rt -or ($afterDT -and $rt -lt $afterDT) -or ($beforeDT -and $rt -gt $beforeDT)) {
                        if ($dropKeys.Add("$src|$detail".ToLower())) { $winDropped++ }
                        continue
                    }
                }
                $hk = "$src|$detail"
                if ($hitKeys.Add($hk.ToLower())) {
                    $hits.Add([pscustomobject]@{ Indicator = $Indicator; Source = $src; Time = $t; MatchedOn = $on; Detail = $detail })
                    $sourcesHit[$src] = [int]$sourcesHit[$src] + 1
                    $newHits++
                    if ($hits.Count -ge 5000) { break }
                }
            }
            if ($hits.Count -ge 5000) { break }
        }
        Write-Host ("  round {0}: {1} name / {2} path / {3} hash / {4} ip / {5} port terms -> {6} new hit(s), {7} instance(s)" -f $round, $names.Count, $paths.Count, $hashes.Count, $ips.Count, $ports.Count, $newHits, $instances.Count) -ForegroundColor DarkGray
        if ($newHits -eq 0 -and ($names.Count + $paths.Count + $hashes.Count + $ports.Count + $pids.Count) -eq $termCount) { break }
    }
    foreach ($sk in $scanSkipped) { Write-Host "  skipped: $sk" -ForegroundColor DarkGray }
    if ($hits.Count -ge 5000) { Write-Host "  hit cap reached (5000 rows) - dossier truncated; refine the seed (PID, full path or hash) for a tighter one" -ForegroundColor Yellow }

    # ---- per-instance detail (ProcessGuid joins into the structured Sysmon CSVs; PID fallback) ----
    # Everything ONE instance did: children, network, DNS, loaded DLLs, file-time changes, registry.
    $perInst = New-Object System.Collections.Generic.List[object]
    $guidFilter = {
        param($name, $gl, $pl)
        if (-not $cache.ContainsKey($name)) { return @() }
        $rows = $cache[$name]
        if ($gl) { return @($rows | Where-Object { "$($_.ProcessGuid)".ToLower() -eq $gl }) }
        if ($pl) { return @($rows | Where-Object { "$($_.ProcessId)" -eq $pl -or "$($_.PID)" -eq $pl }) }
        return @()
    }
    # v2.48: column-specific guid join - EID 8 carries SourceProcessGuid/TargetProcessGuid
    # (who injected / who got injected) instead of a plain ProcessGuid, and no PID column,
    # so the standard filter cannot join it
    $guidFilterCol = {
        param($name, $col, $gl)
        if (-not $gl -or -not $cache.ContainsKey($name)) { return @() }
        return @($cache[$name] | Where-Object { "$($_.$col)".ToLower() -eq $gl })
    }
    foreach ($i in $instances) {
        $gl = "$($i.Guid)".ToLower()
        $pl = "$($i.Pid)"
        $kids = @()
        if ($cache.ContainsKey('sysmon_proc_create')) {
            if ($gl) { $kids = @($cache['sysmon_proc_create'] | Where-Object { "$($_.ParentProcessGuid)".ToLower() -eq $gl }) }
            elseif ($pl) { $kids = @($cache['sysmon_proc_create'] | Where-Object { "$($_.ParentImage)".ToLower() -eq "$($i.Image)".ToLower() }) }
        }
        # v2.47: persistence + C2 beacon joins per instance (name-or-path match - these artifacts
        # carry no ProcessGuid, and on no-Sysmon hosts they are the ONLY instance-level evidence)
        $imgL = "$($i.Image)".ToLower()
        $leafL = ''
        try { $leafL = (Split-Path $imgL -Leaf) } catch { }
        $persistJoin = {
            @('services', 'system_new_services', 'scheduled_tasks', 'security_task_install', 'autoruns_runkeys', 'autoruns_startup_folders', 'sysmon_wmi') | ForEach-Object {
                $srcName = $_
                if (-not $cache.ContainsKey($srcName)) { return }
                foreach ($r in $cache[$srcName]) {
                    $blob = ''
                    foreach ($p2 in $r.PSObject.Properties) { $blob += "$($p2.Value) ".ToLower() }
                    # v2.50: WMI subscription rows join by guid (the registering process), not by image blob
                    $wmiRow = ($srcName -eq 'sysmon_wmi')
                    if ($wmiRow) {
                        $rgl = "$($r.ProcessGuid)".ToLower()
                        if (-not $gl -or -not $rgl -or $rgl -ne $gl) {
                            if (-not $leafL -or "$($r.Image)".ToLower() -notmatch [regex]::Escape($leafL)) { continue }
                        }
                    } elseif (-not $blob.Contains($imgL) -and (-not $leafL -or -not $blob.Contains($leafL))) { continue }
                    $kind = switch ($srcName) {
                        'services' { 'service (live)' }
                        'system_new_services' { 'service install (7045)' }
                        'scheduled_tasks' { 'scheduled task' }
                        'security_task_install' { 'task install (4698)' }
                        'autoruns_runkeys' { 'autorun (run key)' }
                        'autoruns_startup_folders' { 'autorun (startup folder)' }
                        'sysmon_wmi' { 'WMI event subscription' }
                        default { $srcName }
                    }
                    $tm = ''
                    foreach ($pn2 in @('Time', 'KeyTimeStamp')) { $p3 = $r.PSObject.Properties[$pn2]; if ($p3 -and "$($p3.Value)") { $tm = "$($p3.Value)"; break } }
                    [pscustomobject]@{ Time = $tm; Kind = $kind; Source = $srcName; Detail = ($r.PSObject.Properties | Where-Object { "$($_.Value)" -and "$($_.Name)" -ne 'Time' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | ' }
                }
            }
        }
        $beaconJoin = {
            @('beacon_candidates', 'dns_beacon_candidates') | ForEach-Object {
                $srcName = $_
                if (-not $cache.ContainsKey($srcName)) { return }
                foreach ($r in $cache[$srcName]) {
                    $bp = "$($r.Process)".ToLower()
                    if ($bp -ne $imgL -and (-not $leafL -or $bp -notmatch [regex]::Escape($leafL))) { continue }
                    if ($srcName -eq 'beacon_candidates') {
                        [pscustomobject]@{ Kind = 'C2 beacon'; Target = "$($r.RemoteIp):$($r.Port)"; Detail = "$($r.Events) connections over $($r.SpanMin) min, median interval ~$($r.MedianIntervalSec)s, regularity $($r.Regularity), severity $($r.Severity)" }
                    } else {
                        [pscustomobject]@{ Kind = 'DNS beacon'; Target = "$($r.Domain)"; Detail = "$($r.Events) queries over $($r.SpanMin) min, median interval ~$($r.MedianIntervalSec)s, regularity $($r.Regularity), severity $($r.Severity)" }
                    }
                }
            }
        }
        $execJoin = {
            # v2.50 no-Sysmon spine: prefetch/amcache/BAM/shimcache matched by image-or-leaf -
            # "when else did this binary run" evidence that needs no ProcessGuid, so the dossier
            # still builds a per-instance execution story on hosts without Sysmon
            @('prefetch_index', 'prefetch_parsed', 'amcache', 'bam_lastexec', 'shimcache') | ForEach-Object {
                $srcName = $_
                if (-not $cache.ContainsKey($srcName)) { return }
                foreach ($r in $cache[$srcName]) {
                    $blob = ''
                    foreach ($p2 in $r.PSObject.Properties) { $blob += "$($p2.Value) ".ToLower() }
                    if (-not $blob.Contains($imgL) -and (-not $leafL -or -not $blob.Contains($leafL))) { continue }
                    $kind = switch ($srcName) {
                        'prefetch_index' { 'prefetch (file)' }
                        'prefetch_parsed' { 'prefetch (parsed)' }
                        'amcache' { 'amcache (execution)' }
                        'bam_lastexec' { 'BAM/DAM (last exec)' }
                        'shimcache' { 'shimcache (executed from)' }
                        default { $srcName }
                    }
                    $tm = ''
                    foreach ($pn2 in @('LastLaunch', 'LastWrite', 'Timestamp', 'LastModified', 'LastWriteTime', 'CreationTime', 'KeyTimeStamp', 'Time')) { $p3 = $r.PSObject.Properties[$pn2]; if ($p3 -and "$($p3.Value)") { $tm = "$($p3.Value)"; break } }
                    $detail = ($r.PSObject.Properties | Where-Object { "$($_.Value)" -and "$($_.Name)" -ne 'Time' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '
                    if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) + '...' }
                    [pscustomobject]@{ Time = $tm; Kind = $kind; Source = $srcName; Detail = $detail }
                }
            }
        }
        # @() wrappers: & scriptblock unrolls single-element results -> .Count must stay an int
        $det = [pscustomobject]@{
            Instance = $i
            Children = $kids
            Net = @(& $guidFilter 'sysmon_network' $gl $pl)
            Dns = @(& $guidFilter 'sysmon_dns' $gl $pl)
            Dll = @(& $guidFilter 'sysmon_image_load' $gl $pl)
            Reg = @(& $guidFilter 'sysmon_registry' $gl $pl)
            File = @(& $guidFilter 'sysmon_file_time' $gl $pl)
            FileCreate = @(& $guidFilter 'sysmon_file_create' $gl $pl)
            FileDelete = @(& $guidFilter 'sysmon_file_delete' $gl $pl)
            Persist = @(& $persistJoin)
            Beacon = @(& $beaconJoin)
            CrtIn = @(& $guidFilterCol 'sysmon_remote_thread' 'TargetProcessGuid' $gl)
            CrtOut = @(& $guidFilterCol 'sysmon_remote_thread' 'SourceProcessGuid' $gl)
            Pipes = @(& $guidFilter 'sysmon_pipes' $gl $pl)
            Tamper = @(& $guidFilter 'sysmon_proc_tamper' $gl $pl)
            RawDisk = @(& $guidFilter 'sysmon_raw_access' $gl $pl)
            Exec = @(& $execJoin)
        }
        if ($det.Children.Count -gt 0 -or $det.Net.Count -gt 0 -or $det.Dns.Count -gt 0 -or $det.Dll.Count -gt 0 -or $det.Reg.Count -gt 0 -or $det.File.Count -gt 0 -or $det.FileCreate.Count -gt 0 -or $det.FileDelete.Count -gt 0 -or $det.Persist.Count -gt 0 -or $det.Beacon.Count -gt 0 -or $det.CrtIn.Count -gt 0 -or $det.CrtOut.Count -gt 0 -or $det.Pipes.Count -gt 0 -or $det.Tamper.Count -gt 0 -or $det.RawDisk.Count -gt 0 -or $det.Exec.Count -gt 0) {
            $perInst.Add($det)
        }
    }

    # ---- v2.47: ancestry walk-up, respawn narration, target/relative split ----
    $instKey = { param($i2) ("$($i2.Pid)|$($i2.Guid)|$($i2.Image)").ToLower() }
    foreach ($i in $instances) {
        # walk parent rows up the tree: sysmon EID 1 by ParentImage, 4688 by ParentProcess,
        # live snapshot by PPID - stop at 6 generations, a repeated node, or a missing parent row.
        # A parent row must PREDATE its child (same-name siblings/self-rows otherwise win).
        $lin = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $parentName = "$($i.Parent)".Trim()
        $curTime = $null; try { $curTime = [datetime]"$($i.Started)" } catch { }
        $lastGuid = "$($i.Guid)".ToLower()
        $gen = 0
        if ($parentName -match '^PPID ') {
            # live-snapshot parents are just a PPID number - prefer the instance's own EID 1 row,
            # which carries the parent IMAGE (the PPID holder may have exited before collection)
            if ($cache.ContainsKey('sysmon_proc_create')) {
                $own = @()
                if ($lastGuid) { $own = @($cache['sysmon_proc_create'] | Where-Object { "$($_.ProcessGuid)".ToLower() -eq $lastGuid }) }
                if ($own.Count -eq 0) {
                    $il3 = "$($i.Image)".ToLower()
                    $own = @($cache['sysmon_proc_create'] | Where-Object { "$($_.Image)".ToLower() -eq $il3 })
                    if ($own.Count -gt 1 -and $curTime) {
                        $near = @($own | Where-Object { $rt2 = $null; try { $rt2 = [datetime]"$($_.Time)" } catch { }; $rt2 -and [Math]::Abs(($rt2 - $curTime).TotalMinutes) -lt 5 })
                        if ($near.Count -gt 0) { $own = $near }
                    }
                }
                if ($own.Count -gt 0 -and "$($own[0].ParentImage)") { $parentName = "$($own[0].ParentImage)" }
            }
        }
        while ($parentName -and $gen -lt 6) {
            if ($parentName -match '^PPID (\d+)') {
                $pp = $null
                if ($cache.ContainsKey('processes')) { $pp = @($cache['processes'] | Where-Object { "$($_.PID)" -eq $Matches[1] }) }
                if ($pp -and $pp.Count -gt 0 -and "$($pp[0].Path)") { $parentName = "$($pp[0].Path)" } else { break }
            }
            $pl2 = $parentName.ToLower()
            if (-not $seen.Add($pl2)) { break }
            $pleaf = $pl2
            try { $lf = (Split-Path $pl2 -Leaf); if ($lf) { $pleaf = $lf } } catch { }
            $prow = $null
            if ($cache.ContainsKey('sysmon_proc_create')) {
                $best = $null; $bestT = [datetime]::MinValue
                foreach ($c2 in @($cache['sysmon_proc_create'] | Where-Object { "$($_.Image)".ToLower() -eq $pl2 -or "$($_.Image)".ToLower().EndsWith("\$pleaf") })) {
                    if ("$($c2.ProcessGuid)".ToLower() -and "$($c2.ProcessGuid)".ToLower() -eq $lastGuid) { continue }
                    $rt = $null; try { $rt = [datetime]"$($c2.Time)" } catch { }
                    if ($curTime -and $rt -and $rt -gt $curTime.AddSeconds(1)) { continue }
                    if ($null -eq $best -or $rt -ge $bestT) { $best = $c2; $bestT = $rt }
                }
                if ($best) { $prow = $best }
            }
            if (-not $prow -and $cache.ContainsKey('security_proc_events')) {
                $best = $null; $bestT = [datetime]::MinValue
                foreach ($c2 in @($cache['security_proc_events'] | Where-Object { "$($_.NewProcess)".ToLower() -eq $pl2 -or "$($_.NewProcess)".ToLower().EndsWith("\$pleaf") })) {
                    $rt = $null; try { $rt = [datetime]"$($c2.Time)" } catch { }
                    if ($curTime -and $rt -and $rt -gt $curTime.AddSeconds(1)) { continue }
                    if ($null -eq $best -or $rt -ge $bestT) { $best = $c2; $bestT = $rt }
                }
                if ($best) { $prow = $best }
            }
            $lbl = $pleaf
            if ($prow) {
                foreach ($pn2 in @('Time', 'TimeCreated')) {
                    $p3 = $prow.PSObject.Properties[$pn2]
                    if ($p3 -and "$($p3.Value)") { $lbl = "$pleaf ($($p3.Value))"; break }
                }
            }
            $lin.Add($lbl)
            $next = $null
            if ($prow) {
                if ($prow.PSObject.Properties['ParentImage'] -and "$($prow.ParentImage)") { $next = "$($prow.ParentImage)" }
                elseif ($prow.PSObject.Properties['ParentProcess'] -and "$($prow.ParentProcess)") { $next = "$($prow.ParentProcess)" }
                if ($prow.PSObject.Properties['ProcessGuid']) { $lastGuid = "$($prow.ProcessGuid)".ToLower() }
                foreach ($pn2 in @('Time', 'TimeCreated')) {
                    $p3 = $prow.PSObject.Properties[$pn2]
                    if ($p3 -and "$($p3.Value)") { try { $curTime = [datetime]"$($p3.Value)" } catch { }; break }
                }
            }
            if (-not $next -or "$next".ToLower() -eq $pl2) { break }
            $parentName = $next
            $gen++
        }
        $i | Add-Member -NotePropertyName Lineage -NotePropertyValue $lin.ToArray() -Force
    }
    $pathSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($pt in $paths) { $null = $pathSet.Add("$pt".ToLower()) }
    $indLeaf = ''
    try { $lf2 = (Split-Path $ind -Leaf); if ($lf2) { $indLeaf = $lf2.ToLower() } } catch { }
    $targetKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($i in $instances) {
        $il = "$($i.Image)".ToLower()
        if ($pathSet.Contains($il) -or ($indLeaf -and $il.EndsWith("\$indLeaf"))) { $null = $targetKeys.Add((& $instKey $i)) }
    }
    foreach ($grp in (@($instances | Where-Object { $targetKeys.Contains((& $instKey $_)) }) | Group-Object { "$($_.Image)".ToLower() })) {
        $ordered = @($grp.Group | Where-Object { "$($_.Started)" } | Sort-Object { $k2 = [datetime]::MaxValue; try { $k2 = [datetime]"$($_.Started)" } catch { }; $k2 })
        for ($x = 1; $x -lt $ordered.Count; $x++) {
            $t1 = $null; $t2 = $null
            try { $t1 = [datetime]"$($ordered[$x - 1].Started)"; $t2 = [datetime]"$($ordered[$x].Started)" } catch { }
            if (-not $t1 -or -not $t2 -or (($t2 - $t1).TotalMinutes -lt 5)) { continue }
            $gap = "$([int](($t2 - $t1).TotalHours))h$([int](($t2 - $t1).TotalMinutes % 60))m"
            $note = "respawned after $gap"
            $ev = @()
            $il2 = "$($ordered[$x].Image)".ToLower()
            foreach ($d2 in $perInst) {
                foreach ($fc in @($d2.FileCreate)) {
                    $ft = $null; try { $ft = [datetime]"$($fc.Time)" } catch { }
                    if ("$($fc.TargetFilename)".ToLower() -eq $il2 -and $ft -and $t1 -and $ft -ge $t1 -and $ft -le $t2) {
                        $ev += "re-dropped by $(try { Split-Path "$($d2.Instance.Image)" -Leaf } catch { "$($d2.Instance.Image)" })"
                    }
                }
            }
            $own = @($perInst | Where-Object { (& $instKey $_.Instance) -eq (& $instKey $ordered[$x]) })
            if ($own.Count -gt 0 -and @($own[0].Persist).Count -gt 0) { $ev += "persistence: $($own[0].Persist[0].Kind)" }
            if ($ev.Count -gt 0) { $note += " ($(@($ev | Select-Object -Unique) -join ', '))" }
            $ordered[$x] | Add-Member -NotePropertyName Respawn -NotePropertyValue $note -Force
        }
    }

    # ---- activity chain from the master timeline --------------------------
    $chain = New-Object System.Collections.Generic.List[object]
    $tlPath = Join-Path $script:CsvDir 'supertimeline.csv'
    if (-not (Test-Path -LiteralPath $tlPath)) { $tlPath = Join-Path $script:CsvDir (Get-CaseCsvPath 'supertimeline') }
    if (Test-Path $tlPath) {
        foreach ($r in @(Import-Csv -LiteralPath $tlPath -ErrorAction SilentlyContinue)) {
            $blob = ("$($r.Timestamp) $($r.Source) $($r.Type) $($r.Actor) $($r.Entity) $($r.Detail)").ToLower()
            $hit = $false
            foreach ($pn in $names) { if ($pn.Length -ge 4 -and $blob.Contains($pn)) { $hit = $true; break } }
            if (-not $hit) { foreach ($pt in $paths) { if ($blob.Contains($pt)) { $hit = $true; break } } }
            if (-not $hit) { foreach ($h in $hashes) { if ($blob.Contains($h)) { $hit = $true; break } } }
            if (-not $hit) { foreach ($ip in $ips) { if ($blob.Contains($ip)) { $hit = $true; break } } }
            if ($hit) {
                # v2.73: the chain is evidence too - same window rule as the hit records
                if ($afterDT -or $beforeDT) {
                    $rt2 = $null
                    if ("$($r.Timestamp)") { try { $rt2 = [datetime]"$($r.Timestamp)" } catch { } }
                    if (-not $rt2 -or ($afterDT -and $rt2 -lt $afterDT) -or ($beforeDT -and $rt2 -gt $beforeDT)) { $winDropped++; continue }
                }
                $chain.Add($r)
            }
        }
    }
    $chain = [System.Collections.Generic.List[object]]@($chain | Sort-Object { "$($_.Timestamp)" } | Select-Object -First 500)

    # ---- entity groups (path+hash keyed; masquerade split) ----------------
    $groups = New-Object System.Collections.Generic.List[object]
    $hashByPath = @{}
    $phPath = Join-Path $script:CsvDir 'process_hashes.csv'
    if (-not (Test-Path -LiteralPath $phPath)) { $phPath = Join-Path $script:CsvDir (Get-CaseCsvPath 'process_hashes') }
    if (Test-Path $phPath) {
        foreach ($r in @(Import-Csv -LiteralPath $phPath -ErrorAction SilentlyContinue)) {
            $pn = ("$($r.Path)" -replace '(?i)^\\device\\harddiskvolume\d+', 'C:').ToLower()
            if ($pn -and -not $hashByPath[$pn]) { $hashByPath[$pn] = "SHA256:$($r.SHA256)" }
        }
    }
    # v2.82: hash sources beyond process_hashes.csv - yara_scanned.csv (File -> SHA256) and
    # amcache.csv (FullPath -> SHA1). Without these the groups' hash cells came up empty and
    # the report fell back to printing hashes[0] on EVERY group row (the same-hash bug); the
    # algo label also fixes a SHA1 rendering under a SHA256 header (amcache stores SHA1).
    $yaPath = Join-Path $script:CsvDir 'yara_scanned.csv'
    if (-not (Test-Path -LiteralPath $yaPath)) { $yaPath = Join-Path $script:CsvDir (Get-CaseCsvPath 'yara_scanned') }
    if (Test-Path $yaPath) {
        foreach ($r in @(Import-Csv -LiteralPath $yaPath -ErrorAction SilentlyContinue)) {
            $pn = ("$($r.File)" -replace '(?i)^\\device\\harddiskvolume\d+', 'C:').ToLower()
            if ($pn -and "$($r.SHA256)" -and -not $hashByPath[$pn]) { $hashByPath[$pn] = "SHA256:$($r.SHA256)" }
        }
    }
    $amPath = Join-Path $script:CsvDir 'amcache.csv'
    if (-not (Test-Path -LiteralPath $amPath)) { $amPath = Join-Path $script:CsvDir (Get-CaseCsvPath 'amcache') }
    if (Test-Path $amPath) {
        foreach ($r in @(Import-Csv -LiteralPath $amPath -ErrorAction SilentlyContinue)) {
            $pn = ("$($r.FullPath)" -replace '(?i)^\\device\\harddiskvolume\d+', 'C:').ToLower()
            if ($pn -and "$($r.SHA1)" -and -not $hashByPath[$pn]) { $hashByPath[$pn] = "SHA1:$($r.SHA1)" }
        }
    }
    foreach ($pt in $paths) {
        $gHits = @($hits | Where-Object { "$($_.Detail)".ToLower().Contains($pt) })
        $gName = (Split-Path $pt -Leaf)
        if (-not $gName) { $gName = $pt }
        $groups.Add([pscustomobject]@{
            Key = $pt; Name = $gName; Path = $pt
            Hash = $hashByPath[$pt]
            HitCount = $gHits.Count
            FirstSeen = ($gHits | Where-Object { "$($_.Time)" } | Sort-Object { "$($_.Time)" } | Select-Object -First 1).Time
            LastSeen = ($gHits | Where-Object { "$($_.Time)" } | Sort-Object { "$($_.Time)" } | Select-Object -Last 1).Time
        })
    }
    $masq = @()
    $byLeaf = @($groups | Group-Object Name | Where-Object { $_.Count -gt 1 })
    foreach ($m in $byLeaf) { $masq += $m.Name }

    # ---- v2.51 correlation notes: dormancy wake-up + prefetch-vs-telemetry mismatch ----
    $corrNotes = New-Object System.Collections.Generic.List[string]
    $entBlob = { param($r) $b = ''; foreach ($p9 in $r.PSObject.Properties) { $b += "$($p9.Value) ".ToLower() }; $b }
    $entMatch = { param($r) $b = & $entBlob $r; foreach ($pt in $paths) { if ($b.Contains($pt)) { return $true } }; foreach ($nm in $names) { if ($nm.Length -ge 4 -and $b.Contains($nm)) { return $true } }; return $false }
    $execFirst = $null
    foreach ($src9 in @('amcache', 'bam_lastexec', 'shimcache')) {
        if (-not $cache.ContainsKey($src9)) { continue }
        foreach ($r9 in $cache[$src9]) {
            if (-not (& $entMatch $r9)) { continue }
            foreach ($cn in @('Timestamp', 'LastWrite', 'LastModified', 'LastWriteTime')) {
                $p9 = $r9.PSObject.Properties[$cn]
                if (-not ($p9 -and "$($p9.Value)")) { continue }
                $t9 = $null; try { $t9 = [datetime]"$($p9.Value)" } catch { }
                if ($t9 -and ($null -eq $execFirst -or $t9 -lt $execFirst)) { $execFirst = $t9 }
                break
            }
        }
    }
    $logFirst = $null
    foreach ($h9 in $hits) {
        if (@('sysmon_proc_create', 'security_proc_events', 'processes') -notcontains "$($h9.Source)") { continue }
        $t9 = $null; try { $t9 = [datetime]"$($h9.Time)" } catch { }
        if ($t9 -and ($null -eq $logFirst -or $t9 -lt $logFirst)) { $logFirst = $t9 }
    }
    if ($execFirst -and $logFirst -and (($logFirst - $execFirst).TotalDays -ge 7)) {
        $null = $corrNotes.Add("DORMANCY: earliest execution artifact $(if ($execFirst) { $execFirst.ToString('yyyy-MM-dd HH:mm') }) is $([int]($logFirst - $execFirst).TotalDays) days before the first in-window process telemetry ($($logFirst.ToString('yyyy-MM-dd HH:mm'))) - the binary ran long before this window (dormant persistence or an old install waking up)")
    }
    $pfRuns = 0
    if ($cache.ContainsKey('prefetch_parsed')) {
        foreach ($r9 in $cache['prefetch_parsed']) {
            if (-not (& $entMatch $r9)) { continue }
            $p9 = $r9.PSObject.Properties['RunCount']
            if ($p9 -and "$($p9.Value)" -match '^\d+$' -and [int]$p9.Value -gt $pfRuns) { $pfRuns = [int]$p9.Value }
        }
    }
    $procCreates = @($hits | Where-Object { @('sysmon_proc_create', 'security_proc_events') -contains "$($_.Source)" }).Count
    if ($pfRuns -ge 5 -and $procCreates -gt 0 -and $pfRuns -gt ($procCreates * 3)) {
        $null = $corrNotes.Add("EXECUTION MISMATCH: prefetch reports $pfRuns runs - only $procCreates process-creation events in the telemetry window (logging gap, short window, or telemetry tampering - check logging-gaps and the collection range)")
    }

    # ---- zero-hit UX (v2.53): guidance instead of silently writing an empty dossier ----
    # An empty dossier used to overwrite any existing one AND rendered a dead Focus section
    # in the main report - the "option 9 doesn't work" experience.
    if ($hits.Count -eq 0) {
        Write-Host ""
        Write-Host "No evidence found for '$Indicator' in this case." -ForegroundColor Yellow
        Write-Host "  the engine matches: name fragments, path fragments, SHA1/SHA256/MD5, PIDs, IPs, ip:port and ports" -ForegroundColor Gray
        Write-Host "  try instead: the binary's full path, its hash (csv\...\process_hashes.csv), or the remote ip:port it talked to" -ForegroundColor Gray
        foreach ($bc in @('beacon_candidates', 'dns_beacon_candidates')) {
            if (-not $cache.ContainsKey($bc)) { continue }
            foreach ($b2 in @($cache[$bc] | Select-Object -First 3)) {
                if ($bc -eq 'beacon_candidates') { Write-Host "  beacon in this case: $($b2.Process) -> $($b2.RemoteIp):$($b2.Port) (severity $($b2.Severity)) - try seeding that" -ForegroundColor DarkCyan }
                else { Write-Host "  DNS beacon in this case: $($b2.Domain) (severity $($b2.Severity)) - try seeding that domain" -ForegroundColor DarkCyan }
            }
        }
        Write-Host "  nothing was written - any existing dossier is intact" -ForegroundColor DarkGray
        return $true
    }

    # ---- write outputs ----------------------------------------------------
    # v2.56: detection-surface hint computed once here - rides focus_terms.json so the
    # main-report embed shows the same CORROBORATED/SUSPICIOUS/REVIEW banner as the dossier
    $hint = 'REVIEW'; $hintCls = 'info'; $hintTxt = 'No scanner/detection sources corroborated this entity in this case - review the evidence manually (absence of detections is not absence of malware).'
    if ($hits.Count -gt 0) {
        $detSrcs = '^(yara_hits|defender_threats|flash_ioc_hits|ioc_hits_|memory_malfind)'
        $sigSrcs = '^(beacon_candidates|dns_beacon_candidates|hunt_findings|hayabusa_timeline|flash_process_scored|loldrivers_hits)'
        $detHits = @($hits | Where-Object { "$($_.Source)" -match $detSrcs })
        $sigHits = @($hits | Where-Object { "$($_.Source)" -match $sigSrcs })
        if ($detHits.Count -gt 0) { $hint = 'CORROBORATED'; $hintCls = 'crit'; $hintTxt = "Detection sources flagged this entity ($($detHits.Count) row(s)): YARA/Defender/IOC/malfind. Treat as malicious until proven otherwise." }
        elseif ($sigHits.Count -gt 0) { $hint = 'SUSPICIOUS'; $hintCls = 'med'; $hintTxt = "Sigma/hunt/beacon sources light up around this entity ($($sigHits.Count) row(s)). Strong investigation candidate." }
    }
    $hits.ToArray() | Export-Csv -LiteralPath (Join-Path $focusDir 'focus_hits.csv') -NoTypeInformation -Encoding UTF8
    $chain.ToArray() | Export-Csv -LiteralPath (Join-Path $focusDir 'focus_chain.csv') -NoTypeInformation -Encoding UTF8
    # v2.82: flatten Lineage ONLY for export - the raw array exported to CSV rendered as the
    # literal 'System.String[]'; in-memory code still needs the array (nearest-parent reads).
    $expInst = @()
    foreach ($i in $instances) {
        if ($i.PSObject.Properties['Lineage'] -and @($i.Lineage).Count -gt 0) {
            $c9 = $i.PSObject.Copy(); $c9.Lineage = (@($i.Lineage) -join ' <- '); $expInst += $c9
        } else { $expInst += $i }
    }
    $expInst | Export-Csv -LiteralPath (Join-Path $focusDir 'focus_instances.csv') -NoTypeInformation -Encoding UTF8
    @{
        Indicator = $Indicator
        GeneratedUTC = (Get-Date).ToUniversalTime().ToString('o')
        Computer = "$($meta.Computer)"
        CaseID = "$($meta.CaseID)"
        Rounds = $round
        Names = $names.ToArray()
        Paths = $paths.ToArray()
        Hashes = $hashes.ToArray()
        Pids = $pids.ToArray()
        Guids = $guids.ToArray()
        Ips = $ips.ToArray()
        SourcesHit = $sourcesHit
        HitCount = $hits.Count
        InstanceCount = $instances.Count
        CorrNotes = $corrNotes.ToArray()
        # v2.73: the window travels with the dossier - the main-report embed shows it too
        TimeWindow = @{
            From = $(if ($afterDT) { $afterDT.ToString('yyyy-MM-dd HH:mm') } else { '' })
            To = $(if ($beforeDT) { $beforeDT.ToString('yyyy-MM-dd HH:mm') } else { '' })
        }
        RowsOutsideWindow = $winDropped
        Degraded = (-not ($guids.Count -gt 0))
        VerdictHint = $hint
        VerdictHintCls = $hintCls
        VerdictHintTxt = $hintTxt
        Masquerade = @($masq)
        # v2.82: per-group hash rides the JSON so the main-report embed can render each path's
        # OWN hash (it used to print Hashes[0] on every row)
        EntityGroups = @($groups.ToArray())
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $focusDir 'focus_terms.json') -Encoding UTF8

    # ---- standalone dossier ------------------------------------------------
    $esc = { param($s) ("$s" -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;') }
    $buildGraph = {
        # deterministic layered activity map: parents -> instances -> children -> what they did.
        # Pure inline SVG - no JS, no external dependency, prints and screenshots fine.
        $E2 = { param($s) ("$s" -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;') }
        $clip = { param($s, $n) $t = "$s"; if ($t.Length -gt $n) { $t.Substring(0, [Math]::Max(1, $n - 1)) + '...' } else { $t } }
        $XP = 16; $XI = 290; $XC = 570; $XA = 820; $WI = 240
        $nodes = New-Object System.Collections.Generic.List[object]
        $edges = New-Object System.Collections.Generic.List[object]
        $yP = 50; $yI = 50; $yC = 50; $yA = 50
        $parents = New-Object System.Collections.Generic.List[string]
        foreach ($p in $instances) {
            # v2.47: walk the lineage chain root-first so the parent column shows how it arrived
            if ($p.PSObject.Properties['Lineage']) {
                $chain2 = @($p.Lineage)
                for ($x2 = $chain2.Count - 1; $x2 -ge 0; $x2--) { $pv = "$($chain2[$x2])"; if ($pv -and -not $parents.Contains($pv) -and $parents.Count -lt 8) { $parents.Add($pv) } }
            }
            $pv = "$($p.Parent)".Trim()
            if ($pv -and -not $parents.Contains($pv) -and $parents.Count -lt 8) { $parents.Add($pv) }
        }
        foreach ($pv in $parents) {
            $nodes.Add([pscustomobject]@{ Id = "p:$pv"; X = $XP; Y = $yP; W = 240; H = 38; Label = (& $clip $pv 34); Sub = 'parent process'; Fill = '#253044'; Stroke = '#3a4a63' })
            $yP += 52
        }
        $instNodes = @{}
        $shown = 0
        foreach ($i in $instances) {
            if ($shown -ge 12) { break }
            $shown++
            $leaf = Split-Path "$($i.Image)" -Leaf
            if (-not $leaf) { $leaf = "$($i.Image)" }
            $nodes.Add([pscustomobject]@{ Id = "i:$($i.Pid)|$($i.Image)".ToLower(); X = $XI; Y = $yI; W = $WI; H = 44; Label = (& $clip $leaf 24); Sub = (& $clip "PID $($i.Pid) $($i.User)" 34); Fill = '#3a1518'; Stroke = '#a33' })
            $instNodes["$($i.Pid)|$($i.Image)".ToLower()] = "i:$($i.Pid)|$($i.Image)".ToLower()
            $yI += 58
        }
        if ($instances.Count -gt 12) {
            $nodes.Add([pscustomobject]@{ Id = 'i:more'; X = $XI; Y = $yI; W = $WI; H = 24; Label = "+ $($instances.Count - 12) more instance(s)"; Sub = ''; Fill = '#1d2330'; Stroke = '#345' })
            $yI += 38
        }
        foreach ($pd in $perInst) {
            $srcInst = $instNodes["$($pd.Instance.Pid)|$($pd.Instance.Image)".ToLower()]
            foreach ($k in $pd.Children) {
                $kk = "$($k.ProcessId)|$($k.Image)".ToLower()
                $nid = "c:$kk"
                if (-not (@($nodes | Where-Object Id -eq $nid).Count)) {
                    if ((@($nodes | Where-Object { "$($_.Id)" -like 'c:*' }).Count) -ge 14) { break }
                    $leaf = Split-Path "$($k.Image)" -Leaf
                    if (-not $leaf) { $leaf = "$($k.Image)" }
                    $nodes.Add([pscustomobject]@{ Id = $nid; X = $XC; Y = $yC; W = 240; H = 38; Label = (& $clip $leaf 24); Sub = (& $clip "child PID $($k.ProcessId)" 32); Fill = '#33290f'; Stroke = '#c93' })
                    $yC += 52
                }
                if ($srcInst) { $edges.Add(@{ F = $srcInst; T = $nid }) }
            }
            if (-not $srcInst) { continue }
            $chips = New-Object System.Collections.Generic.List[string]
            foreach ($t5 in @($pd.Tamper | Select-Object -First 1)) {
                $cl = ''
                try { $cl = (Split-Path "$($t5.Image)" -Leaf) } catch { $cl = "$($t5.Image)" }
                $chips.Add("TAMPER $(& $clip $cl 24)")
            }
            foreach ($c2 in @($pd.CrtIn | Select-Object -First 2)) {
                $cl = ''
                try { $cl = (Split-Path "$($c2.SourceImage)" -Leaf) } catch { $cl = "$($c2.SourceImage)" }
                $chips.Add("INJECT<- $(& $clip $cl 24)")
            }
            foreach ($c2 in @($pd.CrtOut | Select-Object -First 1)) {
                $cl = ''
                try { $cl = (Split-Path "$($c2.TargetImage)" -Leaf) } catch { $cl = "$($c2.TargetImage)" }
                $chips.Add("THREAD-> $(& $clip $cl 24)")
            }
            foreach ($p2 in @($pd.Pipes | Select-Object -First 1)) { $chips.Add("PIPE $(& $clip "$($p2.PipeName)" 26)") }
            foreach ($f2 in @($pd.FileCreate | Select-Object -First 2)) { $chips.Add("DROP $(& $clip (Split-Path "$($f2.TargetFilename)" -Leaf) 26)") }
            foreach ($f2 in @($pd.FileDelete | Select-Object -First 1)) { $chips.Add("DEL $(& $clip (Split-Path "$($f2.TargetFilename)" -Leaf) 26)") }
            foreach ($b in @($pd.Beacon | Select-Object -First 1)) { $chips.Add("BEACON $($b.Target)") }
            foreach ($pz in @($pd.Persist | Select-Object -First 1)) { $chips.Add("PERSIST $(& $clip $pz.Kind 30)") }
            foreach ($n in @($pd.Net | Select-Object -First 2)) { $chips.Add("NET $($n.DestIp):$($n.DestPort)") }
            foreach ($d in @($pd.Dns | Select-Object -First 1)) { $chips.Add("DNS $(& $clip $d.QueryName 26)") }
            foreach ($f in @($pd.File | Select-Object -First 1)) { $chips.Add("FILE $(& $clip (Split-Path "$($f.TargetFilename)" -Leaf) 26)") }
            foreach ($d in @($pd.Dll | Select-Object -First 1)) { $chips.Add("DLL $(& $clip (Split-Path "$($d.Dll)" -Leaf) 26)") }
            foreach ($r in @($pd.Reg | Select-Object -First 1)) { $chips.Add("REG $(& $clip (Split-Path "$($r.TargetObject)" -Leaf) 26)") }
            $n2 = 0
            foreach ($chip in $chips) {
                if ($n2 -ge 8) { break }
                $nid = "a:$($pd.Instance.Pid):$n2"
                $chipStroke = '#3a5a83'
                if ($chip -match '^(INJECT|TAMPER)') { $chipStroke = '#a33' }
                $nodes.Add([pscustomobject]@{ Id = $nid; X = $XA; Y = $yA; W = 300; H = 24; Label = (& $clip $chip 40); Sub = ''; Fill = '#1f2a3d'; Stroke = $chipStroke })
                $edges.Add(@{ F = $srcInst; T = $nid })
                $yA += 30
                $n2++
            }
            # v2.48: cross-instance injection edges - when both ends of an EID 8 row resolve to
            # tracked instances, draw the inject edge directly between them (red)
            foreach ($c2 in @($pd.CrtOut)) {
                $tgl = "$($c2.TargetProcessGuid)".ToLower()
                if (-not $tgl) { continue }
                $ti = $null
                foreach ($i5 in $instances) { if ("$($i5.Guid)".ToLower() -eq $tgl) { $ti = $i5; break } }
                if (-not $ti) { continue }
                $tn = $instNodes["$($ti.Pid)|$($ti.Image)".ToLower()]
                if (-not $tn -or $tn -eq $srcInst) { continue }
                $edges.Add(@{ F = $srcInst; T = $tn; Stroke = '#a33' })
            }
        }
        $H = [Math]::Max($yP, [Math]::Max($yI, [Math]::Max($yC, $yA))) + 20
        $g = New-Object System.Text.StringBuilder
        [void]$g.AppendLine("<svg viewBox='0 0 1140 $H' style='width:100%;max-width:1140px;background:#10141c;border:1px solid #2a3040;border-radius:6px'>")
        foreach ($c in @(@('PARENTS', $($XP + 4)), @('INSTANCES', $($XI + 4)), @('CHILDREN', $($XC + 4)), @('WHAT IT DID', $($XA + 4)))) {
            [void]$g.AppendLine("<text x='$($c[1])' y='28' fill='#6b7a91' font-size='11' font-weight='bold' font-family='Segoe UI,sans-serif'>$($c[0])</text>")
        }
        foreach ($e in $edges) {
            $f = @($nodes | Where-Object Id -eq $e.F)[0]
            $t = @($nodes | Where-Object Id -eq $e.T)[0]
            if (-not $f -or -not $t) { continue }
            $x1 = $f.X + $f.W; $y1 = $f.Y + [Math]::Floor($f.H / 2); $x2 = $t.X; $y2 = $t.Y + [Math]::Floor($t.H / 2)
            $st = '#3a4a63'; if ($e.Stroke) { $st = $e.Stroke }
            [void]$g.AppendLine("<line x1='$x1' y1='$y1' x2='$x2' y2='$y2' stroke='$st' stroke-width='1'/>")
        }
        foreach ($n in $nodes) {
            [void]$g.AppendLine("<rect x='$($n.X)' y='$($n.Y)' width='$($n.W)' height='$($n.H)' rx='6' fill='$($n.Fill)' stroke='$($n.Stroke)'/>")
            if ($n.Sub) {
                [void]$g.AppendLine("<text x='$($n.X + 10)' y='$($n.Y + 17)' fill='#e0e6ee' font-size='12' font-family='Segoe UI,sans-serif'>$(& $E2 $n.Label)</text>")
                [void]$g.AppendLine("<text x='$($n.X + 10)' y='$($n.Y + 33)' fill='#8a97a8' font-size='10' font-family='Segoe UI,sans-serif'>$(& $E2 $n.Sub)</text>")
            } else {
                $mid = $n.Y + [Math]::Floor($n.H / 2) + 4
                [void]$g.AppendLine("<text x='$($n.X + 10)' y='$mid' fill='#c5cdda' font-size='11' font-family='Consolas,monospace'>$(& $E2 $n.Label)</text>")
            }
        }
        [void]$g.AppendLine('</svg>')
        return $g.ToString()
    }
    $svg = ''
    if ($hits.Count -gt 0) {
        # v2.56: $hint/$hintCls/$hintTxt computed once before the JSON write - reused here
        $h = New-Object System.Text.StringBuilder
        [void]$h.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira focus - $Indicator</title><style>body{background:#141821;color:#cdd3dc;font:13px/1.45 'Segoe UI',sans-serif;margin:20px}h1{color:#eee;font-size:20px}h2{color:#7ab;font-size:15px;border-bottom:1px solid #2a3040;padding-bottom:4px;margin-top:26px}h3{color:#9bd;font-size:13px;margin-top:18px}table{border-collapse:collapse;margin:8px 0;width:100%}th,td{border:1px solid #2a3040;padding:4px 8px;text-align:left;vertical-align:top}th{background:#1d2330;color:#9ab}.path{font-family:Consolas,monospace;font-size:12px;word-break:break-all}td{word-break:break-word}.banner{padding:12px 16px;border-radius:6px;margin:12px 0;font-weight:bold}.crit{background:#3a1518;color:#f88;border:1px solid #722}.med{background:#33290f;color:#fc6;border:1px solid #663}.info{background:#1d2330;color:#8ac;border:1px solid #345}.meta{color:#788;font-size:12px;margin:6px 0}.warn{color:#fc6}</style></head><body>")
        [void]$h.AppendLine("<h1>FOCUS DOSSIER - $(& $esc $Indicator)</h1>")
        [void]$h.AppendLine("<div class='meta'>Host: $(& $esc $meta.Computer) | Case: $(& $esc $meta.CaseID) | Generated: $((Get-Date).ToUniversalTime().ToString('u')) | Ophira v$ScriptVersion | $($hits.Count) evidence row(s) in $($round) round(s) | entity terms: $($names.Count) name / $($paths.Count) path / $($hashes.Count) hash</div>")
        if ($afterDT -or $beforeDT) {
            # v2.73: surface the window honestly - the suppressed count covers out-of-window
            # AND undated rows (undated cannot prove membership once a window is set)
            $wFrom = ''; $wTo = ''
            if ($afterDT) { $wFrom = $afterDT.ToString('yyyy-MM-dd HH:mm') }
            if ($beforeDT) { $wTo = $beforeDT.ToString('yyyy-MM-dd HH:mm') }
            [void]$h.AppendLine("<div class='meta'>time window: $(& $esc $wFrom) to $(& $esc $wTo) - $winDropped row(s) outside window suppressed</div>")
        }
        if (-not ($guids.Count -gt 0)) { [void]$h.AppendLine("<div class='banner info'><span class='warn'>Instance attribution degraded</span> - no ProcessGuid captured in this case (legacy collect or no Sysmon). Per-instance chains below are best-effort.</div>") }
        [void]$h.AppendLine("<div class='banner $hintCls'>$hint - $hintTxt</div>")
        if ($masq.Count -gt 0) { [void]$h.AppendLine("<div class='banner med'><span class='warn'>MASQUERADE WARNING:</span> the name appears at multiple paths - $($(& $esc ($masq -join ', '))). Compare the groups below; only one of them is probably the real OS binary.</div>") }
        if ($corrNotes.Count -gt 0) {
            $cnEsc = @($corrNotes | ForEach-Object { & $esc $_ }) -join '<br>'
            [void]$h.AppendLine("<div class='banner med'><b>Correlation notes</b><br>$cnEsc</div>")
        }
        if ($perInst.Count -gt 0) {
            [void]$h.AppendLine("<h2>Activity graph</h2>")
            $svg = & $buildGraph
            [void]$h.AppendLine($svg)
            [void]$h.AppendLine("<div class='meta'>Left to right: parent processes -> the focused instances (red) -> child processes they spawned (amber) -> what each instance did (chips: TAMPER (Sysmon-detected hollowing) / INJECT<- remote threads into the instance / THREAD-> threads it created in others / PIPE / drops / network / DNS / DLL / file / registry / persistence / beacons). Red edges between instances = cross-process injection. Per-instance detail tables below the instance list. Degraded cases (no ProcessGuid) show fewer joins; execution artifacts (prefetch/amcache/BAM/shimcache) join on every case.</div>")
        }
        if ($groups.Count -gt 0) {
            [void]$h.AppendLine("<h2>Entity groups (path + hash keyed)</h2><table><tr><th>Name</th><th>Path</th><th>Hash (algo-labeled)</th><th>Hits</th><th>First seen</th><th>Last seen</th></tr>")
            foreach ($g in $groups) {
                [void]$h.AppendLine("<tr><td>$(& $esc $g.Name)</td><td class='path'>$(& $esc $g.Path)</td><td class='path'>$(& $esc $g.Hash)</td><td>$($g.HitCount)</td><td>$(& $esc $g.FirstSeen)</td><td>$(& $esc $g.LastSeen)</td></tr>")
            }
            [void]$h.AppendLine("</table>")
        }
        if ($instances.Count -gt 0) {
            $tgI = @($instances | Where-Object { $targetKeys.Contains((& $instKey $_)) })
            $rlI = @($instances | Where-Object { -not $targetKeys.Contains((& $instKey $_)) })
            [void]$h.AppendLine("<h2>Instances - $($tgI.Count) of the target / $($rlI.Count) relative(s) in the chain</h2>")
            [void]$h.AppendLine("<h3>Target instances</h3><table><tr><th>PID</th><th>ProcessGuid</th><th>Started</th><th>Image</th><th>User</th><th>Arrived via</th><th>Notes</th></tr>")
            foreach ($i in $tgI) {
                $ln2 = ''
                if ($i.PSObject.Properties['Lineage'] -and @($i.Lineage).Count -gt 0) { $ln2 = (@($i.Lineage) -join ' &lt;- ') }
                $rp2 = ''
                if ($i.PSObject.Properties['Respawn']) { $rp2 = "<span class='warn'>$(& $esc $i.Respawn)</span>" }
                [void]$h.AppendLine("<tr><td>$(& $esc $i.Pid)</td><td class='path'>$(& $esc $i.Guid)</td><td>$(& $esc $i.Started)</td><td class='path'>$(& $esc $i.Image)</td><td>$(& $esc $i.User)</td><td>$ln2</td><td>$rp2</td></tr>")
            }
            [void]$h.AppendLine("</table>")
            if ($rlI.Count -gt 0) {
                [void]$h.AppendLine("<h3>Relatives in the chain (parents / children of the target)</h3><table><tr><th>PID</th><th>Started</th><th>Image</th><th>Parent</th><th>User</th></tr>")
                foreach ($i in $rlI) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $i.Pid)</td><td>$(& $esc $i.Started)</td><td class='path'>$(& $esc $i.Image)</td><td>$(& $esc $i.Parent)</td><td>$(& $esc $i.User)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
        }
        foreach ($pd in $perInst) {
            $i3 = $pd.Instance
            $hdr = "Instance PID $($i3.Pid)"
            if ("$($i3.Guid)") { $hdr += " - $($i3.Guid)" }
            if ("$($i3.User)") { $hdr += " ($($i3.User))" }
            [void]$h.AppendLine("<h3>$(& $esc $hdr) - everything it did</h3>")
            if ($i3.PSObject.Properties['Respawn']) { [void]$h.AppendLine("<div class='banner med'><span class='warn'>$(& $esc $i3.Respawn)</span></div>") }
            if ($i3.PSObject.Properties['Lineage'] -and @($i3.Lineage).Count -gt 1) {
                [void]$h.AppendLine("<div class='meta'>Arrived via: $(& $esc ((@($i3.Lineage)) -join ' <- '))</div>")
            }
            if ($pd.Children.Count -gt 0) {
                [void]$h.AppendLine("<h4>Child processes ($($pd.Children.Count))</h4><table><tr><th>Time</th><th>Child</th><th>PID</th><th>User</th><th>CommandLine</th></tr>")
                foreach ($x in @($pd.Children | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.Image)</td><td>$(& $esc $x.ProcessId)</td><td>$(& $esc $x.User)</td><td>$(& $esc $x.CommandLine)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Tamper.Count -gt 0) {
                [void]$h.AppendLine("<h4>Process tampering detected by Sysmon ($($pd.Tamper.Count)) - image swap / hollowing (R30)</h4><table><tr><th>Time</th><th>Process</th><th>New image info</th></tr>")
                foreach ($x in @($pd.Tamper | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.Image)</td><td>$(& $esc ("type=$($x.Type) fileVersion=$($x.FileVersion) product=$($x.Product)"))</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.RawDisk.Count -gt 0) {
                [void]$h.AppendLine("<h4>Direct volume access ($($pd.RawDisk.Count)) - raw \\.\ reads (R31)</h4><table><tr><th>Time</th><th>Device</th></tr>")
                foreach ($x in @($pd.RawDisk | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.Device)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.CrtIn.Count -gt 0) {
                [void]$h.AppendLine("<h4>Cross-process injection INTO this instance ($($pd.CrtIn.Count))</h4><table><tr><th>Time</th><th>Injected by</th><th>Start function</th></tr>")
                foreach ($x in @($pd.CrtIn | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.SourceImage)</td><td>$(& $esc ("$($x.StartFunction) @ $($x.StartModule)"))</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.CrtOut.Count -gt 0) {
                [void]$h.AppendLine("<h4>Remote threads this instance created in OTHER processes ($($pd.CrtOut.Count)) - injection activity</h4><table><tr><th>Time</th><th>Target process</th><th>Start function</th></tr>")
                foreach ($x in @($pd.CrtOut | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.TargetImage)</td><td>$(& $esc ("$($x.StartFunction) @ $($x.StartModule)"))</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Pipes.Count -gt 0) {
                [void]$h.AppendLine("<h4>Named pipes created/connected ($($pd.Pipes.Count)) - C2-style pipe channels land here (R29)</h4><table><tr><th>Event</th><th>Time</th><th>Pipe</th></tr>")
                foreach ($x in @($pd.Pipes | Select-Object -First 25)) {
                    $evName = if ("$($x.EventId)" -eq '17') { 'created' } elseif ("$($x.EventId)" -eq '18') { 'connected' } else { "$($x.EventType)" }
                    [void]$h.AppendLine("<tr><td>$(& $esc $evName)</td><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.PipeName)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Persist.Count -gt 0) {
                [void]$h.AppendLine("<h4>Persistence ($($pd.Persist.Count))</h4><table><tr><th>Time</th><th>Mechanism</th><th>Detail</th></tr>")
                foreach ($x in @($pd.Persist | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td>$(& $esc $x.Kind)</td><td class='path'>$(& $esc $x.Detail)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Beacon.Count -gt 0) {
                [void]$h.AppendLine("<h4>C2 beaconing ($($pd.Beacon.Count))</h4><table><tr><th>Kind</th><th>Destination</th><th>Pattern</th></tr>")
                foreach ($x in @($pd.Beacon | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Kind)</td><td class='path'>$(& $esc $x.Target)</td><td>$(& $esc $x.Detail)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Net.Count -gt 0) {
                [void]$h.AppendLine("<h4>Network connections ($($pd.Net.Count))</h4><table><tr><th>Time</th><th>Destination</th><th>Protocol</th></tr>")
                foreach ($x in @($pd.Net | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc ($x.DestIp + ':' + $x.DestPort))</td><td>$(& $esc $x.Protocol)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Dns.Count -gt 0) {
                [void]$h.AppendLine("<h4>DNS queries ($($pd.Dns.Count))</h4><table><tr><th>Time</th><th>Query</th><th>Results</th></tr>")
                foreach ($x in @($pd.Dns | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.QueryName)</td><td class='path'>$(& $esc $x.QueryResults)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Dll.Count -gt 0) {
                [void]$h.AppendLine("<h4>Modules / DLLs loaded ($($pd.Dll.Count))</h4><table><tr><th>Time</th><th>Module</th><th>Signed</th><th>Signature</th></tr>")
                foreach ($x in @($pd.Dll | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.Dll)</td><td>$(& $esc $x.Signed)</td><td>$(& $esc $x.Signature)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.File.Count -gt 0) {
                [void]$h.AppendLine("<h4>File timestamp events ($($pd.File.Count))</h4><table><tr><th>Time</th><th>File</th><th>Previous time</th></tr>")
                foreach ($x in @($pd.File | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.TargetFilename)</td><td>$(& $esc $x.PreviousCreationUtcTime)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.FileCreate.Count -gt 0) {
                [void]$h.AppendLine("<h4>Files created ($($pd.FileCreate.Count))</h4><table><tr><th>Time</th><th>File</th><th>Hashes</th></tr>")
                foreach ($x in @($pd.FileCreate | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.TargetFilename)</td><td class='path'>$(& $esc $x.Hashes)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.FileDelete.Count -gt 0) {
                [void]$h.AppendLine("<h4>Files deleted ($($pd.FileDelete.Count)) - anti-forensics / cleanup evidence</h4><table><tr><th>Time</th><th>File</th><th>Hashes</th></tr>")
                foreach ($x in @($pd.FileDelete | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td class='path'>$(& $esc $x.TargetFilename)</td><td class='path'>$(& $esc $x.Hashes)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Reg.Count -gt 0) {
                [void]$h.AppendLine("<h4>Registry events ($($pd.Reg.Count))</h4><table><tr><th>Time</th><th>Type</th><th>Key</th></tr>")
                foreach ($x in @($pd.Reg | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td>$(& $esc $x.EventType)</td><td class='path'>$(& $esc $x.TargetObject)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
            if ($pd.Exec.Count -gt 0) {
                [void]$h.AppendLine("<h4>Execution artifacts ($($pd.Exec.Count)) - prefetch/amcache/BAM/shimcache: when else this binary ran (the no-Sysmon spine)</h4><table><tr><th>Time</th><th>Artifact</th><th>Detail</th></tr>")
                foreach ($x in @($pd.Exec | Select-Object -First 25)) {
                    [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td>$(& $esc $x.Kind)</td><td class='path'>$(& $esc $x.Detail)</td></tr>")
                }
                [void]$h.AppendLine("</table>")
            }
        }
        if ($chain.Count -gt 0) {
            [void]$h.AppendLine("<h2>Activity chain (master timeline filtered to the entity set, oldest first)</h2><table><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Actor</th><th>Entity</th><th>Detail</th></tr>")
            foreach ($c in @($chain | Select-Object -First 300)) {
                [void]$h.AppendLine("<tr><td>$(& $esc $c.Timestamp)</td><td>$(& $esc $c.Source)</td><td>$(& $esc $c.Type)</td><td>$(& $esc $c.Actor)</td><td class='path'>$(& $esc $c.Entity)</td><td>$(& $esc $c.Detail)</td></tr>")
            }
            [void]$h.AppendLine("</table><div class='meta'>Full chain: focus\focus_chain.csv ($($chain.Count) row(s))</div>")
        }
        $secMap = @(
            @{ Title = 'Detection surface'; Re = '^(yara_hits|defender_threats|flash_ioc_hits|ioc_hits_|memory_malfind|hayabusa_timeline|flash_process_scored|hunt_findings|loldrivers_hits)' },
            @{ Title = 'Network activity'; Re = '^(sysmon_network|sysmon_dns|connections|dns_cache|net_active_probes|firewall|beacon_candidates|dns_beacon_candidates)' },
            @{ Title = 'DLLs and image loads'; Re = '^(sysmon_image_load|sysmon_process_access)' },
            @{ Title = 'Files and execution history'; Re = '^(sysmon_file_time|sysmon_file_create|sysmon_file_delete|mft_recent|usn_write_bursts|prefetch|amcache|userassist|bam_lastexec|execution_timeline|recyclebin|recentfilecache|shimcache|lnk_parsed|jumplist)' },
            @{ Title = 'Registry and persistence'; Re = '^(sysmon_registry|registry_recmd|asep_sweep|autoruns|services|scheduled_tasks|wmi_|security_task_install|startup_info)' },
            @{ Title = 'Process events'; Re = '^(security_proc_events|sysmon_proc_create|processes|process_hashes|process_chains|entities_binaries|sysmon_events|sysmon_remote_thread|sysmon_pipes|sysmon_proc_tamper|sysmon_raw_access|sysmon_wmi)' },
            @{ Title = 'Accounts and sessions'; Re = '^(security_auth|security_kerberos|security_ds_|session_activity|logon_sessions|saved_credentials)' },
            @{ Title = 'Other evidence'; Re = '' }
        )
        $claimed = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($sec in $secMap) {
            if ("$($sec.Re)") {
                $secHits = @($hits | Where-Object { "$($_.Source)" -match $sec.Re -and -not $claimed.Contains("$($_.Source)") })
            } else {
                $secHits = @($hits | Where-Object { -not $claimed.Contains("$($_.Source)") })
            }
            foreach ($x in $secHits) { $null = $claimed.Add("$($x.Source)") }
            if ($secHits.Count -eq 0) { continue }
            [void]$h.AppendLine("<h2>$($sec.Title) ($($secHits.Count))</h2><table><tr><th>Time</th><th>Source</th><th>Matched on</th><th>Detail</th></tr>")
            foreach ($x in @($secHits | Sort-Object { "$($_.Time)" } | Select-Object -First 200)) {
                [void]$h.AppendLine("<tr><td>$(& $esc $x.Time)</td><td>$(& $esc $x.Source)</td><td>$(& $esc $x.MatchedOn)</td><td>$(& $esc ("$($x.Detail)" -replace ' \| ', '<br>'))</td></tr>")
            }
            [void]$h.AppendLine("</table>")
        }
        [void]$h.AppendLine("<div class='meta'>Rebuild: <b>Ophira.ps1 -Mode Focus -ParsePath &lt;case&gt; -ProcessName &lt;indicator&gt;</b> (name, PID, path, hash, IP, ip:port or port). Chain CSV: focus\focus_chain.csv - raw hits: focus\focus_hits.csv</div>")
        [void]$h.AppendLine("</body></html>")
        Set-Content -LiteralPath (Join-Path $focusDir 'focus_report.html') -Value $h.ToString() -Encoding UTF8
    }

    # ---- v2.49 R3: uncapped DOT export for chains bigger than the SVG caps ----
    # Same layered model (parents -> instances -> children -> artifact chips + injection
    # edges) but ALL instances/children and up to 25 chips per instance - opens in any
    # Graphviz/DOT viewer (e.g. https://dreampuf.github.io/GraphvizOnline, xdot).
    if ($hits.Count -gt 0 -and $instances.Count -gt 0) {
        $dot = New-Object System.Text.StringBuilder
        $dotEsc = { param($s) ("$s" -replace '\\', '\\' -replace '"', '\"') }
        [void]$dot.AppendLine('digraph focus {')
        [void]$dot.AppendLine('  rankdir=LR; bgcolor="#10141c";')
        [void]$dot.AppendLine('  node [style=filled, shape=box, fontname="Consolas", fontsize=10, fontcolor="#c5cdda", fillcolor="#1f2a3d", color="#3a5a83"];')
        [void]$dot.AppendLine('  edge [color="#3a4a63"];')
        $dParents = @{}
        $instIds = @{}
        foreach ($i in $instances) {
            $imgL2 = "$($i.Image)"
            $leaf2 = $imgL2
            if ($leaf2) { try { $lf3 = (Split-Path $leaf2 -Leaf); if ($lf3) { $leaf2 = $lf3 } } catch { } }
            if (-not $leaf2) { $leaf2 = '(unknown image)' }
            $nid = "i$($instIds.Count)"
            $instIds["$($i.Pid)|$($i.Image)".ToLower()] = $nid
            [void]$dot.AppendLine("  `"$nid`" [label=`"INSTANCE $(& $dotEsc "$leaf2 (PID $($i.Pid))")`", fillcolor=`"#3a1518`", color=`"#a33`"];")
            # direct parent only (Lineage[0] is the nearest ancestor; Parent falls back)
            $pv = ''
            if ($i.PSObject.Properties['Lineage'] -and @($i.Lineage).Count -gt 0) { $pv = "$(@($i.Lineage)[0])" }
            if (-not $pv) { $pv = "$($i.Parent)".Trim() }
            if ($pv -and "$pv" -notmatch '^PPID ') {
                if (-not $dParents.ContainsKey($pv)) {
                    $dParents[$pv] = "p$($dParents.Count)"
                    [void]$dot.AppendLine("  `"$($dParents[$pv])`" [label=`"PARENT $(& $dotEsc $pv)`", fillcolor=`"#253044`"];")
                }
                [void]$dot.AppendLine("  `"$($dParents[$pv])`" -> `"$nid`";")
            }
        }
        $childIds = @{}
        foreach ($pd in $perInst) {
            $srcId = $instIds["$($pd.Instance.Pid)|$($pd.Instance.Image)".ToLower()]
            if (-not $srcId) { continue }
            foreach ($k in $pd.Children) {
                $ck = "$($k.ProcessId)|$($k.Image)".ToLower()
                $cid = $null
                if (-not $childIds.ContainsKey($ck)) {
                    $cid = "c$($childIds.Count)"
                    $childIds[$ck] = $cid
                    [void]$dot.AppendLine("  `"$cid`" [label=`"CHILD $(& $dotEsc "$(Split-Path "$($k.Image)" -Leaf) (PID $($k.ProcessId))")`", fillcolor=`"#33290f`", color=`"#c93`"];")
                } else { $cid = $childIds[$ck] }
                [void]$dot.AppendLine("  `"$srcId`" -> `"$cid`";")
            }
            $chipN = 0
            foreach ($t5 in @($pd.Tamper)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"TAMPER $(& $dotEsc (Split-Path "$($t5.Image)" -Leaf))`", color=`"#a33`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`"" + ' [color="#a33"];'); $chipN++ }
            foreach ($c2 in @($pd.CrtIn)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"INJECT<- $(& $dotEsc (Split-Path "$($c2.SourceImage)" -Leaf))`", color=`"#a33`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`"" + ' [color="#a33"];'); $chipN++ }
            foreach ($c2 in @($pd.CrtOut)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"THREAD-> $(& $dotEsc (Split-Path "$($c2.TargetImage)" -Leaf))`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`";"); $chipN++ }
            foreach ($p2 in @($pd.Pipes)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"PIPE $(& $dotEsc "$($p2.PipeName)")`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`";"); $chipN++ }
            foreach ($f2 in @($pd.FileCreate)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"DROP $(& $dotEsc (Split-Path "$($f2.TargetFilename)" -Leaf))`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`";"); $chipN++ }
            foreach ($b in @($pd.Beacon)) { if ($chipN -ge 25) { break }; [void]$dot.AppendLine("  `"a$srcId`_$chipN`" [label=`"BEACON $(& $dotEsc "$($b.Target)")`"];"); [void]$dot.AppendLine("  `"$srcId`" -> `"a$srcId`_$chipN`";"); $chipN++ }
            # cross-instance injection edges (both ends tracked)
            foreach ($c2 in @($pd.CrtOut)) {
                $tgl = "$($c2.TargetProcessGuid)".ToLower()
                if (-not $tgl) { continue }
                $ti = $null
                foreach ($i5 in $instances) { if ("$($i5.Guid)".ToLower() -eq $tgl) { $ti = $i5; break } }
                if (-not $ti) { continue }
                $tn = $instIds["$($ti.Pid)|$($ti.Image)".ToLower()]
                if ($tn -and $tn -ne $srcId) { [void]$dot.AppendLine("  `"$srcId`" -> `"$tn`" [color=`"#a33`", penwidth=1.5, label=`"inject`"];") }
            }
        }
        [void]$dot.AppendLine('}')
        try {
            Set-Content -LiteralPath (Join-Path $focusDir 'focus_graph.dot') -Value $dot.ToString() -Encoding UTF8
            Write-Host "  Graphviz export -> focus\focus_graph.dot (uncapped - for chains bigger than the SVG view)" -ForegroundColor DarkGray
        } catch { }
    }

    # ---- per-instance detail + graph for the main report embed (v2.45) ----
    # The general report's Focus section reads this instead of re-computing the joins.
    $detailInstances = @($perInst | ForEach-Object {
        $lnI = @(); $rpI = ''
        if ($_.Instance.PSObject.Properties['Lineage']) { $lnI = @($_.Instance.Lineage) }
        if ($_.Instance.PSObject.Properties['Respawn']) { $rpI = "$($_.Instance.Respawn)" }
        [pscustomobject]@{
            Pid = "$($_.Instance.Pid)"; Guid = "$($_.Instance.Guid)"; Started = "$($_.Instance.Started)"
            Image = "$($_.Instance.Image)"; Parent = "$($_.Instance.Parent)"; User = "$($_.Instance.User)"
            Lineage = $lnI; Respawn = $rpI
            Children = @($_.Children | Select-Object -First 25)
            Net = @($_.Net | Select-Object -First 25)
            Dns = @($_.Dns | Select-Object -First 25)
            Dll = @($_.Dll | Select-Object -First 25)
            Reg = @($_.Reg | Select-Object -First 25)
            File = @($_.File | Select-Object -First 25)
            FileCreate = @($_.FileCreate | Select-Object -First 25)
            FileDelete = @($_.FileDelete | Select-Object -First 25)
            Persist = @($_.Persist | Select-Object -First 25)
            Beacon = @($_.Beacon | Select-Object -First 25)
            CrtIn = @($_.CrtIn | Select-Object -First 25)
            CrtOut = @($_.CrtOut | Select-Object -First 25)
            Pipes = @($_.Pipes | Select-Object -First 25)
            Tamper = @($_.Tamper | Select-Object -First 25)
            RawDisk = @($_.RawDisk | Select-Object -First 25)
            Exec = @($_.Exec | Select-Object -First 25)
        }
    })
    @{
        Indicator = $Indicator
        GraphSvg = $svg
        Instances = $detailInstances
        CorrNotes = $corrNotes.ToArray()
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $focusDir 'focus_instances_detail.json') -Encoding UTF8

    # ---- console summary --------------------------------------------------
    Write-Host ""
    Write-Host "FOCUS '$Indicator' - $($hits.Count) evidence row(s) across $($sourcesHit.Keys.Count) artifact(s), $($groups.Count) entity group(s), $($instances.Count) instance(s):" -ForegroundColor Cyan
    foreach ($g in $groups) {
        $h = if ($g.Hash) { " sha256:$($g.Hash.Substring(0, [Math]::Min(16, $g.Hash.Length)))..." } else { '' }
        Write-Host ("  [{0}] {1}{2}  hits:{3}" -f $g.Name, $g.Path, $h, $g.HitCount) -ForegroundColor White
    }
    if ($masq.Count -gt 0) { Write-Host "  MASQUERADE WARNING: same name at multiple paths -> $($masq -join ', ')" -ForegroundColor Yellow }
    foreach ($cn2 in $corrNotes) { Write-Host "  [note] $cn2" -ForegroundColor Yellow }
    $tg = @($instances | Where-Object { $targetKeys.Contains((& $instKey $_)) })
    $rl = @($instances | Where-Object { -not $targetKeys.Contains((& $instKey $_)) })
    Write-Host ("  instances: {0} of the target / {1} relative(s) in the chain" -f $tg.Count, $rl.Count) -ForegroundColor White
    foreach ($t2 in $tg) {
        $rp = ''; if ($t2.PSObject.Properties['Respawn']) { $rp = "  [$($t2.Respawn)]" }
        $ln = ''
        if ($t2.PSObject.Properties['Lineage'] -and @($t2.Lineage).Count -gt 0) {
            $lc = @($t2.Lineage)
            $ln = "  arrived via: " + (($lc[[Math]::Min($lc.Count - 1, 2)..0] | ForEach-Object { "$_".Trim() }) -join ' <- ')
        }
        Write-Host ("    PID {0}  {1}  started {2}{3}{4}" -f $t2.Pid, $t2.Image, $t2.Started, $rp, $ln) -ForegroundColor Gray
    }
    foreach ($g in ($sourcesHit.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12)) {
        Write-Host ("  {0,-32} x{1}" -f $g.Key, $g.Value) -ForegroundColor Gray
    }
    if (-not ($guids.Count -gt 0)) {
        Write-Host "  note: no ProcessGuid in this case (legacy/no-Sysmon collect) - per-instance attribution is limited" -ForegroundColor DarkYellow
    }
    if ($perInst.Count -gt 0) { Write-Host ("  per-instance detail joined for {0} instance(s): children / tamper / injection / pipes / network / DNS / DLLs / file / registry / persistence / beacons / execution artifacts (no-Sysmon spine)" -f $perInst.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "Dossier -> focus\focus_report.html  (chain: focus\focus_chain.csv, hits: focus\focus_hits.csv)" -ForegroundColor Green
    return $true
}

function Invoke-TimelineMode {
    # v2.25 analyst-side timeframe pivot: filter the case's MASTER TIMELINE to a window and
    # summarize what happened - the "someone reported weird activity around 14:00" workflow.
    # Timestamps in supertimeline.csv are UTC; enter the window in UTC.
    param([string]$Path, [string]$Start, [string]$End)
    Write-Host ""
    Write-Host "=== Timeline pivot (filter the master timeline to a window) ===" -ForegroundColor Cyan
    if (-not $Path) { $Path = (Read-Host "  Case folder or OPHIRA_*.zip path").Trim(' "') }
    $meta = Open-CaseSession -Path $Path
    if (-not $meta) { return $false }
    if (-not $Start) { $Start = (Read-Host "  Window START (yyyy-MM-dd HH:mm, UTC)").Trim() }
    if (-not $End) { $End = (Read-Host "  Window END   (yyyy-MM-dd HH:mm, UTC)").Trim() }
    $t0 = $null; $t1 = $null
    try { $t0 = [datetime]$Start } catch { }
    try { $t1 = [datetime]$End } catch { }
    if (-not $t0 -or -not $t1 -or ($t1 -eq [datetime]::MinValue)) { Write-Host "  invalid start/end - use 'yyyy-MM-dd HH:mm'" -ForegroundColor Red; return $false }
    if ($t1 -lt $t0) { $tmp = $t0; $t0 = $t1; $t1 = $tmp }
    $tlPath = Join-Path $script:CsvDir 'supertimeline.csv'
    if (-not (Test-Path -LiteralPath $tlPath)) { $tlPath = Join-Path $script:CsvDir (Get-CaseCsvPath 'supertimeline') }
    if (-not (Test-Path $tlPath)) { Write-Host "  no supertimeline.csv in this case (collect first, or run -Mode Parse)" -ForegroundColor Red; return $false }
    $tl = @(Import-Csv -LiteralPath $tlPath -ErrorAction SilentlyContinue)
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($r in $tl) {
        $t = $null
        try { $t = [datetime]$r.Timestamp } catch { }
        if ($t -and $t -ge $t0 -and $t -le $t1) { $null = $sel.Add($r) }
    }
    if ($sel.Count -eq 0) {
        Write-Host "  no rows in $t0 -> $t1 UTC. Timeline coverage: $(@($tl)[0].Timestamp) -> $(@($tl)[-1].Timestamp)" -ForegroundColor Yellow
        return $true
    }
    $out = Join-Path $script:CsvDir ("timeline_" + $t0.ToString('yyyyMMdd_HHmm') + "_" + $t1.ToString('yyyyMMdd_HHmm') + ".csv")
    $sel.ToArray() | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "  Window: $t0 -> $t1 UTC   rows: $($sel.Count) of $($tl.Count)  ->  $(Split-Path $out -Leaf)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  By source:" -ForegroundColor White
    foreach ($g in (@($sel | Group-Object Source | Sort-Object Count -Descending))) { Write-Host ("    {0,-28} x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Busiest minutes:" -ForegroundColor White
    foreach ($g in (@($sel | Group-Object { "$($_.Timestamp)".PadRight(16).Substring(0, 16) } | Sort-Object Count -Descending | Select-Object -First 5))) { Write-Host ("    {0}  x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Top actors:" -ForegroundColor White
    foreach ($g in (@($sel | Where-Object { "$($_.Actor)" } | Group-Object Actor | Sort-Object Count -Descending | Select-Object -First 5))) { Write-Host ("    {0,-24} x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Open the CSV in Excel/Timeline Explorer (sorted, filterable). Report refresh: -Mode Parse." -ForegroundColor Gray
    return $true
}

function Invoke-CanaryMode {
    # Detection self-test: plant safe, self-labeled test activity, enable the logging the
    # hunt rules need, run a collection, then score which detections fired. With -Target,
    # also exercises the cross-host story (lateral SMB touch as canary_test -> R12/attribution).
    # The ONLY mode that changes endpoint state (audit policy + registry + test artifacts) -
    # audit changes are restored afterwards unless -KeepLogging.
    param([switch]$KeepLogging, [string]$Target, [string]$TargetUser)
    Write-Host ""
    Write-Host "=== Detection canary (validate the pipeline end-to-end) ===" -ForegroundColor Cyan
    if (-not (Test-IsAdmin)) {
        Write-Host "  Needs an elevated shell (audit policy + registry changes). Relaunching..." -ForegroundColor Yellow
        $argStr = Get-ArgString
        try { Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $argStr"; return } catch { Write-Host "  Elevation declined - canary needs admin." -ForegroundColor Red; return $false }
    }
    if ($script:SimpleUI) { Write-Host "  Canary is a responder tool - not available in the simple owner UI." -ForegroundColor Yellow; return $false }
    if (-not $Target) { $Target = (Read-Host "  Lateral target PC (IP/name, ENTER = single-host canary)").Trim() }
    Write-Host ""
    Write-Host "  This will, on THIS PC:" -ForegroundColor Yellow
    Write-Host "   - enable Process Creation + cmdline + scriptblock logging (restored after, unless -KeepLogging)"
    Write-Host "   - plant self-labeled test activity: renamed cmd copies (one kept alive as a fake tunnel tool),"
    Write-Host "     canary_test user (created + deleted), recon command burst, certutil fetch of a benign file,"
    Write-Host "     canary_tunneld service (registered + immediately removed - the 7045 event remains),"
    Write-Host "     one labeled line in administrators_authorized_keys (file removed/restored after),"
    Write-Host "     a self-labeled named pipe (canary_msagent_f00d, created + closed)"
    Write-Host "   - run a Standard collection and score which hunt rules fired"
    if ($Target) {
        Write-Host "  And on TARGET '$Target':" -ForegroundColor Yellow
        Write-Host "   - enable the same audits (+ Detailed File Share) - restored after"
        Write-Host "   - receive an SMB session + a labeled file write to its admin share (canary_lateral.exe)"
        Write-Host "   - receive its own collection, scored for the cross-host detections"
        Write-Host "  The target must be domain-joined and reachable (this account needs remote-admin rights on it)." -ForegroundColor Yellow
        Write-Host "  Targeting by IP also needs this host's WinRM TrustedHosts to include the target." -ForegroundColor Yellow
    }
    Write-Host "  Lab / validation use only - never run it as part of a live investigation." -ForegroundColor Yellow
    $go = (Read-Host "  Run the canary here? [y/N]").Trim()
    if ($go -notmatch '^y') { Write-Host "  Cancelled." -ForegroundColor Gray; return $false }
    # remote actions need EXPLICIT credentials when this process itself sits in a remoting session
    # (network token cannot authenticate a second hop) - prompt, or read the lab-automation override
    $tCred = $null
    if ($Target) {
        if (-not $TargetUser) { $TargetUser = (Read-Host "  Target admin account (ENTER = current account)").Trim() }
        if ($TargetUser) {
            if ($env:OPHIRA_CANARY_TARGET_PASS) {
                $tpw = ConvertTo-SecureString $env:OPHIRA_CANARY_TARGET_PASS -AsPlainText -Force
                $tCred = New-Object PSCredential($TargetUser, $tpw)
                Write-Host "  Target credentials: $TargetUser (from OPHIRA_CANARY_TARGET_PASS)" -ForegroundColor DarkGray
            } else { $tCred = Get-Credential -UserName $TargetUser -Message "Password for target $Target" }
            if (-not $tCred) { $TargetUser = '' }
        }
        if (-not $TargetUser) { Write-Host "  No target credentials - remote leg uses the current account (works only from a locally-launched, interactive session)." -ForegroundColor DarkYellow }
    }

    # ---- phase 1: enable logging (capturing prior state for restore) ----
    Write-Host ""
    Write-Host "  [1/4] Enabling logging..." -ForegroundColor Cyan
    $undo = New-Object System.Collections.Generic.List[string]
    foreach ($sub in @('Process Creation', 'User Account Management', 'Security Group Management')) {
        $before = (& auditpol.exe /get /subcategory:"$sub" 2>$null | Out-String)
        if ($before -match '(?i)Success') { Write-Host "    $sub - already on" -ForegroundColor DarkGray; continue }
        $null = & auditpol.exe /set /subcategory:"$sub" /success:enable 2>&1
        $undo.Add("auditpol|$sub")
        Write-Host "    $sub - enabled" -ForegroundColor Gray
    }
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdHad = (Get-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    if ("$cmdHad" -ne '1') {
        if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
        if ($null -eq $cmdHad) { New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null; $undo.Add("regdel|$auditKey|ProcessCreationIncludeCmdLine_Enabled") }
        else { Set-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Force; $undo.Add("regset|$auditKey|ProcessCreationIncludeCmdLine_Enabled|$cmdHad") }
        Write-Host "    4688 command line - enabled" -ForegroundColor Gray
    } else { Write-Host "    4688 command line - already on" -ForegroundColor DarkGray }
    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sbHad = (Get-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ("$sbHad" -ne '1') {
        if (-not (Test-Path $psKey)) { New-Item -Path $psKey -Force | Out-Null }
        if ($null -eq $sbHad) { New-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null; $undo.Add("regdel|$psKey|EnableScriptBlockLogging") }
        else { Set-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -Value 1 -Force; $undo.Add("regset|$psKey|EnableScriptBlockLogging|$sbHad") }
        Write-Host "    PowerShell script block logging - enabled" -ForegroundColor Gray
    } else { Write-Host "    PowerShell script block logging - already on" -ForegroundColor DarkGray }
    $bUndo = @()
    if ($Target) {
        Write-Host "    target ${Target}: enabling audits..." -ForegroundColor Gray
        try {
            $rc = @{ ComputerName = $Target; ErrorAction = 'Stop' }
            if ($tCred) { $rc.Credential = $tCred }
            $bUndo = @(Invoke-Command @rc -ScriptBlock {
                param([string[]]$Subs)
                $undo = @()
                foreach ($sub in $Subs) {
                    $before = (& auditpol.exe /get /subcategory:"$sub" 2>$null | Out-String)
                    if ($before -match '(?i)Success') { continue }
                    $null = & auditpol.exe /set /subcategory:"$sub" /success:enable 2>&1
                    $undo += "auditpol|$sub"
                }
                return $undo
            } -ArgumentList (, @('Process Creation', 'User Account Management', 'Security Group Management', 'Detailed File Share')))
            Write-Host "    target ${Target}: audits ready ($(@($bUndo).Count) newly enabled)" -ForegroundColor Gray
        } catch {
            Write-Host "    target unreachable/forbidden ($($_.Exception.Message)) - continuing single-host" -ForegroundColor DarkYellow
            $Target = ''
        }
    }

    # ---- phase 2: plant the battery (everything self-labeled 'canary') ----
    Write-Host "  [2/4] Planting test activity..." -ForegroundColor Cyan
    $canExe = Join-Path $env:PUBLIC 'canary_renamed.exe'
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $canExe -Force
    $null = & $canExe /c "echo canary > `"$env:TEMP\canary_out.txt`"" 2>&1
    Write-Host "    renamed cmd copy run (canary_renamed.exe)" -ForegroundColor Gray
    # tunnel-tool plant: named for a tunnel binary + kept alive so it is RUNNING at collect time
    # (fires R23 via the live process and R1/R1b via the cmd identity; killed in cleanup)
    $ngProc = $null
    $canNgrok = Join-Path $env:PUBLIC 'canary_ngrok.exe'
    try {
        Copy-Item "$env:SystemRoot\System32\cmd.exe" $canNgrok -Force -ErrorAction Stop
        $ngProc = Start-Process -FilePath $canNgrok -ArgumentList '/c', 'ping -n 400 127.0.0.1 > nul' -WindowStyle Hidden -PassThru -ErrorAction Stop
        Write-Host "    canary_ngrok.exe running (kept alive through collection)" -ForegroundColor Gray
    } catch { Write-Host "    canary_ngrok plant failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    # service-install plant: registered + immediately removed - only the 7045 event remains
    if ($ngProc) {
        $null = & sc.exe create canary_tunneld binPath= "$canNgrok" start= demand 2>&1
        $null = & sc.exe delete canary_tunneld 2>&1
        Write-Host "    canary_tunneld service registered + removed (7045 evidence remains)" -ForegroundColor Gray
    }
    # SSH trust plant: one labeled key line (prior file state captured; restored/removed in cleanup)
    $akFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $akPrev = $null
    $akCreated = $false
    $akOk = $false
    try {
        if (Test-Path -LiteralPath $akFile) { $akPrev = @(Get-Content -LiteralPath $akFile -ErrorAction Stop | ForEach-Object { "$_" }) }
        else {
            $akDir = Split-Path $akFile -Parent
            if (-not (Test-Path $akDir)) { New-Item -ItemType Directory -Path $akDir -Force | Out-Null }
            $akCreated = $true
        }
        Add-Content -LiteralPath $akFile -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICANARYKEYLINE canary@ophira-selftest' -ErrorAction Stop
        $akOk = $true
        Write-Host "    labeled line planted in administrators_authorized_keys" -ForegroundColor Gray
    } catch { Write-Host "    authorized_keys plant skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    $canPass = 'Canary!2026'
    $null = & net.exe user canary_test $canPass /add 2>&1
    $null = & net.exe localgroup administrators canary_test /add 2>&1
    Write-Host "    canary_test user created + added to Administrators (kept alive for the lateral leg)" -ForegroundColor Gray
    if ($Target) {
        $lateralOk = $false
        $null = & net.exe use "\\$Target\C$" /delete 2>&1
        # authenticate as the TARGET ADMIN when we have those credentials (R12 needs the admin
        # share anyway; canary_test exercises account lifecycle locally, not this leg)
        $useUser = "$env:USERDOMAIN\canary_test"; $usePass = $canPass
        if ($tCred) { $useUser = $tCred.UserName; $usePass = $tCred.GetNetworkCredential().Password }
        $nu = & net.exe use "\\$Target\C$" $usePass /user:"$useUser" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $null = & cmd.exe /c "dir \\$Target\C$\Users\Public > nul" 2>&1
            try {
                Copy-Item $canExe "\\$Target\C$\Users\Public\canary_lateral.exe" -Force -ErrorAction Stop
                $lateralOk = $true
                Write-Host "    lateral: SMB session as $useUser + canary_lateral.exe written to target admin share" -ForegroundColor Gray
            } catch { Write-Host "    lateral write failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
            $null = & net.exe use "\\$Target\C$" /delete 2>&1
        } else {
            Write-Host "    lateral SMB failed (exit $LASTEXITCODE): $(($nu | Where-Object { "$_" } | Select-Object -Last 1))" -ForegroundColor DarkYellow
            Write-Host "    B-side checks will be BLIND" -ForegroundColor DarkYellow
        }
    }
    $recon = @(
        { & whoami.exe 2>&1 }, { & net.exe user 2>&1 }, { & net.exe localgroup administrators 2>&1 },
        { & nltest.exe /dclist:"$env:USERDOMAIN" 2>&1 }, { & systeminfo.exe 2>&1 }, { & ipconfig.exe /all 2>&1 },
        { & quser.exe 2>&1 }, { & tasklist.exe 2>&1 }, { & klist.exe 2>&1 }, { & netstat.exe -an 2>&1 }
    )
    foreach ($rcmd in $recon) { $null = & $rcmd }
    Write-Host "    discovery burst (10 recon tools)" -ForegroundColor Gray
    try {
        $null = & certutil.exe -urlcache -f 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/README.md' "$env:TEMP\canary_dl.bin" 2>&1
        Write-Host "    certutil benign fetch" -ForegroundColor Gray
    } catch { Write-Host "    certutil fetch skipped (offline?)" -ForegroundColor DarkYellow }
    # pipe plant: a self-labeled pipe named for a known C2 family (fires R29 + proves the
    # EID 17/18 telemetry channel); same-process client connect is enough for both events
    $pipeOk = $false
    $srv = $null; $cli = $null
    try {
        $srv = New-Object System.IO.Pipes.NamedPipeServerStream('canary_msagent_f00d', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None)
        $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'canary_msagent_f00d', [System.IO.Pipes.PipeDirection]::InOut)
        $cli.Connect(3000)
        $srv.WaitForConnection(3000)
        $pipeOk = $true
        Write-Host "    canary_msagent_f00d named pipe created + connected (EID 17/18 evidence)" -ForegroundColor Gray
    } catch { Write-Host "    pipe plant skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    if ($srv) { $srv.Dispose() }
    if ($cli) { $cli.Dispose() }
    $null = & net.exe localgroup administrators canary_test /delete 2>&1
    $null = & net.exe user canary_test /delete 2>&1
    if ($Target) { $null = Invoke-Command @rc -ScriptBlock { Remove-Item C:\Users\Public\canary_lateral.exe -Force -ErrorAction SilentlyContinue } }
    Write-Host "    canary_test removed (all planted artifacts are self-labeled)" -ForegroundColor Gray

    # ---- phase 3: collection (Standard: Quick excludes the 4688/auth parses the scorecard reads) ----
    Write-Host "  [3/4] Collecting (Standard preset, ~3-5 min)..." -ForegroundColor Cyan
    $kit = Get-KitRoot
    $before = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue)
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode Collect -NoMenu -NoElevate -Preset Standard -CaseID CANARY -OutputPath `"$kit`""
    $null = Start-Process -FilePath 'powershell.exe' -ArgumentList $cmd -Wait -WindowStyle Hidden
    $case = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue | Where-Object { $before -notcontains $_ } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if (-not $case) { Write-Host "  collection produced no case folder - see collection.log" -ForegroundColor Red; return $false }
    $csv = Join-Path $case.FullName 'csv'
    $bZip = $null
    if ($Target) {
        Write-Host "  [3/4] Collecting on target $Target (Standard)..." -ForegroundColor Cyan
        $beforeZips = @(Get-ChildItem -Path (Join-Path $kit 'collections') -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue)
        try {
            Invoke-DeployMode -Targets @($Target) -DeployPreset 'Standard' -Cred $tCred -DeployCaseID 'CANARY' -DeploySharePath '' -Threads 1 -PushBin $false -DeployLogHours 168
            $bZip = Get-ChildItem -Path (Join-Path $kit 'collections') -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue | Where-Object { $beforeZips -notcontains $_ } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        } catch { Write-Host "    target collection failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
        if (-not $bZip) { Write-Host "    no result zip from target - B-side checks will be BLIND" -ForegroundColor DarkYellow }
    }

    # ---- phase 4: scorecard ----
    Write-Host ""
    Write-Host "  [4/4] Scorecard - case: $(Split-Path $case.FullName -Leaf)" -ForegroundColor Cyan
    Write-Host ""
    $hf = @(Import-CsvFlatMapped $csv 'hunt_findings')
    $procRows = @(Import-CsvFlatMapped $csv 'security_proc_events')
    $authRows = @(Import-CsvFlatMapped $csv 'security_auth_events')
    $pcRows = @(Import-CsvFlatMapped $csv 'sysmon_proc_create')
    $raRows = @(Import-CsvFlatMapped $csv 'remote_access')
    $sysSvcRows = @(Import-CsvFlatMapped $csv 'system_new_services')
    $pipeRows = @(Import-CsvFlatMapped $csv 'sysmon_pipes')
    $score = 0; $possible = 0
    # v2.47 R4: the focus pipeline gets a canary row like R1-R27 - run the real engine core on
    # the planted canary_ngrok.exe against the fresh case and require a dossier with hits + instance
    $focusFired = 0; $focusData = 0; $focusWhy = 'live snapshot / Sysmon EID 1 missing (Standard preset required)'
    $focusData = @($pcRows | Where-Object { "$($_)" -match 'canary_ngrok' }).Count + @(Get-ChildItem -LiteralPath $csv -Recurse -Filter 'processes.csv' -ErrorAction SilentlyContinue | ForEach-Object { @(Import-Csv -LiteralPath $_.FullName -ErrorAction SilentlyContinue | Where-Object { "$($_)" -match 'canary_ngrok' }).Count } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    $focusTerms = Join-Path $case.FullName 'focus\focus_terms.json'
    if (-not (Test-Path -LiteralPath (Join-Path $case.FullName 'focus'))) {
        $savedCaseDir = $script:CaseDir; $savedCsvDir = $script:CsvDir; $savedRawDir = $script:RawDir; $savedLog = $script:CaseLog
        try {
            $script:CaseDir = $case.FullName
            $script:CsvDir = $csv
            $script:RawDir = Join-Path $case.FullName 'raw'
            $script:CaseLog = Join-Path $case.FullName 'collection.log'
            $null = Invoke-FocusCore -Indicator 'canary_ngrok.exe' -Meta ([pscustomobject]@{ Computer = 'canary'; CaseID = 'CANARY' })
        } catch { Write-Host "    focus canary failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
        finally { $script:CaseDir = $savedCaseDir; $script:CsvDir = $savedCsvDir; $script:RawDir = $savedRawDir; $script:CaseLog = $savedLog }
    }
    if (Test-Path -LiteralPath $focusTerms) {
        try {
            $ftC = Get-Content -LiteralPath $focusTerms -Raw | ConvertFrom-Json
            if ([int]$ftC.HitCount -gt 0) { $focusFired = 1 }
        } catch { }
    }
    $c4720 = @($authRows | Where-Object { "$($_.EventId)" -eq '4720' }).Count
    $c4732 = @($authRows | Where-Object { @('4728', '4732', '4756') -contains "$($_.EventId)" }).Count
    $r6Why = if ($c4720 -eq 0 -and $c4732 -eq 0) { 'User Account Management audit not active' } elseif ($c4732 -eq 0) { 'Security Group Management audit not active (4720 seen, no group change)' } else { 'auth telemetry missing' }
    $checks = @(
        @{ L = 'R1b  renamed LOLBin at rest';      Hit = @($hf | Where-Object { $_.Rule -match 'Renamed LOLBin at rest' }).Count;        Data = @($pcRows | Where-Object { $_ -match 'canary_renamed' }).Count;  DataWhy = 'Sysmon not present or EID 1 not captured' }
        @{ L = 'R6   account lifecycle';           Hit = @($hf | Where-Object { $_.Rule -match 'Account lifecycle' }).Count;              Data = ($c4720 + $c4732); DataWhy = $r6Why }
        @{ L = 'R10  proxy-execution (certutil)';  Hit = @($hf | Where-Object { $_.Rule -match 'proxy-execution' }).Count;                Data = @($procRows | Where-Object { $_ -match 'canary|certutil' }).Count; DataWhy = '4688/cmdline audit not active at plant time' }
        @{ L = 'R13  discovery command storm';     Hit = @($hf | Where-Object { $_.Rule -match 'Discovery command storm' }).Count;        Data = @($procRows | Where-Object { $_ -match 'whoami|systeminfo|nltest' }).Count; DataWhy = '4688 audit not active at plant time' }
        @{ L = 'R23  remote-access tunnel (canary_ngrok)'; Hit = @($hf | Where-Object { $_.Rule -match 'Remote-access tunnel' }).Count; Data = @($raRows | Where-Object { $_ -match 'canary_ngrok' }).Count + @($sysSvcRows | Where-Object { $_ -match 'canary_ngrok|canary_tunneld' }).Count; DataWhy = 'module 8.16 + processes missing (Standard preset required)' }
        @{ L = 'RA   service-install telemetry (7045 canary_tunneld)'; Hit = @($sysSvcRows | Where-Object { $_ -match 'canary_tunneld' }).Count; Data = @($sysSvcRows).Count; DataWhy = 'System log module (4.5) did not run - no 7045 rows' }
        @{ L = 'R26  SSH authorized_keys plant';   Hit = @($hf | Where-Object { $_.Rule -match 'authorized_keys' }).Count;                Data = @($raRows | Where-Object { $_ -match 'administrators_authorized_keys' }).Count; DataWhy = 'module 8.16 missing (Standard preset required)' }
        @{ L = 'R29  C2-style named pipe (canary_msagent_f00d)'; Hit = @($hf | Where-Object { $_.Rule -match 'C2-style named pipe' }).Count; Data = @($pipeRows | Where-Object { "$_" -match 'canary_msagent' }).Count; DataWhy = 'Sysmon EID 17/18 telemetry missing (no Sysmon, or config without PipeEvent blocks)' }
        @{ L = 'FOCUS auto-dossier (canary_ngrok)'; Hit = $focusFired;                                                                    Data = $focusData; DataWhy = $focusWhy }
    )
    foreach ($c in $checks) {
        $possible++
        if ($c.Hit -gt 0) { $score++; Write-Host ("    {0}  FIRED" -f $c.L) -ForegroundColor Green }
        elseif ($c.Data -gt 0) { Write-Host ("    {0}  MISS - data present (x{1}) but rule silent: file this" -f $c.L, $c.Data) -ForegroundColor Red }
        else { Write-Host ("    {0}  BLIND - no telemetry: {1}" -f $c.L, $c.DataWhy) -ForegroundColor Yellow }
    }
    Write-Host "    R25  RDP ServiceDll tamper  n/a - not planted (TermService tamper too invasive for a canary)" -ForegroundColor DarkGray
    Write-Host "    R28  cross-process injection  n/a - not planted (a real remote thread is too invasive for a canary)" -ForegroundColor DarkGray
    $verdict = $null
    try { $verdict = (Get-Content -LiteralPath (Join-Path $case.FullName 'verdict.json') -Raw | ConvertFrom-Json) } catch { }
    Write-Host ""
    Write-Host ("    Pipeline: {0}/{1} canary detections fired. Case verdict: {2}" -f $score, $possible, $(if ($verdict) { "$($verdict.Level) ($($verdict.ConfidencePercent)%)" })) -ForegroundColor $(if ($score -eq $possible) { 'Green' } elseif ($score -gt 0) { 'Yellow' } else { 'Red' })
    Write-Host "    Report: $((Join-Path $case.FullName 'report.html'))" -ForegroundColor Gray

    # ---- phase 4b: cross-host scorecard (target side) ----
    if ($bZip) {
        Write-Host ""
        Write-Host "  Cross-host scorecard - target case: $($bZip.BaseName)" -ForegroundColor Cyan
        $bDir = Join-Path ([IO.Path]::GetTempPath()) ("canary_b_" + (Get-Date -Format 'HHmmss'))
        try { Expand-Archive -LiteralPath $bZip.FullName -DestinationPath $bDir -Force } catch { Write-Host "    cannot extract target case: $($_.Exception.Message)" -ForegroundColor Red; $bDir = $null }
        if ($bDir) {
            $bcsv = Join-Path $bDir 'csv'
            $bAuth = @(Import-CsvFlatMapped $bcsv 'security_auth_events')
            $bShare = @(Import-CsvFlatMapped $bcsv 'security_share_access')
            $bSess = @(Import-CsvFlatMapped $bcsv 'session_activity')
            $bHf = @(Import-CsvFlatMapped $bcsv 'hunt_findings')
            $bAcct = if ($tCred) { ($tCred.UserName -split '\\')[-1] } else { 'canary_test' }
            $c4624 = @($bAuth | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -eq '3' -and "$($_.Account)" -match $bAcct }).Count
            $c5145 = @($bShare | Where-Object { $_ -match 'canary|C\$' }).Count
            $cJoin = @($bSess | Where-Object { $_ -match 'canary' }).Count
            $bChecks = @(
                @{ L = "B 4624 type-3 lateral logon ($bAcct)"; Hit = $c4624; Data = $c4624; DataWhy = 'network logon did not arrive (audit off on target, or SMB leg failed)' }
                @{ L = 'B 5145 share access captured';       Hit = $c5145; Data = $c5145;            DataWhy = 'Detailed File Share audit not active at touch time' }
                @{ L = 'B session attribution join';         Hit = $cJoin; Data = $cJoin;                DataWhy = 'no canary share/process activity to attribute' }
                @{ L = 'B R12  admin-share executable staging'; Hit = @($bHf | Where-Object { $_.Rule -match 'Admin-share' }).Count; Data = @($bShare | Where-Object { $_ -match 'canary_lateral\.exe' }).Count; DataWhy = '5145 rows missing (audit off) or write leg failed' }
            )
            $bs = 0
            foreach ($c in $bChecks) {
                if ($c.Hit -gt 0) { $bs++; Write-Host ("    {0}  FIRED" -f $c.L) -ForegroundColor Green }
                elseif ($c.Data -gt 0) { Write-Host ("    {0}  MISS - data present (x{1}) but rule silent: file this" -f $c.L, $c.Data) -ForegroundColor Red }
                else { Write-Host ("    {0}  BLIND - {1}" -f $c.L, $c.DataWhy) -ForegroundColor Yellow }
            }
            Write-Host ("    Cross-host: {0}/{1} fired. Fleet stitch check: .\Ophira.ps1 -Mode Analyze -AnalyzePath <collections>" -f $bs, $bChecks.Count) -ForegroundColor Gray
            Remove-Item $bDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # ---- cleanup + restore ----
    if ($ngProc -and -not $ngProc.HasExited) { $null = Stop-Process -Id $ngProc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $canExe, $canNgrok, "$env:TEMP\canary_out.txt", "$env:TEMP\canary_dl.bin" -Force -ErrorAction SilentlyContinue
    if ($akOk) {
        try {
            if ($akCreated) { Remove-Item -LiteralPath $akFile -Force -ErrorAction Stop }
            else { Set-Content -LiteralPath $akFile -Value $akPrev -ErrorAction Stop }
            Write-Host "  administrators_authorized_keys restored." -ForegroundColor DarkGray
        } catch { Write-Host "  authorized_keys restore FAILED: $akFile - remove the canary line manually" -ForegroundColor Yellow }
    }
    if (-not $KeepLogging -and $undo.Count -gt 0) {
        Write-Host "  Restoring original audit state..." -ForegroundColor DarkGray
        foreach ($u in $undo) {
            $p2 = $u -split '\|'
            switch ($p2[0]) {
                'auditpol' { $null = & auditpol.exe /set /subcategory:"$($p2[1])" /success:disable 2>&1 }
                'regdel' { Remove-ItemProperty -LiteralPath $p2[1] -Name $p2[2] -Force -ErrorAction SilentlyContinue }
                'regset' { Set-ItemProperty -LiteralPath $p2[1] -Name $p2[2] -Value $p2[3] -Force }
            }
        }
        Write-Host "  Restored. Re-run with -KeepLogging to leave logging enabled." -ForegroundColor DarkGray
    } elseif ($KeepLogging) { Write-Host "  Logging left enabled (-KeepLogging)." -ForegroundColor DarkGray }
    if ($Target -and @($bUndo).Count -gt 0 -and -not $KeepLogging) {
        try {
            $null = Invoke-Command @rc -ScriptBlock {
                param([string[]]$Undo)
                foreach ($u in $Undo) { $p2 = $u -split '\|'; $null = & auditpol.exe /set /subcategory:"$($p2[1])" /success:disable 2>&1 }
            } -ArgumentList (, @($bUndo))
            Write-Host "  Target audit state restored." -ForegroundColor DarkGray
        } catch { Write-Host "  Target audit restore failed ($($_.Exception.Message)) - restore manually on ${Target}:" -ForegroundColor Yellow; $bUndo | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
    }
    return $true
}

function Read-WizardLine {
    # Prompt helper for multi-step wizards: trims input; 'B'/'back' returns $null so the
    # wizard can redo the previous step (or cancel when on the first one).
    param([string]$Prompt)
    $v = (Read-Host "$Prompt  (B = back)").Trim()
    if ($v -match '^(?i)b(ack)?$') { return $null }
    return $v
}

function Invoke-DeployWizard {
    $kit = Get-KitRoot
    $hostsFile = Join-Path $kit 'hosts.txt'
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  PUSH & RUN ON REMOTE PCS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Pushes Ophira to remote PCs over WinRM, runs a collection there"
    Write-Host "  and pulls the result ZIPs back to this PC (or uploads to a share)."
    Write-Host "  Needs: WinRM enabled on targets + an admin account on them."
    Write-Host "  Answer 'B' at any question to go back and change the previous one."
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $defTargets = $script:CfgTargets
    if (-not $defTargets -and (Test-Path -LiteralPath $hostsFile)) { $defTargets = 'hosts.txt' }
    $defPreset = if ($script:CfgDeployPreset) { $script:CfgDeployPreset } else { 'Standard' }
    $pushDef = if ($script:CfgPushTools) { 'Y' } else { 'N' }
    $threads = if ($script:CfgThreads -gt 0) { $script:CfgThreads } else { $MaxThreads }
    $targets = @()
    $targetsIn = ''
    $cred = $null
    $preset = $defPreset
    $push = [bool]$script:CfgPushTools
    $shareIn = ''
    $advLogHours = -1
    $advLogWindow = ''
    $step = 1
    while ($true) {
        switch ($step) {
            1 {
                while ($true) {
                    $prompt = "  Target PCs (comma-separated, or a .txt file path)$(if ($defTargets) { " [$defTargets]" })"
                    $targetsIn = Read-WizardLine $prompt
                    if ($null -eq $targetsIn) { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }
                    if (-not $targetsIn -and $defTargets) { $targetsIn = $defTargets.Trim() }
                    if (-not $targetsIn) { Write-Host "  please enter at least one target" -ForegroundColor Red; continue }
                    if ($targetsIn -match '\.txt$') {
                        $tf = $null
                        if (Test-Path -LiteralPath $targetsIn) { $tf = $targetsIn }
                        elseif (Test-Path -LiteralPath (Join-Path $kit $targetsIn)) { $tf = Join-Path $kit $targetsIn }
                        if ($tf) {
                            $targets = @(Get-Content -LiteralPath $tf | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
                            if ($targets.Count -eq 0) { Write-Host "  file has no host entries: $tf" -ForegroundColor Red }
                        } else { Write-Host "  file not found: $targetsIn" -ForegroundColor Red }
                    } else {
                        $targets = @($targetsIn -split '[,;\s]+' | Where-Object { $_ })
                    }
                    if ($targets.Count -gt 0) { break }
                }
                $step = 2
            }
            2 {
                Write-Host ""
                $cIn = Read-WizardLine "  Credentials: ENTER = your current account ($env:USERDOMAIN\$env:USERNAME), or type a username"
                if ($null -eq $cIn) { $step = 1; continue }
                $cred = $null
                if ($cIn) {
                    $cred = Get-Credential -UserName $cIn -Message "Password for remote PCs"
                    if (-not $cred) { Write-Host "  no credentials entered - using current account" -ForegroundColor Yellow; $cred = $null }
                }
                $step = 3
            }
            3 {
                $pIn = Read-WizardLine "  Collection depth: 1=Quick (~1-2 min/PC) or 2=Standard (~3-5 min/PC) [$defPreset]"
                if ($null -eq $pIn) { $step = 2; continue }
                $preset = $defPreset
                if ($pIn -match '^1' -or $pIn -match '^q(uick)?$') { $preset = 'Quick' }
                elseif ($pIn -match '^2' -or $pIn -match '^s(tandard)?$') { $preset = 'Standard' }
                $step = 4
            }
            4 {
                $p2In = Read-WizardLine "  Also push hayabusa for on-host Sigma detection (removed after run)? [y/N] (default $pushDef)"
                if ($null -eq $p2In) { $step = 3; continue }
                $push = if ($p2In) { $p2In -match '^y' } else { [bool]$script:CfgPushTools }
                $step = 5
            }
            5 {
                if ($script:CfgDeployShare) {
                    $shareIn = Read-WizardLine "  Upload results to share (UNC path, 'none' = pull to collections\, ENTER = $($script:CfgDeployShare))"
                    if ($null -eq $shareIn) { $step = 4; continue }
                    if (-not $shareIn) { $shareIn = $script:CfgDeployShare }
                    if ($shareIn -ieq 'none') { $shareIn = '' }
                } else {
                    $shareIn = Read-WizardLine "  Upload results to a central share instead of pulling back? (UNC path, ENTER = pull to collections\)"
                    if ($null -eq $shareIn) { $step = 4; continue }
                }
                if ($shareIn -and -not (Test-Path $shareIn)) {
                    Write-Host "  WARNING: share not reachable right now ($shareIn) - will retry during run" -ForegroundColor Yellow
                }
                $step = 6
            }
            6 {
                $advLogHours = -1
                $advLogWindow = ''
                $advIn = Read-WizardLine "  Advanced options (Full depth, log window, parallelism)? [y/N]"
                if ($null -eq $advIn) { $step = 5; continue }
                if ($advIn -notmatch '^y') { $step = 7; continue }
                $dIn = Read-WizardLine "  Depth: 1=Quick  2=Standard  3=Full - heaviest, includes SRUM etc. [current: $preset]"
                if ($null -eq $dIn) { $step = 5; continue }
                if ($dIn -match '^3' -or $dIn -match '^f(ull)?$') { $preset = 'Full' }
                $lhIn = Read-WizardLine "  Log analysis window (168 = hours, 30d, 3m, 0 = all, or start date 2026-09-01) [ENTER = 168 = 7 days]"
                if ($null -eq $lhIn) { $step = 5; continue }
                if ($lhIn) {
                    if ($lhIn -match '^\d+$') { $advLogHours = [int]$lhIn }
                    elseif ($null -eq (ConvertTo-LogStart $lhIn)) { Write-Host "  window not understood - keeping the default 7 days" -ForegroundColor Yellow }
                    else { $advLogWindow = $lhIn }
                }
                $thIn = Read-WizardLine "  Hosts to process in parallel (ENTER = current setting)"
                if ($null -eq $thIn) { $step = 5; continue }
                if ($thIn -match '^\d+$' -and [int]$thIn -gt 0) { $threads = [int]$thIn }
                $step = 7
            }
            7 {
                $shown = ($targets | Select-Object -First 5) -join ', '
                if ($targets.Count -gt 5) { $shown += ", ...($($targets.Count) total)" }
                $credNote = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current)" }
                Write-Host ""
                Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
                Write-Host "  Ready to deploy. Please confirm:" -ForegroundColor White
                Write-Host "    Targets   : $shown"
                Write-Host "    Depth     : $preset"
                if ($advLogHours -ge 0) { Write-Host "    Log window: $(if ($advLogHours -eq 0) { 'all available' } else { "$advLogHours hours" })" }
                if ($advLogWindow) { Write-Host "    Log window: from $advLogWindow" }
                Write-Host "    Account   : $credNote"
                Write-Host "    hayabusa  : $(if ($push) { 'push + run + remove' } else { 'not pushed' })"
                Write-Host "    Results   : $(if ($shareIn) { "upload to $shareIn" } else { 'pull to collections\' })"
                if ($CaseID) { Write-Host "    Case ID   : $CaseID" }
                Write-Host "    Parallel  : $threads hosts at once"
                Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
                $go = Read-WizardLine "  Start? [Y/n]"
                if ($null -eq $go) { $step = 6; continue }
                if ($go -match '^[Nn]') { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }
                $step = 8
            }
            8 {
                Invoke-DeployMode -Targets $targets -DeployPreset $preset -Cred $cred -DeployCaseID $CaseID -DeploySharePath $shareIn -Threads $threads -PushBin $push -DeployLogHours $advLogHours -DeployLogWindow $advLogWindow
                $rem = Read-WizardLine "  Remember these answers for next time? [y/N]"
                if ($rem -match '^y') {
                    $vals = @{ TARGETS = $targetsIn; PRESET = $preset; PUSHTOOLS = $(if ($push) { 'yes' } else { 'no' }) }
                    if ($shareIn) { $vals['DEPLOYSHARE'] = $shareIn }
                    if (Save-OphiraConfig -Values $vals) { Write-Host "  Saved to ophira.config.txt" -ForegroundColor Green }
                }
                return
            }
        }
    }
}

function Invoke-AnalyzeWizard {
    $kit = Get-KitRoot
    $def = Join-Path $kit 'collections'
    if (-not (Test-Path -LiteralPath $def)) { $def = $kit }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  ANALYZE COLLECTED RESULTS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Merges OPHIRA_*.zip case files in a folder into one fleet report"
    Write-Host "  (deploy pulls results into 'collections' by default)."
    Write-Host "  A single case folder/zip is finished automatically (parse + regenerate)."
    Write-Host "================================================================" -ForegroundColor Cyan
    while ($true) {
        $pIn = (Read-Host "  Folder with case ZIPs [$def]").Trim()
        $path = if ($pIn) { $pIn } else { $def }
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Host "  not found: $path" -ForegroundColor Red
            $retry = (Read-Host "  Enter another path, or press ENTER to cancel").Trim()
            if (-not $retry) { return }
            $def = $retry
            continue
        }
        # v2.40 auto-parse: one case (a case.json folder, a single zip, or a folder with exactly
        # one zip) goes straight to the parse flow - it completes what the endpoint couldn't
        # finish and regenerates every derived artifact (report, verdict, focus).
        $single = $null
        if ((Test-Path -LiteralPath $path -PathType Leaf) -and $path -match '\.zip$') { $single = $path }
        elseif (Test-Path -LiteralPath (Join-Path $path 'case.json')) { $single = $path }
        else {
            $zips = @(Get-ChildItem -LiteralPath $path -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue)
            if ($zips.Count -eq 1) { $single = $zips[0].FullName }
        }
        if ($single) {
            Write-Host "  Single case detected -> finishing it (analyst-side parse + regenerate)" -ForegroundColor Cyan
            Invoke-ParseMode -Path $single | Out-Null
            return
        }
        Invoke-AnalyzeMode -Path $path -HayabusaExe $HayabusaPath
        return
    }
}

# v2.74 (Task 15): [O] on the done screens - one keypress opens this case's report.html.
# Shared by the Parse done screen and the collect SimpleUI/standard done screens. Prompted
# only when a human is at the console (-NoMenu/unattended flows skip it); a missing report
# answers honestly instead of opening nothing. Uses the existing ReadKey try/catch pattern,
# so a redirected-input host degrades to a no-op.
$script:OfferOpenReport = {
    param([string]$Dir, [bool]$Prompt)
    if (-not $Prompt) { return }
    $rep = Join-Path $Dir 'report.html'
    Write-Host ""
    Write-Host "  [O] Open report.html  (any other key = continue)" -ForegroundColor Cyan
    $k = $null
    try { $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character } catch { return }
    if ("$k" -match '^[Oo]$') {
        if (Test-Path -LiteralPath $rep) {
            try { Invoke-Item -LiteralPath $rep } catch { Write-Host "  could not open report.html: $($_.Exception.Message)" -ForegroundColor Yellow }
        } else {
            Write-Host "  no report.html in $Dir - run -Mode Parse to build it" -ForegroundColor Yellow
        }
    }
}

$bareLaunch = ($Mode -eq 'Collect' -and -not $PSBoundParameters.ContainsKey('Mode') -and -not $NoMenu -and -not $script:SimpleUI)
if ($bareLaunch -and [Environment]::UserInteractive) {
    $front = Show-RoleGate
    if ($front -eq 'run') {
        $script:SimpleUI = $true
        $script:ExtraRelaunchArgs += @('-SimpleUI')
    } else {
        while ($true) {
            $chosenTask = Show-TaskMenu
            if (-not $chosenTask) { exit 0 }
            if ($chosenTask -eq 'Collect') {
                $script:ExtraRelaunchArgs += @('-Mode', 'Collect')
                break
            }
            switch ($chosenTask) {
                'Deploy' { Invoke-DeployWizard }
                'Analyze' { Invoke-AnalyzeWizard }
                'Setup' { Invoke-SetupWizard }
        'UpdateRules' { if (-not (Invoke-UpdateRulesMode)) { exit 1 } }
                'Tune' { Invoke-TuneMode | Out-Null }
                'Parse' { Invoke-ParseMode | Out-Null }
                'Focus' { Invoke-FocusEngine | Out-Null }
                'Process' {
                    # v2.68 (B16): menu arm of the -Mode Process CLI path - mandatory non-empty
                    # process prompt, then the SAME invocation the CLI mode switch uses
                    # (Invoke-FocusEngine -Path $ParsePath -Indicator <name>)
                    $pn = "$ProcessName"
                    while (-not $pn) { $pn = (Read-Host '  Process name / PID / path / hash for the dossier (e.g. certutil.exe)').Trim() }
                    Invoke-FocusEngine -Path $ParsePath -Indicator $pn | Out-Null
                }
                'Timeline' { Invoke-TimelineMode | Out-Null }
                'Watch' { Invoke-WatchMode | Out-Null }
                'Canary' { Invoke-CanaryMode -KeepLogging:$KeepLogging -Target $CanaryTarget -TargetUser $CanaryTargetUser | Out-Null }
                'Links' { Show-ToolLinks }
                'Help' { Show-ScriptHelp }
            }
            Write-Host ""
            Write-Host "Press any key to return to the menu..." -ForegroundColor DarkGray
            try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
        }
    }
}

if ($Mode -ne 'Collect') {
    switch ($Mode) {
        'Links' { Show-ToolLinks }
        'Setup' { Invoke-SetupMode -Wanted $SetupTools }
        'Analyze' { Invoke-AnalyzeMode -Path $AnalyzePath -HayabusaExe $HayabusaPath }
        'Deploy' {
            if ($TargetsFile -and (Test-Path -LiteralPath $TargetsFile)) {
                $ComputerName += @(Get-Content -LiteralPath $TargetsFile | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
            }
            if (-not $ComputerName) { Write-Host "-ComputerName or -TargetsFile required for Deploy mode" -ForegroundColor Red; exit 1 }
            Invoke-DeployMode -Targets $ComputerName -DeployPreset $Preset -Cred $Credential -DeployCaseID $CaseID -DeploySharePath $SharePath -Threads $MaxThreads -PushBin ([bool]$PushTools) -DeployLogHours $LogHours -DeployLogWindow $LogWindow
        }
        'UpdateRules' { Invoke-UpdateRulesMode }
        'Tune' { Invoke-TuneMode | Out-Null }
        'Parse' { Invoke-ParseMode -Path $ParsePath | Out-Null }
        'Process' { Invoke-FocusEngine -Path $ParsePath -Indicator $ProcessName -After $After -Before $Before | Out-Null }
        'Focus' { Invoke-FocusEngine -Path $ParsePath -Indicator $ProcessName -After $After -Before $Before | Out-Null }
        'Timeline' { Invoke-TimelineMode -Path $ParsePath -Start $TimelineStart -End $TimelineEnd | Out-Null }
        'Watch' { Invoke-WatchMode -Interval $WatchInterval | Out-Null }
        'SeedIocs' { Invoke-SeedIocsMode -Value $SeedValue | Out-Null }
        'Canary' { Invoke-CanaryMode -KeepLogging:$KeepLogging -Target $CanaryTarget -TargetUser $CanaryTargetUser | Out-Null }
    }
    # v2.51: opt-in verdict exit codes (-ExitVerdict): Parse/Collect regenerate the verdict in-session
    if ($ExitVerdict -and $script:Verdict) {
        $rank = 0
        try { $rank = [int]$script:Verdict.LevelRank } catch { }
        if ($rank -ge 2) { exit $rank }
    }
    exit 0
}

if (-not (Test-IsAdmin) -and -not $NoElevate) {
    Write-Host "[!] Not elevated. Requesting administrator rights..." -ForegroundColor Yellow
    $argStr = Get-ArgString
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $argStr"
        exit
    } catch {
        Write-Host "[!] Elevation declined. Continuing with LIMITED access (many modules will fail)." -ForegroundColor Red
        try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    }
}

$Computer = $env:COMPUTERNAME
$StartTime = Get-Date
$Stamp = $StartTime.ToString('yyyyMMdd_HHmmss')
$BaseDir = if ($OutputPath) { $OutputPath } else { Get-KitRoot }
$CaseName = "OPHIRA_${Computer}_${Stamp}"
$CaseDir = Join-Path $BaseDir $CaseName
$CsvDir = Join-Path $CaseDir 'csv'
$RawDir = Join-Path $CaseDir 'raw'
$MemDir = Join-Path $CaseDir 'memory'
$CaseLog = Join-Path $CaseDir 'collection.log'

New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$script:FlashLines = New-Object System.Collections.Generic.List[string]
$script:CurrentCaseID = $CaseID
$script:CurrentAnalyst = $Analyst

$IsAdmin = Test-IsAdmin
$Sysmon = Get-SysmonState
if (-not $script:SimpleUI) { Clear-Host }
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   ___  ___  ___ _  _ ___ _____ _   ___ ___   " -ForegroundColor Cyan
Write-Host "  | _ \/ _ \| __| \| | _ \_   _/_\ | _ \ _ \ " -ForegroundColor Cyan
Write-Host "  |  _/ (_) | _|| .\` |  _/ | |/ _ \|   /  _/" -ForegroundColor Cyan
Write-Host "  |_|  \___/|___|_|\_|_|   |_/_/ \_\_|_\_|_\ " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Ophira v$ScriptVersion  -  single-script Windows IR toolkit" -ForegroundColor White
Write-Host "  READ-ONLY: collects evidence, never changes the system" -ForegroundColor DarkGray
Write-Host "  Modes: -Mode Collect | Deploy | Analyze | Setup | Links" -ForegroundColor DarkGray
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  Host      : $Computer"
Write-Host "  OS User   : $env:USERNAME"
    Write-Host "  Elevated  : $(if ($IsAdmin) { 'YES - full access' } else { 'NO - LIMITED (many modules will fail)' })" -ForegroundColor $(if ($IsAdmin) { 'Green' } else { 'Red' })
    Write-Host "  Sysmon    : $(if ($Sysmon) { 'DETECTED - logs will be collected' } else { 'not present' })" -ForegroundColor $(if ($Sysmon) { 'Green' } else { 'DarkGray' })
Write-Host "  Output    : $CaseDir"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-CaseLog "Ophira v$ScriptVersion started on $Computer by $env:USERNAME (admin=$IsAdmin, sysmon=$Sysmon)" 'Gray' -NoConsole

Invoke-FlashTriage

$selection = Get-PresetSelection -P $Preset
if ($NoMenu -or $script:SimpleUI) {
    if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host "" }
    if ($script:SimpleUI) {
        Write-Host "  First quick check done - details are saved for the IR team." -ForegroundColor Cyan
        Write-Host "  Now collecting the full evidence. This usually takes 3-5 minutes." -ForegroundColor Cyan
        Write-Host "  Please DO NOT close this window until it says DONE." -ForegroundColor Yellow
        Write-Host ""
    } else {
        if ($script:HostRole -ne 'Workstation') { Write-CaseLog "Host role detected: $script:HostRole (role telemetry enabled in this preset)" 'Cyan' }
        Write-CaseLog "NoMenu mode: running preset '$Preset' ($(@($selection.Values | Where-Object { $_ }).Count) modules)" 'Cyan'
    }
    if ($Preset -eq 'Flash') {
        Write-CaseLog "Flash-only preset: skipping deep modules" 'Gray'
        $selection = @{}
    }
} else {
    $sel = Show-Menu -Selection $selection
    if (-not $sel) {
        Write-Host "Quit before collection. Flash summary saved to:" -ForegroundColor Yellow
        Write-Host "  $CaseDir\flash_summary.txt"
        exit 0
    }
    $selection = $sel
}

if (@($selection.Values | Where-Object { $_ }).Count -gt 0) {
    Invoke-SelectedModules -Selection $selection
}

New-Package

if ($script:SimpleUI) {
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "     DONE! Everything was collected successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "     Checked: $(Get-LogRangeText)" -ForegroundColor Gray
    if ($script:Verdict) {
        $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
        Write-Host "     RESULT: $($script:Verdict.OwnerLine)" $vColor
        Write-Host "     This is an automated first check - please send the file below" -ForegroundColor DarkGray
        Write-Host "     to the IR team so they can confirm it." -ForegroundColor DarkGray
        Write-Host ""
    }
    if ($script:DeltaCount -gt 0) {
        Write-Host "     NOTE: $script:DeltaCount NEW items appeared since the last check." -ForegroundColor Yellow
        Write-Host "     Mention this to the IR team - they will see the details." -ForegroundColor Yellow
        Write-Host ""
    }
    if ($script:ShareOk) {
        Write-Host "     Your results were uploaded automatically." -ForegroundColor Green
        Write-Host "     Nothing left to do - you can close this window." -ForegroundColor Green
    } else {
        Write-Host "     Please send this file to the IR team:" -ForegroundColor White
        Write-Host ""
        Write-Host "     $script:FinalZipPath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "     The file location is COPIED to your clipboard (Ctrl+V to paste)." -ForegroundColor White
        Write-Host "     A folder window has opened with the file already selected." -ForegroundColor White
        Write-Host "     If some items failed, send the file anyway - it holds everything" -ForegroundColor DarkGray
        Write-Host "     that could be collected." -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor Green
    try { Set-Clipboard -Value $script:FinalZipPath } catch { }
    if ($script:FinalZipPath -and (Test-Path -LiteralPath $script:FinalZipPath)) {
        try { Start-Process explorer.exe -ArgumentList "/select,`"$($script:FinalZipPath)`"" } catch { }
    }
    # v2.74: [O] opens the case report - the DONE screen now waits for one keypress
    # (v2.75 fix: -SimpleUI -NoMenu is unattended and must never block on the keypress)
    & $script:OfferOpenReport -Dir $CaseDir -Prompt:(-not $script:NoMenu)
} elseif (-not $NoMenu) {
    # v2.74: [O] opens the case report before the close key
    & $script:OfferOpenReport -Dir $CaseDir -Prompt:$true
    Write-Host ""
    Write-Host "Press any key to close..." -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}

# v2.51: opt-in verdict exit codes for fleet scripting (-ExitVerdict):
# 0 = clean/inconclusive, 2 = SUSPICIOUS, 3 = LIKELY COMPROMISED, 4 = COMPROMISED
if ($ExitVerdict -and $script:Verdict) {
    $rank = 0
    try { $rank = [int]$script:Verdict.LevelRank } catch { }
    if ($rank -ge 2) { exit $rank }
}
exit 0







