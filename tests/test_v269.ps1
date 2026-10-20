# test_v269.ps1 - v2.69 F1: full RUN detail on both screens, always on.
#   Write-RunDetail prints ONE line per finished module (id + name, key artifact + row count,
#   elapsed) on BOTH screens - the SimpleUI front-screen (alongside the friendly step headers,
#   which stay) and the standard menu run (added AFTER the run; the pre-run [x/y] progress line
#   stays as instant feedback). Data comes from Save-Rows recording every artifact save into
#   $script:SavedArtifacts (seeded fresh in worker runspaces by New-WorkerPreamble, cleared per
#   module by the inline dispatcher); pooled workers return it in an extended result-record
#   field 'Saved', so the pooled dispatcher renders REAL artifact+row numbers too.
#   Gating: these lines ARE the run feedback, so they print at Normal AND Verbose and are NOT
#   SimpleUI-gated (SimpleUI's whole console IS run feedback) - but -LogLevel Quiet still
#   silences them like the rest of the console noise. Console-only: the case log contract is
#   unchanged (log keeps its own Write-CaseLog records).
#   v2.69 Task 2 (F2) appended below as PART E: the help section. One source of truth - a
#   comment-based help block directly above [CmdletBinding()] (.SYNOPSIS/.DESCRIPTION, a
#   .PARAMETER for EVERY param, >= 8 .EXAMPLE flows); -Mode Help renders it via Get-Help
#   against the script file and exits 0 BEFORE config load / elevation / case context;
#   the menu gains [H] Help which renders the same and returns to the menu (never exits).
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# shadow Write-Host BEFORE extracting, so captured function bodies bind to it at call time
# (test_loglevel pattern) - Write-RunDetail writes via Write-Host, we capture the line
$script:Console = New-Object System.Collections.Generic.List[string]
function Write-Host {
    param([string]$Object, [object]$ForegroundColor, [object]$BackgroundColor, [switch]$NoNewline)
    $script:Console.Add("$Object")
    if ($null -ne $ForegroundColor) { Microsoft.PowerShell.Utility\Write-Host $Object -ForegroundColor $ForegroundColor }
    else { Microsoft.PowerShell.Utility\Write-Host $Object }
}
function Reset-Console { $script:Console = New-Object System.Collections.Generic.List[string] }
function ConsoleHas([string]$needle) { @($script:Console | Where-Object { $_ -like "*$needle*" }).Count -gt 0 }
function ConsoleLinesMatching([string]$pattern) { @($script:Console | Where-Object { $_ -match $pattern }) }

# ============================================================================
# PART A - Write-RunDetail: line format + degradation + gating (behavioral)
# ============================================================================
$mWrd = [regex]::Match($src, "(?s)function Write-RunDetail \{.*?\r?\n\}")
Check "F1: Write-RunDetail extracted (top-level, column-0 close)" $mWrd.Success
$csi = [regex]::Match($src, "(?s)function ConvertTo-SafeInt \{.*?\r?\n\}")
if (-not $csi.Success) { throw "extract failed: ConvertTo-SafeInt" }
if ($mWrd.Success) { Invoke-Expression ($csi.Value + "`r`n" + $mWrd.Value) }

$script:SimpleUI = $false
$script:Verbosity = 1

# A1: single-artifact shape - the owner's example line
Reset-Console
Write-RunDetail -Id '2.3' -Name 'Scheduled tasks' -Seconds 1.8 -Saved @([pscustomobject]@{ Path = 'csv\persistence\scheduled_tasks.csv'; Rows = 214 })
$a1 = @(ConsoleLinesMatching 'scheduled_tasks\.csv')
Check "F1: single artifact -> exactly one console line" ($a1.Count -eq 1)
if ($a1.Count -eq 1) {
    Check "F1: line = [id] name + dot leader + csv path + rows + elapsed" ($a1[0] -match '^\s*\[2\.3\] Scheduled tasks \.+ csv\\persistence\\scheduled_tasks\.csv 214 rows 1\.8s$')
} else { Check "F1: line = [id] name + dot leader + csv path + rows + elapsed" $false }

# A2: multi-artifact - honest totals, one line
Reset-Console
Write-RunDetail -Id '1.4' -Name 'DNS cache + ARP table' -Seconds 0.3 -Saved @(
    [pscustomobject]@{ Path = 'csv\volatile\dns_cache.csv'; Rows = 42 },
    [pscustomobject]@{ Path = 'csv\volatile\arp_table.csv'; Rows = 0 },
    [pscustomobject]@{ Path = 'csv\volatile\logon_sessions.csv'; Rows = 218 })
$a2 = @(ConsoleLinesMatching '3 csv, 260 rows')
Check "F1: multi artifact -> 'N csv, M rows' total line" ($a2.Count -eq 1)
Check "F1: multi line still carries id + elapsed" ($a2.Count -eq 1 -and $a2[0] -match '\[1\.4\]' -and $a2[0] -match '0\.3s$')

# A3: nothing saved - degrade honestly, never invent
Reset-Console
Write-RunDetail -Id '8.1' -Name 'Host posture' -Seconds 2.0 -Saved @()
$a3 = @(ConsoleLinesMatching 'no csv artifacts')
Check "F1: no artifacts -> 'no csv artifacts' + elapsed still shown" ($a3.Count -eq 1 -and $a3[0] -match '2\.0s$')

# A4: failed module - ERROR replaces the artifact numbers
Reset-Console
Write-RunDetail -Id '7.1' -Name 'Memory capture' -Seconds 3.2 -ErrMsg 'winpmem not found'
$a4 = @(ConsoleLinesMatching 'ERROR: winpmem not found')
Check "F1: error line carries ERROR + message + elapsed" ($a4.Count -eq 1 -and $a4[0] -match '3\.2s$')
Check "F1: error line carries no fake row counts" (-not ($a4[0] -match 'rows'))

# A5: a failed save degrades to FAILED (Rows = -1 sentinel), not a fake 0
Reset-Console
Write-RunDetail -Id '4.2' -Name 'Yara' -Seconds 9.9 -Saved @([pscustomobject]@{ Path = 'csv\logs\yara_hits.csv'; Rows = -1 })
$a5 = @(ConsoleLinesMatching 'yara_hits\.csv FAILED')
Check "F1: failed save -> 'FAILED' wording" ($a5.Count -eq 1)
Check "F1: failed save shows no row count" ($a5.Count -eq 1 -and -not ($a5[0] -match '\d+ rows'))

# A6: long names truncate, never wrap the layout
Reset-Console
$longName = 'S' * 60
Write-RunDetail -Id '9.9' -Name $longName -Seconds 1.0 -Saved @()
Check "F1: long name truncated with '...'" (ConsoleHas ('S' * 35 + '...') -and -not (ConsoleHas ('S' * 36)))
Check "F1: truncated line still single line with id + artifact" (@(ConsoleLinesMatching "^\s*\[9\.9\] S+").Count -eq 1)

# A7: gating - Quiet silences; Normal and Verbose print; SimpleUI does NOT gate
$script:Verbosity = 0; Reset-Console
Write-RunDetail -Id '2.3' -Name 'Scheduled tasks' -Seconds 1.0 -Saved @()
Check "F1 quiet: console silent" (@($script:Console).Count -eq 0)
$script:Verbosity = 2; Reset-Console
Write-RunDetail -Id '2.3' -Name 'Scheduled tasks' -Seconds 1.0 -Saved @()
Check "F1 verbose: console shows the line" (@($script:Console).Count -eq 1)
$script:Verbosity = 1; $script:SimpleUI = $true; Reset-Console
Write-RunDetail -Id '2.3' -Name 'Scheduled tasks' -Seconds 1.0 -Saved @()
Check "F1 simpleui: detail line prints on the front screen (NOT SimpleUI-gated)" (@($script:Console).Count -eq 1)
$script:SimpleUI = $false

# ============================================================================
# PART B - Save-Rows records every save into $script:SavedArtifacts (behavioral)
# ============================================================================
foreach ($n in 'Get-CaseCsvPath', 'Get-CaseCsvFullPath', 'Save-Rows') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression $m.Value
}
$ccm = [regex]::Match($src, "(?s)\`$script:CsvCatMap = @\{.*?\r?\n\}")
if ($ccm.Success) { Invoke-Expression $ccm.Value }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole) }  # console+file stubbed; only the recording is under test

$CsvDir = Join-Path $env:TEMP ("ophira_v269_csv_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$csvDirB = $CsvDir
$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]

Save-Rows -Name 'scheduled_tasks' -Rows @([pscustomobject]@{ TaskName = 'a' }, [pscustomobject]@{ TaskName = 'b' })
Check "F1 save-rows: success records mapped relative path + row count" ($script:SavedArtifacts.Count -eq 1 -and $script:SavedArtifacts[0].Path -eq 'csv\persistence\scheduled_tasks.csv' -and $script:SavedArtifacts[0].Rows -eq 2)

Save-Rows -Name 'dns_cache' -Rows @()
Check "F1 save-rows: empty marker recorded as 0 rows" ($script:SavedArtifacts.Count -eq 2 -and $script:SavedArtifacts[1].Rows -eq 0)

# per-module reset contract: the dispatcher clears before each module
$script:SavedArtifacts.Clear()
Check "F1 save-rows: Clear() resets accumulation between modules" ($script:SavedArtifacts.Count -eq 0)

# ============================================================================
# PART C - pooled worker path: the result record carries Saved for real (v2.58 smoke pattern)
# ============================================================================
foreach ($n in 'Get-KitRoot', 'New-WorkerPreamble', 'Test-IsAdmin') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if ($m.Success) { Invoke-Expression $m.Value }
}
$sf = [regex]::Match($src, "(?s)\`$script:SharedFunctions = @\(.*?\r?\n\)").Value
Invoke-Expression $sf
foreach ($fn in $script:SharedFunctions) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if ($m.Success) { Invoke-Expression $m.Value }
}
$wt = [regex]::Match($src, "(?s)\`$script:ModuleWorkerText = @'.*?'@").Value
Invoke-Expression $wt
$CaseDir = Join-Path $env:TEMP ("ophira_v269_worker_" + (Get-Date -Format 'HHmmss'))
$CsvDir = Join-Path $CaseDir 'csv'; $RawDir = Join-Path $CaseDir 'raw'; $MemDir = Join-Path $CaseDir 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir, $MemDir -Force | Out-Null
$Computer = 'V269'; $Preset = 'Standard'; $global:LogHours = 168; $global:CaseLog = Join-Path $CaseDir 'c.log'
$fake = @{
    Id = 'T1'; Name = 'worker-detail-smoke'
    RunText = @"
Save-Rows -Name 'scheduled_tasks' -Rows @([pscustomobject]@{ TaskName = 'a' }, [pscustomobject]@{ TaskName = 'b' })
Save-Rows -Name 'dns_cache' -Rows @()
"@
}
$ps = [powershell]::Create()
$null = $ps.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog (Join-Path $CaseDir 'w.log'))).AddArgument($fake)
$r = $ps.Invoke() | Select-Object -First 1
$ps.Dispose()
Check "F1 worker: module ran without error" ($r -and -not $r.Error)
Check "F1 worker: record keeps Id/Name/Seconds/Error shape" ($r -and $r.Id -eq 'T1' -and $r.Name -eq 'worker-detail-smoke' -and $null -ne $r.Seconds -and $null -ne $r.Error)
Check "F1 worker: record carries Saved with both artifacts" ($r -and @($r.Saved).Count -eq 2)
if ($r -and @($r.Saved).Count -eq 2) {
    Check "F1 worker: Saved[0] = mapped path + real row count" ($r.Saved[0].Path -eq 'csv\persistence\scheduled_tasks.csv' -and $r.Saved[0].Rows -eq 2)
    Check "F1 worker: Saved[1] = empty save as 0 rows" ($r.Saved[1].Rows -eq 0)
} else { Check "F1 worker: Saved[0] = mapped path + real row count" $false; Check "F1 worker: Saved[1] = empty save as 0 rows" $false }
Remove-Item -LiteralPath $CaseDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $csvDirB -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================================
# PART D - wiring pins (source scan)
# ============================================================================
Check "F1 wiring: Write-RunDetail Quiet gate present" ($src -match [regex]::Escape('if ($script:Verbosity -lt 1) { return }'))
Check "F1 wiring: SavedArtifacts initialized once + seeded once in preamble (exactly 2)" ([regex]::Matches($src, [regex]::Escape('$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]')).Count -eq 2)
Check "F1 wiring: Save-Rows records all three save outcomes (success/empty/failed)" ([regex]::Matches($src, [regex]::Escape('SavedArtifacts.Add')).Count -eq 3)
Check "F1 wiring: worker record carries Saved from ToArray()" ($src -match [regex]::Escape('$script:SavedArtifacts.ToArray()'))
Check "F1 wiring: inline dispatcher clears per module" ([regex]::Matches($src, [regex]::Escape('$script:SavedArtifacts.Clear()')).Count -eq 1)
Check "F1 wiring: inline dispatcher prints detail after success AND error" ([regex]::Matches($src, [regex]::Escape('Write-RunDetail -Id $m.Id')).Count -eq 2)
Check "F1 wiring: pooled dispatchers (phase B + C) print detail" ([regex]::Matches($src, [regex]::Escape('Write-RunDetail -Id $x.Id')).Count -eq 2)
Check "F1 wiring: pooled detail passes the worker's Saved field" ([regex]::Matches($src, [regex]::Escape('-Saved $x.Saved')).Count -eq 2)
Check "F1 wiring: pre-run [x/y] progress line kept (log contract + instant feedback)" ($src -match [regex]::Escape('Write-CaseLog ("[{0}/{1}] Module {2}: {3}"'))
Check "F1 wiring: SimpleUI friendly step headers kept" ($src -match [regex]::Escape('Step {0}/{1}: {2}...'))
$sfBlock = [regex]::Match($src, "(?s)\`$script:SharedFunctions = @\(.*?\r?\n\)").Value
Check "F1 wiring: Write-RunDetail NOT whitelisted for workers (controller-side only)" (-not $sfBlock.Contains('Write-RunDetail'))
Check "F1 wiring: SimpleUI branch still runs detail via shared runInline" ([regex]::Matches($src, [regex]::Escape('foreach ($m in ($selected | Where-Object { $_.Cat -eq $cat })) { & $runInline $m }')).Count -eq 1)

# ============================================================================
# PART E - F2: help section (v2.69 Task 2)
#   The user-visible complaint was "help is only the flags - no description,
#   no example commands, no when-to-use". Fix has ONE source of truth: the
#   comment-based help block above the param block, rendered by Get-Help.
# ============================================================================

# E1: the help block sits immediately above [CmdletBinding()] with all sections
$hBlocks = [regex]::Matches($src, '(?s)<#.*?#>')
$helpBlock = $null
foreach ($b in $hBlocks) {
    $after = $src.Substring([Math]::Min($b.Index + $b.Length, $src.Length))
    if ($after -match '^\s*\[CmdletBinding\(\)\]') { $helpBlock = $b.Value; break }
}
Check "F2: comment-based help block sits immediately above [CmdletBinding()]" ($null -ne $helpBlock)
if ($helpBlock) {
    Check "F2: .SYNOPSIS present" ($helpBlock -match '(?m)^\.SYNOPSIS')
    Check "F2: .DESCRIPTION present" ($helpBlock -match '(?m)^\.DESCRIPTION')
    $pBlock = [regex]::Match($src, '(?s)\[CmdletBinding\(\)\]\s*param\((.*?)\r?\n\)').Groups[1].Value
    $paramNames = @([regex]::Matches($pBlock, '\$(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $missing = @($paramNames | Where-Object { $helpBlock -notmatch "\.PARAMETER\s+$($_)\b" })
    Check "F2: .PARAMETER for every param ($($paramNames.Count) params)" ($missing.Count -eq 0)
    if ($missing.Count -gt 0) { Write-Host "       missing: $($missing -join ', ')" -ForegroundColor DarkGray }
    $exCount = [regex]::Matches($helpBlock, '(?m)^\.EXAMPLE').Count
    Check "F2: >= 8 .EXAMPLE flows (got $exCount)" ($exCount -ge 8)
} else {
    Check "F2: .SYNOPSIS present" $false
    Check "F2: .DESCRIPTION present" $false
    Check "F2: .PARAMETER for every param" $false
    Check "F2: >= 8 .EXAMPLE flows" $false
}

# E2: 'Help' binds as a Mode (ValidateSet)
$vsMode = [regex]::Match($src, "\[ValidateSet\(([^)]*)\)\]\s*\r?\n\s*\[string\]\`$Mode").Groups[1].Value
Check "F2: Mode ValidateSet contains 'Help'" ($vsMode -match "'Help'")

# E3: dispatch + menu wiring (source scan)
Check "F2: Show-ScriptHelp defined + Help arm prints and exits 0" ($src.Contains('function Show-ScriptHelp {') -and $src.Contains("if (`$Mode -eq 'Help') { Show-ScriptHelp; exit 0 }"))
$dispIdx = $src.IndexOf("if (`$Mode -eq 'Help')")
$cfgIdx = $src.IndexOf('$cfgFile = Join-Path')
Check "F2: Help dispatch precedes config load (no config/elevation/case context)" ($dispIdx -ge 0 -and $cfgIdx -gt $dispIdx)
$mMenu = [regex]::Match($src, "(?s)function Show-TaskMenu \{.*?\r?\n\}")
Check "F2: menu shows [H] Help entry" ($mMenu.Success -and $mMenu.Value.Contains('[H]'))
Check "F2: menu [H] handler returns 'Help'" ($mMenu.Success -and $mMenu.Value.Contains("'^(?i)h$' { return 'Help' }"))
Check "F2: bareLaunch loop renders Help then returns to menu (no exit)" ($src.Contains("'Help' { Show-ScriptHelp }"))

# E4: behavioral E2E - a real -Mode Help run is cheap, side-effect free, no module artifacts
$repoEntriesBefore = @(Get-ChildItem -LiteralPath $repo | ForEach-Object { $_.Name })
$hOut = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Ophira.ps1') -Mode Help 2>&1 | Out-String)
Check "F2 run: -Mode Help exits 0" ($LASTEXITCODE -eq 0)
Check "F2 run: synopsis text in output" ($hOut -match 'single-file Windows incident response triage toolkit')
$hEx = [regex]::Matches($hOut, 'EXAMPLE \d+').Count
Check "F2 run: >= 8 EXAMPLE headers rendered ($hEx)" ($hEx -ge 8)
Check "F2 run: no module-run artifacts (no 'Phase', no task menu)" (-not ($hOut -cmatch 'Phase') -and -not ($hOut -match 'What do you want to do\?'))
$repoEntriesAfter = @(Get-ChildItem -LiteralPath $repo | ForEach-Object { $_.Name })
$created = @($repoEntriesAfter | Where-Object { $repoEntriesBefore -notcontains $_ })
Check "F2 run: side-effect free (nothing created in the repo)" ($created.Count -eq 0)

# E5: Get-Help discovery smoke - PowerShell recognizes the script help against the file path
$scriptPath = Join-Path $repo 'Ophira.ps1'
$gh = (& powershell.exe -NoProfile -Command "Get-Help '$scriptPath' -Full | Out-String") -join "`n"
Check "F2 get-help: Get-Help renders SYNOPSIS from the file (no exception)" ($gh -match '(?m)SYNOPSIS' -and $gh -match 'single-file Windows incident response triage toolkit')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
