# test_v258.ps1 - v2.58 empty-artifacts-explain-themselves pack
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: Get-LocalAdminMembers against the REAL net.exe output shape ----
$m = [regex]::Match($src, "(?s)function Get-LocalAdminMembers \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-LocalAdminMembers extract failed' }
Invoke-Expression $m.Value

$realShape = @(
    '',
    'Alias name     administrators',
    'Comment        Administrators have complete and unrestricted access to the computer/domain',
    '',
    'Members',
    '',
    '-------------------------------------------------------------------------------',
    'Administrator',
    'Aryan',
    'NT AUTHORITY\LOCAL SERVICE',
    'The command completed successfully.',
    ''
)
$mem = Get-LocalAdminMembers $realShape
Check "real net.exe shape: 3 members parsed (old Skip-6 returned ZERO)" (@($mem).Count -eq 3)
Check "member lines exact (no header/footer leakage)" (@($mem) -join '|' -eq 'Administrator|Aryan|NT AUTHORITY\LOCAL SERVICE')

# tight output: no comment line, member directly after dashes
$mem2 = Get-LocalAdminMembers @('Alias name administrators', 'Members', '-------', 'bob')
Check "compact output shape parsed" (@($mem2) -join '|' -eq 'bob')

# degenerate: empty / header-only
Check "empty input -> no members" (@(Get-LocalAdminMembers @()).Count -eq 0)
Check "header-only -> no members" (@(Get-LocalAdminMembers @('Alias name administrators', 'Members', 'The command completed successfully.')).Count -eq 0)

# ---- statics: wiring ----
Check "local_admins module uses the shared parser" ($src -match [regex]::Escape('Get-LocalAdminMembers @(& net.exe localgroup administrators'))
Check "parser whitelisted for module workers" ($src -match [regex]::Escape("'Get-LocalAdminMembers'"))
Check "regen: v2.53 SBECmd orphan cleanup wired" ($src -match [regex]::Escape('removed v2.53 shellbag orphan'))
Check "orphan pattern matches all 6 stray shapes" ((@('Aryan_NTUSER.csv', '0_Aryan_Aryan_UsrClass.csv', 'Aryan_Aryan_NTUSER.csv', 'Aryan_UsrClass.csv', '0_Aryan_Aryan_NTUSER.csv', 'Aryan_Aryan_UsrClass.csv') | Where-Object { $_ -match '^\d{0,3}.*_(NTUSER|UsrClass)\.csv$' }).Count -eq 6)
Check "orphan pattern does not match shellbags.csv" ('shellbags.csv' -notmatch '^\d{0,3}.*_(NTUSER|UsrClass)\.csv$')
Check "parse_needed: analyst-tool-missing advice" ($src -match [regex]::Escape('parser tool missing from the kit - run Ophira.ps1 -Mode Setup first'))
Check "parse_needed: recursive kit tool probe" ($src -match [regex]::Escape("Get-ChildItem -LiteralPath `$td -Recurse -Filter `"`$(`$c.Parser).exe`""))
Check "evidence index: empty-artifact reason map exists" ($src -match [regex]::Escape('$emptyWhy = @{'))
Check "evidence index: why-empty rendered on 0 rows" ($src -match [regex]::Escape("<b>why empty:</b>"))
Check "evidence index: VMware EID-59 noise documented" ($src -match [regex]::Escape('EID 59 rows in this channel are VMware session probes'))
Check "posture: 4688 evidence check in regen (WARN, report-only)" ($src -match [regex]::Escape("Check = 'Process-creation auditing (4688)'; Status = 'WARN'"))
Check "posture: 4688 check gated on readable auth log + zero proc events" ($src -match [regex]::Escape('if ($authN -gt 0 -and $procN -eq 0)'))
Check "verdict: posture signal still keys on BAD only (4688 is WARN = no weight)" ($src.Contains('"$($_.Status)" -eq ''BAD'''))
Check "report: 4688 hardening recommendation" ($src -match [regex]::Escape('4688 process-creation auditing is disabled on this host'))
Check "recommendation wording: no verdict claim" (-not ($src -match [regex]::Escape('4688.*indicates compromise')))

# ---- behavioral: the REAL worker path runs a module end-to-end (v2.58 regression test:
# the sortment map was never seeded into worker runspaces, so every pooled module died
# with "Cannot index into a null array" - advanced-mode collections were dead since v2.42) ----
foreach ($n in 'Get-KitRoot', 'New-WorkerPreamble', 'Test-IsAdmin') {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    Invoke-Expression $m.Value
}
$sf = [regex]::Match($src, "(?s)\`$script:SharedFunctions = @\(.*?\r?\n\)").Value
Invoke-Expression $sf
foreach ($fn in $script:SharedFunctions) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if ($m.Success) { Invoke-Expression $m.Value }
}
$wt = [regex]::Match($src, "(?s)\`$script:ModuleWorkerText = @'.*?'@").Value
Invoke-Expression $wt
$CaseDir = Join-Path $env:TEMP ("ophira_v258_worker_" + (Get-Date -Format 'HHmmss'))
$CsvDir = Join-Path $CaseDir 'csv'; $RawDir = Join-Path $CaseDir 'raw'; $MemDir = Join-Path $CaseDir 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir, $MemDir -Force | Out-Null
$Computer = 'V258'; $Preset = 'Standard'; $global:LogHours = 168; $global:CaseLog = Join-Path $CaseDir 'c.log'
$fake = @{ Id = 'T1'; Name = 'worker-smoke'; RunText = 'Save-Rows -Name ''local_admins'' -Rows @([pscustomobject]@{ Group = ''Administrators''; Member = ''Administrator'' })' }
$ps = [powershell]::Create()
$null = $ps.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog (Join-Path $CaseDir 'w.log'))).AddArgument($fake)
$r = $ps.Invoke() | Select-Object -First 1
$ps.Dispose()
Check "worker: module ran without error" ($r -and -not $r.Error)
$wrote = Join-Path $CsvDir 'context\local_admins.csv'
if (-not (Test-Path $wrote)) { $wrote = Join-Path $CsvDir 'local_admins.csv' }
Check "worker: Save-Rows wrote through the seeded sortment map" ((Test-Path $wrote) -and @(Import-Csv $wrote).Count -eq 1)
Remove-Item -LiteralPath $CaseDir -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.65: worker preamble seed completeness (C2+C3+C4) ----
# pooled workers read branch-state the preamble never seeded: $script:Verbosity gates the
# Invoke-NativeTool tail, $Sysmon/$IsAdmin/$script:EndpointAdmin/$script:HostRole gate module
# paths, $script:FlashLines backs Out-Flash; Test-IsAdmin/Out-Flash/Get-DotNetRelease were not
# whitelisted. Each smoke runs the REAL ModuleWorkerText + REAL preamble.
$cd2 = Join-Path $env:TEMP ("ophira_v265_worker_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $cd2 -Force | Out-Null
$flashFile = Join-Path $cd2 'flash.txt'
$tailFile = Join-Path $cd2 'tail.txt'
$roleFile = Join-Path $cd2 'role.txt'
$wlog2 = Join-Path $cd2 'w2.log'
function New-SeedWorker([string]$RunText, [string]$Extra = '') {
    $ps = [powershell]::Create()
    $null = $ps.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog $wlog2) + $Extra).AddArgument(@{ Id = 'T2'; Name = 'seed-smoke'; RunText = $RunText })
    $all = @($ps.Invoke())
    $ps.Dispose()
    return $all
}

# parent-side values exactly as the live script holds them at pool-creation time
$script:SimpleUI = $true         # keep worker console quiet for the smokes
$script:Verbosity = 1
$Sysmon = $true
$IsAdmin = Test-IsAdmin
$script:EndpointAdmin = $null
$script:HostRole = "O'Brien-DC"  # apostrophe fixture: seed literalization must double it

# 1) Out-Flash callable in a worker + FlashLines seeded (RED: CommandNotFound / null .Add())
$all = New-SeedWorker "Out-Flash 'v265-flash'; Set-Content -LiteralPath '$flashFile' -Value (`$script:FlashLines -join '|'); Set-Content -LiteralPath '$roleFile' -Value `$script:HostRole"
$r = $all | Select-Object -Last 1
Check "v265 worker: Out-Flash callable (no CommandNotFound)" ($r -and -not $r.Error)
Check "v265 worker: FlashLines seeded, contains flashed text" ((Test-Path $flashFile) -and ((Get-Content $flashFile -Raw) -match 'v265-flash'))
Check "v265 worker: HostRole seed survives apostrophe" ((Test-Path $roleFile) -and ((Get-Content $roleFile -Raw).Trim()) -eq "O'Brien-DC")

# 2) $Sysmon branch reflects the seeded value, both polarities (RED: undefined -> always else)
$all = New-SeedWorker "if (`$Sysmon) { 'sysmon-yes' } else { 'sysmon-no' }"
$r = $all | Select-Object -Last 1
Check "v265 worker: Sysmon=`$true visible in worker" ($r -and -not $r.Error -and (@($all) -contains 'sysmon-yes') -and -not (@($all) -contains 'sysmon-no'))
$Sysmon = $false
$all = New-SeedWorker "if (`$Sysmon) { 'sysmon-yes' } else { 'sysmon-no' }"
$r = $all | Select-Object -Last 1
Check "v265 worker: Sysmon=`$false visible in worker" ($r -and -not $r.Error -and (@($all) -contains 'sysmon-no') -and -not (@($all) -contains 'sysmon-yes'))
$Sysmon = $true

# 3) Test-IsAdmin callable in a worker, returns the same elevation state the parent seeded
$all = New-SeedWorker '[bool](Test-IsAdmin)'
$r = $all | Select-Object -Last 1
$branch = "$($all | Select-Object -First 1)"
Check "v265 worker: Test-IsAdmin callable, matches seeded IsAdmin" ($r -and -not $r.Error -and $branch -eq "$IsAdmin")

# 4) Invoke-NativeTool tail honors seeded Verbosity (RED: worker $null -> -NoConsole always True)
$capStub = "function Write-CaseLog { param([string]`$Message,[string]`$Color = 'Gray',[switch]`$NoConsole) Add-Content -LiteralPath '$tailFile' -Value (`"NC=`$NoConsole`") } "
$tailRun = "Invoke-NativeTool -ExePath `$env:ComSpec -ToolArgs @('/c','echo','v265tail')"
$script:Verbosity = 1
Remove-Item -LiteralPath $tailFile -Force -ErrorAction SilentlyContinue
$all = New-SeedWorker $tailRun $capStub
$lines = @(); if (Test-Path $tailFile) { $lines = @(Get-Content $tailFile) }
Check "v265 worker: Verbosity=1 tail -> -NoConsole:True" ($lines.Count -ge 1 -and $lines -contains 'NC=True' -and $lines -notcontains 'NC=False')
$script:Verbosity = 2
Remove-Item -LiteralPath $tailFile -Force -ErrorAction SilentlyContinue
$all = New-SeedWorker $tailRun $capStub
$lines = @(); if (Test-Path $tailFile) { $lines = @(Get-Content $tailFile) }
Check "v265 worker: Verbosity=2 tail -> no -NoConsole (False)" ($lines.Count -ge 1 -and $lines -contains 'NC=False' -and $lines -notcontains 'NC=True')

# 5) statics: every new seed line in the generated preamble; whitelist carries the three names
$script:Verbosity = 1; $IsAdmin = $false; $script:EndpointAdmin = $null
$pre = New-WorkerPreamble -WorkerLog $wlog2
Check "v265 static: preamble seeds `$script:Verbosity" ($pre -match [regex]::Escape('$script:Verbosity = 1'))
Check "v265 static: preamble seeds `$Sysmon" ($pre -match [regex]::Escape('$Sysmon = $True'))
Check "v265 static: preamble seeds `$IsAdmin" ($pre -match [regex]::Escape('$IsAdmin = $False'))
Check "v265 static: preamble seeds `$script:EndpointAdmin" ($pre -match [regex]::Escape('$script:EndpointAdmin = '))
Check "v265 static: HostRole literalized with doubled apostrophe" ($pre -match [regex]::Escape("`$script:HostRole = 'O''Brien-DC'"))
Check "v265 static: preamble creates FlashLines List" ($pre -match [regex]::Escape('$script:FlashLines = New-Object System.Collections.Generic.List[string]'))
$script:EndpointAdmin = $false
$pre2 = New-WorkerPreamble -WorkerLog $wlog2
Check "v265 static: EndpointAdmin=`$false literalizes (not swallowed as null)" ($pre2 -match [regex]::Escape('$script:EndpointAdmin = $False'))
$script:EndpointAdmin = $null
$pre3 = New-WorkerPreamble -WorkerLog $wlog2
Check "v265 static: EndpointAdmin unset passes as `$null" ($pre3 -match [regex]::Escape('$script:EndpointAdmin = $null'))
foreach ($fn in 'Test-IsAdmin', 'Out-Flash', 'Get-DotNetRelease') {
    Check "v265 static: SharedFunctions whitelists $fn" ($script:SharedFunctions -contains $fn)
}

# 6) worker Write-CaseLog STAYS file-only even with Verbosity seeded (v2.63 T5 regression guard)
$all = New-SeedWorker "Write-CaseLog 'v265-fileonly-pin'"
$r = $all | Select-Object -Last 1
$wlText = ''; if (Test-Path $wlog2) { $wlText = Get-Content $wlog2 -Raw }
Check "v265 worker: Write-CaseLog line lands in worker log file" ($r -and -not $r.Error -and @(($wlText -split "\r?\n") -match 'v265-fileonly-pin').Count -ge 1)
$ovl = @(@($pre -split "\r?\n") | Where-Object { $_ -match 'function Write-CaseLog' })
Check "v265 static: worker Write-CaseLog override stays file-only (no Write-Host)" ($ovl.Count -eq 1 -and $ovl[0] -match 'Add-Content' -and $ovl[0] -notmatch 'Write-Host')

Remove-Item -LiteralPath $cd2 -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.65 C5: error-path symmetry between the inline and parallel dispatch paths ----
# Invoke-ModuleBatch has two dispatch shapes: inline ($ps.Invoke(), -Sequential only since C8)
# and parallel (EndInvoke under try/catch). Parallel logs a failed worker and keeps going; inline
# propagated the throw and killed the run. The preamble Invoke-Expression inside
# ModuleWorkerText is also unguarded, so a poisoned preamble crashed the worker (and through
# it the inline path) instead of failing that one module. Each smoke runs the REAL dispatcher,
# REAL preamble and REAL ModuleWorkerText; a test stub poisons one input per scenario.
$mb = [regex]::Match($src, "(?s)function Invoke-ModuleBatch \{.*?\r?\n\}")
if (-not $mb.Success) { throw 'Invoke-ModuleBatch extract failed' }
Invoke-Expression $mb.Value
$mwl = [regex]::Match($src, "(?s)function Merge-WorkerLog \{.*?\r?\n\}")
if (-not $mwl.Success) { throw 'Merge-WorkerLog extract failed' }
Invoke-Expression $mwl.Value

$cd3 = Join-Path $env:TEMP ("ophira_v265_c5_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $cd3 -Force | Out-Null
$CaseDir = $cd3
$global:CaseLog = Join-Path $cd3 'c.log'
$Sequential = $false
$script:logLines = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole) $script:logLines.Add($Message) }

# preamble override: poisons ONLY the first call, delegates the rest to the real builder
$realPreamble = ${function:New-WorkerPreamble}
$script:preCalls = 0
function New-WorkerPreamble {
    param([string]$WorkerLog)
    $script:preCalls++
    if ($script:preCalls -eq 1) { return "function 'broken-pre" }
    return (& $realPreamble -WorkerLog $WorkerLog)
}
function New-BatchMod([string]$Id) {
    # [void]: RunText stays leak-free; the C8 S5 smoke below pins the dispatcher's result-record filter
    @{ Id = $Id; Name = "mod-$Id"; Run = [scriptblock]::Create("[void]'ok-$Id'") }
}
function Reset-Log { $script:logLines = New-Object System.Collections.Generic.List[string]; $script:preCalls = 0 }

# 1) inline path + poisoned preamble -> no crash, logged, batch continues
$Sequential = $true
Reset-Log
$batch = @( (New-BatchMod 'TP'), (New-BatchMod 'TQ') )
$inlineThrew = $null
$inlineResults = @()
try { $inlineResults = @(Invoke-ModuleBatch -Batch $batch) } catch { $inlineThrew = $_.Exception.Message }
Check "c5 inline: poisoned preamble does not crash the batch" ($null -eq $inlineThrew)
$tpFail = @($script:logLines | Where-Object { $_ -match 'TP' -and $_ -match 'ERROR|failed' })
Check "c5 inline: poisoned module logged with id + failure marker" ($tpFail.Count -ge 1)
Check "c5 inline: poisoned module error text captured" ($tpFail.Count -ge 1 -and ($tpFail[0] -match "broken-pre|preamble"))
Check "c5 inline: batch continues after poisoned module" (@($inlineResults | Where-Object { $_.Id -eq 'TQ' }).Count -eq 1)
$tqFail = @($script:logLines | Where-Object { $_ -match 'TQ' -and $_ -match 'ERROR|failed' })
Check "c5 inline: healthy sibling module still logged (no failure)" ($tqFail.Count -eq 0)

# 2) parity: same poisoned preamble through the parallel path -> same failure-marker pattern
$Sequential = $false
Reset-Log
$parThrew = $null
$parResults = @()
try { $parResults = @(Invoke-ModuleBatch -Batch $batch -Workers 4) } catch { $parThrew = $_.Exception.Message }
Check "c5 parallel: poisoned preamble does not crash the pool" ($null -eq $parThrew)
$parFail = @($script:logLines | Where-Object { $_ -match 'TP' -and $_ -match 'ERROR|failed' })
Check "c5 parity: parallel logs a failure marker for the poisoned module" ($parFail.Count -ge 1)
$mkPat = '^Module TP \(mod-TP\) ERROR: '
Check "c5 parity: both paths emit the same marker pattern (id + ERROR/failed)" ($tpFail.Count -ge 1 -and $parFail.Count -ge 1 -and $tpFail[0] -match $mkPat -and $parFail[0] -match $mkPat)
Check "c5 parity: parallel batch continues after poisoned module" (@($parResults | Where-Object { $_.Id -eq 'TQ' }).Count -eq 1)

# 3) poisoned RunText (unbalanced quote) -> the worker's RunText try/catch catches it, inline
# logs the module error, no crash. preCalls is left at 1 so TR's preamble call is a REAL one -
# the failure must come from the RunText catch, not the preamble path.
# (Run is a string here - .ToString() feeds the worker the raw poisoned text, exactly what a
# scriptblock whose literalization broke would hand over)
Reset-Log
$script:preCalls = 1
$badRun = @( @{ Id = 'TR'; Name = 'mod-TR'; Run = 'broken"run text' } )
$trThrew = $null
$trResults = @()
try { $trResults = @(Invoke-ModuleBatch -Batch $badRun) } catch { $trThrew = $_.Exception.Message }
Check "c5 inline: poisoned RunText does not crash the batch" ($null -eq $trThrew)
$trFail = @($script:logLines | Where-Object { $_ -match 'TR' -and $_ -match 'ERROR|failed' })
Check "c5 inline: poisoned RunText logged as module error" ($trFail.Count -ge 1)
Check "c5 inline: RunText failure came from the RunText catch (not preamble/dispatcher)" ($trFail.Count -ge 1 -and $trFail[0] -match 'ERROR: ' -and $trFail[0] -notmatch 'preamble failed' -and $trFail[0] -notmatch 'worker failed')

# 4) dispatcher-level catch: a synchronous worker crash must log + continue on BOTH paths
$savedWt = $script:ModuleWorkerText
$script:ModuleWorkerText = 'param($PreambleText, $ModuleDef) throw "simulated worker crash"'
$Sequential = $true
Reset-Log
$crashThrew = $null
try { $null = Invoke-ModuleBatch -Batch @( (New-BatchMod 'TC'), (New-BatchMod 'TD') ) } catch { $crashThrew = $_.Exception.Message }
$crashInline = @($script:logLines | Where-Object { $_ -match 'TC' -and $_ -match 'worker failed' })
Check "c5 inline: synchronous worker crash does not crash the dispatcher" ($null -eq $crashThrew)
Check "c5 inline: worker crash logged with module id (parallel catch shape)" ($crashInline.Count -ge 1)
$crashPar = $null
$Sequential = $false
try { $null = Invoke-ModuleBatch -Batch @( (New-BatchMod 'TE'), (New-BatchMod 'TF') ) -Workers 4 } catch { $crashPar = $_.Exception.Message }
$crashParFail = @($script:logLines | Where-Object { $_ -match 'TE' -and $_ -match 'worker failed' })
Check "c5 parity: parallel worker crash unchanged (logs, no throw)" ($null -eq $crashPar -and $crashParFail.Count -ge 1)
$script:ModuleWorkerText = $savedWt

Remove-Item -LiteralPath $cd3 -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.65 C8: singleton batches route through the POOLED dispatcher in advanced mode ----
# The Count==1 shortcut sent small batches to the synchronous inline dispatcher even in
# advanced mode - the exact v2.58 masking: a worker/pool-only failure (missing seed,
# preamble break, pool wiring) never reproduces when every test and every small phase runs
# pool-free. Discriminator: the dispatcher labels its own path in the case log - the inline
# branch logs "done in Ns [inline]", the pooled branch logs "done in Ns" without the suffix.
# (Thread ids do NOT discriminate: PS 5.1 runs synchronous Invoke() off the caller thread too.)
# SimpleUI front-screen + -Sequential inline stay BY DESIGN (pinned below, statics + dynamic).
$cd8 = Join-Path $env:TEMP ("ophira_v265_c8_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $cd8 -Force | Out-Null
$CaseDir = $cd8
$global:CaseLog = Join-Path $cd8 'c8.log'
$savedWt8 = $script:ModuleWorkerText
$script:ModuleWorkerText = 'param($PreambleText, $ModuleDef) return [pscustomobject]@{ Id = $ModuleDef.Id; Name = $ModuleDef.Name; Seconds = 0.0; Error = "" }'

# 1) RED: advanced-mode 1-module batch -> POOLED dispatcher (no [inline] marker in the log)
$Sequential = $false
Reset-Log; $script:preCalls = 1
$r8 = @()
try { $r8 = @(Invoke-ModuleBatch -Batch @((New-BatchMod 'S1')) -Workers 2) } catch { }
Check "c8: advanced 1-module batch returned the sentinel result (sentinel used)" ($r8.Count -eq 1 -and $r8[0].Id -eq 'S1')
Check "c8: advanced 1-module batch runs through the POOLED dispatcher (no [inline] marker)" (@($script:logLines | Where-Object { $_ -match 'Module S1 \(mod-S1\) done in ' -and $_ -notmatch '\[inline\]' }).Count -eq 1)

# 2) pin: -Sequential 1-module batch stays INLINE ([inline] marker - by-design serial path)
$Sequential = $true
Reset-Log; $script:preCalls = 1
$r8 = @()
try { $r8 = @(Invoke-ModuleBatch -Batch @((New-BatchMod 'S2')) -Workers 2) } catch { }
Check "c8: -Sequential 1-module batch stays INLINE ([inline] marker)" (@($script:logLines | Where-Object { $_ -match 'Module S2 \(mod-S2\) done in ' -and $_ -match '\[inline\]' }).Count -eq 1)

# 3) pins (static): the SimpleUI front-screen guard still short-circuits BEFORE any
#    Invoke-ModuleBatch call, and phase A still runs its modules inline - the routing fix
#    cannot overreach into the owner-facing path or the volatile phase.
$ism = [regex]::Match($src, "(?s)function Invoke-SelectedModules \{.*?\r?\n\}")
if (-not $ism.Success) { throw 'Invoke-SelectedModules extract failed' }
Check "c8: SimpleUI/-Sequential guard precedes the phase dispatch (front screen stays inline)" ($ism.Value.IndexOf('if ($Sequential -or $script:SimpleUI) {') -ge 0 -and $ism.Value.IndexOf('if ($Sequential -or $script:SimpleUI) {') -lt $ism.Value.IndexOf('Invoke-ModuleBatch -Batch'))
Check "c8: phase A still runs inline via runInline (order-of-volatility semantics untouched)" ($ism.Value -match [regex]::Escape('foreach ($m in $phases.A) { & $runInline $m }'))

# 4) static: the shortcut condition is GONE from the dispatcher (RED today: Count==1 -or)
Check "c8: dispatcher inline guard is Sequential-only (no Count==1 shortcut)" ($mb.Value -match '(?m)^\s*if \(\$Sequential\) \{' -and $mb.Value -notmatch [regex]::Escape('$Batch.Count -eq 1 -or $Sequential'))

# 5) regression: advanced 2-module batch still pooled (no [inline] markers, both results)
$Sequential = $false
Reset-Log; $script:preCalls = 1
$r8 = @()
try { $r8 = @(Invoke-ModuleBatch -Batch @((New-BatchMod 'S3'), (New-BatchMod 'S4')) -Workers 2) } catch { }
Check "c8: advanced 2-module batch still pooled (regression)" ($r8.Count -eq 2 -and @($script:logLines | Where-Object { $_ -match 'done in ' -and $_ -notmatch '\[inline\]' }).Count -eq 2)

# 6) output-shadowing fold-in: a module that leaks pipeline output must not shadow the
#    result record the dispatcher logs/returns (First 1 used to take the leak - it comes
#    first in the output stream, before the worker's return).
$Sequential = $false
Reset-Log; $script:preCalls = 1
$script:ModuleWorkerText = 'param($PreambleText, $ModuleDef) "leaked-noise"; return [pscustomobject]@{ Id = $ModuleDef.Id; Name = $ModuleDef.Name; Seconds = 0.1; Error = "" }'
$r8 = @()
try { $r8 = @(Invoke-ModuleBatch -Batch @((New-BatchMod 'S5')) -Workers 2) } catch { }
Check "c8: leaked pipeline output does not shadow the result record" ($r8.Count -eq 1 -and "$($r8[0].Id)" -eq 'S5' -and @($r8) -notcontains 'leaked-noise')

$script:ModuleWorkerText = $savedWt8
Remove-Item -LiteralPath $cd8 -Recurse -Force -ErrorAction SilentlyContinue

# ---- v2.65 C6+C7: FAILED marker reader protocol + literal-path reads ----
# Save-Rows' catch writes "FAILED: <reason>" as the whole file; the READER must treat that as
# "artifact failed to save" - empty result + an honest warning naming the file and reason -
# never a silent header-row parse. Case paths can carry [ ] wildcard chars, so reads go through
# -LiteralPath (Test-CaseCsv stays wildcard-aware BY DESIGN for jumplist_parsed* lookups - that
# asymmetry is documented at both sites, not a bug to unify). Locked files return @(), never throw.
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
foreach ($n in @('Import-CaseCsv', 'Get-CaseCsvPath')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$n extract failed" }
    Invoke-Expression $m.Value
}
$cd4 = Join-Path $env:TEMP ("ophira_v265_c6c7_" + (Get-Date -Format 'HHmmss'))
$CsvDir = Join-Path $cd4 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$script:capLog = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:capLog.Add($Message) }

# 1) FAILED marker file -> @() + warning carrying the failure text (RED: silent empty)
'FAILED: boom - disk full' | Set-Content -LiteralPath (Join-Path $CsvDir 'broken_artifact.csv') -Encoding UTF8
$c6threw = $null; $c6rows = $null
try { $c6rows = @(Import-CaseCsv 'broken_artifact') } catch { $c6threw = $_.Exception.Message }
Check "c6: FAILED marker file -> empty result, no throw" ($null -eq $c6threw -and $c6rows.Count -eq 0)
$c6warn = @($script:capLog | Where-Object { $_ -match 'broken_artifact' -and $_ -match 'FAILED' -and $_ -match 'boom' })
Check "c6: reader warns honestly that the artifact FAILED (names file + reason)" ($c6warn.Count -ge 1)

# 2) FAILED: mid-line in DATA is untouched - only position 0 of the FIRST line counts
'"Note","Val"' | Set-Content -LiteralPath (Join-Path $CsvDir 'midline.csv') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $CsvDir 'midline.csv') -Value '"run FAILED: hash mismatch",1'
$mid = @(Import-CaseCsv 'midline')
Check "c6: FAILED: mid-data parsed as a normal row" ($mid.Count -eq 1 -and "$($mid[0].Note)" -match 'FAILED: hash mismatch')

# 3) FAILED file through the evidence-index render -> 0 rows + the failure reason as why-empty
'FAILED: disk full while writing prefetch rows' | Set-Content -LiteralPath (Join-Path $CsvDir 'fixture_failed.csv') -Encoding UTF8
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Get-CompromiseVerdict', 'New-HtmlReport', 'New-AttackLayer', 'New-SiemExport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    Invoke-Expression $m.Value
}
$RawDir = Join-Path $cd4 'raw'; $CaseDir = $cd4; $MemDir = Join-Path $cd4 'mem'
$Computer = 'V265'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'C6C7'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
$null = Get-CompromiseVerdict; $script:Verdict = $script:Verdict
$null = New-HtmlReport
$html6 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "c6: evidence index renders the FAILED file at 0 rows" ($html6 -match 'fixture_failed\.csv</a></td><td>0</td>')
Check "c6: evidence index explains the FAILED file (why-empty carries the reason)" ($html6 -match 'artifact FAILED to save during collection' -and $html6 -match [regex]::Escape('disk full while writing prefetch rows'))

# 4) [bracket] wildcard chars in the path -> read works via -LiteralPath (RED: positional throw)
'"Col","Val"' | Set-Content -LiteralPath (Join-Path $CsvDir 'weird[1].csv') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $CsvDir 'weird[1].csv') -Value '"x","y"'
$lthrew = $null; $lt = $null
try { $lt = @(Import-CaseCsv 'weird[1].csv') } catch { $lthrew = $_.Exception.Message }
Check "c7: [bracket] path reads via -LiteralPath (1 row, no throw)" ($null -eq $lthrew -and $lt.Count -eq 1)

# 5) locked file (FileShare.None open in this test) -> @(), never throws (read stays inside try)
'"Col","Val"' | Set-Content -LiteralPath (Join-Path $CsvDir 'locked_artifact.csv') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $CsvDir 'locked_artifact.csv') -Value '"x","y"'
$fs = [System.IO.File]::Open((Join-Path $CsvDir 'locked_artifact.csv'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
$lkthrew = $null; $lk = $null
try { $lk = @(Import-CaseCsv 'locked_artifact') } catch { $lkthrew = $_.Exception.Message }
$fs.Dispose()
Check "c7: locked file -> @() (read inside try), no throw" ($null -eq $lkthrew -and $lk.Count -eq 0)

# 6) regression guards: normal csv / marker / missing / flat-then-mapped all unchanged
'"Col","Val"' | Set-Content -LiteralPath (Join-Path $CsvDir 'plain.csv') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $CsvDir 'plain.csv') -Value '"a","1"'
Add-Content -LiteralPath (Join-Path $CsvDir 'plain.csv') -Value '"b","2"'
Check "c6c7 regression: normal csv -> 2 rows" (@(Import-CaseCsv 'plain').Count -eq 2)
'# no entries' | Set-Content -LiteralPath (Join-Path $CsvDir 'marked.csv') -Encoding UTF8
Check "c6c7 regression: '# no entries' marker -> @()" (@(Import-CaseCsv 'marked').Count -eq 0)
Check "c6c7 regression: missing csv -> @()" (@(Import-CaseCsv 'nope_never').Count -eq 0)
New-Item -ItemType Directory -Path (Join-Path $CsvDir 'artifacts') -Force | Out-Null
'"Col","Val"' | Set-Content -LiteralPath (Join-Path $CsvDir 'artifacts\jumplist_parsed.csv') -Encoding UTF8
Add-Content -LiteralPath (Join-Path $CsvDir 'artifacts\jumplist_parsed.csv') -Value '"x","y"'
Check "c6c7 regression: flat-then-mapped resolution intact (artifacts\jumplist_parsed)" (@(Import-CaseCsv 'jumplist_parsed').Count -eq 1)

Remove-Item -LiteralPath $cd4 -Recurse -Force -ErrorAction SilentlyContinue

if ($fail -gt 0) { Write-Host "`ntest_v258: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v258: $pass passed, 0 failed" -ForegroundColor Green
exit 0
