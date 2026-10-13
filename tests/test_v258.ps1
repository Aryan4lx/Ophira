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
foreach ($n in 'Get-KitRoot', 'New-WorkerPreamble') {
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

if ($fail -gt 0) { Write-Host "`ntest_v258: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v258: $pass passed, 0 failed" -ForegroundColor Green
exit 0
