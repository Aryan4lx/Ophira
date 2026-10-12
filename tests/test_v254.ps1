$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.54 - evidence-index fix pack from the fresh live collection: ShellBags module swept all of
# C:\Users recursively (stale case copies in Temp included) and missed SBECmd's per-hive output
# names (shellbags.csv never built, raw outputs leaked into csv\ as 0-row unknowns); UserAssist
# was always empty (brace-less Win7 GUID list + lowercase-only ROT13); evidence index had no
# descriptions for wildcard-named artifacts.
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
# ConvertTo-Rot13: true ROT13 (the old one only rotated lowercase)
# ============================================================================
$defs = ''
foreach ($n in @('ConvertTo-Rot13', 'Get-UserAssistRows')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
Check "rot13: encoded UEME entry decodes (uppercase rotated)" ((ConvertTo-Rot13 'HRZR_PGYFRFFVBA') -eq 'UEME_CTLSESSION')
Check "rot13: encoded exe name decodes both cases" ((ConvertTo-Rot13 'Zvpebfbsg.Jvaqbjf.Rkcybere') -eq 'Microsoft.Windows.Explorer')
Check "rot13: digits/punctuation untouched" ((ConvertTo-Rot13 '308046O0NS4N39PO') -eq '308046B0AF4A39CB')
Check "userassist: dynamic GUID enumeration (no brace-less hardcoded list)" (($src -notmatch "'CEBFF5CD-ACE2-4F4F-9178-9926F41749EA', 'F4E57C4B") -and ($src.Contains('Get-ChildItem $uaRoot')))
Check "userassist: known-GUID kind labels carried" ($src.Contains("'{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}' = 'executable'"))

# ============================================================================
# module 8.8 through the real Run block: no recursive C:\Users sweep, per-run
# output dirs, merge-all, no csv-root strays
# ============================================================================
$defs2 = ''
foreach ($n in @('Get-KitRoot', 'Get-ToolsDir')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs2 += $m.Value + "`r`n"
}
$mod = [regex]::Match($src, "(?s)\[pscustomobject\]\@\{ Id = '8\.8';.*?\r?\n        \} \}")
if (-not $mod.Success) { throw 'module 8.8 extract failed' }
Invoke-Expression ($defs2 + ($mod.Value -replace '\[pscustomobject\]\@\{', '$mod88 = [pscustomobject]@{'))

$case = Join-Path $env:TEMP "ophira_v254_$stamp"
$csv = Join-Path $case 'csv'
$rawUsers = Join-Path $case 'raw\registry\users'
New-Item -ItemType Directory -Path $csv, $rawUsers -Force | Out-Null
Set-Content (Join-Path $case 'case.json') -Value '{"Computer":"T","CaseID":"C-54","StartedUTC":"2026-10-12T08:00:00.0000000Z","AdminElevated":true,"SysmonPresent":false}' -Encoding UTF8
# fake saved hives (contents never parsed - the stubbed SBECmd just reports dirs)
Set-Content (Join-Path $rawUsers 'Test_NTUSER.DAT') -Value 'fake'
Set-Content (Join-Path $rawUsers 'Test_UsrClass.dat') -Value 'fake'

$script:nativeCalls = @()
function Invoke-NativeTool {
    param([string]$ExePath, [string[]]$ToolArgs)
    $script:nativeCalls += ("SBECmd|" + ($ToolArgs -join ' '))
    # mimic the real SBECmd: --dedupe always writes Deduplicated.csv into the --csv dir
    $csvIdx = [array]::IndexOf($ToolArgs, '--csv')
    if ($csvIdx -ge 0) {
        $outDir = $ToolArgs[$csvIdx + 1]
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        @('BagPath,AbsolutePath,LastWriteTime', "BagMRU,Desktop\$([guid]::NewGuid().ToString('N')),2026-10-12 08:00:00") | Set-Content -LiteralPath (Join-Path $outDir 'Deduplicated.csv') -Encoding UTF8
    }
    return 0
}
$script:savedRows = @{}
function Save-Rows { param($Name, $Rows) $script:savedRows[$Name] = @($Rows) }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$script:RawDir = Join-Path $case 'raw'

& $mod88.Run
Check "shellbags: -d targets the case's own saved hives dir (no recursive C:\Users sweep)" (@($script:nativeCalls | Where-Object { $_ -match '-d .*registry\\users ' }).Count -ge 1 -and @($script:nativeCalls | Where-Object { $_ -match [regex]::Escape("-d $env:SystemDrive\Users ") }).Count -eq 0)
Check "shellbags: per-run output dirs (2nd --dedupe run cannot overwrite the 1st)" ((@($script:nativeCalls | Where-Object { $_ -match '--csv .*\\r1 ' }).Count -eq 1) -and (@($script:nativeCalls | Where-Object { $_ -match '--csv .*\\r2 ' }).Count -eq 1))
Check "shellbags: rows merged from both runs into csv\shellbags.csv" (@($savedRows['shellbags']).Count -eq 2)
Check "shellbags: no raw tool outputs left in the case csv root" ((Get-ChildItem -LiteralPath $csv -Filter '*.csv' -File -ErrorAction SilentlyContinue).Count -eq 0)
Check "shellbags: temp output tree cleaned up" ((Get-ChildItem $env:TEMP -Filter 'ophira_sbe_*' -Directory -ErrorAction SilentlyContinue).Count -eq 0)
Check "shellbags: live stage only for users without a saved hive" (($src -Contains 'coveredUsers') -or $src.Contains('$coveredUsers'))

# no saved hives at all -> clean skip, no crash
$case2 = Join-Path $env:TEMP "ophira_v254b_$stamp"
New-Item -ItemType Directory -Path (Join-Path $case2 'raw') -Force | Out-Null
$script:nativeCalls = @()
$script:RawDir = Join-Path $case2 'raw'
& $mod88.Run
Check "shellbags: no saved hives -> clean skip (or live-stage fallback), never throws" (($script:nativeCalls.Count -eq 0) -or (@($script:nativeCalls | Where-Object { $_ -match [regex]::Escape("-d $env:SystemDrive\Users ") }).Count -eq 0))

# ============================================================================
# evidence index: wildcard descriptions
# ============================================================================
Check "index: wildcard description map entries present" (($src.Contains("'amcache_*'")) -and ($src.Contains("'logon_summary*'")) -and ($src.Contains("'prefetch_parsed_Timeline'")))
Check "index: generic wildcard lookup replaces the hardcoded jumplist special case" (($src.Contains("`$k.EndsWith('*')")) -and ($src -notmatch [regex]::Escape("elseif (`$base -match '^jumplist_parsed')")))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
