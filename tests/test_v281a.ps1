# test_v281a.ps1 - v2.81 T1: R36 Levenshtein masquerade hunt rule
# Part 1: Get-LevenshteinDistance unit checks (note: svchost/scvhost is an adjacent swap,
#         classic non-Damerau DP = 2 - the plan's example value of 1 was arithmetically
#         impossible for the DP it specifies).
# Part 2: R36 through the real New-HuntFindings with stubbed signatures/existence:
#         near-name in user path -> high, exact name gated out, signed system-dir copy
#         skipped, missing file = uncheckable (high, NOT signed), signed elsewhere -> low,
#         distance-3 silent, .dll/no-extension/missing-name-column ignored, 12-finding cap.
# Part 3: verdict wiring - R36-high row alone fires the weight-2 hunt signal; R36-low is
#         report-only.
$ErrorActionPreference = 'Stop'
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
$src = Get-Content -LiteralPath $repoScript -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ---- extract the real functions (house regex: lazy match to column-0 closing brace) ----
$defs = ''
foreach ($n in @('Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'New-HuntFindings', 'Get-CompromiseVerdict', 'Get-LvlRank', 'Get-InvariantDate', 'Get-SafeRuleKey', 'Get-SafeRuleKeyMap', 'Resolve-SafeRuleKey')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

# ============================================================================
# PART 1 - helper unit checks
# ============================================================================
Check "levenshtein: svchost -> svghost (one substitution) = 1" ((Get-LevenshteinDistance 'svchost' 'svghost') -eq 1)
Check "levenshtein: powershell -> powershel1 = 1" ((Get-LevenshteinDistance 'powershell' 'powershel1') -eq 1)
# plan correction: svchost/scvhost differ by an adjacent swap - classic DP gives 2, not 1
Check "levenshtein: svchost -> scvhost (adjacent swap, non-Damerau) = 2" ((Get-LevenshteinDistance 'svchost' 'scvhost') -eq 2)
Check "levenshtein: identical strings = 0" ((Get-LevenshteinDistance 'explorer.exe' 'explorer.exe') -eq 0)
Check "levenshtein: empty vs abc = 3" ((Get-LevenshteinDistance '' 'abc') -eq 3)
Check "levenshtein: abc vs empty = 3" ((Get-LevenshteinDistance 'abc' '') -eq 3)
Check "levenshtein: empty vs empty = 0" ((Get-LevenshteinDistance '' '') -eq 0)

# ============================================================================
# PART 2 - R36 through the real New-HuntFindings
# ============================================================================
$script:Verbosity = 1
$CaseLog = Join-Path $env:TEMP "ophira_v281a_$stamp.log"
$Computer = 'V281HOST'
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:saved = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$script:caseCsv = @{}; $script:fixtureRows = @{}
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return $script:caseCsv[$k] }; if ($script:fixtureRows.ContainsKey($k)) { return $script:fixtureRows[$k] }; return @() }
# controllable Authenticode verdicts by exact path (v280d pattern); Test-Path is scoped to
# the same map: a path with a captured signature "exists", everything else is missing on
# disk (parse mode) - no admin writes needed.
$script:sigByPath = @{}
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $script:sigByPath["$LiteralPath".ToLower()] }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath, [string]$PathType) return $script:sigByPath.ContainsKey("$LiteralPath".ToLower()) }

# ---- run A: classification matrix ----
$script:sigByPath = @{
    'c:\windows\system32\svcchost.exe'     = [pscustomobject]@{ Status = 'Valid' }    # system dir + checkable-signed -> skip
    'c:\program files\vendor\svchostx.exe' = [pscustomobject]@{ Status = 'Valid' }    # signed elsewhere -> low
    'c:\users\public\scvhost.exe'          = [pscustomobject]@{ Status = 'NotSigned' } # unsigned user path -> high
    'c:\windows\system32\svchost.exe'      = [pscustomobject]@{ Status = 'Valid' }    # exact name -> distance gate
}
$script:caseCsv = @{
    'processes' = @(
        [pscustomobject]@{ Name = 'scvhost.exe'; Path = 'C:\Users\Public\scvhost.exe'; PID = '4242' },
        [pscustomobject]@{ Name = 'notanexe'; Path = 'C:\Users\Public\notanexe' },
        [pscustomobject]@{ Timestamp = '2026-10-05 10:00:00' }
    )
    'amcache' = @(
        [pscustomobject]@{ Name = 'svchost.exe'; FullPath = 'C:\Windows\System32\svchost.exe' },
        [pscustomobject]@{ Name = 'svcchost.exe'; FullPath = 'C:\Windows\System32\svcchost.exe' },
        [pscustomobject]@{ Name = 'svchostt.exe'; FullPath = 'C:\Windows\System32\svchostt.exe' },
        [pscustomobject]@{ Name = 'svchostx.exe'; FullPath = 'C:\Program Files\Vendor\svchostx.exe' },
        [pscustomobject]@{ Name = 'evil.dll'; FullPath = 'C:\Users\Public\evil.dll' }
    )
    'prefetch_parsed' = @( [pscustomobject]@{ Executable = 'calc.exe' } )
    'bam_lastexec' = @()
}
$script:saved = @()
New-HuntFindings
$r36 = @($script:saved | Where-Object { $_.Rule -eq 'Lookalike system binary (Levenshtein near-name)' })

Check "R36: exactly 3 findings (2 high, 1 low)" ($r36.Count -eq 3 -and @($r36 | Where-Object { $_.Severity -eq 'high' }).Count -eq 2 -and @($r36 | Where-Object { $_.Severity -eq 'low' }).Count -eq 1)
Check "R36: scvhost.exe unsigned user path -> high, distance 2, T1036.005" (1 -eq @($r36 | Where-Object { "$($_.Entity)" -eq 'C:\Users\Public\scvhost.exe' -and "$($_.Evidence)" -match [regex]::Escape("near 'svchost.exe' (distance 2)") -and "$($_.Evidence)" -match 'signature NotSigned' -and "$($_.Attck)" -eq 'T1036.005' }).Count)
Check "R36: missing file in system dir = uncheckable -> high (NOT signed/skipped)" (1 -eq @($r36 | Where-Object { "$($_.Entity)" -eq 'C:\Windows\System32\svchostt.exe' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'uncheckable' }).Count)
Check "R36: signed elsewhere (Program Files) -> low" (1 -eq @($r36 | Where-Object { "$($_.Entity)" -eq 'C:\Program Files\Vendor\svchostx.exe' -and $_.Severity -eq 'low' -and "$($_.Evidence)" -match 'signature Valid' }).Count)
Check "R36: exact svchost.exe in system32 NOT a finding (distance gate)" (0 -eq @($r36 | Where-Object { "$($_.Entity)" -eq 'C:\Windows\System32\svchost.exe' }).Count)
Check "R36: checkable-signed system-dir near-name (svcchost.exe) skipped" (0 -eq @($r36 | Where-Object { "$($_.Entity)" -eq 'C:\Windows\System32\svcchost.exe' }).Count)
Check "R36: distance-3 name (calc.exe) silent" (0 -eq @($r36 | Where-Object { "$($_.Entity)" -match 'calc\.exe' }).Count)
Check "R36: .dll names ignored" (0 -eq @($r36 | Where-Object { "$($_.Entity)" -match 'evil\.dll' }).Count)
Check "R36: no-extension rows skipped" (0 -eq @($r36 | Where-Object { "$($_.Entity)" -match 'notanexe' }).Count)
$huntLogText = Get-Content -LiteralPath $CaseLog -Raw
Check "R36: one trace line rows-in -> hits -> emitted (9 in, 4 hits incl. the skipped signed system-dir copy, 3 out)" ($huntLogText -match [regex]::Escape('R36 lookalike system binary (Levenshtein near-name): amcache+prefetch_parsed+processes+bam_lastexec: 9 rows -> 4 near-name hits -> 3 emitted'))

# ---- run B: 12-finding cap ----
$bulk = @(1..14 | ForEach-Object { $n = "svchost$([char](96 + $_))"; [pscustomobject]@{ Name = "$n.exe"; FullPath = "C:\Users\Public\$n.exe" } })
$script:caseCsv = @{ 'amcache' = $bulk }
$script:sigByPath = @{}
$script:saved = @()
New-HuntFindings
$r36b = @($script:saved | Where-Object { $_.Rule -eq 'Lookalike system binary (Levenshtein near-name)' })
Check "R36: cap - 14 near-name hits emit at most 12" ($r36b.Count -eq 12)
Check "R36: cap emits the FIRST 12 in row order" ("$($r36b[0].Entity)" -eq 'C:\Users\Public\svchosta.exe')
$huntLogText2 = Get-Content -LiteralPath $CaseLog -Raw
Check "R36: cap trace line" ($huntLogText2 -match [regex]::Escape('14 near-name hits -> 12 emitted'))

# ============================================================================
# PART 3 - verdict wiring: R36-high alone fires the hunt signal; low is report-only
# ============================================================================
$tmp = Join-Path $env:TEMP "ophira_v281av_$stamp"
New-Item -ItemType Directory -Path (Join-Path $tmp 'raw') -Force | Out-Null
$RawDir = Join-Path $tmp 'raw'
$MemDir = Join-Path $tmp 'mem'
$CaseDir = $tmp
$global:LogHours = 168
$script:EndpointAdmin = $true
function Test-CaseCsv([string]$n) { return $false }
function Get-DotNetRelease { return 'net4 present' }
function Get-ToolsDir { return $null }
function Test-IsAdmin { return $false }
function Hf36([string]$sev) {
    [pscustomobject]@{ Found = '2026-10-27 12:00:00'; Rule = 'Lookalike system binary (Levenshtein near-name)'; Severity = $sev; Entity = 'C:\Users\Public\scvhost.exe'; Attck = 'T1036.005'; Evidence = "near 'svchost.exe' (distance 2), C:\Users\Public\scvhost.exe, signature uncheckable" }
}
$script:fixtureRows = @{ 'hunt_findings' = @(Hf36 'high') }
$v = Get-CompromiseVerdict
$hunt = @($v.Signals | Where-Object { $_.Signal -like 'Hunt technique*' })
Check "verdict: R36-high row alone -> 'Hunt techniques (1 fired)' weight 2" ($hunt.Count -eq 1 -and $hunt[0].Weight -eq 2 -and $hunt[0].Signal -eq 'Hunt techniques (1 fired)')
Check "verdict: hunt signal detail names the R36 rule" ("$($hunt[0].Detail)" -match [regex]::Escape('Lookalike system binary (Levenshtein near-name) x1'))
$script:fixtureRows = @{ 'hunt_findings' = @(Hf36 'low') }
$v2 = Get-CompromiseVerdict
Check "verdict: R36-low alone adds NO hunt signal (report-only)" (@($v2.Signals | Where-Object { $_.Signal -like 'Hunt technique*' }).Count -eq 0)

# ---- summary ----
Remove-Item -LiteralPath $CaseLog -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -eq 0) { Write-Host "test_v281a: $pass passed, $fail failed" -ForegroundColor Green }
else { Write-Host "test_v281a: $pass passed, $fail failed" -ForegroundColor Red; exit 1 }
