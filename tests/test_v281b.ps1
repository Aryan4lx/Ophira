# test_v281b.ps1 - v2.81 T2: R37 ShimCache temporal correlation (report-only, no verdict signal)
# R37(a): cache-order violation - a cache entry whose last_modified_ts (inside the Raw Entry JSON)
#         is OLDER than the previous entry's -> ONE aggregated low finding with the violation count.
#         Unparseable timestamps are skipped WITHOUT updating the baseline (chain bridges over them).
# R37(b): scrub survivor - user-writable path with NO corroboration (full path OR leaf name) in
#         amcache/prefetch_parsed/bam_lastexec -> medium finding, capped at 6.
# Through the real New-HuntFindings: summary rows/non-entries excluded, aggregated finding shape,
# trace lines, leaf-name corroboration fallback, non-user-writable gate, cap enforcement.
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
foreach ($n in @('Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

# ---- harness (v281a pattern): stub Save-Rows/Write-CaseLog/Import-CaseCsv + disk presence ----
$script:Verbosity = 1
$CaseLog = Join-Path $env:TEMP "ophira_v281b_$stamp.log"
$Computer = 'V281BHOST'
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:saved = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-KnownBadRegexes { return @() }
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return $script:caseCsv[$k] }; return @() }
$script:sigByPath = @{}
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $script:sigByPath["$LiteralPath".ToLower()] }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath, [string]$PathType) return $script:sigByPath.ContainsKey("$LiteralPath".ToLower()) }

# synthetic execution_timeline row - real chainsaw/module-5.4 shape (Raw Entry carries the JSON)
function ShimRow([string]$path, [string]$ts, [int]$n) {
    [pscustomobject]@{
        Timestamp = ''
        'File Path' = $path
        'Program Name' = (Split-Path $path -Leaf)
        'SHA-1 Hash' = ('0' * 40)
        'Timeline Entry Number' = "$n"
        'Entry Type' = 'ShimcacheFileEntry'
        'Timestamp Description' = 'Last Modified (Registry)'
        'Raw Entry' = ('{"cache_entry_position":' + ($n - 1) + ',"controlset":1,"entry_type":{"File":{"path":"' + ($path -replace '\\', '\\') + '"}},"executed":null,"last_modified_ts":"' + $ts + '","path_size":62,"signature":"10ts"}')
    }
}
function RuleRows([string]$rule) { return @($script:saved | Where-Object { $_.Rule -eq $rule }) }

# ============================================================================
# Run A - out-of-order entries -> exactly ONE aggregated low finding, correct N
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @(
        [pscustomobject]@{ Timestamp = '2026-09-28 03:00:00'; 'Timeline Entry Number' = '0'; 'Entry Type' = 'ShimcacheAppCompatRow'; 'File Path' = ''; 'Raw Entry' = '{}' },
        (ShimRow 'C:\Windows\System32\findstr.exe' '2026-09-28T02:09:56.236Z' 1),
        (ShimRow 'C:\Windows\System32\cmd.exe' '2026-09-20T01:00:00.000Z' 2),      # older than prev -> violation
        (ShimRow 'C:\Windows\System32\ping.exe' '2026-09-25T01:00:00.000Z' 3),
        (ShimRow 'C:\Windows\System32\whoami.exe' '2026-09-21T01:00:00.000Z' 4)    # older than prev -> violation
    )
}
$script:saved = @()
New-HuntFindings
$rA = @(RuleRows 'ShimCache order violation')
Check "R37a: 2 out-of-order entries -> exactly ONE aggregated finding" ($rA.Count -eq 1)
Check "R37a: severity low, entity execution_timeline, ATT&CK T1070.006" ($rA[0].Severity -eq 'low' -and "$($rA[0].Entity)" -eq 'execution_timeline' -and "$($rA[0].Attck)" -eq 'T1070.006')
Check "R37a: detail carries the real count (2)" ("$($rA[0].Evidence)" -eq 'ShimCache order violation: 2 out-of-order entries (timestomping or cache manipulation)')
Check "R37b: system32 paths are never scrub survivors" ((RuleRows 'ShimCache scrub survivor').Count -eq 0)
$huntLogText = Get-Content -LiteralPath $CaseLog -Raw
Check "R37a: one trace line rows -> entries -> violations" ($huntLogText -match [regex]::Escape('R37 ShimCache order violation: execution_timeline: 5 rows -> 4 entries -> 2 out-of-order'))

# ============================================================================
# Run B - all in order (with an unparseable row mid-chain) -> no finding, chain intact
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @(
        (ShimRow 'C:\Windows\System32\findstr.exe' '2026-09-01T01:00:00.000Z' 1),
        (ShimRow 'C:\Windows\System32\cmd.exe' 'not-a-timestamp' 2),               # unparseable -> bridged over
        (ShimRow 'C:\Windows\System32\ping.exe' '2026-09-02T01:00:00.000Z' 3)
    )
}
$script:saved = @()
New-HuntFindings
Check "R37a: all-in-order (unparseable row bridged) -> no finding" ((RuleRows 'ShimCache order violation').Count -eq 0)

# ============================================================================
# Run C - unparseable row must NOT poison the baseline: C older than A still counts 1
# (a MinValue-seeded or chain-breaking implementation would wrongly report 0)
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @(
        (ShimRow 'C:\Windows\System32\findstr.exe' '2026-09-01T01:00:00.000Z' 1),
        (ShimRow 'C:\Windows\System32\cmd.exe' 'garbage-ts' 2),
        (ShimRow 'C:\Windows\System32\ping.exe' '2026-08-25T01:00:00.000Z' 3)
    )
}
$script:saved = @()
New-HuntFindings
$rC = @(RuleRows 'ShimCache order violation')
Check "R37a: unparseable row skipped WITHOUT baseline update -> violation vs last good entry" ($rC.Count -eq 1 -and "$($rC[0].Evidence)" -match [regex]::Escape(': 1 out-of-order entries'))

# ============================================================================
# Run D - scrub survivor: user-writable path, zero corroboration -> ONE medium finding
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @( (ShimRow 'C:\Users\Public\evil.exe' '2026-09-28T02:09:56.236Z' 1) )
    'amcache' = @( [pscustomobject]@{ Name = 'benign.exe'; FullPath = 'C:\Windows\System32\benign.exe' } )
    'prefetch_parsed' = @()
    'bam_lastexec' = @()
}
$script:saved = @()
New-HuntFindings
$rD = @(RuleRows 'ShimCache scrub survivor')
Check "R37b: uncorroborated user-writable path -> exactly ONE medium finding" ($rD.Count -eq 1 -and $rD[0].Severity -eq 'medium')
Check "R37b: entity = the path, detail verbatim, ATT&CK T1070.006" ("$($rD[0].Entity)" -eq 'C:\Users\Public\evil.exe' -and "$($rD[0].Evidence)" -eq 'executed (ShimCache) but absent from all execution corroboration sources - possible cache scrubbing' -and "$($rD[0].Attck)" -eq 'T1070.006')
$huntLogText = Get-Content -LiteralPath $CaseLog -Raw
Check "R37b: trace line paths -> survivors -> emitted (after cap)" ($huntLogText -match [regex]::Escape('R37 ShimCache scrub survivor: corroboration amcache+prefetch_parsed+bam_lastexec: 1 paths -> 1 survivors -> 1 emitted'))

# ============================================================================
# Run E - leaf-name corroboration fallback -> NOT a finding
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @( (ShimRow 'C:\Users\Public\evil.exe' '2026-09-28T02:09:56.236Z' 1) )
    'amcache' = @( [pscustomobject]@{ Name = 'evil.exe'; FullPath = 'C:\Windows\Temp\cache\evil.exe' } )
}
$script:saved = @()
New-HuntFindings
Check "R37b: leaf-name match in another source corroborates -> NOT a finding" ((RuleRows 'ShimCache scrub survivor').Count -eq 0)

# ============================================================================
# Run F - non-user-writable path -> NOT a finding (even with zero corroboration)
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @( (ShimRow 'C:\Windows\System32\findstr.exe' '2026-09-28T02:09:56.236Z' 1) )
}
$script:saved = @()
New-HuntFindings
Check "R37b: non-user-writable path -> NOT a finding" ((RuleRows 'ShimCache scrub survivor').Count -eq 0)

# ============================================================================
# Run G - cap 6: 8 distinct survivors emit the FIRST 6 in row order
# ============================================================================
$script:caseCsv = @{
    'execution_timeline' = @(1..8 | ForEach-Object { ShimRow "C:\Users\Public\tool$('{0:d2}' -f $_).exe" '2026-09-28T02:09:56.236Z' $_ })
}
$script:saved = @()
New-HuntFindings
$rG = @(RuleRows 'ShimCache scrub survivor')
Check "R37b: cap - 8 survivors emit exactly 6" ($rG.Count -eq 6)
Check "R37b: cap emits the FIRST 6 in row order" ("$($rG[0].Entity)" -eq 'C:\Users\Public\tool01.exe' -and "$($rG[5].Entity)" -eq 'C:\Users\Public\tool06.exe')
$huntLogText = Get-Content -LiteralPath $CaseLog -Raw
Check "R37b: cap trace line shows 8 survivors -> 6 emitted" ($huntLogText -match [regex]::Escape('8 paths -> 8 survivors -> 6 emitted'))

# ============================================================================
# Run H - missing execution_timeline degrades to trace + skip, never crashes
# ============================================================================
$script:caseCsv = @{}
$script:saved = @()
New-HuntFindings
Check "R37: missing execution_timeline -> no findings, no crash" ((RuleRows 'ShimCache order violation').Count -eq 0 -and (RuleRows 'ShimCache scrub survivor').Count -eq 0)
$huntLogText = Get-Content -LiteralPath $CaseLog -Raw
Check "R37: both trace lines still present on the degrade path" ($huntLogText -match [regex]::Escape('R37 ShimCache order violation: execution_timeline: 0 rows -> 0 entries -> 0 out-of-order') -and $huntLogText -match [regex]::Escape('R37 ShimCache scrub survivor: corroboration amcache+prefetch_parsed+bam_lastexec: 0 paths -> 0 survivors -> 0 emitted'))

# ============================================================================
# R37 is report-only: neither exact rule name may appear in Get-CompromiseVerdict source
# (case-sensitive: lowercase 'shimcache' legitimately appears in the artifact-spine coverage label)
# ============================================================================
$vsrc = [regex]::Match($src, '(?s)function Get-CompromiseVerdict \{.*?\r?\n\}').Value
Check "R37: no verdict signal wired (exact rule names absent from Get-CompromiseVerdict source)" (($vsrc -cnotmatch 'ShimCache order violation') -and ($vsrc -cnotmatch 'ShimCache scrub survivor'))

Write-Host ''
if ($fail -eq 0) { Write-Host "test_v281b: ALL $pass CHECKS PASSED" -ForegroundColor Green; exit 0 }
Write-Host "test_v281b: $fail of $($pass + $fail) checks FAILED" -ForegroundColor Red
exit 1
