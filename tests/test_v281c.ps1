# test_v281c.ps1 - v2.81 T3: R38 execution hour-of-day stacking + report histogram
# Part 1: R38 through the real New-HuntFindings (stubbed csvs): off-hours burst at 03:00
#         (9 distinct -> low), same 9 at 14:00 silent, window edges (20:00 fires, 07:00
#         silent), non-.exe counts toward burst but not staging, 10 .exe -> Mass binary
#         staging / 9 silent, unparseable timestamps skipped, first-seen dedupe (within a
#         source across hours, cross-source within an hour, case-insensitive), one R38
#         trace line placed after its findings.
# Part 2: report histogram via the REAL inline block extracted from New-HtmlReport
#         extracted from New-HtmlReport: 24 div bars, hour labels, injection payloads
#         neutralized (quote payload escaped by ConvertTo-HtmlEsc; <script> payload cannot
#         survive Split-Path -Leaf at all), caption naming sources + dedupe rule,
#         max-scaled heights with 1px floor.
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
foreach ($n in @('Get-InvariantDate', 'Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'Test-IsPublicIp', 'ConvertTo-HtmlEsc', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

# ---- harness stubs (v281a pattern) ----
$script:Verbosity = 1
$CaseLog = Join-Path $env:TEMP "ophira_v281c_$stamp.log"
$Computer = 'V281HOST'
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:saved = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-KnownBadRegexes { return @() }
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return $script:caseCsv[$k] }; return @() }
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $null }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath, [string]$PathType) return $false }
function Test-CaseCsv([string]$n) { return $false }
function Get-Changes { return @() }
function Invoke-RegenerateOutputs { }
function Get-ToolsDir { return $null }

function Run-Hunt { $script:saved = @(); New-HuntFindings; return (Get-Content -LiteralPath $CaseLog -Raw) }
$script:caseCsv = @{}

# ============================================================================
# PART 1 - R38 through the real New-HuntFindings
# ============================================================================
$burstRule = 'Off-hours execution burst'
$stageRule = 'Mass binary staging'

# ---- run A: 9 distinct binaries first seen at 03:00 -> one low burst finding ----
$script:caseCsv = @{
    'amcache' = @(1..9 | ForEach-Object { $n = 'r38a{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 03:{0:d2}:00' -f ($_ * 6 % 60)) } })
}
$logA = Run-Hunt
$r38a = @($script:saved | Where-Object { $_.Rule -eq $burstRule })
Check "R38: 9 distinct at 03:00 -> exactly 1 burst finding" ($r38a.Count -eq 1)
Check "R38: burst finding low severity, empty ATT&CK (report-only)" ($r38a[0].Severity -eq 'low' -and "$($r38a[0].Attck)" -eq '')
Check "R38: burst entity '03:00-03:59'" ("$($r38a[0].Entity)" -eq '03:00-03:59')
Check "R38: burst detail exact wording" ("$($r38a[0].Evidence)" -eq '9 distinct binaries first seen 03:00-03:59 (off-hours window 20:00-06:59)')
Check "R38: no staging finding at 9 .exe" (0 -eq @($script:saved | Where-Object { $_.Rule -eq $stageRule }).Count)
Check "R38: exactly one trace line for R38" (1 -eq @([regex]::Matches($logA, '(?m)^\[[\d:]+\] R38 ')).Count)
Check "R38: trace placed AFTER its findings (counts 1 finding, 1 low)" ($logA -match [regex]::Escape('R38 execution hour-of-day stacking: amcache+prefetch_parsed+security_proc_events+sysmon_proc_create: 9 rows -> 9 first-seen binaries -> 1 off-hours burst + 0 staging findings -> 1 finding (1 low)'))

# ---- run B: same 9 binaries at 14:00 -> silent (daytime, under staging floor) ----
$script:caseCsv = @{
    'amcache' = @(1..9 | ForEach-Object { $n = 'r38a{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 14:{0:d2}:00' -f ($_ * 6 % 60)) } })
}
$logB = Run-Hunt
Check "R38: same 9 at 14:00 -> no burst, no staging" (0 -eq @($script:saved | Where-Object { $_.Rule -eq $burstRule -or $_.Rule -eq $stageRule }).Count)
Check "R38: daytime trace counts 0 findings" ($logB -match [regex]::Escape('9 rows -> 9 first-seen binaries -> 0 off-hours burst + 0 staging findings -> 0 findings'))

# ---- run C: 10 first-seen .exe staged at 09:00 -> Mass binary staging ----
$script:caseCsv = @{
    'prefetch_parsed' = @(1..10 | ForEach-Object { $n = 'r38s{0:d2}.exe' -f $_; [pscustomobject]@{ Executable = $n; LastRun = ('2026-10-05 09:{0:d2}:00' -f ($_ * 5 % 60)) } })
}
$logC = Run-Hunt
$r38c = @($script:saved | Where-Object { $_.Rule -eq $stageRule })
Check "R38: 10 .exe at 09:00 -> exactly 1 staging finding" ($r38c.Count -eq 1)
Check "R38: staging low, entity '09:00-09:59', empty ATT&CK" ($r38c[0].Severity -eq 'low' -and "$($r38c[0].Entity)" -eq '09:00-09:59' -and "$($r38c[0].Attck)" -eq '')
Check "R38: staging detail exact wording" ("$($r38c[0].Evidence)" -eq '10 first-seen .exe binaries staged 09:00-09:59')
Check "R38: no burst finding at 09:00 (not off-hours)" (0 -eq @($script:saved | Where-Object { $_.Rule -eq $burstRule }).Count)

# ---- run D: 9 .exe + 2 .dll in one daytime hour -> silent (staging is .exe-only, floor 10) ----
$script:caseCsv = @{
    'prefetch_parsed' = @((1..9 | ForEach-Object { $n = 'r38s{0:d2}.exe' -f $_; [pscustomobject]@{ Executable = $n; LastRun = ('2026-10-05 09:{0:d2}:00' -f ($_ * 5 % 60)) } }) +
                          @([pscustomobject]@{ Executable = 'r38x.dll'; LastRun = '2026-10-05 09:55:00' }, [pscustomobject]@{ Executable = 'r38y.dll'; LastRun = '2026-10-05 09:56:00' }))
}
$logD = Run-Hunt
Check "R38: 9 .exe + 2 .dll -> no staging (dll excluded), no burst" (0 -eq @($script:saved | Where-Object { $_.Rule -eq $stageRule -or $_.Rule -eq $burstRule }).Count)
Check "R38: dll rows counted as first-seen in trace (11 rows)" ($logD -match [regex]::Escape('11 rows -> 11 first-seen binaries -> 0 off-hours burst + 0 staging findings -> 0 findings'))

# ---- run E: non-.exe counts toward burst; window edges 20 fires / 07 silent; hour order ----
$script:caseCsv = @{
    'amcache' = @((1..7 | ForEach-Object { $n = 'r38e{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 23:{0:d2}:00' -f ($_ * 7 % 60)) } }) +
                  @([pscustomobject]@{ Name = 'r38e.dll'; FullPath = 'C:\Users\Public\r38e.dll'; Timestamp = '2026-10-05 23:58:00' }) +
                  (1..8 | ForEach-Object { $n = 'r38f{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 20:{0:d2}:00' -f ($_ * 6 % 60)) } }) +
                  (1..8 | ForEach-Object { $n = 'r38g{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 07:{0:d2}:00' -f ($_ * 6 % 60)) } }))
}
$logE = Run-Hunt
$r38e = @($script:saved | Where-Object { $_.Rule -eq $burstRule })
Check "R38: 7 .exe + 1 .dll at 23:00 + 8 .exe at 20:00 -> 2 bursts; hour 07 (>=7) silent" ($r38e.Count -eq 2)
Check "R38: bursts ordered by hour (20 before 23)" ("$($r38e[0].Entity)" -eq '20:00-20:59' -and "$($r38e[1].Entity)" -eq '23:00-23:59')
Check "R38: non-.exe binary counts toward burst (23:00 has 8 distinct incl. 1 dll)" ("$($r38e[1].Evidence)" -eq '8 distinct binaries first seen 23:00-23:59 (off-hours window 20:00-06:59)')

# ---- run F: unparseable/missing timestamps skipped; first-seen dedupe (same src across
#      hours, cross-source within an hour); empty leaf skipped ----
$script:caseCsv = @{
    'amcache' = @(
        [pscustomobject]@{ Name = 'r38d01.exe'; FullPath = 'C:\Users\Public\r38d01.exe'; Timestamp = 'not-a-date' },
        [pscustomobject]@{ Name = 'r38d02.exe'; FullPath = 'C:\Users\Public\r38d02.exe' },
        [pscustomobject]@{ Name = 'r38d03.exe'; FullPath = 'C:\Users\Public\r38d03.exe'; Timestamp = '2026-10-05 02:05:00' },
        [pscustomobject]@{ Name = 'r38d03.exe'; FullPath = 'C:\Users\Public\r38d03.exe'; Timestamp = '2026-10-05 22:30:00' },
        [pscustomobject]@{ Path = ''; Timestamp = '2026-10-05 02:06:00' }
    ) + (4..10 | ForEach-Object { $n = 'r38d{0:d2}.exe' -f $_; [pscustomobject]@{ Name = $n; FullPath = "C:\Users\Public\$n"; Timestamp = ('2026-10-05 02:{0:d2}:00' -f ($_ * 7 % 60)) } }) +
        @([pscustomobject]@{ Name = 'r38m.exe'; FullPath = 'C:\Users\Public\r38m.exe'; Timestamp = '2026-10-05 04:00:00' })
    'prefetch_parsed' = @(
        [pscustomobject]@{ Executable = 'r38m.exe'; LastRun = '2026-10-05 04:10:00' },
        [pscustomobject]@{ Executable = 'R38M.EXE'; LastRun = '2026-10-05 04:12:00' }
    ) + (1..6 | ForEach-Object { $n = 'r38n{0:d2}.exe' -f $_; [pscustomobject]@{ Executable = $n; LastRun = ('2026-10-05 04:{0:d2}:00' -f ($_ * 8 % 60)) } })
}
$logF = Run-Hunt
$r38f = @($script:saved | Where-Object { $_.Rule -eq $burstRule })
Check "R38: unparseable + missing timestamps skipped, empty leaf skipped" ($r38f.Count -eq 1 -and "$($r38f[0].Entity)" -eq '02:00-02:59')
Check "R38: first-seen wins within a source (r38d03 re-seen 22:30 does not split buckets)" ("$($r38f[0].Evidence)" -eq '8 distinct binaries first seen 02:00-02:59 (off-hours window 20:00-06:59)')
Check "R38: cross-source same-leaf dedupe (r38m + case-insensitive re-run = 7 distinct at 04:00 -> silent)" (0 -eq @($r38f | Where-Object { "$($_.Entity)" -eq '04:00-04:59' }).Count -and 0 -eq @($script:saved | Where-Object { $_.Rule -eq $stageRule }).Count)
Check "R38: broken rows never poison the trace counts (21 rows in, 16 first-seen)" ($logF -match [regex]::Escape('21 rows -> 16 first-seen binaries -> 1 off-hours burst + 0 staging findings -> 1 finding (1 low)'))

# ============================================================================
# PART 2 - report histogram: real Get-ExecHourBuckets + real render block
# ============================================================================
# fixtures: hour 8 gets 3 distinct first-seen (cmd.exe seen by 2 sources in the same hour
# collapses to 1; its 14:00 replay is NOT first-seen), hour 5 gets a quote-injection
# payload leaf, hour 6 gets a <script> payload leaf
$script:caseCsv = @{
    'amcache' = @(
        [pscustomobject]@{ Name = 'explorer.exe'; FullPath = 'C:\Windows\explorer.exe'; Timestamp = '2026-10-05 08:15:00' },
        [pscustomobject]@{ Name = 'svchost.exe'; FullPath = 'C:\Windows\System32\svchost.exe'; Timestamp = '2026-10-05 08:45:00' },
        [pscustomobject]@{ Name = 'cmd.exe'; FullPath = 'C:\Windows\System32\cmd.exe'; Timestamp = '2026-10-05 08:20:00' },
        [pscustomobject]@{ Name = 'x'' onerror=alert(1) x.exe'; Timestamp = '2026-10-05 05:30:00' },
        [pscustomobject]@{ Name = '<script>alert(1)</script>.exe'; Timestamp = '2026-10-05 06:30:00' }
    )
    'prefetch_parsed' = @(
        [pscustomobject]@{ Executable = 'cmd.exe'; LastRun = '2026-10-05 08:05:00' },
        [pscustomobject]@{ Executable = 'cmd.exe'; LastRun = '2026-10-05 14:00:00' }
    )
}
$sb = New-Object System.Text.StringBuilder
$m = [regex]::Match($src, '(?s)\$h38Seen = @\{\}.*?\$h38Cells\.ToString\(\).*?\r?\n    \}')
if (-not $m.Success) { throw 'extract failed: histogram render block' }
Invoke-Expression $m.Value
$html = $sb.ToString()

Check "histogram: 5 first-seen binaries total (cmd replay at 14:00 excluded)" ($h38Total -eq 5)
Check "histogram: hour 8 = 3 distinct (cross-source same-leaf collapsed)" ($h38Counts[8] -eq 3)
Check "histogram: hours 5/6 = 1 each, hour 14 absent (first-seen hour wins)" ($h38Counts[5] -eq 1 -and $h38Counts[6] -eq 1 -and -not $h38Counts.ContainsKey(14))

Check "histogram: exactly 24 bar elements" (24 -eq @([regex]::Matches($html, [regex]::Escape('position:absolute;bottom:0;left:0;width:18px'))).Count)
$labelsOk = $true
foreach ($h in 0..23) { if ($html -notmatch [regex]::Escape(('>{0:d2}</div>' -f $h))) { $labelsOk = $false } }
Check "histogram: hour labels 00..23 all present" $labelsOk
Check "histogram: exactly one full-height 64px bar (the max bucket, hour 8)" (1 -eq @([regex]::Matches($html, [regex]::Escape('height:64px;background:'))).Count)
Check "histogram: zero buckets render 1px floor (21 bars)" (21 -eq @([regex]::Matches($html, 'height:1px')).Count)
Check "histogram: proportional bars for the two 1-binary hours (64/3 ~ 21px)" (2 -eq @([regex]::Matches($html, 'height:21px')).Count)
Check "histogram: quote payload escaped in tooltip (ConvertTo-HtmlEsc)" ($html.Contains('x&#39; onerror=alert(1) x.exe') -and -not $html.Contains("x' onerror"))
Check "histogram: <script> payload never appears raw (escaper + Split-Path both strip it)" ($html -notmatch [regex]::Escape('<script>'))
Check "histogram: no JS, no canvas, no svg" ($html -notmatch '(?i)<script|canvas|<svg')
Check "histogram: caption names all sources" ($html.Contains('amcache + prefetch_parsed + 4688 + Sysmon EID1'))
Check "histogram: caption states dedupe rule" ($html.Contains('first-seen per binary, deduped across sources'))

# ---- summary ----
Remove-Item -LiteralPath $CaseLog -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -eq 0) { Write-Host "test_v281c: $pass passed, $fail failed" -ForegroundColor Green }
else { Write-Host "test_v281c: $pass passed, $fail failed" -ForegroundColor Red; exit 1 }
