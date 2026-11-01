$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# test_v290.ps1 - v2.90: focus expansion port-drift brake + indicator-scoped dossier trail
#                  + user-activity rollup (leaf-key merge, parsed last-seen)
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function Read-Host { param([string]$Prompt) return '' }
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# static wiring
# ============================================================================
Check "focus: no port expansion in the matched-row term pull" (-not $src.Contains('& $addPort $v'))
Check "focus: addPort block removed" (-not $src.Contains('$addPort = {'))
Check "focus: drift-brake comment explains the proxy-port bridge" ($src -match [regex]::Escape('bridge unrelated processes'))
Check "report: dossier trail is indicator-scoped (fIndLeaf)" ($src.Contains('$fIndLeaf') -and $src.Contains('"*$fIndLeaf*"'))
Check "report: trail no longer folds every expanded name in" (-not $src.Contains('foreach ($fn2 in @($ft.Names))'))
Check "useract: account rows keyed on the leaf after the backslash" ($src.Contains('("$disp2" -split ''\\'')[-1].ToLower()'))
Check "useract: 4688 rows keyed the same way" ($src.Contains('("$disp3" -split ''\\'')[-1].ToLower()'))
Check "useract: display upgrades to the domain-qualified name" ($src.Contains('if ("$($u2.Name)" -notmatch ''\\'' -and "$disp2" -match ''\\'') { $u2.Name = $disp2 }'))
Check "useract: last-seen uses parsed ticks (uaTicks)" (([regex]::Matches($src, [regex]::Escape('& $uaTicks'))).Count -ge 4)

# ============================================================================
# engine: the port bridge must NOT pull the proxy client into the dossier
# ============================================================================
$defs = ''
foreach ($n in @('Open-CaseSession', 'Invoke-FocusEngine', 'Invoke-FocusCore')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
$mapM = [regex]::Match($src, '(?s)\$script:CsvCatMap = @\{.*?\r?\n\}')
$gcpM = [regex]::Match($src, "(?s)function Get-CaseCsvPath \{.*?\r?\n\}")
if (-not $mapM.Success -or -not $gcpM.Success) { throw 'extract failed: CsvCatMap/Get-CaseCsvPath' }
Invoke-Expression ($mapM.Value + "`r`n" + $gcpM.Value + "`r`n" + $defs)
$ScriptVersion = '2.90'

$case = Join-Path $env:TEMP "ophira_v290_$stamp"
$csv = Join-Path $case 'csv'
New-Item -ItemType Directory -Path (Join-Path $csv 'logs') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $case 'case.json') -Value '{"Computer":"FT","CaseID":"V290","StartedUTC":"2026-11-01T10:00:00Z"}' -Encoding UTF8

# xray.exe: a process + its two public connections + a listener on the local proxy port
New-Csv (Join-Path $csv 'processes.csv') '"Name","PID","PPID","Path","Created"' @(
    '"xray.exe","23128","1000","E:\Apps\v2rayn\bin\xray\xray.exe","2026-11-01 09:00:00"'
)
New-Csv (Join-Path $csv 'connections.csv') '"Time","Proto","LocalAddress","LocalPort","RemoteAddress","RemotePort","State","PID","ProcessPath","Public"' @(
    '"2026-11-01 10:29:13","TCP","192.168.1.13","58324","202.50.253.27","19999","Established","23128","E:\Apps\v2rayn\bin\xray\xray.exe","True"',
    '"2026-11-01 10:29:13","TCP","192.168.1.13","54128","202.50.253.27","19999","Established","23128","E:\Apps\v2rayn\bin\xray\xray.exe","True"',
    '"2026-11-01 10:29:10","TCP","127.0.0.1","10808","0.0.0.0","0","Listening","23128","E:\Apps\v2rayn\bin\xray\xray.exe","False"'
)
# firefox: the proxy CLIENT - only relation to xray is the shared 10808 port
New-Csv (Join-Path $csv 'prefetch_parsed.csv') '"ExecutableName","RunCount","LastRun","SourceFile"' @(
    '"XRAY","223","2026-11-01 05:39:41","XRAY.EXE-B7EED243.pf"',
    '"FIREFOX","1674","2026-11-01 06:46:31","FIREFOX.EXE-66015FD1.pf"'
)

$ok = Invoke-FocusEngine -Path $case -Indicator 'xray.exe'
Check "engine: name seed returns success" ($ok -eq $true)

$terms = $null
try { $terms = Get-Content -LiteralPath (Join-Path (Join-Path $case 'focus') 'focus_terms.json') -Raw | ConvertFrom-Json } catch { }
Check "terms: json written" ($terms -and [int]$terms.HitCount -gt 0)
Check "terms: indicator name present" (@($terms.Names | Where-Object { $_ -match 'xray' }).Count -ge 1)
Check "BRAKE: proxy client firefox NOT expanded via the shared port" (@($terms.Names | Where-Object { $_ -match 'firefox' }).Count -eq 0)
Check "BRAKE: firefox prefetch row not among the hits" (@(Import-Csv -LiteralPath (Join-Path (Join-Path $case 'focus') 'focus_hits.csv') | Where-Object { "$($_.Detail)" -match '(?i)firefox' }).Count -eq 0)
Check "xray connections still matched (exact indicator rows)" (@(Import-Csv -LiteralPath (Join-Path (Join-Path $case 'focus') 'focus_hits.csv') | Where-Object { "$($_.Source)" -eq 'connections' }).Count -ge 2)

# user-activity rollup logic replicated from the report block (same key/merge/ticks rules)
$ua = [ordered]@{}
$uaTicks = { param([string]$s) $d = [datetime]::MinValue; if ($s -and [datetime]::TryParse($s, [ref]$d)) { $d.Ticks } else { [long]::MinValue } }
foreach ($a in @(
    [pscustomobject]@{ Time = '11/1/2026 9:58:14 AM'; Acct = 'SYSTEM'; Dom = 'NT AUTHORITY'; Ev = '4624' },
    [pscustomobject]@{ Time = '11/1/2026 1:59:54 PM'; Acct = 'SYSTEM'; Dom = 'NT AUTHORITY'; Ev = '4624' },
    [pscustomobject]@{ Time = '11/1/2026 12:00:00 PM'; Acct = 'DESKTOP-88Q1H74\Aryan'; Dom = ''; Ev = '4624' },
    [pscustomobject]@{ Time = '11/1/2026 12:05:00 PM'; Acct = 'Aryan'; Dom = ''; Ev = '4688' }
)) {
    $disp = "$(if ("$($a.Dom)" -and "$($a.Dom)" -ne '-') { "$($a.Dom)\" })$($a.Acct)".Trim('\')
    $k = ("$disp" -split '\\')[-1].ToLower()
    if (-not $ua.Contains($k)) { $ua[$k] = @{ Name = $disp; N = 0; Last = '' } }
    $u = $ua[$k]
    if ("$($u.Name)" -notmatch '\\' -and "$disp" -match '\\') { $u.Name = $disp }
    $u.N++
    if ((& $uaTicks "$($a.Time)") -gt (& $uaTicks "$($u.Last)")) { $u.Last = "$($a.Time)" }
}
Check "useract: SYSTEM one row, last seen is the PM event (not lexically-greater AM)" ($ua['system'].N -eq 2 -and $ua['system'].Last -eq '11/1/2026 1:59:54 PM')
Check "useract: bare 4688 account merges into the domain-qualified row" ($ua['aryan'].N -eq 2 -and $ua['aryan'].Name -eq 'DESKTOP-88Q1H74\Aryan')

Remove-Item -Recurse -Force $case -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
exit 0
