# test_v56.ps1 - -Mode Share client-safe bundle (v5.6, ADR-0006)
# Extracts Invoke-ShareMode + stubs Open-CaseSession/Get-KitRoot; feeds a synthetic
# case fixture and asserts the bundle contents, stripping, redaction swap, README,
# zip, auto-detect and guards. House style: Check() + exit code.
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw

$script:fail = 0; $script:n = 0
function Check([string]$name, [bool]$ok) {
    $script:n++
    if ($ok) { Write-Host "[ok] $name" } else { $script:fail++; Write-Host "[FAIL] $name" -ForegroundColor Red }
}

# --- extract Invoke-ShareMode (column-0 closing brace house regex) ---
$m = [regex]::Match($src, '(?s)function Invoke-ShareMode \{.*?\r?\n\}')
Check 'extract Invoke-ShareMode' $m.Success
. ([scriptblock]::Create($m.Value))

# --- stubs ---
$script:Version = '5.6-test'
function Get-KitRoot { return $script:kitRoot }
function Write-CaseLog([string]$m, [object]$c) { }
function Open-CaseSession([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $script:CaseDir = $Path
    $script:OpenCaseTmp = $null
    $cj = Join-Path $Path 'case.json'
    if (-not (Test-Path $cj)) { return $null }
    return Get-Content $cj -Raw | ConvertFrom-Json
}

# --- fixture ---
$script:kitRoot = Join-Path $env:TEMP ("ophira_t56_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:kitRoot -Force | Out-Null
function New-Case([string]$dir) {
    New-Item -ItemType Directory -Path (Join-Path $dir 'csv\volatile') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $dir 'raw') -Force | Out-Null
    Set-Content (Join-Path $dir 'case.json') '{"Computer":"HOSTX","CaseID":"C-1","Analyst":"aryan","ClientName":"acme"}' -Encoding UTF8
    Set-Content (Join-Path $dir 'report.html') '<html>ORIGINAL</html>' -Encoding UTF8
    Set-Content (Join-Path $dir 'ophira_findings.json') '{"schema":"ophira-findings/1"}' -Encoding UTF8
    Set-Content (Join-Path $dir 'ANALYST-START-HERE.txt') 'start here' -Encoding UTF8
    Set-Content (Join-Path $dir 'csv\volatile\processes.csv') 'Name' -Encoding UTF8
    Set-Content (Join-Path $dir 'raw\evil.exe') 'MZ' -Encoding UTF8
    Set-Content (Join-Path $dir 'tools.ps1') 'echo bad' -Encoding UTF8
}
$caseA = Join-Path $script:kitRoot 'OPHIRA_HOSTX_1'
New-Case $caseA
Set-Content (Join-Path $caseA 'report_redacted.html') '<html>REDACTED</html>' -Encoding UTF8
Set-Content (Join-Path $caseA 'redact_map.csv') 'Type,Original' -Encoding UTF8
Set-Content (Join-Path $caseA 'verdict.json') '{"level":"SUSPICIOUS","confidence_percent":85}' -Encoding UTF8

# --- T1: redacted bundle ---
Invoke-ShareMode -CasePath $caseA
$dest = Join-Path $script:kitRoot 'share\OPHIRA_HOSTX_1'
Check 'T1 dest created' (Test-Path $dest)
Check 'T1 report swapped to redacted' ((Get-Content (Join-Path $dest 'report.html') -Raw).Trim() -eq '<html>REDACTED</html>')
Check 'T1 redacted duplicate removed' (-not (Test-Path (Join-Path $dest 'report_redacted.html')))
Check 'T1 redact_map stripped' (-not (Test-Path (Join-Path $dest 'redact_map.csv')))
Check 'T1 exe stripped' (-not (Test-Path (Join-Path $dest 'raw\evil.exe')))
Check 'T1 ps1 stripped' (-not (Test-Path (Join-Path $dest 'tools.ps1')))
Check 'T1 evidence kept' (Test-Path (Join-Path $dest 'csv\volatile\processes.csv'))
Check 'T1 findings kept' (Test-Path (Join-Path $dest 'ophira_findings.json'))
$rm = Get-Content (Join-Path $dest 'SHARE-README.txt') -Raw
Check 'T1 README client' ($rm -match 'acme')
Check 'T1 README verdict' ($rm -match 'SUSPICIOUS - 85% evidence coverage')
Check 'T1 README redacted flag' ($rm -match 'REDACTED copy')
Check 'T1 README names stripped files' ($rm -match 'raw\\evil\.exe')
Check 'T1 original untouched: report' ((Get-Content (Join-Path $caseA 'report.html') -Raw).Trim() -eq '<html>ORIGINAL</html>')
Check 'T1 original untouched: map' (Test-Path (Join-Path $caseA 'redact_map.csv'))

# --- T2: unredacted warning ---
$caseB = Join-Path $script:kitRoot 'OPHIRA_HOSTY_2'
New-Case $caseB
Invoke-ShareMode -CasePath $caseB
$destB = Join-Path $script:kitRoot 'share\OPHIRA_HOSTY_2'
Check 'T2 report stays original' ((Get-Content (Join-Path $destB 'report.html') -Raw).Trim() -eq '<html>ORIGINAL</html>')
Check 'T2 README warns unredacted' ((Get-Content (Join-Path $destB 'SHARE-README.txt') -Raw) -match 'WARNING: no redacted copy')

# --- T3: zip ---
$caseC = Join-Path $script:kitRoot 'OPHIRA_HOSTZ_3'
New-Case $caseC
Invoke-ShareMode -CasePath $caseC -ShareZip
$zp = Join-Path $script:kitRoot 'share\OPHIRA_HOSTZ_3.zip'
Check 'T3 zip created' (Test-Path $zp)
Check 'T3 zip non-empty' ((Get-Item $zp).Length -gt 100)

# --- T4/T5: auto-detect newest vs -ParsePath pin ---
# auto: two candidates -> newest by name desc = OPHIRA_HOSTZ_3
$script:CaseDir = ''
Invoke-ShareMode
Check 'T4 auto-detect picks newest name' ($script:CaseDir -like '*OPHIRA_HOSTZ_3')
$script:CaseDir = ''
Invoke-ShareMode -CasePath $caseB
Check 'T5 -ParsePath pin wins' ($script:CaseDir -eq $caseB)

# --- T6: dest inside case guard ---
Invoke-ShareMode -CasePath $caseA -OutDir (Join-Path $caseA 'inner')
Check 'T6 dest-inside-case refused' (-not (Test-Path (Join-Path $caseA 'inner')))

# --- T7: no verdict.json -> honest README ---
$caseD = Join-Path $script:kitRoot 'OPHIRA_HOSTW_4'
New-Case $caseD
Invoke-ShareMode -CasePath $caseD
Check 'T7 README no-verdict honest' ((Get-Content (Join-Path $script:kitRoot 'share\OPHIRA_HOSTW_4\SHARE-README.txt') -Raw) -match 'not generated')

# --- structural pins ---
Check 'wire: ValidateSet has Share' ($src.Contains("'SeedIocs', 'Share', 'Help'"))
Check 'wire: dispatch arm' ($src.Contains('Invoke-ShareMode -CasePath $ParsePath -OutDir $SharePath'))
Check 'wire: ShareZip param' ($src.Contains('[switch]$ShareZip'))
Check 'wire: menu key S' ($src.Contains('^(?i)s$'))
Check 'wire: help entry' ($src.Contains('.PARAMETER ShareZip'))

# --- cleanup ---
Remove-Item $script:kitRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host "test_v56: $script:n checks, $script:fail failed"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
