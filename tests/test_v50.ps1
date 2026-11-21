# v5.0 Track 5 - E2E fixture gate: build the synthetic xray.exe case, Parse it, assert the
# full pipeline produces the expected derived artifacts + verdict. Runs the REAL script
# end-to-end (in-process child, throwaway dir) - CI-runnable, no tools/cases needed.
$ErrorActionPreference = 'Stop'
$script:Fail = 0
$repo = Split-Path -Parent $PSScriptRoot
$ophira = Join-Path $repo 'Ophira.ps1'
function Check($name, $ok, $detail = '') {
    if ($ok) { Write-Host "  [ok] $name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "  [FAIL] $name $detail" -ForegroundColor Red }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("oph_e2e_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'make_fixture_case.ps1') -Dest $tmp | Out-Null
Check 'fixture built' ((Test-Path (Join-Path $tmp 'case.json')) -and (Test-Path (Join-Path $tmp 'csv\defender\defender_threats.csv')))

$out = & $ophira -Mode Parse -ParsePath $tmp 2>&1 | Out-String
Check 'parse exit 0' ($LASTEXITCODE -eq 0)

$v = $null
$vf = Join-Path $tmp 'verdict.json'
if (Test-Path $vf) { $v = Get-Content $vf -Raw | ConvertFrom-Json }
Check 'verdict.json produced' ($null -ne $v)
Check 'verdict Level = SUSPICIOUS' ("$($v.Level)" -eq 'SUSPICIOUS') "got $($v.Level)"
$sig = @(); if ($null -ne $v.Signals) { $sig = @($v.Signals) }
Check 'verdict signals >= 2' ($sig.Count -ge 2) "got $($sig.Count)"
Check 'Defender detection signal present' (@($sig | Where-Object { "$($_.Signal)" -match 'Defender detection' }).Count -ge 1)
Check 'hunt-technique signal present' (@($sig | Where-Object { "$($_.Signal)" -match 'Hunt techniques' }).Count -ge 1)

$hf = @(Import-Csv (Join-Path $tmp 'csv\derived\hunt_findings.csv') -ErrorAction SilentlyContinue)
Check 'hunt findings >= 3' ($hf.Count -ge 3) "got $($hf.Count)"
$rules = ($hf | ForEach-Object { "$($_.Rule)" }) -join ' | '
Check 'R? encoded-command finding' ($rules -match 'encoded command')
Check 'R36 lookalike finding' ($rules -match 'Lookalike system binary')
Check 'R50 known-bad name finding' ($rules -match 'Known-bad name pattern')
Check 'no explorer false-high' ($rules -notmatch 'Misplaced system binary.*explorer')

$cd = @(Import-Csv (Join-Path $tmp 'csv\connections_dns.csv') -ErrorAction SilentlyContinue)
Check 'connections_dns 2 rows' ($cd.Count -eq 2) "got $($cd.Count)"
$xrayRow = @($cd | Where-Object { "$($_.RemoteAddress)" -eq '203.0.113.66' })[0]
Check 'xray connection resolved via DNS cache' ($null -ne $xrayRow -and "$($xrayRow.ResolvedDomain)" -match 'evil-cdn\.net')

$tc = @(Import-Csv (Join-Path $tmp 'csv\derived\exec_tcorr.csv') -ErrorAction SilentlyContinue)
Check 't-corr pair found (powershell -> xray chain)' ($tc.Count -ge 1)

$tl = @(Import-Csv (Join-Path $tmp 'csv\derived\supertimeline.csv') -ErrorAction SilentlyContinue)
Check 'supertimeline >= 15 events' ($tl.Count -ge 15) "got $($tl.Count)"

$eb = @(Import-Csv (Join-Path $tmp 'csv\derived\entities_binaries.csv') -ErrorAction SilentlyContinue)
$xrayEnt = @($eb | Where-Object { "$($_.Name)" -eq 'xray.exe' -and ([int]"0$($_.CatCount)") -ge 3 })[0]
Check 'xray entity card multi-source (live+exec+net+file)' ($null -ne $xrayEnt) "cats=$($xrayEnt.CatCount)"

$leads = @(Import-Csv (Join-Path $tmp 'csv\derived\leads.csv') -ErrorAction SilentlyContinue)
Check 'triage leads >= 3' ($leads.Count -ge 3) "got $($leads.Count)"

$report = Join-Path $tmp 'report.html'
Check 'report.html rendered' ((Test-Path $report) -and ((Get-Item $report).Length -gt 20000))
Check 'report shows SUSPICIOUS' ((Get-Content $report -Raw).Contains('SUSPICIOUS'))
Check 'focus dossier built' (Test-Path (Join-Path $tmp 'focus\focus_report.html'))
$siem = Join-Path $tmp 'siem_export.ndjson'
Check 'SIEM export records' ((Test-Path $siem) -and (@(Get-Content $siem).Count -ge 3))

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($script:Fail -gt 0) { Write-Host "test_v50: $($script:Fail) failed" -ForegroundColor Red; exit 1 }
Write-Host 'test_v50: fixture E2E gate passed' -ForegroundColor Green
exit 0
