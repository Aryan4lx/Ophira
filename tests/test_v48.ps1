# test_v48.ps1 - SRUM analyst-side completion honesty (v5.0)
# The verdict must SAY when SRUM egress analysis is pending (raw DB copied,
# deep-parse analyst-side) instead of silently diverging from the post-Parse verdict.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw

$checks = 0
function Check { param($name, $ok) $script:checks++; if (-not $ok) { Write-Host "  [FAIL] $name"; $script:failed = $true } else { Write-Host "  [ok] $name" } }
$script:failed = $false

# P1: the caveat exists, in the verdict engine, wired to the right conditions
Check 'verdict has SRUM pending caveat'        ($src -match [regex]::Escape("SRUM network usage copied but not deep-parsed yet - run -Mode Parse with the analyst toolkit; upload-egress signals may appear then"))
Check 'caveat gates on raw SRUDB.dat'          ($src -match '(?s)if \(\(Test-Path \(Join-Path \$script:RawDir ''sru\\SRUDB\.dat''\)\) -and -not \(Test-CaseCsv ''srum_usage''\)\) \{ \$caveats\.Add\(''SRUM network usage')
$iVd  = $src.IndexOf('function Get-CompromiseVerdict')
$iCav = $src.IndexOf('SRUM network usage copied but not deep-parsed yet')
$iRg  = $src.IndexOf('function Invoke-RegenerateOutputs')
Check 'caveat sits inside the verdict engine'  (($iVd -lt $iCav) -and ($iCav -lt $iRg))
Check 'why-note explains the divergence design' ($src -match "net9, never shipped")

# P2: version
Check 'header bumped to v5.1' ($src -match 'Ophira v5\.1  -  Windows Endpoint Triage Toolkit')
Check 'ScriptVersion 5.1'     ($src -match '\$ScriptVersion = "5\.1"')

# P3: functional - the caveat condition is a pure expression; evaluate its logic shape
# by simulating the two branches with a sandboxed Test-Path/Test-CaseCsv pair.
$condMet = $false
$fakeRaw = Join-Path $env:TEMP ("oph_t48_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fakeRaw 'sru') -Force | Out-Null
Set-Content -Path (Join-Path $fakeRaw 'sru\SRUDB.dat') -Value 'x'
$script:caseCsv = @{}
function Test-CaseCsv { param($Name) return $null -ne $script:caseCsv[$Name] }
$condMet = ((Test-Path (Join-Path $fakeRaw 'sru\SRUDB.dat')) -and -not (Test-CaseCsv 'srum_usage'))
Check 'caveat condition TRUE for fresh collection (raw DB, no srum_usage)' ($condMet -eq $true)
$script:caseCsv['srum_usage'] = @([pscustomobject]@{ Application = 'x' })
$condMet = ((Test-Path (Join-Path $fakeRaw 'sru\SRUDB.dat')) -and -not (Test-CaseCsv 'srum_usage'))
Check 'caveat condition FALSE after analyst-side parse' ($condMet -eq $false)
Remove-Item -Recurse -Force $fakeRaw

Write-Host ''
if ($script:failed) { Write-Host "test_v48 FAILED ($script:checks checks)"; exit 1 }
Write-Host "test_v48: all $script:checks checks passed"
exit 0
