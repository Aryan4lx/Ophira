# test_v259.ps1 - SRUM wakes up (SrumECmd analyst-side deep parse) + timeline sparkline
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: ConvertFrom-SrumCsv against the REAL SrumECmd output header shape ----
$m = [regex]::Match($src, "(?s)function ConvertFrom-SrumCsv \{.*?\r?\n\}")
if (-not $m.Success) { throw 'ConvertFrom-SrumCsv extract failed' }
Invoke-Expression $m.Value

$tmp = Join-Path $env:TEMP ("ophira_v259_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

# exact real header/rows (spiked 2026-10-13 against SrumECmd 2026.5.0 on a live SRUDB.dat)
$nuReal = @'
Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesReceived,BytesSent,InterfaceLuid,InterfaceType,L2ProfileFlags,L2ProfileId,ProfileName
1,2026-08-18 22:54:00,Spooler,,,LocalSystem,S-1-5-18,systemprofile,6,310,0,0,0,0,0,0,
3,2026-09-01 03:11:00,\Device\HarddiskVolume3\Users\Aryan\AppData\Roaming\tool.exe,,,UnknownOrUserSid,S-1-5-21-500,aryan,2,77,3000,5000,19985273102270464,IF_TYPE_IEEE80211,0,268435457,
'@
$nuPath = Join-Path $tmp 'usages.csv'
Set-Content -LiteralPath $nuPath -Value $nuReal -Encoding UTF8

$u = @(ConvertFrom-SrumCsv -Path $nuPath)
Check "usage: all rows normalized" ($u.Count -eq 2)
Check "usage: Application carries the SRUM ExeInfo (entity binFromRow + report consumer match)" ($u[1].Application -eq '\Device\HarddiskVolume3\Users\Aryan\AppData\Roaming\tool.exe')
Check "usage: User + bytes columns mapped" ($u[1].User -eq 'aryan' -and $u[1].BytesSent -eq '5000' -and $u[1].BytesReceived -eq '3000')
Check "missing file -> @()" (@(ConvertFrom-SrumCsv -Path (Join-Path $tmp 'nope.csv')).Count -eq 0)
Set-Content -LiteralPath (Join-Path $tmp 'bad.csv') -Value "not,a,csv`r`n`"unterminated" -Encoding UTF8
$noCrash = $false
try { $null = @(ConvertFrom-SrumCsv -Path (Join-Path $tmp 'bad.csv')); $noCrash = $true } catch { }
Check "garbage file -> no crash (rows or @(), never throws)" $noCrash

# ---- behavioral: the weave picks up SRUM usage and skips zero-traffic rows ----
$m = [regex]::Match($src, "(?s)function New-SuperTimeline \{.*?\r?\n\}")
if (-not $m.Success) { throw 'New-SuperTimeline extract failed' }
Invoke-Expression $m.Value
$fixtureRows = @{
    'srum_usage' = @(
        [pscustomobject]@{ Timestamp = '2026-09-01 03:11:00'; Application = 'tool.exe'; User = 'aryan'; BytesSent = '5000'; BytesReceived = '3000'; InterfaceType = 'IF_TYPE_IEEE80211' }
        [pscustomobject]@{ Timestamp = '2026-09-01 04:11:00'; Application = 'Spooler'; User = 'systemprofile'; BytesSent = '0'; BytesReceived = '0'; InterfaceType = '' }
    )
}
function Import-CaseCsv([string]$name) { if ($fixtureRows.ContainsKey($name)) { return $fixtureRows[$name] }; return @() }
function Get-CaseCsvFullPath([string]$n) { Join-Path $tmp 'supertimeline.csv' }
function Get-CaseCsvPath([string]$n) { "derived\$n.csv" }
function Get-HayabusaExe { return $null }
function Write-CaseLog([string]$m2, [object]$c2) { }
New-SuperTimeline
$st = @(Import-Csv -LiteralPath (Join-Path $tmp 'supertimeline.csv'))
$usageHit = @($st | Where-Object { $_.Source -eq 'srum_usage' -and $_.Type -eq 'app network usage (SRUM)' })
Check "weave: real-traffic usage row woven" ($usageHit.Count -eq 1 -and $usageHit[0].Entity -eq 'tool.exe' -and $usageHit[0].Detail -eq 'sent 5000 / recv 3000 bytes')
Check "weave: zero-traffic usage row skipped (cap spent on real events)" (@($st | Where-Object { $_.Entity -eq 'Spooler' }).Count -eq 0)

# ---- statics: wiring ----
Check "module 5.3 SRUM copy is default-on" ($src -match [regex]::Escape("Id = '5.3'; Cat = 'ARTIFACTS'; Name = 'SRUM database (larger, uses VSS copy)'; Default = `$true"))
Check "module 5.4 no longer parses SRUM endpoint-side (one deep parser, analyst-side)" (-not ($src -match [regex]::Escape("'analyse', 'srum'")))
Check "Setup catalog: SrumECmd net9 analyst-side" ($src -match [regex]::Escape("Name = 'SrumECmd';    Direct = 'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'; Zip = `$true; Target = 'analyst'"))
Check "parse mode: SrumECmd block wired" ($src -match [regex]::Escape('SrumECmd: SRUM per-app network usage'))
Check "parse mode: guarded on collected raw SRUDB + not-already-imported" ($src -match [regex]::Escape("-not (Test-CaseCsv 'srum_usage')"))
Check "sortment map: srum_usage = artifacts" ($src -match [regex]::Escape("'srum_usage' = 'artifacts'"))
Check "parse_needed: srum_usage row" ($src -match [regex]::Escape("Artifact = 'srum_usage.csv';         Parser = 'SrumECmd'"))
Check "NetworkConnections deliberately not imported (opaque AppId, zero attribution)" ($src -match [regex]::Escape('every row carries an opaque AppId with no ExeInfo'))
Check "no srum_connections artifact anywhere" (-not ($src -match 'srum_connections'))
Check "sparkline: activity-per-day card rendered" ($src -match [regex]::Escape('<b>Activity per day</b>'))
Check "sparkline: inline SVG bars with tooltips" ($src -match [regex]::Escape("<svg viewBox='0 0 `$sw `$sh'"))
Check "sparkline: busiest day highlighted" ($src -match [regex]::Escape('#e0a93e'))

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { Write-Host "`ntest_v259: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v259: $pass passed, 0 failed" -ForegroundColor Green
exit 0
