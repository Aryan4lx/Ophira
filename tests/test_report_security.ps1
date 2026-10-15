# v2.63 hardening test: HTML report XSS + escaping + elevation fallback
# 1. poisoned hayabusa Details -> no raw </script><img anywhere in report.html
# 2. the var RULES = embed line carries no raw '<'
# 3. planted Level '"><img src=x>' renders escaped in the drill-down level options
# 4. case.json WITHOUT AdminElevated -> banner reads 'Elevated: unknown' (no live-probe)
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath $repoScript -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$names = @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'New-AttackLayer', 'New-SiemExport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel', 'Get-CleanCheckSummary')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$case = Join-Path $env:TEMP ("ophira_sec_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, $rawDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

@'
"RealTimeProtection","AMServiceEnabled","AntispywareEnabled","AntivirusSigAgeDays","QuickScanAge","FullScanAge","LastQuickScan"
"True","True","True","2","1","30","2026-09-25"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'defender_status.csv') -Encoding UTF8
@'
"ThreatName","SeverityID","IsActive","Resources"
"Trojan:Win32/Emotet",4,"True","file:C:\Users\u\evil.exe"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'defender_threats.csv') -Encoding UTF8
@'
"Source","Target","Type"
"TERMSRV","10.0.0.5","DOMAIN/ADMIN"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'saved_credentials.csv') -Encoding UTF8
@'
"Target","UsernameHint","LastUsed"
"10.1.2.3","admin@corp","2026-09-24"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'rdp_client_targets.csv') -Encoding UTF8
@'
"DisplayName","OwnerAccount","JobState","TransferType","Files"
"suspicious_download","CORP\u","Suspended","Download","C:\Users\u\out.zip"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'bits_jobs.csv') -Encoding UTF8
@'
"Timestamp","Computer","EventID","Level","RuleTitle","Details","MitreTactics","MitreTags"
"2026-09-24 10:00:00.000 +00:00","TESTHOST","1","high","Suspicious PowerShell","-enc command","Exec","T1059.001"
"2026-09-24 10:05:00.000 +00:00","TESTHOST","1","low","Run key persistence","reg add","Persis","T1547.001"
"2026-09-24 10:05:00.000 +00:00","TESTHOST","1","info","Same as above","","Persis","T1547.001"
"2026-09-24 10:06:00.000 +00:00","TESTHOST","1","""><img src=x>","Run key persistence","</script><img src=x onerror=alert(1)>","Persis","T1547.001"
"2026-09-24 10:07:00.000 +00:00","TESTHOST","1","""><img src=x>","Poison Alpha","","Exec","T1505.001"
"2026-09-24 10:08:00.000 +00:00","TESTHOST","1","high""><img src=y>","Poison Beta","note","Exec","T1136.001"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'hayabusa_timeline.csv') -Encoding UTF8
# 35-row fixture: caption must say 'First 30 of 35' when only 30 are shown
$psLines = @('"Timestamp","Channel","EventID","DecodedText"') + (1..35 | ForEach-Object { '"2026-09-24 12:{0:00}:00","PowerShell/Operational","4104","decoded command {0}"' -f $_ })
$psLines | Set-Content -LiteralPath (Join-Path $csvDir 'ps_decoded_commands.csv') -Encoding UTF8
@'
"Severity","Rank","Process","RemoteIp","Port","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"
"high",3,"C:\Users\u\beacon.exe","203.0.113.10","443",60,59,59,0.04,1,"public-ip;user-path"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'beacon_candidates.csv') -Encoding UTF8
@'
"WindowStart","WriteEvents","DistinctFiles"
"2026-09-25 08:30",4200,900
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'usn_write_bursts.csv') -Encoding UTF8

foreach ($empty in @('yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'mft_recent', 'prefetch_parsed', 'asep_sweep', 'certificates')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# sanity: the poisoned fixture parses back to the intended raw values
$fx = @(Import-Csv -LiteralPath (Join-Path $csvDir 'hayabusa_timeline.csv'))
$poisonRow = @($fx | Where-Object { "$($_.Details)" -match 'onerror' })[0]
Check "fixture: poisoned Level parses to raw payload" ("$($poisonRow.Level)" -eq '"><img src=x>')
Check "fixture: poisoned Details parses to raw payload" ("$($poisonRow.Details)" -eq '</script><img src=x onerror=alert(1)>')

$v = Get-CompromiseVerdict
$script:Verdict = $v
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

$rulesLine = [regex]::Match($html, 'var RULES = [^\r\n]*').Value
Check "xss: no raw '</script><img' anywhere in report" (-not $html.Contains('</script><img'))
Check "xss: var RULES = line found" ($rulesLine.Length -gt 0)
Check "xss: var RULES = line has no raw '<'" ($rulesLine.Length -gt 0 -and -not ($rulesLine -match '<'))
Check "xss: poisoned Details still present escaped (drill-down data intact)" ($rulesLine.Contains('\u003c/script\u003e'))
Check "xss: poisoned Level option rendered escaped" ($html.Contains('<option>&quot;&gt;&lt;img src=x&gt;</option>'))
Check "xss: no raw injection inside level <option> elements" (-not ($html -match '<option>[^<]*<[a-z]'))
Check "elevation: case.json without AdminElevated -> 'Elevated: unknown'" ($html -match 'Elevated: unknown')

# carried XSS sinks (Task 2): raw Level reached the Sigma top table, drill-down summary,
# ATT&CK level cell and tactic-group cell - the payloads must not render raw ANYWHERE
foreach ($payload in @('"><img src=x>', 'high"><img src=y>')) {
    Check "xss: Level payload '$payload' escaped at ALL sinks (whole document)" (-not $html.Contains($payload))
}

# report correctness: caption must not lie about how many rows are shown
Check "caption: 35-row fixture reads 'First 30 of 35 recovered commands'" ($html.Contains('First 30 of 35 recovered commands'))
Check "caption: no lying 'First 35 recovered commands'" (-not $html.Contains('First 35 recovered commands'))

# print flow: @media print must not hide <details>, and print listeners must open/restore them
$printCss = [regex]::Match($html, '@media print\{[^\r\n]*').Value
Check "print: @media print stylesheet found" ($printCss.Length -gt 0)
Check "print: CSS no longer hides <details> when printing" ($printCss.Length -gt 0 -and -not $printCss.Contains('details'))
Check "print: beforeprint listener opens closed details" ($html -match "addEventListener\('beforeprint'")
Check "print: afterprint listener re-closes them" ($html -match "addEventListener\('afterprint'")

# carried XSS sink (Task 3): the fleet report's Sigma top-table level cell interpolates raw $lvl
# render the REAL fleet block (extracted verbatim from Invoke-AnalyzeMode) against a poisoned feed
$fleetDir = Join-Path $env:TEMP ("ophira_fleet_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $fleetDir -Force | Out-Null
@'
"Computer","RuleTitle","Level","MitreTags"
"HOST1","Poison Rule","""><img src=x>",""
'@ | Set-Content -LiteralPath (Join-Path $fleetDir 'fleet_hay.csv') -Encoding UTF8
$fm = [regex]::Match($src, '(?s)\$fsb = New-Object System\.Text\.StringBuilder.*?Set-Content -LiteralPath \$fleetHtml -Encoding UTF8')
if (-not $fm.Success) { throw 'extract failed: fleet render block' }
$OutFolder = $fleetDir; $fleetHtml = Join-Path $OutFolder 'fleet_report.html'
$hayOut = Join-Path $OutFolder 'fleet_hay.csv'; $Path = Join-Path $OutFolder 'case.zip'
$ScriptVersion = '9.99'
$hosts = @([pscustomobject]@{ Host = 'HOST1'; Verdict = 'CLEAN'; VerdictRank = 0; Confidence = 50; Role = 'workstation'; Collected = 'yes' })
$findings = @(); $highRisk = @(); $crossHost = @(); $proposedTrusted = @()
$lateral = New-Object System.Collections.Generic.List[object]
Invoke-Expression $fm.Value
$fleetHtmlText = Get-Content -LiteralPath $fleetHtml -Raw
Check "fleet: raw Level payload absent from fleet_report.html" (-not $fleetHtmlText.Contains('"><img src=x>'))
Check "fleet: payload rendered escaped in level cell" ($fleetHtmlText.Contains("&quot;&gt;&lt;img src=x&gt;</td>"))
Check "fleet: no raw tag injection inside level cells" (-not ($fleetHtmlText -match "<td class='(?:crit|high|med|info)'>[^<]*<[a-z]"))
Remove-Item -LiteralPath $fleetDir -Recurse -Force -ErrorAction SilentlyContinue

# second case: 5-row ps_decoded_commands (<=30 caption branch) + a dir WITHOUT hayabusa_timeline.csv
$case2 = Join-Path $env:TEMP ("ophira_sec2_" + (Get-Date -Format 'HHmmss'))
$csvDir2 = Join-Path $case2 'csv'; $rawDir2 = Join-Path $case2 'raw'
New-Item -ItemType Directory -Path $csvDir2, $rawDir2 -Force | Out-Null
Copy-Item -Path (Join-Path $csvDir '*') -Destination $csvDir2
Remove-Item -LiteralPath (Join-Path $csvDir2 'hayabusa_timeline.csv') -Force
$psLines2 = @('"Timestamp","Channel","EventID","DecodedText"') + (1..5 | ForEach-Object { '"2026-09-24 12:{0:00}:00","PowerShell/Operational","4104","small case command {0}"' -f $_ })
$psLines2 | Set-Content -LiteralPath (Join-Path $csvDir2 'ps_decoded_commands.csv') -Encoding UTF8
$CaseDir = $case2; $CsvDir = $csvDir2; $RawDir = $rawDir2

# Get-CleanCheckSummary -HayRows: with rows passed it must NOT re-read hayabusa_timeline.csv
# (proven by rendering in a case dir where that csv does not exist)
$cleanHay = @($fx | Where-Object { "$($_.Level)" -eq 'low' -or "$($_.Level)" -eq 'info' })
$sigNo = @(); $sigYes = @()
try { $sumNo = @(Get-CleanCheckSummary); $sigNo = @($sumNo | Where-Object { "$($_.Check)" -eq 'Sigma rule scan' }) } catch { }
try { $sumYes = @(Get-CleanCheckSummary -HayRows $cleanHay); $sigYes = @($sumYes | Where-Object { "$($_.Check)" -eq 'Sigma rule scan' }) } catch { }
Check "cleancheck: without -HayRows and no csv -> no Sigma entry (import path intact)" ($sigNo.Count -eq 0)
Check "cleancheck: -HayRows renders the Sigma entry without re-reading the csv" ($sigYes.Count -eq 1 -and "$($sigYes[0].Detail)" -eq "$($cleanHay.Count) events scanned, 0 critical/high detections")

$v2 = Get-CompromiseVerdict; $script:Verdict = $v2
$null = New-HtmlReport
$html2 = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "caption: 5-row fixture reads 'First 5 recovered commands'" ($html2.Contains('First 5 recovered commands'))
Check "caption: small case has no lying 'of 5' suffix" (-not $html2.Contains('First 5 of 5 recovered commands'))
Remove-Item -LiteralPath $case2 -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $CaseDir" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
