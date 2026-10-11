$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.51 - analyst QoL + correlation + integration: -Mode Watch (live detonation diff),
# dormancy + prefetch-mismatch correlation notes in the focus dossier, STIX 2.1 export,
# fleet hash pivot (fleet_hashes.csv), copy-all-IOCs button, print CSS, -ExitVerdict,
# -Mode SeedIocs.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
$fix = Join-Path ([IO.Path]::GetTempPath()) "ophira_v251_$stamp"
New-Item -ItemType Directory -Path $fix -Force | Out-Null

# ============================================================================
# PART 1 - static wiring
# ============================================================================
Check "params: Watch + SeedIocs in ValidateSet; -WatchInterval/-SeedValue/-ExitVerdict" ((($src -match [regex]::Escape("'Canary', 'Focus', 'Watch', 'SeedIocs'"))) -and ($src -match [regex]::Escape('[int]$WatchInterval = 15')) -and ($src -match [regex]::Escape('[string]$SeedValue = ''''')) -and ($src -match [regex]::Escape('[switch]$ExitVerdict')))
Check "menu: [W] entry + dispatch (menu and -Mode sites)" ((($src -match [regex]::Escape("'^(?i)w$' { return 'Watch' }"))) -and ($src -match [regex]::Escape("'Watch' { Invoke-WatchMode | Out-Null }")) -and ($src -match [regex]::Escape("'Watch' { Invoke-WatchMode -Interval `$WatchInterval | Out-Null }")))
Check "watch: rolling diff state (proc/net/autorun/defender) + baseline tick" ((($src -match [regex]::Escape('$state = @{ Proc = @{}; Net = @{}; Auto = @{}; DefCount = -1 }'))) -and ($src -match 'tick 1 is the baseline') -and ($src -match 'baseline: \{0\} process'))
Check "watch: [PROC]/[NET]/[AUTORUN]/[DEFEND] diff lines + not-elevated degrade" ((($src -match '\[PROC\]')) -and ($src -match '\[NET\]') -and ($src -match '\[AUTORUN\]') -and ($src -match '\[DEFEND\]') -and ($src -match 'not elevated: command lines of other users'))
Check "exitverdict: both exit sites map verdict rank >= 2" ((@([regex]::Matches($src, [regex]::Escape('if ($ExitVerdict -and $script:Verdict)'))).Count -eq 2) -and ($src -match [regex]::Escape('if ($rank -ge 2) { exit $rank }')))
Check "stix: bundle writer in New-CaseIocExport" (($src -match 'ioc_export_stix\.json') -and ($src -match [regex]::Escape("[file:hashes.'SHA-256' = '`$(`$r.Value)']")) -and ($src -match [regex]::Escape("spec_version = '2.1'")))
Check "fleet: fleet_hashes.csv + hash-pivot console + html section" ((($src -match [regex]::Escape("Join-Path `$OutFolder 'fleet_hashes.csv'"))) -and ($src -match 'HASH PIVOT: ') -and ($src -match 'Fleet hash pivot \(same binary on multiple hosts'))
Check "qol: copy-all-IOCs button + print stylesheet" ((($src -match [regex]::Escape('copyIocAll(this)'))) -and ($src -match [regex]::Escape("id='iocblock'")) -and ($src -match '@media print'))
Check "evidence index: stix mention in the ioc_export entry" ($src -match [regex]::Escape('STIX 2.1 bundle next to it for MISP/OpenCTI'))

# ============================================================================
# PART 2 - SeedIocs through the real function
# ============================================================================
$mSeed = [regex]::Match($src, "(?s)function Invoke-SeedIocsMode \{.*?\r?\n\}")
if (-not $mSeed.Success) { throw 'extract failed: Invoke-SeedIocsMode' }
$toolsDir = Join-Path $fix 'tools'
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $toolsDir 'iocs.txt') -Value "# existing feed`n203.0.113.50" -Encoding ASCII
function Get-ToolsDir { $script:toolsDir }
Invoke-Expression $mSeed.Value
$ok1 = Invoke-SeedIocsMode -Value 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999'
$ok2 = Invoke-SeedIocsMode -Value '198.51.100.77'
$ok3 = Invoke-SeedIocsMode -Value 'Evil-Example.COM'
$ok4 = Invoke-SeedIocsMode -Value 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999'
$ok5 = Invoke-SeedIocsMode -Value 'not a valid indicator!!'
$iocsTxt = @(Get-Content -LiteralPath (Join-Path $toolsDir 'iocs.txt'))
Check "seediocs: hash + ip + domain appended (domain lowercased)" (($ok1 -and $ok2 -and $ok3) -and (@($iocsTxt | Where-Object { $_ -match '^AAAABBBB.*9999 # seeded' }).Count -eq 1) -and (@($iocsTxt | Where-Object { $_ -match '^198\.51\.100\.77 # seeded' }).Count -eq 1) -and (@($iocsTxt | Where-Object { $_ -match '^evil-example\.com # seeded' }).Count -eq 1))
Check "seediocs: duplicate and garbage rejected" (($ok4 -eq $true) -and ($ok5 -eq $false) -and (@($iocsTxt | Where-Object { $_ -match '^AAAABBBB' }).Count -eq 1))
Check "seediocs: existing feed entries untouched" (@($iocsTxt | Where-Object { $_ -eq '203.0.113.50' }).Count -eq 1)

# ============================================================================
# PART 3 - STIX export through the real New-CaseIocExport + round-trip via the real Get-IocList
# ============================================================================
$mExport = [regex]::Match($src, "(?s)function New-CaseIocExport \{.*?\r?\n\}")
$mIoc = [regex]::Match($src, "(?s)function Get-IocList \{.*?\r?\n\}")
if (-not $mExport.Success -or -not $mIoc.Success) { throw 'extract failed: New-CaseIocExport/Get-IocList' }
$RawDir = Join-Path $fix 'raw'
New-Item -ItemType Directory -Path $RawDir -Force | Out-Null
$Computer = 'FT'; $script:CurrentCaseID = 'C-51'
$caseCsv = @{
    'process_hashes'         = @([pscustomobject]@{ Name = 'malware.exe'; Path = 'C:\Users\dev\AppData\Roaming\malware.exe'; SHA256 = '1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF' })
    'flash_process_scored'   = @([pscustomobject]@{ PID = '4812'; Name = 'malware.exe'; Path = 'C:\Users\dev\AppData\Roaming\malware.exe'; Score = '9'; Verdict = 'HIGH'; Evidence = 'x' })
    'yara_hits'              = @()
    'beacon_candidates'      = @([pscustomobject]@{ Severity = 'high'; Rank = '3'; Process = 'p'; RemoteIp = '185.199.10.7'; Port = '443'; Events = '38'; SpanMin = '190'; MedianIntervalSec = '60'; Jitter = '0.06'; Regularity = '0.94'; Flags = '' })
    'dns_beacon_candidates'  = @([pscustomobject]@{ Severity = 'high'; Rank = '1'; Process = 'p'; Domain = 'Evil-C2.example'; Events = '90'; SpanMin = '180'; MedianIntervalSec = '120'; Jitter = '0.05'; Regularity = '0.95'; Flags = '' })
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
function Get-IocList { $null }
function Save-Rows { param([string]$Name, $Rows) }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression $mExport.Value
New-CaseIocExport
$stixPath = Join-Path $RawDir 'analysis\ioc_export_stix.json'
$bundle = $null
try { $bundle = Get-Content -LiteralPath $stixPath -Raw | ConvertFrom-Json } catch { }
Check "stix: valid bundle JSON with 3 indicator objects" ($bundle -and "$($bundle.type)" -eq 'bundle' -and @($bundle.objects).Count -eq 3 -and @(@($bundle.objects) | Where-Object { "$($_.id)" -match '^indicator--' }).Count -eq 3)
Check "stix: patterns cover sha256 + ipv4 + domain, case-attributed" ((@($bundle.objects | Where-Object { "$($_.pattern)" -eq "[file:hashes.'SHA-256' = '1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF']" }).Count -eq 1) -and (@($bundle.objects | Where-Object { "$($_.pattern)" -eq "[ipv4-addr:value = '185.199.10.7']" }).Count -eq 1) -and (@($bundle.objects | Where-Object { "$($_.pattern)" -match 'domain-name:value' -and "$($_.pattern)" -match 'evil-c2\.example' }).Count -eq 1) -and (@($bundle.objects | Where-Object { "$($_.description)" -match 'C-51 / FT' }).Count -eq 3))
# round-trip: the exported bundle ingests through the REAL Get-IocList STIX reader
$feedDir = Join-Path $toolsDir 'iocs'
New-Item -ItemType Directory -Path $feedDir -Force | Out-Null
Copy-Item -LiteralPath $stixPath -Destination (Join-Path $feedDir 'case_C-51.json')
Remove-Item -LiteralPath (Join-Path $toolsDir 'iocs.txt') -Force -ErrorAction SilentlyContinue
Invoke-Expression $mIoc.Value
$iocs2 = Get-IocList
Check "stix round-trip: real Get-IocList ingests the exported bundle" ($iocs2 -and ($iocs2.Hashes.ContainsKey('1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF')) -and ($iocs2.Ips.ContainsKey('185.199.10.7')) -and ($iocs2.Domains.ContainsKey('evil-c2.example')))

# ============================================================================
# PART 4 - Watch mode: no live loop (statics only); focus cues functional in test_focus
# ============================================================================
Check "watch: Ctrl+C-safe finally + collection pointer" (($src -match 'watch ended after \$tick tick') -and ($src -match 'run the collection now to capture everything seen'))

Write-Host ""
Write-Host "test_v251: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $fix -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 }
