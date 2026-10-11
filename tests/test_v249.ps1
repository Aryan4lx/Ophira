$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.49 - bundled Sysmon config removed (Ophira never deploys Sysmon; it parses whatever
# telemetry the endpoint's own config produces), IOC feedback loop (case -> fleet memory:
# New-CaseIocExport + feed-hash x process_hashes xref), R3 uncapped DOT graph export.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
$fix = Join-Path ([IO.Path]::GetTempPath()) "ophira_v249_$stamp"
New-Item -ItemType Directory -Path $fix -Force | Out-Null

# ============================================================================
# PART 1 - removal + static wiring
# ============================================================================
Check "removal: no bundled Sysmon config in the repo" (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\sysmon')))
Check "removal: config-gap hint names the endpoint's own config, no kit pointer" (($src -match "endpoint's own Sysmon config") -and ($src -notmatch 'ophira-sysmon\.xml'))
Check "removal: setup inventory no longer mentions the config" ($src -notmatch 'recommended Sysmon config')
Check "sortment: ioc_hits_hash + ioc_export mapped to derived" (($src -match [regex]::Escape("'ioc_hits_hash' = 'derived'")) -and ($src -match [regex]::Escape("'ioc_export' = 'derived'")))
Check "evidence index: entries for ioc_hits_hash + ioc_export" (($src -match [regex]::Escape("'ioc_hits_hash'                   =")) -and ($src -match [regex]::Escape("'ioc_export'                      =")))
Check "verdict: known-bad-hash-in-execution-history signal (floor 2)" ($src -match "Add-Signal 'IOC hit - known-bad binary hash in execution history' 2")
Check "regen: New-CaseIocExport runs in the shared pipeline" ($src -match 'try \{ New-CaseIocExport \}')
Check "report: defanged block gains hash hits + fleet-memory pointer" (($src -match [regex]::Escape("Import-CaseCsv 'ioc_hits_hash'")) -and ($src -match 'Fleet memory:'))
Check "focus: uncapped DOT export wired" ($src -match [regex]::Escape('focus_graph.dot'))

# ============================================================================
# PART 2 - New-CaseIocExport through the real function
# ============================================================================
$mExport = [regex]::Match($src, "(?s)function New-CaseIocExport \{.*?\r?\n\}")
if (-not $mExport.Success) { throw 'extract failed: New-CaseIocExport' }
$RawDir = Join-Path $fix 'raw'
New-Item -ItemType Directory -Path $RawDir -Force | Out-Null
$Computer = 'FT'; $script:CurrentCaseID = 'C-49'
$feedHash = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999'
$yaraHash = '1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF'
function Get-IocList {
    @{ Hashes = @{ $feedHash = $true }; Sha1 = @{}; Ips = @{}; Domains = @{}; Names = @{}; Feed = @{ $feedHash = 'prior-case' } }
}
$caseCsv = @{
    'process_hashes'         = @(
        [pscustomobject]@{ Name = 'malware.exe'; Path = 'C:\Users\dev\AppData\Roaming\malware.exe'; SHA256 = $feedHash },
        [pscustomobject]@{ Name = 'implant.dll'; Path = 'C:\Users\dev\AppData\Roaming\implant.dll'; SHA256 = $yaraHash }
    )
    'flash_process_scored'   = @(
        [pscustomobject]@{ PID = '4812'; Name = 'malware.exe'; Path = 'C:\Users\dev\AppData\Roaming\malware.exe'; Score = '9'; Verdict = 'HIGH'; Evidence = 'runs-from-user-path' },
        [pscustomobject]@{ PID = '500'; Name = 'notepad.exe'; Path = 'C:\Windows\System32\notepad.exe'; Score = '0'; Verdict = 'LOW'; Evidence = '' }
    )
    'yara_hits'              = @([pscustomobject]@{ Time = '2026-10-05 14:20:00'; Binary = 'C:\Users\dev\AppData\Roaming\implant.dll'; Rule = 'MALWARE_FAMILY_Test'; Score = 'high'; Detail = 'YARA match on flagged binary' })
    'beacon_candidates'      = @(
        [pscustomobject]@{ Severity = 'high'; Rank = '3'; Process = 'C:\Users\dev\AppData\Roaming\malware.exe'; RemoteIp = '185.199.10.7'; Port = '443'; Events = '38'; SpanMin = '190'; MedianIntervalSec = '60'; Jitter = '0.06'; Regularity = '0.94'; Flags = 'user-path' },
        [pscustomobject]@{ Severity = 'medium'; Rank = '2'; Process = ''; RemoteIp = '198.51.100.9'; Port = '8443'; Events = '12'; SpanMin = '60'; MedianIntervalSec = '120'; Jitter = '0.10'; Regularity = '0.88'; Flags = '' }
    )
    'dns_beacon_candidates'  = @([pscustomobject]@{ Severity = 'high'; Rank = '1'; Process = 'C:\Users\dev\AppData\Roaming\malware.exe'; Domain = 'evil-c2.example'; Events = '90'; SpanMin = '180'; MedianIntervalSec = '120'; Jitter = '0.05'; Regularity = '0.95'; Flags = '' })
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression $mExport.Value
New-CaseIocExport
$exp = $saved['ioc_export']
Check "export: yara-hit binary hash exported (HIGH-verdict twin suppressed as feed echo)" ((@($exp | Where-Object { $_.Kind -eq 'sha256' -and $_.Value -eq $yaraHash }).Count -eq 1) -and (@($exp | Where-Object { $_.Kind -eq 'sha256' }).Count -eq 1))
Check "export: YARA-hit source attributed with rule name" (@($exp | Where-Object { "$($_.Source)" -eq 'YARA MALWARE_FAMILY_Test' }).Count -eq 1)
Check "export: feed echo suppressed (hash already in tools\iocs NOT re-exported)" (@($exp | Where-Object { $_.Value -eq $feedHash }).Count -eq 0)
Check "export: high beacon IP in, medium beacon out" ((@($exp | Where-Object { $_.Kind -eq 'ip' -and $_.Value -eq '185.199.10.7' }).Count -eq 1) -and (@($exp | Where-Object { $_.Value -eq '198.51.100.9' }).Count -eq 0))
Check "export: high dns beacon domain in" (@($exp | Where-Object { $_.Kind -eq 'domain' -and $_.Value -eq 'evil-c2.example' }).Count -eq 1)
Check "export: LOW verdict notepad excluded" (@($exp | Where-Object { "$($_.Detail)" -match 'notepad' }).Count -eq 0)
Check "export: schema Kind/Value/Source/Detail" ("$(@($exp)[0].PSObject.Properties.Name -join ',')" -eq 'Kind,Value,Source,Detail')
$txt = Get-Content -LiteralPath (Join-Path $RawDir 'analysis\ioc_export.txt')
Check "export: ioc_export.txt written in the iocs.txt dialect" (($txt | Where-Object { $_ -match "^# case IOC export \(FT / C-49\)" }).Count -eq 1 -and ($txt | Where-Object { $_ -match '^11112222[0-9A-Fa-f]+ # sha256 - YARA' }).Count -eq 1 -and ($txt | Where-Object { $_ -match '^185\.199\.10\.7 # ip - high C2 beacon' }).Count -eq 1)

# round-trip: the exported txt parses through the REAL Get-IocList
$mIoc = [regex]::Match($src, "(?s)function Get-IocList \{.*?\r?\n\}")
if (-not $mIoc.Success) { throw 'extract failed: Get-IocList' }
$toolsDir = Join-Path $fix 'tools'
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $RawDir 'analysis\ioc_export.txt') -Destination (Join-Path $toolsDir 'iocs.txt')
function Get-ToolsDir { $script:toolsDir }
function Write-CaseLog2 { }
Invoke-Expression $mIoc.Value
$iocs2 = Get-IocList
Check "round-trip: exported hash/domain/ip parse back through the real Get-IocList" (($iocs2.Hashes.ContainsKey($yaraHash.ToUpper())) -and ($iocs2.Ips.ContainsKey('185.199.10.7')) -and ($iocs2.Domains.ContainsKey('evil-c2.example')) -and (@($iocs2.Hashes.Keys | Where-Object { $_ -eq $feedHash }).Count -eq 0))

# ============================================================================
# PART 3 - feed-hash x process_hashes xref through the real New-IocHits
# ============================================================================
$mHits = [regex]::Match($src, "(?s)function New-IocHits \{.*?\r?\n\}")
if (-not $mHits.Success) { throw 'extract failed: New-IocHits' }
$savedHits = @{}
function Save-Rows { param([string]$Name, $Rows) $script:savedHits[$Name] = @($Rows) }
# feeds (stubbed): the yara hash is a known-bad indicator attributed to a prior case
function Get-IocList {
    @{ Hashes = @{ $yaraHash = $true }; Sha1 = @{}; Ips = @{}; Domains = @{}; Names = @{}; Feed = @{ $yaraHash = 'prior-case' } }
}
$hitsCsv = @{
    'process_hashes' = @(
        [pscustomobject]@{ Name = 'implant.dll'; Path = 'C:\Users\dev\AppData\Roaming\implant.dll'; SHA256 = $yaraHash },
        [pscustomobject]@{ Name = 'calc.exe'; Path = 'C:\Windows\System32\calc.exe'; SHA256 = 'DEAD' }
    )
}
function Import-CaseCsv { param([string]$Name) if ($script:hitsCsv.ContainsKey($Name)) { return $script:hitsCsv[$Name] }; return @() }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression $mHits.Value
New-IocHits
$hh = $savedHits['ioc_hits_hash']
Check "hash xref: feed hash in execution history found (uppercase, attributed)" ((@($hh | Where-Object { $_.Indicator -eq $yaraHash.ToUpper() -and "$($_.Feed)" -eq 'prior-case' -and "$($_.Match)" -eq 'execution-hash' })).Count -eq 1)
Check "hash xref: non-matching binary not flagged" (@($hh | Where-Object { "$($_.Process)" -eq 'calc.exe' }).Count -eq 0)

# ============================================================================
# PART 4 - DOT export shape (functional run covered by test_focus)
# ============================================================================
Check "dot: digraph header + instance/parent/child/chip node kinds" (($src -match [regex]::Escape('digraph focus {')) -and ($src -match [regex]::Escape('INSTANCE $(& $dotEsc')) -and ($src -match [regex]::Escape('PARENT $(& $dotEsc')) -and ($src -match [regex]::Escape('CHILD $(& $dotEsc')))
Check "dot: uncapped intent (25-chip cap vs the SVG's 8) + red injection edges" (($src.Contains('if ($chipN -ge 25) { break }')) -and ($src.Contains('penwidth=1.5, label=`"inject')))

Write-Host ""
Write-Host "test_v249: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $fix -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 }
