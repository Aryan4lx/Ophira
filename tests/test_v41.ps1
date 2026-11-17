# tests/test_v41.ps1 - v4.1 BAM/SRUM egress batch fixtures
#   P1 New-SrumAppTotals: aggregation, sort, users dedupe, garbage numerics, empty table
#   P2 R56 upload-dominant egress rule: fires medium, gates (size/ratio/safe-list/windows path)
#   P3 wiring: verdict door, regen step order, maps, entity + report blocks
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- extraction: only what P1/P2 need (heavy stub set reused from test_v400) ----
$defs = ''
foreach ($n in @('Get-InvariantDate', 'Get-LevenshteinDistance', 'Test-IsUserWritablePath', 'Test-IsPublicIp', 'ConvertTo-HtmlEsc', 'ConvertTo-SafeInt', 'ConvertTo-SafeDbl', 'Get-KnownBadRegexes', 'Get-LvlRank', 'New-HuntFindings', 'New-SrumAppTotals')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

function Save-Rows { param([string]$Name, $Rows) $script:rows[$Name] = @($Rows) }
$script:logs = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:logs.Add("$Message") }
function QuietLog { param([string]$Message) }
function Get-AuthenticodeSignature { param([string]$LiteralPath) return $null }
function Test-Path { param([string]$LiteralPath, [string]$PathType, $ErrorAction) return $false }
function Test-CaseCsv([string]$n) { return $false }
function Get-ToolsDir { return $null }
function Get-Changes { return @() }
function Export-Evtx { param($LogName, $OutPath, $rest) }
function Get-LogStart { return (Get-InvariantDate '2026-11-10 00:00:00') }
function Get-EventDataRows { param($LogName, $Id, $Start, $Cap, $Fields, $rest) return @() }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $rest) return $script:fakeEvents }
function Get-TaskDeletionRows { param($Start) return @() }
function Get-EsentNtdsRows { param($Start) return @() }
function Get-Item { param($Path, $LiteralPath, $rest) return $null }
function New-Item { param($Path, $ItemType, $Force, $LiteralPath, $rest) }
function Copy-Item { param($LiteralPath, $Destination, $Force, $Path, $ErrorAction, $rest) }
function Get-ChildItem { param($Path, $Filter, $File, $Recurse, $ErrorAction, $rest) return @() }
function Get-ItemProperty { param($LiteralPath, $ErrorAction, $rest) return $null }
$script:rows = @{}
$script:fakeEvents = @()
$script:caseCsv = @{}
function Import-CaseCsv { param([string]$Name) $k = "$Name" -replace '\.csv$', ''; if ($script:caseCsv.ContainsKey($k)) { return @($script:caseCsv[$k]) }; return @() }

# ================= P1: New-SrumAppTotals =================
$script:rows = @{}
$script:caseCsv = @{ 'srum_usage' = @(
    [pscustomobject]@{ Timestamp = '2026-11-15 08:00:00'; Application = '\device\harddiskvolume3\tools\exfil.exe'; User = 'desktop\aryan';  BytesSent = '9437184'; BytesReceived = '1048576'; InterfaceType = 'ethernet' },
    [pscustomobject]@{ Timestamp = '2026-11-15 09:00:00'; Application = '\device\harddiskvolume3\tools\exfil.exe'; User = 'DESKTOP\aryan';  BytesSent = '1048576';  BytesReceived = '524288';  InterfaceType = 'ethernet' },
    [pscustomobject]@{ Timestamp = '2026-11-15 08:00:00'; Application = 'C:\Program Files\backup.exe';            User = 'system';        BytesSent = '2048';     BytesReceived = '1024';    InterfaceType = 'ethernet' },
    [pscustomobject]@{ Timestamp = '2026-11-15 10:00:00'; Application = '';                                       User = '';              BytesSent = '1';        BytesReceived = '1';       InterfaceType = 'ethernet' },
    [pscustomobject]@{ Timestamp = '2026-11-15 11:00:00'; Application = 'weird.exe';                              User = 'svc';           BytesSent = 'not-a-number'; BytesReceived = 'x'; InterfaceType = '' }
) }
New-SrumAppTotals
$tot = $script:rows['srum_app_totals']
Check 'P1: totals saved (empty app skipped)' ($tot.Count -eq 3)
$ex = @($tot | Where-Object { $_.Leaf -eq 'exfil.exe' })[0]
Check 'P1: bytes summed across rows' ("$($ex.BytesSent)" -eq '10485760' -and "$($ex.BytesReceived)" -eq '1572864')
Check 'P1: rounds counted' ("$($ex.Rounds)" -eq '2')
Check 'P1: users deduped case-insensitive' ("$($ex.Users)" -eq 'desktop\aryan')
Check 'P1: first/last seen picked' ("$($ex.FirstSeen)" -eq '2026-11-15 08:00:00' -and "$($ex.LastSeen)" -eq '2026-11-15 09:00:00')
$up = [double]"$($ex.UploadRatio)"
Check 'P1: upload ratio 2dp' ($up -eq 0.87)
$bk = @($tot | Where-Object { $_.Leaf -eq 'backup.exe' })[0]
Check 'P1: sorted by bytes sent desc (exfil first)' ("$($tot[0].Leaf)" -eq 'exfil.exe' -and "$($bk.TotalBytes)" -eq '3072')
$wd = @($tot | Where-Object { $_.Leaf -eq 'weird.exe' })[0]
Check 'P1: garbage numerics -> zeros not crash' ("$($wd.BytesSent)" -eq '0')

$script:rows = @{}; $script:caseCsv = @{}
New-SrumAppTotals
Check 'P1: empty table -> empty artifact' ($script:rows['srum_app_totals'].Count -eq 0)

# ================= P2: R56 rule in New-HuntFindings =================
$script:rows = @{}; $script:caseCsv = @{}
$script:caseCsv['srum_app_totals'] = @(
    [pscustomobject]@{ Application = 'C:\Users\aryan\pub\drop.exe'; Leaf = 'drop.exe'; BytesSent = '9437184'; BytesReceived = '1048576'; TotalBytes = '10485760'; UploadRatio = '0.9'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' },
    [pscustomobject]@{ Application = 'C:\Users\aryan\pub\balanced.exe'; Leaf = 'balanced.exe'; BytesSent = '5242880'; BytesReceived = '5242880'; TotalBytes = '10485760'; UploadRatio = '0.5'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' },
    [pscustomobject]@{ Application = 'C:\Users\aryan\pub\small.exe'; Leaf = 'small.exe'; BytesSent = '917504'; BytesReceived = '1024'; TotalBytes = '918528'; UploadRatio = '1'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' },
    [pscustomobject]@{ Application = 'C:\Windows\System32\svchost.exe'; Leaf = 'svchost.exe'; BytesSent = '9437184'; BytesReceived = '1048576'; TotalBytes = '10485760'; UploadRatio = '0.9'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' },
    [pscustomobject]@{ Application = 'WinDefend'; Leaf = 'windefend'; BytesSent = '9437184'; BytesReceived = '1048576'; TotalBytes = '10485760'; UploadRatio = '0.9'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' },
    [pscustomobject]@{ Application = 'C:\Program Files\Dropbox\dropbox.exe'; Leaf = 'dropbox.exe'; BytesSent = '9437184'; BytesReceived = '1048576'; TotalBytes = '10485760'; UploadRatio = '0.9'; Rounds = '5'; Users = 'u'; FirstSeen = ''; LastSeen = '' }
)
$script:Verbosity = 2
New-HuntFindings
$hf = $script:rows['hunt_findings']
$r56 = @($hf | Where-Object { $_.Rule -eq 'Upload-dominant egress (SRUM)' })
Check 'P2: exactly one R56 finding' ($r56.Count -eq 1)
Check 'P2: entity is drop.exe path' ("$($r56[0].Entity)" -eq 'C:\Users\aryan\pub\drop.exe')
Check 'P2: severity medium' ("$($r56[0].Severity)" -eq 'medium')
Check 'P2: evidence has MB + percent' ("$($r56[0].Evidence)" -match '9 MB sent' -and "$($r56[0].Evidence)" -match '90% outbound')
Check 'P2: ATT&CK T1041' ("$($r56[0].Attck)" -eq 'T1041')
Check 'P2: balanced 50% not flagged' (@($hf | Where-Object { $_.Entity -match 'balanced' }).Count -eq 0)
Check 'P2: sub-1MB not flagged' (@($hf | Where-Object { $_.Entity -match 'small\.exe' }).Count -eq 0)
Check 'P2: windows path not flagged' (@($hf | Where-Object { $_.Entity -match 'svchost' }).Count -eq 0)
Check 'P2: bare service name (no .exe) not flagged' (@($hf | Where-Object { $_.Entity -match 'WinDefend' }).Count -eq 0)
Check 'P2: safe-list leaf not flagged' (@($hf | Where-Object { $_.Entity -match 'dropbox\.exe' }).Count -eq 0)
Check 'P2: R56 trace logged' (@($script:logs | Where-Object { $_ -match '^R56 upload-dominant egress' }).Count -ge 1)

# ================= P3: wiring =================
Check 'P3: verdict door floor 2' ($src.Contains("Add-Signal 'Upload-dominant egress (SRUM)' 2"))
Check 'P3: CsvCatMap derived entry' ($src -match "'srum_app_totals' = 'derived'")
Check 'P3: desc map entry' ($src -match "'srum_app_totals'\s+=\s+'SRUM: aggregated")
Check 'P3: emptyWhy entry (10+ chars)' ($src -match "'srum_app_totals'\s+=\s+'SRUM usage table absent")
$iTot = [regex]::Match($src, "(?m)^\s*& \`$rgStep 'srum egress totals'").Index
$iHunt = [regex]::Match($src, "(?m)^\s*& \`$rgStep 'hunt findings'").Index
Check 'P3: totals step before hunt findings (feed order)' ($iTot -gt 0 -and $iHunt -gt $iTot)
Check 'P3: entity srum-egress category wired' ($src.Contains("'srum-egress'"))
Check 'P3: report egress h3 present' ($src.Contains('Egress heavyweights (SRUM totals)'))
Check 'P3: verdict recompute mirrors rule gates' ($src.Contains('Upload-dominant egress (SRUM)'))
Check 'P3: no phantom helper names (SafeDouble typo class)' (-not $src.Contains('ConvertTo-SafeDouble'))

Write-Host ''
Write-Host "test_v41: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
exit 0
