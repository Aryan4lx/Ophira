# v2.88 - entity correlation merge + evidence caps + SRUM display
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$fn = [regex]::Match((Get-Content (Join-Path $repo 'Ophira.ps1') -Raw), '(?s)function New-EntityCorrelation \{.*?\r?\n\}').Value
Invoke-Expression $fn
$fnS = [regex]::Match((Get-Content (Join-Path $repo 'Ophira.ps1') -Raw), '(?s)function Get-InvariantDate \{.*?\r?\n\}').Value
if ($fnS) { Invoke-Expression $fnS }

$fx = @{}
$fx['flash_process_scored'] = @(
    [pscustomobject]@{ PID = '100'; Name = 'xray.exe'; Path = 'E:\Apps\v2rayN\bin\xray\xray.exe'; Verdict = 'HIGH'; Score = '6'; Signer = ''; Company = ''; Description = ''; Evidence = 'unsigned' }
)
$fx['flash_public_connections'] = @(
    [pscustomobject]@{ Proto = 'TCP'; LocalAddress = '1.2.3.4'; LocalPort = '1'; RemoteAddress = '202.50.253.27'; RemotePort = '19999'; State = 'Established'; PID = '100'; ProcessPath = 'E:\Apps\v2rayN\bin\xray\xray.exe'; Public = 'True' }
)
$fx['srum_usage'] = @(
    [pscustomobject]@{ Application = '\device\harddiskvolume4\apps\v2rayn\bin\xray\xray.exe'; BytesSent = '9341169'; BytesReceived = '9258540' },
    [pscustomobject]@{ Application = '\device\harddiskvolume4\apps\v2rayn\bin\xray\xray.exe'; BytesSent = '188151835'; BytesReceived = '174077587' },
    [pscustomobject]@{ Application = '\device\harddiskvolume4\apps\v2rayn\bin\xray\xray.exe'; BytesSent = '108490219'; BytesReceived = '26413697' },
    [pscustomobject]@{ Application = '\device\harddiskvolume4\apps\v2rayn\bin\xray\xray.exe'; BytesSent = '145023070'; BytesReceived = '32107593' }
)
$fx['security_auth_events'] = @(); $fx['security_proc_events'] = @(); $fx['security_share_access'] = @()
$fx['hunt_findings'] = @(); $fx['autoruns'] = @(); $fx['services'] = @(); $fx['scheduled_tasks'] = @()
$fx['process_hashes'] = @(); $fx['yara_hits'] = @(); $fx['beacon_candidates'] = @()
$fx['processes'] = @(
    [pscustomobject]@{ PID = '100'; Name = 'xray.exe'; Path = 'E:\Apps\v2rayN\bin\xray\xray.exe'; Company = 'Acme'; Description = 'Xray core' }
)

function Import-CaseCsv([string]$Name) { if ($fx.ContainsKey($Name)) { return @($fx[$Name]) }; return @() }
function Save-Rows { param($Name, $Rows) $saved[$Name] = $Rows }
function Write-CaseLog { param($m) }
function Get-ToolsDir { return $null }
function Test-IsPublicIp { param($ip) return $true }
$saved = @{}

$checkFail = 0
function Check([string]$Name, [bool]$Ok) {
    if ($Ok) { Write-Host "  [ok] $Name" }
    else { Write-Host "  [FAIL] $Name"; $script:checkFail++ }
}

New-EntityCorrelation

$bins = $saved['entities_binaries']
$xray = @($bins | Where-Object { $_.Name -eq 'xray.exe' })
Check "drive-letter/case split unified to ONE card" ($xray.Count -eq 1)
if ($xray.Count -eq 1) {
    $b = $xray[0]
    Check "merged card keeps canonical path" ("$($b.Path)" -eq 'E:\Apps\v2rayN\bin\xray\xray.exe')
    Check "merged cats carry verdict+conn+srum" ((";$($b.Categories);" -like '*;verdict;*') -and (";$($b.Categories);" -like '*;conn;*') -and (";$($b.Categories);" -like '*;srum-usage;*'))
    Check "Company/Desc captured from live process" ("$($b.Company)" -eq 'Acme' -and "$($b.Description)" -eq 'Xray core')
    $ev = @("$($b.Evidence)" -split ' \| ')
    Check "per-category evidence cap (srum <= 3)" ((@($ev | Where-Object { $_ -like 'srum-usage*' }).Count) -le 3)
    Check "'also seen as' records the losing path" (@($ev | Where-Object { $_ -match '^correlated: same binary also seen as C:\\apps' }).Count -eq 1)
    Check "conn evidence preserved" (@($ev | Where-Object { $_ -match 'conn: public 202\.50\.253\.27' }).Count -ge 1)
} else {
    Check "merged card exists" $false
}

# static: merge pass exists + interpolation is correct ($($...) form)
$src = Get-Content (Join-Path $repo 'Ophira.ps1') -Raw
Check "merge pass keyed by leaf+tail segments" ($src.Contains('$gk = ("$($segs[$n-3])\$($segs[$n-2])\$($segs[$n-1])").ToLower()'))
Check "no broken hashtable interpolation in merge" (-not $src.Contains('"$binsByPath[$kv].Path"'))
Check "per-category evidence cap present" ($src.Contains('EvPerCat'))

if ($checkFail -gt 0) { Write-Host "RESULT: $($checkFail) failed"; exit 1 }
Write-Host 'RESULT: all passed'
exit 0
