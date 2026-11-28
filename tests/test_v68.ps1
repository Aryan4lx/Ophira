# test_v68.ps1 - v6.7 fleet campaign ties v2 (account / source-IP / USB edges, spans, flagged counts)
# Extracts Get-InvariantDate + New-FleetCampaigns from Ophira.ps1, feeds fixture rows, and asserts
# the new edge types merge campaigns, spans are computed from tie times, and flagged counts render.
# House harness: regex extraction + positional Check calls (project test style).
$ErrorActionPreference = 'Stop'
$script:src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$script:pass = 0; $script:fail = 0
function Check { param([string]$Name, [bool]$Cond)
    if ($Cond) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green }
    else { $script:fail++; Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red }
}
function Get-Fn { param([string]$Name)
    $m = [regex]::Match($script:src, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "function $Name not found" }
    return $m.Value
}

Invoke-Expression (Get-Fn 'Get-InvariantDate')
Invoke-Expression (Get-Fn 'New-FleetCampaigns')

# ---- fixture row builders (field names = fleet harvest shapes) ----
function SRow { param([string]$Host_, [string]$User, [string]$Start, [string]$Type = '2', [string]$Source = '-')
    [pscustomobject]@{ Host = $Host_; User = $User; Start = $Start; Type = $Type; Source = $Source } }
function URow { param([string]$Host_, [string]$Serial, [string]$Friendly, [string]$Stamp)
    [pscustomobject]@{ Host = $Host_; Serial = $Serial; FriendlyName = $Friendly; Stamp = $Stamp } }

function Invoke-Stitch {
    param([object[]]$SessionRows = @(), [object[]]$UsbRows = @(), [object[]]$HashRows = @(), [object[]]$CrossRows = @(),
          [object[]]$Lateral = @(), [object[]]$Waves = @(), [string[]]$AllHosts, [hashtable]$Verdicts = @{}, [hashtable]$ClientBy = @{})
    try {
        return @(New-FleetCampaigns -HashRows $HashRows -CrossRows $CrossRows -Lateral $Lateral -Waves $Waves `
            -AllHosts $AllHosts -Verdicts $Verdicts -ClientBy $ClientBy -SessionRows $SessionRows -UsbRows $UsbRows)
    } catch { $script:lastErr = $_.Exception.Message; return $null }
}
$script:lastErr = ''

Write-Host '--- T0: the extended stitcher call binds ---'
$a = @(Invoke-Stitch -AllHosts @('H1', 'H2') -SessionRows @( (SRow 'H1' 'jsmith' '2026-11-24 09:12:00'), (SRow 'H2' 'jsmith' '2026-11-24 09:20:00') ))
Check 'T0 stitcher accepts -SessionRows/-UsbRows (no binding error)' ($null -ne $a)
if ($null -eq $a) { Write-Host "      lastErr: $script:lastErr" }

Write-Host '--- T1: account tie merges hosts; machine/SYSTEM/empty users never tie ---'
$t1 = @(Invoke-Stitch -AllHosts @('H1', 'H2', 'H3') -SessionRows @(
    (SRow 'H1' 'jsmith' '2026-11-24 09:12:00'), (SRow 'H2' 'jsmith' '2026-11-24 09:20:00'),
    (SRow 'H1' 'WS-01$' '2026-11-24 10:00:00'), (SRow 'H2' 'WS-01$' '2026-11-24 10:05:00'),
    (SRow 'H2' 'SYSTEM' '2026-11-24 11:00:00'), (SRow 'H3' '' '2026-11-24 12:00:00') ))
Check 'T1 one campaign formed' ($null -ne $t1 -and $t1.Count -eq 1)
Check 'T1 campaign has both hosts' ($null -ne $t1 -and "$($t1[0].Hosts)" -match 'H1' -and "$($t1[0].Hosts)" -match 'H2')
Check 'T1 evidence names the account tie' ($null -ne $t1 -and "$($t1[0].Evidence)" -like '*account: jsmith on*')
Check 'T1 machine account never reaches evidence' ($null -ne $t1 -and "$($t1[0].Evidence)" -notlike '*WS-01$*')

Write-Host '--- T2: source-IP tie merges host + lateral target; LOCAL/loopback never tie ---'
$t2 = @(Invoke-Stitch -AllHosts @('H1', 'H2', 'H3', 'H4', 'H5') -SessionRows @(
    (SRow 'H3' 'bob' '2026-11-24 09:00:00' '2' '10.1.2.9'),
    (SRow 'H3' 'svc1' '2026-11-24 09:30:00' '2' 'LOCAL'), (SRow 'H5' 'svc2' '2026-11-24 09:35:00' '2' 'LOCAL') ) `
    -Lateral @( [pscustomobject]@{ FromHost = 'H3'; ToHost = 'H4'; Account = 'bob'; Share = 'C$'; Target = 'tools.exe'; Time = '2026-11-24 09:10:00'; SourceIp = '10.1.2.9'; EventId = '5145' } ))
Check 'T2 campaign formed from shared source IP' ($null -ne $t2 -and $t2.Count -eq 1 -and $t2[0].HostCount -eq 2)
Check 'T2 campaign is H3+H4' ($null -ne $t2 -and "$($t2[0].Hosts)" -match 'H3' -and "$($t2[0].Hosts)" -match 'H4')
Check 'T2 evidence names the source IP' ($null -ne $t2 -and "$($t2[0].Evidence)" -like '*source IP 10.1.2.9*')
Check 'T2 LOCAL source never merges H3+H5' ($null -ne $t2 -and "$($t2[0].Hosts)" -notmatch 'H5')

Write-Host '--- T3: USB serial tie merges hosts; single-host serial stays quiet ---'
$t3 = @(Invoke-Stitch -AllHosts @('H1', 'H2', 'H3') -UsbRows @(
    (URow 'H1' 'SN123' 'Kingston DataTraveler' '2026-11-24 08:00:00'), (URow 'H2' 'SN123' 'Kingston DataTraveler' '2026-11-24 07:30:00'),
    (URow 'H3' 'SN999' 'SanDisk' '2026-11-24 06:00:00') ))
Check 'T3 campaign formed from shared USB serial' ($null -ne $t3 -and $t3.Count -eq 1 -and $t3[0].HostCount -eq 2)
Check 'T3 campaign is H1+H2' ($null -ne $t3 -and "$($t3[0].Hosts)" -match 'H1' -and "$($t3[0].Hosts)" -match 'H2')
Check 'T3 evidence names the USB device' ($null -ne $t3 -and "$($t3[0].Evidence)" -like '*USB*SN123*')

Write-Host '--- T4: span = min/max tie-evidence times; time-less ties leave it empty ---'
$t4 = @(Invoke-Stitch -AllHosts @('H1', 'H2', 'H3', 'H4') `
    -UsbRows @((URow 'H1' 'SN123' 'Kingston' '2026-11-24 08:00:00'), (URow 'H2' 'SN123' 'Kingston' '2026-11-24 07:30:00')) `
    -HashRows @( [pscustomobject]@{ SHA256 = 'deadbeef'; Name = 'implant.exe'; Hosts = 'H3, H4'; MultiHost = 'YES' } ))
$usbRow = @($t4 | Where-Object { "$($_.Hosts)" -match 'H1' })[0]
$hashRow = @($t4 | Where-Object { "$($_.Hosts)" -match 'H3' })[0]
Check 'T4 USB campaign carries a span' ($null -ne $usbRow -and "$($usbRow.Span)" -ne '')
Check 'T4 span is min-max of tie times' ($null -ne $usbRow -and "$($usbRow.Span)" -eq '2026-11-24 07:30 - 2026-11-24 08:00')
Check 'T4 hash-only campaign has empty span' ($null -ne $hashRow -and "$($hashRow.Span)" -eq '')

Write-Host '--- T5: flagged count + worst verdict roll up across the campaign ---'
$t5 = @(Invoke-Stitch -AllHosts @('H1', 'H2', 'H3') -SessionRows @(
    (SRow 'H1' 'jsmith' '2026-11-24 09:00:00'), (SRow 'H2' 'jsmith' '2026-11-24 09:05:00'), (SRow 'H3' 'jsmith' '2026-11-24 09:10:00') ) `
    -Verdicts @{ 'H1' = 'SUSPICIOUS'; 'H2' = 'NO EVIDENCE' } )
Check 'T5 campaign covers 3 hosts' ($null -ne $t5 -and $t5.Count -eq 1 -and $t5[0].HostCount -eq 3)
Check 'T5 worst verdict is SUSPICIOUS' ($null -ne $t5 -and "$($t5[0].WorstVerdict)" -eq 'SUSPICIOUS')
Check 'T5 flagged count renders 1 of 3' ($null -ne $t5 -and "$($t5[0].Flagged)" -eq '1 of 3 host(s)')

Write-Host '--- T6: client guard holds for new ties; host/user case+whitespace still merge ---'
$t6 = @(Invoke-Stitch -AllHosts @('H1', 'H2') -SessionRows @(
    (SRow 'H1' 'jsmith' '2026-11-24 09:00:00'), (SRow 'H2' 'jsmith' '2026-11-24 09:05:00') ) `
    -ClientBy @{ 'h1' = 'ClientA'; 'h2' = 'ClientB' } )
Check 'T6 cross-client account tie does not merge' ($null -ne $t6 -and $t6.Count -eq 0)
Check 'T6 cross-client tie recorded' ($script:FleetCrossClientTies.Count -ge 1)
$t6b = @(Invoke-Stitch -AllHosts @('WS-01', 'ws-02') -SessionRows @(
    (SRow 'WS-01' 'JSmith ' '2026-11-24 09:00:00'), (SRow 'ws-02' 'jsmith' '2026-11-24 09:05:00') ))
Check 'T6b case/whitespace variants merge' ($null -ne $t6b -and $t6b.Count -eq 1 -and $t6b[0].HostCount -eq 2)

Write-Host '--- T7: repeated sessions produce ONE deduped evidence line ---'
$t7 = @(Invoke-Stitch -AllHosts @('H1', 'H2') -SessionRows @(
    (SRow 'H1' 'jsmith' '2026-11-24 09:00:00'), (SRow 'H1' 'jsmith' '2026-11-24 10:00:00'),
    (SRow 'H2' 'jsmith' '2026-11-24 11:00:00'), (SRow 'H2' 'jsmith' '2026-11-24 12:00:00') ))
$ev7 = if ($t7) { "$($t7[0].Evidence)" } else { '' }
$cnt7 = [regex]::Matches($ev7, [regex]::Escape('account: jsmith on')).Count
Check 'T7 account tie line deduped to one' ($cnt7 -eq 1)

Write-Host '--- T8: fleet harvest wiring pins (Analyze-mode plumbing) ---'
Check 'T8 $fleetUsb list initialized' ($script:src -match [regex]::Escape('$fleetUsb = New-Object System.Collections.Generic.List[object]'))
Check 'T8 usb_devices harvest with cap + serial filter' ($script:src -match [regex]::Escape('Join-Path $csvDir ''usb_devices.csv''') -and $script:src -match '\$fleetUsb\.Count -lt 5000' -and $script:src -match [regex]::Escape('$sn -eq ''0'''))
Check 'T8 stitcher call wires SessionRows + UsbRows' ($script:src -match [regex]::Escape('-SessionRows $fleetSess.ToArray() -UsbRows $fleetUsb.ToArray()'))

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
