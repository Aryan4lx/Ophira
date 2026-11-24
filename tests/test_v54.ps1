# tests/test_v54.ps1 - v5.4 fleet campaign clustering (union-find over shared ties)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# P0: wiring - function exists, caller wired in Analyze mode, HTML section present
Check 'function New-FleetCampaigns exists' ($src -match 'function New-FleetCampaigns \{')
Check 'Analyze mode wires campaign builder' ($src -match 'New-FleetCampaigns -HashRows \$fleetHashRows -CrossRows \$crossHost')
Check 'fleet_campaigns.csv exported' ($src -match "fleet_campaigns\.csv")
Check 'report renders Campaigns section' ($src -match 'Campaigns - clustered host groups')

$m = [regex]::Match($src, '(?s)function New-FleetCampaigns \{.*?\r?\n\}')
if (-not $m.Success) { Write-Host '  [FAIL] cannot extract New-FleetCampaigns'; exit 1 }
Invoke-Expression $m.Value

$verd = @{ 'A' = 'SUSPICIOUS'; 'B' = 'LIKELY COMPROMISED'; 'C' = 'SUSPICIOUS'; 'D' = 'NO EVIDENCE'; 'E' = 'INCONCLUSIVE' }

# P1: full mesh - hash A,B + cross A,B,C + lateral B,C + wave A,B -> one campaign of 3
$h1 = @([pscustomobject]@{ SHA256 = 'h1'; Name = 'evil.exe'; Hosts = 'A, B'; HostCount = 2; MultiHost = 'YES - lateral candidate' })
$x1 = @([pscustomobject]@{ Indicator = 'evil.exe'; Hosts = 'A, B, C'; HostCount = 3 })
$l1 = @([pscustomobject]@{ FromHost = 'B'; ToHost = 'C'; Account = 'admin'; Share = 'C$'; Time = 't'; SourceIp = '10.0.0.1' })
$w1 = @([pscustomobject]@{ Name = 'evil.exe'; Class = 'wave'; SpreadMinutes = 12; HostCount = 2; Hosts = 'A, B'; FirstSeen = 'x' })
$r1 = @(New-FleetCampaigns -HashRows $h1 -CrossRows $x1 -Lateral $l1 -Waves $w1 -AllHosts @('A','B','C','D','E') -Verdicts $verd)
Check 'P1: single campaign found' ($r1.Count -eq 1)
Check 'P1: campaign = A,B,C' ("$($r1[0].Hosts)" -eq 'A, B, C')
Check 'P1: host count 3' ($r1[0].HostCount -eq 3)
Check 'P1: worst verdict = LIKELY COMPROMISED' ("$($r1[0].WorstVerdict)" -eq 'LIKELY COMPROMISED')
Check 'P1: evidence names all four tie types' (("$($r1[0].Evidence)" -match 'lateral: B -> C') -and ("$($r1[0].Evidence)" -match 'shared binary hash: evil\.exe') -and ("$($r1[0].Evidence)" -match 'shared indicator: evil\.exe') -and ("$($r1[0].Evidence)" -match 'deployment wave: evil\.exe'))
Check 'P1: campaign id C1' ("$($r1[0].Campaign)" -eq 'C1')

# P2: no ties at all -> empty
$r2 = @(New-FleetCampaigns -HashRows @() -CrossRows @() -Lateral @() -Waves @() -AllHosts @('A','B','C') -Verdicts $verd)
Check 'P2: no ties -> no campaigns' ($r2.Count -eq 0)

# P3: lateral-only pair -> one campaign of 2 (weakest input still clusters)
$l3 = @([pscustomobject]@{ FromHost = 'F'; ToHost = 'G'; Account = 'a'; Share = 'ADMIN$'; Time = 't'; SourceIp = 'x' })
$r3 = @(New-FleetCampaigns -HashRows @() -CrossRows @() -Lateral $l3 -Waves @() -AllHosts @('F','G','H') -Verdicts @{})
Check 'P3: lateral-only pair clusters' ($r3.Count -eq 1 -and $r3[0].HostCount -eq 2 -and "$($r3[0].Hosts)" -eq 'F, G')
Check 'P3: no verdicts map -> WorstVerdict empty' ("$($r3[0].WorstVerdict)" -eq '')

# P4: two disjoint clusters sort by worst verdict rank then size
$h4 = @(
    [pscustomobject]@{ SHA256 = 'a'; Name = 'a.exe'; Hosts = 'A, B'; HostCount = 2; MultiHost = 'YES' },
    [pscustomobject]@{ SHA256 = 'b'; Name = 'b.exe'; Hosts = 'D, E'; HostCount = 2; MultiHost = 'YES' }
)
$r4 = @(New-FleetCampaigns -HashRows $h4 -CrossRows @() -Lateral @() -Waves @() -AllHosts @('A','B','D','E') -Verdicts $verd)
Check 'P4: two disjoint campaigns' ($r4.Count -eq 2)
Check 'P4: LIKELY COMPROMISED cluster sorts first' ("$($r4[0].Hosts)" -eq 'A, B' -and "$($r4[0].WorstVerdict)" -eq 'LIKELY COMPROMISED')
Check 'P4: NO EVIDENCE cluster second' ("$($r4[1].Hosts)" -eq 'D, E' -and "$($r4[1].WorstVerdict)" -eq 'NO EVIDENCE')

# P5: transitivity - hash A,B and hash B,C (never A,C directly) still unite A,B,C
$h5 = @(
    [pscustomobject]@{ SHA256 = 'x'; Name = 'x.exe'; Hosts = 'A, B'; HostCount = 2; MultiHost = 'YES' },
    [pscustomobject]@{ SHA256 = 'y'; Name = 'y.exe'; Hosts = 'B, C'; HostCount = 2; MultiHost = 'YES' }
)
$r5 = @(New-FleetCampaigns -HashRows $h5 -CrossRows @() -Lateral @() -Waves @() -AllHosts @('A','B','C') -Verdicts $verd)
Check 'P5: transitive closure unites via shared member' ($r5.Count -eq 1 -and $r5[0].HostCount -eq 3)

# P6: fewer than 2 hosts -> early out
$r6 = @(New-FleetCampaigns -HashRows @() -CrossRows @() -Lateral @() -Waves @() -AllHosts @('A') -Verdicts $verd)
Check 'P6: single host -> empty' ($r6.Count -eq 0)

# P7: case-insensitive host matching
$l7 = @([pscustomobject]@{ FromHost = 'host-a'; ToHost = 'HOST-A'; Account = 'self'; Share = 'C$'; Time = 't'; SourceIp = 'x' })
$r7 = @(New-FleetCampaigns -HashRows @() -CrossRows @() -Lateral $l7 -Waves @() -AllHosts @('Host-A') -Verdicts @{})
Check 'P7: self-loop edge ignored (case-insensitive)' ($r7.Count -eq 0)

Write-Host ''
if ($fail -eq 0) { Write-Host "v5.4: $pass passed, 0 failed" -ForegroundColor Green; exit 0 }
Write-Host "v5.4: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1
