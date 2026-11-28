# test_v55.ps1 - v5.6: findings JSON, client boundaries, redacted copy
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fail = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { Write-Host "[PASS] $name" } else { Write-Host "[FAIL] $name"; $script:fail++ }
}

# ---- extract helpers ----
foreach ($fn in @('New-FindingsJson', 'New-FleetCampaigns', 'New-RedactedCopy')) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { Write-Host "[FAIL] extract $fn"; exit 1 }
    Invoke-Expression $m.Value
}
function Write-CaseLog { param($m) $script:lastLog = "$m" }
function Import-CaseCsv {
    param($Name)
    if ($null -ne $script:caseCsv[$Name]) { return $script:caseCsv[$Name] }
    return @()
}
$script:caseCsv = @{}

# ---- fixtures ----
$tmp = Join-Path $env:TEMP ("oph_v55_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

$Computer = 'LAB-HOST-01'
$ScriptVersion = '5.6'
$Preset = 'Standard'
$script:HostRole = 'Workstation'
$script:ClientName = 'Contoso Ltd'
$script:CurrentCaseID = 'INC-TEST-42'
$script:CurrentAnalyst = 'jsmith'
$script:Verdict = [pscustomobject]@{
    Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 85; OwnerLine = 'test owner line'
    Signals = @([pscustomobject]@{ Signal = 'Test signal'; Weight = 2; Count = 3; Detail = 'detail text' })
    Caveats = @('caveat one')
    CoverageSourcesCollected = 24; CoverageSourcesTotal = 33; CoveragePercentUnadjusted = 72
    Coverage = @(
        [pscustomobject]@{ Source = 'Event log export'; Collected = $true; Weight = 20 },
        [pscustomobject]@{ Source = 'Live memory triage'; Collected = $false; Weight = 15 }
    )
}
[IO.File]::WriteAllText((Join-Path $tmp 'case.json'), '{"Computer":"LAB-HOST-01","CaseID":"INC-TEST-42","Analyst":"jsmith","ClientName":"Contoso Ltd","Preset":"Standard","StartedUTC":"2026-11-24T08:00:00.0000000Z"}')
[IO.File]::WriteAllText((Join-Path $tmp 'report.html'), "<html><body><h1>report for LAB-HOST-01</h1><p>user jsmith did things</p><p>alice and bob ran tools</p><p>10.1.2.3 and 8.8.8.8 and 192.168.5.6</p><p>MAC aa:bb:cc:dd:ee:ff here</p><p>intranet.corp and evil.example.com</p><p>NT VIRTUAL MACHINE sessions; SYSTEM stays</p></body></html>")
$script:caseCsv['entities_accounts'] = @(
    [pscustomobject]@{ Account = 'DESKTOP-LAB-01\alice' },
    [pscustomobject]@{ Account = 'bob' },
    [pscustomobject]@{ Account = 'NT VIRTUAL MACHINE\aa4f2c9e' },
    [pscustomobject]@{ Account = 'SYSTEM' }
)

# ---- P1: findings JSON ----
New-FindingsJson -CaseDir $tmp
$fj = Get-Content (Join-Path $tmp 'ophira_findings.json') -Raw | ConvertFrom-Json
Check 'P1 schema key' ("$($fj.schema)" -eq 'ophira-findings/1')
Check 'P1 tool key' ("$($fj.tool)" -match 'Ophira v5\.6')
Check 'P1 identity host' ("$($fj.identity.host)" -eq 'LAB-HOST-01')
Check 'P1 identity client' ("$($fj.identity.client)" -eq 'Contoso Ltd')
Check 'P1 identity case_id' ("$($fj.identity.case_id)" -eq 'INC-TEST-42')
Check 'P1 collected_utc from case.json' ("$($fj.identity.collected_utc)" -match '2026-11-24')
Check 'P1 preset from case.json' ("$($fj.identity.preset)" -eq 'Standard')
Check 'P1 verdict level' ("$($fj.verdict.level)" -eq 'SUSPICIOUS')
Check 'P1 verdict signals embedded' (@($fj.verdict.signals)[0].Signal -eq 'Test signal')
Check 'P1 caveats embedded' (@($fj.verdict.caveats)[0] -eq 'caveat one')
Check 'P1 coverage totals' ($fj.coverage.sources_collected -eq 24 -and $fj.coverage.sources_total -eq 33)
Check 'P1 coverage missing only uncollected' (@($fj.coverage.missing).Count -eq 1 -and @($fj.coverage.missing)[0].Source -eq 'Live memory triage')
Check 'P1 leads empty (none in fixture)' (@($fj.leads).Count -eq 0)
Check 'P1 campaign null' ($null -eq $fj.campaign)

# leads embedding: 3 rows capped at first 50, schema passthrough
$script:caseCsv['leads'] = @(1..60 | ForEach-Object { [pscustomobject]@{ Rank = 'high'; Title = "lead $_" } })
New-FindingsJson -CaseDir $tmp
$fj2 = Get-Content (Join-Path $tmp 'ophira_findings.json') -Raw | ConvertFrom-Json
Check 'P1 leads capped at 50' (@($fj2.leads).Count -eq 50)
$script:caseCsv['leads'] = @()

# no verdict -> verdict/coverage null, still valid json
$script:Verdict = $null
New-FindingsJson -CaseDir $tmp
$fj3 = Get-Content (Join-Path $tmp 'ophira_findings.json') -Raw | ConvertFrom-Json
Check 'P1 verdict null when engine silent' ($null -eq $fj3.verdict -and $null -eq $fj3.coverage)
$script:Verdict = $null

# ---- P2: fleet client boundaries ----
$vMap = @{ 'host-a' = 'SUSPICIOUS'; 'host-b' = 'NO EVIDENCE'; 'host-c' = 'NO EVIDENCE' }
$hashRows = @([pscustomobject]@{ SHA256 = 'aa'; Name = 'evil.exe'; Hosts = 'host-a, host-b'; MultiHost = 'YES' })

# same client -> merges into one campaign
$clientBy = @{ 'host-a' = 'Contoso'; 'host-b' = 'Contoso' }
$rows = @(New-FleetCampaigns -HashRows $hashRows -CrossRows @() -Lateral @() -Waves @() -AllHosts @('host-a', 'host-b') -Verdicts $vMap -ClientBy $clientBy)
Check 'P2 same client merges' ($rows.Count -eq 1 -and $rows[0].HostCount -eq 2)
Check 'P2 campaign Client column set' ("$($rows[0].Client)" -eq 'Contoso')

# different clients -> no merge + tie recorded
$script:FleetCrossClientTies = $null
$clientBy2 = @{ 'host-a' = 'Contoso'; 'host-b' = 'Fabrikam' }
$rows2 = @(New-FleetCampaigns -HashRows $hashRows -CrossRows @() -Lateral @() -Waves @() -AllHosts @('host-a', 'host-b') -Verdicts $vMap -ClientBy $clientBy2)
Check 'P2 cross-client never merges' ($rows2.Count -eq 0)
Check 'P2 tie recorded' ($null -ne $script:FleetCrossClientTies -and $script:FleetCrossClientTies.Count -eq 1)
Check 'P2 tie details' ("$($script:FleetCrossClientTies[0].ClientA)" -eq 'Contoso' -and "$($script:FleetCrossClientTies[0].ClientB)" -eq 'Fabrikam' -and "$($script:FleetCrossClientTies[0].HostA)" -eq 'host-a')

# three hosts, one tie crosses clients: a-b same client merges, b-c cross-client kept apart
$hashRows3 = @(
    [pscustomobject]@{ SHA256 = 'aa'; Name = 'evil.exe'; Hosts = 'host-a, host-b'; MultiHost = 'YES' },
    [pscustomobject]@{ SHA256 = 'bb'; Name = 'tool.exe'; Hosts = 'host-b, host-c'; MultiHost = 'YES' }
)
$script:FleetCrossClientTies = $null
$clientBy3 = @{ 'host-a' = 'Contoso'; 'host-b' = 'Contoso'; 'host-c' = 'Fabrikam' }
$rows3 = @(New-FleetCampaigns -HashRows $hashRows3 -CrossRows @() -Lateral @() -Waves @() -AllHosts @('host-a', 'host-b', 'host-c') -Verdicts $vMap -ClientBy $clientBy3)
Check 'P2 partial chain: a+b merged, c separate' ($rows3.Count -eq 1 -and $rows3[0].HostCount -eq 2 -and $rows3[0].Hosts -notmatch 'host-c')
Check 'P2 partial chain tie row' ($script:FleetCrossClientTies.Count -eq 1 -and "$($script:FleetCrossClientTies[0].HostB)" -eq 'host-c')

# legacy behavior: no ClientBy -> merges as before (backward compat)
$rows4 = @(New-FleetCampaigns -HashRows $hashRows -CrossRows @() -Lateral @() -Waves @() -AllHosts @('host-a', 'host-b') -Verdicts $vMap)
Check 'P2 legacy no-ClientBy merges' ($rows4.Count -eq 1)

# ---- P3: redacted copy ----
New-RedactedCopy -CaseDir $tmp
$red = Get-Content (Join-Path $tmp 'report_redacted.html') -Raw
Check 'P3 redacted file written' (Test-Path (Join-Path $tmp 'report_redacted.html'))
Check 'P3 banner present' ($red -match 'REDACTED COPY')
Check 'P3 host tokenized' ($red -notmatch 'LAB-HOST-01' -and $red -match 'HOST-1')
Check 'P3 user tokenized' ($red -notmatch '\balice\b' -and $red -match 'USER-2')
Check 'P3 analyst tokenized as user' ($red -notmatch '\bjsmith\b' -and $red -match 'USER-1')
Check 'P3 bare user tokenized' ($red -notmatch '\bbob\b' -and $red -match 'USER-3')
Check 'P3 internal IP tokenized' ($red -notmatch '10\.1\.2\.3' -and $red -notmatch '192\.168\.5\.6' -and $red -match 'IP-INT-1' -and $red -match 'IP-INT-2')
Check 'P3 public IP untouched' ($red -match '8\.8\.8\.8')
Check 'P3 MAC tokenized' ($red -notmatch 'aa:bb:cc:dd:ee:ff' -and $red -match 'MAC-1')
Check 'P3 corp-domain tokenized' ($red -notmatch 'intranet\.corp' -and $red -match 'HOST-2')
Check 'P3 external domain untouched' ($red -match 'evil\.example\.com')
Check 'P3 hyperv guid not a user token' ($red -match 'NT VIRTUAL MACHINE')
Check 'P3 wellknown SYSTEM untouched' ($red -match 'SYSTEM')
$map = @(Import-Csv (Join-Path $tmp 'redact_map.csv'))
Check 'P3 map rows present' ($map.Count -ge 6)
Check 'P3 map has host+user+ip+mac' ((@($map | Where-Object Type -eq 'HOST').Count -ge 1) -and (@($map | Where-Object Type -eq 'USER').Count -ge 1) -and (@($map | Where-Object Type -eq 'IP-INT').Count -ge 2) -and (@($map | Where-Object Type -eq 'MAC').Count -eq 1))

# no report.html -> honest skip
$logBefore = $script:lastLog
New-RedactedCopy -CaseDir (Join-Path $tmp 'nope')
Check 'P3 missing report honest skip' ("$script:lastLog" -match 'no report\.html')

# ---- P4: wiring pins ----
Check 'P4 param ClientName declared' ($src -match '\[string\]\$ClientName')
Check 'P4 param Redact declared' ($src -match '\[switch\]\$Redact')
Check 'P4 help ClientName' ($src -match '\.PARAMETER ClientName')
Check 'P4 help Redact' ($src -match '\.PARAMETER Redact')
Check 'P4 case.json ClientName row' ($src -match 'ClientName = "\$script:ClientName"')
Check 'P4 parse adopt ClientName' ($src -match '\$script:ClientName = "\$\(\$meta\.ClientName\)"')
Check 'P4 provenance Client seg' ($src -match 'Client: \$\(ConvertTo-HtmlEsc \$script:ClientName\)')
Check 'P4 regen findings step' ($src.Contains("& `$rgStep 'findings json' 'New-FindingsJson'"))
Check 'P4 redact hook in parse tail' ($src -match 'New-RedactedCopy -CaseDir \(Split-Path -Parent \$script:CsvDir\)')
Check 'P4 fleet hosts Client column' ($src -match 'Client = \$\(if \(\$meta -and "\$\(\$meta\.ClientName\)"\)')
Check 'P4 fleet call passes ClientBy' ($src -match '-Verdicts \$vMap -ClientBy \$clientBy')
Check 'P4 cross-client export' ($src -match 'fleet_cross_client_ties\.csv')
Check 'P4 fleet hosts csv Client' ($src -match 'Select-Object Host, Client, Verdict, VerdictRank')
Check 'P4 fleet html Client header' ($src -match '<th>Host</th><th>Client</th><th>Verdict</th>')

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($fail -gt 0) { Write-Host "FAILED: $fail check(s)"; exit 1 }
Write-Host 'ALL PASSED'
exit 0
