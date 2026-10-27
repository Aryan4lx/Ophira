$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'
# v2.80 T3 tests - F2 union schema in Save-Rows: mixed event-ID lists (4.9 Kerberos 4768/4769,
# ds_access 4662/5136) must export a CSV header carrying the UNION of all rows' properties, so
# R17 (TicketEnc) and R18 (PreAuth) can never be killed by row order. Behavioral suite: extracts
# Save-Rows, stubs the case-IO helpers, feeds synthetic rows, reads the CSVs back.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- extract Save-Rows (house pattern: lazy match to column-0 closing brace) ----
$ms = [regex]::Match($src, '(?s)function Save-Rows \{.*?\r?\n\}')
if (-not $ms.Success) { throw 'Save-Rows extract failed' }

# ---- stubs for the helpers Save-Rows calls + a per-run temp case csv dir ----
$TestDir = Join-Path $env:TEMP "ophira_t3_$(Get-Random)"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
$script:SavedArtifacts = New-Object System.Collections.Generic.List[object]
function Get-CaseCsvPath { param([string]$Name) "$Name.csv" }
function Get-CaseCsvFullPath { param([string]$Name) Join-Path $TestDir "$Name.csv" }
function Write-CaseLog { param($Msg, $Color) }
Invoke-Expression $ms.Value

# synthetic rows in the exact shape Get-EventDataRows emits (Time, EventId, then mapped fields)
function New-KerRow([string]$Id, [hashtable]$Fields) {
    $o = [ordered]@{ Time = '2026-10-27 10:00:00'; EventId = $Id }
    foreach ($k in $Fields.Keys) { $o[$k] = "$($Fields[$k])" }
    [pscustomobject]$o
}

try {
    # ---- pin 1: 4768-first sequence followed by a 4769 row -> TicketEnc survives in the header ----
    $ker1 = @(
        (New-KerRow '4768' @{ Account = 'alice'; Service = 'krbtgt'; IpAddress = '10.0.0.5'; PreAuth = '15'; Status = '0x0' }),
        (New-KerRow '4769' @{ Account = 'bob'; Service = 'MSSQLSvc'; IpAddress = '10.0.0.6'; TicketEnc = '0x17'; Status = '0x0' })
    )
    Save-Rows -Name 'security_kerberos' -Rows $ker1
    $csv1 = Import-Csv -LiteralPath (Join-Path $TestDir 'security_kerberos.csv')
    $hdr1 = ((Get-Content -LiteralPath (Join-Path $TestDir 'security_kerberos.csv') -First 1) -split ',').Trim(' "') # manual header split keeps quote chars (AGENTS.md)
    Check "4768-first: header contains TicketEnc" ($hdr1 -contains 'TicketEnc')
    Check "4768-first: header keeps the 4768 columns" (($hdr1 -contains 'PreAuth') -and ($hdr1 -contains 'Service'))
    Check "4768-first: 4769 row's TicketEnc value round-trips" ("$(@($csv1 | Where-Object { "$($_.EventId)" -eq '4769' })[0].TicketEnc)" -eq '0x17')

    # ---- pin 2: 4769-first sequence followed by a 4768 row -> PreAuth survives in the header ----
    $ker2 = @(
        (New-KerRow '4769' @{ Account = 'svc-a'; Service = 'cifs'; IpAddress = '10.0.0.7'; TicketEnc = '0x12'; Status = '0x0' }),
        (New-KerRow '4768' @{ Account = 'asrep-user'; Service = 'krbtgt'; IpAddress = '10.0.0.8'; PreAuth = '0'; Status = '0x0' })
    )
    Save-Rows -Name 'security_kerberos_rev' -Rows $ker2
    $csv2 = Import-Csv -LiteralPath (Join-Path $TestDir 'security_kerberos_rev.csv')
    $hdr2 = ((Get-Content -LiteralPath (Join-Path $TestDir 'security_kerberos_rev.csv') -First 1) -split ',').Trim(' "')
    Check "4769-first: header contains PreAuth" ($hdr2 -contains 'PreAuth')
    Check "4769-first: header keeps TicketEnc" ($hdr2 -contains 'TicketEnc')
    Check "4769-first: 4768 row's PreAuth value round-trips" ("$(@($csv2 | Where-Object { "$($_.EventId)" -eq '4768' })[0].PreAuth)" -eq '0')

    # ---- pin 3: security_ds_access union - 4662-first then 5136 keeps ObjectDN/Attribute/Value ----
    $ds = @(
        (New-KerRow '4662' @{ Account = 'evil$'; Object = 'DS010904'; OpType = 'Object Access'; Properties = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }),
        (New-KerRow '5136' @{ Account = 'admin'; ObjectDN = 'CN=AdminSDHolder,DC=corp,DC=local'; OpType = 'Value Added'; Attribute = 'member'; Value = 'CN=hacker,CN=Users,DC=corp,DC=local' })
    )
    Save-Rows -Name 'security_ds_access' -Rows $ds
    $dsCsv = Import-Csv -LiteralPath (Join-Path $TestDir 'security_ds_access.csv')
    $r5136 = @($dsCsv | Where-Object { "$($_.EventId)" -eq '5136' })[0]
    Check "ds_access 4662-first: ObjectDN survives in the CSV" ($r5136.ObjectDN -like '*AdminSDHolder*')
    Check "ds_access 4662-first: Attribute + Value round-trip" (($r5136.Attribute -eq 'member') -and ($r5136.Value -like '*hacker*'))

    # ---- pin 4: single-schema lists are byte-identical to plain Export-Csv (no behavior change) ----
    $plain = @(1..50 | ForEach-Object { New-KerRow '4769' @{ Account = "u$_"; Service = 'cifs'; IpAddress = "10.0.0.$_"; TicketEnc = '0x12'; Status = '0x0' } })
    Save-Rows -Name 'plain_union' -Rows $plain
    $plain | Export-Csv -LiteralPath (Join-Path $TestDir 'plain_direct.csv') -NoTypeInformation -Encoding UTF8
    $bU = [System.IO.File]::ReadAllBytes((Join-Path $TestDir 'plain_union.csv'))
    $bD = [System.IO.File]::ReadAllBytes((Join-Path $TestDir 'plain_direct.csv'))
    Check "single-schema: union Save-Rows output byte-identical to plain Export-Csv ($($bU.Length) bytes)" ((($bU.Length -eq $bD.Length)) -and (-not (Compare-Object $bU $bD -SyncWindow 0)))

    # ---- pin 5: R17's reader logic works against the union CSV (RC4 TGS filter finds rows after 4768s) ----
    $ker3 = @(
        (New-KerRow '4768' @{ Account = 'a1'; Service = 'krbtgt'; IpAddress = '10.0.0.9'; PreAuth = '15'; Status = '0x0' }),
        (New-KerRow '4768' @{ Account = 'a2'; Service = 'krbtgt'; IpAddress = '10.0.0.9'; PreAuth = '15'; Status = '0x0' }),
        (New-KerRow '4769' @{ Account = 'sql-svc'; Service = 'MSSQLSvc/sql.corp.local:1433'; IpAddress = '10.0.0.9'; TicketEnc = '0x17'; Status = '0x0' }),
        (New-KerRow '4769' @{ Account = 'sql-svc'; Service = 'MSSQLSvc/bk.corp.local:1433'; IpAddress = '10.0.0.9'; TicketEnc = '0x17'; Status = '0x0' })
    )
    Save-Rows -Name 'r17_probe' -Rows $ker3
    $r17rows = @(Import-Csv -LiteralPath (Join-Path $TestDir 'r17_probe.csv'))
    # R17 filter exactly as written at Ophira.ps1 R17: -eq '4769' -and TicketEnc -eq '0x17'
    $tgs = @($r17rows | Where-Object { "$($_.EventId)" -eq '4769' -and "$($_.TicketEnc)" -eq '0x17' })
    Check "R17 reader logic: RC4 TGS rows found in 4768-first union CSV (got $($tgs.Count), need 2)" ($tgs.Count -eq 2)

    # ---- guards for the region this fix touched: empty marker + SavedArtifacts bookkeeping ----
    Save-Rows -Name 'empty_probe' -Rows @()
    $emptyFirst = Get-Content -LiteralPath (Join-Path $TestDir 'empty_probe.csv') -First 1
    Check "empty list still writes the '# no entries' marker" ($emptyFirst -eq '# no entries')
    $book = @{}
    foreach ($a in $script:SavedArtifacts) { $book[$a.Path] = $a.Rows }
    Check "SavedArtifacts bookkeeping unchanged (rows counted, empty = 0)" (($book['csv\r17_probe.csv'] -eq 4) -and ($book['csv\empty_probe.csv'] -eq 0))
} finally {
    Remove-Item -LiteralPath $TestDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
