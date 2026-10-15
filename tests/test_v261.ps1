# test_v261.ps1 - Assessment at a glance: negative evidence + verdict meaning + incident window
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- behavioral: Get-CleanCheckSummary against fixture CSVs ----
$m = [regex]::Match($src, "(?s)function Get-CleanCheckSummary \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-CleanCheckSummary extract failed' }
Invoke-Expression $m.Value
function Test-CaseCsv([string]$n) { return $script:existing.ContainsKey($n) }
function Get-IocList { return $script:feed }
$script:existing = @{}
$script:feed = $null
$fx = @{}

# case 1: sources ran, everything clean -> rows with examined counts where available
$fx['hayabusa_timeline'] = @(1..40 | ForEach-Object { [pscustomobject]@{ Timestamp = "2026-10-01 10:$_(`"{0:d2}`" -f ($_ % 60)):00"; Level = 'info'; RuleTitle = 'info rule'; Channel = 'Sys' } })
$fx['yara_scanned'] = @([pscustomobject]@{ File = 'a.exe'; SHA256 = 'x'; Hits = 0; Rules = '' })
$fx['security_auth_events'] = @(1..12 | ForEach-Object { [pscustomobject]@{ Time = '2026-10-01 10:00:00'; EventId = 4624; Account = 'u' } })
$fx['flash_public_connections'] = @([pscustomobject]@{ RemoteAddress = '1.2.3.4'; RemotePort = 443 })
# v2.64: the beacon clean row keys on telemetry PRESENCE (Test-CaseCsv, same inputs the verdict
# uses) instead of row counts - so the fixture must mark flash_public_connections collected.
$existing = @{ hunt_findings = $true; usn_write_bursts = $true; loldrivers_hits = $true; logging_gaps = $true; credential_sweep = $true; svchost_audit = $true; wmi_event_consumers = $true; flash_public_connections = $true }
$feed = @{ Hashes = @{ 'deadbeef' = $true }; Ips = @{}; Domains = @{ 'bad.example' = $true }; Names = @{} }
function Import-CaseCsv([string]$name) { if ($fx.ContainsKey($name)) { return $fx[$name] }; return @() }
$clean = @(Get-CleanCheckSummary)
$byName = @{}; foreach ($c in $clean) { $byName[$c.Check] = $c }
Check "sigma: 40 events, 0 crit/high -> clean row with count" ($byName['Sigma rule scan'].Detail -match '40 events scanned, 0 critical/high')
Check "yara: 1 scanned, 0 hits -> clean row" ($byName['YARA scan'].Detail -match '1 binaries scanned, 0 matched')
Check "ioc xref: 2 indicators, 0 hits across surfaces -> clean row" ($byName['IOC feed cross-reference'].Detail -match '2 indicators checked')
Check "beacon: network data present, 0 candidates -> clean row" ($byName['Beacon detection'] -ne $null)
Check "hunt/usn/loldrivers/logintegrity/cred/svchost/wmi all render clean rows" ((@('Technique hunt rules', 'Mass file modification scan', 'Loaded driver check', 'Log integrity', 'Credential exposure sweep', 'svchost masquerade audit', 'WMI event subscriptions') | Where-Object { $byName[$_] } | Measure-Object).Count -eq 7)
Check "brute force: 12 logon events analyzed" ($byName['Brute-force analysis'].Detail -match '12 logon events analyzed')

# case 2: findings exist -> those checks are OMITTED (they render as signals), clean ones stay
$fx['yara_hits'] = @([pscustomobject]@{ File = 'evil.exe'; Severity = 'high'; Rule = 'Ransom' })
$fx['hayabusa_timeline'] = @([pscustomobject]@{ Timestamp = '2026-10-01 10:00:00'; Level = 'crit'; RuleTitle = 'Defender Alert'; Channel = 'Defender' })
$fx['credential_sweep'] = @([pscustomobject]@{ Item = 'dump'; Detail = 'x'; Risk = 'HIGH' })
$fx['hunt_findings'] = @([pscustomobject]@{ Found = '2026-10-01'; Rule = 'USB execution trail'; Severity = 'info'; Entity = 'x'; Attck = 'T1091'; Evidence = 'y' })
$clean2 = @(Get-CleanCheckSummary)
$byName2 = @{}; foreach ($c in $clean2) { $byName2[$c.Check] = $c }
Check "sigma with a crit finding -> NO clean row (it renders as a signal)" ($byName2['Sigma rule scan'] -eq $null)
Check "yara with a hit -> NO clean row" ($byName2['YARA scan'] -eq $null)
Check "credential HIGH -> NO clean row" ($byName2['Credential exposure sweep'] -eq $null)
Check "hunt findings present (even info-level) -> NO clean row" ($byName2['Technique hunt rules'] -eq $null)
Check "unrelated clean rows still render" ($byName2['Mass file modification scan'] -ne $null)

# case 3: no network telemetry -> beacon check must NOT claim clean
# v2.64: the gate is presence-based, so the fixture drops flash_public_connections from the
# collected map (removing the row data alone no longer changes the verdict-input view)
$fx.Remove('flash_public_connections')
$existing.Remove('flash_public_connections')
$fx['hayabusa_timeline'] = @()
$fx['credential_sweep'] = @()
$clean3 = @(Get-CleanCheckSummary)
$byName3 = @{}; foreach ($c in $clean3) { $byName3[$c.Check] = $c }
Check "no network data -> no beacon-clean claim (honest omission)" ($byName3['Beacon detection'] -eq $null)

# ---- statics: banner wiring ----
Check "banner retitled to Assessment at a glance" ($src -match [regex]::Escape("<h2>Assessment at a glance</h2>"))
Check "verdict meaning line per rank" ($src -match [regex]::Escape('This is not a guarantee: the clean-check list shows exactly what was verified'))
Check "banner renders the clean-check list" ($src -match [regex]::Escape('<b>Checked and clean</b>'))
Check "clean rows use the green badge" ($src -match [regex]::Escape("<span class='badge LOW'>clean</span>"))
Check "evidence window line with busiest day" ($src -match [regex]::Escape('<b>Evidence window:</b>'))
Check "caveats retitled could-not-check" ($src -match [regex]::Escape('<b>Could not check / what would change this verdict</b>'))
Check "helper is report-side only (no Save-Rows writes)" ($m.Value -notmatch 'Save-Rows')

if ($fail -gt 0) { Write-Host "`ntest_v261: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v261: $pass passed, 0 failed" -ForegroundColor Green
exit 0
