# v6.1: sigma baseline-diff (New-SigmaBaseline) + fleet campaign narrative pins
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_casehelpers.ps1')
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fail = 0; $n = 0
function Check([string]$Name, [bool]$Ok) {
    $script:n++
    if (-not $Ok) { $script:fail++; Write-Host "[FAIL] $Name" } else { Write-Host "[ ok ] $Name" }
}
# extract the functions under test
foreach ($fn in @('New-SigmaBaseline', 'Get-LvlRank')) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { Write-Host "EXTRACT FAILED: $fn"; exit 1 }
    Invoke-Expression $m.Value
}
$script:log = New-Object System.Collections.Generic.List[string]
function Write-CaseLog([string]$m) { $script:log.Add("$m") }
$script:saved = @{}
function Save-Rows([string]$Name, $Rows) { $script:saved[$Name] = @($Rows) }
function Import-CaseCsv([string]$Name) {
    if ($null -ne $script:caseCsv[$Name]) { return @($script:caseCsv[$Name]) }
    return @()
}
function Get-CaseCsvFullPath([string]$Name) { return Join-Path $env:TEMP ("oph61_" + $Name) }

$baseDir = Join-Path $env:TEMP 'baselines'
if (Test-Path $baseDir) { Remove-Item $baseDir -Recurse -Force }
$script:SigmaBaselineRoot = $env:TEMP
$script:Computer = 'TESTBOX'

# P1: first run - all rules NEW, baseline file written
$row = { param($rule, $level) [pscustomobject]@{ Rule = $rule; Level = $level; Time = '2026-11-25 10:00:00'; Computer = 'TESTBOX'; EventID = 4688; Details = 'x' } }
$script:caseCsv = @{ 'hayabusa_timeline.csv' = @(& $row 'Credential Manager Accessed' 'low'; & $row 'Credential Manager Accessed' 'low'; & $row 'Potential Suspicious PowerShell Keywords' 'med') }
New-SigmaBaseline
Check 'P1: diff saved with 2 rules' ($script:saved['sigma_baseline_diff'].Count -eq 2)
$d1 = @($script:saved['sigma_baseline_diff'] | Where-Object { "$($_.Rule)" -eq 'Credential Manager Accessed' })[0]
Check 'P1: first run class = new' ("$($d1.Class)" -eq 'new')
Check 'P1: hits counted' ("$($d1.Hits)" -eq '2')
$bf = Join-Path $baseDir 'sigma_TESTBOX.csv'
Check 'P1: baseline file written' (Test-Path $bf)
$b1 = Import-Csv -LiteralPath $bf
Check 'P1: baseline SeenCount=1 HitsSum=2' ("$(($b1 | Where-Object { $_.Rule -eq 'Credential Manager Accessed' }).SeenCount)" -eq '1' -and "$(($b1 | Where-Object { $_.Rule -eq 'Credential Manager Accessed' }).HitsSum)" -eq '2')

# P2: second run, same volume -> chronic (2 vs avg 2.0; 2 < 2*2+5)
$script:caseCsv = @{ 'hayabusa_timeline.csv' = @(& $row 'Credential Manager Accessed' 'low'; & $row 'Credential Manager Accessed' 'low') }
New-SigmaBaseline
$d2 = @($script:saved['sigma_baseline_diff'] | Where-Object { "$($_.Rule)" -eq 'Credential Manager Accessed' })[0]
Check 'P2: same volume class = chronic' ("$($d2.Class)" -eq 'chronic')
Check 'P2: PrevSeen/PrevAvg carried' ("$($d2.PrevSeen)" -eq '1' -and "$($d2.PrevAvg)" -eq '2')

# P3: spike - 12 hits vs avg 2.0 (12 >= 2*2+5)
$many = @(); for ($i = 0; $i -lt 12; $i++) { $many += & $row 'Credential Manager Accessed' 'low' }
$script:caseCsv = @{ 'hayabusa_timeline.csv' = $many }
New-SigmaBaseline
$d3 = @($script:saved['sigma_baseline_diff'] | Where-Object { "$($_.Rule)" -eq 'Credential Manager Accessed' })[0]
Check 'P3: volume burst class = spike' ("$($d3.Class)" -eq 'spike')
$lg = ($script:log -match 'sigma baseline:')[0]
Check 'P3: log line has new/spiked/chronic counts' ("$lg" -match 'sigma baseline: \d+ rule\(s\) diffed vs \d+ prior collection\(s\) \(\d+ new, \d+ spiked, \d+ chronic\)')

# P4: safe-host filename (weird computer names never escape the baselines dir)
$script:Computer = 'HOST<|>WEIRD'
$script:caseCsv = @{ 'hayabusa_timeline.csv' = @(& $row 'R1' 'low') }
New-SigmaBaseline
Check 'P4: unsafe host chars sanitized' ((Get-ChildItem $baseDir -Filter 'sigma_*.csv' | Where-Object { $_.Name -notmatch '^sigma_[A-Za-z0-9_.-]+\.csv$' }).Count -eq 0)

if (Test-Path $baseDir) { Remove-Item $baseDir -Recurse -Force }

# P5: wiring pins
Check 'P5: CsvCatMap derived entry' ($src.Contains("'sigma_baseline_diff' = 'derived'"))
Check 'P5: emptyWhy honesty entry' ($src.Contains("baselines\sigma_<host>.csv"))
Check 'P5: regen step wired' ($src.Contains("& `$rgStep 'sigma baseline diff' 'New-SigmaBaseline' { New-SigmaBaseline }"))
Check 'P5: report imports diff' ($src.Contains("Import-CaseCsv 'sigma_baseline_diff.csv'"))
Check 'P5: report meta line' ($src.Contains('compared against $sbPrior prior collection(s)'))
Check 'P5: chronic annotation only below crit/high' ($src.Contains("-notmatch '^(critical|high)$'") -and $src.Contains('chronic x'))
Check 'P5: fleet campaign narrative' ($src.Contains('Campaign story (largest cluster)'))
Check 'P5: version 6.1' ($src.Contains('Ophira v6.1') -and $src.Contains('$ScriptVersion = "6.1"'))

Write-Host "test_v61: $n checks, $fail failed"
if ($fail -gt 0) { exit 1 }
exit 0
