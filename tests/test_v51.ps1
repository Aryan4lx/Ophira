# test_v51.ps1 - v5.2 locale-invariant evidence-time parsing
# The 5 report/focus/verdict sort+format sites now route through Get-InvariantDate, so
# evidence stamps parse identically on ANY analyst locale. Proof: compute ticks under
# en-US and de-DE current culture - must match, and en-US stamps must not fail on de-DE.
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$fails = 0
function Check($name, $ok) {
    if ($ok) { Write-Host "[PASS] $name" } else { Write-Host "[FAIL] $name"; $script:fails++ }
}

# extract Get-InvariantDate and IEX it
$m = [regex]::Match($src, '(?s)function Get-InvariantDate \{.*?\r?\n\}')
Check 'extract Get-InvariantDate' $m.Success
Invoke-Expression $m.Value

$enUS = [Globalization.CultureInfo]::GetCultureInfo('en-US')
$deDE = [Globalization.CultureInfo]::GetCultureInfo('de-DE')
$stamps = @('10/27/2026 10:15:00 PM', '2026-11-01 11:49:58', '2025-12-31T20:30:00Z', '10/28/2026 1:13:14 PM', 'not a date', '')

foreach ($s in $stamps) {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $enUS
    $t1 = (Get-InvariantDate $s).Ticks
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $deDE
    $t2 = (Get-InvariantDate $s).Ticks
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $enUS
    Check ("ticks locale-stable: '{0}'" -f $s) ($t1 -eq $t2)
}

# en-US stamp must actually PARSE (non-MinValue) - the de-DE culture-default bug was silent failure
[System.Threading.Thread]::CurrentThread.CurrentCulture = $deDE
Check 'en-US stamp parses under de-DE via helper' ((Get-InvariantDate '10/27/2026 10:15:00 PM') -ne [datetime]::MinValue)
Check 'ISO-Z parses' ((Get-InvariantDate '2025-12-31T20:30:00Z') -ne [datetime]::MinValue)
[System.Threading.Thread]::CurrentThread.CurrentCulture = $enUS

Check 'garbage -> MinValue' ((Get-InvariantDate 'not a date') -eq [datetime]::MinValue)
Check 'empty -> MinValue' ((Get-InvariantDate '') -eq [datetime]::MinValue)

# ordering: en-US PM stamp must beat the 2025 ISO stamp (lexical compare used to invert)
$tPm = (Get-InvariantDate '10/28/2026 1:13:14 PM').Ticks
$tIso = (Get-InvariantDate '2025-12-31T20:30:00Z').Ticks
Check 'ticks ordering correct across dialects' ($tPm -gt $tIso)

# wiring pins: old culture-default TryParse sites are gone
Check 'no culture-default TryParse left in report sorts' (-not $src.Contains('if ($s -and [datetime]::TryParse($s, [ref]$d))'))
Check 'report fmtTs routes Get-InvariantDate' $src.Contains('$fmtTs = { param($v5) $d5 = Get-InvariantDate')
Check 'focus group sort routes Get-InvariantDate' $src.Contains('Sort-Object { (Get-InvariantDate $_.Time).Ticks }')
Check 'defender detail routes Get-InvariantDate' $src.Contains('$d = Get-InvariantDate $ts; if ($d -ne [datetime]::MinValue)')
Check 'version bumped' ($src.Contains('Ophira v6.1') -and $src.Contains('$ScriptVersion = "6.1"'))

Write-Host ''
if ($fails -eq 0) { Write-Host 'ALL PASSED' ; exit 0 } else { Write-Host "$fails FAILED"; exit 1 }
