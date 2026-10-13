# test_v255.ps1 - v2.55 report-truthfulness fixes
# Static assertions on Ophira.ps1 source (Contains / regex, no fixture parse)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$fail = 0
function Assert-Has([string]$needle, [string]$label) {
    if ($src.Contains($needle)) { Write-Host "[ok] $label" -ForegroundColor Green }
    else { Write-Host "[FAIL] $label - not found: $needle" -ForegroundColor Red; $script:fail++ }
}
function Assert-Lacks([string]$needle, [string]$label) {
    if (-not $src.Contains($needle)) { Write-Host "[ok] $label" -ForegroundColor Green }
    else { Write-Host "[FAIL] $label - forbidden text present: $needle" -ForegroundColor Red; $script:fail++ }
}
function Assert-Match([string]$pattern, [string]$label) {
    if ($src -match $pattern) { Write-Host "[ok] $label" -ForegroundColor Green }
    else { Write-Host "[FAIL] $label - regex not found: $pattern" -ForegroundColor Red; $script:fail++ }
}

# ---- Task 1: 7 lying bugs ----
# 1a confidence label
Assert-Has 'Evidence coverage: ' '1a confidence renamed to coverage'
Assert-Has 'how much of the case was collected' '1a coverage not probability note'
Assert-Lacks '(evidence coverage)' '1a old confidence wording gone'

# 1b leads pointer fallback
Assert-Has 'work the leads below (or review the Sigma findings' '1b leads pointer fallback'

# 1c log-clearing overclaim
Assert-Has '$gapTamperRec' '1c gap tamper variable'
Assert-Has 'Chronological gaps detected in event logs' '1c honest gap wording'
Assert-Lacks "if (`$gapRows.Count -gt 0) {`r`n        `$recs.Add('Security log clearing" '1c old unconditional clear claim gone'

# 1d elevation source
Assert-Has 'AdminElevated' '1d case.json AdminElevated read'
Assert-Has '$elevLabel' '1d elevation label variable'
Assert-Has '$recElev' '1d recommendation elevation variable'

# 1e remote endpoint IP + VT link
Assert-Has 'ConvertTo-HtmlEsc $e.Remote) $(New-VtLink' '1e remote IP shown with VT link'

# 1f case-draft count
Assert-Has '@($ft2.SourcesHit.PSObject.Properties).Count' '1f case-draft count wrapped'

# 1g MFT path
Assert-Has "Join-Path `$dl (`$parent -replace" '1g MFT path Join-Path fix'
Assert-Lacks '"$dl$parent\$name"' '1g old C:. concat gone'

# ---- Task 2 markers (sigma dedupe + self-noise) ----
Assert-Has 'Test-SigmaSelfNoise' '2b self-noise helper exists'
Assert-Has "'Test-SigmaSelfNoise'" '2b self-noise in SharedFunctions'
Assert-Match 'CollectorPids' '2a collector PID capture'
Assert-Has 'Sigma volume signal' '2e sigma volume signal'

# ---- Task 3 markers (defender 1116) ----
Assert-Has 'evtx-history' '3b defender evtx-history source label'
Assert-Has 'DetectedUTC' '3a 1116 DetectedUTC column'
Assert-Has 'ResourcePath' '3a 1116 ResourcePath column'

# ---- Task 4 markers (scoring credits) ----
Assert-Has 'runs-from-user-path' '4a user-path credit'
Assert-Has 'persistence:task(' '4a task-persist credit'
Assert-Match 'non-cloud' '4a non-cloud credit'

# ---- Task 5 markers (cloud-IP table) ----
Assert-Has 'Get-IpCloudClass' '5a cloud classifier exists'
Assert-Has "'Get-IpCloudClass'" '5b wired into SharedFunctions or scoring'

# ---- Task 6 markers (leads from medium) ----
Assert-Has 'sigma volume spike' '6a sigma storm lead source'
Assert-Has 'process lineage:' '6a process chain lead source'
Assert-Has 'non-cloud public IP' '6a non-cloud conn lead source'

# ---- Task 7 markers (logon multi-EID + signals) ----
Assert-Match "EventId -eq '4648'|4648" '7a 4648 in logon section'
Assert-Has 'Security posture gaps' '7b posture signal'
Assert-Has 'Credential material exposure' '7c credential sweep signal'

# ---- console truthfulness (matches the report banner wording) ----
Assert-Has 'evidence coverage $($v.ConfidencePercent)% of expected sources' 'consoles: draft line says coverage'
Assert-Has 'VERDICT: $($script:Verdict.Level) (evidence coverage' 'consoles: verdict log says coverage'
Assert-Has 'VERDICT     : $($script:Verdict.Level)  (evidence coverage' 'consoles: summary screen says coverage'

if ($fail -gt 0) { Write-Host "`n$fail assertion(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nALL v255 ASSERTIONS PASSED" -ForegroundColor Green
exit 0
