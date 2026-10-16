# test_v256.ps1 - v2.56 report-weaves-the-story: entity cross-links, file links, conn dedupe, focus embed
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$fail = 0
function Assert-Has([string]$needle, [string]$label) {
    if ($src.Contains($needle)) { Write-Host "[ok] $label" -ForegroundColor Green }
    else { Write-Host "[FAIL] $label - not found: $needle" -ForegroundColor Red; $script:fail++ }
}

# ---- Task 9: entity cross-links ----
Assert-Has 'function Get-SectionAnchorForSource' '9a anchor helper exists'
Assert-Has "appears in:" '9d appears-in chip row'
Assert-Has 'Showing the top $($entTop.Count) of <b>$($entAll.Count)</b>' '9c of-N label'
Assert-Has 'Sort-Object { [int]"$($_.CatCount)" } -Descending' '9c entity cards sorted by CatCount'
Assert-Has '$srcAnc = Get-SectionAnchorForSource $parts[0]' '9a evidence Source cells link'
Assert-Has '$chainParent[(Split-Path "$($i.Image)" -Leaf).ToLower()]' '9b focus parent from process_chains'

# ---- Task 10: clickable local file links ----
Assert-Has 'function ConvertTo-CaseFileLink' '10a file-link helper exists'
Assert-Has 'ConvertTo-CaseFileLink $f.FullName $evLbl' '10b evidence index rows link'
Assert-Has "ConvertTo-CaseFileLink (Join-Path `$caseRoot 'supertimeline.csv') 'supertimeline.csv'" '10b also-in-case links'
Assert-Has "ConvertTo-CaseFileLink (Join-Path `$focusDirP 'focus_report.html') 'focus\focus_report.html'" '10b focus dossier links'
Assert-Has "ConvertTo-CaseFileLink (Join-Path `$CsvDir (Get-CaseCsvPath 'supertimeline'))" '10b context-window link'

# ---- Task 11: public-connection dedupe + attribution ----
Assert-Has 'Group-Object RemoteAddress, RemotePort' '11a conn dedupe by destination'
Assert-Has '<th>Talking processes</th>' '11a talking-processes column'
Assert-Has '$entLeaf.ContainsKey(' '11c talker links to #entities'

# ---- Task 12: focus embed keeps the dossier ----
Assert-Has 'VerdictHint = $hint' '12a verdict hint in terms JSON'
Assert-Has 'Masquerade = @($masq)' '12d masquerade in terms JSON'
Assert-Has 'if ("$($ft.VerdictHint)")' '12a embed banner from JSON'
Assert-Has 'MASQUERADE WARNING:</b> the name appears at multiple paths' '12d embed masquerade banner'
Assert-Has '<details><summary><b>Evidence by artifact</b>' '12b aggregate table collapsed'
Assert-Has 'and $($fGroups.Count - 30) more source(s)' '12b aggregate of-N note'
Assert-Has 'showing 25 of $($rows2.Count)' '12c per-instance truncation note'
Assert-Has '</details>' '12c per-instance details closed'

# ---- behavioral: the two helpers through the real functions ----
$defs = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'Get-SectionAnchorForSource', 'ConvertTo-CaseFileLink')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$a1 = Get-SectionAnchorForSource 'hayabusa_timeline'
$a2 = Get-SectionAnchorForSource 'beacon_candidates'
$a3 = Get-SectionAnchorForSource 'sysmon_proc_create'
$a4 = Get-SectionAnchorForSource 'totally_unknown_source'
if ($a1 -eq 'sigma') { Write-Host "[ok] behavioral: hayabusa_timeline -> sigma" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: hayabusa_timeline -> '$a1' (want sigma)" -ForegroundColor Red; $fail++ }
if ($a2 -eq 'beacons') { Write-Host "[ok] behavioral: beacon_candidates -> beacons" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: beacon_candidates -> '$a2'" -ForegroundColor Red; $fail++ }
if ($a3 -eq 'processes') { Write-Host "[ok] behavioral: sysmon_proc_create -> processes" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: sysmon_proc_create -> '$a3'" -ForegroundColor Red; $fail++ }
if (-not $a4) { Write-Host "[ok] behavioral: unknown source -> no anchor (plain chip)" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: unknown source -> '$a4' (want empty)" -ForegroundColor Red; $fail++ }

# v2.66: hrefs are case-relative now - forward slashes, no file:// scheme, no drive letter;
# existing file -> link, label text unchanged, missing file -> plain text (the v2.56 behavioral pin)
$CaseDir = $env:TEMP
$tmp = Join-Path $env:TEMP "ophira_v256_link_$(Get-Date -Format 'HHmmss').csv"
'# no entries' | Set-Content -LiteralPath $tmp -Encoding UTF8
$l1 = ConvertTo-CaseFileLink $tmp 'thefile'
if ($l1 -eq "<a href='$(Split-Path -Leaf $tmp)'>thefile</a>" -and $l1 -notmatch 'file://' -and $l1 -notmatch "href='[A-Za-z]:") { Write-Host "[ok] behavioral: existing file -> relative case link" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: link was: $l1" -ForegroundColor Red; $fail++ }
$l2 = ConvertTo-CaseFileLink (Join-Path $env:TEMP 'no_such_file_v256.xyz') 'missing'
if ($l2 -eq 'missing') { Write-Host "[ok] behavioral: missing file -> plain text" -ForegroundColor Green } else { Write-Host "[FAIL] behavioral: missing-file render was: $l2" -ForegroundColor Red; $fail++ }
Remove-Item -LiteralPath $tmp -Force

if ($fail -gt 0) { Write-Host "`n$fail assertion(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nALL v256 ASSERTIONS PASSED" -ForegroundColor Green
exit 0
