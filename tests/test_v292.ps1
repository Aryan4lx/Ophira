# test_v292.ps1 - v2.92 interaction rebuild:
#   B1/B2 span-swap clip cells (New-ClipCell helper: preview in span.cpv, full in data-full,
#        data-prevn carries preview length - no button-text corruption possible)
#   B4 honest clipboard (fallback + failure toast in JS)
#   B5 renderRule calls ophEnhance()
#   B7 dblclick removed, one delegated click handler
#   C7 clip cells emitted by multiple sections (ps_decoded, hunt evidence, entity trail, run keys)
#   C9 print CSS: ATT&CK evidence rows display:table-row + clip cells unwrap
#   B6 focus report: <br> literal bug fixed (split-escape-join), detail cap 1200
$ErrorActionPreference = 'Stop'
$passed = 0; $failed = 0
function Check([string]$name, [bool]$ok) {
    if ($ok) { $script:passed++; Write-Host "  [ok] $name" }
    else { $script:failed++; Write-Host "  [FAIL] $name" }
}
$repo = Split-Path -Parent $PSScriptRoot
$src = [IO.File]::ReadAllText((Join-Path $repo 'Ophira.ps1'))

Write-Host "== P1: New-ClipCell helper =="
$m = [regex]::Match($src, "(?s)function New-ClipCell \{.*?\r?\n\}")
Check 'P1: helper extracts' ($m.Success)
if ($m.Success) {
    $script:caseCsv = @{}
    function ConvertTo-HtmlEsc { param([string]$s) if ($null -eq $s) { return '' }; return ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;') }
    . ([ScriptBlock]::Create($m.Value))
    $short = New-ClipCell -Text 'short.exe' -TdClass 'clip path' -Threshold 120
    Check 'P1: short text -> plain td, no data-full' ($short -notmatch 'data-full' -and $short -match "^<td class='clip path'><span class='cpv'>short\.exe</span></td>$")
    $long = ('x' * 200)
    $clipped = New-ClipCell -Text $long -TdClass 'clip path' -Threshold 120
    Check 'P1: long text -> data-full + data-prevn + span preview' ($clipped -match 'data-full="x{200}"' -and $clipped -match 'data-prevn="120"' -and $clipped -match 'x{120}\.{3}</span></td>$')
    $huge = ('y' * 5000)
    $capped = New-ClipCell -Text $huge -Threshold 120 -MaxFull 4000
    Check 'P1: MaxFull caps data-full at 4000+ellipsis' ($capped -match 'data-full="y{4000}\.\.\."')
    $esc1 = New-ClipCell -Text 'cmd /c "echo <b>&</b> done"' -Threshold 5
    Check 'P1: html-escaping applied to preview and attr' ($esc1 -match '&lt;b&gt;&amp;lt;' -or ($esc1.Contains('&lt;b&gt;') -and $esc1.Contains('&quot;')))
}

Write-Host "== P2: emission sites use the helper =="
Check 'P2: ps_decoded decoded-content cell' ($src.Contains("New-ClipCell -Text `$txt -TdClass 'clip path' -Threshold 400"))
Check 'P2: hunt evidence cell' ($src.Contains("New-ClipCell -Text `$ev2 -TdClass 'clip path' -Threshold 120"))
Check 'P2: entity trail detail cell' ($src.Contains('New-ClipCell -Text "$($r3.Entity) $($r3.Detail)"'))
Check 'P2: run-key command cell' ($src.Contains("New-ClipCell -Text `$r.Value -TdClass 'clip path' -Threshold 120"))
Check 'P2: old corrupting enhance block gone' (-not $src.Contains("b.addEventListener('click',function(e){e.stopPropagation();t.textContent=f;"))

Write-Host "== P3: JS architecture =="
Check 'P3: ophEnhance defined + initial call' ($src.Contains('function ophEnhance()') -and $src.Contains("      ophEnhance();"))
Check 'P3: renderRule calls ophEnhance (B5)' ($src.Contains('ophEnhance();}'))
Check 'P3: span-swap toggle in enhance' ($src.Contains("sp.textContent=f;") -and $src.Contains("sp.textContent=f.substring(0,n)+'...';"))
Check 'P3: dblclick handler removed (B7)' (-not $src.Contains("addEventListener('dblclick'"))
Check 'P3: copy skips swall buttons (B7)' ($src.Contains("e.target.closest('.swall'))return;"))
Check 'P3: clipboard fallback exists (B4)' ($src.Contains('ophCopyFallback') -and $src.Contains("execCommand('copy')"))
Check 'P3: honest failure toast (B4)' ($src.Contains('copy failed - select the text manually'))
Check 'P3: state-machine full toggle (B2)' ($src.Contains('function ophFullState(on)') -and $src.Contains("document.body.setAttribute('data-full',on?'on':'off')"))
Check 'P3: print remembers prior state' ($src.Contains('wasFull'))
Check 'P3: no fullSaved textContent save/restore left' (-not $src.Contains('fullSaved'))

Write-Host "== P4: CSS + print (C9) =="
Check 'P4: .clip.open wraps' ($src.Contains('td.clip.open{white-space:normal;word-break:break-word}'))
Check 'P4: ATT&CK evidence rows print' ($src.Contains("tr[id^='ev_']{display:table-row!important}"))
Check 'P4: clip cells unwrap in print' ($src.Contains('td.clip{white-space:normal!important'))

Write-Host "== P5: focus report fixes (B6) =="
Check 'P5: literal <br> bug fixed (split-escape-join)' ($src.Contains("-split ' \| ') | ForEach-Object { & `$esc `$ }") -or $src.Contains("-split ' \| ') | ForEach-Object {"))
Check 'P5: escaped replace no longer nests <br> inside esc' (-not $src.Contains("-replace ' \| ', '<br>'"))
Check 'P5: focus detail cap raised to 1200 with csv pointer' ($src.Contains('Substring(0, 1200)') -and $src.Contains('full text: focus_hits.csv'))

Write-Host "== P6: version =="
Check 'P6: version bumped' ($src.Contains('$ScriptVersion = "2.92"'))

Write-Host ""
Write-Host "RESULT: $passed passed, $failed failed"
if ($failed -gt 0) { exit 1 } else { exit 0 }
