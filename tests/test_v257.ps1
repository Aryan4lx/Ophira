# test_v257.ps1 - v2.57 plaso l2t import adapter + the analyst TODO next to the results
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = Get-Content -LiteralPath (Join-Path $repo 'Ophira.ps1') -Raw
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ---- statics: the TODO sits next to the generated results ----
Check "parse_needed: plaso deep-timeline row wired" ($src -match [regex]::Escape("'supertimeline.csv (deeper: plaso)'"))
Check "parse_needed: row only until plaso.csv exists" ($src -match [regex]::Escape('$plasoIn = Join-Path $plasoCaseRoot ' + "'plaso.csv'"))
Check "regen: plaso import called right after the supertimeline build" ($src -match "(?s)New-SuperTime.*?Import-PlasoTimeline")
Check "report: deep-timeline recommendation present" ($src -match [regex]::Escape("Deeper timeline available (optional, analyst-side)"))
Check "parse mode: console TODO line next to the Done line" ($src -match [regex]::Escape('deep-timeline (optional): log2timeline.py <case>\raw'))
Check "importer: no Python runtime shipped" (-not ($src -match 'log2timeline\.py"' -and $src -match 'Compress-ToolZip.*plaso'))

# ---- behavioral: the real importer against fixture cases ----
$m = [regex]::Match($src, "(?s)function Import-PlasoTimeline \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Import-PlasoTimeline extract failed' }
Invoke-Expression $m.Value

$case = Join-Path $env:TEMP ("ophira_v257_" + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Path $case -Force | Out-Null
$stPath = Join-Path $case 'supertimeline.csv'

# 1) no plaso.csv -> silent -1, supertimeline untouched
Set-Content -LiteralPath $stPath -Value @('"Timestamp","Source","Type","Actor","Entity","Detail"', '"2026-01-02 10:00:00","mft_recent","PE","","C:\x\a.exe","created"') -Encoding UTF8
$r1 = Import-PlasoTimeline $case
Check "no plaso.csv -> returns -1 (silent no-op)" ($r1 -eq -1)
Check "no plaso.csv -> supertimeline untouched" (@(Import-Csv $stPath).Count -eq 1)

# 2) modern l2tcsv (with sourcetype) -> merged, normalized, sorted
Set-Content -LiteralPath (Join-Path $case 'plaso.csv') -Encoding UTF8 -Value @(
    '"date","time","timezone","MACB","source","sourcetype","host","desc","short","version","filename","inode","notes","format","extra"',
    '"01/03/2026","09:00:00","UTC","M","WEBHIST","Firefox History","HOST1","Visit: http://evil.example/payload visit_count=2","Visit http://evil.example","2","C:\Users\u\places.sqlite","","","SQLite","-"',
    '"01/01/2026","08:00:00","UTC","M","REG","WinReg Key","HOST1","[MRU] Run key = C:\mal\evil.exe","[MRU] Run key","2","C:\Users\u\NTUSER.DAT","","","regf","-"',
    '"01/02/2026","10:00:00","UTC","M","LOG","EVT Log","HOST1","garbage-date-row-but-valid","short","2","C:\Windows\System32\winevt\Sec.evtx","","","EVTX","-"'
)
$r2 = Import-PlasoTimeline $case
Check "plaso.csv present -> 3 rows imported" ($r2 -eq 3)
$st = @(Import-Csv $stPath)
Check "merge keeps the native row" (@($st | Where-Object { $_.Source -eq 'mft_recent' }).Count -eq 1)
Check "plaso rows carry Source 'plaso'" (@($st | Where-Object { $_.Source -eq 'plaso' }).Count -eq 3)
Check "timestamp normalized to weave format" ("$($st[0].Timestamp)" -eq '2026-01-01 08:00:00')
Check "sorted chronologically (native 01-02 row before plaso 01-03 row)" ("$($st[3].Timestamp)" -eq '2026-01-03 09:00:00')
Check "Type prefers sourcetype" (@($st | Where-Object { $_.Type -eq 'Firefox History' }).Count -eq 1)
Check "Actor/Entity/Detail mapped" (@($st | Where-Object { $_.Actor -eq 'HOST1' -and $_.Entity -match 'places\.sqlite' -and $_.Detail -match 'evil\.example/payload' }).Count -eq 1)

# 3) idempotent: re-import replaces plaso rows, native row survives
$r3 = Import-PlasoTimeline $case
$st3 = @(Import-Csv $stPath)
Check "re-import still reports 3 (no doubling)" ($r3 -eq 3)
Check "re-import: exactly 3 plaso rows in file" (@($st3 | Where-Object { $_.Source -eq 'plaso' }).Count -eq 3)
Check "re-import: native row still there" (@($st3 | Where-Object { $_.Source -eq 'mft_recent' }).Count -eq 1)

# 4) legacy l2tcsv (no sourcetype) -> Type falls back to format; bad dates skipped
Set-Content -LiteralPath (Join-Path $case 'plaso.csv') -Encoding UTF8 -Value @(
    '"date","time","timezone","MACB","source","host","desc","short","version","filename","inode","notes","format","extra"',
    '"01/05/2026","12:00:00","UTC","M","LNK","HOST1","Link: payload.lnk","Link payload","2","C:\Users\u\Recent","","","LNK","-"',
    '"0000-00-00","00:00:00","UTC","M","LOG","HOST1","dateless junk","junk","2","x","","","EVTX","-"'
)
$r4 = Import-PlasoTimeline $case
$st4 = @(Import-Csv $stPath)
Check "legacy header: 1 valid row imported (bad date skipped)" ($r4 -eq 1)
Check "legacy header: Type falls back to format" (@($st4 | Where-Object { $_.Type -eq 'LNK' }).Count -eq 1)
Check "bad-date row never lands in the timeline" (@($st4 | Where-Object { $_.Detail -match 'dateless junk' }).Count -eq 0)

Remove-Item -LiteralPath $case -Recurse -Force

if ($fail -gt 0) { Write-Host "`ntest_v257: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`ntest_v257: $pass passed, 0 failed" -ForegroundColor Green
exit 0
