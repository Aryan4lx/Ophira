# test_v3.ps1 - v3.0: YARA Forge integration + noise suppression + design v3 pins
# Extracts module 4.7 (YARA scan) and asserts the forge-dir merge; structural pins for
# the Setup catalog row, the report noise-suppression block, tactic drill-downs,
# branding reword and design-v3 CSS.

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$src = [IO.File]::ReadAllText((Join-Path $repo 'Ophira.ps1'))
if ($src.Length -gt 0 -and $src[0] -eq [char]0xFEFF) { $src = $src.TrimStart([char]0xFEFF) }

$script:pass = 0; $script:fail = 0
function Check { param([string]$Name, [bool]$Ok) if ($Ok) { $script:pass++; Write-Host "  [ok] $Name" } else { $script:fail++; Write-Host "  [FAIL] $Name" -ForegroundColor Red } }

Write-Host "== v3.0 structural =="
# setup catalog: yaraforge entry (Neo23x0 repo, conservative pack, endpoint target)
Check 'setup: yaraforge catalog row' ($src.Contains("Name = 'yaraforge';   Repo = 'Neo23x0/YaraForge'"))
Check 'setup: conservative pattern' ($src.Contains("(?i)conservative.*\.zip$"))
# tools display table row
Check 'tools table: forge row' ($src.Contains('YARA Forge (curated rule packs)'))

# module 4.7: forge merge
$m47 = [regex]::Match($src, "(?s)Id = '4\.7';.*?Run = \{(.*?)\r?\n        \} \}").Groups[1].Value
Check '4.7: extracted' ($m47.Length -gt 500)
Check '4.7: forge dir discovery' ($m47 -match "tools\\endpoint'\) 'yaraforge'")
Check '4.7: forge file count logged' ($m47 -match 'Neo23x0/YaraForge conservative pack')
Check '4.7: scanDirs list used for rule enumeration' ($m47 -match 'Get-ChildItem -Path \$scanDirs')
Check '4.7: per-file loop iterates scanDirs' ($m47 -match 'foreach \(\$sd in \$scanDirs\)')

# suppression block in report
Check 'report: suppress file read' ($src.Contains("sigma\suppress.txt"))
Check 'report: suppression counted note' ($src.Contains('hidden as routine noise'))
Check 'report: tools guard (fixture suites)' ($src -match 'Get-Command Get-ToolsDir -ErrorAction SilentlyContinue')
Check 'report: rule-title column detection' ($src.Contains("@('RuleTitle', 'Alert', 'Rule')"))

# sigma cap-note fixed (csv path not column name)
Check 'report: sigma cap note uses csv name' ($src.Contains("Add-CapNote `$hayRows.Count 20 'hayabusa_timeline' 'Top sigma alerts'"))

# tactic drill-down links
Check 'tactics: drill link emitted' ($src.Contains("open the Sigma drill-down for this rule"))

# branding
Check 'brand: endpoint triage toolkit header' ($src.Contains('Windows Endpoint Triage Toolkit'))
Check 'brand: no old IR banner left' (-not $src.Contains('Windows IR toolkit'))
Check 'brand: nav brand sub' ($src.Contains('endpoint triage report'))
Check 'brand: version 6.3' ($src.Contains('$ScriptVersion = "6.7"'))

# design v3 css
Check 'css: body depth gradient' ($src.Contains('radial-gradient(1100px 480px'))
Check 'css: h2 accent bar' ($src.Contains('border-left:4px solid var(--acc)'))
Check 'css: verdict gradient + rail' ($src.Contains('.vbanner{border-radius:12px;padding:22px 26px'))
Check 'css: opaque topbar (no ghost-through)' (-not $src.Contains('backdrop-filter:blur') -and $src.Contains('box-shadow:0 2px 12px rgba(0,0,0,.32)'))
Check 'css: nav active gradient' ($src.Contains('.nav a.act{background:linear-gradient(90deg'))
Check 'css: print rules intact' ($src.Contains('tr[id^=') -and $src -match "@media print\{body\{background:#fff")

Write-Host ""
Write-Host "v3.0: $script:pass passed, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
exit 0
