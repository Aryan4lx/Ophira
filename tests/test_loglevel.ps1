$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.63 - -LogLevel Quiet|Normal|Verbose: gates ONLY the console side; the case log file is always the full record
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# shadow Write-Host BEFORE extracting, so captured function bodies bind to it at call time
$script:Console = New-Object System.Collections.Generic.List[string]
function Write-Host {
    param([string]$Object, [object]$ForegroundColor, [object]$BackgroundColor, [switch]$NoNewline)
    $script:Console.Add("$Object")
    if ($null -ne $ForegroundColor) { Microsoft.PowerShell.Utility\Write-Host $Object -ForegroundColor $ForegroundColor }
    else { Microsoft.PowerShell.Utility\Write-Host $Object }
}

$defs = ''
foreach ($n in @('Write-CaseLog', 'Out-Flash', 'Invoke-NativeTool')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$script:SimpleUI = $false
$script:FlashLines = New-Object System.Collections.Generic.List[string]
$CaseLog = Join-Path $env:TEMP "ophira_ll_$stamp.log"
Set-Content -LiteralPath $CaseLog -Value '' -Encoding UTF8

function Reset-Console { $script:Console = New-Object System.Collections.Generic.List[string] }
function FileLines { @(Get-Content -LiteralPath $CaseLog | Where-Object { $_ }) }
function ConsoleHas([string]$needle) { @($script:Console | Where-Object { $_ -like "*$needle*" }).Count -gt 0 }

# ============================================================================
# PART 1 - Write-CaseLog / Out-Flash verbosity gates (file always grows)
# ============================================================================
$before = (FileLines).Count
$script:Verbosity = 0
Reset-Console
Write-CaseLog "LL-quiet-caselog" 'Gray'
Out-Flash "LL-quiet-flash"
Check "quiet: Write-CaseLog console silent" (-not (ConsoleHas 'LL-quiet-caselog'))
Check "quiet: Out-Flash console silent" (-not (ConsoleHas 'LL-quiet-flash'))
Check "quiet: Out-Flash still records FlashLines" (@($script:FlashLines | Where-Object { $_ -match 'LL-quiet-flash' }).Count -eq 1)
Check "quiet: case log file still grew (full record)" ((FileLines).Count -eq $before + 1)

$script:Verbosity = 1
Reset-Console
Write-CaseLog "LL-normal-caselog" 'Gray'
Write-CaseLog "LL-normal-noconsole" 'Gray' -NoConsole
Out-Flash "LL-normal-flash"
Check "normal: Write-CaseLog console captured" (ConsoleHas 'LL-normal-caselog')
Check "normal: -NoConsole still silences console" (-not (ConsoleHas 'LL-normal-noconsole'))
Check "normal: Out-Flash console captured" (ConsoleHas 'LL-normal-flash')
Check "normal: file grew (cumulative 3 lines)" ((FileLines).Count -eq $before + 3)

$script:Verbosity = 2
Reset-Console
Write-CaseLog "LL-verbose-caselog" 'Gray'
Check "verbose: Write-CaseLog console captured" (ConsoleHas 'LL-verbose-caselog')

# SimpleUI silences console at ANY verbosity, file keeps the record
foreach ($v in @(1, 2)) {
    $script:Verbosity = $v
    $script:SimpleUI = $true
    Reset-Console
    Write-CaseLog "LL-simple$v-caselog" 'Gray'
    Out-Flash "LL-simple$v-flash"
    $script:SimpleUI = $false
    Check "simpleui v${v}: Write-CaseLog console silent" (-not (ConsoleHas "LL-simple$v-caselog"))
    Check "simpleui v${v}: Out-Flash console silent" (-not (ConsoleHas "LL-simple$v-flash"))
}
Check "simpleui: case log file still grew" ((FileLines).Count -eq $before + 6)

# ============================================================================
# PART 2 - Invoke-NativeTool tails: Normal suppresses, Verbose shows, QuietLog none
# ============================================================================
$cmd = $env:ComSpec
$script:Verbosity = 1
Reset-Console
$fb1 = (FileLines).Count
$null = Invoke-NativeTool -ExePath $cmd -ToolArgs @('/c', 'echo', 'LL-tail-normal')
Check "tails v1: tail reached the file" (@(FileLines | Where-Object { $_ -match 'LL-tail-normal' }).Count -gt 0)
Check "tails v1: tail NOT on console (-NoConsole passed)" (-not (ConsoleHas 'LL-tail-normal'))

$script:Verbosity = 2
Reset-Console
$null = Invoke-NativeTool -ExePath $cmd -ToolArgs @('/c', 'echo', 'LL-tail-verbose')
Check "tails v2: tail on console" (ConsoleHas 'LL-tail-verbose')

Reset-Console
$fb3 = (FileLines).Count
$null = Invoke-NativeTool -ExePath $cmd -ToolArgs @('/c', 'echo', 'LL-tail-quietlog') -QuietLog
Check "tails -QuietLog: nothing in file" (@(FileLines | Where-Object { $_ -match 'LL-tail-quietlog' }).Count -eq 0 -and (FileLines).Count -eq $fb3)
Check "tails -QuietLog: nothing on console" (-not (ConsoleHas 'LL-tail-quietlog'))

# ============================================================================
# PART 3 - static wiring: param, init, gates, blanks, Clear-Host
# ============================================================================
Check "wiring: -LogLevel param with ValidateSet" ($src -match "\[ValidateSet\('Quiet',\s*'Normal',\s*'Verbose'\)\]\s*\r?\n\s*\[string\]\`$LogLevel = 'Normal'")
Check "wiring: Verbosity init maps Quiet=0 Normal=1 Verbose=2" ($src -match "\`$script:Verbosity = @\('Quiet', 'Normal', 'Verbose'\)\.IndexOf")
Check "wiring: Write-CaseLog console gate honors verbosity" ($src -match [regex]::Escape('-not $NoConsole -and -not $script:SimpleUI -and $script:Verbosity -ge 1'))
Check "wiring: Out-Flash console gate honors verbosity" ($src -match [regex]::Escape('if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host $Text'))
Check "wiring: native tails pass -NoConsole:($script:Verbosity -lt 2)" ($src -match [regex]::Escape('-NoConsole:($script:Verbosity -lt 2)'))
Check "wiring: Clear-Host guarded on SimpleUI" ($src -match [regex]::Escape('if (-not $script:SimpleUI) { Clear-Host }'))
$blankGuard = [regex]::Matches($src, [regex]::Escape('if (-not $script:SimpleUI -and $script:Verbosity -ge 1) { Write-Host "" }'))
Check "wiring: exactly 4 blank-line sites guarded (SimpleUI + verbosity)" ($blankGuard.Count -eq 4)

# ============================================================================
# PART 4 - v2.63: unattended -NoMenu runs must not hang on 7.1's prompts
# ============================================================================
Check "wiring: -NoMenu param defined" ($src -match "\[switch\]\`$NoMenu,")
Check "wiring: NoMenu seeded as [bool] at init" ([regex]::Matches($src, [regex]::Escape('$script:NoMenu = [bool]$NoMenu')).Count -eq 1)

$m71 = [regex]::Match($src, "(?s)Id = '7\.1';.*?Run = \{(.*?)\r?\n        \} \}")
Check "unattended: module 7.1 Run block extracted" ($m71.Success)
$run71 = $m71.Groups[1].Value

$guard = 'if ($script:NoMenu) { Write-CaseLog "    Memory capture skipped (non-interactive -NoMenu)" ''Yellow''; return }'
Check "unattended: exactly 2 NoMenu guards in 7.1 body" ([regex]::Matches($run71, [regex]::Escape($guard)).Count -eq 2)
Check "unattended: guard before winpmem URL prompt" ($run71 -match ([regex]::Escape($guard) + '\s*\r?\n\s*\$url = Read-Host'))
Check "unattended: guard before RAM confirm prompt" ($run71 -match ([regex]::Escape($guard) + '\s*\r?\n\s*\$confirm = Read-Host'))

# shadow Read-Host: throws if a prompt is reached while PromptReply is $null,
# otherwise returns the scripted reply (so the $false branch can be driven)
$script:PromptCalled = 0
$script:PromptReply = $null
function Read-Host {
    param([string]$Prompt)
    $script:PromptCalled++
    if ($null -eq $script:PromptReply) { throw "PROMPT REACHED: $Prompt" }
    return $script:PromptReply
}
function Get-ToolsDir { return $null }
function Invoke-WebRequest { param($Uri, $OutFile, $UseBasicParsing, $ErrorAction) throw "DOWNLOAD REACHED: $Uri" }

$before71 = (FileLines).Count
$script:NoMenu = $true
$script:PromptCalled = 0
$threw = $false
try { Invoke-Expression $run71 } catch { $threw = $true }
Check "unattended NoMenu=true: returns without any prompt" ($script:PromptCalled -eq 0 -and -not $threw)
Check "unattended NoMenu=true: tool-missing + skip lines in case log" ((FileLines).Count -eq $before71 + 2 -and @(FileLines | Where-Object { $_ -match 'Memory capture skipped \(non-interactive -NoMenu\)' }).Count -ge 1)

$script:NoMenu = $false
$script:PromptReply = ''
$script:PromptCalled = 0
$threw = $false
$fb71 = (FileLines).Count
try { Invoke-Expression $run71 } catch { $threw = $true }
Check "unattended NoMenu=false: prompt still reached (interactive behavior kept)" ($script:PromptCalled -eq 1 -and -not $threw)
Check "unattended NoMenu=false: only tool-missing line logged (no capture attempted)" ((FileLines).Count -eq $fb71 + 1)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $CaseLog -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
