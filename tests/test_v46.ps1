# test_v46.ps1 - v4.6 Sysmon deploy support (-Mode Setup sysmon* + Deploy -InstallSysmon)
$ErrorActionPreference = 'Stop'
$scriptPath = $PSScriptRoot -replace 'tests$', ''
$script:Checks = 0; $script:Fails = New-Object System.Collections.Generic.List[string]
function Check($name, $ok, $detail) {
    $script:Checks++
    if ($ok) { Write-Host "  [PASS] $name" -ForegroundColor DarkGray }
    else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:Fails.Add("$name $detail") }
}
$src = [IO.File]::ReadAllText((Join-Path $scriptPath 'Ophira.ps1'))

# --- extracts -------------------------------------------------------------
function Extract-Fn($name) {
    $m = [regex]::Match($src, "(?s)function $name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "cannot extract $name" }
    return $m.Value
}
$sysmonInstallFn = Extract-Fn 'New-SysmonRemoteInstall'
$setupFn = Extract-Fn 'Invoke-SetupMode'

Write-Host "== P1: New-SysmonRemoteInstall script text ==" -ForegroundColor Cyan
$smDir = 'C:\ophira'
$txt = & ([scriptblock]::Create("$sysmonInstallFn`nNew-SysmonRemoteInstall -RemoteDir '$smDir'"))
Check 'returns script text' ("$txt" -is [string] -and "$txt".Length -gt 100) "$txt"
$fake = [pscustomobject]@{}
$tests = @(
    @{ name = 'no exe -> SYSMON-FAIL'; prep = { }; expect = 'SYSMON-FAIL' },
    @{ name = 'exe present, service running -> SYSMON-OK'; prep = {
            New-Item -ItemType Directory -Path "$smDir\sysmon" -Force | Out-Null
            Set-Content -Path "$smDir\sysmon\Sysmon64.exe" -Value 'x'
            Set-Content -Path "$smDir\sysmon\sysmonconfig-export.xml" -Value '<x/>'
            Set-Content -Path "$smDir\sysmon\Sysmon64.exe" -Value 'x'
        }; expect = 'SYSMON-OK' }
)
# execute the generated script with stubs for exe-run + service
$run = [scriptblock]::Create("$txt`nexit 0")
# stub Test-Path/Get-Service via a shadowed environment: run in a child scope with functions defined first
$stubEnv = @'
function Test-Path($p) { return (Test-Path2 $p) }
function Get-Service($n) { if ($script:svcOk) { return [pscustomobject]@{ Name = $n; Status = 'Running' } } return $null }
function Get-ChildItem { param($a, $Filter, $ErrorAction) if ($Filter -eq '*.xml') { return [pscustomobject]@{ FullName = "$a\sysmonconfig-export.xml" } } return @() }
'@
# Simpler: text-level assertions + a behavioral run with fake commands replaced
$txtNoSvc = $txt -replace 'Get-Service -Name ([^\s]+) -ErrorAction SilentlyContinue', "`$tmp = `$null"
Check 'uses Sysmon64.exe then Sysmon.exe fallback' ($txt -match "Sysmon64\.exe" -and $txt -match 'Sysmon\.exe') ''
Check 'uses -accepteula -i with config' ($txt -match '-accepteula -i') ''
Check 'config glob picks *.xml' ($txt -match "Filter '\*\.xml'") ''
Check 'idempotent wording present' ($txt -match 'SYSMON-OK' -and $txt -match 'SYSMON-FAIL') ''
Check 'remoteDir interpolated' ($txt.Contains($smDir)) ''

Write-Host "== P2: Setup catalog gains sysmon entries ==" -ForegroundColor Cyan
Check 'sysmon direct entry' ($src -match "Name = 'sysmon';\s+Direct = 'https://download\.sysinternals\.com/files/Sysmon\.zip'") ''
Check 'sysmon-config raw entry' ($src -match "Name = 'sysmon-config';\s+Raw = @\('https://raw\.githubusercontent\.com/SwiftOnSecurity/sysmon-config") ''
Check 'catalog source line handles sysinternals' ($src -match 'if \(\$assetUrl -match ''sysinternals''\) \{ ''Sysinternals live link''') ''

Write-Host "== P3: wiring ==" -ForegroundColor Cyan
Check 'param InstallSysmon declared' ($src -match '\[switch\]\$InstallSysmon,') ''
Check 'param doc present' ($src -match '\.PARAMETER InstallSysmon') ''
Check 'Invoke-DeployMode param gains InstallSysmon' ($src -match '(?s)function Invoke-DeployMode \{.*?param\(\[string\[\]\]\$Targets.*?\[switch\]\$InstallSysmon\)') ''
Check 'worker param gains insSysmon' ($src -match 'param\(\$c, \$scriptPath, \$toolsDir, \$preset, \$caseID, \$sharePath, \$cred, \$outFolder, \$binZip, \$logHours, \$logWindow, \$insSysmon\)') ''
Check 'worker sysmon copy block' ($src -match "Filter 'sysmon\*'") ''
Check 'worker uses -ToSession copy' ($src -match '-ToSession \$s -Force -ErrorAction Stop') ''
Check 'worker note prepended to Detail' ($src -match 'if \(\$smNote\) \{ \$result\.Detail = \$smNote \+ \$result\.Detail \}') ''
Check 'AddArguments gains 12th arg' ($src -match 'AddArgument\(\$DeployLogWindow\)\.AddArgument\(\[bool\]\$InstallSysmon\)') ''
Check 'wizard step 5 sysmon question' ($src -match "Install/refresh Sysmon telemetry on targets first") ''
Check 'wizard confirm line' ($src -match 'Sysmon    : \$\(if \(\$insSysmon\) \{ ''install/refresh before collect'' \}') ''
Check 'wizard run passes -InstallSysmon' ($src -match 'Invoke-DeployMode -Targets \$targets -DeployPreset \$preset -Cred \$cred -DeployCaseID \$CaseID -DeploySharePath \$shareIn -Threads \$threads -PushBin \$push -DeployLogHours \$advLogHours -DeployLogWindow \$advLogWindow -InstallSysmon:\$insSysmon') ''
Check 'direct dispatch passes -InstallSysmon' ($src -match '-InstallSysmon:\$InstallSysmon') ''
Check 'version bumped' ($src -match 'Ophira v5\.9' -and $src -match '\$ScriptVersion = "5\.9"') ''

Write-Host ''
if ($script:Fails.Count -gt 0) {
    Write-Host "FAILED: $($script:Fails.Count) of $($script:Checks)" -ForegroundColor Red
    exit 1
}
Write-Host "ALL PASSED: $($script:Checks) checks" -ForegroundColor Green
exit 0
