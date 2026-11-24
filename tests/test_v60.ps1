# test_v60.ps1 - v6.0 user MRU artifacts (Get-UserMruRows + R60 hunt + verdict door)
$ErrorActionPreference = 'Stop'
$src = Get-Content (Join-Path $PSScriptRoot '..\Ophira.ps1') -Raw
$checks = 0; $failed = 0
function Check([string]$Name, [bool]$Ok) {
    $script:checks++
    if (-not $Ok) { $script:failed++; Write-Host "[FAIL] $Name" } else { Write-Host "[ ok ] $Name" }
}

# ---- extracts ----
function Get-Fn([string]$Name) {
    $m = [regex]::Match($src, "(?s)function $Name \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract $Name failed" }
    return $m.Value
}
$mruBody = Get-Fn 'Get-UserMruRows'
$iwPath = Get-Fn 'Test-IsUserWritablePath'
$hfBody = Get-Fn 'New-HuntFindings'
Invoke-Expression $iwPath

# ---- registry stubs keyed by path ----
$script:regExists = @{}
$script:regProps = @{}
function Test-Path($p) { return $script:regExists.ContainsKey("$p") -and $script:regExists["$p"] }
function Get-ItemProperty([string]$Path) {
    if ($script:regProps.ContainsKey($Path)) { return $script:regProps[$Path] }
    return $null
}
function Get-ChildItem($p) {
    if ("$p" -eq 'Registry::HKEY_USERS') {
        return @([pscustomobject]@{ PSChildName = 'S-1-5-21-1001'; PSPath = 'reg:sid1001' })
    }
    return @()
}
Invoke-Expression $mruBody

function Run-Mru {
    $rows = Get-UserMruRows
    return @($rows)
}

# ---- T1: MUICache rows parse + suffix strip ----
$script:regProps = @{
    'Registry::HKEY_USERS\S-1-5-21-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' = [pscustomobject]@{
        'PSPath'                                                          = 'reg:path'
        'C:\Users\Aryan\Downloads\tool.exe.FriendlyAppName'               = 'Tool Application'
        'C:\Windows\System32\notepad.exe.FriendlyAppName'                 = 'Notepad'
        'C:\Users\Aryan\Downloads\installer.exe.ApplicationCompany'       = 'ACME'
        'LangID'                                                          = 'en-US'
    }
}
$script:regExists = @{
    'Registry::HKEY_USERS\S-1-5-21-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' = $true
}
$r = Run-Mru
Check 'T1: muicache rows with suffix stripped (bare LangID dropped)' ((@($r | Where-Object { $_.Kind -eq 'muicache' }).Count) -eq 3)
Check 'T1: friendly-name row entry + detail' ("$(($r | Where-Object { "$($_.Entry)" -eq 'C:\Users\Aryan\Downloads\tool.exe' })[0].Detail)" -eq 'Tool Application')
Check 'T1: ApplicationCompany suffix also stripped' ((@($r | Where-Object { "$($_.Entry)" -eq 'C:\Users\Aryan\Downloads\installer.exe' }).Count) -eq 1)

# ---- T2: RunMRU trims \1 sentinel, drops MRUList ----
$script:regProps = @{
    'Registry::HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' = [pscustomobject]@{
        'MRUList' = 'ab'
        'a'       = "c:\users\public\evil.exe$( [char]1 )"
        'b'       = "notepad$( [char]1 )"
        'c'       = 'dxdiag\1'
    }
}
$script:regExists = @{ 'Registry::HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' = $true }
$r = Run-Mru
$rr = @($r | Where-Object { $_.Kind -eq 'runmru' })
Check 'T2: runmru entries, MRUList dropped' ($rr.Count -eq 3)
Check 'T2: sentinels trimmed (byte 0x01 + literal backslash-1)' ("$($rr[0].Entry)" -eq 'c:\users\public\evil.exe' -and "$($rr[1].Entry)" -eq 'notepad' -and "$($rr[2].Entry)" -eq 'dxdiag')

# ---- T3: TypedPaths url values ----
$script:regProps = @{
    'Registry::HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' = [pscustomobject]@{
        'url1' = 'c:\users\public\tools'
        'url2' = ''
    }
}
$script:regExists = @{ 'Registry::HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' = $true }
$r = Run-Mru
$tp = @($r | Where-Object { $_.Kind -eq 'typedpath' })
Check 'T3: typedpath url rows (empty dropped)' ($tp.Count -eq 1 -and "$($tp[0].Entry)" -eq 'c:\users\public\tools')

# ---- T4: R60 hunt rule ----
$script:caseCsv = @{}
function Import-CaseCsv([string]$Name) {
    $k = $Name -replace '\.csv$', ''
    if ($null -eq $script:caseCsv[$k]) { return @() }
    return $script:caseCsv[$k]
}
$script:saved = @{}
function Save-Rows([string]$Name, $Rows) { $script:saved[$Name] = @($Rows) }
function Write-CaseLog([string]$m, [string]$c) { }
function QuietLog([string]$m) { }
function Get-LevenshteinDistance([string]$a, [string]$b) { return 99 }
function Get-KnownBadRegexes { return @() }
$script:caseCsv['user_mru'] = @(
    [pscustomobject]@{ User = 'S-1-5-21-1001'; Kind = 'runmru'; Entry = 'c:\users\public\evil.exe'; Detail = '' },
    [pscustomobject]@{ User = 'S-1-5-21-1001'; Kind = 'typedpath'; Entry = '\\fileserver\share'; Detail = '' },
    [pscustomobject]@{ User = 'S-1-5-21-1001'; Kind = 'muicache'; Entry = 'C:\Users\Aryan\Downloads\setup.exe'; Detail = 'Setup' },
    [pscustomobject]@{ User = 'S-1-5-21-1001'; Kind = 'muicache'; Entry = 'C:\Program Files\App\app.exe'; Detail = 'App' }
)
$hf = [scriptblock]::Create($hfBody)
. $hf
New-HuntFindings
$hf60hi = @($script:saved['hunt_findings'] | Where-Object { $_.Rule -match 'Typed execution of user-writable binary' })
$hf60low = @($script:saved['hunt_findings'] | Where-Object { $_.Rule -match 'MUICache: user-writable binary' })
$hf60info = @($script:saved['hunt_findings'] | Where-Object { $_.Rule -match 'Typed command' })
Check 'T4: runmru writable-exe = high T1204' ($hf60hi.Count -eq 1 -and "$($hf60hi[0].Attck)" -eq 'T1204')
Check 'T4: muicache writable = low; system-dir muicache skipped' ($hf60low.Count -eq 1 -and "$($hf60low[0].Entity)" -eq 'setup.exe')
Check 'T4: non-path typed entry = info context' ($hf60info.Count -eq 1)

# ---- T5: wiring pins ----
Check 'T5: module 5.2 saves user_mru' ($src.Contains("Save-Rows -Name 'user_mru' -Rows (Get-UserMruRows)"))
Check 'T5: SharedFunctions rehydrates Get-UserMruRows' ($src.Contains("'Get-UserAssistRows', 'Get-UserMruRows'"))
Check 'T5: CsvCatMap + emptyWhy + desc entries' ($src.Contains("'user_mru' = 'artifacts'") -and $src.Contains("'user_mru'                        = 'no MRU rows"))
Check 'T5: snapshot h3 + verdict door wired' ($src.Contains('User MRU artifacts (typed commands') -and $src.Contains("Add-Signal 'Hands-on-keyboard typed execution (RunMRU/TypedPaths)' 2"))
Check 'T5: nav snapshot count includes mruRows' ($src.Contains('+ $aswRows.Count + $mruRows.Count'))
Check 'T5: version 6.0' ($src.Contains('$ScriptVersion = "6.0"'))

Write-Host ''
Write-Host "test_v60: $checks checks, $failed failed"
if ($failed -gt 0) { exit 1 }
exit 0
