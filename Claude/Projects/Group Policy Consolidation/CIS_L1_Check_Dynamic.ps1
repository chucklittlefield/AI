#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Windows 11 Enterprise Benchmark v4.0.0 - L1 Compliance Check (Dynamic)

.DESCRIPTION
    Reads "Group Policy Settings.xlsx" at runtime, extracts all rows where
    Compliance Status = "Compliant", and checks each setting against this
    machine's actual configuration.

    Requires the ImportExcel PowerShell module (auto-installed if missing).

.PARAMETER ExcelPath
    Path to "Group Policy Settings.xlsx". Defaults to the same folder as this script.

.PARAMETER OutputPath
    Path for the CSV output. Defaults to the script folder with a timestamp.

.NOTES
    Run as Administrator.
    Usage:  .\CIS_L1_Check_Dynamic.ps1
            .\CIS_L1_Check_Dynamic.ps1 -ExcelPath "C:\Path\Group Policy Settings.xlsx"
#>

[CmdletBinding()]
param(
    [string]$ExcelPath   = (Join-Path $PSScriptRoot 'Group Policy Settings.xlsx'),
    [string]$OutputPath  = (Join-Path $PSScriptRoot "CIS_L1_Compliance_Dynamic_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ============================================================
# PREREQUISITES
# ============================================================
if (-not (Test-Path $ExcelPath)) {
    Write-Error "Excel file not found: $ExcelPath"
    exit 1
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host 'ImportExcel module not found. Installing...' -ForegroundColor Yellow
    try {
        Install-Module ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
        Write-Host 'ImportExcel installed.' -ForegroundColor Green
    } catch {
        Write-Error "Failed to install ImportExcel: $_`nInstall manually: Install-Module ImportExcel -Scope CurrentUser"
        exit 1
    }
}
Import-Module ImportExcel -ErrorAction Stop

# ============================================================
# LOAD SPREADSHEET
# ============================================================
Write-Host "Reading: $ExcelPath" -ForegroundColor Cyan

# Header is on row 4 (1-indexed), so StartRow=4 makes row 4 the header
$rows = Import-Excel -Path $ExcelPath -WorksheetName 'Recommendations' -StartRow 4

$compliant = @($rows | Where-Object { $_.'Compliance Status' -eq 'Compliant' })
Write-Host "Found $($compliant.Count) Compliant settings to verify." -ForegroundColor Cyan

# ============================================================
# HELPERS
# ============================================================
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Result {
    param($Number, $Title, $GPO, $Type, $Expected, $Actual, $Status, $Details = '')
    $Results.Add([PSCustomObject]@{
        Number   = $Number
        GPO      = $GPO
        Title    = $Title
        Type     = $Type
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
        Details  = $Details
    })
}

# Parses CIS audit text → [hashtable] with Hive, RegPath, ValueName, RegType, Expected
# Returns $null if no registry entry found
function Parse-RegistryCheck([string]$AuditText) {
    # Fix common line-wrap: "683F-11D2- A89A" → "683F-11D2-A89A"
    $t = $AuditText -replace '(\w)-\s+([A-Fa-f0-9])', '$1-$2'

    # Extract expected type + value (appears BEFORE the path in CIS text)
    $regType = 'REG_DWORD'; $expected = $null
    if ($t -match '(REG_\w+) value of ([^\s\n\.]+)') {
        $regType = $Matches[1]
        $raw     = $Matches[2].TrimEnd(':').Trim('"')
        $expected = if ($regType -eq 'REG_DWORD') {
            try { [int]$raw } catch { $raw }
        } else { $raw }
    }

    # Extract registry path:valuename
    if ($t -match '(HK[A-Z_]+\\(?:[\w\{\}\-\. ]+\\)*[\w\{\}\-\. ]+):([\w\-]+)') {
        $fullPath  = $Matches[1].Trim()
        $valueName = $Matches[2].Trim()
        $parts     = $fullPath -split '\\'
        return @{
            Hive      = $parts[0]
            RegPath   = ($parts | Select-Object -Skip 1) -join '\'
            ValueName = $valueName
            RegType   = $regType
            Expected  = $expected
        }
    }
    return $null
}

function Parse-AuditPolCheck([string]$Remediation, [string]$Title) {
    $sub = $null
    if ($Remediation -match 'Advanced Audit Policy Configuration\\(?:Audit Policies\\)?(?:.+?)\\(.+?)$') {
        $sub = $Matches[1].Trim()
    }
    $exp = ''
    foreach ($kw in @('Success and Failure','Success','Failure','No Auditing')) {
        if ($Remediation -match [regex]::Escape($kw) -or $Title -match [regex]::Escape($kw)) {
            $exp = $kw; break
        }
    }
    return @{ Subcategory = $sub; Expected = $exp }
}

$RIGHT_CONST = @{
    'Access Credential Manager as a trusted caller'                 = 'SeTrustedCredManAccessPrivilege'
    'Access this computer from the network'                         = 'SeNetworkLogonRight'
    'Act as part of the operating system'                           = 'SeTcbPrivilege'
    'Adjust memory quotas for a process'                            = 'SeIncreaseQuotaPrivilege'
    'Allow log on locally'                                          = 'SeInteractiveLogonRight'
    'Allow log on through Remote Desktop Services'                  = 'SeRemoteInteractiveLogonRight'
    'Back up files and directories'                                 = 'SeBackupPrivilege'
    'Change the system time'                                        = 'SeSystemtimePrivilege'
    'Create a pagefile'                                             = 'SeCreatePagefilePrivilege'
    'Create a token object'                                         = 'SeCreateTokenPrivilege'
    'Create global objects'                                         = 'SeCreateGlobalPrivilege'
    'Create permanent shared objects'                               = 'SeCreatePermanentPrivilege'
    'Create symbolic links'                                         = 'SeCreateSymbolicLinkPrivilege'
    'Debug programs'                                                = 'SeDebugPrivilege'
    'Force shutdown from a remote system'                           = 'SeRemoteShutdownPrivilege'
    'Generate security audits'                                      = 'SeAuditPrivilege'
    'Impersonate a client after authentication'                     = 'SeImpersonatePrivilege'
    'Increase scheduling priority'                                  = 'SeIncreaseBasePriorityPrivilege'
    'Lock pages in memory'                                          = 'SeLockMemoryPrivilege'
    'Manage auditing and security log'                              = 'SeSecurityPrivilege'
    'Modify firmware environment values'                            = 'SeSystemEnvironmentPrivilege'
    'Profile single process'                                        = 'SeProfileSingleProcessPrivilege'
    'Profile system performance'                                    = 'SeSystemProfilePrivilege'
    'Restore files and directories'                                 = 'SeRestorePrivilege'
    'Take ownership of files or other objects'                      = 'SeTakeOwnershipPrivilege'
}

$ACCT_KEY = @{
    'Enforce password history'                   = 'PasswordHistorySize'
    'Maximum password age'                       = 'MaximumPasswordAge'
    'Minimum password age'                       = 'MinimumPasswordAge'
    'Minimum password length'                    = 'MinimumPasswordLength'
    'Password must meet complexity requirements' = 'PasswordComplexity'
    'Store passwords using reversible encryption'= 'ClearTextPassword'
    'Account lockout duration'                   = 'LockoutDuration'
    'Account lockout threshold'                  = 'LockoutBadCount'
    'Reset account lockout counter after'        = 'ResetLockoutCount'
    'Account lockout observation window'         = 'ResetLockoutCount'
}

function Get-SeceditValue([string[]]$Lines, [string]$Section, [string]$Key) {
    $inSec = $false
    foreach ($l in $Lines) {
        if ($l -match "^\[$([regex]::Escape($Section))\]") { $inSec = $true; continue }
        if ($inSec -and $l -match '^\[') { break }
        if ($inSec -and $l -match "^$([regex]::Escape($Key))\s*=\s*(.+)$") { return $Matches[1].Trim() }
    }
    return $null
}

function Resolve-AccountSid([string]$Entry) {
    $sid = $Entry.TrimStart('*')
    $map = @{
        'S-1-5-6'      = 'SERVICE'
        'S-1-5-19'     = 'LOCAL SERVICE'
        'S-1-5-20'     = 'NETWORK SERVICE'
        'S-1-5-32-544' = 'Administrators'
        'S-1-5-32-545' = 'Users'
        'S-1-5-32-546' = 'Guests'
        'S-1-5-32-551' = 'Backup Operators'
        'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-32-578' = 'Hyper-V Administrators'
    }
    if ($map.ContainsKey($sid)) { return $map[$sid] }
    try { return ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $sid }
}

# ============================================================
# SECEDIT EXPORT (needed for user rights + account policy)
# ============================================================
Write-Host 'Exporting local security policy...' -ForegroundColor Cyan
$seceditTmp   = [System.IO.Path]::GetTempFileName() + '.inf'
& secedit /export /cfg $seceditTmp /quiet
$seceditLines = if (Test-Path $seceditTmp) { Get-Content $seceditTmp -Encoding Unicode } else { @() }

# ============================================================
# PROCESS EACH COMPLIANT SETTING
# ============================================================
Write-Host 'Running checks...' -ForegroundColor Cyan

$i = 0
foreach ($row in $compliant) {
    $i++
    $num   = "$($row.Number)".Trim()
    $title = "$($row.Title)".Trim()
    $gpo   = "$($row.GPO)".Trim()
    $rem   = "$($row.Remediation)".Trim()
    $audit = "$($row.Audit)".Trim()

    # ── Registry (Admin Templates + Security Options backed by registry) ──────
    $regCheck = Parse-RegistryCheck $audit
    if ($regCheck) {
        $regPath = "$($regCheck.Hive):\$($regCheck.RegPath)"
        try {
            $actual = Get-ItemPropertyValue -Path $regPath -Name $regCheck.ValueName -ErrorAction Stop
            if ($null -eq $regCheck.Expected) {
                Add-Result $num $title $gpo 'Registry' 'Exists' "$actual" 'CONFIGURED'
            } elseif ($regCheck.RegType -eq 'REG_DWORD') {
                $status = if ([int64]"$actual" -eq [int64]"$($regCheck.Expected)") { 'PASS' } else { 'FAIL' }
                Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" "$actual" $status
            } else {
                $status = if ("$actual" -eq "$($regCheck.Expected)") { 'PASS' } else { 'FAIL' }
                Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" "$actual" $status
            }
        } catch {
            Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" 'NOT FOUND' 'MISSING' 'Key/value not present'
        }
        continue
    }

    # ── Advanced Audit Policy ────────────────────────────────────────────────
    if ($rem -match 'Advanced Audit Policy') {
        $ap = Parse-AuditPolCheck $rem $title
        if ($ap.Subcategory) {
            $raw  = & auditpol /get /subcategory:"$($ap.Subcategory)" 2>$null
            $line = $raw | Where-Object { $_ -match [regex]::Escape($ap.Subcategory) }
            if ($line) {
                $actual = ($line -split '\s{2,}')[-1].Trim()
                $pass = switch ($ap.Expected) {
                    'Success and Failure' { $actual -eq 'Success and Failure' }
                    'Success'             { $actual -in @('Success','Success and Failure') }
                    'Failure'             { $actual -in @('Failure','Success and Failure') }
                    'No Auditing'         { $actual -eq 'No Auditing' }
                    default               { $actual -eq $ap.Expected }
                }
                Add-Result $num $title $gpo 'AuditPol' $ap.Expected $actual ($(if ($pass) { 'PASS' } else { 'FAIL' }))
            } else {
                Add-Result $num $title $gpo 'AuditPol' $ap.Expected 'NOT FOUND' 'MISSING' 'auditpol output not parsed'
            }
        } else {
            Add-Result $num $title $gpo 'AuditPol' '' '' 'MANUAL' 'Could not parse subcategory from remediation text'
        }
        continue
    }

    # ── User Rights Assignment ───────────────────────────────────────────────
    if ($rem -match 'User Rights Assignment') {
        $right = ''
        if ($rem -match 'User Rights Assignment\\(.+?)$') { $right = $Matches[1].Trim() }
        $exp = ''
        if ($rem -match "set the following UI path to (.+?):") { $exp = $Matches[1].Trim() }

        $const = $RIGHT_CONST[$right]
        if (-not $const) {
            Add-Result $num $title $gpo 'UserRight' $exp '' 'MANUAL' "No secedit constant mapped for: $right"
            continue
        }
        $raw     = Get-SeceditValue $seceditLines 'Privilege Rights' $const
        $members = if ($null -eq $raw -or $raw.Trim() -eq '') { @() }
                   else { $raw -split ',' | ForEach-Object { Resolve-AccountSid $_.Trim() } }
        $actual  = if ($members.Count -eq 0) { '(empty)' } else { $members -join ', ' }

        if ($exp -ieq 'No One') {
            $status = if ($members.Count -eq 0) { 'PASS' } else { 'FAIL' }
        } else {
            $exp_list = $exp -split ',' | ForEach-Object { $_.Trim() }
            $missing  = @($exp_list | Where-Object { $ea=$_; -not ($members | Where-Object { $_ -like "*$ea*" -or $ea -like "*$_*" }) })
            $extra    = @($members  | Where-Object { $m=$_;  -not ($exp_list  | Where-Object { $m -like "*$_*" -or $_ -like "*$m*"  }) })
            $status   = if ($missing.Count -eq 0 -and $extra.Count -eq 0) { 'PASS' }
                        elseif ($missing.Count -gt 0) { 'FAIL' }
                        else { 'REVIEW' }
        }
        Add-Result $num $title $gpo 'UserRight' $exp $actual $status
        continue
    }

    # ── Account / Password Policy ─────────────────────────────────────────────
    if ($rem -match 'Account Policies') {
        $setting = ''
        if ($rem -match 'Account Policies\\(?:.+?)\\(.+?)$') { $setting = $Matches[1].Trim() }
        $exp = ''
        if ($rem -match "set the following UI path to (.+?):") { $exp = $Matches[1].Trim() }

        $key = $ACCT_KEY[$setting]
        if (-not $key) {
            Add-Result $num $title $gpo 'AccountPolicy' $exp '' 'MANUAL' "No secedit key mapped for: $setting"
            continue
        }
        $val = Get-SeceditValue $seceditLines 'System Access' $key
        if ($null -eq $val) { Add-Result $num $title $gpo 'AccountPolicy' $exp 'NOT FOUND' 'MISSING'; continue }
        $n = [int]$val
        $status = if     ($exp -match '(\d+) or fewer .+, but not 0') { if ($n -gt 0 -and $n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
                  elseif ($exp -match '(\d+) or fewer')               { if ($n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
                  elseif ($exp -match '(\d+) or more')                { if ($n -ge [int]$Matches[1]) {'PASS'} else {'FAIL'} }
                  elseif ($exp -match 'Disabled')                     { if ($n -eq 0) {'PASS'} else {'FAIL'} }
                  elseif ($exp -match 'Enabled')                      { if ($n -eq 1) {'PASS'} else {'FAIL'} }
                  else                                                 { 'REVIEW' }
        Add-Result $num $title $gpo 'AccountPolicy' $exp $n $status
        continue
    }

    # ── Security Options / Fallback ───────────────────────────────────────────
    $exp = ''
    if ($rem -match "set the following UI path to (.+?):") { $exp = $Matches[1].Trim() }
    Add-Result $num $title $gpo 'Other' $exp '' 'MANUAL' 'Verify manually in Local Security Policy / Group Policy'
}

Remove-Item $seceditTmp -Force -ErrorAction SilentlyContinue

# ============================================================
# RESULTS
# ============================================================
$pass    = @($Results | Where-Object Status -eq 'PASS').Count
$fail    = @($Results | Where-Object Status -eq 'FAIL').Count
$missing = @($Results | Where-Object Status -eq 'MISSING').Count
$review  = @($Results | Where-Object Status -in @('REVIEW','MANUAL','CONFIGURED')).Count

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host " CIS L1 Compliance - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan
Write-Host "  PASS    : $pass"    -ForegroundColor Green
Write-Host "  FAIL    : $fail"    -ForegroundColor Red
Write-Host "  MISSING : $missing" -ForegroundColor Red
Write-Host "  REVIEW  : $review"  -ForegroundColor Yellow
Write-Host "  TOTAL   : $($Results.Count)"
Write-Host ''

if ($fail -gt 0 -or $missing -gt 0) {
    Write-Host 'Non-passing settings:' -ForegroundColor Red
    $Results | Where-Object { $_.Status -in @('FAIL','MISSING') } |
        Sort-Object Number |
        Format-Table Number, GPO, Status, Expected, Actual -AutoSize
}

$Results | Sort-Object Number | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Full results saved to: $OutputPath" -ForegroundColor Cyan
