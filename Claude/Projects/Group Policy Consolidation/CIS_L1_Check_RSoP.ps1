#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Windows 11 Enterprise Benchmark v4.0.0 - L1 Compliance Check (RSoP)

.DESCRIPTION
    Reads "Group Policy Settings.xlsx" at runtime, then checks each Compliant
    setting against the machine's Resultant Set of Policy (RSoP) data via WMI
    rather than reading the registry or secedit directly.

    RSoP reflects only what Group Policy has explicitly configured. Settings
    absent from RSoP are reported as NOT_IN_RSoP — this may mean the setting
    is controlled by a local default rather than a GPO, which warrants review.

    Check coverage:
      Registry (Admin Templates)  → RSOP_RegistryPolicySetting WMI class
      User Rights Assignment      → RSOP_UserPrivilegeRight WMI class
      Account / Lockout Policy    → RSOP_PasswordPolicy / RSOP_LockoutPolicy WMI classes
      Advanced Audit Policy       → auditpol (no RSoP WMI class for subcategories)
      Security Options            → MANUAL (no reliable RSoP WMI representation)

    Requires ImportExcel module (auto-installed if missing).

.PARAMETER ExcelPath
    Path to "Group Policy Settings.xlsx". Defaults to same folder as script.

.PARAMETER OutputPath
    CSV output path. Defaults to script folder with timestamp.

.PARAMETER ForceGPUpdate
    Run gpupdate /force before collecting RSoP data. Adds ~30 seconds but
    ensures RSoP reflects the latest applied policy.

.NOTES
    Run as Administrator.
    Usage:  .\CIS_L1_Check_RSoP.ps1
            .\CIS_L1_Check_RSoP.ps1 -ForceGPUpdate
#>

[CmdletBinding()]
param(
    [string]$ExcelPath     = (Join-Path $PSScriptRoot 'Group Policy Settings.xlsx'),
    [string]$OutputPath    = (Join-Path $PSScriptRoot "CIS_L1_Compliance_RSoP_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"),
    [switch]$ForceGPUpdate
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
# OPTIONAL GP REFRESH
# ============================================================
if ($ForceGPUpdate) {
    Write-Host 'Running gpupdate /force...' -ForegroundColor Yellow
    & gpupdate /force /wait:60 | Out-Null
    Write-Host 'GP update complete.' -ForegroundColor Green
}

# ============================================================
# LOAD SPREADSHEET
# ============================================================
Write-Host "Reading: $ExcelPath" -ForegroundColor Cyan
$rows      = Import-Excel -Path $ExcelPath -WorksheetName 'Recommendations' -StartRow 4
$compliant = @($rows | Where-Object { $_.'Compliance Status' -eq 'Compliant' })
Write-Host "Found $($compliant.Count) Compliant settings to verify." -ForegroundColor Cyan

# ============================================================
# LOAD RSoP DATA FROM WMI  (namespace: root\rsop\computer)
# ============================================================
Write-Host 'Loading RSoP data from WMI...' -ForegroundColor Cyan
$rsopNs = 'root\rsop\computer'

# Registry-based policy settings (Administrative Templates)
# KeyPath uses full hive name: "HKEY_LOCAL_MACHINE\SOFTWARE\..."
# Precedence 1 = winning GPO; we only want winning values
$rsopRegRaw = @(Get-WmiObject -Namespace $rsopNs -Class RSOP_RegistryPolicySetting -ErrorAction SilentlyContinue |
                Where-Object { $_.precedence -eq 1 })

# Build lookup: normalised "HKLM\Path:ValueName" (lowercase) -> value
$rsopRegMap = @{}
foreach ($r in $rsopRegRaw) {
    $normPath = $r.KeyPath `
        -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\' `
        -replace '^HKEY_CURRENT_USER\\',  'HKCU\' `
        -replace '^HKEY_USERS\\',         'HKU\'  `
        -replace '^HKEY_CLASSES_ROOT\\',  'HKCR\'
    $key = "$normPath`:$($r.ValueName)".ToLower()
    $rsopRegMap[$key] = $r.Value
}
Write-Host "  Registry policies loaded : $($rsopRegMap.Count)" -ForegroundColor Gray

# User Rights Assignment
$rsopRightsRaw = @(Get-WmiObject -Namespace $rsopNs -Class RSOP_UserPrivilegeRight -ErrorAction SilentlyContinue |
                   Where-Object { $_.precedence -eq 1 })
$rsopRightsMap = @{}
foreach ($r in $rsopRightsRaw) {
    $rsopRightsMap[$r.UserRight] = $r.AccountList   # comma-separated SID or account strings
}
Write-Host "  User rights loaded       : $($rsopRightsMap.Count)" -ForegroundColor Gray

# Password Policy
$rsopPwdPol  = Get-WmiObject -Namespace $rsopNs -Class RSOP_PasswordPolicy  -ErrorAction SilentlyContinue |
               Where-Object { $_.precedence -eq 1 } | Select-Object -First 1

# Lockout Policy
$rsopLockPol = Get-WmiObject -Namespace $rsopNs -Class RSOP_LockoutPolicy   -ErrorAction SilentlyContinue |
               Where-Object { $_.precedence -eq 1 } | Select-Object -First 1

Write-Host "  Password policy loaded   : $($null -ne $rsopPwdPol)" -ForegroundColor Gray
Write-Host "  Lockout policy loaded    : $($null -ne $rsopLockPol)" -ForegroundColor Gray

# ============================================================
# AUDIT POLICY (auditpol - no RSoP WMI class for subcategories)
# ============================================================
# Pre-cache all subcategory results to avoid repeated auditpol calls
Write-Host 'Caching audit policy subcategories...' -ForegroundColor Cyan
$auditpolCache = @{}
$auditpolRaw = & auditpol /get /category:* 2>$null
if ($auditpolRaw) {
    foreach ($line in $auditpolRaw) {
        # Lines look like: "  Credential Validation             Success and Failure"
        if ($line -match '^\s{2}(.+?)\s{2,}(\w.+)$') {
            $auditpolCache[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
}
Write-Host "  Audit subcategories cached: $($auditpolCache.Count)" -ForegroundColor Gray

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

function Parse-RegistryCheck([string]$AuditText) {
    $t = $AuditText -replace '(\w)-\s+([A-Fa-f0-9])', '$1-$2'
    $regType = 'REG_DWORD'; $expected = $null
    if ($t -match '(REG_\w+) value of ([^\s\n\.]+)') {
        $regType = $Matches[1]
        $raw     = $Matches[2].TrimEnd(':').Trim('"')
        $expected = if ($regType -eq 'REG_DWORD') { try { [int]$raw } catch { $raw } } else { $raw }
    }
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
            LookupKey = "$($parts[0])\$(($parts | Select-Object -Skip 1) -join '\'):$valueName".ToLower()
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

function Resolve-RsopAccount([string]$Entry) {
    # RSoP AccountList entries may be SIDs or domain\user strings
    $sid = $Entry.Trim().TrimStart('*')
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
    catch { return $Entry.Trim() }
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

$ACCT_KEY_PWD = @{
    'Enforce password history'                    = 'PasswordHistorySize'
    'Maximum password age'                        = 'MaximumPasswordAge'
    'Minimum password age'                        = 'MinimumPasswordAge'
    'Minimum password length'                     = 'MinimumPasswordLength'
    'Password must meet complexity requirements'  = 'PasswordComplexity'
    'Store passwords using reversible encryption' = 'ClearTextPassword'
}

$ACCT_KEY_LOCK = @{
    'Account lockout duration'           = 'LockoutDuration'
    'Account lockout threshold'          = 'LockoutBadCount'
    'Reset account lockout counter after'= 'ResetLockoutCount'
    'Account lockout observation window' = 'ResetLockoutCount'
}

function Test-NumericExpected([string]$Exp, [int]$n) {
    if     ($Exp -match '(\d+) or fewer .+, but not 0') { if ($n -gt 0 -and $n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
    elseif ($Exp -match '(\d+) or fewer')               { if ($n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
    elseif ($Exp -match '(\d+) or more')                { if ($n -ge [int]$Matches[1]) {'PASS'} else {'FAIL'} }
    elseif ($Exp -match 'Disabled')                     { if ($n -eq 0) {'PASS'} else {'FAIL'} }
    elseif ($Exp -match 'Enabled')                      { if ($n -eq 1) {'PASS'} else {'FAIL'} }
    else                                                { 'REVIEW' }
}

# ============================================================
# PROCESS EACH COMPLIANT SETTING
# ============================================================
Write-Host 'Running checks...' -ForegroundColor Cyan

foreach ($row in $compliant) {
    $num   = "$($row.Number)".Trim()
    $title = "$($row.Title)".Trim()
    $gpo   = "$($row.GPO)".Trim()
    $rem   = "$($row.Remediation)".Trim()
    $audit = "$($row.Audit)".Trim()

    # ── Registry / Administrative Templates ──────────────────────────────────
    $regCheck = Parse-RegistryCheck $audit
    if ($regCheck) {
        $rsopVal = $rsopRegMap[$regCheck.LookupKey]

        if ($null -eq $rsopVal) {
            Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" 'NOT IN RSoP' 'NOT_IN_RSoP' `
                'Setting not found in RSoP - may be a local default or GPO not linked'
        } elseif ($null -eq $regCheck.Expected) {
            Add-Result $num $title $gpo 'Registry' 'Configured' "$rsopVal" 'CONFIGURED'
        } elseif ($regCheck.RegType -eq 'REG_DWORD') {
            $status = if ([int64]"$rsopVal" -eq [int64]"$($regCheck.Expected)") { 'PASS' } else { 'FAIL' }
            Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" "$rsopVal" $status
        } else {
            $status = if ("$rsopVal" -eq "$($regCheck.Expected)") { 'PASS' } else { 'FAIL' }
            Add-Result $num $title $gpo 'Registry' "$($regCheck.Expected)" "$rsopVal" $status
        }
        continue
    }

    # ── Advanced Audit Policy (auditpol - no RSoP WMI class) ─────────────────
    if ($rem -match 'Advanced Audit Policy') {
        $ap = Parse-AuditPolCheck $rem $title
        if ($ap.Subcategory) {
            $actual = $auditpolCache[$ap.Subcategory]
            if (-not $actual) {
                Add-Result $num $title $gpo 'AuditPol' $ap.Expected 'NOT FOUND' 'MISSING' 'Subcategory not in auditpol cache'
            } else {
                $pass = switch ($ap.Expected) {
                    'Success and Failure' { $actual -eq 'Success and Failure' }
                    'Success'             { $actual -in @('Success','Success and Failure') }
                    'Failure'             { $actual -in @('Failure','Success and Failure') }
                    'No Auditing'         { $actual -eq 'No Auditing' }
                    default               { $actual -eq $ap.Expected }
                }
                Add-Result $num $title $gpo 'AuditPol' $ap.Expected $actual ($(if ($pass) { 'PASS' } else { 'FAIL' }))
            }
        } else {
            Add-Result $num $title $gpo 'AuditPol' '' '' 'MANUAL' 'Could not parse subcategory'
        }
        continue
    }

    # ── User Rights Assignment (RSOP_UserPrivilegeRight) ─────────────────────
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

        if (-not $rsopRightsMap.ContainsKey($const)) {
            Add-Result $num $title $gpo 'UserRight' $exp 'NOT IN RSoP' 'NOT_IN_RSoP' `
                'Right not found in RSoP - may not be configured via GPO'
            continue
        }

        $rawList = $rsopRightsMap[$const]
        $members = if ([string]::IsNullOrWhiteSpace($rawList)) { @() }
                   else { $rawList -split ',' | ForEach-Object { Resolve-RsopAccount $_ } }
        $actual  = if ($members.Count -eq 0) { '(empty)' } else { $members -join ', ' }

        if ($exp -ieq 'No One') {
            $status = if ($members.Count -eq 0) { 'PASS' } else { 'FAIL' }
        } else {
            $exp_list = $exp -split ',' | ForEach-Object { $_.Trim() }
            $missing  = @($exp_list | Where-Object { $ea=$_; -not ($members | Where-Object { $_ -like "*$ea*" -or $ea -like "*$_*" }) })
            $extra    = @($members  | Where-Object { $m=$_;  -not ($exp_list  | Where-Object { $m -like "*$_*" -or $_ -like "*$m*"  }) })
            $status   = if ($missing.Count -eq 0 -and $extra.Count -eq 0) { 'PASS' }
                        elseif ($missing.Count -gt 0) { 'FAIL' }
                        else { 'REVIEW' }  # extra accounts beyond CIS baseline
        }
        Add-Result $num $title $gpo 'UserRight' $exp $actual $status
        continue
    }

    # ── Account / Password Policy (RSOP_PasswordPolicy / RSOP_LockoutPolicy) ─
    if ($rem -match 'Account Policies') {
        $setting = ''
        if ($rem -match 'Account Policies\\(?:.+?)\\(.+?)$') { $setting = $Matches[1].Trim() }
        $exp = ''
        if ($rem -match "set the following UI path to (.+?):") { $exp = $Matches[1].Trim() }

        $propName = $ACCT_KEY_PWD[$setting]
        $srcObj   = $rsopPwdPol
        if (-not $propName) {
            $propName = $ACCT_KEY_LOCK[$setting]
            $srcObj   = $rsopLockPol
        }

        if (-not $propName) {
            Add-Result $num $title $gpo 'AccountPolicy' $exp '' 'MANUAL' "No RSoP property mapped for: $setting"
            continue
        }
        if ($null -eq $srcObj) {
            Add-Result $num $title $gpo 'AccountPolicy' $exp 'NOT IN RSoP' 'NOT_IN_RSoP' 'Policy object not found in RSoP WMI'
            continue
        }

        $val = $srcObj.$propName
        if ($null -eq $val) {
            Add-Result $num $title $gpo 'AccountPolicy' $exp 'NOT IN RSoP' 'NOT_IN_RSoP' "Property $propName not present in RSoP WMI object"
            continue
        }

        $n      = [int]$val
        $status = Test-NumericExpected $exp $n
        Add-Result $num $title $gpo 'AccountPolicy' $exp $n $status
        continue
    }

    # ── Security Options / Fallback ───────────────────────────────────────────
    $exp = ''
    if ($rem -match "set the following UI path to (.+?):") { $exp = $Matches[1].Trim() }
    Add-Result $num $title $gpo 'Other' $exp '' 'MANUAL' 'No RSoP WMI class available - verify in Group Policy'
}

# ============================================================
# RESULTS
# ============================================================
$pass       = @($Results | Where-Object Status -eq 'PASS').Count
$fail       = @($Results | Where-Object Status -eq 'FAIL').Count
$notInRsop  = @($Results | Where-Object Status -eq 'NOT_IN_RSoP').Count
$missing    = @($Results | Where-Object Status -eq 'MISSING').Count
$review     = @($Results | Where-Object Status -in @('REVIEW','MANUAL','CONFIGURED')).Count

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host " CIS L1 RSoP Check - $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan
Write-Host "  PASS        : $pass"       -ForegroundColor Green
Write-Host "  FAIL        : $fail"       -ForegroundColor Red
Write-Host "  NOT IN RSoP : $notInRsop"  -ForegroundColor Yellow
Write-Host "  MISSING     : $missing"    -ForegroundColor Red
Write-Host "  REVIEW      : $review"     -ForegroundColor Yellow
Write-Host "  TOTAL       : $($Results.Count)"
Write-Host ''
Write-Host 'NOTE: NOT_IN_RSoP means the setting is not explicitly configured via GPO.' -ForegroundColor Yellow
Write-Host '      The setting may still be correct due to Windows defaults.' -ForegroundColor Yellow
Write-Host ''

if ($fail -gt 0 -or $missing -gt 0) {
    Write-Host 'Failing settings:' -ForegroundColor Red
    $Results | Where-Object { $_.Status -in @('FAIL','MISSING') } |
        Sort-Object Number |
        Format-Table Number, GPO, Status, Expected, Actual -AutoSize
}

if ($notInRsop -gt 0) {
    Write-Host "Settings not found in RSoP ($notInRsop):" -ForegroundColor Yellow
    $Results | Where-Object { $_.Status -eq 'NOT_IN_RSoP' } |
        Sort-Object Number |
        Format-Table Number, GPO, Type, Title -AutoSize -Wrap
}

$Results | Sort-Object Number | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Full results saved to: $OutputPath" -ForegroundColor Cyan
