#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Creates AZ admin AD accounts for each OpCo Network Administrator.

.DESCRIPTION
    Provisions az.<First>.<Last> accounts in the OU=AZ Admins,OU=Users,OU=Admin,DC=FCTG,DC=NET
    organizational unit. Each account UPN is set to az.<First>.<Last>@fctg.com.
    After creation, every account is added to the "Password Length Policy - Priviledged" group.

    Accounts are enabled with ChangePasswordAtLogon = true.
    Existing accounts are detected and skipped rather than overwritten.

    NOTE: PFP (Plateau Forest Products) is managed by New Fathom MSP -- no individual
    network admin account exists; this OpCo is intentionally excluded.

.PARAMETER DomainController
    Optional. FQDN or IP of the DC to target. Defaults to the PDC emulator.

.PARAMETER DefaultPassword
    Optional. SecureString initial password for all new accounts.
    If omitted, the script prompts once before processing begins.

.EXAMPLE
    # Dry-run -- shows what would be created without making changes
    .\New-OpCoAzAdminAccounts.ps1 -WhatIf

.EXAMPLE
    # Live run, explicit DC
    .\New-OpCoAzAdminAccounts.ps1 -DomainController dc01.fctg.net -Verbose

.NOTES
    Author      : Chuck Littlefield / FCTG IT
    Requires    : ActiveDirectory module; rights to create users in the target OU
                  and to modify the target group membership.
    UPN Suffix  : All accounts use @fctg.com -- no alternate UPN suffix required.
    SAM limit   : AD SAMAccountName is capped at 20 characters. Names that exceed
                  this are auto-truncated and a warning is logged.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = 'Target DC FQDN or IP. Omit to use PDC emulator.')]
    [string]$DomainController = '',

    [Parameter(HelpMessage = 'Initial password as SecureString. Prompted if omitted.')]
    [securestring]$DefaultPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

$targetOU    = 'OU=AZ Admins,OU=Users,OU=Admin,DC=FCTG,DC=NET'
$targetGroup = 'Password Length Policy - Priviledged'

$networkAdmins = @(
    # AIFP/AR -- American International Forest Products / Affiliated Resources
    [PSCustomObject]@{ OpCo = 'AIFP/AR'; GivenName = 'Kevin';   Surname = 'Curtis'      }
    # BIFP -- Birmingham International Forest Products
    [PSCustomObject]@{ OpCo = 'BIFP';    GivenName = 'Keaton';  Surname = 'Russell'     }
    # BP -- Buckeye Pacific
    [PSCustomObject]@{ OpCo = 'BP';      GivenName = 'Jordan';  Surname = 'Staples'     }
    # OI -- Olympic Industries
    [PSCustomObject]@{ OpCo = 'OI';      GivenName = 'Chris';   Surname = 'Irwin'       }
    # PFP excluded -- managed by New Fathom MSP, no named individual
    # RIFP -- Richmond International Forest Products
    [PSCustomObject]@{ OpCo = 'RIFP';    GivenName = 'Bobby';   Surname = 'Bui'         }
    # SIFP -- Seaboard International Forest Products (two admins)
    [PSCustomObject]@{ OpCo = 'SIFP';    GivenName = 'Janice';  Surname = 'Clark'       }
    [PSCustomObject]@{ OpCo = 'SIFP';    GivenName = 'Charles'; Surname = 'Littlefield' }
    # SMT -- Southern Mississippi Trading
    [PSCustomObject]@{ OpCo = 'SMT';     GivenName = 'Sean';    Surname = 'Scoggins'    }
    # TIFP -- Tampa International Forest Products
    [PSCustomObject]@{ OpCo = 'TIFP';    GivenName = 'David';   Surname = 'Garnica'     }
    # VFP -- Viking Forest Products (three admins)
    [PSCustomObject]@{ OpCo = 'VFP';     GivenName = 'Lula';    Surname = 'Mesfin'      }
    [PSCustomObject]@{ OpCo = 'VFP';     GivenName = 'Garrett'; Surname = 'Moore'       }
    [PSCustomObject]@{ OpCo = 'VFP';     GivenName = 'Ben';     Surname = 'Schuler'     }
)

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level,
        [string]$Message
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red'    }
        default { 'Cyan'   }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

function Get-AzSamAccountName {
    param(
        [Parameter(Mandatory)][string]$GivenName,
        [Parameter(Mandatory)][string]$Surname
    )
    $sam = 'az.' + $GivenName.ToLower() + '.' + $Surname.ToLower()
    if ($sam.Length -gt 20) {
        $truncated = $sam.Substring(0, 20)
        Write-Log 'WARN' "SAMAccountName '$sam' exceeds 20 chars -- truncated to '$truncated'"
        $sam = $truncated
    }
    return $sam
}

# ---------------------------------------------------------------------------
#  Pre-flight checks
# ---------------------------------------------------------------------------

if (-not $DefaultPassword) {
    $DefaultPassword = Read-Host -AsSecureString -Prompt 'Enter initial password for new accounts'
}

$dcSplat = @{}
if ($DomainController) {
    $dcSplat['Server'] = $DomainController
    Write-Log 'INFO' "Targeting DC: $DomainController"
} else {
    Write-Log 'INFO' 'No DC specified -- will use PDC emulator'
}

Write-Log 'INFO' "Verifying target OU: $targetOU"
try {
    $null = Get-ADOrganizationalUnit -Identity $targetOU @dcSplat
    Write-Log 'INFO' 'Target OU found.'
} catch {
    throw "Target OU not found or inaccessible: $targetOU`n$_"
}

Write-Log 'INFO' "Verifying target group: $targetGroup"
try {
    $groupObj = Get-ADGroup -Identity $targetGroup @dcSplat
    Write-Log 'INFO' "Target group found: $($groupObj.DistinguishedName)"
} catch {
    throw "Target group not found or inaccessible: '$targetGroup'`n$_"
}

# ---------------------------------------------------------------------------
#  Main loop
# ---------------------------------------------------------------------------

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$total   = $networkAdmins.Count
$i       = 0

foreach ($admin in $networkAdmins) {

    $i++
    $sam         = Get-AzSamAccountName -GivenName $admin.GivenName -Surname $admin.Surname
    $upn         = 'az.' + $admin.GivenName.ToLower() + '.' + $admin.Surname.ToLower() + '@fctg.com'
    $displayName = 'az.' + $admin.GivenName + ' ' + $admin.Surname
    $description = 'AZ Admin account - ' + $admin.OpCo + ' Network Admin'

    Write-Progress -Activity 'Creating OpCo AZ Admin Accounts' `
                   -Status    "[$i/$total] $upn" `
                   -PercentComplete ([math]::Round($i / $total * 100))

    Write-Log 'INFO' "[$($admin.OpCo)] Processing: $upn  (SAM: $sam)"

    $result = [PSCustomObject]@{
        OpCo    = $admin.OpCo
        SAM     = $sam
        UPN     = $upn
        Status  = 'Pending'
        Details = ''
    }

    try {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" @dcSplat -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log 'WARN' "Account already exists -- skipping: $sam"
            $result.Status  = 'Skipped'
            $result.Details = 'Account already exists'
            $results.Add($result)
            continue
        }

        if ($PSCmdlet.ShouldProcess($upn, 'New-ADUser')) {
            New-ADUser @dcSplat `
                -SamAccountName        $sam `
                -UserPrincipalName     $upn `
                -GivenName             $admin.GivenName `
                -Surname               $admin.Surname `
                -DisplayName           $displayName `
                -Name                  $displayName `
                -Description           $description `
                -Path                  $targetOU `
                -AccountPassword       $DefaultPassword `
                -ChangePasswordAtLogon $true `
                -Enabled               $true

            Write-Log 'INFO' "Created account: $upn"

            Add-ADGroupMember -Identity $targetGroup -Members $sam @dcSplat
            Write-Log 'INFO' "Added '$sam' to '$targetGroup'"

            $result.Status  = 'Created'
            $result.Details = "Member of '$targetGroup'"
        }

    } catch {
        Write-Log 'ERROR' "Failed for ${upn}: $_"
        $result.Status  = 'Error'
        $result.Details = $_.Exception.Message
    }

    $results.Add($result)
}

Write-Progress -Activity 'Creating OpCo AZ Admin Accounts' -Completed

# ---------------------------------------------------------------------------
#  Summary
# ---------------------------------------------------------------------------

$created = ($results | Where-Object Status -eq 'Created').Count
$skipped = ($results | Where-Object Status -eq 'Skipped').Count
$errors  = ($results | Where-Object Status -eq 'Error').Count

Write-Host ''
Write-Host '------------------------------------------------------------'
Write-Host "  OpCo AZ Admin Account Provisioning - Complete"
Write-Host "  Created : $created  |  Skipped : $skipped  |  Errors : $errors"
Write-Host '------------------------------------------------------------'
$results | Format-Table OpCo, SAM, UPN, Status, Details -AutoSize
Write-Host '------------------------------------------------------------'

$results
