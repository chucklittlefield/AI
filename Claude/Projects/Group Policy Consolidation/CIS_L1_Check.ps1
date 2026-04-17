#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Windows 11 Enterprise Benchmark v4.0.0 - L1 Compliance Check

.DESCRIPTION
    Checks all settings currently marked 'Compliant' in Group Policy Settings.xlsx
    against this machine's actual configuration. Covers:
      184 registry | 25 audit policy | 15 user rights | 4 account policy | 2 security options

.NOTES
    Requires: Run as Administrator
    Output:   CSV file in the current directory
    Usage:    .\CIS_L1_Check.ps1
              .\CIS_L1_Check.ps1 -OutputPath C:\Temp\results.csv
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\CIS_L1_Compliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

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

# ==============================================================================
# 1/5  REGISTRY  (184 checks)
# ==============================================================================
Write-Host '[1/5] Registry checks...' -ForegroundColor Cyan

$RegChecks = @(
    @{ Number='2.3.1.2'; Title='Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='LimitBlankPasswordUse'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.2.1'; Title='Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settin'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='SCENoApplyLegacyAuditPolicy'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.2.2'; Title='Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='CrashOnAuditFail'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.6.1'; Title='Ensure ''Domain member: Digitally encrypt or sign secure channel data (always)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='RequireSignOrSeal'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.6.2'; Title='Ensure ''Domain member: Digitally encrypt secure channel data (when possible)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='SealSecureChannel'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.6.3'; Title='Ensure ''Domain member: Digitally sign secure channel data (when possible)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='SignSecureChannel'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.6.4'; Title='Ensure ''Domain member: Disable machine account password changes'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='DisablePasswordCha'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.6.5'; Title='Ensure ''Domain member: Maximum machine account password age'' is set to ''30 or fewer days, but not 0'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='System\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='MaximumPasswordAge'; RegType='REG_DWORD'; Expected=30 }
    @{ Number='2.3.6.6'; Title='Ensure ''Domain member: Require strong (Windows 2000 or later) session key'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; ValueName='RequireStrongKey'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.8.1'; Title='Ensure ''Microsoft network client: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName='RequireSe'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.8.2'; Title='Ensure ''Microsoft network client: Digitally sign communications (if server agrees)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName='EnableSec'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.8.3'; Title='Ensure ''Microsoft network client: Send unencrypted password to third-party SMB servers'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName='EnablePla'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.9.1'; Title='Ensure ''Microsoft network server: Amount of idle time required before suspending session'' is set to ''15 or fewer minute('; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; ValueName='AutoDisconnect'; RegType='REG_DWORD'; Expected=15 }
    @{ Number='2.3.9.2'; Title='Ensure ''Microsoft network server: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; ValueName='RequireSecurit'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.9.3'; Title='Ensure ''Microsoft network server: Digitally sign communications (if client agrees)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; ValueName='EnableSecurity'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.9.4'; Title='Ensure ''Microsoft network server: Disconnect clients when logon hours expire'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; ValueName='enableforcedlo'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.10.2'; Title='Ensure ''Network access: Do not allow anonymous enumeration of SAM accounts'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='RestrictAnonymousSAM'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.10.5'; Title='Ensure ''Network access: Let Everyone permissions apply to anonymous users'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='EveryoneIncludesAnonymous'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.10.7'; Title='Ensure ''Network access: Remotely accessible registry paths'' is configured (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPa ths'; ValueName='Machine'; RegType='REG_MULTI_SZ'; Expected='System\CurrentControlSet\Control\ProductOptions,' }
    @{ Number='2.3.10.8'; Title='Ensure ''Network access: Remotely accessible registry paths and sub-paths'' is configured (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'; ValueName='M'; RegType='REG_DWORD'; Expected='System\CurrentControlSet\Control\Print\Printers,' }
    @{ Number='2.3.10.9'; Title='Ensure ''Network access: Restrict anonymous access to Named Pipes and Shares'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; ValueName='RestrictNullSe'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.10.10'; Title='Ensure ''Network access: Restrict clients allowed to make remote calls to SAM'' is set to ''Administrators: Remote Access: '; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='restrictremotesam'; RegType='REG_SZ'; Expected='O:BAG:BAD:(A;;RC;;;BA)' }
    @{ Number='2.3.10.12'; Title='Ensure ''Network access: Sharing and security model for local accounts'' is set to ''Classic - local users authenticate as '; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='ForceGuest'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.11.2'; Title='Ensure ''Network security: Allow LocalSystem NULL session fallback'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; ValueName='AllowNullSessionFallback'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.11.3'; Title='Ensure ''Network Security: Allow PKU2U authentication requests to this computer to use online identities'' is set to ''Disa'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa\pku2u'; ValueName='AllowOnlineID'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='2.3.15.1'; Title='Ensure ''System objects: Require case insensitivity for non-Windows subsystems'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'; ValueName='ObCaseInsensitive'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.15.2'; Title='Ensure ''System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)'' is set to ''Enab'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Session Manager'; ValueName='ProtectionMode'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.17.5'; Title='Ensure ''User Account Control: Only elevate UIAccess applications that are installed in secure locations'' is set to ''Enab'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='EnableSecureUI'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.17.6'; Title='Ensure ''User Account Control: Run all administrators in Admin Approval Mode'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='EnableLUA'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.17.7'; Title='Ensure ''User Account Control: Switch to the secure desktop when prompting for elevation'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='PromptOnSecure'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='2.3.17.8'; Title='Ensure ''User Account Control: Virtualize file and registry write failures to per-user locations'' is set to ''Enabled'' (Au'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='EnableVirtuali'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='5.20'; Title='Ensure ''Remote Procedure Call (RPC) Locator (RpcLocator)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\RpcLocator'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.22'; Title='Ensure ''Routing and Remote Access (RemoteAccess)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\RemoteAccess'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.27'; Title='Ensure ''SSDP Discovery (SSDPSRV)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\SSDPSRV'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.28'; Title='Ensure ''UPnP Device Host (upnphost)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\upnphost'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.32'; Title='Ensure ''Windows Media Player Network Sharing Service (WMPNetworkSvc)'' is set to ''Disabled'' or ''Not Installed'' (Automated'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\WMPNetworkSvc'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.33'; Title='Ensure ''Windows Mobile Hotspot Service (icssvc)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\icssvc'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.39'; Title='Ensure ''Xbox Accessory Management Service (XboxGipSvc)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\XboxGipSvc'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.40'; Title='Ensure ''Xbox Live Auth Manager (XblAuthManager)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\XblAuthManager'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.41'; Title='Ensure ''Xbox Live Game Save (XblGameSave)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\XblGameSave'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='5.42'; Title='Ensure ''Xbox Live Networking Service (XboxNetApiSvc)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise-Services -workstation'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\XboxNetApiSvc'; ValueName='Start'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='9.1.3'; Title='Ensure ''Windows Firewall: Domain: Settings: Display a notification'' is set to ''No'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName='DisableNotific'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.1.4'; Title='Ensure ''Windows Firewall: Domain: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\domainfw.log'' (Autom'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; ValueName='LogFil'; RegType='REG_SZ'; Expected='%SystemRoot%\System32\logfiles\firewall\domainfw' }
    @{ Number='9.1.5'; Title='Ensure ''Windows Firewall: Domain: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; ValueName='LogFil'; RegType='REG_DWORD'; Expected=16384 }
    @{ Number='9.1.6'; Title='Ensure ''Windows Firewall: Domain: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; ValueName='LogDro'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.1.7'; Title='Ensure ''Windows Firewall: Domain: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; ValueName='LogSuc'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.2.3'; Title='Ensure ''Windows Firewall: Private: Settings: Display a notification'' is set to ''No'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName='DisableNotifi'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.2.4'; Title='Ensure ''Windows Firewall: Private: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\privatefw.log'' (Aut'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; ValueName='LogFi'; RegType='REG_SZ'; Expected='%SystemRoot%\System32\logfiles\firewall\privatefw' }
    @{ Number='9.2.5'; Title='Ensure ''Windows Firewall: Private: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; ValueName='LogFi'; RegType='REG_DWORD'; Expected=16384 }
    @{ Number='9.2.6'; Title='Ensure ''Windows Firewall: Private: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; ValueName='LogDr'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.2.7'; Title='Ensure ''Windows Firewall: Private: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; ValueName='LogSu'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.3.3'; Title='Ensure ''Windows Firewall: Public: Settings: Display a notification'' is set to ''No'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='DisableNotific'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.3.4'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local firewall rules'' is set to ''No'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='AllowLocalPoli'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='9.3.5'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local connection security rules'' is set to ''No'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='AllowLocalIPse'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='9.3.6'; Title='Ensure ''Windows Firewall: Public: Logging: Name'' is set to ''%SystemRoot%\System32\logfiles\firewall\publicfw.log'' (Autom'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; ValueName='LogFil'; RegType='REG_SZ'; Expected='%SystemRoot%\System32\logfiles\firewall\publicfw' }
    @{ Number='9.3.7'; Title='Ensure ''Windows Firewall: Public: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; ValueName='LogFil'; RegType='REG_DWORD'; Expected=16384 }
    @{ Number='9.3.8'; Title='Ensure ''Windows Firewall: Public: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; ValueName='LogDro'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='9.3.9'; Title='Ensure ''Windows Firewall: Public: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; GPO='Enterprise  - Firewall Non Policy Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; ValueName='LogSuc'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.1.1.1'; Title='Ensure ''Prevent enabling lock screen camera'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Personalization'; ValueName='NoLockScreenCamera'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.1.1.2'; Title='Ensure ''Prevent enabling lock screen slide show'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Personalization'; ValueName='NoLockScreenSlidesho'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.1.2.2'; Title='Ensure ''Allow users to enable online speech recognition services'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\InputPersonalization'; ValueName='AllowInputPersonalizati'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.4.1'; Title='Ensure ''Apply UAC restrictions to local accounts on network logons'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='LocalAccountTo'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.4.5'; Title='Ensure ''Enable Structured Exception Handling Overwrite Protection (SEHOP)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; ValueName='DisableExceptionChainValidation'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.4.6'; Title='Ensure ''NetBT NodeType configuration'' is set to ''Enabled: P-node (recommended)'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; ValueName='NodeType'; RegType='REG_DWORD'; Expected=2 }
    @{ Number='18.4.7'; Title='Ensure ''WDigest Authentication'' is set to ''Disabled'' (Automated)'; GPO='MDIR-1.16_18-PwdPol_Wdigest'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; ValueName='UseLogonCrede'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.5.1'; Title='Ensure ''MSS: (AutoAdminLogon) Enable Automatic Logon'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; ValueName='AutoAdminLogon'; RegType='REG_SZ'; Expected='0' }
    @{ Number='18.5.2'; Title='Ensure ''MSS: (DisableIPSourceRouting IPv6) IP source routing protection level'' is set to ''Enabled: Highest protection, s'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; ValueName='DisableIPSourceRouti'; RegType='REG_DWORD'; Expected=2 }
    @{ Number='18.5.3'; Title='Ensure ''MSS: (DisableIPSourceRouting) IP source routing protection level'' is set to ''Enabled: Highest protection, source'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; ValueName='DisableIPSourceRoutin'; RegType='REG_DWORD'; Expected=2 }
    @{ Number='18.5.5'; Title='Ensure ''MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes'' is set to ''Disabled'' (Automate'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; ValueName='EnableICMPRedirect'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.5.7'; Title='Ensure ''MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; ValueName='NoNameReleaseOnDemand'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.5.9'; Title='Ensure ''MSS: (SafeDllSearchMode) Enable Safe DLL search mode'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Session Manager'; ValueName='SafeDllSearchMode'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.5.13'; Title='Ensure ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'''; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Services\Eventlog\Security'; ValueName='WarningLevel'; RegType='REG_DWORD'; Expected=90 }
    @{ Number='18.6.7.1'; Title='Ensure ''Audit client does not support encryption'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='AuditClientDoesNotSuppo'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.7.2'; Title='Ensure ''Audit client does not support signing'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='AuditClientDoesNotSuppo'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.7.3'; Title='Ensure ''Audit insecure guest logon'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='AuditInsecureGuestLogon'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.7.4'; Title='Ensure ''Enable authentication rate limiter'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='EnableAuthRateLimiter'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.7.5'; Title='Ensure ''Enable remote mailslots'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Bowser'; ValueName='EnableMailslots'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.6.7.6'; Title='Ensure ''Mandate the minimum version of SMB'' is set to ''Enabled: 3.1.1'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='MinSmb2Dialect'; RegType='REG_DWORD'; Expected=785 }
    @{ Number='18.6.7.7'; Title='Ensure ''Set authentication rate limiter delay (milliseconds)'' is set to ''Enabled: 2000'' or more (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; ValueName='InvalidAuthenticationDe'; RegType='REG_DWORD'; Expected=2000 }
    @{ Number='18.6.8.1'; Title='Ensure ''Audit insecure guest logon'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='AuditInsecureGuest'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.8.2'; Title='Ensure ''Audit server does not support encryption'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='AuditServerDoesNot'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.8.3'; Title='Ensure ''Audit server does not support signing'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='AuditServerDoesNot'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.6.8.4'; Title='Ensure ''Enable insecure guest logons'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='AllowInsecureGuest'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.6.8.5'; Title='Ensure ''Enable remote mailslots'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\NetworkProvider'; ValueName='EnableMailslots'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.6.8.6'; Title='Ensure ''Mandate the minimum version of SMB'' is set to ''Enabled: 3.1.1'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='MinSmb2Dialect'; RegType='REG_DWORD'; Expected=785 }
    @{ Number='18.6.8.7'; Title='Ensure ''Require Encryption'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Security defaults'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='RequireEncryption'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.7.2'; Title='Ensure ''Configure Redirection Guard'' is set to ''Enabled: Redirection Guard Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Printers'; ValueName='RedirectionguardPolicy'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.7.8'; Title='Ensure ''Configure RPC packet level privacy setting for incoming connections'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Print'; ValueName='RpcAuthnLevelPrivacyEnabled'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.7.10'; Title='Ensure ''Limits print driver installation to Administrators'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; ValueName='RestrictDriverInstallationToAdministrators'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.7.11'; Title='Ensure ''Manage processing of Queue-specific files'' is set to ''Enabled: Limit Queue-specific files to Color profiles'' (Au'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Printers'; ValueName='CopyFilesPolicy'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.7.12'; Title='Ensure ''Point and Print Restrictions: When installing drivers for a new connection'' is set to ''Enabled: Show warning and'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; ValueName='NoWarningNoElevationOnInstall'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.7.13'; Title='Ensure ''Point and Print Restrictions: When updating drivers for an existing connection'' is set to ''Enabled: Show warning'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; ValueName='UpdatePromptSettings'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.4.1'; Title='Ensure ''Encryption Oracle Remediation'' is set to ''Enabled: Force Updated Clients'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parame ters'; ValueName='AllowEncryptionOracle'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.4.2'; Title='Ensure ''Remote host allows delegation of non- exportable credentials'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; ValueName='AllowProtected'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.7.2'; Title='Ensure ''Prevent device metadata retrieval from the Internet'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; ValueName='PreventDeviceMetadataFromNetwork'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.13.1'; Title='Ensure ''Boot-Start Driver Initialization Policy'' is set to ''Enabled: Good, unknown and bad but critical'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; ValueName='DriverLoadPolicy'; RegType='REG_DWORD'; Expected=3 }
    @{ Number='18.9.19.2'; Title='Ensure ''Configure registry policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FA'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; ValueName='NoBackgroundPolicy'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.19.3'; Title='Ensure ''Configure registry policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enab'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; ValueName='NoGPOListChanges'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.19.4'; Title='Ensure ''Configure security policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FA'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; ValueName='NoBackgroundPolicy'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.19.5'; Title='Ensure ''Configure security policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enab'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; ValueName='NoGPOListChanges'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.19.6'; Title='Ensure ''Continue experiences on this device'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='EnableCdp'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.19.7'; Title='Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - GPO Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='DisableBkGndGr'; RegType='REG_DWORD'; Expected='' }
    @{ Number='18.9.20.1.2'; Title='Ensure ''Turn off downloading of print drivers over HTTP'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Printers'; ValueName='DisableWebPnPDownload'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.20.1.6'; Title='Ensure ''Turn off Internet download for Web publishing and online ordering wizards'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName='NoWebService'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.25.1'; Title='Ensure ''Configure password backup directory'' is set to ''Enabled: Active Directory'' or ''Enabled: Azure Active Directory'' '; GPO='Enterprise - LAPS'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='BackupDirectory'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.25.2'; Title='Ensure ''Do not allow password expiration time longer than required by policy'' is set to ''Enabled'' (Automated)'; GPO='MDIR-1.17-LAPS'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PasswordExpirati'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.25.3'; Title='Ensure ''Enable password encryption'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='ADPasswordEncryp'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.25.4'; Title='Ensure ''Password Settings: Password Complexity'' is set to ''Enabled: Large letters + small letters + numbers + special ch'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PasswordComplexi'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='18.9.25.5'; Title='Ensure ''Password Settings: Password Length'' is set to ''Enabled: 15 or more'' (Automated)'; GPO='Enterprise - LAPS'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PasswordLength'; RegType='REG_DWORD'; Expected=15 }
    @{ Number='18.9.25.6'; Title='Ensure ''Password Settings: Password Age (Days)'' is set to ''Enabled: 30 or fewer'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PasswordAgeDays'; RegType='REG_DWORD'; Expected=30 }
    @{ Number='18.9.25.7'; Title='Ensure ''Post-authentication actions: Grace period (hours)'' is set to ''Enabled: 8 or fewer hours, but not 0'' (Automated)'; GPO='Enterprise - LAPS'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PostAuthenticati'; RegType='REG_DWORD'; Expected=8 }
    @{ Number='18.9.25.8'; Title='Ensure ''Post-authentication actions: Actions'' is set to ''Enabled: Reset the password and logoff the managed account'' or '; GPO='Enterprise - LAPS'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName='PostAuthenticati'; RegType='REG_DWORD'; Expected=3 }
    @{ Number='18.9.26.1'; Title='Ensure ''Allow Custom SSPs and APs to be loaded into LSASS'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='AllowCustomSSPsAPs'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.26.2'; Title='Ensure ''Configures LSASS to run as a protected process'' is set to ''Enabled: Enabled with UEFI Lock'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SYSTEM\CurrentControlSet\Control\Lsa'; ValueName='RunAsPPL'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.28.1'; Title='Ensure ''Block user from showing account details on sign-in'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='BlockUserFromShowingAccountDe'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.28.2'; Title='Ensure ''Do not display network selection UI'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='DontDisplayNetworkSelectionUI'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.28.3'; Title='Ensure ''Do not enumerate connected users on domain-joined computers'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='DontEnumerateConnectedUsers'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.28.4'; Title='Ensure ''Enumerate local users on domain-joined computers'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='EnumerateLocalUsers'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.28.5'; Title='Ensure ''Turn off app notifications on the lock screen'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='DisableLockScreenAppNotificat'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.28.6'; Title='Ensure ''Turn off picture password sign-in'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='BlockDomainPicturePassword'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.30.1.1'; Title='Ensure ''Block NetBIOS-based discovery for domain controller location'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Netlogon\Parameters'; ValueName='BlockNetbiosDiscovery'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.33.6.1'; Title='Ensure ''Allow network connectivity during connected-standby (on battery)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; ValueName='DCSettingIndex'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.33.6.2'; Title='Ensure ''Allow network connectivity during connected-standby (plugged in)'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; ValueName='ACSettingIndex'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.33.6.5'; Title='Ensure ''Require a password when a computer wakes (on battery)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; ValueName='DCSettingIndex'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.33.6.6'; Title='Ensure ''Require a password when a computer wakes (plugged in)'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; ValueName='ACSettingIndex'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.35.1'; Title='Ensure ''Configure Offer Remote Assistance'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='fAllowUnsolicited'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.35.2'; Title='Ensure ''Configure Solicited Remote Assistance'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='fAllowToGetHelp'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.9.36.1'; Title='Ensure ''Enable RPC Endpoint Mapper Client Authentication'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; ValueName='EnableAuthEpResolution'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.36.2'; Title='Ensure ''Restrict Unauthenticated RPC clients'' is set to ''Enabled: Authenticated'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; ValueName='RestrictRemoteClients'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.39.1'; Title='Ensure ''Configure SAM change password RPC methods policy'' is set to ''Enabled: Block all change password RPC methods'' (Au'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM'; ValueName='SamrChange'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.9.51.1.1'; Title='Ensure ''Enable Windows NTP Client'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'; ValueName='Enabled'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.5.1'; Title='Ensure ''Let Windows apps activate with voice while the system is locked'' is set to ''Enabled: Force Deny'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; ValueName='LetAppsActivateWithVoiceA'; RegType='REG_DWORD'; Expected=2 }
    @{ Number='18.10.6.1'; Title='Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='MSAOptional'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.8.1'; Title='Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Explorer'; ValueName='NoAutoplayfornonVolume'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.8.2'; Title='Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName='NoAutorun'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.8.3'; Title='Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName='NoDriveTypeA'; RegType='REG_DWORD'; Expected=255 }
    @{ Number='18.10.9.1.1'; Title='Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; ValueName='EnhancedAntiSpoofi'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.13.3'; Title='Ensure ''Turn off Microsoft consumer experiences'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; ValueName='DisableWindowsConsumerF'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.14.1'; Title='Ensure ''Require pin for pairing'' is set to ''Enabled: First Time'' OR ''Enabled: Always'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Connect'; ValueName='RequirePinForPairing'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.15.2'; Title='Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; ValueName='EnumerateAdmin'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.15.3'; Title='Ensure ''Prevent the use of security questions for local accounts'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\System'; ValueName='NoLocalPasswordResetQuestions'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.16.1'; Title='Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required dia'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='AllowTelemetry'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.16.3'; Title='Ensure ''Disable OneSettings Downloads'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='DisableOneSettingsDow'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.16.4'; Title='Ensure ''Do not show feedback notifications'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='DoNotShowFeedbackNoti'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.16.5'; Title='Ensure ''Enable OneSettings Auditing'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='EnableOneSettingsAudi'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.16.6'; Title='Ensure ''Limit Diagnostic Log Collection'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='LimitDiagnosticLogCol'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.16.7'; Title='Ensure ''Limit Dump Collection'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName='LimitDumpCollection'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.17.1'; Title='Ensure ''Download Mode'' is NOT set to ''Enabled: Internet'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DODownloadMode'; RegType='REG_DWORD'; Expected='anything' }
    @{ Number='18.10.26.1.1'; Title='Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automa'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; ValueName='Retention'; RegType='REG_SZ'; Expected='0' }
    @{ Number='18.10.26.1.2'; Title='Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; GPO='Enterprise - Logging'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; ValueName='MaxSize'; RegType='REG_DWORD'; Expected=32768 }
    @{ Number='18.10.26.2.1'; Title='Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; ValueName='Retention'; RegType='REG_SZ'; Expected='0' }
    @{ Number='18.10.26.2.2'; Title='Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater'' (Automated)'; GPO='Enterprise - Logging'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; ValueName='MaxSize'; RegType='REG_DWORD'; Expected=196608 }
    @{ Number='18.10.26.3.1'; Title='Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; ValueName='Retention'; RegType='REG_SZ'; Expected='0' }
    @{ Number='18.10.26.3.2'; Title='Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; GPO='Enterprise - Logging'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; ValueName='MaxSize'; RegType='REG_DWORD'; Expected=32768 }
    @{ Number='18.10.26.4.1'; Title='Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; ValueName='Retention'; RegType='REG_SZ'; Expected='0' }
    @{ Number='18.10.26.4.2'; Title='Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; GPO='Enterprise - Logging'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; ValueName='MaxSize'; RegType='REG_DWORD'; Expected=32768 }
    @{ Number='18.10.29.3'; Title='Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Explorer'; ValueName='NoDataExecutionPrevention'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.29.4'; Title='Ensure ''Do not apply the Mark of the Web tag to files copied from insecure sources'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Explorer'; ValueName='DisableMotWOnInsecurePathCo'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.29.5'; Title='Ensure ''Turn off heap termination on corruption'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Explorer'; ValueName='NoHeapTerminationOnCorrupti'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.29.6'; Title='Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName='PreXPSP2Shel'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.43.5.1'; Title='Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; ValueName='LocalSettingOverrideSpynetReporting'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.57.3.3.3'; Title='Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='fDisableCdm'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.57.3.9.2'; Title='Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='fEncryptRPCTraffic'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.57.3.9.3'; Title='Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='SecurityLayer'; RegType='REG_DWORD'; Expected=2 }
    @{ Number='18.10.57.3.9.4'; Title='Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (A'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='UserAuthentication'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.57.3.9.5'; Title='Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='MinEncryptionLevel'; RegType='REG_DWORD'; Expected=3 }
    @{ Number='18.10.57.3.11.1'; Title='Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'; GPO='Enterprise -RDP Hardening'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='DeleteTempDirsOnExit'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.58.1'; Title='Ensure ''Prevent downloading of enclosures'' is set to ''Enabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; ValueName='DisableEnclosureDownload'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.58.2'; Title='Ensure ''Turn on Basic feed authentication over HTTP'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKEY_LOCAL_MACHINE'; RegPath='Software\Policies\Microsoft\Internet Explorer\Feeds'; ValueName='AllowBasicAuthInClear'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.66.2'; Title='Ensure ''Turn off Automatic Download and Install of updates'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsStore'; ValueName='AutoDownload'; RegType='REG_DWORD'; Expected=4 }
    @{ Number='18.10.72.1'; Title='Ensure ''Allow widgets'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Dsh'; ValueName='AllowNewsAndInterests'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.78.1'; Title='Ensure ''Enables or disables Windows Game Recording and Broadcasting'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\GameDVR'; ValueName='AllowGameDVR'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.79.1'; Title='Ensure ''Enable ESS with Supported Peripherals'' is set to ''Enabled: 1'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics'; ValueName='EnableESSwithSupp'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.80.2'; Title='Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled'' (Aut'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; ValueName='AllowWindowsInkWorkspace'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.81.1'; Title='Ensure ''Allow user control over installs'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Installer'; ValueName='EnableUserControl'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.81.2'; Title='Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'; GPO='FCTG-Disable Windows Installer'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Installer'; ValueName='AlwaysInstallElevated'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.82.1'; Title='Ensure ''Configure the transmission of the user''s password in the content of MPR notifications sent by winlogon.'' is set '; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='EnableMPR'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.82.2'; Title='Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName='DisableAutomat'; RegType='REG_DWORD'; Expected=1 }
    @{ Number='18.10.89.1.1'; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; ValueName='AllowBasic'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.89.1.2'; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; ValueName='AllowUnencryptedTraffic'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.89.2.1'; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; ValueName='AllowBasic'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.89.2.3'; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Set Default Settings'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; ValueName='AllowUnencryptedTraffi'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.91.1'; Title='Ensure ''Allow clipboard sharing with Windows Sandbox'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Sandbox'; ValueName='AllowClipboardRedirection'; RegType='REG_DWORD'; Expected=0 }
    @{ Number='18.10.91.3'; Title='Ensure ''Allow networking in Windows Sandbox'' is set to ''Disabled'' (Automated)'; GPO='Enterprise - Misc'; Hive='HKLM'; RegPath='SOFTWARE\Policies\Microsoft\Windows\Sandbox'; ValueName='AllowNetworking'; RegType='REG_DWORD'; Expected=0 }
)

foreach ($c in $RegChecks) {
    $regPath = "$($c.Hive):\$($c.RegPath)"
    try {
        $actual = Get-ItemPropertyValue -Path $regPath -Name $c.ValueName -ErrorAction Stop
        if ($c.Expected -eq '') {
            Add-Result $c.Number $c.Title $c.GPO 'Registry' 'Exists' "$actual" 'CONFIGURED'
        } elseif ($c.RegType -eq 'REG_DWORD') {
            $status = if ([int64]"$actual" -eq [int64]"$($c.Expected)") { 'PASS' } else { 'FAIL' }
            Add-Result $c.Number $c.Title $c.GPO 'Registry' "$($c.Expected)" "$actual" $status
        } else {
            $status = if ("$actual" -eq "$($c.Expected)") { 'PASS' } else { 'FAIL' }
            Add-Result $c.Number $c.Title $c.GPO 'Registry' "$($c.Expected)" "$actual" $status
        }
    } catch {
        Add-Result $c.Number $c.Title $c.GPO 'Registry' "$($c.Expected)" 'NOT FOUND' 'MISSING' 'Key/value not present'
    }
}

# ==============================================================================
# 2/5  AUDIT POLICY  (25 checks)
# ==============================================================================
Write-Host '[2/5] Audit policy checks...' -ForegroundColor Cyan

$AuditChecks = @(
    @{ Number='17.1.1'; Title='Ensure ''Audit Credential Validation'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Credential Validation'; Expected='Success and Failure' }
    @{ Number='17.2.1'; Title='Ensure ''Audit Application Group Management'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Application Group Management'; Expected='Success and Failure' }
    @{ Number='17.2.2'; Title='Ensure ''Audit Security Group Management'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Security Group Management'; Expected='Success' }
    @{ Number='17.2.3'; Title='Ensure ''Audit User Account Management'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit User Account Management'; Expected='Success and Failure' }
    @{ Number='17.3.1'; Title='Ensure ''Audit PNP Activity'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit PNP Activity'; Expected='Success' }
    @{ Number='17.3.2'; Title='Ensure ''Audit Process Creation'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Process Creation'; Expected='Success' }
    @{ Number='17.5.1'; Title='Ensure ''Audit Account Lockout'' is set to include ''Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Account Lockout'; Expected='Failure' }
    @{ Number='17.5.2'; Title='Ensure ''Audit Group Membership'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Group Membership'; Expected='Success' }
    @{ Number='17.5.3'; Title='Ensure ''Audit Logoff'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Logoff'; Expected='Success' }
    @{ Number='17.5.4'; Title='Ensure ''Audit Logon'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Logon'; Expected='Success and Failure' }
    @{ Number='17.5.5'; Title='Ensure ''Audit Other Logon/Logoff Events'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Other Logon/Logoff Events'; Expected='Success and Failure' }
    @{ Number='17.5.6'; Title='Ensure ''Audit Special Logon'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Special Logon'; Expected='Success' }
    @{ Number='17.6.3'; Title='Ensure ''Audit Other Object Access Events'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Other Object Access Events'; Expected='Success and Failure' }
    @{ Number='17.6.4'; Title='Ensure ''Audit Removable Storage'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Removable Storage'; Expected='Success and Failure' }
    @{ Number='17.7.1'; Title='Ensure ''Audit Audit Policy Change'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Audit Policy Change'; Expected='Success' }
    @{ Number='17.7.2'; Title='Ensure ''Audit Authentication Policy Change'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Authentication Policy Change'; Expected='Success' }
    @{ Number='17.7.3'; Title='Ensure ''Audit Authorization Policy Change'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Authorization Policy Change'; Expected='Success' }
    @{ Number='17.7.4'; Title='Ensure ''Audit MPSSVC Rule-Level Policy Change'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit MPSSVC Rule- Level Policy Change'; Expected='Success and Failure' }
    @{ Number='17.7.5'; Title='Ensure ''Audit Other Policy Change Events'' is set to include ''Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Other Policy Change Events'; Expected='Failure' }
    @{ Number='17.8.1'; Title='Ensure ''Audit Sensitive Privilege Use'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Sensitive Privilege Use'; Expected='Success and Failure' }
    @{ Number='17.9.1'; Title='Ensure ''Audit IPsec Driver'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit IPsec Driver'; Expected='Success and Failure' }
    @{ Number='17.9.2'; Title='Ensure ''Audit Other System Events'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Other System Events'; Expected='Success and Failure' }
    @{ Number='17.9.3'; Title='Ensure ''Audit Security State Change'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Security State Change'; Expected='Success' }
    @{ Number='17.9.4'; Title='Ensure ''Audit Security System Extension'' is set to include ''Success'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit Security System Extension'; Expected='Success' }
    @{ Number='17.9.5'; Title='Ensure ''Audit System Integrity'' is set to ''Success and Failure'' (Automated)'; GPO='Enterprise -Audit Settings'; Subcategory='Audit System Integrity'; Expected='Success and Failure' }
)

foreach ($c in $AuditChecks) {
    $raw = & auditpol /get /subcategory:"$($c.Subcategory)" 2>$null
    if (-not $raw) {
        Add-Result $c.Number $c.Title $c.GPO 'AuditPol' $c.Expected 'NOT FOUND' 'MISSING' 'Subcategory not found'
        continue
    }
    $line = $raw | Where-Object { $_ -match [regex]::Escape($c.Subcategory) }
    if (-not $line) {
        Add-Result $c.Number $c.Title $c.GPO 'AuditPol' $c.Expected 'NOT PARSED' 'MISSING' 'Output not parsed'
        continue
    }
    $actual = ($line -split '\s{2,}')[-1].Trim()
    $pass = switch ($c.Expected) {
        'Success and Failure' { $actual -eq 'Success and Failure' }
        'Success'             { $actual -in @('Success', 'Success and Failure') }
        'Failure'             { $actual -in @('Failure', 'Success and Failure') }
        'No Auditing'         { $actual -eq 'No Auditing' }
        default               { $actual -eq $c.Expected }
    }
    Add-Result $c.Number $c.Title $c.GPO 'AuditPol' $c.Expected $actual ($(if ($pass) { 'PASS' } else { 'FAIL' }))
}

# ==============================================================================
# 3/5  SECEDIT EXPORT
# ==============================================================================
Write-Host '[3/5] Exporting local security policy...' -ForegroundColor Cyan

$seceditTmp = [System.IO.Path]::GetTempFileName() + '.inf'
& secedit /export /cfg $seceditTmp /quiet
$seceditLines = if (Test-Path $seceditTmp) { Get-Content $seceditTmp -Encoding Unicode } else { @() }

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

# ==============================================================================
# 4/5  USER RIGHTS ASSIGNMENT  (15 checks)
# ==============================================================================
Write-Host '[4/5] User rights checks...' -ForegroundColor Cyan

$UserRightChecks = @(
    @{ Number='2.2.6'; Title='Ensure ''Allow log on through Remote Desktop Services'' is set to ''Administrators, Remote Desktop Users'' (Automated)'; GPO='Enterprise - RDP Hardening'; Right='Allow log on through Remote Desktop Services'; Constant='SeRemoteInteractiveLogonRight'; Expected='Administrators, Remote Desktop Users' }
    @{ Number='2.2.10'; Title='Ensure ''Create a pagefile'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Create a pagefile'; Constant='SeCreatePagefilePrivilege'; Expected='Administrators' }
    @{ Number='2.2.11'; Title='Ensure ''Create a token object'' is set to ''No One'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Create a token object'; Constant='SeCreateTokenPrivilege'; Expected='No One' }
    @{ Number='2.2.12'; Title='Ensure ''Create global objects'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Create global objects'; Constant='SeCreateGlobalPrivilege'; Expected='Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' }
    @{ Number='2.2.13'; Title='Ensure ''Create permanent shared objects'' is set to ''No One'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Create permanent shared objects'; Constant='SeCreatePermanentPrivilege'; Expected='No One' }
    @{ Number='2.2.14'; Title='Ensure ''Create symbolic links'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Create symbolic links'; Constant='SeCreateSymbolicLinkPrivilege'; Expected='' }
    @{ Number='2.2.25'; Title='Ensure ''Increase scheduling priority'' is set to ''Administrators, Window Manager\Window Manager Group'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Increase scheduling priority'; Constant='SeIncreaseBasePriorityPrivilege'; Expected='Administrators, Window Manager\Window Manager Group' }
    @{ Number='2.2.27'; Title='Ensure ''Lock pages in memory'' is set to ''No One'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Lock pages in memory'; Constant='SeLockMemoryPrivilege'; Expected='No One' }
    @{ Number='2.2.30'; Title='Ensure ''Manage auditing and security log'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Manage auditing and security log'; Constant='SeSecurityPrivilege'; Expected='Administrators' }
    @{ Number='2.2.31'; Title='Ensure ''Modify an object label'' is set to ''No One'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Modify an object label'; Constant=''; Expected='No One' }
    @{ Number='2.2.32'; Title='Ensure ''Modify firmware environment values'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Modify firmware environment values'; Constant='SeSystemEnvironmentPrivilege'; Expected='Administrators' }
    @{ Number='2.2.33'; Title='Ensure ''Perform volume maintenance tasks'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Perform volume maintenance tasks'; Constant=''; Expected='Administrators' }
    @{ Number='2.2.34'; Title='Ensure ''Profile single process'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Profile single process'; Constant='SeProfileSingleProcessPrivilege'; Expected='Administrators' }
    @{ Number='2.2.35'; Title='Ensure ''Profile system performance'' is set to ''Administrators, NT SERVICE\WdiServiceHost'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Profile system performance'; Constant='SeSystemProfilePrivilege'; Expected='Administrators, NT SERVICE\WdiServiceHost' }
    @{ Number='2.2.39'; Title='Ensure ''Take ownership of files or other objects'' is set to ''Administrators'' (Automated)'; GPO='Enterprise - Set Default Settings'; Right='Take ownership of files or other objects'; Constant='SeTakeOwnershipPrivilege'; Expected='Administrators' }
)

foreach ($c in $UserRightChecks) {
    if (-not $c.Constant) {
        Add-Result $c.Number $c.Title $c.GPO 'UserRight' $c.Expected '' 'MANUAL' "No secedit constant for: $($c.Right)"
        continue
    }
    $raw = Get-SeceditValue $seceditLines 'Privilege Rights' $c.Constant
    $members = if ($null -eq $raw -or $raw.Trim() -eq '') { @() }
               else { $raw -split ',' | ForEach-Object { Resolve-AccountSid $_.Trim() } }
    $actual = if ($members.Count -eq 0) { '(empty)' } else { $members -join ', ' }

    if ($c.Expected -ieq 'No One') {
        $status = if ($members.Count -eq 0) { 'PASS' } else { 'FAIL' }
    } else {
        $exp_list = $c.Expected -split ',' | ForEach-Object { $_.Trim() }
        $missing  = @($exp_list | Where-Object { $ea=$_; -not ($members | Where-Object { $_ -like "*$ea*" -or $ea -like "*$_*" }) })
        $extra    = @($members  | Where-Object { $m=$_;  -not ($exp_list  | Where-Object { $m -like "*$_*" -or $_ -like "*$m*"  }) })
        $status   = if ($missing.Count -eq 0 -and $extra.Count -eq 0) { 'PASS' }
                    elseif ($missing.Count -gt 0) { 'FAIL' }
                    else { 'REVIEW' }
    }
    Add-Result $c.Number $c.Title $c.GPO 'UserRight' $c.Expected $actual $status
}

# ==============================================================================
# 5/5  ACCOUNT POLICY  (4 checks)
# ==============================================================================
Write-Host '[5/5] Account policy checks...' -ForegroundColor Cyan

$AcctChecks = @(
    @{ Number='1.1.2'; Title='Ensure ''Maximum password age'' is set to ''365 or fewer days, but not 0'' (Automated)'; GPO=''; Setting='Maximum password age'; SeceditKey='MaximumPasswordAge'; Expected='365 or fewer days, but not 0' }
    @{ Number='1.1.7'; Title='Ensure ''Store passwords using reversible encryption'' is set to ''Disabled'' (Automated)'; GPO=''; Setting='Store passwords using reversible encryption'; SeceditKey='ClearTextPassword'; Expected='Disabled' }
    @{ Number='1.2.1'; Title='Ensure ''Account lockout duration'' is set to ''15 or more minute(s)'' (Automated)'; GPO=''; Setting='Account lockout duration'; SeceditKey='LockoutDuration'; Expected='15 or more minute(s)' }
    @{ Number='1.2.4'; Title='Ensure ''Reset account lockout counter after'' is set to ''15 or more minute(s)'' (Automated)'; GPO=''; Setting='Reset account lockout counter after'; SeceditKey='ResetLockoutCount'; Expected='15 or more minute(s)' }
)

foreach ($c in $AcctChecks) {
    $val = Get-SeceditValue $seceditLines 'System Access' $c.SeceditKey
    if ($null -eq $val) { Add-Result $c.Number $c.Title $c.GPO 'AccountPolicy' $c.Expected 'NOT FOUND' 'MISSING'; continue }
    $n = [int]$val
    $status = if     ($c.Expected -match '(\d+) or fewer .+, but not 0') { if ($n -gt 0 -and $n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
              elseif ($c.Expected -match '(\d+) or fewer')               { if ($n -le [int]$Matches[1]) {'PASS'} else {'FAIL'} }
              elseif ($c.Expected -match '(\d+) or more')                { if ($n -ge [int]$Matches[1]) {'PASS'} else {'FAIL'} }
              elseif ($c.Expected -match 'Disabled')                      { if ($n -eq 0) {'PASS'} else {'FAIL'} }
              elseif ($c.Expected -match 'Enabled')                       { if ($n -eq 1) {'PASS'} else {'FAIL'} }
              else                                                         { 'REVIEW' }
    Add-Result $c.Number $c.Title $c.GPO 'AccountPolicy' $c.Expected $n $status
}

# Security Options
Add-Result '2.3.10.1' 'Ensure ''Network access: Allow anonymous SID/Name translation'' is set to ''Disabled'' (Automated)' 'Enterprise - Set Default Settings' 'SecurityOption' 'Disabled' '' 'MANUAL' 'Verify in Local Security Policy'
Add-Result '2.3.11.6' 'Ensure ''Network security: Force logoff when logon hours expire'' is set to ''Enabled'' (Manual)' 'Enterprise - Set Default Settings' 'SecurityOption' 'Enabled. Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security' '' 'MANUAL' 'Verify in Local Security Policy'

Remove-Item $seceditTmp -Force -ErrorAction SilentlyContinue

# ==============================================================================
# RESULTS
# ==============================================================================
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