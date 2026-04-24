<#
.SYNOPSIS
    Audits Active Directory OU permissions and generates a two-tab HTML report.

.DESCRIPTION
    Reads the DACL on every OU via Get-Acl on the AD: PSDrive, resolves ObjectType
    and InheritedObjectType GUIDs to friendly names, classifies dangerous ACEs
    (GenericAll, WriteDACL, WriteOwner, GenericWrite, AllExtendedRights, DCSync,
    ForceChangePassword, Shadow Credentials, RBCD, etc.), and outputs a color-coded
    HTML report with:
      Tab 1 — All non-inherited explicit ACEs across every OU
      Tab 2 — Dangerous permissions with risk level and description

.PARAMETER OutputPath
    Path for the HTML report. Defaults to .\OUPermissions_Report.html

.PARAMETER SearchBase
    DN to limit scope. Defaults to the domain root.

.PARAMETER IncludeInherited
    Include inherited ACEs (excluded by default to reduce noise).

.PARAMETER ExcludeDefaultPrincipals
    Suppress well-known trustees: SYSTEM, Domain Admins, Enterprise Admins,
    Administrators, Enterprise Domain Controllers, Creator Owner.

.EXAMPLE
    .\Get-OUPermissions.ps1
    .\Get-OUPermissions.ps1 -IncludeInherited
    .\Get-OUPermissions.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com" -ExcludeDefaultPrincipals
    .\Get-OUPermissions.ps1 -OutputPath "C:\Reports\OUPerms.html" -IncludeInherited

.NOTES
    Requires: ActiveDirectory module (RSAT) and Read access to AD objects.
    Run as Domain Admin or equivalent to ensure full ACL visibility.
#>

[CmdletBinding()]
param(
    [string]$OutputPath             = ".\OUPermissions_Report.html",
    [string]$SearchBase             = "",
    [switch]$IncludeInherited,
    [switch]$ExcludeDefaultPrincipals
)

#region ── Prerequisites ──────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a DC."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop
Add-Type -AssemblyName System.Web

# Ensure the AD: PSDrive is available
if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
    Write-Error "AD: PSDrive not available. Ensure ActiveDirectory module loaded correctly."
    exit 1
}
#endregion

#region ── GUID Resolution Map ───────────────────────────────────────────────
Write-Host "Building GUID resolution map from schema and extended rights..." -ForegroundColor Cyan

$rootDSE     = Get-ADRootDSE
$schemaNC    = $rootDSE.schemaNamingContext
$configNC    = $rootDSE.configurationNamingContext
$guidMap     = @{}

# Schema attributes and classes → schemaIDGUID
try {
    Get-ADObject -SearchBase $schemaNC -LDAPFilter '(schemaIDGUID=*)' `
                 -Properties name, schemaIDGUID -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $g = ([System.Guid]$_.schemaIDGUID).ToString().ToLower()
            if ($g -ne '00000000-0000-0000-0000-000000000000') {
                $guidMap[$g] = $_.name
            }
        } catch {}
    }
} catch {
    Write-Warning "Could not fully enumerate schema GUIDs: $_"
}

# Extended rights (controlAccessRight) → rightsGuid
try {
    Get-ADObject -SearchBase $configNC -LDAPFilter '(rightsGuid=*)' `
                 -Properties name, rightsGuid -ErrorAction SilentlyContinue |
    ForEach-Object {
        if ($_.rightsGuid) {
            $guidMap[$_.rightsGuid.ToLower()] = $_.name
        }
    }
} catch {
    Write-Warning "Could not fully enumerate extended right GUIDs: $_"
}

Write-Host "  → Resolved $($guidMap.Count) GUIDs." -ForegroundColor Gray

function Resolve-Guid {
    param([System.Guid]$guid)
    if ($guid -eq [System.Guid]::Empty) { return "All" }
    $key = $guid.ToString().ToLower()
    if ($guidMap.ContainsKey($key)) { return $guidMap[$key] }
    return $guid.ToString()
}
#endregion

#region ── Dangerous Permission Definitions ──────────────────────────────────
# Rights flags considered dangerous (Allow ACEs only)
$dangerousRightsMask =
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll    -bor
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl     -bor
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner    -bor
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite

# Extended right GUIDs that are dangerous
$dangerousExtRights = @{
    '00299570-246d-11d0-a768-00aa006e0529' = @{ Name='User-Force-Change-Password'; Level='High';     Desc='Reset passwords without knowing the current password.' }
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = @{ Name='DS-Replication-Get-Changes';         Level='Critical'; Desc='Replicate directory changes — part of DCSync attack to dump password hashes.' }
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = @{ Name='DS-Replication-Get-Changes-All';     Level='Critical'; Desc='Replicate all directory changes including secrets — enables full DCSync attack.' }
    '89e95b76-444d-4c62-991a-0facbeda640c' = @{ Name='DS-Replication-Get-Changes-In-Filtered-Set'; Level='Critical'; Desc='Replicate filtered set of changes — another DCSync variant.' }
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' = @{ Name='Reanimate-Tombstone';   Level='Medium';   Desc='Restore deleted objects. Can be used to resurface old, potentially misconfigured accounts.' }
    '0488629f-a0f7-11d1-9c27-00c04fc2dcd2' = @{ Name='Receive-As';            Level='High';     Desc='Read another mailbox as if the owner — allows reading all mail in affected mailboxes.' }
    'ab721a56-1e2f-11d0-9819-00aa0040529b' = @{ Name='Send-As';               Level='Medium';   Desc='Send email on behalf of another account without delegation.' }
}

# WriteProperty GUIDs that are dangerous
$dangerousWriteProp = @{
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = @{ Name='member';                              Level='High';     Desc='Add or remove group members — can be used to gain group privileges.' }
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = @{ Name='msDS-KeyCredentialLink';              Level='Critical'; Desc='Shadow Credentials attack — add a certificate-based credential to any account.' }
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = @{ Name='msDS-AllowedToActOnBehalfOfOtherIdentity'; Level='Critical'; Desc='Resource-Based Constrained Delegation (RBCD) — enables full impersonation of any user to this host.' }
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = @{ Name='servicePrincipalName';                Level='High';     Desc='Set SPNs on an account — enables Kerberoasting attacks.' }
    '77b5b886-944a-11d1-aebd-0000f80367c1' = @{ Name='pwdLastSet';                          Level='Medium';   Desc='Modify password last-set timestamp — can bypass password expiry policies.' }
    '28630ebf-41d5-11d1-a9c1-0000f80367c1' = @{ Name='userAccountControl';                  Level='High';     Desc='Modify account flags (e.g. disable pre-auth, mark as trusted for delegation).' }
    'bf967953-0de6-11d0-a285-00aa003049e2' = @{ Name='scriptPath (logon script)';           Level='Medium';   Desc='Set the logon script path — runs arbitrary code at next user logon.' }
}

# Well-known default trustees to optionally exclude
$defaultTrustees = @(
    'NT AUTHORITY\SYSTEM','BUILTIN\Administrators',
    'CREATOR OWNER','NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    'NT AUTHORITY\Authenticated Users' # context-dependent but usually expected
)

function Get-DangerousInfo {
    param([System.DirectoryServices.ActiveDirectoryAccessRule]$ace)

    if ($ace.AccessControlType -ne 'Allow') { return $null }

    $rights     = $ace.ActiveDirectoryRights
    $objType    = $ace.ObjectType.ToString().ToLower()
    $rightsName = $rights.ToString()

    # GenericAll (0xF01FF) is a multi-bit composite — must test all bits present,
    # not just -band (which is truthy for any partial overlap like CreateChild/DeleteChild).
    $gaFlag = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    if (($rights -band $gaFlag) -eq $gaFlag) {
        return @{ Level='Critical'; Reason='GenericAll'; Desc='Full control of the OU and all objects within it. Can read/write all attributes, change permissions, and take ownership.' }
    }

    # WriteDACL — single bit (0x40000), plain -band is fine
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) {
        return @{ Level='Critical'; Reason='WriteDACL'; Desc='Can modify the access control list, allowing the trustee to grant themselves any additional right including GenericAll.' }
    }

    # WriteOwner — single bit (0x80000), plain -band is fine
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) {
        return @{ Level='Critical'; Reason='WriteOwner'; Desc='Can take ownership of the OU. Owners can grant themselves full control regardless of the DACL.' }
    }

    # GenericWrite (0x20028 = ReadControl|WriteProperty|Self) is also multi-bit —
    # WriteProperty alone would satisfy a plain -band check.
    $gwFlag = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
    if (($rights -band $gwFlag) -eq $gwFlag) {
        return @{ Level='High'; Reason='GenericWrite'; Desc='Write access to all non-protected attributes. Can modify logon scripts, SPNs, group memberships, and more.' }
    }

    # ExtendedRight — check for AllExtendedRights or specific dangerous ones
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        if ($ace.ObjectType -eq [System.Guid]::Empty) {
            return @{ Level='High'; Reason='AllExtendedRights'; Desc='Access to all extended rights on this OU, potentially including ForceChangePassword and replication rights on child objects.' }
        }
        if ($dangerousExtRights.ContainsKey($objType)) {
            $info = $dangerousExtRights[$objType]
            return @{ Level=$info.Level; Reason=$info.Name; Desc=$info.Desc }
        }
    }

    # WriteProperty — check for specific dangerous attribute GUIDs
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
        if ($ace.ObjectType -eq [System.Guid]::Empty) {
            return @{ Level='High'; Reason='WriteProperty (All)'; Desc='Can write to any attribute on objects in this OU, enabling manipulation of group membership, SPNs, logon scripts, and more.' }
        }
        if ($dangerousWriteProp.ContainsKey($objType)) {
            $info = $dangerousWriteProp[$objType]
            return @{ Level=$info.Level; Reason="WriteProperty: $($info.Name)"; Desc=$info.Desc }
        }
    }

    return $null
}
#endregion

#region ── Collect OU ACLs ───────────────────────────────────────────────────
$domain     = Get-ADDomain
$domainDN   = $domain.DistinguishedName
$domainName = $domain.DNSRoot
$base       = if ($SearchBase) { $SearchBase } else { $domainDN }
$runTime    = Get-Date

# Resolve default principal SIDs to exclude dynamically
$excludeSids = @()
if ($ExcludeDefaultPrincipals) {
    $wellKnownGroups = @('Domain Admins','Enterprise Admins','Schema Admins')
    foreach ($grpName in $wellKnownGroups) {
        try {
            $sid = (Get-ADGroup $grpName -ErrorAction SilentlyContinue).SID.Value
            if ($sid) { $excludeSids += $sid }
        } catch {}
    }
}

Write-Host "Collecting OUs under: $base" -ForegroundColor Cyan
$allOUs = @(Get-ADOrganizationalUnit -Filter * -SearchBase $base -Properties DistinguishedName, Name)
$totalOUs = $allOUs.Count
Write-Host "  → Found $totalOUs OUs. Reading ACLs..." -ForegroundColor Gray

$allAces      = [System.Collections.Generic.List[PSObject]]::new()
$dangerousAces= [System.Collections.Generic.List[PSObject]]::new()
$current      = 0
$errCount     = 0

foreach ($ou in $allOUs | Sort-Object DistinguishedName) {
    $current++
    Write-Progress -Activity "Reading OU ACLs" `
                   -Status "$current of $totalOUs — $($ou.Name)" `
                   -PercentComplete (($current / $totalOUs) * 100)

    try {
        $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction Stop
    } catch {
        $errCount++
        Write-Warning "Could not read ACL for: $($ou.DistinguishedName)"
        continue
    }

    foreach ($ace in $acl.Access) {
        # Skip inherited unless requested
        if ($ace.IsInherited -and -not $IncludeInherited) { continue }

        $identity = $ace.IdentityReference.ToString()

        # Skip default principals if requested
        if ($ExcludeDefaultPrincipals) {
            $skip = $false
            foreach ($def in $defaultTrustees) {
                if ($identity -like "*$def*") { $skip = $true; break }
            }
            if (-not $skip -and $excludeSids.Count -gt 0) {
                try {
                    $sidStr = (New-Object System.Security.Principal.NTAccount($identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($excludeSids -contains $sidStr) { $skip = $true }
                } catch {}
            }
            if ($skip) { continue }
        }

        $objTypeResolved      = Resolve-Guid $ace.ObjectType
        $inheritTypeResolved  = Resolve-Guid $ace.InheritedObjectType
        $rightsStr            = $ace.ActiveDirectoryRights.ToString()
        $dangerInfo           = Get-DangerousInfo -ace $ace

        $entry = [PSCustomObject]@{
            OUName            = $ou.Name
            OUDN              = $ou.DistinguishedName
            Identity          = $identity
            Rights            = $rightsStr
            AccessType        = $ace.AccessControlType.ToString()
            Inherited         = $ace.IsInherited
            InheritanceType   = $ace.InheritanceType.ToString()
            ObjectType        = $objTypeResolved
            InheritedObjType  = $inheritTypeResolved
            IsDangerous       = ($dangerInfo -ne $null)
            DangerLevel       = if ($dangerInfo) { $dangerInfo.Level }  else { '' }
            DangerReason      = if ($dangerInfo) { $dangerInfo.Reason } else { '' }
            DangerDesc        = if ($dangerInfo) { $dangerInfo.Desc }   else { '' }
        }

        $allAces.Add($entry)
        if ($dangerInfo) { $dangerousAces.Add($entry) }
    }
}

Write-Progress -Activity "Reading OU ACLs" -Completed

$criticalCount = ($dangerousAces | Where-Object DangerLevel -eq 'Critical').Count
$highCount     = ($dangerousAces | Where-Object DangerLevel -eq 'High').Count
$mediumCount   = ($dangerousAces | Where-Object DangerLevel -eq 'Medium').Count

Write-Host "Done. $($allAces.Count) ACEs collected, $($dangerousAces.Count) flagged as dangerous." -ForegroundColor Green
#endregion

#region ── Build HTML ────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Web

# Build compact data objects for JS — HTML-encode strings here so innerHTML is safe
function New-AllDataRow {
    param([PSObject]$e)
    [ordered]@{
        n   = [System.Web.HttpUtility]::HtmlEncode($e.OUName)
        dn  = [System.Web.HttpUtility]::HtmlEncode($e.OUDN)
        id  = [System.Web.HttpUtility]::HtmlEncode($e.Identity)
        r   = [System.Web.HttpUtility]::HtmlEncode($e.Rights)
        a   = $e.AccessType
        inh = [bool]$e.Inherited
        it  = $e.InheritanceType
        ot  = [System.Web.HttpUtility]::HtmlEncode($e.ObjectType)
        iot = [System.Web.HttpUtility]::HtmlEncode($e.InheritedObjType)
        d   = [bool]$e.IsDangerous
        k   = $e.OUDN.ToLower()
    }
}

function New-DangDataRow {
    param([PSObject]$e)
    [ordered]@{
        n   = [System.Web.HttpUtility]::HtmlEncode($e.OUName)
        dn  = [System.Web.HttpUtility]::HtmlEncode($e.OUDN)
        id  = [System.Web.HttpUtility]::HtmlEncode($e.Identity)
        r   = [System.Web.HttpUtility]::HtmlEncode($e.Rights)
        lv  = $e.DangerLevel
        rs  = [System.Web.HttpUtility]::HtmlEncode($e.DangerReason)
        ds  = [System.Web.HttpUtility]::HtmlEncode($e.DangerDesc)
        a   = $e.AccessType
        inh = [bool]$e.Inherited
        ot  = [System.Web.HttpUtility]::HtmlEncode($e.ObjectType)
        k   = $e.OUDN.ToLower()
    }
}

# PS5-safe JSON array serialisation — ConvertTo-Json drops the array wrapper for single items
function ConvertTo-SafeJsonArray {
    param([array]$Items)
    if (-not $Items -or $Items.Count -eq 0) { return '[]' }
    $parts = $Items | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 3 }
    return '[' + ($parts -join ',') + ']'
}

$allDataRows  = @($allAces | ForEach-Object { New-AllDataRow $_ })
$dangDataRows = @($dangerousAces |
    Sort-Object { switch($_.DangerLevel){'Critical'{0}'High'{1}default{2}} }, OUDN |
    ForEach-Object { New-DangDataRow $_ })

$jsonAll  = ConvertTo-SafeJsonArray $allDataRows
$jsonDang = ConvertTo-SafeJsonArray $dangDataRows
# Prevent </script> injection (belt-and-suspenders; data is already HTML-encoded)
$jsonAll  = $jsonAll  -replace '</script>', '<\/script>'
$jsonDang = $jsonDang -replace '</script>', '<\/script>'

# Build OU list for tree view — one entry per OU with pre-computed ACE counts
$aceByOU  = @{}
$dangByOU = @{}
foreach ($ace in $allAces)       { $k = $ace.OUDN.ToLower(); $aceByOU[$k]  = ($aceByOU[$k]  -as [int]) + 1 }
foreach ($ace in $dangerousAces) { $k = $ace.OUDN.ToLower(); $dangByOU[$k] = ($dangByOU[$k] -as [int]) + 1 }
$ouListItems = @($allOUs | Sort-Object DistinguishedName | ForEach-Object {
    $k = $_.DistinguishedName.ToLower()
    [ordered]@{
        n  = [System.Web.HttpUtility]::HtmlEncode($_.Name)
        dn = $k
        ac = if ($aceByOU.ContainsKey($k))  { $aceByOU[$k]  } else { 0 }
        dc = if ($dangByOU.ContainsKey($k)) { $dangByOU[$k] } else { 0 }
    }
})
$jsonOuList = ConvertTo-SafeJsonArray $ouListItems
$jsonOuList = $jsonOuList -replace '</script>', '<\/script>'

$inhNote = if ($IncludeInherited) { "Inherited ACEs: <strong>included</strong>" } else { "Inherited ACEs: <strong>excluded</strong> (use -IncludeInherited to show)" }
$defNote = if ($ExcludeDefaultPrincipals) { "Default trustees: <strong>hidden</strong>" } else { "" }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OU Permissions Report — $domainName</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body   { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: #1a1a2e; }

  /* ── Header ── */
  header { background: #1a237e; color: #fff; padding: 26px 40px 20px; }
  header h1 { font-size: 1.55rem; font-weight: 600; }
  header p  { font-size: 0.82rem; opacity: .72; margin-top: 5px; }

  /* ── Summary bar ── */
  .summary-bar {
    display: flex; gap: 0; flex-wrap: wrap; align-items: stretch;
    background: #fff; border-bottom: 1px solid #e0e0e0;
  }
  .stat {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    padding: 14px 28px; border-right: 1px solid #e0e0e0; min-width: 120px;
  }
  .stat:last-child { border-right: none; margin-left: auto; align-items: flex-end; padding-right: 40px; }
  .stat-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: .07em; color: #777; }
  .stat-value { font-size: 1.5rem; font-weight: 700; }
  .v-blue   { color: #1a237e; }
  .v-crit   { color: #b71c1c; }
  .v-high   { color: #e65100; }
  .v-medium { color: #f57f17; }
  .v-green  { color: #2e7d32; }

  /* ── Tabs ── */
  .tab-bar {
    display: flex; align-items: flex-end; gap: 0;
    background: #283593; padding: 0 40px;
  }
  .tab-btn {
    background: none; border: none; cursor: pointer;
    color: rgba(255,255,255,.6); font-size: 0.88rem; font-weight: 600;
    padding: 12px 22px; border-bottom: 3px solid transparent;
    transition: all .15s; display: flex; align-items: center; gap: 8px;
  }
  .tab-btn:hover  { color: #fff; }
  .tab-btn.active { color: #fff; border-bottom-color: #ffcc02; }
  .tab-count {
    background: rgba(255,255,255,.2); border-radius: 999px;
    padding: 1px 8px; font-size: 0.72rem;
  }
  .tab-count.danger-count { background: #c62828; }

  /* ── Filter bar ── */
  .filter-bar {
    display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
    padding: 12px 40px; background: #e8eaf6; border-bottom: 1px solid #c5cae9;
  }
  .filter-bar label { font-size: 0.75rem; font-weight: 700; color: #283593; white-space: nowrap; }
  .f-btn {
    cursor: pointer; border: 1.5px solid #9fa8da; background: #fff;
    border-radius: 999px; padding: 3px 13px; font-size: 0.75rem;
    color: #283593; font-weight: 600; transition: all .15s;
  }
  .f-btn:hover, .f-btn.active { background: #283593; color: #fff; border-color: #283593; }
  .f-sep { color: #bdbdbd; }
  .search-input {
    margin-left: auto; padding: 5px 12px; border: 1.5px solid #9fa8da;
    border-radius: 6px; font-size: 0.82rem; min-width: 220px; outline: none;
  }
  .search-input:focus { border-color: #1a237e; }

  /* ── Danger filter bar ── */
  .danger-filter-bar {
    display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
    padding: 12px 40px; background: #ffebee; border-bottom: 1px solid #ef9a9a;
  }
  .danger-filter-bar label { font-size: 0.75rem; font-weight: 700; color: #b71c1c; }
  .df-btn {
    cursor: pointer; border: 1.5px solid #ef9a9a; background: #fff;
    border-radius: 999px; padding: 3px 13px; font-size: 0.75rem;
    color: #b71c1c; font-weight: 600; transition: all .15s;
  }
  .df-btn:hover, .df-btn.active { background: #b71c1c; color: #fff; border-color: #b71c1c; }
  .d-search {
    margin-left: auto; padding: 5px 12px; border: 1.5px solid #ef9a9a;
    border-radius: 6px; font-size: 0.82rem; min-width: 220px; outline: none;
  }
  .d-search:focus { border-color: #b71c1c; }

  /* ── Main ── */
  main { padding: 24px 40px; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* ── Warning callout ── */
  .callout {
    padding: 14px 18px; border-radius: 8px; margin-bottom: 18px;
    font-size: 0.82rem; display: flex; gap: 12px; align-items: flex-start;
  }
  .callout-warn { background: #fff8e1; border-left: 4px solid #ffa000; color: #5d4037; }
  .callout-info { background: #e3f2fd; border-left: 4px solid #1565c0; color: #1a237e; }
  .callout-icon { font-size: 1.2rem; flex-shrink: 0; }

  /* ── Card ── */
  .card {
    background: #fff; border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.10); overflow: hidden;
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 13px 18px; border-bottom: 1px solid #e0e0e0;
  }
  .card-header h2 { font-size: 0.95rem; font-weight: 600; }
  .row-counter { font-size: 0.78rem; color: #777; }

  /* ── Table ── */
  .tbl-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.835rem; }
  thead th {
    background: #e8eaf6; color: #283593;
    text-align: left; padding: 9px 12px;
    font-size: 0.70rem; text-transform: uppercase; letter-spacing: .05em;
    white-space: nowrap; position: sticky; top: 0; z-index: 2;
    cursor: pointer; user-select: none;
  }
  thead th:hover { background: #c5cae9; }
  thead th::after { content: ' ⇅'; opacity: .3; font-size: .65rem; }
  thead th.asc::after  { content: ' ▲'; opacity: 1; }
  thead th.desc::after { content: ' ▼'; opacity: 1; }

  /* Danger table header */
  .danger-table thead th { background: #ffcdd2; color: #b71c1c; }
  .danger-table thead th:hover { background: #ef9a9a; }

  tbody tr { border-bottom: 1px solid #f3f3f3; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #f5f7ff; }
  .danger-table tbody tr:hover { background: #fff5f5; }
  td { padding: 8px 12px; vertical-align: top; }

  .ou-name   { display: block; font-weight: 600; }
  .dn-text   { display: block; font-size: 0.70rem; color: #999; font-family: 'Consolas',monospace; word-break: break-all; margin-top: 2px; }
  .id-cell   { font-size: 0.82rem; white-space: nowrap; }
  .rights-cell { font-size: 0.75rem; color: #444; font-family: 'Consolas',monospace; max-width: 260px; word-break: break-word; }
  .desc-text { font-size: 0.75rem; color: #666; margin-top: 3px; display: block; }
  .none      { text-align: center; padding: 40px; color: #999; font-style: italic; }

  /* ── Badges ── */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 0.70rem; font-weight: 700; white-space: nowrap;
  }
  .acc-allow  { background: #e8f5e9; color: #1b5e20; border: 1px solid #a5d6a7; }
  .acc-deny   { background: #fce4ec; color: #880e4f; border: 1px solid #f48fb1; }
  .inh-yes    { background: #fff3e0; color: #e65100; border: 1px solid #ffcc02; }
  .inh-no     { background: #f3e5f5; color: #4a148c; border: 1px solid #ce93d8; }
  .lvl-crit   { background: #b71c1c; color: #fff; }
  .lvl-high   { background: #e65100; color: #fff; }
  .lvl-med    { background: #f57f17; color: #fff; }
  .danger-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
  .dot-crit { background: #b71c1c; }
  .dot-high { background: #e65100; }
  .dot-med  { background: #f57f17; }

  /* ── Pager ── */
  .pager {
    display: flex; align-items: center; gap: 10px; padding: 10px 18px;
    border-top: 1px solid #e0e0e0; background: #fafafa; min-height: 44px;
  }
  .pg-btn {
    cursor: pointer; border: 1.5px solid #9fa8da; background: #fff;
    border-radius: 6px; padding: 4px 14px; font-size: 0.80rem;
    color: #283593; font-weight: 600; transition: all .15s;
  }
  .pg-btn:hover:not(:disabled) { background: #283593; color: #fff; border-color: #283593; }
  .pg-btn:disabled { opacity: 0.4; cursor: default; }
  .pg-info { font-size: 0.80rem; color: #666; }
  .pg-jump { width: 52px; padding: 3px 6px; border: 1.5px solid #9fa8da; border-radius: 6px; font-size: 0.80rem; text-align: center; }

  /* ── Tip ── */
  .tip {
    margin-top: 20px; padding: 13px 17px;
    background: #fffde7; border-left: 4px solid #f9a825;
    border-radius: 6px; font-size: 0.80rem; color: #555; line-height: 1.7;
  }
  .tip code { font-family: monospace; background: #fff8e1; padding: 1px 5px; border-radius: 3px; }

  /* ── OU Tree layout ── */
  .tree-layout {
    display: flex; height: calc(100vh - 210px); min-height: 480px; overflow: hidden;
  }
  .tree-pane {
    width: 380px; min-width: 220px; overflow-y: auto; overflow-x: hidden;
    border-right: 2px solid #c5cae9; background: #f8f9ff;
    padding: 8px 0; flex-shrink: 0; resize: horizontal;
  }
  .tree-node { user-select: none; }
  .tree-row {
    display: flex; align-items: center; gap: 3px; cursor: pointer;
    padding: 4px 8px 4px 0; border-radius: 4px; margin: 1px 4px;
    font-size: 0.83rem; white-space: nowrap;
  }
  .tree-row:hover { background: #e8eaf6; }
  .tree-row.selected { background: #283593; color: #fff; }
  .tree-row.selected .tree-ace  { background: rgba(255,255,255,.18); color: #fff; border-color: transparent; }
  .tree-row.selected .tree-dang { background: rgba(255,255,255,.18); color: #ffe082; border-color: transparent; }
  .tree-toggle {
    width: 18px; min-width: 18px; background: none; border: none; cursor: pointer;
    font-size: 0.58rem; color: inherit; padding: 0; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
  }
  .tree-toggle-leaf { width: 18px; min-width: 18px; display: inline-block; flex-shrink: 0; }
  .tree-folder { font-size: 0.9rem; flex-shrink: 0; }
  .tree-label  { flex: 1; overflow: hidden; text-overflow: ellipsis; }
  .tree-ace  {
    font-size: 0.65rem; font-weight: 700; padding: 1px 5px; border-radius: 999px;
    background: #e8eaf6; color: #283593; border: 1px solid #9fa8da; white-space: nowrap; flex-shrink: 0;
  }
  .tree-ace-zero { opacity: 0.35; }
  .tree-dang {
    font-size: 0.65rem; font-weight: 700; padding: 1px 5px; border-radius: 999px;
    background: #ffcdd2; color: #b71c1c; border: 1px solid #ef9a9a; white-space: nowrap; flex-shrink: 0;
  }
  .tree-empty { padding: 28px; text-align: center; color: #999; font-style: italic; font-size: 0.85rem; }

  /* ── Tree detail pane ── */
  .detail-pane { flex: 1; overflow-y: auto; background: #fff; display: flex; flex-direction: column; }
  .detail-placeholder {
    flex: 1; display: flex; align-items: center; justify-content: center;
    color: #bbb; font-size: 0.95rem; font-style: italic; padding: 40px;
  }
  .detail-header {
    background: #e8eaf6; padding: 14px 20px 10px; border-bottom: 1px solid #c5cae9;
    position: sticky; top: 0; z-index: 1;
  }
  .detail-ou-name { font-size: 1.05rem; font-weight: 700; color: #1a237e; }
  .detail-ou-dn   { font-size: 0.70rem; color: #777; font-family: 'Consolas',monospace; margin-top: 3px; word-break: break-all; }
  .detail-badges  { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
  .stat-chip {
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 0.72rem; font-weight: 700; background: #c5cae9; color: #1a237e; border: 1px solid #9fa8da;
  }
  .chip-dang { background: #ffcdd2; color: #b71c1c; border-color: #ef9a9a; }
  .detail-pane-body { padding: 14px 18px; }
  .detail-none { padding: 28px 20px; color: #999; font-style: italic; font-size: 0.85rem; }
  .detail-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  .detail-table thead th {
    background: #e8eaf6; color: #283593; text-align: left; padding: 8px 11px;
    font-size: 0.70rem; text-transform: uppercase; letter-spacing: .05em;
    white-space: nowrap; position: sticky; top: 0; z-index: 1;
  }
  .detail-table tbody tr { border-bottom: 1px solid #f3f3f3; }
  .detail-table tbody tr:hover { background: #f5f7ff; }
  .detail-table tbody tr.dang-row { background: #fff5f5; }
  .detail-table tbody tr.dang-row:hover { background: #ffe8e8; }
  .detail-table td { padding: 7px 11px; vertical-align: top; }
  .tree-dang-dot {
    display: inline-block; width: 7px; height: 7px; border-radius: 50%;
    background: #b71c1c; margin-right: 5px; vertical-align: middle; flex-shrink: 0;
  }

  footer { text-align: center; padding: 22px; font-size: 0.73rem; color: #aaa; }
</style>
</head>
<body>

<header>
  <h1>&#128274; OU Permissions Audit Report</h1>
  <p>Domain: <strong>$domainName</strong> &nbsp;|&nbsp; Search Base: $base &nbsp;|&nbsp; $inhNote$(if($defNote){" &nbsp;|&nbsp; $defNote"})</p>
</header>

<div class="summary-bar">
  <div class="stat"><span class="stat-label">OUs Scanned</span><span class="stat-value v-blue">$totalOUs</span></div>
  <div class="stat"><span class="stat-label">Total ACEs</span><span class="stat-value v-blue">$($allAces.Count)</span></div>
  <div class="stat"><span class="stat-label">Dangerous ACEs</span><span class="stat-value v-crit">$($dangerousAces.Count)</span></div>
  <div class="stat"><span class="stat-label">&#9888; Critical</span><span class="stat-value v-crit">$criticalCount</span></div>
  <div class="stat"><span class="stat-label">&#9888; High</span><span class="stat-value v-high">$highCount</span></div>
  <div class="stat"><span class="stat-label">&#9888; Medium</span><span class="stat-value v-medium">$mediumCount</span></div>
  <div class="stat"><span class="stat-label">Generated</span><span class="stat-value v-green" style="font-size:.88rem;padding-top:6px">$($runTime.ToString("yyyy-MM-dd HH:mm"))</span></div>
</div>

<div class="tab-bar">
  <button class="tab-btn active" onclick="switchTab('all', this)">
    &#128203; All Permissions <span class="tab-count">$($allAces.Count)</span>
  </button>
  <button class="tab-btn" onclick="switchTab('danger', this)">
    &#9888; Dangerous <span class="tab-count danger-count">$($dangerousAces.Count)</span>
  </button>
  <button class="tab-btn" onclick="switchTab('tree', this)">
    &#127968; OU Tree <span class="tab-count">$totalOUs</span>
  </button>
</div>

<!-- ═══════════════════════════ TAB 1: ALL ════════════════════════════════ -->
<div id="tab-all" class="tab-content active">
  <div class="filter-bar">
    <label>Access:</label>
    <button class="f-btn active" onclick="allFilter('access','all',this)">All</button>
    <button class="f-btn" onclick="allFilter('access','Allow',this)">Allow</button>
    <button class="f-btn" onclick="allFilter('access','Deny',this)">Deny</button>
    <span class="f-sep">|</span>
    <label>Risk:</label>
    <button class="f-btn active" onclick="allFilter('dangerous','all',this)">All</button>
    <button class="f-btn" onclick="allFilter('dangerous','true',this)">&#9888; Dangerous Only</button>
    <button class="f-btn" onclick="allFilter('dangerous','false',this)">Clean Only</button>
    <input class="search-input" type="search" placeholder="&#128269; Search OU, identity, rights&#8230;" oninput="allSearch(this.value)">
  </div>
  <main>
    <div class="card">
      <div class="card-header">
        <h2>All OU Permissions</h2>
        <span id="all-count" class="row-counter">Loading&#8230;</span>
      </div>
      <div class="tbl-wrap">
        <table id="allTable">
          <thead>
            <tr>
              <th onclick="sortTbl('all',0,this)">OU / Distinguished Name</th>
              <th onclick="sortTbl('all',1,this)">Identity (Trustee)</th>
              <th onclick="sortTbl('all',2,this)">Rights</th>
              <th onclick="sortTbl('all',3,this)">Type</th>
              <th onclick="sortTbl('all',4,this)">Inherited</th>
              <th onclick="sortTbl('all',5,this)">Inheritance Scope</th>
              <th onclick="sortTbl('all',6,this)">Object Type</th>
              <th onclick="sortTbl('all',7,this)">Inherits To</th>
            </tr>
          </thead>
          <tbody id="allBody"></tbody>
        </table>
      </div>
      <div id="all-pager" class="pager"></div>
    </div>
    <div class="callout callout-info" style="margin-top:18px">
      <span class="callout-icon">&#8505;&#65039;</span>
      <span>Rows in the <strong>Dangerous</strong> tab are also present here.
      Use the <em>Dangerous Only</em> filter above to cross-reference.
      <em>Object Type = All</em> means the right applies to all object types / attributes.</span>
    </div>
  </main>
</div>

<!-- ══════════════════════════ TAB 2: DANGEROUS ══════════════════════════ -->
<div id="tab-danger" class="tab-content">
  <div class="danger-filter-bar">
    <label>Risk Level:</label>
    <button class="df-btn active" onclick="dangFilter('all',this)">All</button>
    <button class="df-btn" onclick="dangFilter('Critical',this)"><span class="danger-dot dot-crit"></span>Critical</button>
    <button class="df-btn" onclick="dangFilter('High',this)"><span class="danger-dot dot-high"></span>High</button>
    <button class="df-btn" onclick="dangFilter('Medium',this)"><span class="danger-dot dot-med"></span>Medium</button>
    <input class="d-search" type="search" placeholder="&#128269; Search OU, identity, reason&#8230;" oninput="dangSearch(this.value)">
  </div>
  <main>
    <div class="callout callout-warn">
      <span class="callout-icon">&#9888;&#65039;</span>
      <span><strong>Review Required.</strong> The permissions below can be abused to compromise AD objects, escalate privileges, or steal credentials.
      Not all findings are exploitable — expected delegations (e.g. Helpdesk resetting passwords) will appear here.
      Verify each identity is intentionally granted these rights, is tightly scoped, and is documented.
      Investigate any unexpected or unfamiliar trustees immediately.</span>
    </div>
    <div class="card">
      <div class="card-header">
        <h2>&#9888; Dangerous Permissions</h2>
        <span id="dang-count" class="row-counter">Loading&#8230;</span>
      </div>
      <div class="tbl-wrap">
        <table id="dangTable" class="danger-table">
          <thead>
            <tr>
              <th onclick="sortTbl('dang',0,this)">OU / Distinguished Name</th>
              <th onclick="sortTbl('dang',1,this)">Identity (Trustee)</th>
              <th onclick="sortTbl('dang',2,this)">Rights</th>
              <th onclick="sortTbl('dang',3,this)">Risk Level</th>
              <th onclick="sortTbl('dang',4,this)">Reason &amp; Description</th>
              <th onclick="sortTbl('dang',5,this)">Type</th>
              <th onclick="sortTbl('dang',6,this)">Object Type</th>
              <th onclick="sortTbl('dang',7,this)">Inherited</th>
            </tr>
          </thead>
          <tbody id="dangBody"></tbody>
        </table>
      </div>
      <div id="dang-pager" class="pager"></div>
    </div>
    <div class="tip">
      <strong>Remediation — remove an ACE via PowerShell:</strong><br>
      <code>`$acl = Get-Acl "AD:\OU=Name,DC=domain,DC=com"</code><br>
      <code>`$ace = `$acl.Access | Where-Object { `$_.IdentityReference -eq "DOMAIN\User" -and `$_.ActiveDirectoryRights -match "GenericAll" }</code><br>
      <code>`$acl.RemoveAccessRule(`$ace)</code><br>
      <code>Set-Acl -Path "AD:\OU=Name,DC=domain,DC=com" -AclObject `$acl</code><br><br>
      Always document changes and verify in a test environment first. Consider using <strong>AD Delegation Wizard</strong> to re-apply standard delegations cleanly.
    </div>
  </main>
</div>

<!-- ═══════════════════════════ TAB 3: TREE ═══════════════════════════════ -->
<div id="tab-tree" class="tab-content">
  <div class="tree-layout">
    <div class="tree-pane" id="treePane">
      <p class="tree-empty">Select this tab to build the tree&#8230;</p>
    </div>
    <div class="detail-pane" id="detailPane">
      <div class="detail-placeholder">&#128193;&nbsp; Select an OU from the tree to view its permissions.</div>
    </div>
  </div>
</div>

<footer>Generated by Get-OUPermissions.ps1 &mdash; $($runTime.ToString("dddd, MMMM d, yyyy 'at' h:mm tt")) &mdash; $domainName</footer>

<script>
var PAGE_SIZE = 250;

// ── Source data embedded by PowerShell ──
var allData  = $jsonAll;
var dangData = $jsonDang;
var ouList   = $jsonOuList;

// ── Per-tab state ──
var allState  = { src: allData,  filtered: allData.slice(),  page: 0, access: 'all', dangerous: 'all', term: '' };
var dangState = { src: dangData, filtered: dangData.slice(), page: 0, level: 'all',  term: '' };

// ── Row builders (strings are already HTML-encoded by PowerShell) ──
function bdg(cls, txt) { return '<span class="badge ' + cls + '">' + txt + '</span>'; }

function buildAllRow(row) {
  var acc = row.a === 'Allow' ? bdg('acc-allow','Allow') : bdg('acc-deny','Deny');
  var inh = row.inh ? bdg('inh-yes','Yes') : bdg('inh-no','No');
  return '<tr>' +
    '<td><span class="ou-name">' + row.n + '</span><span class="dn-text">' + row.dn + '</span></td>' +
    '<td class="id-cell">'     + row.id  + '</td>' +
    '<td class="rights-cell">' + row.r   + '</td>' +
    '<td>' + acc + '</td>' +
    '<td>' + inh + '</td>' +
    '<td>' + row.it  + '</td>' +
    '<td>' + row.ot  + '</td>' +
    '<td>' + row.iot + '</td>' +
    '</tr>';
}

function buildDangRow(row) {
  var lvlCls = row.lv === 'Critical' ? 'lvl-crit' : (row.lv === 'High' ? 'lvl-high' : 'lvl-med');
  var acc    = row.a === 'Allow' ? bdg('acc-allow','Allow') : bdg('acc-deny','Deny');
  var inh    = row.inh ? bdg('inh-yes','Yes') : bdg('inh-no','No');
  return '<tr>' +
    '<td><span class="ou-name">' + row.n + '</span><span class="dn-text">' + row.dn + '</span></td>' +
    '<td class="id-cell">'     + row.id + '</td>' +
    '<td class="rights-cell">' + row.r  + '</td>' +
    '<td>' + bdg(lvlCls, row.lv) + '</td>' +
    '<td><strong>' + row.rs + '</strong><br><span class="desc-text">' + row.ds + '</span></td>' +
    '<td>' + acc + '</td>' +
    '<td>' + row.ot + '</td>' +
    '<td>' + inh + '</td>' +
    '</tr>';
}

// ── Render current page ──
function render(st, bodyId, countId, pagerId, builder) {
  var total = st.filtered.length;
  var start = st.page * PAGE_SIZE;
  if (start >= total && total > 0) { st.page = 0; start = 0; }
  var end = Math.min(start + PAGE_SIZE, total);
  var html = '';
  if (total === 0) {
    html = '<tr><td colspan="8" class="none">No results match the current filters.</td></tr>';
  } else {
    for (var i = start; i < end; i++) { html += builder(st.filtered[i]); }
  }
  document.getElementById(bodyId).innerHTML = html;
  var countEl = document.getElementById(countId);
  if (countEl) {
    countEl.textContent = total === 0 ? 'No results' :
      'Showing ' + (start + 1) + '–' + end + ' of ' + total;
  }
  renderPager(st, pagerId, total);
}

function renderAll()  { render(allState,  'allBody',  'all-count',  'all-pager',  buildAllRow);  }
function renderDang() { render(dangState, 'dangBody', 'dang-count', 'dang-pager', buildDangRow); }

// ── Pager ──
function renderPager(st, pagerId, total) {
  var pager = document.getElementById(pagerId);
  if (!pager) return;
  var pages = Math.ceil(total / PAGE_SIZE);
  if (pages <= 1) { pager.innerHTML = ''; return; }
  var pg = st.page;
  pager.innerHTML =
    '<button class="pg-btn" onclick="goPage(\'' + pagerId + '\',' + (pg - 1) + ')"' + (pg === 0 ? ' disabled' : '') + '>&#8592; Prev</button>' +
    '<span class="pg-info">Page ' + (pg + 1) + ' of ' + pages + '</span>' +
    '<input class="pg-jump" type="number" min="1" max="' + pages + '" value="' + (pg + 1) + '" onchange="goPage(\'' + pagerId + '\',(+this.value-1))" title="Go to page">' +
    '<button class="pg-btn" onclick="goPage(\'' + pagerId + '\',' + (pg + 1) + ')"' + (pg >= pages - 1 ? ' disabled' : '') + '>Next &#8594;</button>';
}

function goPage(pagerId, page) {
  var st = (pagerId === 'all-pager') ? allState : dangState;
  var pages = Math.ceil(st.filtered.length / PAGE_SIZE);
  st.page = Math.max(0, Math.min(page, pages - 1));
  if (pagerId === 'all-pager') renderAll(); else renderDang();
}

// ── Tab switching ──
var treeInited = false;
function switchTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(function(t){ t.classList.remove('active'); });
  document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'tree' && !treeInited) { treeInited = true; initTree(); }
}

// ── All-tab filters ──
function allFilter(type, val, btn) {
  if (type === 'access') allState.access = val; else allState.dangerous = val;
  var grpBtns = Array.from(document.querySelectorAll('#tab-all .f-btn')).filter(function(b){
    return b.getAttribute('onclick') && b.getAttribute('onclick').indexOf("'" + type + "'") !== -1;
  });
  grpBtns.forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  applyAllFilters();
}

function allSearch(val) { allState.term = val.toLowerCase(); applyAllFilters(); }

function applyAllFilters() {
  var acc  = allState.access;
  var dng  = allState.dangerous;
  var term = allState.term;
  allState.filtered = allState.src.filter(function(row) {
    var mAcc  = acc  === 'all' || row.a === acc;
    var mDng  = dng  === 'all' || String(row.d) === dng;
    var mTerm = !term || (row.n + ' ' + row.dn + ' ' + row.id + ' ' + row.r + ' ' + row.ot).toLowerCase().indexOf(term) !== -1;
    return mAcc && mDng && mTerm;
  });
  allState.page = 0;
  renderAll();
}

// ── Danger-tab filters ──
function dangFilter(level, btn) {
  dangState.level = level;
  document.querySelectorAll('#tab-danger .df-btn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  applyDangFilters();
}

function dangSearch(val) { dangState.term = val.toLowerCase(); applyDangFilters(); }

function applyDangFilters() {
  var lv   = dangState.level;
  var term = dangState.term;
  dangState.filtered = dangState.src.filter(function(row) {
    var mLv   = lv   === 'all' || row.lv === lv;
    var mTerm = !term || (row.n + ' ' + row.dn + ' ' + row.id + ' ' + row.rs + ' ' + row.ds).toLowerCase().indexOf(term) !== -1;
    return mLv && mTerm;
  });
  dangState.page = 0;
  renderDang();
}

// ── Sortable columns ──
var lvlOrder = { Critical: 0, High: 1, Medium: 2 };
var sortDirs = {};
var allFields  = ['n','id','r','a','inh','it','ot','iot'];
var dangFields = ['n','id','r','lv','rs','a','ot','inh'];

function sortTbl(tab, col, th) {
  var key = tab + '_' + col;
  var dir = (sortDirs[key] === 1) ? -1 : 1;
  sortDirs[key] = dir;
  var isAll  = (tab === 'all');
  var st     = isAll ? allState : dangState;
  var fields = isAll ? allFields : dangFields;
  var field  = fields[col];
  var tbl    = document.getElementById(isAll ? 'allTable' : 'dangTable');
  tbl.querySelectorAll('thead th').forEach(function(t){ t.classList.remove('asc','desc'); });
  th.classList.add(dir === 1 ? 'asc' : 'desc');
  st.filtered.sort(function(a, b) {
    if (field === 'lv') {
      var va = lvlOrder[a.lv] !== undefined ? lvlOrder[a.lv] : 9;
      var vb = lvlOrder[b.lv] !== undefined ? lvlOrder[b.lv] : 9;
      return (va - vb) * dir;
    }
    var sa = String(a[field] || '');
    var sb = String(b[field] || '');
    return sa.localeCompare(sb, undefined, { numeric: true }) * dir;
  });
  st.page = 0;
  if (isAll) renderAll(); else renderDang();
}

// ── OU Tree (Tab 3) ──
function getParentDN(dn) {
  var i = dn.indexOf(',');
  return i === -1 ? null : dn.substring(i + 1);
}

// Build tree structure from flat ouList
var ouTree = (function() {
  var nodes = [];
  var byDN  = {};
  ouList.forEach(function(ou, i) {
    var node = { n: ou.n, dn: ou.dn, ac: ou.ac, dc: ou.dc, id: i, children: [], open: false };
    nodes.push(node);
    byDN[ou.dn] = node;
  });
  var roots = [];
  nodes.forEach(function(node) {
    var pdn = getParentDN(node.dn);
    if (pdn && byDN[pdn]) { byDN[pdn].children.push(node); }
    else { roots.push(node); }
  });
  function sortNode(n) {
    n.children.sort(function(a, b) { return a.n.localeCompare(b.n); });
    n.children.forEach(sortNode);
  }
  roots.forEach(sortNode);
  return { nodes: nodes, roots: roots, byDN: byDN };
})();

function renderTreeNode(node, depth) {
  var hasKids  = node.children.length > 0;
  var tgl      = hasKids
    ? '<button class="tree-toggle" data-tid="' + node.id + '">&#9658;</button>'
    : '<span class="tree-toggle tree-toggle-leaf"></span>';
  var folder   = hasKids ? '&#128193;' : '&#128196;';
  var aceBadge = '<span class="tree-ace' + (node.ac === 0 ? ' tree-ace-zero' : '') + '">' + node.ac + '</span>';
  var dngBadge = node.dc > 0 ? ' <span class="tree-dang">&#9888;&nbsp;' + node.dc + '</span>' : '';
  var pad      = (8 + depth * 18) + 'px';
  var kids     = '';
  if (hasKids) {
    kids = '<div class="tree-children" id="tc_' + node.id + '" style="display:none">' +
      node.children.map(function(c) { return renderTreeNode(c, depth + 1); }).join('') +
      '</div>';
  }
  return '<div class="tree-node" id="tn_' + node.id + '">' +
    '<div class="tree-row" data-nid="' + node.id + '" style="padding-left:' + pad + '">' +
      tgl +
      '<span class="tree-folder">' + folder + '</span>&nbsp;' +
      '<span class="tree-label">'  + node.n  + '</span>' +
      '&nbsp;' + aceBadge + dngBadge +
    '</div>' + kids +
    '</div>';
}

function initTree() {
  var pane = document.getElementById('treePane');
  if (!pane) return;
  if (ouTree.roots.length === 0) {
    pane.innerHTML = '<p class="tree-empty">No OUs found.</p>';
    return;
  }
  pane.innerHTML = ouTree.roots.map(function(r) { return renderTreeNode(r, 0); }).join('');

  // Auto-expand top-level nodes
  ouTree.roots.forEach(function(r) {
    if (r.children.length > 0) {
      var c = document.getElementById('tc_' + r.id);
      var b = pane.querySelector('[data-tid="' + r.id + '"]');
      if (c) c.style.display = 'block';
      if (b) b.innerHTML = '&#9660;';
      r.open = true;
    }
  });

  // Event delegation — toggle and select
  pane.addEventListener('click', function(e) {
    var tglBtn = e.target.closest('[data-tid]');
    if (tglBtn) {
      e.stopPropagation();
      var nid  = parseInt(tglBtn.getAttribute('data-tid'), 10);
      var node = ouTree.nodes[nid];
      var c    = document.getElementById('tc_' + nid);
      if (!node || !c) return;
      node.open          = !node.open;
      c.style.display    = node.open ? 'block' : 'none';
      tglBtn.innerHTML   = node.open ? '&#9660;' : '&#9658;';
      return;
    }
    var row = e.target.closest('.tree-row');
    if (!row) return;
    var nid  = parseInt(row.getAttribute('data-nid'), 10);
    var node = ouTree.nodes[nid];
    if (!node) return;
    pane.querySelectorAll('.tree-row.selected').forEach(function(r){ r.classList.remove('selected'); });
    row.classList.add('selected');
    renderDetailPane(node);
  });
}

function renderDetailPane(node) {
  var pane  = document.getElementById('detailPane');
  var aces  = allData.filter(function(r) { return r.k === node.dn; });
  var daces = dangData.filter(function(r) { return r.k === node.dn; });
  var safedn = node.dn.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  var html  = '<div class="detail-header">' +
    '<div class="detail-ou-name">&#128193;&nbsp;' + node.n + '</div>' +
    '<div class="detail-ou-dn">'  + safedn + '</div>' +
    '<div class="detail-badges">' +
      '<span class="stat-chip">'  + aces.length  + '&nbsp;ACE(s)</span>' +
      (daces.length > 0 ? '<span class="stat-chip chip-dang">&#9888;&nbsp;' + daces.length + ' dangerous</span>' : '') +
    '</div></div>';
  if (aces.length === 0) {
    html += '<p class="detail-none">No explicit ACEs found on this OU with the current run options (check -IncludeInherited or -ExcludeDefaultPrincipals).</p>';
  } else {
    var rows = aces.map(function(row) {
      var acc = row.a === 'Allow' ? bdg('acc-allow','Allow') : bdg('acc-deny','Deny');
      var inh = row.inh ? bdg('inh-yes','Yes') : bdg('inh-no','No');
      var dot = row.d ? '<span class="tree-dang-dot"></span>' : '';
      return '<tr' + (row.d ? ' class="dang-row"' : '') + '>' +
        '<td class="id-cell">'     + dot + row.id + '</td>' +
        '<td class="rights-cell">' + row.r  + '</td>' +
        '<td>' + acc + '</td>' +
        '<td>' + inh + '</td>' +
        '<td>' + row.ot + '</td>' +
        '</tr>';
    }).join('');
    html += '<div class="detail-pane-body"><div class="tbl-wrap">' +
      '<table class="detail-table"><thead><tr>' +
        '<th>Identity (Trustee)</th><th>Rights</th><th>Type</th><th>Inherited</th><th>Object Type</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
  }
  pane.innerHTML = html;
}

// ── Init ──
renderAll();
renderDang();
</script>
</body>
</html>
"@
#endregion

#region ── Write Output ───────────────────────────────────────────────────────
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$html | Out-File -FilePath $resolvedPath -Encoding UTF8 -Force
Write-Host "Report saved to: $resolvedPath" -ForegroundColor Cyan
if ($errCount -gt 0) {
    Write-Warning "$errCount OU(s) could not be read (access denied or invalid path). Run as Domain Admin for full coverage."
}
#endregion
