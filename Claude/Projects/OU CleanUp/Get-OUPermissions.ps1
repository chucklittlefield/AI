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

    # GenericAll — highest risk
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
        return @{ Level='Critical'; Reason='GenericAll'; Desc='Full control of the OU and all objects within it. Can read/write all attributes, change permissions, and take ownership.' }
    }

    # WriteDACL
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) {
        return @{ Level='Critical'; Reason='WriteDACL'; Desc='Can modify the access control list, allowing the trustee to grant themselves any additional right including GenericAll.' }
    }

    # WriteOwner
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) {
        return @{ Level='Critical'; Reason='WriteOwner'; Desc='Can take ownership of the OU. Owners can grant themselves full control regardless of the DACL.' }
    }

    # GenericWrite
    if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) {
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

function ConvertTo-HtmlRow {
    param([PSObject]$e, [bool]$includeDanger = $false)

    $ouName   = [System.Web.HttpUtility]::HtmlEncode($e.OUName)
    $ouDN     = [System.Web.HttpUtility]::HtmlEncode($e.OUDN)
    $identity = [System.Web.HttpUtility]::HtmlEncode($e.Identity)
    $rights   = [System.Web.HttpUtility]::HtmlEncode($e.Rights)
    $objType  = [System.Web.HttpUtility]::HtmlEncode($e.ObjectType)
    $inhType  = [System.Web.HttpUtility]::HtmlEncode($e.InheritedObjType)
    $inhFlag  = if ($e.Inherited) { '<span class="badge inh-yes">Yes</span>' } else { '<span class="badge inh-no">No</span>' }
    $accType  = if ($e.AccessType -eq 'Allow') { '<span class="badge acc-allow">Allow</span>' } else { '<span class="badge acc-deny">Deny</span>' }

    if ($includeDanger) {
        $lvlClass = switch ($e.DangerLevel) { 'Critical'{'lvl-crit'} 'High'{'lvl-high'} default{'lvl-med'} }
        $reason = [System.Web.HttpUtility]::HtmlEncode($e.DangerReason)
        $desc   = [System.Web.HttpUtility]::HtmlEncode($e.DangerDesc)
        return "
        <tr data-level='$($e.DangerLevel)'>
          <td><span class='ou-name'>$ouName</span><span class='dn-text'>$ouDN</span></td>
          <td class='id-cell'>$identity</td>
          <td class='rights-cell'>$rights</td>
          <td><span class='badge $lvlClass'>$($e.DangerLevel)</span></td>
          <td><strong>$reason</strong><br><span class='desc-text'>$desc</span></td>
          <td>$accType</td>
          <td>$objType</td>
          <td>$inhFlag</td>
        </tr>"
    } else {
        return "
        <tr data-access='$($e.AccessType)' data-dangerous='$($e.IsDangerous.ToString().ToLower())'>
          <td><span class='ou-name'>$ouName</span><span class='dn-text'>$ouDN</span></td>
          <td class='id-cell'>$identity</td>
          <td class='rights-cell'>$rights</td>
          <td>$accType</td>
          <td>$inhFlag</td>
          <td>$($e.InheritanceType)</td>
          <td>$objType</td>
          <td>$inhType</td>
        </tr>"
    }
}

$allRows  = if ($allAces.Count -eq 0) {
    '<tr><td colspan="8" class="none">No ACEs found with the current filters.</td></tr>'
} else {
    ($allAces | ForEach-Object { ConvertTo-HtmlRow $_ $false }) -join ""
}

$dangRows = if ($dangerousAces.Count -eq 0) {
    '<tr><td colspan="8" class="none">No dangerous permissions detected.</td></tr>'
} else {
    ($dangerousAces | Sort-Object { switch($_.DangerLevel){'Critical'{0}'High'{1}default{2}} }, OUDN |
     ForEach-Object { ConvertTo-HtmlRow $_ $true }) -join ""
}

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
  tbody tr.hidden { display: none; }
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

  /* ── Tip ── */
  .tip {
    margin-top: 20px; padding: 13px 17px;
    background: #fffde7; border-left: 4px solid #f9a825;
    border-radius: 6px; font-size: 0.80rem; color: #555; line-height: 1.7;
  }
  .tip code { font-family: monospace; background: #fff8e1; padding: 1px 5px; border-radius: 3px; }

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
    <input class="search-input" type="search" placeholder="&#128269; Search OU, identity, rights…" oninput="allSearch(this.value)">
  </div>
  <main>
    <div class="card">
      <div class="card-header">
        <h2>All OU Permissions</h2>
        <span id="all-count" class="row-counter">Showing all $($allAces.Count) ACE(s)</span>
      </div>
      <div class="tbl-wrap">
        <table id="allTable">
          <thead>
            <tr>
              <th onclick="sortTbl('allTable',0,this)">OU / Distinguished Name</th>
              <th onclick="sortTbl('allTable',1,this)">Identity (Trustee)</th>
              <th onclick="sortTbl('allTable',2,this)">Rights</th>
              <th onclick="sortTbl('allTable',3,this)">Type</th>
              <th onclick="sortTbl('allTable',4,this)">Inherited</th>
              <th onclick="sortTbl('allTable',5,this)">Inheritance Scope</th>
              <th onclick="sortTbl('allTable',6,this)">Object Type</th>
              <th onclick="sortTbl('allTable',7,this)">Inherits To</th>
            </tr>
          </thead>
          <tbody>
$allRows
          </tbody>
        </table>
      </div>
    </div>
    <div class="callout callout-info" style="margin-top:18px">
      <span class="callout-icon">&#8505;&#65039;</span>
      <span>Rows highlighted in the <strong>Dangerous</strong> tab are also present here.
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
    <input class="d-search" type="search" placeholder="&#128269; Search OU, identity, reason…" oninput="dangSearch(this.value)">
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
        <span id="dang-count" class="row-counter">Showing all $($dangerousAces.Count) finding(s)</span>
      </div>
      <div class="tbl-wrap">
        <table id="dangTable" class="danger-table">
          <thead>
            <tr>
              <th onclick="sortTbl('dangTable',0,this)">OU / Distinguished Name</th>
              <th onclick="sortTbl('dangTable',1,this)">Identity (Trustee)</th>
              <th onclick="sortTbl('dangTable',2,this)">Rights</th>
              <th onclick="sortTbl('dangTable',3,this)">Risk Level</th>
              <th onclick="sortTbl('dangTable',4,this)">Reason &amp; Description</th>
              <th onclick="sortTbl('dangTable',5,this)">Type</th>
              <th onclick="sortTbl('dangTable',6,this)">Object Type</th>
              <th onclick="sortTbl('dangTable',7,this)">Inherited</th>
            </tr>
          </thead>
          <tbody>
$dangRows
          </tbody>
        </table>
      </div>
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

<footer>Generated by Get-OUPermissions.ps1 &mdash; $($runTime.ToString("dddd, MMMM d, yyyy 'at' h:mm tt")) &mdash; $domainName</footer>

<script>
// ── Tab switching ──
function switchTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(function(t){ t.classList.remove('active'); });
  document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}

// ── All-tab filters ──
var allFilters = { access: 'all', dangerous: 'all' };
var allTerm = '';

function allFilter(type, val, btn) {
  allFilters[type] = val;
  var grpBtns = Array.from(document.querySelectorAll('#tab-all .f-btn')).filter(function(b){
    return b.getAttribute('onclick') && b.getAttribute('onclick').indexOf("'" + type + "'") !== -1;
  });
  grpBtns.forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  applyAllFilters();
}

function allSearch(val) { allTerm = val.toLowerCase(); applyAllFilters(); }

function applyAllFilters() {
  var rows = document.querySelectorAll('#allTable tbody tr');
  var visible = 0;
  rows.forEach(function(row) {
    var access = row.getAttribute('data-access') || '';
    var dang   = row.getAttribute('data-dangerous') || '';
    var text   = row.innerText.toLowerCase();
    var show =
      (allFilters.access    === 'all' || access === allFilters.access) &&
      (allFilters.dangerous === 'all' || dang   === allFilters.dangerous) &&
      (allTerm === '' || text.indexOf(allTerm) !== -1);
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  });
  document.getElementById('all-count').textContent = 'Showing ' + visible + ' of ' + rows.length + ' ACE(s)';
}

// ── Danger-tab filters ──
var dangLevel = 'all';
var dangTerm  = '';

function dangFilter(level, btn) {
  dangLevel = level;
  document.querySelectorAll('#tab-danger .df-btn').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  applyDangFilters();
}

function dangSearch(val) { dangTerm = val.toLowerCase(); applyDangFilters(); }

function applyDangFilters() {
  var rows = document.querySelectorAll('#dangTable tbody tr');
  var visible = 0;
  rows.forEach(function(row) {
    var lvl  = row.getAttribute('data-level') || '';
    var text = row.innerText.toLowerCase();
    var show =
      (dangLevel === 'all' || lvl === dangLevel) &&
      (dangTerm === '' || text.indexOf(dangTerm) !== -1);
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  });
  document.getElementById('dang-count').textContent = 'Showing ' + visible + ' of ' + rows.length + ' finding(s)';
}

// ── Sortable columns ──
var sortState = {};
function sortTbl(tableId, col, th) {
  var key = tableId + '_' + col;
  var dir = (sortState[key] === 1) ? -1 : 1;
  sortState[key] = dir;

  var table = document.getElementById(tableId);
  var ths   = table.querySelectorAll('thead th');
  ths.forEach(function(t){ t.classList.remove('asc','desc'); });
  th.classList.add(dir === 1 ? 'asc' : 'desc');

  var tbody = table.tBodies[0];
  var rows  = Array.from(tbody.querySelectorAll('tr:not(.hidden), tr.hidden'));
  rows.sort(function(a, b) {
    var ta = a.cells[col] ? a.cells[col].innerText.trim() : '';
    var tb = b.cells[col] ? b.cells[col].innerText.trim() : '';
    return ta.localeCompare(tb, undefined, { numeric: true }) * dir;
  });
  rows.forEach(function(r){ tbody.appendChild(r); });
}
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
