<#
.SYNOPSIS
    Discovers GPOs by name pattern, parses Restricted Groups, recursively expands
    all memberships via Active Directory, and produces a single interactive HTML report.

.DESCRIPTION
    Three input modes (combinable):
      -AutoDiscover          Query AD for all GPOs whose DisplayName matches -NameFilter
      -XmlPaths <path[]>     One or more pre-exported GPO Report XML files
      -XmlFolder <path>      A folder – every *.xml inside is processed

    Add -PickGPOs to any mode to open an interactive Out-GridView picker before
    processing begins. For -AutoDiscover the picker appears before XML reports are
    pulled, so only selected GPOs incur the network cost. For file-based sources
    the picker appears after files are scanned, letting you deselect any you don't
    want included.

    For each GPO the script:
      1. Extracts Restricted Groups and their direct members
      2. Recursively expands every nested group via Get-ADGroupMember
      3. Enriches leaf accounts with DisplayName, Email, Enabled, LastLogonDate
      4. Collects GPO link (OU scope) information
      5. Emits one self-contained HTML report + a companion CSV

.PARAMETER AutoDiscover
    Switch. Query AD for GPOs matching -NameFilter and export their XML on the fly.

.PARAMETER NameFilter
    Wildcard pattern used with -AutoDiscover. Default: '*DelegatedAdmin*'

.PARAMETER Domain
    AD domain to query. Defaults to the current user's domain.

.PARAMETER XmlPaths
    Array of explicit GPO Report XML file paths.

.PARAMETER XmlFolder
    Folder path. All *.xml files inside are added to the processing list.

.PARAMETER PickGPOs
    Switch. Opens an Out-GridView selection dialog so you can choose which GPOs to
    process. With -AutoDiscover the picker shows AD results before XML is fetched.
    With file-based sources it shows after scanning, before any AD queries run.
    Hold Ctrl or Shift to select multiple rows. Click OK to proceed.

.PARAMETER SaveXmlFolder
    When using -AutoDiscover, save each fetched GPO XML report to this folder.
    Files are named <GPODisplayName>_<GUID>.xml (display name is sanitized for the
    filesystem). The folder is created if it does not already exist.

.PARAMETER OutputPath
    Full path for the HTML report.
    Default: <script dir>\RestrictedGroups_Report_<timestamp>.html

.EXAMPLE
    # Auto-discover, then pick which GPOs to process
    .\Expand-RestrictedGroups.ps1 -AutoDiscover -PickGPOs

.EXAMPLE
    # Widen the search and pick interactively
    .\Expand-RestrictedGroups.ps1 -AutoDiscover -NameFilter '*Admin*' -PickGPOs

.EXAMPLE
    # Auto-discover all DelegatedAdmin GPOs (no picker)
    .\Expand-RestrictedGroups.ps1 -AutoDiscover

.EXAMPLE
    # Auto-discover and save the raw XML files for later reuse
    .\Expand-RestrictedGroups.ps1 -AutoDiscover -SaveXmlFolder "C:\GPOExports"

.EXAMPLE
    # Auto-discover, pick interactively, and save selected XML files
    .\Expand-RestrictedGroups.ps1 -AutoDiscover -PickGPOs -SaveXmlFolder "C:\GPOExports"

.EXAMPLE
    # Supply specific files
    .\Expand-RestrictedGroups.ps1 -XmlPaths "C:\GPOs\DASIFP.xml","C:\GPOs\DANC.xml"

.EXAMPLE
    # Scan a folder, then pick which files to include
    .\Expand-RestrictedGroups.ps1 -XmlFolder "C:\GPOExports" -PickGPOs

.EXAMPLE
    # Combine auto-discover with an extra file, pick from the merged list
    .\Expand-RestrictedGroups.ps1 -AutoDiscover -XmlPaths "C:\GPOs\Extra.xml" -PickGPOs
#>

[CmdletBinding(DefaultParameterSetName = 'Auto')]
param(
    [switch]$AutoDiscover,
    [string]$NameFilter  = '*Delegated*',
    [string]$Domain      = $env:USERDNSDOMAIN,

    [switch]$PickGPOs,

    [string[]]$XmlPaths    = @(),
    [string]$XmlFolder     = '',
    [string]$SaveXmlFolder = '',

    [string]$OutputPath  = (Join-Path $PSScriptRoot (
        "RestrictedGroups_Report_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmm')
    ))
)

#Requires -Modules ActiveDirectory, GroupPolicy

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

function Escape-Html ([string]$s) {
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function Get-AccountType ([string]$SamAccountName, [string]$ObjectClass) {
    if ($ObjectClass -eq 'group')    { return 'Domain Group' }
    if ($ObjectClass -eq 'computer') { return 'Computer' }
    $svcPatterns = 'svc\.|_svc|\.svc|veeam|sql|iis|app_|_app|backup|scan|print|sched|task|srvc|bot\.'
    if ($SamAccountName -match $svcPatterns) { return 'Service Account' }
    return 'User Account'
}

function Get-TypeTag ([string]$AccountType) {
    switch ($AccountType) {
        'Domain Group'    { '<span class="tag tag-group">&#127991; Domain Group</span>' }
        'User Account'    { '<span class="tag tag-user">&#128100; User Account</span>' }
        'Service Account' { '<span class="tag tag-svc">&#9881; Service Account</span>' }
        'Local Account'   { '<span class="tag tag-local">&#127968; Local Account</span>' }
        'Computer'        { '<span class="tag tag-comp">&#128187; Computer</span>' }
        default           { '<span class="tag tag-local">? Unknown</span>' }
    }
}

function Get-EnabledBadge ($Enabled) {
    if ($null -eq $Enabled) { return '<span class="badge badge-na">N/A</span>' }
    if ($Enabled)            { return '<span class="badge badge-on">&#10003; Enabled</span>' }
    return                          '<span class="badge badge-off">&#10007; Disabled</span>'
}

# Recursive group expander — returns flat list of PSCustomObjects
function Expand-Group ([string]$GroupName, [string]$Domain,
                       [System.Collections.Generic.HashSet[string]]$Visited,
                       [string]$Path) {
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Visited.Add($GroupName)) {
        Write-Warning "Circular reference: '$GroupName' — skipping."
        return $out
    }
    try { $adMembers = Get-ADGroupMember -Identity $GroupName -Server $Domain -EA Stop }
    catch { Write-Warning "Cannot query '$GroupName': $_"; return $out }

    foreach ($m in $adMembers) {
        $displayName = $email = ''; $enabled = $null; $lastLogon = $null
        if ($m.objectClass -in 'user','inetOrgPerson') {
            try {
                $u = Get-ADUser $m.SID -Server $Domain `
                     -Properties DisplayName,EmailAddress,Enabled,LastLogonDate -EA SilentlyContinue
                $displayName = $u.DisplayName; $email = $u.EmailAddress
                $enabled = $u.Enabled; $lastLogon = $u.LastLogonDate
            } catch {}
        }
        $entry = [PSCustomObject]@{
            SamAccountName = $m.SamAccountName
            DisplayName    = $displayName
            Email          = $email
            ObjectClass    = $m.objectClass
            AccountType    = (Get-AccountType $m.SamAccountName $m.objectClass)
            SID            = $m.SID.Value
            Enabled        = $enabled
            LastLogon      = $lastLogon
            ResolutionPath = $Path
            IsLeaf         = ($m.objectClass -ne 'group')
        }
        $out.Add($entry)
        if ($m.objectClass -eq 'group') {
            foreach ($n in (Expand-Group $m.SamAccountName $Domain $Visited "$Path → $($m.SamAccountName)")) {
                $out.Add($n)
            }
        }
    }
    return $out
}

# Parse one XML (as [xml] object) → returns a GPO data hashtable
function Parse-GpoXml ([xml]$xml, [string]$SourceLabel) {
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('gp',  'http://www.microsoft.com/GroupPolicy/Settings')
    $ns.AddNamespace('gpt', 'http://www.microsoft.com/GroupPolicy/Types')
    $ns.AddNamespace('sec', 'http://www.microsoft.com/GroupPolicy/Settings/Security')

    $gpoName      = $xml.GPO.Name
    $gpoDomain    = $xml.GPO.Identifier.Domain
    $createdTime  = $xml.GPO.CreatedTime
    $modifiedTime = $xml.GPO.ModifiedTime
    $gpoGuid      = $xml.GPO.Identifier.Identifier.'#text'

    # --- Links (OU scope) ---
    # Use PowerShell's XML adapter ($xml.GPO.LinksTo) rather than SelectNodes() so
    # that the default namespace on the GPO element is handled transparently.
    # SelectNodes('//GPO/LinksTo') without a namespace manager silently matches nothing
    # when the document uses a default namespace (xmlns="...").
    $links = @()
    foreach ($lt in @($xml.GPO.LinksTo)) {
        if ($null -eq $lt) { continue }
        $links += [PSCustomObject]@{
            OUName    = [string]$lt.SOMName
            OUPath    = [string]$lt.SOMPath
            Enabled   = ([string]$lt.Enabled -eq 'true')
            NoOverride= ([string]$lt.NoOverride -eq 'true')
        }
    }

    # --- Restricted Groups ---
    $restrictedGroups = @()
    $rgNodes = $xml.SelectNodes('//sec:RestrictedGroups', $ns)
    foreach ($rg in $rgNodes) {
        $grpNodes = $rg.ChildNodes | Where-Object { $_.LocalName -eq 'GroupName' }
        foreach ($grpNode in $grpNodes) {
            $sidNode   = $grpNode.SelectSingleNode('*[local-name()="SID"]')
            $nameNode  = $grpNode.SelectSingleNode('*[local-name()="Name"]')
            $groupSID  = if ($sidNode)  { $sidNode.InnerText  } else { '' }
            $groupName = if ($nameNode) { $nameNode.InnerText } else { '' }
            $directMembers = @()
            $sib = $grpNode.NextSibling
            while ($null -ne $sib -and $sib.LocalName -eq 'Member') {
                $mSidNode  = $sib.SelectSingleNode('*[local-name()="SID"]')
                $mNameNode = $sib.SelectSingleNode('*[local-name()="Name"]')
                $directMembers += [PSCustomObject]@{
                    SID  = if ($mSidNode)  { $mSidNode.InnerText  } else { '' }
                    Name = if ($mNameNode) { $mNameNode.InnerText } else { '' }
                }
                $sib = $sib.NextSibling
            }
            $restrictedGroups += [PSCustomObject]@{
                GroupSID      = $groupSID
                GroupName     = $groupName
                DirectMembers = $directMembers
            }
        }
    }

    return @{
        GpoName          = $gpoName
        GpoDomain        = $gpoDomain
        GpoGuid          = $gpoGuid
        CreatedTime      = $createdTime
        ModifiedTime     = $modifiedTime
        SourceLabel      = $SourceLabel
        Links            = $links
        RestrictedGroups = $restrictedGroups
    }
}

# ══════════════════════════════════════════════════════
#  STEP 1 — Collect XML sources
# ══════════════════════════════════════════════════════
Write-Host "`n[1/5] Collecting GPO XML sources..." -ForegroundColor Cyan

$xmlSources = [System.Collections.Generic.List[hashtable]]::new()   # {Label, Xml}

# Auto-discover via GroupPolicy module
if ($AutoDiscover) {
    Write-Host "  Auto-discovering GPOs matching '$NameFilter' in domain '$Domain'..." -ForegroundColor Gray
    $matchedGPOs = @(Get-GPO -All -Domain $Domain | Where-Object { $_.DisplayName -like $NameFilter })
    Write-Host "  Found $($matchedGPOs.Count) GPO(s)." -ForegroundColor Gray

    if ($matchedGPOs.Count -eq 0) {
        Write-Warning "No GPOs matched the filter '$NameFilter'."
    } else {
        # Optional interactive picker — shown BEFORE XML reports are fetched
        if ($PickGPOs) {
            Write-Host "  Opening GPO picker (Ctrl/Shift-click to multi-select, then OK)..." -ForegroundColor Yellow
            $pickerInput = $matchedGPOs | Select-Object `
                @{N='DisplayName';  E={$_.DisplayName}},
                @{N='GUID';         E={"{$($_.Id)}"}},
                @{N='GpoStatus';    E={$_.GpoStatus}},
                @{N='Created';      E={$_.CreationTime.ToString('yyyy-MM-dd')}},
                @{N='LastModified'; E={$_.ModificationTime.ToString('yyyy-MM-dd')}},
                @{N='Domain';       E={$_.DomainName}}

            $selectedRows = $pickerInput | Out-GridView -Title "Select GPOs to include — Ctrl/Shift for multi-select" -PassThru

            if (-not $selectedRows) {
                Write-Warning "No GPOs selected in picker — skipping auto-discover results."
                $matchedGPOs = @()
            } else {
                # Map selection back to GPO objects by display name + GUID
                $selectedNames = @($selectedRows | ForEach-Object { $_.DisplayName })
                $matchedGPOs   = @($matchedGPOs | Where-Object { $selectedNames -contains $_.DisplayName })
                Write-Host "  Selected $($matchedGPOs.Count) GPO(s)." -ForegroundColor Gray
            }
        }

        # Prepare save folder once, before the fetch loop
        if ($SaveXmlFolder) {
            if (-not (Test-Path $SaveXmlFolder)) {
                New-Item -ItemType Directory -Path $SaveXmlFolder -Force | Out-Null
                Write-Host "  Created XML save folder: $SaveXmlFolder" -ForegroundColor Gray
            }
        }

        foreach ($gpo in $matchedGPOs) {
            Write-Host "    Fetching XML: $($gpo.DisplayName) {$($gpo.Id)}" -ForegroundColor DarkGray
            $reportXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain
            $xmlSources.Add(@{ Label = $gpo.DisplayName; Xml = [xml]$reportXml })

            if ($SaveXmlFolder) {
                $safeName  = $gpo.DisplayName -replace '[\\/:*?"<>|]', '_'
                $xmlFile   = Join-Path $SaveXmlFolder ("{0}_{1}.xml" -f $safeName, $gpo.Id)
                $reportXml | Out-File -FilePath $xmlFile -Encoding Unicode -NoNewline
                Write-Host "      Saved: $xmlFile" -ForegroundColor DarkGray
            }
        }
    }
}

# Explicit file paths
foreach ($p in $XmlPaths) {
    if (Test-Path $p) {
        Write-Host "  + File: $p" -ForegroundColor Gray
        $xmlSources.Add(@{ Label = (Split-Path $p -Leaf); Xml = [xml](Get-Content $p -Encoding Unicode) })
    } else {
        Write-Warning "File not found, skipping: $p"
    }
}

# Folder of XML files
if ($XmlFolder -and (Test-Path $XmlFolder)) {
    $folderFiles = @(Get-ChildItem $XmlFolder -Filter '*.xml')
    Write-Host "  + Folder '$XmlFolder': $($folderFiles.Count) XML file(s)." -ForegroundColor Gray
    foreach ($f in $folderFiles) {
        $xmlSources.Add(@{ Label = $f.Name; Xml = [xml](Get-Content $f.FullName -Encoding Unicode) })
    }
}

# Optional picker for file-based sources (XmlPaths / XmlFolder)
# Runs after all files are loaded so the picker shows GPO names read from the XML,
# not just filenames. Skips sources already handled by the AutoDiscover picker above.
$fileOnlySources = @($xmlSources | Where-Object {
    # Identify sources that came from files (AutoDiscover sources have a Label
    # matching a GPO DisplayName — file sources have a .xml extension in the label)
    $_.Label -match '\.xml$' -or -not $AutoDiscover
})

if ($PickGPOs -and $fileOnlySources.Count -gt 0) {
    Write-Host "  Opening file-source picker..." -ForegroundColor Yellow

    $filePickerInput = $fileOnlySources | ForEach-Object {
        $x = $_.Xml
        [PSCustomObject]@{
            Label        = $_.Label
            GPOName      = $x.GPO.Name
            Domain       = $x.GPO.Identifier.Domain
            GUID         = $x.GPO.Identifier.Identifier.'#text'
            Created      = $x.GPO.CreatedTime
            LastModified = $x.GPO.ModifiedTime
        }
    }

    $selectedFiles = $filePickerInput | Out-GridView -Title "Select XML sources to include — Ctrl/Shift for multi-select" -PassThru

    if (-not $selectedFiles) {
        Write-Warning "No file sources selected in picker — removing all file-based sources."
        # Remove file-based sources from xmlSources
        $xmlSources = [System.Collections.Generic.List[hashtable]]::new(
            @($xmlSources | Where-Object { $fileOnlySources -notcontains $_ })
        )
    } else {
        $selectedLabels = @($selectedFiles | ForEach-Object { $_.Label })
        # Keep only the selected file sources (plus any AutoDiscover sources)
        $xmlSources = [System.Collections.Generic.List[hashtable]]::new(
            @($xmlSources | Where-Object {
                ($fileOnlySources -notcontains $_) -or ($selectedLabels -contains $_.Label)
            })
        )
        Write-Host "  Selected $($selectedFiles.Count) file source(s)." -ForegroundColor Gray
    }
}

# Deduplicate by GPO GUID (auto-discover + explicit file might overlap)
$seenGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueSources = @($xmlSources | Where-Object {
    $tmpXml = $_.Xml
    $guid = $tmpXml.GPO.Identifier.Identifier.'#text'
    if (-not $guid) { $guid = $_.Label }
    $seenGuids.Add($guid)
})

if ($uniqueSources.Count -eq 0) {
    throw "No GPO XML sources found. Use -AutoDiscover, -XmlPaths, or -XmlFolder."
}
Write-Host "  Processing $($uniqueSources.Count) unique GPO(s)." -ForegroundColor Yellow

# ══════════════════════════════════════════════════════
#  STEP 2 — Parse XML → GPO data structures
# ══════════════════════════════════════════════════════
Write-Host "`n[2/5] Parsing GPO XML files..." -ForegroundColor Cyan

$allGpos = @()
foreach ($src in $uniqueSources) {
    try {
        $gpoData = Parse-GpoXml -xml $src.Xml -SourceLabel $src.Label
        $allGpos += $gpoData
        Write-Host "  Parsed: $($gpoData.GpoName) — $($gpoData.RestrictedGroups.Count) restricted group(s), $($gpoData.Links.Count) link(s)" -ForegroundColor Gray
    } catch {
        Write-Warning "Failed to parse '$($src.Label)': $_"
    }
}

# ══════════════════════════════════════════════════════
#  STEP 3 — Recursive AD expansion
# ══════════════════════════════════════════════════════
Write-Host "`n[3/5] Expanding memberships via Active Directory..." -ForegroundColor Cyan

# Master list: each entry tagged with GpoName + RestrictedGroupName
$masterList = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($gpo in $allGpos) {
    foreach ($rg in $gpo.RestrictedGroups) {
        Write-Host "  [$($gpo.GpoName)] Restricted Group: $($rg.GroupName)" -ForegroundColor Yellow

        foreach ($dm in $rg.DirectMembers) {
            $samName    = ($dm.Name -split '\\')[-1]
            $hasNoDomain= ($dm.Name -notmatch '\\')

            Write-Host "    Direct: $($dm.Name)" -ForegroundColor DarkGray

            if ($hasNoDomain) {
                $masterList.Add([PSCustomObject]@{
                    GpoName         = $gpo.GpoName
                    GpoGuid         = $gpo.GpoGuid
                    RestrictedGroup = $rg.GroupName
                    SamAccountName  = $dm.Name
                    DisplayName     = ''; Email = ''
                    ObjectClass     = 'localUser'
                    AccountType     = 'Local Account'
                    SID             = $dm.SID
                    Enabled         = $null; LastLogon = $null
                    ResolutionPath  = $rg.GroupName
                    IsLeaf          = $true
                })
                continue
            }

            # Look up in AD
            $adObj = $null
            try { $adObj = Get-ADObject -Filter "SamAccountName -eq '$samName'" -Server $Domain -EA SilentlyContinue } catch {}
            if (-not $adObj -and $dm.SID) {
                try { $adObj = Get-ADObject -Identity $dm.SID -Server $Domain -EA SilentlyContinue } catch {}
            }
            $objClass = if ($adObj) { $adObj.objectClass } else { 'unknown' }

            if ($objClass -eq 'group') {
                $masterList.Add([PSCustomObject]@{
                    GpoName         = $gpo.GpoName
                    GpoGuid         = $gpo.GpoGuid
                    RestrictedGroup = $rg.GroupName
                    SamAccountName  = $samName
                    DisplayName     = ''; Email = ''
                    ObjectClass     = 'group'
                    AccountType     = 'Domain Group'
                    SID             = $dm.SID
                    Enabled         = $null; LastLogon = $null
                    ResolutionPath  = $rg.GroupName
                    IsLeaf          = $false
                })
                $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($e in (Expand-Group $samName $Domain $visited "$($rg.GroupName) → $samName")) {
                    $e | Add-Member -NotePropertyName GpoName         -NotePropertyValue $gpo.GpoName -Force
                    $e | Add-Member -NotePropertyName GpoGuid         -NotePropertyValue $gpo.GpoGuid -Force
                    $e | Add-Member -NotePropertyName RestrictedGroup -NotePropertyValue $rg.GroupName -Force
                    $masterList.Add($e)
                }
            } else {
                $displayName = $email = ''; $enabled = $null; $lastLogon = $null
                if ($adObj) {
                    try {
                        $u = Get-ADUser $adObj.SID -Server $Domain `
                             -Properties DisplayName,EmailAddress,Enabled,LastLogonDate -EA SilentlyContinue
                        $displayName = $u.DisplayName; $email = $u.EmailAddress
                        $enabled = $u.Enabled; $lastLogon = $u.LastLogonDate
                    } catch {}
                }
                $masterList.Add([PSCustomObject]@{
                    GpoName         = $gpo.GpoName
                    GpoGuid         = $gpo.GpoGuid
                    RestrictedGroup = $rg.GroupName
                    SamAccountName  = $samName
                    DisplayName     = $displayName; Email = $email
                    ObjectClass     = $objClass
                    AccountType     = (Get-AccountType $samName $objClass)
                    SID             = $dm.SID
                    Enabled         = $enabled; LastLogon = $lastLogon
                    ResolutionPath  = $rg.GroupName
                    IsLeaf          = $true
                })
            }
        }
    }
}

# ── Summary numbers ──
$totalLeafAccounts = @($masterList | Where-Object IsLeaf).Count
$totalGroups       = @($masterList | Where-Object { $_.AccountType -eq 'Domain Group' }).Count
$totalDisabled     = @($masterList | Where-Object { $_.Enabled -eq $false }).Count
$totalSvc          = @($masterList | Where-Object { $_.AccountType -eq 'Service Account' }).Count

# Cross-GPO: accounts appearing in more than one GPO
$crossGpoAccounts  = @($masterList | Where-Object IsLeaf |
    Group-Object SamAccountName |
    Where-Object { ($_.Group | Select-Object GpoName -Unique).Count -gt 1 })

# ── CSV export ──
$csvPath = [System.IO.Path]::ChangeExtension($OutputPath, 'csv')
$masterList | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`n[4/5] CSV exported: $csvPath" -ForegroundColor Cyan

# ══════════════════════════════════════════════════════
#  STEP 4 — Build HTML
# ══════════════════════════════════════════════════════
Write-Host "`n[5/5] Building HTML report..." -ForegroundColor Cyan

$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm'
$gpoCount   = $allGpos.Count

# ── Per-GPO accordion sections ──
function Build-MembersTable ([System.Collections.Generic.List[PSCustomObject]]$rows) {
    $html = '<div style="overflow-x:auto;"><table class="members-table"><thead><tr>'
    $html += '<th>#</th><th>sAMAccountName</th><th>Display Name</th><th>Type</th>'
    $html += '<th>Status</th><th>Email</th><th>Last Logon</th><th>SID</th><th>Resolution Path</th>'
    $html += '</tr></thead><tbody>'
    $i = 0
    foreach ($r in $rows) {
        $i++
        $isGroup  = ($r.ObjectClass -eq 'group')
        $rowStyle = if ($isGroup) { ' class="row-group"' } else { '' }
        $indent   = [Math]::Max(0, ($r.ResolutionPath -split '→').Count - 1) * 20
        $samHtml  = if ($isGroup) {
            "<span class='nested-group' style='padding-left:${indent}px'>&#9654; $(Escape-Html $r.SamAccountName)</span>"
        } else {
            "<span style='padding-left:${indent}px'>$(Escape-Html $r.SamAccountName)</span>"
        }
        $ll  = if ($r.LastLogon) { ([datetime]$r.LastLogon).ToString('yyyy-MM-dd') } else { '—' }
        $em  = if ($r.Email)     { Escape-Html $r.Email } else { '—' }
        $dn  = if ($r.DisplayName) { Escape-Html $r.DisplayName } else { '—' }
        $pth = Escape-Html $r.ResolutionPath

        $html += "<tr$rowStyle><td class='num-col'>$i</td>"
        $html += "<td class='mono'>$samHtml</td>"
        $html += "<td>$dn</td>"
        $html += "<td>$(Get-TypeTag $r.AccountType)</td>"
        $html += "<td>$(Get-EnabledBadge $r.Enabled)</td>"
        $html += "<td class='small-text'>$em</td>"
        $html += "<td class='small-text'>$ll</td>"
        $html += "<td class='sid-cell'>$(Escape-Html $r.SID)</td>"
        $html += "<td class='path-cell' title='$pth'>$pth</td></tr>"
    }
    $html += '</tbody></table></div>'
    return $html
}

$gpoSections = ''
$gpoIndex = 0
foreach ($gpo in $allGpos) {
    $gpoIndex++
    $gpoId   = "gpo_$gpoIndex"
    $gpoRows = @($masterList | Where-Object { $_.GpoName -eq $gpo.GpoName })
    $leafCnt = @($gpoRows | Where-Object IsLeaf).Count
    $disabledCnt = @($gpoRows | Where-Object { $_.Enabled -eq $false }).Count

    # Link pills
    $linkPills = ''
    foreach ($lk in $gpo.Links) {
        $cls  = if ($lk.Enabled) { 'link-pill-on' } else { 'link-pill-off' }
        $dot  = if ($lk.Enabled) { '&#9679;' } else { '&#9675;' }
        $noov = if ($lk.NoOverride) { ' <span class="tag-enforced">Enforced</span>' } else { '' }
        $linkPills += "<span class='link-pill $cls'>$dot $(Escape-Html $lk.OUName)$noov<br><small>$(Escape-Html $lk.OUPath)</small></span> "
    }

    # Per restricted-group subsections
    $rgSections = ''
    foreach ($rg in $gpo.RestrictedGroups) {
        $rgRows  = @($gpoRows | Where-Object { $_.RestrictedGroup -eq $rg.GroupName })
        $rgLeafs = @($rgRows | Where-Object IsLeaf).Count
        $rgSections += "<div class='rg-block'>"
        $rgSections += "<div class='rg-header'><span class='rg-icon'>&#128273;</span>"
        $rgSections += "<div><div class='rg-name'>$(Escape-Html $rg.GroupName)</div>"
        $rgSections += "<div class='rg-sid'>SID: $(Escape-Html $rg.GroupSID)</div></div>"
        $rgSections += "<span class='rg-badge'>$($rgRows.Count) entries &bull; $rgLeafs leaf accounts</span></div>"
        $rgSections += (Build-MembersTable ([System.Collections.Generic.List[PSCustomObject]]($rgRows)))
        $rgSections += "</div>"
    }

    $modDate = if ($gpo.ModifiedTime) { $gpo.ModifiedTime } else { '—' }

    $gpoSections += @"
<div class="gpo-accordion" id="$gpoId">
  <div class="gpo-acc-header" onclick="toggleAccordion('$gpoId')">
    <div class="gpo-acc-left">
      <span class="acc-arrow" id="arrow_$gpoId">&#9654;</span>
      <div>
        <div class="gpo-acc-title">$(Escape-Html $gpo.GpoName)</div>
        <div class="gpo-acc-sub">$(Escape-Html $gpo.GpoGuid) &nbsp;|&nbsp; Domain: $(Escape-Html $gpo.GpoDomain) &nbsp;|&nbsp; Modified: $modDate</div>
      </div>
    </div>
    <div class="gpo-acc-badges">
      <span class="acc-badge acc-badge-blue">$($gpo.RestrictedGroups.Count) restricted groups</span>
      <span class="acc-badge acc-badge-green">$leafCnt accounts</span>
      $(if ($disabledCnt -gt 0) { "<span class='acc-badge acc-badge-red'>$disabledCnt disabled</span>" })
    </div>
  </div>
  <div class="gpo-acc-body" id="body_$gpoId" style="display:none;">

    <div class="scope-section">
      <div class="scope-label">&#128205; GPO Scope (OU Links)</div>
      <div class="link-pills">$linkPills</div>
    </div>

    $rgSections
  </div>
</div>
"@
}

# ── Cross-GPO analysis table ──
$crossGpoHtml = ''
if ($crossGpoAccounts.Count -gt 0) {
    $crossGpoHtml = '<div class="analysis-card warn"><div class="analysis-title">&#9888;&#65039; Accounts Present in Multiple GPOs</div><div style="overflow-x:auto;"><table class="members-table"><thead><tr><th>sAMAccountName</th><th>GPOs</th><th>Type</th><th>Status</th><th>Email</th></tr></thead><tbody>'
    foreach ($grp in $crossGpoAccounts) {
        $sample  = $grp.Group[0]
        $gpoList = ($grp.Group | Select-Object GpoName -Unique | ForEach-Object { "<span class='gpo-chip'>$(Escape-Html $_.GpoName)</span>" }) -join ' '
        $crossGpoHtml += "<tr><td class='mono'>$(Escape-Html $sample.SamAccountName)</td><td>$gpoList</td><td>$(Get-TypeTag $sample.AccountType)</td><td>$(Get-EnabledBadge $sample.Enabled)</td><td class='small-text'>$(if($sample.Email){Escape-Html $sample.Email}else{'—'})</td></tr>"
    }
    $crossGpoHtml += '</tbody></table></div></div>'
} else {
    $crossGpoHtml = '<div class="analysis-card ok"><div class="analysis-title">&#10003; No accounts appear in multiple GPOs</div></div>'
}

# Disabled accounts with access
$disabledRows = @($masterList | Where-Object { $_.Enabled -eq $false } | Sort-Object SamAccountName -Unique)
$disabledHtml = ''
if ($disabledRows.Count -gt 0) {
    $disabledHtml = '<div class="analysis-card danger"><div class="analysis-title">&#128683; Disabled Accounts with Local Admin Access</div><div style="overflow-x:auto;"><table class="members-table"><thead><tr><th>sAMAccountName</th><th>Display Name</th><th>GPO</th><th>Restricted Group</th><th>Resolution Path</th></tr></thead><tbody>'
    foreach ($r in $disabledRows) {
        $disabledHtml += "<tr><td class='mono'>$(Escape-Html $r.SamAccountName)</td><td>$(if($r.DisplayName){Escape-Html $r.DisplayName}else{'—'})</td><td><span class='gpo-chip'>$(Escape-Html $r.GpoName)</span></td><td class='mono'>$(Escape-Html $r.RestrictedGroup)</td><td class='path-cell'>$(Escape-Html $r.ResolutionPath)</td></tr>"
    }
    $disabledHtml += '</tbody></table></div></div>'
} else {
    $disabledHtml = '<div class="analysis-card ok"><div class="analysis-title">&#10003; No disabled accounts found with local admin access</div></div>'
}

# Service account summary
$svcRows = @($masterList | Where-Object { $_.AccountType -eq 'Service Account' } |
    Group-Object SamAccountName | ForEach-Object { $_.Group[0] } | Sort-Object SamAccountName)
$svcHtml = ''
if ($svcRows.Count -gt 0) {
    $svcHtml = '<div class="analysis-card info"><div class="analysis-title">&#9881; Service Accounts with Local Admin Access</div><div style="overflow-x:auto;"><table class="members-table"><thead><tr><th>sAMAccountName</th><th>GPO(s)</th><th>Restricted Group</th><th>Status</th></tr></thead><tbody>'
    foreach ($r in $svcRows) {
        $gposForSvc = ($masterList | Where-Object { $_.SamAccountName -eq $r.SamAccountName } |
            Select-Object GpoName -Unique | ForEach-Object { "<span class='gpo-chip'>$(Escape-Html $_.GpoName)</span>" }) -join ' '
        $svcHtml += "<tr><td class='mono'>$(Escape-Html $r.SamAccountName)</td><td>$gposForSvc</td><td class='mono'>$(Escape-Html $r.RestrictedGroup)</td><td>$(Get-EnabledBadge $r.Enabled)</td></tr>"
    }
    $svcHtml += '</tbody></table></div></div>'
}

# ── By-OU view ──
# Build a map: OUPath → list of {Gpo, Link} entries
$ouMap = @{}
foreach ($gpo in $allGpos) {
    foreach ($lk in $gpo.Links) {
        $key = $lk.OUPath
        if (-not $ouMap.ContainsKey($key)) {
            $ouMap[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $ouMap[$key].Add([PSCustomObject]@{ Gpo = $gpo; Link = $lk })
    }
}

$ouSections = ''
$ouIndex = 0
foreach ($ouPath in ($ouMap.Keys | Sort-Object)) {
    $ouIndex++
    $ouId      = "ou_$ouIndex"
    $entries   = $ouMap[$ouPath]
    $ouName    = $entries[0].Link.OUName

    $linkedGpoNames = @($entries | ForEach-Object { $_.Gpo.GpoName })
    $ouRows     = @($masterList | Where-Object { $linkedGpoNames -contains $_.GpoName })
    $ouLeafs    = @($ouRows | Where-Object IsLeaf).Count
    $ouDisabled = @($ouRows | Where-Object { $_.Enabled -eq $false }).Count

    # GPO pills for this OU
    $ouGpoPills = ''
    foreach ($entry in $entries) {
        $lk   = $entry.Link
        $cls  = if ($lk.Enabled) { 'link-pill-on' } else { 'link-pill-off' }
        $dot  = if ($lk.Enabled) { '&#9679;' } else { '&#9675;' }
        $noov = if ($lk.NoOverride) { ' <span class="tag-enforced">Enforced</span>' } else { '' }
        $ouGpoPills += "<span class='link-pill $cls'>$dot $(Escape-Html $entry.Gpo.GpoName)$noov</span> "
    }

    # Per restricted-group subsections within this OU
    $ouRgSections = ''
    foreach ($entry in $entries) {
        $gpo = $entry.Gpo
        foreach ($rg in $gpo.RestrictedGroups) {
            $rgRows = @($ouRows | Where-Object { $_.GpoName -eq $gpo.GpoName -and $_.RestrictedGroup -eq $rg.GroupName })
            if ($rgRows.Count -eq 0) { continue }
            $rgLeafs = @($rgRows | Where-Object IsLeaf).Count
            $ouRgSections += "<div class='rg-block'>"
            $ouRgSections += "<div class='rg-header'><span class='rg-icon'>&#128273;</span>"
            $ouRgSections += "<div><div class='rg-name'>$(Escape-Html $rg.GroupName)</div>"
            $ouRgSections += "<div class='rg-sid'><span class='gpo-chip'>$(Escape-Html $gpo.GpoName)</span> &nbsp; SID: $(Escape-Html $rg.GroupSID)</div></div>"
            $ouRgSections += "<span class='rg-badge'>$($rgRows.Count) entries &bull; $rgLeafs leaf accounts</span></div>"
            $ouRgSections += (Build-MembersTable ([System.Collections.Generic.List[PSCustomObject]]($rgRows)))
            $ouRgSections += "</div>"
        }
    }

    $ouSections += @"
<div class="gpo-accordion" id="$ouId">
  <div class="gpo-acc-header" onclick="toggleAccordion('$ouId')">
    <div class="gpo-acc-left">
      <span class="acc-arrow" id="arrow_$ouId">&#9654;</span>
      <div>
        <div class="gpo-acc-title">$(Escape-Html $ouName)</div>
        <div class="gpo-acc-sub">$(Escape-Html $ouPath)</div>
      </div>
    </div>
    <div class="gpo-acc-badges">
      <span class="acc-badge acc-badge-blue">$($entries.Count) GPO(s)</span>
      <span class="acc-badge acc-badge-green">$ouLeafs accounts</span>
      $(if ($ouDisabled -gt 0) { "<span class='acc-badge acc-badge-red'>$ouDisabled disabled</span>" })
    </div>
  </div>
  <div class="gpo-acc-body" id="body_$ouId" style="display:none;">
    <div class="scope-section">
      <div class="scope-label">&#128230; GPOs Linked to This OU</div>
      <div class="link-pills">$ouGpoPills</div>
    </div>
    $ouRgSections
  </div>
</div>
"@
}

# ══════════════════════════════════════════════════════
#  Final HTML assembly
# ══════════════════════════════════════════════════════
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Restricted Groups Audit – $gpoCount GPO(s)</title>
<style>
:root {
  --bg:#0f1117; --surface:#1a1d27; --surface2:#22263a; --border:#2e3350;
  --accent:#4f6ef7; --accent2:#7c3aed; --green:#22c55e; --red:#ef4444;
  --yellow:#f59e0b; --text:#e2e8f0; --muted:#8892a4;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem;line-height:1.5;}

/* Header */
.header{background:linear-gradient(135deg,#1a1d27,#22263a);border:1px solid var(--border);border-radius:12px;padding:2rem 2.5rem;margin-bottom:2rem;position:relative;overflow:hidden;}
.header::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));}
.header-title{font-size:1.7rem;font-weight:700;background:linear-gradient(135deg,#e2e8f0,#94a3b8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.header-sub{color:var(--muted);font-size:.9rem;margin-top:.3rem;}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-top:1.5rem;padding-top:1.5rem;border-top:1px solid var(--border);}
.meta-item label{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);display:block;margin-bottom:.2rem;}
.meta-item value{font-size:.88rem;font-weight:500;font-family:'Consolas',monospace;}

/* Stats */
.summary-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1.5rem;text-align:center;}
.stat-card .num{font-size:2.2rem;font-weight:800;line-height:1;margin-bottom:.25rem;}
.stat-card .lbl{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;}
.c-blue{color:var(--accent)} .c-purple{color:#a78bfa} .c-green{color:var(--green)} .c-orange{color:#fb923c} .c-red{color:var(--red)}

/* Section title */
.section-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:1.5rem 0 .75rem;display:flex;align-items:center;gap:.5rem;}
.section-title::after{content:'';flex:1;height:1px;background:var(--border);}

/* Search */
.search-bar{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:.7rem 1rem .7rem 2.5rem;color:var(--text);font-size:.9rem;margin-bottom:1.25rem;outline:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238892a4' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:.8rem center;}
.search-bar:focus{border-color:var(--accent);}

/* Accordion */
.gpo-accordion{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:1rem;overflow:hidden;}
.gpo-acc-header{padding:1.2rem 1.5rem;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;user-select:none;transition:background .15s;}
.gpo-acc-header:hover{background:var(--surface2);}
.gpo-acc-left{display:flex;align-items:center;gap:.9rem;}
.acc-arrow{font-size:.8rem;color:var(--muted);transition:transform .2s;display:inline-block;}
.acc-arrow.open{transform:rotate(90deg);}
.gpo-acc-title{font-weight:600;font-size:1rem;font-family:'Consolas',monospace;}
.gpo-acc-sub{font-size:.72rem;color:var(--muted);margin-top:.2rem;}
.gpo-acc-badges{display:flex;gap:.5rem;flex-wrap:wrap;}
.acc-badge{font-size:.72rem;font-weight:700;padding:.2rem .6rem;border-radius:999px;}
.acc-badge-blue{background:rgba(79,110,247,.2);color:#7c9ffe;}
.acc-badge-green{background:rgba(34,197,94,.15);color:var(--green);}
.acc-badge-red{background:rgba(239,68,68,.15);color:var(--red);}
.gpo-acc-body{padding:1.5rem;border-top:1px solid var(--border);}

/* Scope links */
.scope-section{margin-bottom:1.5rem;}
.scope-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:.6rem;}
.link-pills{display:flex;flex-wrap:wrap;gap:.5rem;}
.link-pill{padding:.4rem .8rem;border-radius:6px;font-size:.78rem;line-height:1.4;}
.link-pill small{font-family:'Consolas',monospace;font-size:.68rem;opacity:.7;}
.link-pill-on{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3);color:#86efac;}
.link-pill-off{background:rgba(75,85,99,.2);border:1px solid rgba(75,85,99,.4);color:#6b7280;}
.tag-enforced{background:rgba(245,158,11,.2);color:#fbbf24;font-size:.65rem;padding:.1rem .35rem;border-radius:3px;margin-left:.3rem;font-weight:700;}

/* Restricted group block */
.rg-block{margin-bottom:1.5rem;border:1px solid var(--border);border-radius:10px;overflow:hidden;}
.rg-header{background:var(--surface2);padding:1rem 1.25rem;display:flex;align-items:center;gap:.9rem;border-bottom:1px solid var(--border);flex-wrap:wrap;}
.rg-icon{width:36px;height:36px;border-radius:7px;background:linear-gradient(135deg,#4f6ef7,#7c3aed);display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0;}
.rg-name{font-weight:600;font-family:'Consolas',monospace;font-size:.95rem;}
.rg-sid{font-size:.7rem;color:var(--muted);font-family:'Consolas',monospace;margin-top:.1rem;}
.rg-badge{margin-left:auto;background:var(--accent);color:#fff;font-size:.72rem;font-weight:700;padding:.2rem .65rem;border-radius:999px;}

/* Table */
.members-table{width:100%;border-collapse:collapse;}
.members-table th{padding:.65rem 1rem;text-align:left;font-size:.67rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:rgba(255,255,255,.02);border-bottom:1px solid var(--border);white-space:nowrap;}
.members-table td{padding:.8rem 1rem;border-bottom:1px solid rgba(46,51,80,.4);vertical-align:middle;}
.members-table tr:last-child td{border-bottom:none;}
.members-table tr:hover td{background:rgba(79,110,247,.05);}
.row-group td{background:rgba(79,110,247,.04);}
.num-col{color:var(--muted);font-size:.78rem;text-align:center;width:36px;}
.mono{font-family:'Consolas',monospace;font-size:.85rem;}
.small-text{font-size:.8rem;color:var(--muted);}
.sid-cell{font-family:'Consolas',monospace;font-size:.68rem;color:var(--muted);max-width:230px;word-break:break-all;}
.path-cell{font-size:.72rem;color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:default;}
.nested-group{color:#a78bfa;font-weight:700;}

/* Tags & badges */
.tag{display:inline-flex;align-items:center;gap:.25rem;padding:.18rem .55rem;border-radius:4px;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;}
.tag-user{background:#1e3a5f;color:#60a5fa;}
.tag-group{background:#2d1b69;color:#a78bfa;}
.tag-svc{background:#1a3a2a;color:#4ade80;}
.tag-local{background:#3b2200;color:#fb923c;}
.tag-comp{background:#1a2a3b;color:#38bdf8;}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.7rem;font-weight:700;text-transform:uppercase;}
.badge-on{background:rgba(34,197,94,.15);color:var(--green);}
.badge-off{background:rgba(239,68,68,.15);color:var(--red);}
.badge-na{background:rgba(139,146,164,.1);color:var(--muted);}

/* Analysis cards */
.analysis-card{border-radius:10px;margin-bottom:1rem;overflow:hidden;border:1px solid;}
.analysis-title{padding:.85rem 1.25rem;font-size:.82rem;font-weight:600;}
.analysis-card.warn{border-color:rgba(245,158,11,.3);}.analysis-card.warn .analysis-title{background:rgba(245,158,11,.1);color:#fbbf24;}
.analysis-card.danger{border-color:rgba(239,68,68,.3);}.analysis-card.danger .analysis-title{background:rgba(239,68,68,.1);color:#f87171;}
.analysis-card.info{border-color:rgba(79,110,247,.3);}.analysis-card.info .analysis-title{background:rgba(79,110,247,.1);color:#7c9ffe;}
.analysis-card.ok{border-color:rgba(34,197,94,.25);}.analysis-card.ok .analysis-title{background:rgba(34,197,94,.08);color:var(--green);}
.analysis-card .members-table td,.analysis-card .members-table th{padding:.6rem 1rem;}

/* GPO chips */
.gpo-chip{display:inline-block;background:rgba(79,110,247,.15);border:1px solid rgba(79,110,247,.3);color:#7c9ffe;padding:.1rem .45rem;border-radius:4px;font-size:.72rem;margin:.1rem;}

/* Legend */
.legend{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1rem;}

/* Tab nav */
.tab-nav{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap;}
.tab-btn{padding:.5rem 1.1rem;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;font-size:.82rem;font-weight:600;transition:all .15s;}
.tab-btn:hover{border-color:var(--accent);color:var(--text);}
.tab-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;}
.tab-panel{display:none;} .tab-panel.active{display:block;}

.footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--border);text-align:center;color:var(--muted);font-size:.75rem;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-title">&#128737;&#65039; Restricted Groups Audit</div>
  <div class="header-sub">Recursive Active Directory Membership Expansion &mdash; $gpoCount GPO(s)</div>
  <div class="meta-grid">
    <div class="meta-item"><label>Domain</label><value>$Domain</value></div>
    <div class="meta-item"><label>GPOs Processed</label><value>$gpoCount</value></div>
    <div class="meta-item"><label>Name Filter</label><value>$NameFilter</value></div>
    <div class="meta-item"><label>Report Generated</label><value>$reportDate</value></div>
  </div>
</div>

<!-- SUMMARY STATS -->
<div class="summary-row">
  <div class="stat-card"><div class="num c-blue">$gpoCount</div><div class="lbl">GPOs</div></div>
  <div class="stat-card"><div class="num c-purple">$totalLeafAccounts</div><div class="lbl">Leaf Accounts</div></div>
  <div class="stat-card"><div class="num c-green">$totalSvc</div><div class="lbl">Service Accounts</div></div>
  <div class="stat-card"><div class="num c-orange">$($crossGpoAccounts.Count)</div><div class="lbl">Cross-GPO Accounts</div></div>
  <div class="stat-card"><div class="num c-red">$totalDisabled</div><div class="lbl">Disabled Accounts</div></div>
</div>

<!-- TABS -->
<div class="tab-nav">
  <button class="tab-btn active" onclick="switchTab('tab-gpos',this)">&#128230; GPO Memberships</button>
  <button class="tab-btn" onclick="switchTab('tab-analysis',this)">&#128202; Analysis</button>
  <button class="tab-btn" onclick="switchTab('tab-ou',this)">&#128205; By OU</button>
</div>

<!-- TAB: GPO Memberships -->
<div id="tab-gpos" class="tab-panel active">
  <div class="legend">
    <span class="tag tag-group">&#127991; Domain Group</span>
    <span class="tag tag-user">&#128100; User Account</span>
    <span class="tag tag-svc">&#9881; Service Account</span>
    <span class="tag tag-local">&#127968; Local Account</span>
    <span class="tag tag-comp">&#128187; Computer</span>
  </div>
  <input class="search-bar" type="text" id="searchBox" placeholder="Filter by name, SID, email, path, GPO..." oninput="filterAll()">
  <div id="gpo-list">
    $gpoSections
  </div>
</div>

<!-- TAB: Analysis -->
<div id="tab-analysis" class="tab-panel">

  <div class="section-title">Cross-GPO Account Overlap</div>
  $crossGpoHtml

  <div class="section-title">Disabled Accounts</div>
  $disabledHtml

  <div class="section-title">Service Accounts</div>
  $svcHtml

</div>

<!-- TAB: By OU -->
<div id="tab-ou" class="tab-panel">
  <div class="legend">
    <span class="tag tag-group">&#127991; Domain Group</span>
    <span class="tag tag-user">&#128100; User Account</span>
    <span class="tag tag-svc">&#9881; Service Account</span>
    <span class="tag tag-local">&#127968; Local Account</span>
    <span class="tag tag-comp">&#128187; Computer</span>
  </div>
  <div id="ou-list">
    $ouSections
    $(if (-not $ouSections) {
      '<div class="analysis-card ok" style="margin-top:1rem;"><div class="analysis-title">&#128205; No OU links found in the processed GPOs. GPOs must be linked to at least one OU for this view to populate.</div></div>'
    })
  </div>
</div>

<div class="footer">
  Restricted Groups Audit &nbsp;|&nbsp; Domain: $Domain &nbsp;|&nbsp; $gpoCount GPO(s) &nbsp;|&nbsp; Generated: $reportDate
</div>

<script>
// Tab switching
function switchTab(id, btn) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}

// Accordion toggle
function toggleAccordion(id) {
  const body  = document.getElementById('body_'  + id);
  const arrow = document.getElementById('arrow_' + id);
  const open  = body.style.display !== 'none';
  body.style.display  = open ? 'none' : 'block';
  arrow.classList.toggle('open', !open);
}

// Global filter — expands matching accordions
function filterAll() {
  const q = document.getElementById('searchBox').value.toLowerCase().trim();
  document.querySelectorAll('.gpo-accordion').forEach(acc => {
    const body   = acc.querySelector('[id^="body_"]');
    const arrow  = acc.querySelector('.acc-arrow');
    const rows   = acc.querySelectorAll('.members-table tbody tr');
    let anyMatch = false;
    rows.forEach(row => {
      const match = !q || row.textContent.toLowerCase().includes(q);
      row.style.display = match ? '' : 'none';
      if (match) anyMatch = true;
    });
    if (q) {
      body.style.display = anyMatch ? 'block' : 'none';
      if (anyMatch) arrow.classList.add('open'); else arrow.classList.remove('open');
      acc.style.display = anyMatch ? '' : 'none';
    } else {
      acc.style.display = '';
      body.style.display = 'none';
      arrow.classList.remove('open');
    }
  });
}
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
Write-Host "  Report: $OutputPath" -ForegroundColor Green
Write-Host "`nDone.`n" -ForegroundColor Green
