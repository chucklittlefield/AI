<#
.SYNOPSIS
    Finds all GPOs in the domain that are not linked to any OU, site, or domain root,
    and produces a self-contained HTML report and an Excel workbook.

.DESCRIPTION
    Uses AD gPLink attribute queries instead of per-GPO XML reports, so it runs quickly
    even in large environments. Searches the domain root, all OUs, and all AD Sites for
    GPO links, then compares against the full GPO list to identify unlinked objects.

    Excel output requires the ImportExcel module (Install-Module ImportExcel).
    If the module is not present the script emits a CSV instead and warns you.

.PARAMETER Domain
    AD domain to query. Defaults to the current user's domain.

.PARAMETER OutputPath
    Full path for the HTML report.
    Default: <script dir>\UnassignedGPOs_<timestamp>.html

.PARAMETER ExcelPath
    Full path for the Excel workbook.
    Default: <script dir>\UnassignedGPOs_<timestamp>.xlsx

.PARAMETER IncludeSites
    Switch. Also scans AD Sites for GPO links (requires access to the Configuration
    partition). On by default; suppress with -IncludeSites:$false if Sites are not used.

.EXAMPLE
    .\UnassignedGPOs.ps1

.EXAMPLE
    .\UnassignedGPOs.ps1 -Domain corp.contoso.com -OutputPath C:\Reports\unlinked.html

.NOTES
    Requires: ActiveDirectory module, GroupPolicy module
    Excel:    ImportExcel module (optional — falls back to CSV if absent)
#>

#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
param(
    [string]$Domain = $env:USERDNSDOMAIN,

    [string]$OutputPath = (Join-Path $PSScriptRoot (
        "UnassignedGPOs_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmm')
    )),

    [string]$ExcelPath = (Join-Path $PSScriptRoot (
        "UnassignedGPOs_{0}.xlsx" -f (Get-Date -Format 'yyyyMMdd_HHmm')
    )),

    [switch]$IncludeSites = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

function Escape-Html ([string]$s) {
    if (-not $s) { return '' }
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

# Extract {GUID} tokens from a gPLink string
function Get-GuidsFromGpLink ([string]$gpLink) {
    if (-not $gpLink) { return @() }
    [regex]::Matches($gpLink, '\{[0-9A-Fa-f\-]+\}') | ForEach-Object { $_.Value.ToUpper() }
}

function Get-StatusBadge ([string]$status) {
    switch ($status) {
        'AllSettingsEnabled'          { return '<span class="badge badge-on">All Enabled</span>' }
        'UserSettingsDisabled'        { return '<span class="badge badge-warn">User Disabled</span>' }
        'ComputerSettingsDisabled'    { return '<span class="badge badge-warn">Computer Disabled</span>' }
        'AllSettingsDisabled'         { return '<span class="badge badge-off">All Disabled</span>' }
        default                       { return "<span class='badge badge-na'>$status</span>" }
    }
}

# ══════════════════════════════════════════════════════
#  STEP 1 — Collect all linked GPO GUIDs from AD
# ══════════════════════════════════════════════════════
Write-Host "`n[1/4] Collecting GPO links from Active Directory..." -ForegroundColor Cyan

$linkedGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Domain root
Write-Host "  Querying domain root..." -ForegroundColor Gray
$domainObj = Get-ADDomain -Server $Domain
$rootDN    = $domainObj.DistinguishedName
$rootAD    = Get-ADObject -Identity $rootDN -Properties gPLink -Server $Domain
foreach ($g in (Get-GuidsFromGpLink $rootAD.gPLink)) { $linkedGuids.Add($g) | Out-Null }
Write-Host "    Domain root links: $($linkedGuids.Count)" -ForegroundColor DarkGray

# All OUs
Write-Host "  Querying all OUs..." -ForegroundColor Gray
$ouCount = 0
Get-ADOrganizationalUnit -Filter * -Properties gPLink -Server $Domain | ForEach-Object {
    $ouCount++
    foreach ($g in (Get-GuidsFromGpLink $_.gPLink)) { $linkedGuids.Add($g) | Out-Null }
}
Write-Host "    OUs scanned: $ouCount" -ForegroundColor DarkGray

# AD Sites (Configuration partition)
if ($IncludeSites) {
    Write-Host "  Querying AD Sites..." -ForegroundColor Gray
    try {
        $sitesBase = "CN=Sites,CN=Configuration,$rootDN"
        $siteCount = 0
        Get-ADObject -Filter * -SearchBase $sitesBase -Properties gPLink -Server $Domain -EA SilentlyContinue |
            ForEach-Object {
                $siteCount++
                foreach ($g in (Get-GuidsFromGpLink $_.gPLink)) { $linkedGuids.Add($g) | Out-Null }
            }
        Write-Host "    Site objects scanned: $siteCount" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not query AD Sites: $_"
    }
}

Write-Host "  Total unique linked GPO GUIDs: $($linkedGuids.Count)" -ForegroundColor Yellow

# ══════════════════════════════════════════════════════
#  STEP 2 — Get all GPOs and identify unlinked ones
# ══════════════════════════════════════════════════════
Write-Host "`n[2/4] Retrieving all GPOs..." -ForegroundColor Cyan

$allGpos = @(Get-GPO -All -Domain $Domain | Sort-Object DisplayName)
Write-Host "  Total GPOs in domain: $($allGpos.Count)" -ForegroundColor Gray

$unlinked = @($allGpos | Where-Object {
    $guidKey = "{$($_.Id.ToString().ToUpper())}"
    -not $linkedGuids.Contains($guidKey)
})

Write-Host "  Unlinked GPOs found: $($unlinked.Count)" -ForegroundColor Yellow

# Safe property helper — returns $null without throwing under Set-StrictMode
function Get-GpoProp ([object]$Gpo, [string]$Name) {
    $p = $Gpo.PSObject.Properties[$Name]
    if ($p) { return $p.Value } else { return $null }
}

# Build enriched result objects
$results = foreach ($gpo in $unlinked) {
    $createTime = Get-GpoProp $gpo 'CreationTime'
    $modTime    = Get-GpoProp $gpo 'ModificationTime'
    $wmiObj     = Get-GpoProp $gpo 'WmiFilter'
    $wmiFilter  = if ($wmiObj) { "$((Get-GpoProp $wmiObj 'Name') ?? '')" } else { '' }

    [PSCustomObject]@{
        Name          = "$((Get-GpoProp $gpo 'DisplayName') ?? '')"
        GUID          = "{$($gpo.Id)}"
        Status        = "$((Get-GpoProp $gpo 'GpoStatus') ?? 'Unknown')"
        Created       = if ($createTime) { $createTime.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
        Modified      = if ($modTime)    { $modTime.ToString('yyyy-MM-dd HH:mm') }    else { 'N/A' }
        Owner         = "$((Get-GpoProp $gpo 'Owner') ?? '')"
        WmiFilter     = $wmiFilter
        Description   = "$((Get-GpoProp $gpo 'Description') ?? '')"
        DaysSinceEdit = if ($modTime) { [int]((Get-Date) - $modTime).TotalDays } else { -1 }
    }
}

# Summary breakdowns
$totalAll      = $allGpos.Count
$totalUnlinked = $unlinked.Count
$cntDisabled   = @($results | Where-Object { $_.Status -eq 'AllSettingsDisabled' }).Count
$cntPartial    = @($results | Where-Object { $_.Status -in 'UserSettingsDisabled','ComputerSettingsDisabled' }).Count
$cntEnabled    = @($results | Where-Object { $_.Status -eq 'AllSettingsEnabled' }).Count
$cntStale      = @($results | Where-Object { $_.DaysSinceEdit -gt 365 }).Count

# ══════════════════════════════════════════════════════
#  STEP 3 — Export Excel / CSV
# ══════════════════════════════════════════════════════
Write-Host "`n[3/4] Exporting data..." -ForegroundColor Cyan

$exportData = $results | Select-Object Name, GUID, Status, Created, Modified, DaysSinceEdit, Owner, WmiFilter, Description

$csvPath = [System.IO.Path]::ChangeExtension($ExcelPath, 'csv')

$hasImportExcel = $null -ne (Get-Module -ListAvailable -Name ImportExcel)

if ($hasImportExcel) {
    Import-Module ImportExcel -EA Stop

    $excelParams = @{
        Path          = $ExcelPath
        WorksheetName = 'Unlinked GPOs'
        TableName     = 'UnlinkedGPOs'
        TableStyle    = 'Medium9'
        AutoSize      = $true
        FreezeTopRow  = $true
        BoldTopRow    = $true
        PassThru      = $true
    }

    $xl = $exportData | Export-Excel @excelParams

    # Conditional formatting — highlight fully-disabled rows red
    $ws = $xl.Workbook.Worksheets['Unlinked GPOs']
    $lastRow = $ws.Dimension.End.Row

    for ($row = 2; $row -le $lastRow; $row++) {
        $statusVal = $ws.Cells[$row, 3].Value
        $color = switch ($statusVal) {
            'AllSettingsDisabled'       { [System.Drawing.Color]::FromArgb(80, 239, 68, 68) }
            'UserSettingsDisabled'      { [System.Drawing.Color]::FromArgb(80, 245, 158, 11) }
            'ComputerSettingsDisabled'  { [System.Drawing.Color]::FromArgb(80, 245, 158, 11) }
            default                     { $null }
        }
        if ($color) {
            $ws.Cells[$row, 1, $row, $ws.Dimension.End.Column].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $ws.Cells[$row, 1, $row, $ws.Dimension.End.Column].Style.Fill.BackgroundColor.SetColor($color)
        }
        # Highlight stale GPOs (>365 days) with italic
        $days = $ws.Cells[$row, 6].Value
        if ($days -gt 365) {
            $ws.Cells[$row, 1].Style.Font.Italic = $true
        }
    }

    # Summary sheet
    $summaryData = [PSCustomObject]@{
        'Total GPOs in Domain' = $totalAll
        'Unlinked GPOs'        = $totalUnlinked
        'All Settings Enabled' = $cntEnabled
        'Partially Disabled'   = $cntPartial
        'All Settings Disabled'= $cntDisabled
        'Stale (>365 days)'    = $cntStale
        'Report Date'          = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        'Domain'               = $Domain
    }
    $summaryData | Export-Excel -ExcelPackage $xl -WorksheetName 'Summary' -AutoSize -BoldTopRow

    Close-ExcelPackage $xl
    Write-Host "  Excel: $ExcelPath" -ForegroundColor Green
} else {
    Write-Warning "ImportExcel module not found. Install it with: Install-Module ImportExcel"
    Write-Warning "Falling back to CSV export: $csvPath"
    $exportData | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV:   $csvPath" -ForegroundColor Yellow
}

# ══════════════════════════════════════════════════════
#  STEP 4 — Build HTML report
# ══════════════════════════════════════════════════════
Write-Host "`n[4/4] Building HTML report..." -ForegroundColor Cyan

$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm'

# Build table rows
$tableRows = ''
foreach ($r in ($results | Sort-Object DaysSinceEdit -Descending)) {
    $rowClass = switch ($r.Status) {
        'AllSettingsDisabled'       { ' class="row-disabled"' }
        'UserSettingsDisabled'      { ' class="row-partial"' }
        'ComputerSettingsDisabled'  { ' class="row-partial"' }
        default                     { '' }
    }
    $staleFlag  = if ($r.DaysSinceEdit -gt 365) { ' <span class="stale-flag">Stale</span>' } else { '' }
    $wmi        = if ($r.WmiFilter)   { "<span class='wmi-chip'>$(Escape-Html $r.WmiFilter)</span>" } else { '<span class="na">—</span>' }
    $desc       = if ($r.Description) { Escape-Html $r.Description } else { '<span class="na">—</span>' }
    $owner      = if ($r.Owner)       { Escape-Html ($r.Owner -replace '^.+\\','') } else { '<span class="na">—</span>' }

    $tableRows += "<tr$rowClass>"
    $tableRows += "<td class='name-col'>$(Escape-Html $r.Name)$staleFlag</td>"
    $tableRows += "<td class='mono guid-col'>$(Escape-Html $r.GUID)</td>"
    $tableRows += "<td>$(Get-StatusBadge $r.Status)</td>"
    $tableRows += "<td class='date-col'>$($r.Modified)</td>"
    $tableRows += "<td class='days-col'>$($r.DaysSinceEdit)d</td>"
    $tableRows += "<td class='owner-col'>$owner</td>"
    $tableRows += "<td>$wmi</td>"
    $tableRows += "<td class='desc-col'>$desc</td>"
    $tableRows += "</tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Unlinked GPO Audit – $Domain</title>
<style>
:root {
  --bg:#0f1117; --surface:#1a1d27; --surface2:#22263a; --border:#2e3350;
  --accent:#4f6ef7; --accent2:#7c3aed; --green:#22c55e; --red:#ef4444;
  --yellow:#f59e0b; --orange:#fb923c; --text:#e2e8f0; --muted:#8892a4;
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
.c-blue{color:var(--accent)} .c-purple{color:#a78bfa} .c-green{color:var(--green)}
.c-orange{color:var(--orange)} .c-red{color:var(--red)} .c-yellow{color:var(--yellow)}

/* Search */
.search-bar{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:.7rem 1rem .7rem 2.5rem;color:var(--text);font-size:.9rem;margin-bottom:1.25rem;outline:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238892a4' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:.8rem center;}
.search-bar:focus{border-color:var(--accent);}

/* Filter pills */
.filter-row{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1.25rem;align-items:center;}
.filter-lbl{font-size:.75rem;color:var(--muted);margin-right:.25rem;}
.filter-pill{padding:.35rem .85rem;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;font-size:.75rem;font-weight:600;transition:all .15s;}
.filter-pill:hover{border-color:var(--accent);color:var(--text);}
.filter-pill.active{background:var(--accent);border-color:var(--accent);color:#fff;}

/* Table */
.table-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border);}
table{width:100%;border-collapse:collapse;}
th{padding:.7rem 1rem;text-align:left;font-size:.67rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;}
th:hover{color:var(--text);}
th .sort-arrow{margin-left:.3rem;opacity:.4;font-size:.6rem;}
th.sorted .sort-arrow{opacity:1;color:var(--accent);}
td{padding:.85rem 1rem;border-bottom:1px solid rgba(46,51,80,.4);vertical-align:middle;font-size:.85rem;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(79,110,247,.05);}
tr.row-disabled td{background:rgba(239,68,68,.04);}
tr.row-disabled:hover td{background:rgba(239,68,68,.08);}
tr.row-partial td{background:rgba(245,158,11,.04);}
tr.row-partial:hover td{background:rgba(245,158,11,.08);}
.name-col{font-weight:500;min-width:220px;}
.guid-col{font-size:.72rem;color:var(--muted);min-width:280px;word-break:break-all;}
.date-col{white-space:nowrap;font-size:.8rem;color:var(--muted);}
.days-col{text-align:right;font-family:'Consolas',monospace;font-size:.8rem;min-width:60px;}
.owner-col{font-size:.8rem;color:var(--muted);}
.desc-col{font-size:.78rem;color:var(--muted);max-width:260px;}
.mono{font-family:'Consolas',monospace;}
.na{color:rgba(136,146,164,.4);}

/* Badges */
.badge{display:inline-block;padding:.18rem .55rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;}
.badge-on{background:rgba(34,197,94,.15);color:var(--green);}
.badge-off{background:rgba(239,68,68,.15);color:var(--red);}
.badge-warn{background:rgba(245,158,11,.15);color:var(--yellow);}
.badge-na{background:rgba(139,146,164,.1);color:var(--muted);}

/* Chips */
.wmi-chip{display:inline-block;background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.3);color:#c4b5fd;padding:.1rem .45rem;border-radius:4px;font-size:.72rem;}
.stale-flag{display:inline-block;background:rgba(251,146,60,.15);border:1px solid rgba(251,146,60,.3);color:var(--orange);padding:.08rem .4rem;border-radius:3px;font-size:.65rem;font-weight:700;text-transform:uppercase;margin-left:.4rem;vertical-align:middle;}

/* Row count */
.row-count{font-size:.78rem;color:var(--muted);margin-bottom:.6rem;}
.row-count span{color:var(--text);font-weight:600;}

.footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--border);text-align:center;color:var(--muted);font-size:.75rem;}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-title">&#128230; Unlinked GPO Audit</div>
  <div class="header-sub">Group Policy Objects with no OU, site, or domain-root links &mdash; $Domain</div>
  <div class="meta-grid">
    <div class="meta-item"><label>Domain</label><value>$Domain</value></div>
    <div class="meta-item"><label>Total GPOs</label><value>$totalAll</value></div>
    <div class="meta-item"><label>Unlinked GPOs</label><value>$totalUnlinked</value></div>
    <div class="meta-item"><label>Report Generated</label><value>$reportDate</value></div>
  </div>
</div>

<!-- SUMMARY STATS -->
<div class="summary-row">
  <div class="stat-card"><div class="num c-blue">$totalAll</div><div class="lbl">Total GPOs</div></div>
  <div class="stat-card"><div class="num c-purple">$totalUnlinked</div><div class="lbl">Unlinked</div></div>
  <div class="stat-card"><div class="num c-green">$cntEnabled</div><div class="lbl">Enabled (Unlinked)</div></div>
  <div class="stat-card"><div class="num c-yellow">$cntPartial</div><div class="lbl">Partially Disabled</div></div>
  <div class="stat-card"><div class="num c-red">$cntDisabled</div><div class="lbl">Fully Disabled</div></div>
  <div class="stat-card"><div class="num c-orange">$cntStale</div><div class="lbl">Stale (&gt;365d)</div></div>
</div>

<!-- FILTER + SEARCH -->
<div class="filter-row">
  <span class="filter-lbl">Filter:</span>
  <button class="filter-pill active" onclick="setFilter('all',this)">All ($totalUnlinked)</button>
  <button class="filter-pill" onclick="setFilter('AllSettingsEnabled',this)">Enabled ($cntEnabled)</button>
  <button class="filter-pill" onclick="setFilter('partial',this)">Partial ($cntPartial)</button>
  <button class="filter-pill" onclick="setFilter('AllSettingsDisabled',this)">Disabled ($cntDisabled)</button>
  <button class="filter-pill" onclick="setFilter('stale',this)">Stale &gt;365d ($cntStale)</button>
</div>
<input class="search-bar" type="text" id="searchBox" placeholder="Filter by name, GUID, owner, description..." oninput="applyFilters()">

<div class="row-count">Showing <span id="visibleCount">$totalUnlinked</span> of $totalUnlinked GPOs</div>

<!-- TABLE -->
<div class="table-wrap">
  <table id="gpoTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">GPO Name <span class="sort-arrow">&#9650;</span></th>
        <th onclick="sortTable(1)">GUID <span class="sort-arrow">&#9650;</span></th>
        <th onclick="sortTable(2)">Status <span class="sort-arrow">&#9650;</span></th>
        <th onclick="sortTable(3)">Last Modified <span class="sort-arrow">&#9650;</span></th>
        <th onclick="sortTable(4)">Days Since Edit <span class="sort-arrow">&#9650;</span></th>
        <th onclick="sortTable(5)">Owner <span class="sort-arrow">&#9650;</span></th>
        <th>WMI Filter</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody id="tableBody">
      $tableRows
    </tbody>
  </table>
</div>

<div class="footer">
  Unlinked GPO Audit &nbsp;|&nbsp; Domain: $Domain &nbsp;|&nbsp; $totalUnlinked of $totalAll GPOs unlinked &nbsp;|&nbsp; Generated: $reportDate
</div>

<script>
let activeFilter = 'all';

function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

function applyFilters() {
  const q    = document.getElementById('searchBox').value.toLowerCase().trim();
  const rows = document.querySelectorAll('#tableBody tr');
  let visible = 0;

  rows.forEach(row => {
    const statusCell = row.cells[2] ? row.cells[2].textContent.trim() : '';
    const daysCell   = row.cells[4] ? parseInt(row.cells[4].textContent) : 0;
    const text       = row.textContent.toLowerCase();

    let filterMatch = true;
    if (activeFilter === 'AllSettingsEnabled')   filterMatch = statusCell.includes('All Enabled');
    if (activeFilter === 'AllSettingsDisabled')  filterMatch = statusCell.includes('All Disabled');
    if (activeFilter === 'partial')              filterMatch = statusCell.includes('Disabled') && !statusCell.includes('All Disabled');
    if (activeFilter === 'stale')                filterMatch = daysCell > 365;

    const searchMatch = !q || text.includes(q);
    const show = filterMatch && searchMatch;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  document.getElementById('visibleCount').textContent = visible;
}

// Sortable columns
let sortCol = -1, sortAsc = true;
function sortTable(col) {
  const tbody = document.getElementById('tableBody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }

  rows.sort((a, b) => {
    const av = a.cells[col] ? a.cells[col].textContent.trim() : '';
    const bv = b.cells[col] ? b.cells[col].textContent.trim() : '';
    const an = parseFloat(av), bn = parseFloat(bv);
    const cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : av.localeCompare(bv);
    return sortAsc ? cmp : -cmp;
  });

  rows.forEach(r => tbody.appendChild(r));

  document.querySelectorAll('th').forEach((th, i) => {
    th.classList.toggle('sorted', i === col);
    const arr = th.querySelector('.sort-arrow');
    if (arr) arr.textContent = (i === col) ? (sortAsc ? '▲' : '▼') : '▲';
  });
}
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -NoNewline
Write-Host "  HTML:  $OutputPath" -ForegroundColor Green
Write-Host "`nDone.`n" -ForegroundColor Green
