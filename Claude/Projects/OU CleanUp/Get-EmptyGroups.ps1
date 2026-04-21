<#
.SYNOPSIS
    Scans Active Directory for empty security and distribution groups and generates an HTML report.

.DESCRIPTION
    Queries all groups in the domain (or a specified OU), identifies those with no members,
    and outputs a color-coded, filterable HTML report grouped by scope and category.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to .\EmptyGroups_Report.html

.PARAMETER SearchBase
    Distinguished Name to limit the search scope. Defaults to the domain root.

.PARAMETER ExcludeBuiltin
    Switch to exclude built-in/default system groups (e.g. Domain Users, Schema Admins, etc.)

.EXAMPLE
    .\Get-EmptyGroups.ps1
    .\Get-EmptyGroups.ps1 -OutputPath "C:\Reports\EmptyGroups.html" -ExcludeBuiltin
    .\Get-EmptyGroups.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com"

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT or AD DS role).
#>

[CmdletBinding()]
param(
    [string]$OutputPath    = ".\EmptyGroups_Report.html",
    [string]$SearchBase    = "",
    [switch]$ExcludeBuiltin
)

#region --- Prerequisites ---
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a Domain Controller."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop
#endregion

#region --- Collect Data ---
$domain     = Get-ADDomain
$domainDN   = $domain.DistinguishedName
$domainName = $domain.DNSRoot
$base       = if ($SearchBase) { $SearchBase } else { $domainDN }
$runTime    = Get-Date

# Well-known built-in groups to optionally exclude
$builtinNames = @(
    'Domain Users','Domain Computers','Domain Controllers','Domain Guests',
    'Schema Admins','Enterprise Admins','Group Policy Creator Owners',
    'Read-only Domain Controllers','Cloneable Domain Controllers',
    'Protected Users','Key Admins','Enterprise Key Admins',
    'DnsUpdateProxy','RAS and IAS Servers','Cert Publishers',
    'Allowed RODC Password Replication Group','Denied RODC Password Replication Group',
    'Windows Authorization Access Group','Terminal Server License Servers',
    'Incoming Forest Trust Builders','Pre-Windows 2000 Compatible Access',
    'Network Configuration Operators','Performance Monitor Users',
    'Performance Log Users','Distributed COM Users','IIS_IUSRS','Cryptographic Operators',
    'Event Log Readers','Certificate Service DCOM Access','Access Control Assistance Operators',
    'Remote Management Users','Storage Replica Administrators'
)

Write-Host "Scanning groups under: $base" -ForegroundColor Cyan

$allGroups = Get-ADGroup -Filter * -SearchBase $base `
             -Properties Name, SamAccountName, GroupCategory, GroupScope,
                         Description, DistinguishedName, Members, Created, Modified, ManagedBy

$emptyGroups  = [System.Collections.Generic.List[PSObject]]::new()
$totalCount   = $allGroups.Count
$current      = 0

foreach ($grp in $allGroups) {
    $current++
    Write-Progress -Activity "Checking Groups" `
                   -Status "$current of $totalCount — $($grp.Name)" `
                   -PercentComplete (($current / $totalCount) * 100)

    if ($ExcludeBuiltin -and ($builtinNames -contains $grp.Name)) { continue }

    if ($grp.Members.Count -eq 0) {
        # Resolve ManagedBy DN to a display name
        $managedBy = "—"
        if ($grp.ManagedBy) {
            try {
                $mgr = Get-ADObject -Identity $grp.ManagedBy -Properties DisplayName
                $managedBy = if ($mgr.DisplayName) { $mgr.DisplayName } else { $grp.ManagedBy }
            } catch { $managedBy = $grp.ManagedBy }
        }

        $emptyGroups.Add([PSCustomObject]@{
            Name              = $grp.Name
            SamAccountName    = $grp.SamAccountName
            Category          = $grp.GroupCategory   # Security | Distribution
            Scope             = $grp.GroupScope       # DomainLocal | Global | Universal
            Description       = if ($grp.Description) { $grp.Description } else { "—" }
            ManagedBy         = $managedBy
            DistinguishedName = $grp.DistinguishedName
            Created           = if ($grp.Created)  { $grp.Created.ToString("yyyy-MM-dd HH:mm") }  else { "—" }
            Modified          = if ($grp.Modified) { $grp.Modified.ToString("yyyy-MM-dd HH:mm") } else { "—" }
        })
    }
}

Write-Progress -Activity "Checking Groups" -Completed

$secCount  = ($emptyGroups | Where-Object Category -eq 'Security').Count
$distCount = ($emptyGroups | Where-Object Category -eq 'Distribution').Count

Write-Host "Found $($emptyGroups.Count) empty group(s) out of $totalCount total." -ForegroundColor Green
#endregion

#region --- Build HTML rows ---
Add-Type -AssemblyName System.Web

$tableRows = if ($emptyGroups.Count -eq 0) {
    '<tr><td colspan="8" class="none">No empty groups found.</td></tr>'
} else {
    ($emptyGroups | Sort-Object Category, Scope, Name | ForEach-Object {
        $catClass  = if ($_.Category -eq 'Security') { 'cat-sec' } else { 'cat-dist' }
        $scopeClass = switch ($_.Scope) {
            'Universal'   { 'scope-univ' }
            'Global'      { 'scope-glob' }
            'DomainLocal' { 'scope-dom'  }
            default       { '' }
        }
        $name = [System.Web.HttpUtility]::HtmlEncode($_.Name)
        $sam  = [System.Web.HttpUtility]::HtmlEncode($_.SamAccountName)
        $dn   = [System.Web.HttpUtility]::HtmlEncode($_.DistinguishedName)
        $desc = [System.Web.HttpUtility]::HtmlEncode($_.Description)
        $mgr  = [System.Web.HttpUtility]::HtmlEncode($_.ManagedBy)

        "<tr data-category='$($_.Category)' data-scope='$($_.Scope)'>
            <td><strong>$name</strong><br><span class='sam'>$sam</span></td>
            <td><span class='badge $catClass'>$($_.Category)</span></td>
            <td><span class='badge $scopeClass'>$($_.Scope)</span></td>
            <td>$desc</td>
            <td>$mgr</td>
            <td>$($_.Created)</td>
            <td>$($_.Modified)</td>
            <td class='mono small'>$dn</td>
        </tr>"
    }) -join "`n"
}
#endregion

#region --- HTML ---
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Empty Groups Report — $domainName</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body   { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: #1a1a2e; }

  /* ── Header ── */
  header { background: #1b5e20; color: #fff; padding: 28px 40px 22px; }
  header h1 { font-size: 1.6rem; font-weight: 600; }
  header p  { font-size: 0.85rem; opacity: .75; margin-top: 4px; }

  /* ── Summary bar ── */
  .summary-bar {
    display: flex; gap: 24px; flex-wrap: wrap; align-items: center;
    background: #fff; border-bottom: 1px solid #e0e0e0;
    padding: 16px 40px;
  }
  .stat { display: flex; flex-direction: column; }
  .stat-label { font-size: 0.70rem; text-transform: uppercase; letter-spacing: .07em; color: #666; }
  .stat-value { font-size: 1.45rem; font-weight: 700; color: #1b5e20; }
  .divider { width: 1px; background: #e0e0e0; align-self: stretch; }

  /* ── Filter bar ── */
  .filter-bar {
    display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
    padding: 14px 40px; background: #f9fbe7; border-bottom: 1px solid #dcedc8;
  }
  .filter-bar label { font-size: 0.78rem; font-weight: 600; color: #33691e; }
  .filter-btn {
    cursor: pointer; border: 1.5px solid #aed581; background: #fff;
    border-radius: 999px; padding: 4px 14px; font-size: 0.78rem;
    color: #33691e; font-weight: 600; transition: all .15s;
  }
  .filter-btn:hover, .filter-btn.active {
    background: #33691e; color: #fff; border-color: #33691e;
  }
  .filter-sep { color: #bdbdbd; font-size: 0.9rem; }
  .search-box {
    margin-left: auto; padding: 5px 12px; border: 1.5px solid #aed581;
    border-radius: 6px; font-size: 0.82rem; min-width: 200px;
    outline: none; color: #1a1a2e;
  }
  .search-box:focus { border-color: #33691e; }

  /* ── Main ── */
  main { padding: 28px 40px; }

  .card {
    background: #fff; border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.10);
    overflow: hidden;
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px; border-bottom: 1px solid #e0e0e0;
  }
  .card-header h2 { font-size: 1rem; font-weight: 600; }
  #row-count { font-size: 0.78rem; color: #666; }

  /* ── Table ── */
  table { width: 100%; border-collapse: collapse; font-size: 0.855rem; }
  thead th {
    background: #f1f8e9; color: #33691e;
    text-align: left; padding: 9px 13px;
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: .05em;
    white-space: nowrap; position: sticky; top: 0; z-index: 1;
    cursor: pointer; user-select: none;
  }
  thead th:hover { background: #dcedc8; }
  thead th::after { content: ' ⇅'; opacity: .35; font-size: .7rem; }
  thead th.asc::after  { content: ' ▲'; opacity: 1; }
  thead th.desc::after { content: ' ▼'; opacity: 1; }

  tbody tr { border-bottom: 1px solid #f0f0f0; transition: background .1s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #f9fbe7; }
  tbody tr.hidden { display: none; }
  td { padding: 9px 13px; vertical-align: top; }
  .sam   { font-size: 0.75rem; color: #888; margin-top: 2px; display: block; }
  .mono  { font-family: 'Cascadia Code','Consolas',monospace; word-break: break-all; }
  .small { font-size: 0.73rem; color: #777; }
  .none  { text-align: center; padding: 40px; color: #888; font-style: italic; }

  /* ── Badges ── */
  .badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 0.72rem; font-weight: 700; white-space: nowrap;
  }
  .cat-sec  { background: #e3f2fd; color: #0d47a1; border: 1px solid #90caf9; }
  .cat-dist { background: #fce4ec; color: #880e4f; border: 1px solid #f48fb1; }
  .scope-univ { background: #f3e5f5; color: #4a148c; border: 1px solid #ce93d8; }
  .scope-glob { background: #e8f5e9; color: #1b5e20; border: 1px solid #a5d6a7; }
  .scope-dom  { background: #fff3e0; color: #e65100; border: 1px solid #ffb74d; }

  /* ── Tip ── */
  .tip {
    margin-top: 22px; padding: 14px 18px;
    background: #fffde7; border-left: 4px solid #f9a825;
    border-radius: 6px; font-size: 0.82rem; color: #555; line-height: 1.6;
  }
  .tip code {
    font-family: monospace; background: #fff8e1;
    padding: 1px 5px; border-radius: 3px;
  }

  footer { text-align: center; padding: 24px; font-size: 0.75rem; color: #999; }
</style>
</head>
<body>

<header>
  <h1>&#128101; Empty AD Groups Report</h1>
  <p>Domain: <strong>$domainName</strong> &nbsp;|&nbsp; Search Base: $base</p>
</header>

<div class="summary-bar">
  <div class="stat">
    <span class="stat-label">Total Groups Scanned</span>
    <span class="stat-value">$totalCount</span>
  </div>
  <div class="divider"></div>
  <div class="stat">
    <span class="stat-label">Empty Groups Found</span>
    <span class="stat-value">$($emptyGroups.Count)</span>
  </div>
  <div class="divider"></div>
  <div class="stat">
    <span class="stat-label">Empty Security</span>
    <span class="stat-value" style="color:#0d47a1">$secCount</span>
  </div>
  <div class="divider"></div>
  <div class="stat">
    <span class="stat-label">Empty Distribution</span>
    <span class="stat-value" style="color:#880e4f">$distCount</span>
  </div>
  <div class="divider"></div>
  <div class="stat">
    <span class="stat-label">Generated</span>
    <span class="stat-value" style="font-size:.95rem; padding-top:5px">$($runTime.ToString("yyyy-MM-dd HH:mm"))</span>
  </div>
</div>

<div class="filter-bar">
  <label>Category:</label>
  <button class="filter-btn active" onclick="setFilter('category','all',this)">All</button>
  <button class="filter-btn" onclick="setFilter('category','Security',this)">Security</button>
  <button class="filter-btn" onclick="setFilter('category','Distribution',this)">Distribution</button>
  <span class="filter-sep">|</span>
  <label>Scope:</label>
  <button class="filter-btn active" onclick="setFilter('scope','all',this)">All</button>
  <button class="filter-btn" onclick="setFilter('scope','Global',this)">Global</button>
  <button class="filter-btn" onclick="setFilter('scope','Universal',this)">Universal</button>
  <button class="filter-btn" onclick="setFilter('scope','DomainLocal',this)">Domain Local</button>
  <input class="search-box" type="search" placeholder="&#128269; Search name, DN, description…" oninput="applySearch(this.value)">
</div>

<main>
  <div class="card">
    <div class="card-header">
      <h2>Empty Groups</h2>
      <span id="row-count">Showing all $($emptyGroups.Count) result(s)</span>
    </div>
    <table id="groupTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Name / SAM</th>
          <th onclick="sortTable(1)">Category</th>
          <th onclick="sortTable(2)">Scope</th>
          <th onclick="sortTable(3)">Description</th>
          <th onclick="sortTable(4)">Managed By</th>
          <th onclick="sortTable(5)">Created</th>
          <th onclick="sortTable(6)">Last Modified</th>
          <th onclick="sortTable(7)">Distinguished Name</th>
        </tr>
      </thead>
      <tbody>
$tableRows
      </tbody>
    </table>
  </div>

  <div class="tip">
    <strong>Tip — Remove an empty group via PowerShell:</strong><br>
    <code>Remove-ADGroup -Identity "GroupName" -Confirm:`$false</code><br><br>
    <strong>Bulk remove all empty security groups (use with caution):</strong><br>
    <code>Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties Members | Where-Object { `$_.Members.Count -eq 0 } | Remove-ADGroup -Confirm:`$false</code>
  </div>
</main>

<footer>Generated by Get-EmptyGroups.ps1 &mdash; $($runTime.ToString("dddd, MMMM d, yyyy 'at' h:mm tt"))</footer>

<script>
  // ── Filter state ──
  const filters = { category: 'all', scope: 'all' };
  let searchTerm = '';

  function setFilter(type, value, btn) {
    filters[type] = value;
    // Toggle active button in the same group
    btn.closest('.filter-bar')
       .querySelectorAll('.filter-btn')
       .forEach(b => { if (b.dataset.group === undefined) b.classList.remove('active'); });
    // Only deactivate buttons in same logical group
    const allBtns = [...document.querySelectorAll('.filter-btn')];
    const groupBtns = allBtns.filter(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + type + "'"));
    groupBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }

  function applySearch(val) {
    searchTerm = val.toLowerCase();
    applyFilters();
  }

  function applyFilters() {
    const rows = document.querySelectorAll('#groupTable tbody tr[data-category]');
    let visible = 0;
    rows.forEach(row => {
      const cat   = row.dataset.category;
      const scope = row.dataset.scope;
      const text  = row.innerText.toLowerCase();
      const show  =
        (filters.category === 'all' || cat === filters.category) &&
        (filters.scope     === 'all' || scope === filters.scope) &&
        (searchTerm === '' || text.includes(searchTerm));
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    });
    document.getElementById('row-count').textContent = 'Showing ' + visible + ' of ' + rows.length + ' result(s)';
  }

  // ── Column sort ──
  let sortCol = -1, sortDir = 1;
  function sortTable(col) {
    const table = document.getElementById('groupTable');
    const tbody = table.tBodies[0];
    const rows  = [...tbody.querySelectorAll('tr[data-category]')];
    const ths   = table.querySelectorAll('thead th');

    if (sortCol === col) { sortDir *= -1; } else { sortCol = col; sortDir = 1; }
    ths.forEach((th, i) => {
      th.classList.remove('asc','desc');
      if (i === col) th.classList.add(sortDir === 1 ? 'asc' : 'desc');
    });

    rows.sort((a, b) => {
      const ta = a.cells[col] ? a.cells[col].innerText.trim() : '';
      const tb = b.cells[col] ? b.cells[col].innerText.trim() : '';
      return ta.localeCompare(tb, undefined, {numeric: true}) * sortDir;
    });
    rows.forEach(r => tbody.appendChild(r));
  }
</script>
</body>
</html>
"@
#endregion

#region --- Write Output ---
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$html | Out-File -FilePath $resolvedPath -Encoding UTF8 -Force
Write-Host "Report saved to: $resolvedPath" -ForegroundColor Cyan
#endregion
