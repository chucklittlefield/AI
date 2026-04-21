<#
.SYNOPSIS
    Scans Active Directory for empty Organizational Units and generates an HTML report.

.DESCRIPTION
    Queries all OUs in the domain, checks each for any direct child objects
    (users, computers, groups, contacts, and nested OUs), and outputs a
    color-coded HTML report of empty OUs.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to .\EmptyOUs_Report.html

.PARAMETER SearchBase
    Distinguished Name to limit the search scope. Defaults to the domain root.

.EXAMPLE
    .\Get-EmptyOUs.ps1
    .\Get-EmptyOUs.ps1 -OutputPath "C:\Reports\EmptyOUs.html"
    .\Get-EmptyOUs.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com"

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT or AD DS role).
    Run as a user with at least Read access to AD objects.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\EmptyOUs_Report.html",
    [string]$SearchBase = ""
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
$searchBase = if ($SearchBase) { $SearchBase } else { $domainDN }
$runTime    = Get-Date

Write-Host "Scanning OUs under: $searchBase" -ForegroundColor Cyan

$allOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $searchBase -Properties DistinguishedName, Name, Description, Created, Modified

$emptyOUs   = [System.Collections.Generic.List[PSObject]]::new()
$totalCount = $allOUs.Count
$current    = 0

foreach ($ou in $allOUs) {
    $current++
    Write-Progress -Activity "Checking OUs" `
                   -Status "$current of $totalCount — $($ou.Name)" `
                   -PercentComplete (($current / $totalCount) * 100)

    # Count any direct children (all object classes)
    $childCount = (Get-ADObject -Filter * -SearchBase $ou.DistinguishedName `
                                -SearchScope OneLevel -ErrorAction SilentlyContinue |
                   Measure-Object).Count

    if ($childCount -eq 0) {
        $emptyOUs.Add([PSCustomObject]@{
            Name              = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            Description       = if ($ou.Description) { $ou.Description } else { "—" }
            Created           = if ($ou.Created)  { $ou.Created.ToString("yyyy-MM-dd HH:mm") }  else { "—" }
            Modified          = if ($ou.Modified) { $ou.Modified.ToString("yyyy-MM-dd HH:mm") } else { "—" }
        })
    }
}

Write-Progress -Activity "Checking OUs" -Completed
Write-Host "Found $($emptyOUs.Count) empty OU(s) out of $totalCount total." -ForegroundColor Green
#endregion

#region --- Build HTML ---
$tableRows = if ($emptyOUs.Count -eq 0) {
    '<tr><td colspan="5" class="none">No empty OUs found.</td></tr>'
} else {
    ($emptyOUs | Sort-Object DistinguishedName | ForEach-Object {
        $dn   = [System.Web.HttpUtility]::HtmlEncode($_.DistinguishedName)
        $name = [System.Web.HttpUtility]::HtmlEncode($_.Name)
        $desc = [System.Web.HttpUtility]::HtmlEncode($_.Description)
        "<tr>
            <td><strong>$name</strong></td>
            <td class='mono'>$dn</td>
            <td>$desc</td>
            <td>$($_.Created)</td>
            <td>$($_.Modified)</td>
        </tr>"
    }) -join "`n"
}

$badgeClass = if ($emptyOUs.Count -eq 0) { "badge-ok" } else { "badge-warn" }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Empty OU Report — $domainName</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body   { font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: #1a1a2e; }

  header { background: #1a237e; color: #fff; padding: 28px 40px 24px; }
  header h1 { font-size: 1.6rem; font-weight: 600; }
  header p  { font-size: 0.85rem; opacity: .75; margin-top: 4px; }

  .summary-bar {
    display: flex; gap: 20px; flex-wrap: wrap;
    background: #fff; border-bottom: 1px solid #e0e0e0;
    padding: 16px 40px;
  }
  .stat { display: flex; flex-direction: column; }
  .stat-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: .06em; color: #666; }
  .stat-value { font-size: 1.4rem; font-weight: 700; color: #1a237e; }

  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }
  .badge-warn { background: #fff3e0; color: #e65100; border: 1px solid #ffb74d; }
  .badge-ok   { background: #e8f5e9; color: #2e7d32; border: 1px solid #81c784; }

  main { padding: 30px 40px; }

  .card {
    background: #fff; border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.10);
    overflow: hidden;
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px; border-bottom: 1px solid #e0e0e0;
  }
  .card-header h2 { font-size: 1rem; font-weight: 600; }

  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  thead th {
    background: #e8eaf6; color: #283593;
    text-align: left; padding: 10px 14px;
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em;
    white-space: nowrap;
  }
  tbody tr { border-bottom: 1px solid #f0f0f0; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #f5f7ff; }
  td { padding: 10px 14px; vertical-align: top; }
  .mono { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.78rem; color: #555; word-break: break-all; }
  .none { text-align: center; padding: 40px; color: #666; font-style: italic; }

  .tip {
    margin-top: 22px; padding: 14px 18px;
    background: #fffde7; border-left: 4px solid #f9a825;
    border-radius: 6px; font-size: 0.82rem; color: #555;
  }
  .tip code { font-family: monospace; background: #fff8e1; padding: 1px 5px; border-radius: 3px; }

  footer { text-align: center; padding: 24px; font-size: 0.75rem; color: #999; }
</style>
</head>
<body>

<header>
  <h1>&#128193; Empty OU Report</h1>
  <p>Domain: <strong>$domainName</strong> &nbsp;|&nbsp; Search Base: $searchBase</p>
</header>

<div class="summary-bar">
  <div class="stat">
    <span class="stat-label">Total OUs Scanned</span>
    <span class="stat-value">$totalCount</span>
  </div>
  <div class="stat">
    <span class="stat-label">Empty OUs Found</span>
    <span class="stat-value">$($emptyOUs.Count)</span>
  </div>
  <div class="stat">
    <span class="stat-label">Run Time</span>
    <span class="stat-value" style="font-size:1rem; padding-top:6px">$($runTime.ToString("yyyy-MM-dd HH:mm"))</span>
  </div>
  <div class="stat" style="justify-content:flex-end; flex:1; align-items:flex-end">
    <span class="badge $badgeClass">$($emptyOUs.Count) Empty OU$(if($emptyOUs.Count -ne 1){'s'})</span>
  </div>
</div>

<main>
  <div class="card">
    <div class="card-header">
      <h2>Empty Organizational Units</h2>
    </div>
    <table>
      <thead>
        <tr>
          <th>OU Name</th>
          <th>Distinguished Name</th>
          <th>Description</th>
          <th>Created</th>
          <th>Last Modified</th>
        </tr>
      </thead>
      <tbody>
        $tableRows
      </tbody>
    </table>
  </div>

  <div class="tip">
    <strong>Tip:</strong> To delete an empty OU via PowerShell, first clear the accidental-deletion protection:<br>
    <code>Set-ADOrganizationalUnit -Identity "OU=Name,DC=domain,DC=com" -ProtectedFromAccidentalDeletion `$false</code><br>
    Then remove it: <code>Remove-ADOrganizationalUnit -Identity "OU=Name,DC=domain,DC=com" -Recursive -Confirm:`$false</code>
  </div>
</main>

<footer>Generated by Get-EmptyOUs.ps1 &mdash; $($runTime.ToString("dddd, MMMM d, yyyy 'at' h:mm tt"))</footer>

</body>
</html>
"@
#endregion

#region --- Write Output ---
# Resolve relative path before writing
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$html | Out-File -FilePath $resolvedPath -Encoding UTF8 -Force
Write-Host "Report saved to: $resolvedPath" -ForegroundColor Cyan
#endregion
