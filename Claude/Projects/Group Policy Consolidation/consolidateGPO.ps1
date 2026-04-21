#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Consolidates multiple GPOs into a single new GPO.
.DESCRIPTION
    Presents all domain GPOs for selection via Out-GridView, extracts registry-based
    (Administrative Template) settings from each selected GPO by parsing their Registry.pol
    backup files, prompts the user to resolve value conflicts, then creates a new consolidated
    GPO with the merged settings applied via Set-GPRegistryValue.

    Security template settings (GptTmpl.inf — account policies, audit policies, user rights,
    etc.) are detected and flagged for manual migration in GPMC. Logon/logoff scripts and
    software installation settings are not automatically merged.
.PARAMETER BackupPath
    Temporary folder for GPO backups. Defaults to a timestamped subfolder under %TEMP%.
    Backup files are optionally deleted at the end of the run.
.EXAMPLE
    .\consolidateGPO.ps1

    Runs the interactive consolidation wizard using the default temp path.
.EXAMPLE
    .\consolidateGPO.ps1 -BackupPath 'C:\Temp\GPOMerge'

    Uses a custom path for temporary backup files.
.NOTES
    Requires the GroupPolicy RSAT module (RSAT-GPMC feature / Group Policy Management Console).
    Run as a domain user with permissions to back up GPOs and create new GPOs.
    Only registry-based (Administrative Template) settings are automatically merged.
    Author: Chuck Littlefield / SIFP-FCTG IT Operations
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$BackupPath = (Join-Path $env:TEMP "GPOMerge_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper: Console formatting ─────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    $line = '─' * 64
    Write-Host "`n$line" -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

#endregion

#region ── Helper: Registry.pol binary parser ─────────────────────────────────

function Read-Utf16String {
    <#
        Reads a null-terminated UTF-16LE string from a byte array starting at $Pos.
        Stops early at any UTF-16 code unit listed in $StopChars (e.g. 0x003B for ';').
        On return, $Pos points at the first byte of the stop/null character (caller skips it).
    #>
    [OutputType([string])]
    param(
        [byte[]]$Bytes,
        [ref]$Pos,
        [int[]]$StopChars = @()
    )

    $sb = [System.Text.StringBuilder]::new()
    while ($Pos.Value + 1 -lt $Bytes.Length) {
        $charVal = [BitConverter]::ToUInt16($Bytes, $Pos.Value)
        if ($charVal -eq 0) {
            $Pos.Value += 2   # consume null terminator
            break
        }
        if ($charVal -in $StopChars) { break }
        [void]$sb.Append([char]$charVal)
        $Pos.Value += 2
    }
    return $sb.ToString()
}

function Read-RegistryPolFile {
    <#
    .SYNOPSIS
        Parses a Registry.pol binary file and returns a list of setting hashtables.
    .DESCRIPTION
        Registry.pol uses the PReg format:
          Header : 'PReg' (4 bytes) + version 1 (4 bytes)
          Records: [ key ; valuename ; type(DWORD) ; size(DWORD) ; data ]
                   All strings are null-terminated UTF-16LE; delimiters are also UTF-16LE.
    #>
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Computer', 'User')][string]$Scope
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()
    if (-not (Test-Path $Path)) { return $results }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8) { return $results }

    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
        Write-Warning "Skipping '$Path' — not a valid Registry.pol file."
        return $results
    }

    $hive = if ($Scope -eq 'Computer') { 'HKLM' } else { 'HKCU' }
    $pos  = 8   # skip 4-byte signature + 4-byte version

    while ($pos -lt $bytes.Length) {
        # Locate opening bracket '[' (0x5B 0x00 in UTF-16LE)
        if ($pos + 1 -ge $bytes.Length -or
            $bytes[$pos] -ne 0x5B -or $bytes[$pos + 1] -ne 0x00) {
            $pos++
            continue
        }
        $pos += 2

        try {
            # Key path (stop at ';' = 0x003B)
            $key = Read-Utf16String -Bytes $bytes -Pos ([ref]$pos) -StopChars @(0x003B)
            $pos += 2   # skip ';'

            # Value name
            $valName = Read-Utf16String -Bytes $bytes -Pos ([ref]$pos) -StopChars @(0x003B)
            $pos += 2   # skip ';'

            # Type — 4-byte LE DWORD
            if ($pos + 3 -ge $bytes.Length) { break }
            $typeInt = [BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            $pos += 2   # skip ';'

            # Data size — 4-byte LE DWORD
            if ($pos + 3 -ge $bytes.Length) { break }
            $dataSize = [int][BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            $pos += 2   # skip ';'

            # Raw data bytes
            $rawData = [byte[]]@()
            if ($dataSize -gt 0 -and ($pos + $dataSize - 1) -lt $bytes.Length) {
                $rawData = $bytes[$pos..($pos + $dataSize - 1)]
            }
            $pos += $dataSize
            $pos += 2   # skip ']'

            # Skip policy-engine directives (**del, **delvals, etc.)
            if ($key.StartsWith('**') -or $valName.StartsWith('**')) { continue }
            if (-not $key) { continue }

            # Map PReg type integer to Set-GPRegistryValue type name
            $typeStr = switch ($typeInt) {
                1  { 'String' }
                2  { 'ExpandString' }
                3  { 'Binary' }
                4  { 'DWord' }
                7  { 'MultiString' }
                11 { 'QWord' }
                default { $null }
            }
            if (-not $typeStr) {
                Write-Verbose "Unsupported registry type $typeInt — '$key\$valName' skipped."
                continue
            }

            $displayValue = switch ($typeInt) {
                1  { [System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0) }
                2  { [System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0) }
                4  { if ($rawData.Length -ge 4) { [BitConverter]::ToUInt32($rawData, 0) } else { 0 } }
                11 { if ($rawData.Length -ge 8) { [BitConverter]::ToUInt64($rawData, 0) } else { 0 } }
                7  {
                        $raw = [System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0)
                        ($raw -split [char]0 | Where-Object { $_ }) -join ' | '
                   }
                3  { [BitConverter]::ToString($rawData) }
                default { '(raw)' }
            }

            $results.Add(@{
                Scope        = $Scope
                Hive         = $hive
                Key          = $key
                ValueName    = $valName
                TypeInt      = $typeInt
                TypeStr      = $typeStr
                DisplayValue = "$displayValue"
                RawData      = $rawData
                SettingKey   = "$Scope|$key|$valName"
                GPOName      = ''    # populated by caller
            })

        } catch {
            Write-Verbose "Parse error at byte $pos`: $_"
            $pos++
        }
    }

    return $results
}

#endregion

#region ── Helper: Conflict resolution via Out-GridView ───────────────────────

function Resolve-SettingConflict {
    [OutputType([hashtable])]
    param(
        [string]$SettingKey,
        [hashtable[]]$Candidates
    )

    Write-Host "`n  [CONFLICT] $SettingKey" -ForegroundColor Yellow

    $display = $Candidates | ForEach-Object {
        [PSCustomObject]@{
            'Source GPO'   = $_['GPOName']
            'Scope'        = $_['Scope']
            'Registry Key' = $_['Key']
            'Value Name'   = $_['ValueName']
            'Type'         = $_['TypeStr']
            'Value'        = $_['DisplayValue']
        }
    }

    $chosen = $display | Out-GridView `
        -Title "CONFLICT — Select ONE value to keep for: $SettingKey" `
        -OutputMode Single

    if (-not $chosen) {
        Write-Host "    → No selection made. Setting will be SKIPPED." -ForegroundColor DarkYellow
        return $null
    }

    $winner = $Candidates | Where-Object { $_['GPOName'] -eq $chosen.'Source GPO' } | Select-Object -First 1
    Write-Host "    → Keeping value from '$($winner['GPOName'])'" -ForegroundColor Green
    return $winner
}

#endregion

#region ── Helper: Apply a single merged setting to the new GPO ───────────────

function Set-MergedRegistryValue {
    param(
        [guid]$GPOGuid,
        [hashtable]$Setting
    )

    $fullKey = "$($Setting['Hive'])\$($Setting['Key'])"
    $rawData = [byte[]]$Setting['RawData']

    $value = switch ($Setting['TypeInt']) {
        1  { [string][System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0) }
        2  { [string][System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0) }
        3  { $rawData }
        4  { if ($rawData.Length -ge 4) { [int][BitConverter]::ToInt32($rawData, 0) } else { 0 } }
        7  {
                $str = [System.Text.Encoding]::Unicode.GetString($rawData).TrimEnd([char]0)
                [string[]]($str -split [char]0 | Where-Object { $_ })
           }
        11 { if ($rawData.Length -ge 8) { [long][BitConverter]::ToInt64($rawData, 0) } else { 0L } }
        default { throw "Unsupported type $($Setting['TypeInt'])" }
    }

    Set-GPRegistryValue -Guid $GPOGuid `
        -Key       $fullKey `
        -ValueName $Setting['ValueName'] `
        -Type      $Setting['TypeStr'] `
        -Value     $value | Out-Null
}

#endregion

#region ── Main ───────────────────────────────────────────────────────────────

Write-Header 'GPO Consolidation Wizard'

# ── Step 1: Select source GPOs ────────────────────────────────────────────────
Write-Header 'Step 1 of 6 — Select Source GPOs'
Write-Host 'Retrieving all GPOs from the domain...'

try {
    $allGPOInfo = Get-GPO -All -ErrorAction Stop |
        Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime |
        Sort-Object DisplayName
} catch {
    Write-Error "Cannot retrieve GPOs. Verify RSAT-GPMC is installed and you are on a domain-joined machine.`n$_"
    exit 1
}

$selectedInfo = $allGPOInfo | Out-GridView `
    -Title 'Select GPOs to consolidate  (Ctrl+Click or Shift+Click for multiple)' `
    -OutputMode Multiple

if (-not $selectedInfo -or @($selectedInfo).Count -lt 2) {
    Write-Host 'At least 2 GPOs must be selected. Exiting.' -ForegroundColor Yellow
    exit 0
}

$sourceGPOs = @($selectedInfo) | ForEach-Object { Get-GPO -Guid $_.Id }

Write-Host "`nSelected $($sourceGPOs.Count) source GPO(s):" -ForegroundColor Green
$sourceGPOs | ForEach-Object { Write-Host "  • $($_.DisplayName)" }

# ── Step 2: Name the new consolidated GPO ────────────────────────────────────
Write-Header 'Step 2 of 6 — Name the New GPO'

do {
    $newGPOName = (Read-Host 'Enter a name for the new consolidated GPO').Trim()
    if (-not $newGPOName) {
        Write-Host 'Name cannot be empty.' -ForegroundColor Yellow
        continue
    }
    if (Get-GPO -Name $newGPOName -ErrorAction SilentlyContinue) {
        Write-Host "A GPO named '$newGPOName' already exists. Choose a different name." -ForegroundColor Yellow
        $newGPOName = $null
    }
} while (-not $newGPOName)

# ── Step 3: Back up source GPOs ───────────────────────────────────────────────
Write-Header 'Step 3 of 6 — Backing Up Source GPOs'
$null = New-Item -ItemType Directory -Path $BackupPath -Force
Write-Host "Backup path: $BackupPath"

$backupMap = @{}   # GPO Id (string) → GpoBackup object

foreach ($gpo in $sourceGPOs) {
    Write-Host "  Backing up '$($gpo.DisplayName)'..." -NoNewline
    try {
        $b = Backup-GPO -Guid $gpo.Id -Path $BackupPath -ErrorAction Stop
        $backupMap[$gpo.Id.ToString()] = $b
        Write-Host ' Done' -ForegroundColor Green
    } catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
    }
}

# ── Step 4: Parse Registry.pol files from each backup ─────────────────────────
Write-Header 'Step 4 of 6 — Extracting Registry Settings'

$allSettings = [System.Collections.Generic.List[hashtable]]::new()

foreach ($gpo in $sourceGPOs) {
    $bk = $backupMap[$gpo.Id.ToString()]
    if (-not $bk) {
        Write-Host "  Skipping '$($gpo.DisplayName)' — no backup available." -ForegroundColor DarkYellow
        continue
    }

    # Backup-GPO stores each backup under a GUID-named subfolder
    $backupDir = Join-Path $bk.BackupDirectory $bk.Id.ToString('B')
    $count     = 0

    foreach ($scope in 'Computer', 'User') {
        $sysvolSub = if ($scope -eq 'Computer') { 'Machine' } else { 'User' }
        $polPath   = Join-Path $backupDir "DomainSysvol\GPO\$sysvolSub\registry.pol"

        $parsed = Read-RegistryPolFile -Path $polPath -Scope $scope
        foreach ($s in $parsed) { $s['GPOName'] = $gpo.DisplayName }
        $allSettings.AddRange($parsed)
        $count += $parsed.Count
    }

    Write-Host "  '$($gpo.DisplayName)': $count registry setting(s) found."
}

Write-Host "`nTotal raw settings collected: $($allSettings.Count)"

# ── Step 5: Merge and resolve conflicts ───────────────────────────────────────
Write-Header 'Step 5 of 6 — Merging Settings & Resolving Conflicts'

$merged    = [System.Collections.Generic.Dictionary[string, hashtable]]::new()
$conflicts = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[hashtable]]]::new()

foreach ($s in $allSettings) {
    $sk = $s['SettingKey']
    if ($merged.ContainsKey($sk)) {
        $existing    = $merged[$sk]
        $existingHex = [BitConverter]::ToString([byte[]]$existing['RawData'])
        $newHex      = [BitConverter]::ToString([byte[]]$s['RawData'])

        if ($existingHex -ne $newHex) {
            # Different values for the same key — record conflict
            if (-not $conflicts.ContainsKey($sk)) {
                $cList = [System.Collections.Generic.List[hashtable]]::new()
                $cList.Add($existing)
                $conflicts[$sk] = $cList
            }
            $conflicts[$sk].Add($s)
        }
        # Identical value across multiple GPOs — keep existing entry silently
    } else {
        $merged[$sk] = $s
    }
}

Write-Host "Unique settings : $($merged.Count)"
Write-Host "Conflicts found : $($conflicts.Count)"

if ($conflicts.Count -gt 0) {
    Write-Host "`nResolving $($conflicts.Count) conflict(s) — an Out-GridView dialog will open for each..." -ForegroundColor Yellow

    foreach ($ck in @($conflicts.Keys)) {
        $winner = Resolve-SettingConflict -SettingKey $ck -Candidates ($conflicts[$ck].ToArray())
        if ($winner) {
            $merged[$ck] = $winner
        } else {
            $merged.Remove($ck) | Out-Null
        }
    }

    Write-Host "`nFinal settings to apply: $($merged.Count)" -ForegroundColor Green
}

# ── Step 6: Create new GPO and apply merged settings ──────────────────────────
Write-Header 'Step 6 of 6 — Creating & Populating Consolidated GPO'

$gpoComment = "Consolidated from: $($sourceGPOs.DisplayName -join '; '). " +
              "Created $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $env:USERNAME@$env:USERDOMAIN."

try {
    $newGPO = New-GPO -Name $newGPOName -Comment $gpoComment -ErrorAction Stop
    Write-Host "GPO created: '$newGPOName'  [$($newGPO.Id)]" -ForegroundColor Green
} catch {
    Write-Error "Failed to create GPO '$newGPOName': $_"
    exit 1
}

$applied = 0
$failed  = 0

foreach ($setting in $merged.Values) {
    try {
        Set-MergedRegistryValue -GPOGuid $newGPO.Id -Setting $setting
        $applied++
    } catch {
        Write-Warning "Could not apply '$($setting['SettingKey'])': $_"
        $failed++
    }
}

$color = if ($failed -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "Applied : $applied   Failed : $failed" -ForegroundColor $color

# ── Security settings notice ──────────────────────────────────────────────────
$secGPOs = foreach ($gpo in $sourceGPOs) {
    $bk = $backupMap[$gpo.Id.ToString()]
    if (-not $bk) { continue }
    $bkDir   = Join-Path $bk.BackupDirectory $bk.Id.ToString('B')
    $infPath = Join-Path $bkDir 'DomainSysvol\GPO\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (Test-Path $infPath) { $gpo.DisplayName }
}

if ($secGPOs) {
    Write-Host "`n[MANUAL ACTION REQUIRED] Security Template settings detected in:" -ForegroundColor Yellow
    $secGPOs | ForEach-Object { Write-Host "  • $_" -ForegroundColor Yellow }
    Write-Host @"

  Security settings (account policies, audit policies, user rights, restricted groups,
  etc.) cannot be merged automatically and must be configured manually.

  To migrate them:
    1. Open Group Policy Management  (gpmc.msc)
    2. Right-click '$newGPOName'  →  Edit
    3. Navigate to: Computer Config > Policies > Windows Settings > Security Settings
    4. Configure the settings from each source GPO listed above.

"@ -ForegroundColor Cyan
}

# ── Cleanup ────────────────────────────────────────────────────────────────────
Write-Header 'Cleanup'
$ans = Read-Host "Delete temporary backup files at '$BackupPath'? [Y/N]"
if ($ans -match '^[Yy]') {
    Remove-Item -Path $BackupPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Temporary files removed.'
} else {
    Write-Host "Backup files retained at: $BackupPath"
}

Write-Host "`nDone. GPO '$newGPOName' is ready in Active Directory." -ForegroundColor Green
Write-Host "Link it to the appropriate OUs in GPMC to activate it." -ForegroundColor Cyan

#endregion
