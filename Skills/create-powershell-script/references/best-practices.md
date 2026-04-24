# PowerShell Best Practices Reference

## Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Scripts | Verb-Noun.ps1 | `Get-RandomPassword.ps1` |
| Functions | Verb-Noun | `Invoke-IPv4NetworkScan` |
| Variables | camelCase | `$outputPath`, `$userList` |
| Constants | UPPER_SNAKE | `$MAX_RETRIES = 3` |
| Parameters | PascalCase | `$InputPath`, `$LogLevel` |
| Private helpers | Verb-NounImpl or prefix `_` | `_ConvertEntry` |

Use only [approved PowerShell verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands).

---

## Script Structure

Every script should follow this top-to-bottom layout:

```
1. #Requires statements           (PS version, modules, elevation)
2. [CmdletBinding()] + param()    (if the script itself takes parameters)
3. Set-StrictMode / $ErrorActionPreference
4. Dot-sourced helpers / imports
5. Main logic (or call to main function)
```

### Mandatory header block

```powershell
#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Az'; ModuleVersion='10.0.0' }  # if applicable
# #Requires -RunAsAdministrator                                   # if applicable

[CmdletBinding(SupportsShouldProcess)]
param (
    # parameters here
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

---

## Error Handling

### ErrorActionPreference

Set at the top of every script:
```powershell
$ErrorActionPreference = 'Stop'   # non-terminating errors become terminating
```

### try/catch/finally pattern

```powershell
try {
    # risky operation
}
catch [System.UnauthorizedAccessException] {
    Write-Error "Access denied to '$Path'. Run as administrator."
    return
}
catch [System.IO.FileNotFoundException] {
    Write-Error "File not found: '$Path'"
    return
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    throw   # re-throw if the caller should handle it
}
finally {
    # cleanup that must always run (close handles, remove temp files)
}
```

### Validate early, fail fast

```powershell
if (-not (Test-Path $InputPath)) {
    throw [System.IO.FileNotFoundException] "Input file not found: $InputPath"
}
```

---

## Logging

### Simple console logging with severity

```powershell
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp][$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Error   $entry }
        'WARN'  { Write-Warning $entry }
        'DEBUG' { Write-Debug   $entry }
        default { Write-Verbose $entry }
    }
    # Optionally append to file:
    # Add-Content -Path $LogFile -Value $entry
}
```

### Tee to file

```powershell
Start-Transcript -Path $LogFile -Append
# ... script body ...
Stop-Transcript
```

---

## Parameters & Validation

```powershell
param (
    # Path that must exist
    [Parameter(Mandatory)][ValidateScript({ Test-Path $_ })][string]$InputPath,

    # Constrained string set
    [ValidateSet('Dev','Staging','Prod')][string]$Environment = 'Dev',

    # Positive integer
    [ValidateRange(1,100)][int]$RetryCount = 3,

    # Non-empty string
    [ValidateNotNullOrEmpty()][string]$ApiKey,

    # Pattern match
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$Date,

    # Switch (flag)
    [switch]$WhatIf,
    [switch]$Force
)
```

---

## Pipeline Support

Make functions pipeline-friendly when the use case fits:

```powershell
function Process-Item {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name
    )
    process {
        # called once per pipeline object
        "Processing: $Name"
    }
}

# Usage:
"alpha","beta","gamma" | Process-Item
Get-ChildItem | Select-Object -ExpandProperty Name | Process-Item
```

---

## Output & Return Values

- **Never use `return` to output objects** from a function — use the pipeline.
- **Suppress unwanted output** with `| Out-Null` or `$null = ...`
- **Return structured objects**, not formatted strings, so callers can filter/sort:

```powershell
# Good — caller can pipe to Where-Object, Select-Object, etc.
[PSCustomObject]@{
    Name   = $item.Name
    Status = 'OK'
    SizeKB = [math]::Round($item.Length / 1KB, 2)
}

# Bad — caller gets a string they have to parse
"$($item.Name): OK ($('{0:N2}' -f ($item.Length/1KB)) KB)"
```

---

## Security

- **Never store credentials in plaintext.** Use `Get-Credential`, `SecureString`, or a secrets manager.
- **Avoid `Invoke-Expression`** — it opens injection vulnerabilities. Prefer direct cmdlets.
- **Sanitize user-supplied paths** — use `[System.IO.Path]::GetFullPath()` or `Resolve-Path`.
- **Sign scripts** for production deployment: `Set-AuthenticodeSignature`.
- **Execution policy** — document the minimum required (`RemoteSigned`, `AllSigned`).

```powershell
# Safe credential handling
$cred = Get-Credential -Message "Enter service account credentials"
# Use $cred.GetNetworkCredential().Password only where absolutely needed
```

---

## Modules

When a script grows beyond ~200 lines of functions, consider extracting to a module:

```
MyModule/
├── MyModule.psd1       (manifest)
├── MyModule.psm1       (root module, dot-sources private + exports public)
├── Public/             (exported functions)
│   └── Get-Thing.ps1
└── Private/            (internal helpers)
    └── _ParseEntry.ps1
```

`MyModule.psm1` pattern:
```powershell
$Public  = Get-ChildItem "$PSScriptRoot/Public/*.ps1"  -ErrorAction SilentlyContinue
$Private = Get-ChildItem "$PSScriptRoot/Private/*.ps1" -ErrorAction SilentlyContinue
($Public + $Private) | ForEach-Object { . $_.FullName }
Export-ModuleMember -Function $Public.BaseName
```

---

## Testing with Pester

```powershell
Describe 'Get-Something' {
    BeforeAll {
        . "$PSScriptRoot/../Public/Get-Something.ps1"
    }
    Context 'When input is valid' {
        It 'returns the expected object' {
            $result = Get-Something -Name 'test'
            $result.Name   | Should -Be 'test'
            $result.Status | Should -Be 'OK'
        }
    }
    Context 'When input is missing' {
        It 'throws' {
            { Get-Something -Name '' } | Should -Throw
        }
    }
}
```

---

## Common Patterns

### Idempotent file/directory creation
```powershell
$dir = Join-Path $env:TEMP 'MyScript'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
```

### Progress reporting for long loops
```powershell
$items = 1..100
for ($i = 0; $i -lt $items.Count; $i++) {
    Write-Progress -Activity "Processing" -Status "Item $($i+1) of $($items.Count)" `
                   -PercentComplete (($i / $items.Count) * 100)
    # ... work ...
}
Write-Progress -Activity "Processing" -Completed
```

### Parallel processing (PS 7+)
```powershell
$items | ForEach-Object -Parallel {
    # each item processed in a runspace
    $_
} -ThrottleLimit 5
```

### Registry access
```powershell
$regPath = 'HKLM:\SOFTWARE\MyApp'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'Version' -Value '1.0'
```