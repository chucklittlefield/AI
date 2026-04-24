---
name: create-powershell-script
description: >
  Create, write, or generate PowerShell scripts (.ps1 files). Use this skill
  whenever a user asks to automate a Windows task, write a PowerShell script,
  build a .ps1 file, schedule a job, manage Active Directory, interact with
  Azure or Microsoft 365 via PowerShell, parse logs, manage files/registry,
  or do anything scripted in PowerShell. Also trigger for requests like
  "script this for me", "automate this in PowerShell", "write me a PS script",
  "how do I do X in PowerShell" where the answer is a reusable script, or
  "add error handling / logging to my script". Always use this skill when the
  output is a .ps1 file — even for short scripts.
---

# create-powershell-script

Produce professional, production-ready PowerShell scripts that are readable,
robust, and consistent. Always save the final script to
`/mnt/user-data/outputs/<Verb-Noun>.ps1` and present it with `present_files`.

---

## Workflow

### 1. Clarify requirements (if needed)

Before writing, confirm (from context or by asking):

- **What does the script do?** Core task in one sentence.
- **Inputs** — paths, credentials, parameters the caller will supply.
- **Outputs** — files written, objects returned, console feedback expected.
- **Environment** — Windows PowerShell 5.1 vs PowerShell 7+, target OS,
  required modules (Az, ActiveDirectory, ExchangeOnlineManagement, etc.),
  elevation requirements.
- **Edge cases** — what happens when a file is missing, a service is down,
  input is empty?

If the user's request is clear, skip straight to writing.

### 2. Plan the script

Decide on structure before writing:

| Script size | Structure |
|-------------|-----------|
| < 50 lines  | Single script file, inline logic |
| 50-200 lines | Script with named functions |
| > 200 lines | Consider module layout (see references/best-practices.md) |

Choose the right Verb from the approved list (Get, Set, New, Remove,
Invoke, Start, Stop, Export, Import, Test, Update, Copy, Move, Rename,
Send, Publish, Register, Unregister, etc.).

### 3. Write the script

Always apply these non-negotiables at the top of every script:

```powershell
#Requires -Version 5.1                  # or 7.0 if using PS7 features
# #Requires -RunAsAdministrator         # uncomment if elevation is needed

[CmdletBinding(SupportsShouldProcess)]
param ( ... )

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

Then follow the conventions below and the template in
`assets/PS-Function-Template.ps1`.

### 4. Save and present

Save the finished script to `/mnt/user-data/outputs/<Verb-Noun>.ps1`,
then use `present_files` to hand it to the user. Include a short note covering:
- What the script does
- Example invocation
- Any prerequisites (modules to install, required permissions)

---

## Mandatory Conventions

See `references/best-practices.md` for full detail. The essentials:

### Naming
- Scripts and public functions: Verb-Noun  (e.g. Invoke-DatabaseBackup.ps1)
- Parameters: PascalCase  ($InputPath, $LogLevel)
- Local variables: camelCase  ($outputFile, $retryCount)

### Comment-based help on every function
Every function must have .SYNOPSIS, .DESCRIPTION, .PARAMETER (one per param),
.EXAMPLE, and .NOTES. Use `assets/PS-Function-Template.ps1` as the skeleton.

### Error handling
- Wrap all risky operations in try/catch/finally
- Catch specific exception types before the catch-all
- Use `throw` to re-raise when the caller should handle it
- Validate inputs early: if (-not (Test-Path $x)) { throw ... }

### Logging
Include a Write-Log helper (or Start-Transcript) for any script that runs
unattended or touches production resources.
Log format: [yyyy-MM-dd HH:mm:ss][LEVEL] message

### Output discipline
- Return objects, not formatted strings, so output is pipeline-friendly
- Suppress noisy cmdlet output with | Out-Null or $null = ...
- Use Write-Verbose for progress chatter; reserve Write-Host for interactive UX

### ShouldProcess / -WhatIf
Add SupportsShouldProcess and $PSCmdlet.ShouldProcess(...) around any
destructive or mutating action (deletes, writes, API calls).

### Security
- No plaintext passwords — use Get-Credential, SecureString, or a secrets manager
- Avoid Invoke-Expression
- Sanitize user-supplied paths with [System.IO.Path]::GetFullPath()

---

## Reference Files

| File | When to read |
|------|-------------|
| assets/PS-Function-Template.ps1 | Copy as skeleton for every new function |
| references/best-practices.md | Deep-dive: naming, error handling, logging, modules, Pester tests, patterns |

Load them with the `view` tool when you need detailed guidance on a specific
topic (module layout, Pester test structure, parallel processing, etc.).

---

## Quick-Reference: Common Patterns

```powershell
# Idempotent directory creation
$dir = Join-Path $env:TEMP 'MyScript'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

# Pipeline-friendly output
[PSCustomObject]@{ Name = $name; Status = 'OK'; SizeKB = [math]::Round($bytes/1KB,2) }

# Progress bar
Write-Progress -Activity "Processing" -Status "$i of $total" -PercentComplete ($i/$total*100)

# Safe credential
$cred = Get-Credential -Message "Enter service account"

# Parallel (PS 7+)
$items | ForEach-Object -Parallel { $_ } -ThrottleLimit 5
```