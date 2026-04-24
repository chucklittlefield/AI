function Verb-Noun {
    <#
    .SYNOPSIS
        One-line summary of what this function does.

    .DESCRIPTION
        A fuller explanation of the function's purpose, behavior, and any
        important implementation details. Can span multiple lines.

    .PARAMETER ParamOne
        Description of the first parameter. Include type, required/optional,
        and valid values if applicable.

    .PARAMETER ParamTwo
        Description of the second parameter.

    .EXAMPLE
        Verb-Noun -ParamOne "value1" -ParamTwo "value2"

        Explains what this invocation does and what output to expect.

    .EXAMPLE
        "value1" | Verb-Noun -ParamTwo "value2"

        Shows pipeline usage where applicable.

    .NOTES
        Author:  <Author Name>
        Version: 1.0.0
        Date:    YYYY-MM-DD
        Any known limitations, dependencies, or caveats go here.

    .LINK
        https://docs.microsoft.com/en-us/powershell/
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ParamOne,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Option1", "Option2", "Option3")]
        [string]$ParamTwo = "Option1",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        # Runs once before pipeline input. Initialize resources, validate
        # preconditions, set up logging.
        Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"
    }

    process {
        # Runs once per pipeline object. Main logic lives here.
        try {
            if ($PSCmdlet.ShouldProcess($ParamOne, "Describe the action")) {
                # --- Core logic ---
            }
        }
        catch [System.IO.IOException] {
            Write-Error "IO error processing '$ParamOne': $_"
        }
        catch {
            Write-Error "Unexpected error processing '$ParamOne': $_"
            throw
        }
    }

    end {
        # Runs once after all pipeline input. Cleanup, summary output.
        Write-Verbose "Completed $($MyInvocation.MyCommand.Name)"
    }
}