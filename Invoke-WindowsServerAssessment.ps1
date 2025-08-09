#requires -Version 5.1
<#
.SYNOPSIS
Invokes Windows Server Assessment Tool on one or more remote computers in parallel and collects results locally.

.DESCRIPTION
Copies `WindowsServerAssessmentTool_V1.0.ps1` to each target, executes it remotely with the chosen menu option, waits for completion (with throttle),
then pulls back the generated artifacts into a local output folder per target. Cleans up temporary files on remote.

.PARAMETER ComputerName
One or more target computers. Use names or IPs resolvable via WinRM.

.PARAMETER Credential
Optional credential for remoting. If omitted, current user context is used.

.PARAMETER MenuChoice
Which report to run: 1 System, 2 Network, 3 Security, 4 Tasks/Startup/Logs, 5 All (default).

.PARAMETER OutputRoot
Local path where per-computer results will be copied. Defaults to "./_out/remote" next to this script.

.PARAMETER ThrottleLimit
Maximum number of concurrent remoting jobs. Default 10.

.PARAMETER UseSSL
Use HTTPS (5986) for WinRM connections.

.PARAMETER Port
Custom WinRM port. Defaults to 5985 or 5986 depending on UseSSL.

.EXAMPLE
Invoke-WindowsServerAssessment -ComputerName srv1,srv2 -MenuChoice 5 -OutputRoot C:\Reports\WSAT -ThrottleLimit 20

.NOTES
Requires WinRM remoting enabled on targets and network/firewall access.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('CN','Server','Name')]
    [string[]]$ComputerName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateSet('1','2','3','4','5')]
    [string]$MenuChoice = '5',

    [Parameter()]
    [string]$OutputRoot = $(Join-Path -Path $PSScriptRoot -ChildPath '_out/remote'),

    [Parameter()]
    [int]$ThrottleLimit = 10,

    [Parameter()]
    [switch]$UseSSL,

    [Parameter()]
    [int]$Port
)

begin {
    $ErrorActionPreference = 'Stop'

    # Resolve script to run
    $AssessmentScript = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsServerAssessmentTool_V1.0.ps1'
    if (-not (Test-Path -LiteralPath $AssessmentScript)) {
        throw "Assessment script not found at $AssessmentScript"
    }

    # Ensure local output root exists
    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    }

    # Compute default port
    if (-not $PSBoundParameters.ContainsKey('Port')) {
        $Port = if ($UseSSL) { 5986 } else { 5985 }
    }

    # WSMan timeouts require integer milliseconds
    $sessionOptions = New-PSSessionOption -OperationTimeout 1800000 -IdleTimeout 3600000 -OpenTimeout 60000 -CancelTimeout 60000

    $jobs = @()
    $sessionMap = @{}
    $tempName = ('WSAT_{0:yyyyMMdd_HHmmss}_{1}' -f (Get-Date), [System.Guid]::NewGuid().ToString('N'))
}

process {
    foreach ($cn in $ComputerName) {
        # Create a per-target local output folder
        $localOut = Join-Path -Path $OutputRoot -ChildPath $cn
        if (-not (Test-Path -LiteralPath $localOut)) { New-Item -ItemType Directory -Force -Path $localOut | Out-Null }

        Write-Verbose "[$cn] Creating session..."
        try {
            $splat = @{
                ComputerName   = $cn
                UseSSL         = [bool]$UseSSL
                Port           = $Port
                SessionOption  = $sessionOptions
                ErrorAction    = 'Stop'
            }
            if ($Credential) { $splat.Credential = $Credential }
            $session = New-PSSession @splat
            $sessionMap[$cn] = [PSCustomObject]@{
                Session       = $session
                LocalOut      = $localOut
                RemoteTempDir = "$env:TEMP\$tempName"
                RemoteScript  = "$env:TEMP\$tempName\WindowsServerAssessmentTool_V1.0.ps1"
            }
        }
        catch {
            Write-Warning "[$cn] Failed to create session: $($_.Exception.Message)"
            continue
        }

        try {
            # Prepare remote temp directory
            Invoke-Command -Session $session -ScriptBlock {
                param($dir)
                if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
            } -ArgumentList $sessionMap[$cn].RemoteTempDir | Out-Null

            # Copy script to remote
            Copy-Item -ToSession $session -Path $AssessmentScript -Destination $sessionMap[$cn].RemoteScript -Force

            # Set remote output folder (under temp, then we will pull it back)
            $remoteOut = Join-Path -Path $sessionMap[$cn].RemoteTempDir -ChildPath 'out'

            # Start job on remote
            Write-Verbose "[$cn] Starting remote job..."
            $job = Invoke-Command -Session $session -AsJob -ScriptBlock {
                param($scriptPath, $outDir, $choice)
                try {
                    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
                    & powershell -NoProfile -ExecutionPolicy Bypass -File $scriptPath -path $outDir -menuChoice $choice
                    if ($LASTEXITCODE -ne 0) { throw "Script exit code $LASTEXITCODE" }
                    return [PSCustomObject]@{ Success = $true; OutputDir = $outDir }
                }
                catch {
                    return [PSCustomObject]@{ Success = $false; Error = $_.Exception.Message; OutputDir = $outDir }
                }
            } -ArgumentList @($sessionMap[$cn].RemoteScript, $remoteOut, $MenuChoice)

            # Annotate job with target info
            $job.PSBeginTime | Out-Null  # force materialization
            $job | Add-Member -NotePropertyName Target -NotePropertyValue $cn -Force
            $job | Add-Member -NotePropertyName RemoteOut -NotePropertyValue $remoteOut -Force
            $job | Add-Member -NotePropertyName LocalOut -NotePropertyValue $localOut -Force
            $jobs += $job
        }
        catch {
            Write-Warning "[$cn] Failed to start remote job: $($_.Exception.Message)"
        }
    }
}

end {
    if (-not $jobs) {
        Write-Warning 'No jobs started.'
        return
    }

    Write-Verbose ("Waiting for {0} jobs (throttle {1})..." -f $jobs.Count, $ThrottleLimit)

    # Wait for completion; do not Receive-Job until a job is done
    $inProgress = @($jobs)
    $completed = @()

    while ($inProgress.Count -gt 0) {
        $done = Wait-Job -Job $inProgress -Any -Timeout 5
        if ($done) {
            foreach ($j in @($done)) {
                try {
                    Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
                } catch { }
                $inProgress = $inProgress | Where-Object { $_.Id -ne $j.Id }
                $completed += $j
            }
        }
    }

    $results = @()
    foreach ($j in $completed) {
        $cn = $j.Target
        $sess = $sessionMap[$cn].Session
        $remoteOut = $j.RemoteOut
        $localOut = $j.LocalOut

    # Job already completed; receive without -Wait and suppress non-terminating errors
    $payload = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue
        $success = $false
        $errorMsg = $null
        if ($payload -and $payload.Success) {
            $success = $true
        }
        elseif ($payload) {
            $errorMsg = $payload.Error
        }

        if ($success) {
            try {
                # Pull artifacts
                Copy-Item -FromSession $sess -Path (Join-Path $remoteOut '*') -Destination $localOut -Recurse -Force -ErrorAction Stop
            }
            catch {
                $success = $false
                $errorMsg = "Copy back failed: $($_.Exception.Message)"
            }
        }

        # Cleanup remote temp
        try {
            Invoke-Command -Session $sess -ScriptBlock { param($dir) if (Test-Path -LiteralPath $dir) { Remove-Item -Recurse -Force -Path $dir } } -ArgumentList $sessionMap[$cn].RemoteTempDir -ErrorAction SilentlyContinue | Out-Null
        } catch { }

        $results += [PSCustomObject]@{
            ComputerName = $cn
            Success      = $success
            LocalOutput  = $localOut
            Error        = $errorMsg
        }
    }

    # Close sessions
    if ($sessionMap.Count -gt 0) {
        try { Remove-PSSession -Session ($sessionMap.Values | ForEach-Object { $_.Session }) -ErrorAction SilentlyContinue } catch { }
    }

    # Emit summary
    $results
}
