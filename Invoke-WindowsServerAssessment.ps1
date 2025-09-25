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
# LAPS support: Use -UseLaps to authenticate with Local Administrator Password Solution passwords per target. Requires the 'LAPS' (Windows LAPS) or 'AdmPwd.PS' (legacy) module and read permissions.
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
    [int]$Port,

    # Use LAPS credentials when connecting (retrieved per target)
    [Parameter()]
    [switch]$UseLaps,

    # Optional override for the local admin account name if the LAPS policy uses a non-default name (otherwise the account name from Windows LAPS will be used, or 'Administrator' for legacy LAPS)
    [Parameter()]
    [string]$LapsAccountName
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

    # TrustedHosts management for LAPS connections
    $originalTrustedHosts = $null
    $trustedHostsModified = $false

    function Get-TargetLapsCredential {
        param(
            [Parameter(Mandatory)][string]$ComputerName
        )
        # Try Windows LAPS first (Get-LapsADPassword)
        $lapsAD = Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue
        if ($lapsAD) {
            # Extract short name from FQDN if needed
            $shortName = $ComputerName
            if ($ComputerName -like '*.*') {
                $shortName = $ComputerName.Split('.')[0]
            }
            # Try with short name first (since manual command works), then FQDN
            foreach ($name in @($shortName, $ComputerName)) {
                try {
                    $res = Get-LapsADPassword -Identity $name -AsPlainText
                    if ($res -and $res.Password) {
                        $pwdPlain = [string]$res.Password
                        $acctName = if ($res.Account) { [string]$res.Account } else { 'Administrator' }
                        $sec = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
                        $user = ".\$acctName"  # Use local account format for authentication
                        return (New-Object System.Management.Automation.PSCredential($user, $sec))
                    }
                } catch {}
            }
        }
        # Legacy LAPS (AdmPwd.PS)
        $legacy = Get-Command -Name Get-AdmPwdPassword -ErrorAction SilentlyContinue
        if ($legacy) {
            # Extract short name from FQDN if needed
            $shortName = $ComputerName
            if ($ComputerName -like '*.*') {
                $shortName = $ComputerName.Split('.')[0]
            }
            # Try with short name first, then FQDN
            foreach ($name in @($shortName, $ComputerName)) {
                try {
                    $res = Get-AdmPwdPassword -ComputerName $name -ErrorAction Stop
                    if ($res) {
                        $pwdPlain = [string]$res.Password
                        $acctName = 'Administrator'  # Legacy LAPS typically uses Administrator
                        $sec = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
                        $user = ".\$acctName"  # Use local account format for authentication
                        return (New-Object System.Management.Automation.PSCredential($user, $sec))
                    }
                } catch {}
            }
        }
        throw "Failed to retrieve LAPS password for $ComputerName. Ensure LAPS module is installed and you have read permissions."
    }
}

process {
    # Manage TrustedHosts for LAPS connections
    if ($UseLaps) {
        try {
            $originalTrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
            Write-Verbose "Original TrustedHosts: $originalTrustedHosts"
            
            # Add target computers to TrustedHosts
            $currentHosts = if ($originalTrustedHosts) { $originalTrustedHosts -split ',' | ForEach-Object { $_.Trim() } } else { @() }
            $newHosts = @()
            
            foreach ($cn in $ComputerName) {
                if ($currentHosts -notcontains $cn) {
                    $newHosts += $cn
                }
            }
            
            if ($newHosts.Count -gt 0) {
                $updatedHosts = $currentHosts + $newHosts
                $trustedHostsString = $updatedHosts -join ','
                Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $trustedHostsString -Force
                $trustedHostsModified = $true
                Write-Verbose "Added to TrustedHosts: $($newHosts -join ', ')"
            }
        } catch {
            Write-Warning "Failed to modify TrustedHosts: $($_.Exception.Message). WinRM connections may fail due to certificate validation."
        }
    }

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
            elseif ($UseLaps) {
                try {
                    $lapsCred = Get-TargetLapsCredential -ComputerName $cn
                    $splat.Credential = $lapsCred
                    # Use default authentication (don't force Negotiate for local accounts)
                } catch {
                    Write-Warning "[$cn] LAPS credential retrieval failed: $($_.Exception.Message)"; throw
                }
            }
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
            $console = & powershell -NoProfile -ExecutionPolicy Bypass -File $scriptPath -path $outDir -menuChoice $choice 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "Script exit code $LASTEXITCODE" }
            # Check remote for a generated report
            $html = Get-ChildItem -LiteralPath $outDir -Filter '*-SystemReport.html' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
            return [PSCustomObject]@{ Success = $true; OutputDir = $outDir; Html = $html; Console = $console }
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
                # Do not receive here; just move to completed list
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

        # Job already completed; receive without -Wait and capture errors silently
        $payloadAll = $null
        try {
            $payloadAll = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        } catch { }
        $payload = if ($payloadAll -is [array]) { $payloadAll[-1] } else { $payloadAll }
        $success = $false
        $errorMsg = $null
        $consoleOut = $null
    if ($payload -and $payload.Success) {
            $success = $true
            if ($payload.PSObject.Properties.Match('Console').Count -gt 0) { $consoleOut = $payload.Console }
        }
        elseif ($payload) {
            $errorMsg = $payload.Error
            if ($payload.PSObject.Properties.Match('Console').Count -gt 0) { $consoleOut = $payload.Console }
        }

    if ($success) {
            try {
                # Check if any files were generated
                $hasFiles = $false
                try {
                    $fileCount = Invoke-Command -Session $sess -ScriptBlock { param($p) if (Test-Path -LiteralPath $p) { (Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count } else { 0 } } -ArgumentList $remoteOut -ErrorAction Stop
                    if ($fileCount -and $fileCount -gt 0) { $hasFiles = $true }
                } catch { $hasFiles = $false }

                if ($hasFiles) {
                    # Pull artifacts (copy contents). Use wildcard only when files exist.
                    Copy-Item -FromSession $sess -Path (Join-Path $remoteOut '*') -Destination $localOut -Recurse -Force -ErrorAction Stop
                } else {
                    $success = $false
            $errorMsg = 'Remote run completed but no files were generated.'
                }
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

        # Discover HTML report (pattern: <hostname>-SystemReport.html)
    $htmlReport = $null
        try {
            $htmlReport = Get-ChildItem -LiteralPath $localOut -Filter '*-SystemReport.html' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        } catch { }

        $results += [PSCustomObject]@{
            ComputerName = $cn
            Success      = $success
            LocalOutput  = $localOut
            HtmlReport   = $htmlReport
            Error        = $errorMsg
            Console      = $consoleOut
        }
    }

    # Close sessions
    if ($sessionMap.Count -gt 0) {
        try { Remove-PSSession -Session ($sessionMap.Values | ForEach-Object { $_.Session }) -ErrorAction SilentlyContinue } catch { }
    }

    # Restore TrustedHosts if modified
    if ($trustedHostsModified -and $null -ne $originalTrustedHosts) {
        try {
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $originalTrustedHosts -Force
            Write-Verbose "Restored original TrustedHosts: $originalTrustedHosts"
        } catch {
            Write-Warning "Failed to restore TrustedHosts: $($_.Exception.Message)"
        }
    }

    # Emit summary
    $results
}
