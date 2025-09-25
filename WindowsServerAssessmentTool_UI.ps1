#requires -Version 5.1
<#
.SYNOPSIS
WPF GUI to discover Domain Controllers and run Windows Server Assessment.
.DESCRIPTION
- Provides RSAT/LAPS install buttons with status indicators.
- Lets you choose Menu Choice (1-5), Output Path, and whether to use LAPS credentials.
- Runs Invoke-WindowsServerAssessment.ps1 against selected computers asynchronously.
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Control]::CheckForIllegalCrossThreadCalls = $false

# Paths
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$wrapperPath = Join-Path $scriptRoot 'Invoke-WindowsServerAssessment.ps1'

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Server Assessment UI" Height="760" Width="840" WindowStartupLocation="CenterScreen">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Toolbar: RSAT & LAPS -->
    <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8" VerticalAlignment="Center">
      <Button x:Name="BtnInstallRSAT" Content="Install RSAT (AD Module)" Width="200" Margin="0,0,8,0"/>
      <TextBlock x:Name="LblRSATStatus" Text="RSAT: Unknown" Width="140" VerticalAlignment="Center"/>
      <Button x:Name="BtnInstallLAPS" Content="Install LAPS modules" Width="200" Margin="16,0,8,0"/>
      <TextBlock x:Name="LblLAPSStatus" Text="LAPS: Unknown" Width="160" VerticalAlignment="Center"/>
    </StackPanel>

    <!-- Discovery row -->
    <StackPanel Orientation="Horizontal" Grid.Row="1" Margin="0,0,0,8">
      <Button x:Name="BtnGetDCs" Content="Get Domain Controllers" Width="220" Margin="0,0,8,0"/>
      <Button x:Name="BtnGetMembers" Content="Get Member Servers" Width="220"/>
    </StackPanel>

    <!-- Computers list -->
    <StackPanel Grid.Row="2" Margin="0,0,0,8">
      <TextBlock Text="Computers (select one or more):" Margin="0,0,0,4"/>
      <ListBox x:Name="LbComputers" Height="200" SelectionMode="Extended"/>
      <CheckBox x:Name="ChkRunAll" Content="Run on all listed computers" Margin="0,6,0,0"/>
    </StackPanel>

    <!-- Menu choice -->
    <StackPanel Orientation="Horizontal" Grid.Row="3" Margin="0,0,0,8" VerticalAlignment="Center">
      <TextBlock Text="Menu Choice:" Width="100" VerticalAlignment="Center"/>
      <ComboBox x:Name="CbMenu" Width="320">
        <ComboBoxItem>5 - All Sections</ComboBoxItem>
        <ComboBoxItem>1 - System Only</ComboBoxItem>
        <ComboBoxItem>2 - Network Only</ComboBoxItem>
        <ComboBoxItem>3 - Security Only</ComboBoxItem>
        <ComboBoxItem>4 - Tasks/Startup/Logs Only</ComboBoxItem>
      </ComboBox>
    </StackPanel>

    <!-- Output path and run controls -->
    <StackPanel Grid.Row="4" Margin="0,0,0,8">
      <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
        <TextBlock Text="Output Path:" Width="100" VerticalAlignment="Center"/>
        <TextBox x:Name="TbOutput" Width="600" Margin="0,0,8,0"/>
        <Button x:Name="BtnBrowse" Content="Browse" Width="80"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal">
        <Button x:Name="BtnRun" Content="Run Assessment" Width="180"/>
        <CheckBox x:Name="ChkUseLaps" Content="Use LAPS credentials" Margin="12,6,0,0"/>
      </StackPanel>
    </StackPanel>

    <!-- Log -->
    <StackPanel Grid.Row="5">
      <TextBlock Text="Log:"/>
      <ScrollViewer VerticalScrollBarVisibility="Auto" Height="200">
        <TextBox x:Name="TbLog" AcceptsReturn="True" IsReadOnly="True" TextWrapping="NoWrap"/>
      </ScrollViewer>
    </StackPanel>
  </Grid>
</Window>
"@

[xml]$xml = $xaml
$reader = New-Object System.Xml.XmlNodeReader $xml
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Find controls
$BtnInstallRSAT = $Window.FindName('BtnInstallRSAT')
$LblRSATStatus  = $Window.FindName('LblRSATStatus')
$BtnInstallLAPS = $Window.FindName('BtnInstallLAPS')
$LblLAPSStatus  = $Window.FindName('LblLAPSStatus')
$BtnGetDCs      = $Window.FindName('BtnGetDCs')
$BtnGetMembers  = $Window.FindName('BtnGetMembers')
$LbComputers    = $Window.FindName('LbComputers')
$ChkRunAll      = $Window.FindName('ChkRunAll')
$CbMenu         = $Window.FindName('CbMenu')
$TbOutput       = $Window.FindName('TbOutput')
$BtnBrowse      = $Window.FindName('BtnBrowse')
$BtnRun         = $Window.FindName('BtnRun')
$ChkUseLaps     = $Window.FindName('ChkUseLaps')
$TbLog          = $Window.FindName('TbLog')

# Initialize defaults
$CbMenu.SelectedIndex = 0
$TbOutput.Text = (Join-Path $scriptRoot 'AssessmentResults')
$BtnRun.IsEnabled = Test-Path -LiteralPath $wrapperPath

# Helpers
function Write-UILog {
    param([string]$msg)
    $Window.Dispatcher.Invoke([action]{
        $TbLog.AppendText(("[{0}] {1}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $msg))
        $TbLog.ScrollToEnd()
    })
}

function Test-ActiveDirectoryModulePresent {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-UILog 'ActiveDirectory module not found. Install RSAT: Active Directory module and try again.'
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
    return $true
}

function Test-IsElevated { 
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-RSATStatus {
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            $Window.Dispatcher.Invoke([action]{ $LblRSATStatus.Text = 'RSAT: Installed'; $LblRSATStatus.Foreground = 'Green' })
        } else {
            $Window.Dispatcher.Invoke([action]{ $LblRSATStatus.Text = 'RSAT: Not installed'; $LblRSATStatus.Foreground = 'Red' })
        }
    } catch {
        $Window.Dispatcher.Invoke([action]{ $LblRSATStatus.Text = 'RSAT: Unknown'; $LblRSATStatus.Foreground = 'Black' })
    }
}

function Test-LAPSModulePresent {
    try {
        if (Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue) { return $true }
        if (Get-Command -Name Get-AdmPwdPassword -ErrorAction SilentlyContinue) { return $true }
        return $false
    } catch { return $false }
}

function Update-LAPSStatus {
    try {
        if (Test-LAPSModulePresent) {
            $Window.Dispatcher.Invoke([action]{ $LblLAPSStatus.Text = 'LAPS: Installed'; $LblLAPSStatus.Foreground = 'Green' })
        } else {
            $Window.Dispatcher.Invoke([action]{ $LblLAPSStatus.Text = 'LAPS: Not installed'; $LblLAPSStatus.Foreground = 'Red' })
        }
    } catch {
        $Window.Dispatcher.Invoke([action]{ $LblLAPSStatus.Text = 'LAPS: Unknown'; $LblLAPSStatus.Foreground = 'Black' })
    }
}

function Install-LAPSModulesFromGallery {
    Write-UILog 'Checking for LAPS modules...'
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Write-UILog 'Setting PSGallery as Trusted for module install.'
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { Write-UILog ("PSGallery check failed: {0}" -f $_.Exception.Message) }

    $installedAny = $false
    if (-not (Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue)) {
        try {
            Write-UILog 'Installing LAPS module (Windows LAPS) from PSGallery...'
            Install-Module -Name LAPS -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module LAPS -ErrorAction SilentlyContinue | Out-Null
            $installedAny = $true
            Write-UILog 'Installed LAPS module.'
        } catch { Write-UILog ("Failed to install LAPS module: {0}" -f $_.Exception.Message) }
    }
    if (-not (Get-Command -Name Get-AdmPwdPassword -ErrorAction SilentlyContinue)) {
        try {
            Write-UILog 'Installing AdmPwd.PS (legacy LAPS) from PSGallery...'
            Install-Module -Name AdmPwd.PS -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module AdmPwd.PS -ErrorAction SilentlyContinue | Out-Null
            $installedAny = $true
            Write-UILog 'Installed AdmPwd.PS module.'
        } catch { Write-UILog ("Failed to install AdmPwd.PS: {0}" -f $_.Exception.Message) }
    }
    if (-not $installedAny) { Write-UILog 'No LAPS modules were installed. They may already be present or installation failed.' }
    Update-LAPSStatus
}

function Install-ADModuleOnClient {
    try {
        Write-UILog 'Checking Windows Capabilities for RSAT Active Directory...'
        $cap = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like 'Rsat.ActiveDirectory*' } | Select-Object -First 1
        if (-not $cap) { Write-UILog 'RSAT AD capability not found. Your Windows edition may not support FoD or WSUS blocks downloads.'; return }
        if ($cap.State -eq 'Installed') { Write-UILog 'RSAT AD capability already installed.'; return }
        Write-UILog ("Installing capability: {0}" -f $cap.Name)
        $res = Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
        Write-UILog ("Install state: {0}" -f $res.State)
    } catch { Write-UILog ("Failed to install RSAT via capabilities: {0}" -f $_.Exception.Message) }
}

function Install-ADModuleOnServer {
    try {
        if (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue) {
            Write-UILog 'Installing feature RSAT-AD-PowerShell (server)...'
            $r = Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop
            if ($r.Success) { Write-UILog 'Feature installed or already present.' } else { Write-UILog 'Feature install did not report success.' }
        } elseif (Get-Command -Name Add-WindowsFeature -ErrorAction SilentlyContinue) {
            Write-UILog 'Installing feature RSAT-AD-PowerShell (legacy server)...'
            $r = Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
            if ($r.Success) { Write-UILog 'Feature installed or already present.' } else { Write-UILog 'Feature install did not report success.' }
        } else {
            Write-UILog 'Windows feature cmdlets not available on this system.'
        }
    } catch { Write-UILog ("Failed to install RSAT feature: {0}" -f $_.Exception.Message) }
}

# Events
$BtnBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.SelectedPath = $TbOutput.Text
    if ($fbd.ShowDialog() -eq 'OK') { $TbOutput.Text = $fbd.SelectedPath }
})

$BtnGetDCs.Add_Click({
    $LbComputers.Items.Clear()
    if (-not (Test-ActiveDirectoryModulePresent)) { return }
    try {
        Write-UILog 'Querying domain controllers in all domains via Get-ADComputer...'
        $filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

        # Get all domains in the forest
        $forest = Get-ADForest
        $allDCs = @()

        foreach ($domain in $forest.Domains) {
            Write-UILog ("Querying domain: {0}" -f $domain)
            try {
                $domainDCs = Get-ADComputer -LDAPFilter $filter -Server $domain -Properties DNSHostName | Sort-Object Name
                $allDCs += $domainDCs
            } catch {
                Write-UILog ("Failed to query domain {0}: {1}" -f $domain, $_.Exception.Message)
            }
        }

        # Remove duplicates based on DNSHostName or Name
        $uniqueDCs = $allDCs | Group-Object -Property { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } } | ForEach-Object { $_.Group[0] }

        foreach ($dc in $uniqueDCs) {
            $hostname = if ($dc.DNSHostName) { $dc.DNSHostName } else { $dc.Name }
            [void]$LbComputers.Items.Add($hostname)
        }
        Write-UILog ("Found {0} domain controllers across {1} domains" -f $LbComputers.Items.Count, $forest.Domains.Count)
    } catch { Write-UILog ("Failed to query DCs: {0}" -f $_.Exception.Message) }
})

$BtnGetMembers.Add_Click({
    $LbComputers.Items.Clear()
    if (-not (Test-ActiveDirectoryModulePresent)) { return }
    try {
        Write-UILog 'Querying member servers via Get-ADComputer...'
        $filter = '(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
        $servers = Get-ADComputer -LDAPFilter $filter -Properties DNSHostName,OperatingSystem | Sort-Object Name
        foreach ($srv in $servers) {
            $hostname = if ($srv.DNSHostName) { $srv.DNSHostName } else { $srv.Name }
            [void]$LbComputers.Items.Add($hostname)
        }
        Write-UILog ("Found {0} member servers" -f $LbComputers.Items.Count)
    } catch { Write-UILog ("Failed to query member servers: {0}" -f $_.Exception.Message) }
})

$BtnInstallRSAT.Add_Click({
    if (-not (Test-IsElevated)) { [void][System.Windows.MessageBox]::Show('Please run this UI as Administrator to install RSAT.'); return }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $isClient = ($os.ProductType -eq 1)
        if ($isClient) { Install-ADModuleOnClient } else { Install-ADModuleOnServer }
        try { Import-Module ActiveDirectory -ErrorAction Stop | Out-Null; Write-UILog 'ActiveDirectory module loaded.' } catch { Write-UILog 'ActiveDirectory module still not available after install.' }
        Update-RSATStatus
    } catch { Write-UILog ("OS detection or install failed: {0}" -f $_.Exception.Message) }
})

$BtnInstallLAPS.Add_Click({
    try { Install-LAPSModulesFromGallery } catch { Write-UILog ("LAPS install error: {0}" -f $_.Exception.Message) }
})

$ChkUseLaps.Add_Checked({
    # LAPS is enabled, no additional setup needed
})

$ChkUseLaps.Add_Unchecked({
    # LAPS is disabled, no action needed
})

$BtnRun.Add_Click({
    $menuText = ($CbMenu.SelectedItem | ForEach-Object { $_.ToString() })
    $menuChoice = '5'
    if ($menuText -match '^(\d) ') { $menuChoice = $Matches[1] }
    $outDir = $TbOutput.Text.Trim()
    if (-not $outDir) { [void][System.Windows.MessageBox]::Show('Please select Output Path.'); return }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    $targets = @()
    if ($ChkRunAll.IsChecked) {
        foreach ($item in $LbComputers.Items) { $targets += [string]$item }
    } else {
        foreach ($item in $LbComputers.SelectedItems) { $targets += [string]$item }
    }
    if (-not $targets -or $targets.Count -eq 0) { [void][System.Windows.MessageBox]::Show('No computers selected or listed.'); return }
    if (-not (Test-Path -LiteralPath $wrapperPath)) { [void][System.Windows.MessageBox]::Show("Wrapper not found: $wrapperPath"); return }

    # Pre-validate LAPS credentials if LAPS is enabled
    if ($ChkUseLaps.IsChecked) {
        Write-UILog "Pre-validating LAPS credentials for all targets before starting assessment..."
        Write-UILog "NOTE: When using LAPS accounts, ensure LocalAccountTokenFilterPolicy=1 is set on target servers."
        Write-UILog "See: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction"

        # Import LAPS modules if needed
        try { Import-Module LAPS -ErrorAction SilentlyContinue } catch {}
        try { Import-Module AdmPwd.PS -ErrorAction SilentlyContinue } catch {}

        # Define the LAPS credential function inline
        function Get-TargetLapsCredential {
            param(
                [Parameter(Mandatory)][string]$ComputerName
            )
            # Extract short name from FQDN if needed
            $shortName = $ComputerName
            if ($ComputerName -like '*.*') {
                $shortName = $ComputerName.Split('.')[0]
            }

            # Try Windows LAPS first (Get-LapsADPassword)
            $lapsAD = Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue
            if ($lapsAD) {
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
            throw "Failed to retrieve LAPS password for $ComputerName (tried both short name and FQDN)."
        }

        $validationErrors = @()
        foreach ($computer in $targets) {
            try {
                $cred = Get-TargetLapsCredential -ComputerName $computer
                Write-UILog ("[OK] LAPS credentials validated for {0} (account: {1})" -f $computer, $cred.UserName)
            } catch {
                $errorMsg = $_.Exception.Message
                Write-UILog ("[FAIL] LAPS credential validation failed for {0}: {1}" -f $computer, $errorMsg)
                $validationErrors += "${computer}: $errorMsg"
            }
        }

        if ($validationErrors.Count -gt 0) {
            $errorSummary = "LAPS credential validation failed for {0} out of {1} computers:`n`n" -f $validationErrors.Count, $targets.Count
            $errorSummary += ($validationErrors -join "`n")
            $errorSummary += "`n`nPlease ensure LAPS is properly configured for these computers."
            [void][System.Windows.MessageBox]::Show($errorSummary, 'LAPS Validation Failed')
            return
        }

        Write-UILog "All LAPS credentials validated successfully. Starting assessment..."
    }

    $BtnRun.IsEnabled = $false
    Write-UILog ("Starting assessment on {0} target(s) with menu {1}" -f $targets.Count, $menuChoice)

    $job = Start-Job -ScriptBlock {
        param($wrapper, $cn, $choice, $out, $useLaps)
        try {
            $params = @{
                ComputerName = $cn
                MenuChoice = $choice
                OutputRoot = $out
            }
            if ($useLaps) {
                $params.UseLaps = $true
            }
            & $wrapper @params
        } catch { "ERROR: $($_.Exception.Message)" }
    } -ArgumentList @($wrapperPath, $targets, $menuChoice, $outDir, $ChkUseLaps.IsChecked)

    # Track job output indices
    if (-not $script:jobOutputIndex) { $script:jobOutputIndex = @{} }
    $script:jobOutputIndex[$job.Id] = 0
    $script:currentJobId = $job.Id
    Write-UILog ("Started job Id {0} for {1} target(s)." -f $script:currentJobId, $targets.Count)

    if (-not $script:dispatcherTimer) {
        $script:dispatcherTimer = New-Object Windows.Threading.DispatcherTimer
        $script:dispatcherTimer.Interval = [TimeSpan]::FromSeconds(20)
        $script:dispatcherTimer.add_Tick({
            try {
                $jid = $script:currentJobId
                if (-not $jid) { return }
                if (-not (Get-Job -Id $jid -ErrorAction SilentlyContinue)) { return }
                $state = (Get-Job -Id $jid).State
                $all = Receive-Job -Id $jid -Keep -ErrorAction SilentlyContinue
                if ($all) {
                    $arr = if ($all -is [System.Array]) { $all } else { @($all) }
                    # Ensure jobOutputIndex entry exists
                    if (-not $script:jobOutputIndex.ContainsKey($jid)) {
                        $script:jobOutputIndex[$jid] = 0
                    }
                    $start = [int]($script:jobOutputIndex[$jid])
                    for ($i = $start; $i -lt $arr.Count; $i++) {
                        $o = $arr[$i]
                        if ($o -is [psobject] -and $o.PSObject.Properties.Match('ComputerName').Count -gt 0) {
                            Write-UILog ("{0} => Success={1}; Output={2}; Html={3}; Error={4}" -f $o.ComputerName, $o.Success, $o.LocalOutput, $o.HtmlReport, $o.Error)
                            if (-not $o.Success -and $o.PSObject.Properties.Match('Console').Count -gt 0 -and $o.Console) {
                                Write-UILog ('--- Console ---')
                                ($o.Console -split "\r?\n") | ForEach-Object { if($_){ Write-UILog $_ } }
                                Write-UILog ('---------------')
                            }
                        } else {
                            Write-UILog ([string]$o)
                        }
                    }
                    $script:jobOutputIndex[$jid] = $arr.Count
                }

                $running = @(Get-Job | Where-Object { $_.State -eq 'Running' }).Count
                $notStarted = @(Get-Job | Where-Object { $_.State -eq 'NotStarted' }).Count
                Write-UILog ("State=$state; RunningJobs=$running; Pending=$notStarted")

                if ($state -in 'Completed','Failed','Stopped') {
                    $final = Receive-Job -Id $jid -Keep -ErrorAction SilentlyContinue
                    if ($final) {
                        # Ensure jobOutputIndex entry exists before updating
                        if (-not $script:jobOutputIndex.ContainsKey($jid)) {
                            $script:jobOutputIndex[$jid] = 0
                        }
                        if ($final -is [System.Array]) { $script:jobOutputIndex[$jid] = $final.Count }
                        else { $script:jobOutputIndex[$jid] = 1 }
                    }
                    Remove-Job -Id $jid -Force -ErrorAction SilentlyContinue | Out-Null
                    $script:dispatcherTimer.Stop()
                    $Window.Dispatcher.Invoke([action]{ $BtnRun.IsEnabled = $true })
                    Write-UILog 'Assessment jobs finished.'
                    $script:currentJobId = $null
                }
            } catch {
                Write-UILog ("Progress error: {0}" -f $_.Exception.Message)
                $script:dispatcherTimer.Stop()
                $Window.Dispatcher.Invoke([action]{ $BtnRun.IsEnabled = $true })
            }
        })
    }
    $script:dispatcherTimer.Start()
})

# Show window
Update-RSATStatus
Update-LAPSStatus
[void]$Window.ShowDialog()
