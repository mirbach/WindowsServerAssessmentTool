#requires -Version 5.1
<#
.SYNOPSIS
Simple GUI to discover Domain Controllers and run Windows Server Assessment.
.DESCRIPTION
- "Get Domain Controllers" uses Get-ADComputer with an LDAP filter for DCs.
- Lets you choose Menu Choice (1-5) and Output Path.
- Runs the existing Invoke-WindowsServerAssessment.ps1 script against selected computers.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Control]::CheckForIllegalCrossThreadCalls = $false

function New-Label {
    param([string]$Text,[int]$X,[int]$Y,[int]$W=160,[int]$H=20)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Location = (New-Object System.Drawing.Point ($X,$Y)); $l.Size = (New-Object System.Drawing.Size ($W,$H))
    return $l
}
function New-Button {
    param([string]$Text,[int]$X,[int]$Y,[int]$W=160,[int]$H=30)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = (New-Object System.Drawing.Point ($X,$Y)); $b.Size = (New-Object System.Drawing.Size ($W,$H))
    return $b
}
function New-TextBox {
    param([string]$Text,[int]$X,[int]$Y,[int]$W=420,[int]$H=23)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Text = $Text; $t.Location = (New-Object System.Drawing.Point ($X,$Y)); $t.Size = (New-Object System.Drawing.Size ($W,$H))
    return $t
}
function New-ComboBox {
    param([int]$X,[int]$Y,[int]$W=260,[int]$H=23)
    $c = New-Object System.Windows.Forms.ComboBox
    $c.DropDownStyle = 'DropDownList'
    $c.Location = (New-Object System.Drawing.Point ($X,$Y)); $c.Size = (New-Object System.Drawing.Size ($W,$H))
    return $c
}
function New-ListBox {
    param([int]$X,[int]$Y,[int]$W=420,[int]$H=180)
    $lb = New-Object System.Windows.Forms.ListBox
    $lb.SelectionMode = 'MultiExtended'
    $lb.Location = (New-Object System.Drawing.Point ($X,$Y)); $lb.Size = (New-Object System.Drawing.Size ($W,$H))
    return $lb
}
function New-CheckBox {
    param([string]$Text,[int]$X,[int]$Y,[int]$W=220,[int]$H=20)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Location = (New-Object System.Drawing.Point ($X,$Y)); $c.Size = (New-Object System.Drawing.Size ($W,$H))
    return $c
}

$Form = New-Object System.Windows.Forms.Form
$Form.Text = 'Windows Server Assessment UI'
$Form.StartPosition = 'CenterScreen'
$Form.Size = (New-Object System.Drawing.Size (820, 760))
$Form.MaximizeBox = $true
$Form.AutoScaleMode = 'None'

# Paths
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$wrapperPath = Join-Path $scriptRoot 'Invoke-WindowsServerAssessment.ps1'

# Panels to group controls nicely
$pRSAT = New-Object System.Windows.Forms.Panel
$pRSAT.Location = (New-Object System.Drawing.Point (20,15))
$pRSAT.Size = (New-Object System.Drawing.Size (760,40))

$pDiscover = New-Object System.Windows.Forms.Panel
$pDiscover.Location = (New-Object System.Drawing.Point (20,60))
$pDiscover.Size = (New-Object System.Drawing.Size (760,40))

# Controls
$btnInstallRSAT = New-Button -Text 'Install RSAT (AD Module)' -X 0 -Y 8 -W 200
$lblRSATStatus = New-Label -Text 'RSAT: Unknown' -X 205 -Y 10 -W 120
# LAPS controls in the same toolbar
$btnInstallLAPS = New-Button -Text 'Install LAPS modules' -X 340 -Y 8 -W 200
$lblLAPSStatus = New-Label -Text 'LAPS: Unknown' -X 545 -Y 10 -W 200
# Left align discovery buttons
$btnGetDCs = New-Button -Text 'Get Domain Controllers' -X 0 -Y 8 -W 220
$btnGetMembers = New-Button -Text 'Get Member Servers' -X 240 -Y 8 -W 220
$lblComputers = New-Label -Text 'Computers (select one or more):' -X 20 -Y 120 -W 300
$lbComputers = New-ListBox -X 20 -Y 145 -W 760 -H 170
$chkRunAll = New-CheckBox -Text 'Run on all listed computers' -X 20 -Y 290 -W 260

$lblMenu = New-Label -Text 'Menu Choice:' -X 20 -Y 320
$cbMenu = New-ComboBox -X 120 -Y 350 -W 300
$cbMenu.Items.AddRange(@(
    '5 - All Sections',
    '1 - System Only',
    '2 - Network Only',
    '3 - Security Only',
    '4 - Tasks/Startup/Logs Only'
)) | Out-Null
$cbMenu.SelectedIndex = 0

$lblOutput = New-Label -Text 'Output Path:' -X 20 -Y 390
$tbOutput = New-TextBox -Text (Join-Path $scriptRoot 'AssessmentResults') -X 120 -Y 418 -W 600
$btnBrowse = New-Button -Text 'Browse' -X 730 -Y 418 -W 50 -H 26

$btnRun = New-Button -Text 'Run Assessment' -X 20 -Y 460 -W 220
$chkUseLaps = New-CheckBox -Text 'Use LAPS credentials' -X 260 -Y 467 -W 200
$btnRun.Enabled = Test-Path -LiteralPath $wrapperPath

$lblLog = New-Label -Text 'Log:' -X 20 -Y 500
$tbLog = New-Object System.Windows.Forms.TextBox
$tbLog.Multiline = $true; $tbLog.ScrollBars = 'Vertical'; $tbLog.ReadOnly = $true
$tbLog.Location = (New-Object System.Drawing.Point (20, 520))
$tbLog.Size = (New-Object System.Drawing.Size (760, 100))

# Job progress timer and output index
$progressTimer = New-Object System.Windows.Forms.Timer
$progressTimer.Interval = 20000
$script:jobOutputIndex = @{}
$script:currentJobId = $null
$script:timerHooked = $false

# Add controls
$pRSAT.Controls.AddRange(@($btnInstallRSAT, $lblRSATStatus, $btnInstallLAPS, $lblLAPSStatus))
$pDiscover.Controls.AddRange(@($btnGetDCs, $btnGetMembers))
$Form.Controls.AddRange(@(
    $pRSAT, $pDiscover,
    $lblComputers, $lbComputers, $chkRunAll,
    $lblMenu, $cbMenu,
    $lblOutput, $tbOutput, $btnBrowse,
    $btnRun, $chkUseLaps, $lblLog, $tbLog
))

# Helpers
function Write-UILog {
    param([string]$msg)
    $tbLog.AppendText(("[{0}] {1}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $msg))
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
            $lblRSATStatus.Text = 'RSAT: Installed'
            $lblRSATStatus.ForeColor = [System.Drawing.Color]::Green
        } else {
            $lblRSATStatus.Text = 'RSAT: Not installed'
            $lblRSATStatus.ForeColor = [System.Drawing.Color]::Red
        }
    } catch {
        $lblRSATStatus.Text = 'RSAT: Unknown'
        $lblRSATStatus.ForeColor = [System.Drawing.Color]::Black
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
            $lblLAPSStatus.Text = 'LAPS: Installed'
            $lblLAPSStatus.ForeColor = [System.Drawing.Color]::Green
        } else {
            $lblLAPSStatus.Text = 'LAPS: Not installed'
            $lblLAPSStatus.ForeColor = [System.Drawing.Color]::Red
        }
    } catch {
        $lblLAPSStatus.Text = 'LAPS: Unknown'
        $lblLAPSStatus.ForeColor = [System.Drawing.Color]::Black
    }
}

function Install-LAPSModulesFromGallery {
    Write-UILog 'Checking for LAPS modules...'
    try {
        # Trust PSGallery for this session if needed
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Write-UILog 'Setting PSGallery as Trusted for module install.'
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { Write-UILog ('PSGallery check failed: {0}' -f $_.Exception.Message) }

    $installedAny = $false
    # Try Windows LAPS module first
    if (-not (Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue)) {
        try {
            Write-UILog 'Installing LAPS module (Windows LAPS) from PSGallery...'
            Install-Module -Name LAPS -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module LAPS -ErrorAction SilentlyContinue | Out-Null
            $installedAny = $true
            Write-UILog 'Installed LAPS module.'
        } catch { Write-UILog ('Failed to install LAPS module: {0}' -f $_.Exception.Message) }
    }
    # Legacy AdmPwd.PS
    if (-not (Get-Command -Name Get-AdmPwdPassword -ErrorAction SilentlyContinue)) {
        try {
            Write-UILog 'Installing AdmPwd.PS (legacy LAPS) from PSGallery...'
            Install-Module -Name AdmPwd.PS -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module AdmPwd.PS -ErrorAction SilentlyContinue | Out-Null
            $installedAny = $true
            Write-UILog 'Installed AdmPwd.PS module.'
        } catch { Write-UILog ('Failed to install AdmPwd.PS: {0}' -f $_.Exception.Message) }
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
    } catch {
        Write-UILog ("Failed to install RSAT via capabilities: {0}" -f $_.Exception.Message)
    }
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
    } catch {
        Write-UILog ("Failed to install RSAT feature: {0}" -f $_.Exception.Message)
    }
}

# Events
$btnBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.SelectedPath = $tbOutput.Text
    if ($fbd.ShowDialog() -eq 'OK') { $tbOutput.Text = $fbd.SelectedPath }
})

$btnGetDCs.Add_Click({
    $lbComputers.Items.Clear()
    if (-not (Test-ActiveDirectoryModulePresent)) { return }
    try {
    Write-UILog 'Querying domain controllers via Get-ADComputer...'
        $filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        $dcs = Get-ADComputer -LDAPFilter $filter -Properties DNSHostName | Sort-Object Name
        foreach ($dc in $dcs) {
            $hostname = if ($dc.DNSHostName) { $dc.DNSHostName } else { $dc.Name }
            [void]$lbComputers.Items.Add($hostname)
        }
        Write-UILog ("Found {0} domain controllers" -f $lbComputers.Items.Count)
    } catch {
        Write-UILog ("Failed to query DCs: {0}" -f $_.Exception.Message)
    }
})

$btnGetMembers.Add_Click({
    $lbComputers.Items.Clear()
    if (-not (Test-ActiveDirectoryModulePresent)) { return }
    try {
        Write-UILog 'Querying member servers via Get-ADComputer...'
        $filter = '(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
        $servers = Get-ADComputer -LDAPFilter $filter -Properties DNSHostName,OperatingSystem | Sort-Object Name
        foreach ($srv in $servers) {
            $hostname = if ($srv.DNSHostName) { $srv.DNSHostName } else { $srv.Name }
            [void]$lbComputers.Items.Add($hostname)
        }
        Write-UILog ("Found {0} member servers" -f $lbComputers.Items.Count)
    } catch {
        Write-UILog ("Failed to query member servers: {0}" -f $_.Exception.Message)
    }
})

$btnInstallRSAT.Add_Click({
    if (-not (Test-IsElevated)) { [void][System.Windows.Forms.MessageBox]::Show('Please run this UI as Administrator to install RSAT.'); return }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $isClient = ($os.ProductType -eq 1)
        if ($isClient) { Install-ADModuleOnClient } else { Install-ADModuleOnServer }
        # Try import after install
    try { Import-Module ActiveDirectory -ErrorAction Stop | Out-Null; Write-UILog 'ActiveDirectory module loaded.' } catch { Write-UILog 'ActiveDirectory module still not available after install.' }
    Update-RSATStatus
    } catch {
        Write-UILog ("OS detection or install failed: {0}" -f $_.Exception.Message)
    }
})

$btnInstallLAPS.Add_Click({
    try {
        Install-LAPSModulesFromGallery
    } catch {
        Write-UILog ('LAPS install error: {0}' -f $_.Exception.Message)
    }
})

$btnRun.Add_Click({
    # Validate
    $menuText = $cbMenu.SelectedItem
    $menuChoice = '5'
    if ($menuText -match '^(\d) ') { $menuChoice = $Matches[1] }
    $outDir = $tbOutput.Text.Trim()
    if (-not $outDir) { [void][System.Windows.Forms.MessageBox]::Show('Please select Output Path.'); return }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    $targets = @()
    if ($chkRunAll.Checked) {
        foreach ($item in $lbComputers.Items) { $targets += [string]$item }
    } else {
        foreach ($item in $lbComputers.SelectedItems) { $targets += [string]$item }
    }
    if (-not $targets -or $targets.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show('No computers selected or listed.'); return }
    if (-not (Test-Path -LiteralPath $wrapperPath)) { [void][System.Windows.Forms.MessageBox]::Show("Wrapper not found: $wrapperPath"); return }

    $btnRun.Enabled = $false
    Write-UILog ("Starting assessment on {0} target(s) with menu {1}" -f $targets.Count, $menuChoice)

    $job = Start-Job -ScriptBlock {
        param($wrapper, $cn, $choice, $out, $useLaps)
        try {
            # Invoke the wrapper script directly to get structured results
            if ($useLaps) {
                & $wrapper -ComputerName $cn -MenuChoice $choice -OutputRoot $out -UseLaps
            } else {
                & $wrapper -ComputerName $cn -MenuChoice $choice -OutputRoot $out
            }
        } catch {
            "ERROR: $($_.Exception.Message)"
        }
    } -ArgumentList @($wrapperPath, $targets, $menuChoice, $outDir, $chkUseLaps.Checked)

    # Initialize output index for this job and register job id for the timer
    $script:currentJobId = $job.Id
    $script:jobOutputIndex[$script:currentJobId] = 0
    Write-UILog ("Started job Id {0} for {1} target(s)." -f $script:currentJobId, $targets.Count)

    # Start/ensure timer, attach handler once
    $progressTimer.Stop()
    if (-not $script:timerHooked) {
    $progressTimer.add_Tick({
        try {
            $jid = $script:currentJobId
            if (-not $jid) { return }
            if (-not (Get-Job -Id $jid -ErrorAction SilentlyContinue)) { return }
            $state = (Get-Job -Id $jid).State
            # Read incremental output
            $all = Receive-Job -Id $jid -Keep -ErrorAction SilentlyContinue
            if ($all) {
                $arr = if ($all -is [System.Array]) { $all } else { @($all) }
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

            # Periodic progress line
            $running = @(Get-Job | Where-Object { $_.State -eq 'Running' }).Count
            $notStarted = @(Get-Job | Where-Object { $_.State -eq 'NotStarted' }).Count
            $stateText = "State=$state; RunningJobs=$running; Pending=$notStarted"
            Write-UILog $stateText

            if ($state -in 'Completed','Failed','Stopped') {
                # Final receive to ensure no missed output
                $final = Receive-Job -Id $jid -Keep -ErrorAction SilentlyContinue
                if ($final) {
                    if ($final -is [System.Array]) {
                        $script:jobOutputIndex[$jid] = $final.Count
                    } else {
                        $script:jobOutputIndex[$jid] = 1
                    }
                }
                Remove-Job -Id $jid -Force -ErrorAction SilentlyContinue | Out-Null
                $progressTimer.Stop()
                $btnRun.Enabled = $true
                Write-UILog 'Assessment jobs finished.'
                $script:currentJobId = $null
            }
        } catch {
            Write-UILog ("Progress error: {0}" -f $_.Exception.Message)
            $progressTimer.Stop()
            $btnRun.Enabled = $true
        }
    })
    $script:timerHooked = $true
    }
    $progressTimer.Start()
})

# Show form
    Update-RSATStatus
    Update-LAPSStatus
[void]$Form.ShowDialog()
