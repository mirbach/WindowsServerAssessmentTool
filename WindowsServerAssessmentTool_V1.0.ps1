<#
.SYNOPSIS
    Generates a comprehensive system health check report in HTML and CSV formats.
.DESCRIPTION
    This script collects various system information including hardware, software, security settings,
    and performance metrics, then exports them to an HTML report and individual CSV files. Running the script on a domain controller may not provide all information
.NOTES
    File Name      : WindowsServerAssessmentTool_V1.ps1
    Author         : Abdullah Zmaili
    Version       : 1.0
    Date Created : 2025-June-16
    Prerequisite   : PowerShell 5.1 or later, Administrator privileges for some checks
#>

param(
    [string]$path = "C:\temp",
    [ValidateSet("1","2","3","4","5")]
    [string]$menuChoice = "5"
)

# === Create directory if it doesn't exist ===
if (-not (Test-Path -Path $path)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

# === Define output file paths ===
$ServerName = hostname
$htmlFile = Join-Path -Path $path -ChildPath "$ServerName-SystemReport.html"
$GPOSettings = Join-Path -Path $path -ChildPath "$ServerName-GPOSettings.html"
$csvSystemlogs = Join-Path -Path $path -ChildPath "$ServerName-Systemlogs.csv"
$csvApplicationlogs = Join-Path -Path $path -ChildPath "$ServerName-Applicationlogs.csv"
$csvSecuritylogs = Join-Path -Path $path -ChildPath "$ServerName-Securitylogs.csv"
$csvShares = Join-Path -Path $path -ChildPath "$ServerName-SMBShares.csv"
$csvRunning = Join-Path -Path $path -ChildPath "$ServerName-RunningServices.csv"
$csvStopped = Join-Path -Path $path -ChildPath "$ServerName-StoppedServices.csv"
$csvWinFeatures = Join-Path -Path $path -ChildPath "$ServerName-WinFeatures.csv"
$csvdiskinfo = Join-Path -Path $path -ChildPath "$ServerName-DiskInfo.csv"
$csvraminfo = Join-Path -Path $path -ChildPath "$ServerName-RAMInfo.csv"
$csvnicinfo = Join-Path -Path $path -ChildPath "$ServerName-NICInfo.csv"
$csvtrafficinfo = Join-Path -Path $path -ChildPath "$ServerName-TrafficInfo.csv"
$csvcpuusageinfo = Join-Path -Path $path -ChildPath "$ServerName-CPUUsage.csv"
$csvcpuinfo = Join-Path -Path $path -ChildPath "$ServerName-CPUInfo.csv"
$csvosinfo = Join-Path -Path $path -ChildPath "$ServerName-OSInfo.csv"
$csvupdatesinstalledinfo = Join-Path -Path $path -ChildPath "$ServerName-UpdatesInstalledInfo.csv"
$csvinactiveaccountsinfo = Join-Path -Path $path -ChildPath "$ServerName-InactiveAccountsInfo.csv"
$csvlocalAdmins = Join-Path -Path $path -ChildPath "$ServerName-LocalAdmins.csv"
$csvuptimeinfo = Join-Path -Path $path -ChildPath "$ServerName-UpTime.csv"
$csvmissingupdatesinfo  = Join-Path -Path $path -ChildPath "$ServerName-MissingUpdates.csv"
$csveventlog = Join-Path -Path $path -ChildPath "$ServerName-EventViewerLogs.csv"
$csvAVsettingsinfo = Join-Path -Path $path -ChildPath "$ServerName-AVSettings.csv"
$csvFWstatusinfo = Join-Path -Path $path -ChildPath "$ServerName-FirewallStatus.csv"
$csvFWSettingsinfo = Join-Path -Path $path -ChildPath "$ServerName-FirewallSettings.csv"
$csvstartupprogsinfo = Join-Path -Path $path -ChildPath "$ServerName-StartupProgs.csv"
$csvScheduledTasksinfo = Join-Path -Path $path -ChildPath "$ServerName-ScheduledTasks.csv"
$csvinstalledprogsinfo = Join-Path -Path $path -ChildPath "$ServerName-InstalledProgs.csv"
$csvopenportsinfo = Join-Path -Path $path -ChildPath "$ServerName-OpenPorts.csv"
$csvallProcesses  = Join-Path -Path $path -ChildPath "$ServerName-allProcesses.csv"
$csvSMBv1 = Join-Path -Path $path -ChildPath "$ServerName-SMBv1.csv"
$csvauditSettings = Join-Path -Path $path -ChildPath "$ServerName-auditSettings.csv"
$csvTLSregSettings = Join-Path -Path $path -ChildPath "$ServerName-TLSregSettings.csv"
$csvUACSettings = Join-Path -Path $path -ChildPath "$ServerName-UACSettings.csv"
$csvPSExecPolicy = Join-Path -Path $path -ChildPath "$ServerName-PSExecPolicy.csv"
$csvRDPSecurity = Join-Path -Path $path -ChildPath "$ServerName-RDPSecurity.csv"
$csvCertificates = Join-Path -Path $path -ChildPath "$ServerName-Certificates.csv"
$csvDNSSettings = Join-Path -Path $path -ChildPath "$ServerName-DNSSettings.csv"
$csvDefenderASR = Join-Path -Path $path -ChildPath "$ServerName-DefenderASR.csv"

# ----------------------------
# MENU SELECTION (PARAMETERIZED)
# ----------------------------

Write-Host "`n=== SYSTEM HEALTH CHECK MENU ===" -ForegroundColor Cyan
Write-Host "Selected scope: $menuChoice" -ForegroundColor Yellow
switch ($menuChoice) {
    "1" { Write-Host "SYSTEM INFORMATION ONLY" -ForegroundColor Green }
    "2" { Write-Host "NETWORK CHECKS ONLY" -ForegroundColor Green }
    "3" { Write-Host "SECURITY CHECKS ONLY" -ForegroundColor Green }
    "4" { Write-Host "SCHEDULED TASKS & STARTUP & LOGS ONLY" -ForegroundColor Green }
    "5" { Write-Host "ALL SECTIONS (Complete Health Check)" -ForegroundColor Green }
}

$collectSystemOnly = ($menuChoice -eq "1")
$collectNetworkOnly = ($menuChoice -eq "2")
$collectSecurityOnly = ($menuChoice -eq "3")
$collectTasksOnly = ($menuChoice -eq "4")

if ($collectSystemOnly) {
    Write-Host "The script will collect only system-related information." -ForegroundColor Yellow
} elseif ($collectNetworkOnly) {
    Write-Host "The script will collect only network-related information." -ForegroundColor Yellow
} elseif ($collectSecurityOnly) {
    Write-Host "The script will collect only security-related information." -ForegroundColor Yellow
} elseif ($collectTasksOnly) {
    Write-Host "The script will collect only tasks, startup programs, and logs information." -ForegroundColor Yellow
} else {
    Write-Host "The script will collect comprehensive system health information." -ForegroundColor Yellow
}
Write-Host "`nStarting data collection..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

function Get-IconHTML {
    <#
    .SYNOPSIS
        Helper function to get HTML icon symbols
    .PARAMETER IconName
        Name of the icon
    #>
    param(
        [string]$IconName
    )
    
    # Return simple HTML symbols/characters based on icon name
    switch ($IconName) {
        'chart' { return '<span class="icon-emoji">&#128202;</span>' }
        'clipboard' { return '<span class="icon-emoji">&#128203;</span>' }
        'building' { return '<span class="icon-emoji">&#127970;</span>' }
        'computer' { return '<span class="icon-emoji">&#128187;</span>' }
        'server' { return '<span class="icon-emoji">&#128421;</span>' }
        'gear' { return '<span class="icon-emoji">&#9881;</span>' }
        'search' { return '<span class="icon-emoji">&#128269;</span>' }
        'globe' { return '<span class="icon-emoji">&#127760;</span>' }
        'network' { return '<span class="icon-emoji">&#127760;</span>' }
        'folder' { return '<span class="icon-emoji">&#128193;</span>' }
        'users' { return '<span class="icon-emoji">&#128101;</span>' }
        'user' { return '<span class="icon-emoji">&#128100;</span>' }
        'database' { return '<span class="icon-emoji">&#128451;</span>' }
        'file' { return '<span class="icon-emoji">&#128196;</span>' }
        'lock' { return '<span class="icon-emoji">&#128274;</span>' }
        'key' { return '<span class="icon-emoji">&#128273;</span>' }
        'shield' { return '<span class="icon-emoji">&#128737;</span>' }
        'crown' { return '<span class="icon-emoji">&#128081;</span>' }
        'package' { return '<span class="icon-emoji">&#128230;</span>' }
        'plug' { return '<span class="icon-emoji">&#128268;</span>' }
        'lightning' { return '<span class="icon-emoji">&#9889;</span>' }
        'wrench' { return '<span class="icon-emoji">&#128295;</span>' }
        'clock' { return '<span class="icon-emoji">&#128336;</span>' }
        'hospital' { return '<span class="icon-emoji">&#127973;</span>' }
        'refresh' { return '<span class="icon-emoji">&#128260;</span>' }
        'target' { return '<span class="icon-emoji">&#127919;</span>' }
        'folder2' { return '<span class="icon-emoji">&#128194;</span>' }
        'memory' { return '<span class="icon-emoji">&#129504;</span>' }
        'disk' { return '<span class="icon-emoji">&#128190;</span>' }
        'cpu' { return '<span class="icon-emoji">&#128421;</span>' }
        'process' { return '<span class="icon-emoji">&#9881;</span>' }
        'service' { return '<span class="icon-emoji">&#128295;</span>' }
        'update' { return '<span class="icon-emoji">&#128260;</span>' }
        'program' { return '<span class="icon-emoji">&#128230;</span>' }
        'port' { return '<span class="icon-emoji">&#128268;</span>' }
        'firewall' { return '<span class="icon-emoji">&#128293;</span>' }
        'antivirus' { return '<span class="icon-emoji">&#128737;</span>' }
        'certificate' { return '<span class="icon-emoji">&#128196;</span>' }
        'dns' { return '<span class="icon-emoji">&#127760;</span>' }
        'audit' { return '<span class="icon-emoji">&#128202;</span>' }
        'task' { return '<span class="icon-emoji">&#128203;</span>' }
        'startup' { return '<span class="icon-emoji">&#128640;</span>' }
        'log' { return '<span class="icon-emoji">&#128221;</span>' }
        'eye' { return '<span class="icon-emoji">&#128065;</span>' }
        'home' { return '<span class="icon-emoji">&#127968;</span>' }
        'info' { return '<span class="icon-emoji">&#8505;</span>' }
        'menu' { return '<span class="icon-emoji">&#9776;</span>' }
        'warning' { return '<span class="icon-emoji">&#9888;</span>' }
        'check' { return '<span class="icon-emoji">&#9989;</span>' }
        'cross' { return '<span class="icon-emoji">&#10060;</span>' }
        default { return '<span class="icon-emoji">&#8226;</span>' }
    }
}

# ----------------------------
# 1. SYSTEM INFORMATION
# ----------------------------

# === 1.1 System Information Function === #
function Get-SystemInformation {
    <#
    .SYNOPSIS
        Collects comprehensive system information for the health check report.
    .DESCRIPTION
        This function gathers OS details, CPU information, disk space, memory usage,
        Windows features, services, installed programs, running processes, and update information.
        It exports data to CSV files and returns HTML sections for the main report.
    .PARAMETER Path
        The directory path where CSV files will be saved.
    .PARAMETER ServerName
        The name of the server for file naming purposes.
    .OUTPUTS
        Returns a hashtable containing HTML sections for inclusion in the main report.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    Write-Host "=== COLLECTING SYSTEM INFORMATION ===" -ForegroundColor Cyan
    
    # Initialize hashtable to store HTML sections
    $htmlSections = @{
        "OSInfo" = ""
        "Uptime" = ""
        "CPUUsage" = ""
        "CPUInfo" = ""
        "DiskInfo" = ""
        "RAMInfo" = ""
        "WindowsFeatures" = ""
        "RunningServices" = ""
        "StoppedServices" = ""
        "InstalledPrograms" = ""
        "RunningProcesses" = ""
        "InstalledUpdates" = ""
        "MissingUpdates" = ""
    }      # === OS Details ===
        # Add User Rights Assignments section to HTML sections
        $htmlSections["UserRightsAssignments"] = ""
$csvUserRightsAssignments = Join-Path -Path $path -ChildPath "$ServerName-UserRightsAssignments.csv"
    Write-Host "Collecting OS Details..." -ForegroundColor Yellow
    try {
        $osInfoRaw = Get-ComputerInfo | Select-Object OsName, OsArchitecture, CsName, OsVersion, OsBuildNumber, WindowsInstallationType, WindowsInstallDateFromRegistry
        $osInfoAll = Get-ComputerInfo | Select-Object *
        
        # Format OS installation date
        $formattedInstallDate = "N/A"
        if ($osInfoRaw.WindowsInstallDateFromRegistry) {
            try {
                $formattedInstallDate = $osInfoRaw.WindowsInstallDateFromRegistry.ToString("dd MMMM yyyy h:mm:ss tt")
            } catch {
                # If formatting fails, try alternative method using Win32_OperatingSystem
                try {
                    $osInstallDate = (Get-CimInstance Win32_OperatingSystem).InstallDate
                    if ($osInstallDate) {
                        $formattedInstallDate = $osInstallDate.ToString("dd MMMM yyyy h:mm:ss tt")
                    }
                } catch {
                    $formattedInstallDate = if ($osInfoRaw.WindowsInstallDateFromRegistry) { $osInfoRaw.WindowsInstallDateFromRegistry.ToString() } else { "N/A" }
                }
            }
        } else {
            # Try alternative method using Win32_OperatingSystem if WindowsInstallDateFromRegistry is not available
            try {
                $osInstallDate = (Get-CimInstance Win32_OperatingSystem).InstallDate
                if ($osInstallDate) {
                    $formattedInstallDate = $osInstallDate.ToString("dd MMMM yyyy h:mm:ss tt")
                }
            } catch {
                $formattedInstallDate = "N/A"
            }
        }
        
        # Create custom object with renamed columns for HTML display
        $osInfo = [PSCustomObject]@{
            "Operating System" = $osInfoRaw.OsName
            "OS Architecture" = $osInfoRaw.OsArchitecture
            "Computer Name" = $osInfoRaw.CsName
            "OS Version" = $osInfoRaw.OsVersion
            "OS Build Number" = $osInfoRaw.OsBuildNumber
            "Server/Client" = $osInfoRaw.WindowsInstallationType
            "OS Installation Date" = $formattedInstallDate
        }
        
        $csvosinfo = Join-Path -Path $Path -ChildPath "$ServerName-OSInfo.csv"
        $osInfoAll | Export-Csv -Path $csvosinfo -NoTypeInformation
        $htmlSections['OSInfo'] = $osInfo | ConvertTo-Html -Fragment -PreContent "<h2>OS Details</h2>"
        Write-Host "OS Details - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect OS Details: $($_.Exception.Message)"
        $htmlSections['OSInfo'] = "<h2>OS Details</h2><p>Error collecting OS information</p>"
    }

    # === OS Uptime Info ===
    Write-Host "Collecting System Uptime..." -ForegroundColor Yellow
    try {
        $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days, Hours, Minutes
        $uptimeAll = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object *
        $csvuptimeinfo = Join-Path -Path $Path -ChildPath "$ServerName-UpTime.csv"
        $uptimeAll | Export-Csv -Path $csvuptimeinfo -NoTypeInformation
        $htmlSections['Uptime'] = $uptime | ConvertTo-Html -Fragment -PreContent "<h2>System Uptime</h2>"
        Write-Host "System Uptime - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect System Uptime: $($_.Exception.Message)"
        $htmlSections['Uptime'] = "<h2>System Uptime</h2><p>Error collecting uptime information</p>"
    }

    # === CPU Details ===
    Write-Host "Collecting CPU Information..." -ForegroundColor Yellow
    try {
        # CPU Usage
        $cpuusage = Get-Counter '\Processor(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | 
            Where-Object {$_.InstanceName -ne '_Total'} | ForEach-Object {
            [PSCustomObject]@{
                "Logical Core" = $_.InstanceName
                "Logical Core Utilization Percentage(%)" = [math]::Round($_.CookedValue,2)
             }
        }
        $csvcpuusageinfo = Join-Path -Path $Path -ChildPath "$ServerName-CPUUsage.csv"
        $cpuusage | Export-Csv -Path $csvcpuusageinfo -NoTypeInformation
        $htmlSections['CPUUsage'] = $cpuusage | ConvertTo-Html -Fragment -PreContent "<h2>CPU Usage</h2>"        # CPU Information
        $cpuinfo = Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage
        $cpuinfoAll = Get-CimInstance Win32_Processor | Select-Object *
        $csvcpuinfo = Join-Path -Path $Path -ChildPath "$ServerName-CPUInfo.csv"
        $cpuinfoAll | Export-Csv -Path $csvcpuinfo -NoTypeInformation
        
        # Create custom display object for HTML with renamed columns
        $cpuinfoDisplay = $cpuinfo | ForEach-Object {
            [PSCustomObject]@{
                "CPU Name" = $_.Name
                "Manufacturer" = $_.Manufacturer
                "Physical Cores" = $_.NumberOfCores
                "Logical Cores" = $_.NumberOfLogicalProcessors
                "Utilization Percentage" = $_.LoadPercentage
            }
        }
        $htmlSections['CPUInfo'] = $cpuinfoDisplay | ConvertTo-Html -Fragment -PreContent "<h2>CPU Details</h2>"
        Write-Host "CPU Information - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect CPU Information: $($_.Exception.Message)"
        $htmlSections['CPUUsage'] = "<h2>CPU Usage</h2><p>Error collecting CPU usage</p>"
        $htmlSections['CPUInfo'] = "<h2>CPU Details</h2><p>Error collecting CPU details</p>"
    }

    # === Disk Details ===
    Write-Host "Collecting Disk Information..." -ForegroundColor Yellow
    try {
        $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk | ForEach-Object {
            # Avoid division by zero if size is zero or null
            if ($_.Size -gt 0) {
                $usedSpace = $_.Size - $_.FreeSpace
                $freePercent = ($_.FreeSpace / $_.Size) * 100
            } else {
                $usedSpace = 0
                $freePercent = 0
            }

            [PSCustomObject]@{
                "Partition"        = $_.DeviceID
                "Drive Type"        = switch ($_.DriveType) {
                                        0 { "Unknown" }
                                        1 { "No Root Directory" }
                                        2 { "Removable Disk" }
                                        3 { "Local Disk" }
                                        4 { "Network Drive" }
                                        5 { "CD-ROM" }
                                        6 { "RAM Disk" }
                                    }
                "File System"       = $_.FileSystem
                "Total Size(GB)"    = [math]::Round($_.Size / 1GB, 2)
                "Used Space(GB)"    = [math]::Round($usedSpace / 1GB, 2)
                "Free Space(GB)"    = [math]::Round($_.FreeSpace / 1GB, 2)
                "Free Percentage(%)"   = [math]::Round($freePercent, 2)
                "VolumeName"       = $_.VolumeName
                "Description"      = $_.Description
            }
        }
        $csvdiskinfo = Join-Path -Path $Path -ChildPath "$ServerName-DiskInfo.csv"
        $diskInfo | Export-Csv -Path $csvdiskinfo -NoTypeInformation
        $htmlSections['DiskInfo'] = $diskInfo | ConvertTo-Html -Fragment -PreContent "<h2>Disk Details</h2>"
        Write-Host "Disk Information - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Disk Information: $($_.Exception.Message)"
        $htmlSections['DiskInfo'] = "<h2>Disk Details</h2><p>Error collecting disk information</p>"
    }

    # === RAM Details ===
    Write-Host "Collecting Memory Information..." -ForegroundColor Yellow
    try {
        $memoryCounter = Get-Counter -Counter "\Memory\Available MBytes"
        $totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        $freeRAM = $memoryCounter.CounterSamples.CookedValue / 1024 # Convert MB to GB
        $usedRAM = $totalRAM - $freeRAM
        $usagePercent = [math]::Round(($usedRAM / $totalRAM) * 100, 2)
        $freePercent = [math]::Round(($freeRAM / $totalRAM) * 100, 2)

        $RAMreport = [PSCustomObject]@{
            "Total RAM(GB)" = [math]::Round($totalRAM, 2)
            "Used RAM(GB)" = [math]::Round($usedRAM, 2)
            "RAM Utilization Percentage(%)" = $usagePercent
            "Free RAM(GB)" = [math]::Round($freeRAM, 2)
            "Free RAM Percentage(%)" = $freePercent
        }
        $csvraminfo = Join-Path -Path $Path -ChildPath "$ServerName-RAMInfo.csv"
        $RAMreport | Export-Csv -Path $csvraminfo -NoTypeInformation
        $htmlSections['RAMInfo'] = $RAMreport | ConvertTo-Html -Fragment -PreContent "<h2>RAM Details</h2>"
        Write-Host "Memory Information - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Memory Information: $($_.Exception.Message)"
        $htmlSections['RAMInfo'] = "<h2>RAM Details</h2><p>Error collecting memory information</p>"
    }    # === Windows Features ===
    Write-Host "Collecting Windows Features..." -ForegroundColor Yellow
    try {
        $featuresRaw = Get-WindowsFeature | Where-Object {$_.Installed -eq $True} | Select-Object Name, DisplayName, Path, InstallState, FeatureType
        $FeaturesAll = Get-WindowsFeature | Where-Object {$_.Installed -eq $True} | Select-Object * -ExcludeProperty DependsOn
        
        # Create PSCustomObject array with user-friendly column names
        $Features = $featuresRaw | ForEach-Object {
            [PSCustomObject]@{
                'Name' = $_.Name
                'Feature Display Name' = $_.DisplayName
                'Feature Path' = if ($_.Path) { $_.Path } else { "N/A" }
                'Installation State' = $_.InstallState
                'Feature Type' = $_.FeatureType
            }
        }
        
        $csvWinFeatures = Join-Path -Path $Path -ChildPath "$ServerName-WinFeatures.csv"
        $FeaturesAll | Export-Csv -Path $csvWinFeatures -NoTypeInformation
        $htmlSections['WindowsFeatures'] = "<div class='table-container'>" + ($Features | ConvertTo-Html -Fragment -PreContent "<h2>Windows Features Installed</h2>") + "</div>"
        Write-Host "Windows Features - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Windows Features: $($_.Exception.Message)"
        $htmlSections['WindowsFeatures'] = "<h2>Windows Features Installed</h2><p>Error collecting Windows features</p>"
    }

    # === Windows Services ===
    Write-Host "Collecting Windows Services..." -ForegroundColor Yellow
    try {
        $runningServicesData = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object DisplayName, Status, ServiceType
        $stoppedServicesData = Get-Service | Where-Object { $_.Status -eq 'Stopped' } | Select-Object DisplayName, Status, ServiceType

        $runningServicesDataAll = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object * 
        $stoppedServicesDataAll = Get-Service | Where-Object { $_.Status -eq 'Stopped' } | Select-Object * 

        $csvRunning = Join-Path -Path $Path -ChildPath "$ServerName-RunningServices.csv"
        $csvStopped = Join-Path -Path $Path -ChildPath "$ServerName-StoppedServices.csv"
        $runningServicesDataAll | Export-Csv -Path $csvRunning -NoTypeInformation
        $stoppedServicesDataAll | Export-Csv -Path $csvStopped -NoTypeInformation        # Create Running Services HTML without search functionality
        $runningServicesHtml = $runningServicesData | ConvertTo-Html -Fragment -PreContent "<h2>Running Windows Services</h2>"
        $htmlSections['RunningServices'] = $runningServicesHtml
        $htmlSections['StoppedServices'] = $stoppedServicesData | ConvertTo-Html -Fragment -PreContent "<h2>Stopped Windows Services</h2>"
        Write-Host "Windows Services - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Windows Services: $($_.Exception.Message)"
        $htmlSections['RunningServices'] = "<h2>Running Windows Services</h2><p>Error collecting running services</p>"
        $htmlSections['StoppedServices'] = "<h2>Stopped Windows Services</h2><p>Error collecting stopped services</p>"
    }
        # === User Rights Assignments ===
        Write-Host "Collecting User Rights Assignments..." -ForegroundColor Yellow
        try {
            $tempInf = Join-Path -Path $env:TEMP -ChildPath "UserRightsAssignments.inf"
            secedit /export /cfg $tempInf /areas USER_RIGHTS | Out-Null

            # Base parse (Privilege -> comma-separated identities)
            $userRightsRaw = Select-String -Path $tempInf -Pattern "^Se.* = .*" | ForEach-Object {
                $line = $_.Line
                $parts = $line -split " = ", 2
                if ($parts.Count -ge 2) {
                    [PSCustomObject]@{
                        Privilege  = $parts[0]
                        AssignedTo = $parts[1]
                    }
                }
            } | Where-Object { $_ }

            # Well-known SID map (subset of documented SIDs and built-in groups)
            $WellKnownSidMap = @{
                'S-1-0-0'          = 'Null SID'
                'S-1-1-0'          = 'Everyone'
                'S-1-2-0'          = 'Local'
                'S-1-2-1'          = 'Console Logon'
                'S-1-3-0'          = 'Creator Owner'
                'S-1-3-1'          = 'Creator Group'
                'S-1-3-2'          = 'Creator Owner Server'
                'S-1-3-3'          = 'Creator Group Server'
                'S-1-3-4'          = 'Owner Rights'
                'S-1-5-1'          = 'Dialup'
                'S-1-5-2'          = 'Network'
                'S-1-5-3'          = 'Batch'
                'S-1-5-4'          = 'Interactive'
                'S-1-5-6'          = 'Service'
                'S-1-5-7'          = 'Anonymous Logon'
                'S-1-5-8'          = 'Proxy'
                'S-1-5-9'          = 'Enterprise Domain Controllers'
                'S-1-5-10'         = 'Self'
                'S-1-5-11'         = 'Authenticated Users'
                'S-1-5-12'         = 'Restricted'
                'S-1-5-13'         = 'Terminal Server Users'
                'S-1-5-14'         = 'Remote Interactive Logon'
                'S-1-5-15'         = 'This Organization'
                'S-1-5-17'         = 'IUSR'
                'S-1-5-18'         = 'LOCAL SYSTEM'
                'S-1-5-19'         = 'LOCAL SERVICE'
                'S-1-5-20'         = 'NETWORK SERVICE'
                'S-1-5-32-544'     = 'Administrators'
                'S-1-5-32-545'     = 'Users'
                'S-1-5-32-546'     = 'Guests'
                'S-1-5-32-547'     = 'Power Users'
                'S-1-5-32-548'     = 'Account Operators'
                'S-1-5-32-549'     = 'Server Operators'
                'S-1-5-32-550'     = 'Print Operators'
                'S-1-5-32-551'     = 'Backup Operators'
                'S-1-5-32-552'     = 'Replicator'
                'S-1-5-32-554'     = 'Pre-Windows 2000 Compatible Access'
                'S-1-5-32-555'     = 'Remote Desktop Users'
                'S-1-5-32-556'     = 'Network Configuration Operators'
                'S-1-5-32-557'     = 'Incoming Forest Trust Builders'
                'S-1-5-32-558'     = 'Performance Monitor Users'
                'S-1-5-32-559'     = 'Performance Log Users'
                'S-1-5-32-560'     = 'Windows Authorization Access Group'
                'S-1-5-32-561'     = 'Terminal Server License Servers'
                'S-1-5-32-562'     = 'Distributed COM Users'
                'S-1-5-32-568'     = 'IIS_IUSRS'
                'S-1-5-32-569'     = 'Cryptographic Operators'
                'S-1-5-32-573'     = 'Event Log Readers'
                'S-1-5-32-574'     = 'Certificate Service DCOM Access'
                'S-1-5-32-575'     = 'RDS Remote Access Servers'
                'S-1-5-32-576'     = 'RDS Endpoint Servers'
                'S-1-5-32-577'     = 'RDS Management Servers'
                'S-1-5-32-578'     = 'Hyper-V Administrators'
                'S-1-5-32-579'     = 'Access Control Assistance Operators'
                'S-1-5-32-580'     = 'Remote Management Users'
                'S-1-5-32-581'     = 'System Managed Accounts Group'
                'S-1-5-32-582'     = 'Storage Replica Administrators'
            }

            function Resolve-IdentityString {
                param([string]$Value)
                $raw = if ($null -ne $Value) { $Value } else { '' }
                $raw = $raw.Trim()
                if ($raw.StartsWith('*')) { $raw = $raw.Substring(1) }
                $sid = $null; $name = $null; $source = $null
                if ($raw -match '^S-1-') {
                    $sid = $raw
                    if ($WellKnownSidMap.ContainsKey($sid)) { $name = $WellKnownSidMap[$sid]; $source = 'WellKnown' }
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                        $acct = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        $name = $acct
                        $source = if ($source) { $source + '+NT' } else { 'NT' }
                    } catch { }
                    if (-not $name) { $name = $sid; $source = 'Original' }
                } else {
                    $name = $raw
                    try {
                        $acct = New-Object System.Security.Principal.NTAccount($raw)
                        $sidObj = $acct.Translate([System.Security.Principal.SecurityIdentifier])
                        $sid = $sidObj.Value
                        if ($WellKnownSidMap.ContainsKey($sid)) { $source = 'NT+WellKnown' } else { $source = 'NT' }
                    } catch { $source = 'Original' }
                }
                [PSCustomObject]@{ Input=$Value; SID=$sid; Name=$name; Source=$source }
            }

            # Expand to one row per identity with resolved names/SIDs
            $userRightsExpanded = @()
            foreach ($row in $userRightsRaw) {
                $idList = @()
                if ($row.AssignedTo) { $idList = $row.AssignedTo -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
                if ($idList.Count -eq 0) {
                    $userRightsExpanded += [PSCustomObject]@{
                        Privilege = $row.Privilege
                        Account   = '(none)'
                        SID       = ''
                        Source    = ''
                    }
                } else {
                    foreach ($id in $idList) {
                        $res = Resolve-IdentityString -Value $id
                        $userRightsExpanded += [PSCustomObject]@{
                            Privilege = $row.Privilege
                            Account   = $res.Name
                            SID       = $res.SID
                            Source    = $res.Source
                        }
                    }
                }
            }

            $userRightsExpanded | Export-Csv -Path $csvUserRightsAssignments -NoTypeInformation

            # For HTML readability: one line per privilege with aggregated accounts
            $userRightsGrouped = $userRightsExpanded |
                Group-Object Privilege |
                ForEach-Object {
                    $accounts = $_.Group | ForEach-Object { $_.Account } | Where-Object { $_ } | Sort-Object -Unique
                    $accountsStr = if ($accounts -and $accounts.Count -gt 0) { ($accounts -join '; ') } else { '(none)' }
                    $acctCount = ($accounts | Where-Object { $_ -ne '(none)' } | Measure-Object).Count
                    [PSCustomObject]@{
                        Privilege    = $_.Name
                        Accounts     = $accountsStr
                        AccountCount = $acctCount
                    }
                }

            $htmlSections['UserRightsAssignments'] = $userRightsGrouped |
                ConvertTo-Html -Fragment -PreContent "<h2>User Rights Assignments (resolved)</h2>"
            Write-Host "User Rights Assignments - Completed" -ForegroundColor Green
            Remove-Item $tempInf -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Failed to collect User Rights Assignments: $($_.Exception.Message)"
            $htmlSections['UserRightsAssignments'] = "<h2>User Rights Assignments</h2><p>Error collecting User Rights Assignments</p>"
        }
    # === Installed Programs ===
    Write-Host "Collecting Installed Programs..." -ForegroundColor Yellow
    if (-not $htmlSections) { $htmlSections = @{} }
    try {
        # Get installed programs from 32-bit, 64-bit, and user-specific registry locations
        $installedprogs32 = @(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" })
        $installedprogs64 = @(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" })
        $installedprogsUser = @(Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" })

        # Combine all lists and remove duplicates based on DisplayName; drop nulls defensively
        $installedprogsAll = @($installedprogs32 + $installedprogs64 + $installedprogsUser) |
            Where-Object { $_ -and $_.DisplayName } |
            Sort-Object -Property DisplayName -Unique

        # Select only relevant fields and filter out empty entries
        $installedprogs = @($installedprogsAll | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" })

        $csvinstalledprogsinfo = Join-Path -Path $Path -ChildPath "$ServerName-InstalledProgs.csv"
        $installedprogs | Export-Csv -Path $csvinstalledprogsinfo -NoTypeInformation

        # Create display list; avoid fragile date parsing and just render as string
        if (-not $installedprogs -or $installedprogs.Count -eq 0) {
            $installedprogsDisplay = @([PSCustomObject]@{
                "Program Name" = "None"
                "Program Version" = "N/A"
                "Publisher" = "N/A"
                "Size (MB)" = "N/A"
                "Installed Date" = "N/A"
            })
        } else {
            $installedprogsDisplay = $installedprogs | ForEach-Object {
                [PSCustomObject]@{
                    "Program Name" = $_.DisplayName
                    "Program Version" = $_.DisplayVersion
                    "Publisher" = $_.Publisher
                    "Size (MB)" = $_.EstimatedSize
                    "Installed Date" = if ($_.InstallDate) { $_.InstallDate.ToString() } else { "N/A" }
                }
            }
        }
        $htmlSections['InstalledPrograms'] = $installedprogsDisplay | ConvertTo-Html -Fragment -PreContent "<h2>Installed Programs</h2>"
        Write-Host "Installed Programs - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Installed Programs: $($_.Exception.Message)"
        if ($null -ne $htmlSections) {
            $htmlSections['InstalledPrograms'] = "<h2>Installed Programs</h2><p>Error collecting installed programs</p>"
        }
    }
    # === Running Processes ===
    Write-Host "Collecting Current Running Processes..." -ForegroundColor Yellow
    try {
        $procList = $null
        $includeUserName = $true
        try {
            $procList = Get-Process -IncludeUserName -ErrorAction Stop
        } catch {
            Write-Verbose "Get-Process -IncludeUserName failed, falling back without usernames: $($_.Exception.Message)"
            $procList = Get-Process
            $includeUserName = $false
        }

        $allProcesses = @($procList)

        # Create PSCustomObject array with user-friendly column names, guarding properties that can throw
        $CurrentProcesses = foreach ($p in $allProcesses) {
            $id = $null; $sid = $null; $pname = $null; $start = $null; $uTime = $null; $tTime = $null; $cpu = $null; $desc = $null; $uname = $null; $pathExe = $null
            try { $id = $p.Id } catch {}
            try { $sid = $p.SessionId } catch {}
            try { $pname = $p.ProcessName } catch {}
            try { $start = $p.StartTime } catch {}
            try { $uTime = $p.UserProcessorTime } catch {}
            try { $tTime = $p.TotalProcessorTime } catch {}
            try { $cpu = $p.CPU } catch {}
            try { $desc = $p.Description } catch {}
            if ($includeUserName) { try { $uname = $p.UserName } catch {} }
            try { $pathExe = $p.Path } catch {}

            [PSCustomObject]@{
                'Process ID' = if ($id) { $id } else { 'N/A' }
                'Session ID' = if ($null -ne $sid) { $sid } else { 'N/A' }
                'Process Name' = if ($pname) { $pname } else { 'N/A' }
                'Start Time' = if ($start) { $start.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                'User CPU Time' = if ($uTime) { $uTime.ToString('hh\:mm\:ss') } else { 'N/A' }
                'Total CPU Time' = if ($tTime) { $tTime.ToString('hh\:mm\:ss') } else { 'N/A' }
                'CPU %' = if ($null -ne $cpu) { [math]::Round([double]$cpu, 2) } else { 'N/A' }
                'Description' = if ($desc) { $desc } else { 'N/A' }
                'User Name' = if ($uname) { $uname } else { 'N/A' }
                'Executable Path' = if ($pathExe) { $pathExe } else { 'N/A' }
            }
        }

        $csvallProcesses = Join-Path -Path $Path -ChildPath "$ServerName-allProcesses.csv"
        if ($allProcesses.Count -gt 0) {
            $allProcesses | Export-Csv -Path $csvallProcesses -NoTypeInformation
        } else {
            Write-Verbose "No running processes found to export. Skipping CSV export."
        }

        if ($null -eq $htmlSections) { $htmlSections = @{} }
        if ($CurrentProcesses -and $CurrentProcesses.Count -gt 0) {
            $htmlSections['RunningProcesses'] = "<div class='table-container'>" + ($CurrentProcesses | ConvertTo-Html -Fragment -PreContent "<h2>Current Running Processes</h2>") + "</div>"
        } else {
            $htmlSections['RunningProcesses'] = "<h2>Current Running Processes</h2><p>No process information available.</p>"
        }
        Write-Host "Current Running Processes - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Running Processes: $($_.Exception.Message)"
        if ($null -eq $htmlSections) { $htmlSections = @{} }
        $htmlSections['RunningProcesses'] = "<h2>Current Running Processes</h2><p>Error collecting running processes</p>"
    }
    # === Updates Installed ===
    Write-Host "Collecting Windows Updates..." -ForegroundColor Yellow
    try {
        $updatesRaw = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, InstalledOn, InstalledBy)
        $updates = $updatesRaw | ForEach-Object {
            [PSCustomObject]@{
                "Hot Fix ID" = $_.HotFixID
                "Installed On" = if ($_.InstalledOn) { $_.InstalledOn } else { $null }
                "Installed By" = if ($_.InstalledBy) { $_.InstalledBy } else { 'N/A' }
            }
        }
        $updatesAll = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object *)
        $csvupdatesinstalledinfo = Join-Path -Path $Path -ChildPath "$ServerName-UpdatesInstalledInfo.csv"
        if ($updatesAll.Count -gt 0) {
            $updatesAll | Export-Csv -Path $csvupdatesinstalledinfo -NoTypeInformation
        } else {
            Write-Verbose "No installed updates returned by Get-HotFix. Skipping CSV export."
        }
        if ($null -eq $htmlSections) { $htmlSections = @{} }
        if ($updates -and $updates.Count -gt 0) {
            $htmlSections['InstalledUpdates'] = $updates | ConvertTo-Html -Fragment -PreContent "<h2>Updates Installed</h2>"
        } else {
            $htmlSections['InstalledUpdates'] = "<h2>Updates Installed</h2><p>No installed updates were returned.</p>"
        }
        Write-Host "Windows Updates - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Windows Updates: $($_.Exception.Message)"
        if ($null -eq $htmlSections) { $htmlSections = @{} }
        $htmlSections['InstalledUpdates'] = "<h2>Updates Installed</h2><p>Error collecting installed updates</p>"
    }

    # === Missing Windows Updates ===
    Write-Host "Checking for Missing Windows Updates..." -ForegroundColor Yellow
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $missingupdatesResult = $updateSearcher.Search("IsInstalled=0")
        $missingupdates = @($missingupdatesResult.Updates | ForEach-Object {
            $sizeBytes = $null
            try { $sizeBytes = $_.MaxDownloadSize } catch {}
            [PSCustomObject]@{
                "Missing Windows Update" = $_.Title
                "KB" = ($_.KBArticleIDs -join ", ")
                "Size (MB)" = if ($null -ne $sizeBytes) { [math]::Round(([double]$sizeBytes / 1MB), 2) } else { 0 }
            }
        })
        $csvmissingupdatesinfo = Join-Path -Path $Path -ChildPath "$ServerName-MissingUpdates.csv"
        if ($missingupdates.Count -gt 0) {
            $missingupdates | Export-Csv -Path $csvmissingupdatesinfo -NoTypeInformation
        } else {
            Write-Verbose "No missing updates found. Skipping CSV export."
        }
        if ($null -eq $htmlSections) { $htmlSections = @{} }
        if ($missingupdates.Count -gt 0) {
            $htmlSections['MissingUpdates'] = $missingupdates | ConvertTo-Html -Fragment -PreContent "<h2>Missing Windows Updates</h2>"
        } else {
            $htmlSections['MissingUpdates'] = "<h2>Missing Windows Updates</h2><p>No missing updates found.</p>"
        }
        Write-Host "Missing Windows Updates - Completed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check for Missing Windows Updates: $($_.Exception.Message)"
        if ($null -eq $htmlSections) { $htmlSections = @{} }
        $htmlSections['MissingUpdates'] = "<h2>Missing Windows Updates</h2><p>Error checking for missing updates</p>"
    }

    Write-Host "=== SYSTEM INFORMATION COLLECTION COMPLETED ===" -ForegroundColor Green

    return $htmlSections
}


# Check if user selected to collect system information (system-only or all sections)
if ($collectSystemOnly -or (-not $collectNetworkOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly)) {

# 1.2. Collect System Information
$systemInfoHtml = Get-SystemInformation -Path $path -ServerName $ServerName

# 1.3. Extract individual HTML sections from system information function
$osInfoHtml = $systemInfoHtml['OSInfo']
$uptimeHtml = $systemInfoHtml['Uptime']
$cpuInfoHtml = $systemInfoHtml['CPUInfo']
$cpuusageInfoHtml = $systemInfoHtml['CPUUsage']
$RAMHtml = $systemInfoHtml['RAMInfo']
$diskInfoHtml = $systemInfoHtml['DiskInfo']
$FeaturesHtml = $systemInfoHtml['WindowsFeatures']
$runningHtml = $systemInfoHtml['RunningServices']
$stoppedHtml = $systemInfoHtml['StoppedServices']
$installedprogsHtml = $systemInfoHtml['InstalledPrograms']
$CurrentProcessesHtml = $systemInfoHtml['RunningProcesses']
$updatesHtml = $systemInfoHtml['InstalledUpdates']
$missingupdatesHtml = $systemInfoHtml['MissingUpdates']
$userRightsAssignmentsHtml = $systemInfoHtml['UserRightsAssignments']

} # End system information collection


# Check if user selected to collect network or all sections
if ($collectNetworkOnly -or (-not $collectSystemOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly)) {

# ----------------------------
# 2. NETWORK CHECKS
# ----------------------------

# 2.1. Network Information Function === #
function Get-NetworkInformation {
    <#
    .SYNOPSIS
        Collects comprehensive network information for the health check report.
    .DESCRIPTION
        This function gathers network interface details, current traffic statistics,
        and open TCP ports. It exports data to CSV files and returns HTML sections
        for the main report.
    .PARAMETER Path
        The directory path where CSV files will be saved.
    .PARAMETER ServerName
        The name of the server for file naming purposes.
    .PARAMETER CsvNicInfo
        Path for NIC information CSV file.
    .PARAMETER CsvTrafficInfo
        Path for traffic information CSV file.
    .PARAMETER CsvOpenPortsInfo
        Path for open ports information CSV file.
    .OUTPUTS
        Returns a hashtable containing HTML sections for inclusion in the main report.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvNicInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvTrafficInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvOpenPortsInfo
    )
    
    Write-Host "=== COLLECTING NETWORK INFORMATION ===" -ForegroundColor Cyan
    
    # === NIC Details ===
    Write-Host "Collecting NIC Details..." -ForegroundColor Yellow
    $nicInfo = Get-NetIPConfiguration | ForEach-Object {
        [PSCustomObject]@{
            "Interface Name" = $_.InterfaceAlias
            "Description" = $_.InterfaceDescription
            "Network Profile" = $_.NetProfile.Name
            "Status" = $_.NetAdapter.Status
            "IPv4Address" = ($_.IPv4Address.IPAddress -join ', ')
            "IPv6Address" = ($_.IPv6Address.IPAddress -join ', ')
            "DNS Server" = ($_.DNSServer.ServerAddresses -join ', ')
            "IPv6 Interface" = $_.NetIPv6Interface.DHCP
            "IPv4 Interface" = $_.NetIPv4Interface.DHCP
            "MAC" = $_.NetAdapter.MacAddress
            "Speed" = $_.NetAdapter.LinkSpeed
        }
    } 

    $nicInfo | Export-Csv -Path $CsvNicInfo -NoTypeInformation
    $nicInfoHtml = $nicInfo | ConvertTo-Html -Fragment -PreContent "<h2>NIC Details</h2>"

    # === Current Traffic ===
    Write-Host "Collecting Current Traffic Information..." -ForegroundColor Yellow
    $trafficInfo = Get-Counter '\Network Interface(*)\Bytes Received/sec', 
                    '\Network Interface(*)\Bytes Sent/sec' |
            Select-Object -ExpandProperty CounterSamples | Where-Object {$_.InstanceName -notlike '*isatap*' -and $_.InstanceName -notlike '*Loopback*' -and $_.InstanceName -notlike '*tunnel*'} | ForEach-Object {
             [PSCustomObject]@{
                         "NIC"=$_.InstanceName
                         "Received(MB/s)"=[math]::Round($_.CookedValue/1MB,2)
                         "Sent(MB/s)"=[math]::Round($_.CookedValue/1MB,2)
             }
     }

    $trafficInfo | Export-Csv -Path $CsvTrafficInfo -NoTypeInformation
    $trafficInfoHtml = $trafficInfo | ConvertTo-Html -Fragment -PreContent "<h2>Current Traffic Details</h2>"    # === TCP Ports Opened ===
    Write-Host "Collecting Open TCP Ports..." -ForegroundColor Yellow
    $openportsRaw = Get-NetTCPConnection | Select-Object Localaddress, Localport, Remoteaddress, Remoteport, State, OwningProcess
    $openportsAll = Get-NetTCPConnection | Select-Object *
    
    # Create PSCustomObject array with user-friendly column names
    $openports = $openportsRaw | ForEach-Object {
        [PSCustomObject]@{
            'Source IP Address' = $_.Localaddress
            'Source Port' = $_.Localport
            'Destination IP Address' = if ($_.Remoteaddress) { $_.Remoteaddress } else { "N/A" }
            'Destination Port' = if ($_.Remoteport) { $_.Remoteport } else { "N/A" }
            'Connection State' = $_.State
            'Owning Process ID' = $_.OwningProcess
        }
    }
    
    $openportsAll | Export-Csv -Path $CsvOpenPortsInfo -NoTypeInformation
    $openportsHtml = "<div class='table-container'>" + ($openports | ConvertTo-Html -Fragment -PreContent "<h2>TCP Ports Opened</h2>") + "</div>"

    Write-Host "Network Information Collection Complete" -ForegroundColor Green
    
    # Return HTML sections
    return @{
        'NICInfo' = $nicInfoHtml
        'TrafficInfo' = $trafficInfoHtml
        'OpenPorts' = $openportsHtml
    }
}

# ----------------------------

# 2.2. Collect Network Information ===

$networkInfoHtml = Get-NetworkInformation -Path $path -ServerName $ServerName -CsvNicInfo $csvnicinfo -CsvTrafficInfo $csvtrafficinfo -CsvOpenPortsInfo $csvopenportsinfo

# 2.3. Extract individual HTML sections from network information function
$nicInfoHtml = $networkInfoHtml['NICInfo']
$trafficInfoHtml = $networkInfoHtml['TrafficInfo']
$openportsHtml = $networkInfoHtml['OpenPorts']

} # End network-only or all sections check

# Check if user selected to collect security or all sections
if ($collectSecurityOnly -or (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectTasksOnly)) {

# ----------------------------
# 3. SECURITY CHECKS
# ----------------------------

# === Security Information Function === #
function Get-SecurityInformation {
    param(
        [string]$Path,
        [string]$ServerName,
        [string]$GPOSettings,
        [string]$CsvAVSettings,
        [string]$CsvFWStatusInfo,
        [string]$CsvFWSettingsInfo,
        [string]$CsvSMBv1,
        [string]$CsvInactiveAccountsInfo,
        [string]$CsvLocalAdmins,
    [string]$CsvAccountPolicyPath,
        [string]$CsvShares,
        [string]$CsvAuditSettings,
        [string]$CsvTLSregSettings,
        [string]$CsvUACSettings,
        [string]$CsvPSExecPolicy,
        [string]$CsvRDPSecurity,
        [string]$CsvCertificates,
        [string]$CsvDNSSettings,
        [string]$CsvDefenderASR
    )
      Write-Host "=== COLLECTING SECURITY INFORMATION ===" -ForegroundColor Cyan    # === Antivirus ===
    Write-Host "Collecting Antivirus Settings..." -ForegroundColor Yellow
    $AVsettingsRaw = Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntispywareEnabled,  IoavProtectionEnabled, AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated, FullScanStartTime, FullScanEndTime, QuickScanStartTime, QuickScanEndTime
    $AVsettings = [PSCustomObject]@{
        "AV Enabled" = $AVsettingsRaw.AntivirusEnabled
        "Real Time Protection" = $AVsettingsRaw.RealTimeProtectionEnabled
        "Behavior Monitor" = $AVsettingsRaw.BehaviorMonitorEnabled
        "Anti Spyware Enabled" = $AVsettingsRaw.AntispywareEnabled
        "Ioav Protection Enabled" = $AVsettingsRaw.IoavProtectionEnabled
        "AV Signature Last Updates" = $AVsettingsRaw.AntivirusSignatureLastUpdated
        "Anti Spyware Signature Last Updates" = $AVsettingsRaw.AntispywareSignatureLastUpdated
        "Full Scan Start Time" = $AVsettingsRaw.FullScanStartTime
        "Full Scan End Time" = $AVsettingsRaw.FullScanEndTime
        "Quick Scan Start Time" = $AVsettingsRaw.QuickScanStartTime
        "Quick Scan End Time" = $AVsettingsRaw.QuickScanEndTime
    }
    $AVsettingsAll = Get-MpComputerStatus | Select-Object *
    $AVsettingsAll | Export-Csv -Path $CsvAVSettings -NoTypeInformation
    $AVsettingsHtml = $AVsettings | ConvertTo-Html -Fragment -PreContent "<h2>Anti-Virus Settings</h2>"

    # === Firewall status ===
    Write-Host "Collecting Firewall Status..." -ForegroundColor Yellow
    $FWstatus = Get-NetFirewallProfile | Select-Object Name, Enabled
    $FWstatusAll = Get-NetFirewallProfile | Select-Object *
    $FWstatusAll | Export-Csv -Path $CsvFWStatusInfo -NoTypeInformation
    $FWstatusHtml = $FWstatus | ConvertTo-Html -Fragment -PreContent "<h2>Firewall Status</h2>"

    # === All firewall rules (filtered example) ===
    Write-Host "Collecting Firewall Rules..." -ForegroundColor Yellow
    $FWSettings = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Select-Object DisplayName, Description, Direction, Action, Profile
    $FWSettingsAll = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Select-Object *
    $FWSettingsAll | Export-Csv -Path $CsvFWSettingsInfo -NoTypeInformation
    $FWSettingsHtml = $FWSettings | ConvertTo-Html -Fragment -PreContent "<h2>Firewall Settings</h2>"

    # === SMB V1 Status ===
    Write-Host "Collecting SMB V1 Status..." -ForegroundColor Yellow
    $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, DisplayName, State, RestartRequired
    $SMBv1All = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object *
    $SMBv1All | Export-Csv -Path $CsvSMBv1 -NoTypeInformation
    $SMBv1Html = $SMBv1 | ConvertTo-Html -Fragment -PreContent "<h2>SMB V1 Status</h2>"
     
    # === Inactive Accounts (no login in last 365 days) ===
    Write-Host "Collecting Inactive Accounts..." -ForegroundColor Yellow
    $inactiveAccounts = Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-365) } | Select-Object Name, Enabled, LastLogon
    $inactiveAccountsAll = Get-LocalUser | Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-365) } | Select-Object *
    $inactiveAccountsAll | Export-Csv -Path $CsvInactiveAccountsInfo -NoTypeInformation
    $inactiveAccountsHtml = $inactiveAccounts | ConvertTo-Html -Fragment -PreContent "<h2>Inactive Accounts (no login in last 365 days)</h2>"

    # === Local Admin Accounts ===
    Write-Host "Collecting Local Admin Accounts..." -ForegroundColor Yellow
    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, SID
    $localAdmins | Export-Csv -Path $CsvLocalAdmins -NoTypeInformation
    $localAdminsHtml = $localAdmins | ConvertTo-Html -Fragment -PreContent "<h2>Local Admin Accounts</h2>"

    # === Password Policy Info ===
    Write-Host "Collecting Password Policy..." -ForegroundColor Yellow
    $minAge = (net accounts | Select-String "Minimum password age").ToString().Split(':')[1].Trim()
    $maxAge = (net accounts | Select-String "Maximum password age").ToString().Split(':')[1].Trim()
    $Minimumpasswordlength = (net accounts | Select-String "Minimum password length").ToString().Split(':')[1].Trim()
    $Lengthofpasswordhistory = (net accounts | Select-String "Length of password history maintained").ToString().Split(':')[1].Trim()

    $forcelogoff = (net accounts | Select-String "Force user logoff how long after time expires?").ToString().Split(':')[1].Trim()
    $Lockoutthreshold = (net accounts | Select-String "Lockout threshold").ToString().Split(':')[1].Trim()
    $Lockoutduration = (net accounts | Select-String "Lockout duration").ToString().Split(':')[1].Trim()
    $Lockoutobservationwindow = (net accounts | Select-String "Lockout observation window").ToString().Split(':')[1].Trim()
    $passwordPolicy = [PSCustomObject]@{
        "Minimum Password Age" = $minAge
        "Maximum Password Age" = $maxAge
        "Password Length" = $Minimumpasswordlength
        "Password History" = $Lengthofpasswordhistory
        "Lockout Threshold" = $Lockoutthreshold
        "Lockout Duration" = $Lockoutduration
        "Lockout Observation Window" = $Lockoutobservationwindow
        "Force Logoff" = $forcelogoff
    }

    $passwordPolicy | Export-Csv -Path $CsvAccountPolicyPath -NoTypeInformation
    $passwordPolicyHtml = $passwordPolicy | ConvertTo-Html -Fragment -PreContent "<h2>Password Policy Details</h2>"    # === SMB Shares ===
    Write-Host "Collecting SMB Shares..." -ForegroundColor Yellow
    $sharesRaw = Get-SmbShare | Select-Object ShareType, FolderEnumerationMode, Description, Name, Path, ShadowCopy, Volume
    $shares = $sharesRaw | ForEach-Object {
        [PSCustomObject]@{
            "Share Type" = $_.ShareType
            "Folder Enumeration Mode" = $_.FolderEnumerationMode
            "Description" = $_.Description
            "Share Folder Name" = $_.Name
            "Share Folder Path" = $_.Path
            "Is Shadow Copy" = $_.ShadowCopy
            "Volume" = $_.Volume
        }
    }
    $sharesAll = Get-SmbShare | Select-Object *
    $sharesAll | Export-Csv -Path $CsvShares -NoTypeInformation
    $sharesHtml = $shares | ConvertTo-Html -Fragment -PreContent "<h2>SMB Shares</h2>"

    # === GPO Settings ===
    Write-Host "Collecting GPO Settings..." -ForegroundColor Yellow    
    GPResult /H $GPOSettings

    # Function to parse audit policy with Category, Subcategory, and Setting
    function Get-AuditPolicyStructured {
        $raw = auditpol /get /category:* | Out-String
        $lines = $raw -split "`r`n"
        $results = New-Object System.Collections.Generic.List[object]
        $currentCategory = $null

        foreach ($rawLine in $lines) {
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            $line = $rawLine
            # Skip header/separator rows (language-agnostic heuristics)
            if ($line -match '^-{3,}' -or $line -match 'Category/.*Subcategory' -or $line -match 'System audit policy') { continue }

            # Category lines typically have no leading spaces; subcategories are indented
            if ($line -notmatch '^\s') {
                $currentCategory = $line.Trim()
                continue
            }

            # Subcategory rows: "    <Subcategory><spaces><Setting>"
            $m = [regex]::Match($line, '^\s{2,}(.+?)\s{2,}([^\s].*)$')
            if (-not $m.Success) { continue }
            $sub = $m.Groups[1].Value.Trim()
            $setting = $m.Groups[2].Value.Trim()

            $obj = [PSCustomObject]@{
                Category      = $currentCategory
                Subcategory   = $sub
                Setting       = $setting
                'SettingText' = ("{0}  {1}" -f $sub, $setting) # two spaces to match dashboard parser
                Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
            $results.Add($obj) | Out-Null
        }
        return $results
    }

    Write-Host "Collecting Audit Policy Settings..." -ForegroundColor Yellow
    $auditSettings = Get-AuditPolicyStructured
    $auditSettings | Export-Csv -Path $CsvAuditSettings -NoTypeInformation
    # Prefer a clean projection (Category, Subcategory, Setting) for HTML
    $auditSettingsHtml = ($auditSettings | Select-Object Category, Subcategory, Setting) | ConvertTo-Html -Fragment -PreContent "<h2>Audit Policies Settings</h2>"

    # === TLS 1.2 Check ===
    Write-Host "Collecting TLS Registry Settings..." -ForegroundColor Yellow
    
    # Function to get registry value with error handling
    function Get-TLSRegistryValue {
        param($Path, $Name)
        try {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -eq $value) {
                return "Not Found"
            } else {
                return $value.$Name
            }
        } catch {
            return "Not Found"
        }
    }
    
    $regSettings = @()

    # Check .NET Framework TLS settings (32-bit)
    $regKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'SystemDefaultTlsVersions'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'SystemDefaultTlsVersions'
    }
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'SchUseStrongCrypto'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'SchUseStrongCrypto'
    }

    # Check .NET Framework TLS settings (64-bit)
    $regKey = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'SystemDefaultTlsVersions'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'SystemDefaultTlsVersions'
    }
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'SchUseStrongCrypto'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'SchUseStrongCrypto'
    }

    # Check TLS 1.2 Server settings
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'Enabled'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'Enabled'
    }
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'DisabledByDefault'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'DisabledByDefault'
    }

    # Check TLS 1.2 Client settings
    $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'Enabled'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'Enabled'
    }
    $regSettings += [PSCustomObject]@{
        Path = $regKey
        Name = 'DisabledByDefault'
        Value = Get-TLSRegistryValue -Path $regKey -Name 'DisabledByDefault'
    }

    $regSettings | Export-Csv -Path $CsvTLSregSettings -NoTypeInformation
    $TLSregSettingsHtml = $regSettings | ConvertTo-Html -Fragment -PreContent "<h2>TLS 1.2 Settings</h2>"

    # === UAC Settings ===
    Write-Host "Collecting UAC Settings..." -ForegroundColor Yellow
    try {
        $uacRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacSettings = Get-ItemProperty -Path $uacRegPath -ErrorAction SilentlyContinue
        
        $uacInfo = [PSCustomObject]@{
            "Enable LUA" = if($uacSettings.EnableLUA -eq 1) {"Enabled"} elseif($uacSettings.EnableLUA -eq 0) {"Disabled"} else {"Not Configured"}
            "Consent Prompt Behavior Admin" = switch ($uacSettings.ConsentPromptBehaviorAdmin) {
                0 {"Elevate without prompting"}
                1 {"Prompt for credentials on secure desktop"}
                2 {"Prompt for consent on secure desktop"}
                3 {"Prompt for credentials"}
                4 {"Prompt for consent"}
                5 {"Prompt for consent for non-Windows binaries (Default)"}
                default {"Not Configured"}
            }
            "Prompt On Secure Desktop" = if($uacSettings.PromptOnSecureDesktop -eq 1) {"Enabled (Default)"} elseif($uacSettings.PromptOnSecureDesktop -eq 0) {"Disabled"} else {"Not Configured"}
            "Filter Administrator Token" = if($uacSettings.FilterAdministratorToken -eq 1) {"Enabled"} elseif($uacSettings.FilterAdministratorToken -eq 0) {"Disabled (Default)"} else {"Not Configured"}
            "Security Status" = if($uacSettings.EnableLUA -eq 1) {"Secure"} else {"Potential Security Risk - UAC Disabled"}
        }
    } catch {
        $uacInfo = [PSCustomObject]@{
            SecurityStatus = "Error retrieving UAC settings: $($_.Exception.Message)"
        }
    }
    $uacInfo | Export-Csv -Path $CsvUACSettings -NoTypeInformation
    $uacHtml = $uacInfo | ConvertTo-Html -Fragment -PreContent "<h2>User Account Control (UAC) Settings</h2>"    # === PowerShell Execution Policy ===
    Write-Host "Collecting PowerShell Execution Policy..." -ForegroundColor Yellow
    try {
        $psExecPolicy = Get-ExecutionPolicy -List | ForEach-Object {
            [PSCustomObject]@{
                "Scope" = $_.Scope
                "Execution Policy" = $_.ExecutionPolicy
                "Security Risk" = switch ($_.ExecutionPolicy) {
                    "Unrestricted" {"High Risk - Allows all scripts"}
                    "Bypass" {"High Risk - Nothing is blocked"}
                    "AllSigned" {"Low Risk - Only signed scripts"}
                    "RemoteSigned" {"Medium Risk - Downloaded scripts must be signed"}
                    "Restricted" {"Very Secure - No scripts allowed"}
                    "Default" {"Inherits from parent scope"}
                    "Undefined" {"Not configured"}
                    default {"Unknown Policy"}
                }
            }
        }
    } catch {
        $psExecPolicy = [PSCustomObject]@{
            Scope = "Error"
            ExecutionPolicy = "Failed to retrieve: $($_.Exception.Message)"
            SecurityRisk = "Unknown"
        }
    }
    $psExecPolicy | Export-Csv -Path $CsvPSExecPolicy -NoTypeInformation
    $psExecPolicyHtml = $psExecPolicy | ConvertTo-Html -Fragment -PreContent "<h2>PowerShell Execution Policy (All Scopes)</h2>"

    # === RDP Security (Network Level Authentication) ===
    Write-Host "Collecting RDP Security Settings..." -ForegroundColor Yellow
    try {
        $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        $rdpSettings = Get-ItemProperty -Path $rdpRegPath -ErrorAction SilentlyContinue
        $rdpMainPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $rdpMainSettings = Get-ItemProperty -Path $rdpMainPath -ErrorAction SilentlyContinue
          $rdpSecurity = [PSCustomObject]@{
            "Network Level Authentication" = if($rdpSettings.UserAuthentication -eq 1) {"Enabled (Secure)"} elseif($rdpSettings.UserAuthentication -eq 0) {"Disabled (Security Risk)"} else {"Not Configured"}
            "RDP Enabled" = if($rdpMainSettings.fDenyTSConnections -eq 0) {"Enabled"} elseif($rdpMainSettings.fDenyTSConnections -eq 1) {"Disabled"} else {"Not Configured"}
            "Security Layer" = switch ($rdpSettings.SecurityLayer) {
                0 {"RDP Security Layer"}
                1 {"Negotiate (Default)"}
                2 {"SSL (TLS 1.0)"}
                default {"Not Configured"}
            }
            "Encryption Level" = switch ($rdpSettings.MinEncryptionLevel) {
                1 {"Low"}
                2 {"Client Compatible"}
                3 {"High (Default)"}
                4 {"FIPS Compliant"}
                default {"Not Configured"}
            }
            "Security Assessment" = if($rdpSettings.UserAuthentication -eq 1 -and $rdpSettings.MinEncryptionLevel -ge 3) {"Secure Configuration"} else {"Review Required - Security Risks Present"}
        }
    } catch {
        $rdpSecurity = [PSCustomObject]@{
            SecurityAssessment = "Error retrieving RDP settings: $($_.Exception.Message)"
        }
    }
    $rdpSecurity | Export-Csv -Path $CsvRDPSecurity -NoTypeInformation
    $rdpSecurityHtml = $rdpSecurity | ConvertTo-Html -Fragment -PreContent "<h2>RDP Security (Network Level Authentication)</h2>"

    # === Certificate Expiry Analysis ===
    Write-Host "Collecting Certificate Expiry Analysis..." -ForegroundColor Yellow
    try {
        $allCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        $certificates = @()
        
        if($allCerts -and $allCerts.Count -gt 0) {
            Write-Host "Found $($allCerts.Count) certificate(s) to analyze" -ForegroundColor Green
            foreach($cert in $allCerts) {
                try {
                    $daysUntilExpiry = if($cert.NotAfter) { [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0) } else { "Unknown" }
                    
                    # Safely get Key Usage
                    $keyUsageExt = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Key Usage"}
                    $keyUsage = if($keyUsageExt) { 
                        try { $keyUsageExt.Format($false) } catch { "Unable to read" }
                    } else { "Not specified" }
                      $certificates += [PSCustomObject]@{
                        "Subject" = if($cert.Subject) { $cert.Subject } else { "Unknown Subject" }
                        "Issuer" = if($cert.Issuer) { $cert.Issuer } else { "Unknown Issuer" }
                        "Expiration Date" = if($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "Unknown" }
                        "Days to Expire" = $daysUntilExpiry
                        "Thumbprint" = if($cert.Thumbprint) { $cert.Thumbprint } else { "Unknown" }
                        "Has Private Key" = if($null -ne $cert.HasPrivateKey) { $cert.HasPrivateKey } else { "Unknown" }
                        "Key Usage" = $keyUsage
                        "Status" = if($daysUntilExpiry -is [int]) {
                            if($daysUntilExpiry -le 0) {"EXPIRED - Immediate Action Required"} 
                            elseif($daysUntilExpiry -le 30) {"Expires Soon - Action Required"} 
                            elseif($daysUntilExpiry -le 90) {"Monitor - Expires in 3 months"} 
                            else {"Valid"}
                        } else { "Unable to determine expiry" }
                    }
                } catch {
                    Write-Warning "Error processing certificate: $($_.Exception.Message)"                    $certificates += [PSCustomObject]@{
                        Subject = "Error reading certificate"
                        Issuer = "Error"
                        NotBefore = "Error"
                        NotAfter = "Error"
                        DaysUntilExpiry = "Error"
                        Thumbprint = "Error"
                        HasPrivateKey = "Error"
                        KeyUsage = "Error"
                        Status = "Error: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        if($certificates.Count -eq 0) {
            Write-Host "No certificates found in LocalMachine\My store" -ForegroundColor Yellow            $certificates = @([PSCustomObject]@{
                Subject = "No certificates found"
                Issuer = "N/A"
                NotBefore = "N/A"
                NotAfter = "N/A"
                DaysUntilExpiry = "N/A"
                Thumbprint = "N/A"
                HasPrivateKey = "N/A"
                KeyUsage = "N/A"
                Status = "No certificates in LocalMachine\My store"
            })
        }
    } catch {
        Write-Error "Failed to analyze certificates: $($_.Exception.Message)"        $certificates = @([PSCustomObject]@{
            Subject = "Error"
            Issuer = "N/A"
            NotBefore = "N/A"
            NotAfter = "N/A"
            DaysUntilExpiry = "N/A"
            Thumbprint = "N/A"
            HasPrivateKey = "N/A"
            KeyUsage = "N/A"
            Status = "Failed to retrieve certificates: $($_.Exception.Message)"
        })
    }
    $certificates | Export-Csv -Path $CsvCertificates -NoTypeInformation
    $certificatesHtml = $certificates | ConvertTo-Html -Fragment -PreContent "<h2>Certificate Expiry Analysis</h2>"

    # === DNS Client Settings ===
    Write-Host "Collecting DNS Client Settings..." -ForegroundColor Yellow
    try {
        # Get DNS Over HTTPS settings
        $dohStatus = "Not Available"
        try {
            $dohSettings = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
            if($dohSettings) {
                $dohStatus = "Configured: $($dohSettings.ServerAddress -join ', ')"
            } else {
                $dohStatus = "Not Configured"
            }
        } catch {
            $dohStatus = "Not Available"
        }

        # Get DNSSEC settings
        $dnssecStatus = "Not Available"
        try {
            $dnssec = Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue
            if($dnssec) {
                $dnssecStatus = "DNSSEC Policies: $($dnssec.Count)"
            } else {
                $dnssecStatus = "No DNSSEC Policies"
            }
        } catch {
            $dnssecStatus = "Not Available"
        }        $dnsSettings = [PSCustomObject]@{
            "DNS Servers" = (Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2} | ForEach-Object {"$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')"}) -join "; "
            "DNS Over HTTPS" = $dohStatus
            "DNS Cache" = (Get-DnsClientCache | Measure-Object).Count
            "DNS Suffix Search List" = (Get-DnsClientGlobalSetting).SuffixSearchList -join ", "
            "Secure Name Resolution" = $dnssecStatus
        }
    } catch {
        $dnsSettings = [PSCustomObject]@{
            Error = "Failed to retrieve DNS settings: $($_.Exception.Message)"
        }
    }
    $dnsSettings | Export-Csv -Path $CsvDNSSettings -NoTypeInformation
    $dnsSettingsHtml = $dnsSettings | ConvertTo-Html -Fragment -PreContent "<h2>DNS Client Settings</h2>"

    # === Windows Defender Attack Surface Reduction (ASR) & Exploit Guard ===
    Write-Host "Collecting Windows Defender ASR Settings..." -ForegroundColor Yellow
    try {
        # Get ASR Rules
        $asrRulesCount = 0
        $asrRulesStatus = "Not Available"
        try {
            $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
            if($asrRules) {
                $asrRulesCount = $asrRules.Count
            }
            $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
            if($asrActions) {
                $asrRulesStatus = "Configured: $($asrActions.Count) rules"
            } else {
                $asrRulesStatus = "Not Configured"
            }
        } catch {
            $asrRulesStatus = "Not Available"
        }

        # Get Controlled Folder Access
        $cfaStatus = "Not Available"
        try {
            $cfa = Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess -ErrorAction SilentlyContinue
            $cfaStatus = switch($cfa) {
                0 {"Disabled"}
                1 {"Enabled"}
                2 {"Audit Mode"}
                default {"Not Configured"}
            }
        } catch {
            $cfaStatus = "Not Available"
        }

        # Get Exploit Protection
        $exploitStatus = "Not Available"
        try {
            $exploit = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
            if($exploit) {
                $exploitStatus = "System-wide policies configured"
            } else {
                $exploitStatus = "Default settings"
            }
        } catch {
            $exploitStatus = "Not Available"
        }

        # Get Network Protection
        $netProtectionStatus = "Not Available"
        try {
            $netProtection = Get-MpPreference | Select-Object -ExpandProperty EnableNetworkProtection -ErrorAction SilentlyContinue
            $netProtectionStatus = switch($netProtection) {
                0 {"Disabled"}
                1 {"Enabled"}
                2 {"Audit Mode"}
                default {"Not Configured"}
            }
        } catch {
            $netProtectionStatus = "Not Available"
        }        $defenderASR = [PSCustomObject]@{
            "ASR Rules Enabled" = $asrRulesCount
            "ASR Rules Status" = $asrRulesStatus
            "Controlled Folder Access" = $cfaStatus
            "Exploit Protection" = $exploitStatus
            "Network Protection" = $netProtectionStatus
        }
    } catch {
        $defenderASR = [PSCustomObject]@{
            Error = "Failed to retrieve Windows Defender settings: $($_.Exception.Message)"
        }
    }
    $defenderASR | Export-Csv -Path $CsvDefenderASR -NoTypeInformation
    $defenderASRHtml = $defenderASR | ConvertTo-Html -Fragment -PreContent "<h2>Windows Defender Attack Surface Reduction (ASR) & Exploit Guard</h2>"

    Write-Host "Security Information Collection Complete" -ForegroundColor Green

    # Return HTML sections
    $sections = [ordered]@{}
    $sections['AntiVirus'] = $AVsettingsHtml
    $sections['FirewallStatus'] = $FWstatusHtml
    $sections['FirewallSettings'] = $FWSettingsHtml
    $sections['SMBv1Status'] = $SMBv1Html
    $sections['InactiveAccounts'] = $inactiveAccountsHtml
    $sections['LocalAdmins'] = $localAdminsHtml
    $sections['PasswordPolicy'] = $passwordPolicyHtml
    $sections['SMBShares'] = $sharesHtml
    $sections['AuditSettings'] = $auditSettingsHtml
    $sections['TLSSettings'] = $TLSregSettingsHtml
    $sections['UACSettings'] = $uacHtml
    $sections['PSExecutionPolicy'] = $psExecPolicyHtml
    $sections['RDPSecurity'] = $rdpSecurityHtml
    $sections['Certificates'] = $certificatesHtml
    $sections['DNSSettings'] = $dnsSettingsHtml
    $sections['DefenderASR'] = $defenderASRHtml
    return $sections
}

# 3.1 Collect Security Information ===
$securityInfoHtml = Get-SecurityInformation -Path $path -ServerName $ServerName -GPOSettings $GPOSettings -CsvAVSettings $csvAVsettingsinfo -CsvFWStatusInfo $csvFWstatusinfo -CsvFWSettingsInfo $csvFWSettingsinfo -CsvSMBv1 $csvSMBv1 -CsvInactiveAccountsInfo $csvinactiveaccountsinfo -CsvLocalAdmins $csvlocalAdmins -CsvAccountPolicyPath (Join-Path -Path $path -ChildPath "$ServerName-PasswordPolicyInfo.csv") -CsvShares $csvShares -CsvAuditSettings $csvauditSettings -CsvTLSregSettings $csvTLSregSettings -CsvUACSettings $csvUACSettings -CsvPSExecPolicy $csvPSExecPolicy -CsvRDPSecurity $csvRDPSecurity -CsvCertificates $csvCertificates -CsvDNSSettings $csvDNSSettings -CsvDefenderASR $csvDefenderASR

# 3.2 Extract individual HTML sections from security information function
$AVsettingsHtml = $securityInfoHtml['AntiVirus']
$FWstatusHtml = $securityInfoHtml['FirewallStatus']
$FWSettingsHtml = $securityInfoHtml['FirewallSettings']
$SMBv1Html = $securityInfoHtml['SMBv1Status']
$inactiveAccountsHtml = $securityInfoHtml['InactiveAccounts']
$localAdminsHtml = $securityInfoHtml['LocalAdmins']
$passwordPolicyHtml = $securityInfoHtml['PasswordPolicy']
$sharesHtml = $securityInfoHtml['SMBShares']
$auditSettingsHtml = $securityInfoHtml['AuditSettings']
$TLSregSettingsHtml = $securityInfoHtml['TLSSettings']
$uacHtml = $securityInfoHtml['UACSettings']
$psExecPolicyHtml = $securityInfoHtml['PSExecutionPolicy']
$rdpSecurityHtml = $securityInfoHtml['RDPSecurity']
$certificatesHtml = $securityInfoHtml['Certificates']
$dnsSettingsHtml = $securityInfoHtml['DNSSettings']
$defenderASRHtml = $securityInfoHtml['DefenderASR']
$userRightsAssignmentsHtml = if ($systemInfoHtml.ContainsKey('UserRightsAssignments')) { $systemInfoHtml['UserRightsAssignments'] } else { $null }

} # End security-only or all sections check

# ----------------------------
# 4. SCHEDULED TASKS & STARTUP & LOGS
# ----------------------------

# === Tasks, Startup, and Logs Information Function === #
function Get-TasksStartupLogsInformation {
    <#
    .SYNOPSIS
        Collects comprehensive tasks, startup programs, and logs information for the health check report.
    .DESCRIPTION
        This function gathers information about startup programs, scheduled tasks, event viewer logs,
        and recent system/application/security logs. It exports data to CSV files and returns HTML
        sections for the main report.
    .PARAMETER Path
        The directory path where CSV files will be saved.
    .PARAMETER ServerName
        The name of the server for file naming purposes.
    .PARAMETER CsvStartupProgsInfo
        Path for startup programs CSV file.
    .PARAMETER CsvScheduledTasksInfo
        Path for scheduled tasks CSV file.
    .PARAMETER CsvEventLog
        Path for event log details CSV file.
    .PARAMETER CsvSystemLogs
        Path for system logs CSV file.
    .PARAMETER CsvApplicationLogs
        Path for application logs CSV file.
    .PARAMETER CsvSecurityLogs
        Path for security logs CSV file.
    .OUTPUTS
        Returns a hashtable containing HTML sections for inclusion in the main report.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvStartupProgsInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvScheduledTasksInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvEventLog,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvSystemLogs,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvApplicationLogs,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvSecurityLogs
    )
    
    Write-Host "=== COLLECTING Scheduled Tasks, Startup Programs, and Logs INFORMATION ===" -ForegroundColor Cyan
    
    # === Startup Programs ===
    Write-Host "Collecting Startup Programs..." -ForegroundColor Yellow
    $startupprogs = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location
    $startupprogsAll = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object *
    $startupprogsAll | Export-Csv -Path $CsvStartupProgsInfo -NoTypeInformation
    $startupprogsHtml = $startupprogs | ConvertTo-Html -Fragment -PreContent "<h2>Startup Programs</h2>"

    # === Scheduled Tasks ===
    Write-Host "Collecting Scheduled Tasks..." -ForegroundColor Yellow
    $ScheduledTasks = Get-ScheduledTask | Select-Object TaskName, State, Taskpath
    $ScheduledTasksAll = Get-ScheduledTask | Select-Object *
    $ScheduledTasksAll | Export-Csv -Path $CsvScheduledTasksInfo -NoTypeInformation
    $ScheduledTasksHtml = $ScheduledTasks | ConvertTo-Html -Fragment -PreContent "<h2>Scheduled Tasks</h2>"    # === Event Viewer Logs Details ===
    Write-Host "Collecting Event Viewer Logs Size and Retention Details..." -ForegroundColor Yellow
    $eventlogRaw = Get-EventLog -List  | Select-Object LogDisplayName, MaximumKilobytes, OverflowAction, MinimumRetentionDays, EnableRaisingEvents
    $eventlogAll = Get-EventLog -List  | Select-Object *
    
    # Create PSCustomObject array with user-friendly column names
    $eventlog = $eventlogRaw | ForEach-Object {
        [PSCustomObject]@{
            'Log Name' = $_.LogDisplayName
            'Maximum Log Size (KB)' = $_.MaximumKilobytes
            'Overflow Action' = $_.OverflowAction
            'Minimum Retention (Days)' = $_.MinimumRetentionDays
            'Event Raising Enabled' = $_.EnableRaisingEvents
        }
    }
    
    $eventlogAll | Export-Csv -Path $CsvEventLog -NoTypeInformation
    $eventlogHtml = "<div class='table-container'>" + ($eventlog | ConvertTo-Html -Fragment -PreContent "<h2>Event Viewer Logs Size and Retention Details</h2>") + "</div>"

    # === Get Event Viewer Logs for last 3 days ===
    Write-Host "Collecting Event Logs for last 3 days (Errors and Warnings)..." -ForegroundColor Yellow
    $startDate = (Get-Date).AddDays(-3)

    # === Get System logs ===
    Write-Host "  - Processing System logs..." -ForegroundColor Gray
    try {
        $Systemlogs = Get-WinEvent  -FilterHashtable @{
            LogName = 'System'
            StartTime = $startDate
        } | Where-Object { $_.LevelDisplayName -in "Error", "Warning" } | Select-Object *
        $Systemlogs | Export-Csv -Path $CsvSystemLogs -NoTypeInformation
        Write-Host "    Found $($Systemlogs.Count) System log entries" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect System logs: $($_.Exception.Message)"
        $Systemlogs = @()
    }

    # === Get Application logs ===
    Write-Host "  - Processing Application logs..." -ForegroundColor Gray
    try {
        $Applicationlogs = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $startDate
        } | Where-Object { $_.LevelDisplayName -in "Error", "Warning" }  | Select-Object *
        $Applicationlogs | Export-Csv $CsvApplicationLogs -NoTypeInformation
        Write-Host "    Found $($Applicationlogs.Count) Application log entries" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Application logs: $($_.Exception.Message)"
        $Applicationlogs = @()
    }

    # === Get Security logs ===
    Write-Host "  - Processing Security logs..." -ForegroundColor Gray
    try {
        $Securitylogs = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $startDate
        } | Where-Object { $_.LevelDisplayName -in "Error", "Warning" } | Select-Object *
        $Securitylogs | Export-Csv -Path $CsvSecurityLogs -NoTypeInformation
        Write-Host "    Found $($Securitylogs.Count) Security log entries" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect Security logs: $($_.Exception.Message)"
        $Securitylogs = @()
    }

    Write-Host "Scheduled Tasks, Startup Programs, and Logs Information Collection Complete" -ForegroundColor Green
    
    # Return HTML sections
    return @{
        'StartupPrograms' = $startupprogsHtml
        'ScheduledTasks' = $ScheduledTasksHtml 
        'EventLogDetails' = $eventlogHtml
    }
}

# ----------------------------

# 4.2. Collect Tasks, Startup, and Logs Information
$tasksStartupLogsInfoHtml = Get-TasksStartupLogsInformation -Path $path -ServerName $ServerName -CsvStartupProgsInfo $csvstartupprogsinfo -CsvScheduledTasksInfo $csvScheduledTasksinfo -CsvEventLog $csveventlog -CsvSystemLogs $csvSystemlogs -CsvApplicationLogs $csvApplicationlogs -CsvSecurityLogs $csvSecuritylogs

# 4.3. Extract individual HTML sections from tasks, startup, and logs information function
$startupprogsHtml = $tasksStartupLogsInfoHtml['StartupPrograms']
$ScheduledTasksHtml = $tasksStartupLogsInfoHtml['ScheduledTasks']
$eventlogHtml = $tasksStartupLogsInfoHtml['EventLogDetails']


# Initialize empty variables for sections not collected based on user selection
if ($collectSystemOnly) {
    Write-Host "=== SKIPPING NETWORK, SECURITY & TASKS SECTIONS (System Information Only Mode) ===" -ForegroundColor Yellow
    
    # Initialize empty HTML sections for network, security and tasks information
    $nicInfoHtml = ""
    $trafficInfoHtml = ""
    $openportsHtml = ""
    $AVsettingsHtml = ""
    $userRightsAssignmentsHtml = ""
   
   
    $FWstatusHtml = ""
    $FWSettingsHtml = ""
    $SMBv1Html = ""
    $inactiveAccountsHtml = ""
    $localAdminsHtml = ""
    $passwordPolicyHtml = ""
    $sharesHtml = ""
    $auditSettingsHtml = ""
    $TLSregSettingsHtml = ""
    $uacHtml = ""
    $psExecPolicyHtml = ""
    $rdpSecurityHtml = ""
    $certificatesHtml = ""
    $dnsSettingsHtml = ""
    $defenderASRHtml = ""
    $startupprogsHtml = ""
    $ScheduledTasksHtml = ""
    $eventlogHtml = ""
} elseif ($collectNetworkOnly) {
    Write-Host "=== SKIPPING SYSTEM, SECURITY & TASKS SECTIONS (Network Checks Only Mode) ===" -ForegroundColor Yellow
    
    # Initialize empty HTML sections for system, security and tasks information
    $osInfoHtml = ""
    $uptimeHtml = ""
    $cpuInfoHtml = ""
    $cpuusageInfoHtml = ""
    $RAMHtml = ""
    $diskInfoHtml = ""
    $FeaturesHtml = ""
    $runningHtml = ""
    $stoppedHtml = ""
    $installedprogsHtml = ""
    $CurrentProcessesHtml = ""
    $updatesHtml = ""
    $missingupdatesHtml = ""
    $AVsettingsHtml = ""
    $FWstatusHtml = ""
    $FWSettingsHtml = ""
    $SMBv1Html = ""
    $inactiveAccountsHtml = ""
    $localAdminsHtml = ""
    $passwordPolicyHtml = ""
    $sharesHtml = ""
    $auditSettingsHtml = ""
    $TLSregSettingsHtml = ""
    $uacHtml = ""
    $psExecPolicyHtml = ""
    $rdpSecurityHtml = ""
    $certificatesHtml = ""
    $dnsSettingsHtml = ""
    $defenderASRHtml = ""
    $userRightsAssignmentsHtml = ""
    $startupprogsHtml = ""
    $ScheduledTasksHtml = ""
    $eventlogHtml = ""
} 
elseif ($collectTasksOnly) {
    Write-Host "=== SKIPPING SYSTEM, NETWORK & SECURITY SECTIONS (Tasks & Logs Only Mode) ===" -ForegroundColor Yellow
    
    # Initialize empty HTML sections for system, network and security information
    $osInfoHtml = ""
    $uptimeHtml = ""
    $cpuInfoHtml = ""
    $cpuusageInfoHtml = ""
    $RAMHtml = ""
    $diskInfoHtml = ""
    $FeaturesHtml = ""
    $runningHtml = ""
    $stoppedHtml = ""
    $installedprogsHtml = ""
    $CurrentProcessesHtml = ""
    $updatesHtml = ""
    $missingupdatesHtml = ""
    $nicInfoHtml = ""
    $trafficInfoHtml = ""
    $openportsHtml = ""
    $AVsettingsHtml = ""
    $FWstatusHtml = ""
    $FWSettingsHtml = ""
    $SMBv1Html = ""
    $inactiveAccountsHtml = ""
    $localAdminsHtml = ""
    $passwordPolicyHtml = ""
    $sharesHtml = ""
    $auditSettingsHtml = ""
    $TLSregSettingsHtml = ""
    $uacHtml = ""
    $psExecPolicyHtml = ""
    $rdpSecurityHtml = ""
    $certificatesHtml = ""
    $dnsSettingsHtml = ""
    $defenderASRHtml = ""
    $userRightsAssignmentsHtml = ""
} elseif ($collectSecurityOnly) {
    Write-Host "=== SKIPPING SYSTEM, NETWORK & TASKS SECTIONS (Security Checks Only Mode) ===" -ForegroundColor Yellow
    
    # Initialize empty HTML sections for system, network and tasks information
    $osInfoHtml = ""
    $uptimeHtml = ""
    $cpuInfoHtml = ""
    $cpuusageInfoHtml = ""
    $RAMHtml = ""
    $diskInfoHtml = ""
    $FeaturesHtml = ""
    $runningHtml = ""
    $stoppedHtml = ""
    $installedprogsHtml = ""
    $CurrentProcessesHtml = ""
    $updatesHtml = ""
    $missingupdatesHtml = ""
    $nicInfoHtml = ""
    $trafficInfoHtml = ""
    $openportsHtml = ""
    $userRightsAssignmentsHtml = ""
    $startupprogsHtml = ""
    $ScheduledTasksHtml = ""
    $eventlogHtml = ""
} else {
    # All sections mode - check if any individual sections were skipped
    if (-not ($collectSystemOnly -or $collectNetworkOnly -or $collectSecurityOnly)) {
        # Initialize empty variables for tasks section if it was skipped
        if ($collectSystemOnly -or $collectNetworkOnly -or $collectSecurityOnly) {
            $startupprogsHtml = ""
            $ScheduledTasksHtml = ""
            $eventlogHtml = ""
        }
    }
}


# ----------------------------
# FINAL OUTPUT
# ----------------------------

# === Combine into HTML ===
$reportTitle = if ($collectSystemOnly) { 
    "System Information Report" 
} elseif ($collectNetworkOnly) { 
    "Network Checks Report" 
} elseif ($collectSecurityOnly) { 
    "Security Checks Report" 
} elseif ($collectTasksOnly) { 
    "Tasks & Logs Report" 
} else { 
    "System Health Check Report" 
}

$reportScope = if ($collectSystemOnly) { 
    "System Information Only (13 sections only)" 
} elseif ($collectNetworkOnly) { 
    "Network Checks Only (3 sections only)" 
} elseif ($collectSecurityOnly) { 
    "Security Checks Only (16 sections only)" 
} elseif ($collectTasksOnly) { 
    "Tasks & Logs Only (3 sections only) " 
} else { 
    "Complete Health Check (All Sections - 35 sections)" 
}

# Pre-generate all required icons
Write-Host "Loading icons..." -ForegroundColor Yellow
$iconChart = Get-IconHTML -IconName 'chart'
$iconClipboard = Get-IconHTML -IconName 'clipboard'
$iconComputer = Get-IconHTML -IconName 'computer'
$iconServer = Get-IconHTML -IconName 'server'
$iconGear = Get-IconHTML -IconName 'gear'
$iconShield = Get-IconHTML -IconName 'shield'
$iconNetwork = Get-IconHTML -IconName 'network'
$iconLock = Get-IconHTML -IconName 'lock'
$iconKey = Get-IconHTML -IconName 'key'
$iconUser = Get-IconHTML -IconName 'user'
$iconUsers = Get-IconHTML -IconName 'users'
$iconFolder = Get-IconHTML -IconName 'folder'
$iconClock = Get-IconHTML -IconName 'clock'
$iconWarning = Get-IconHTML -IconName 'warning'
$iconCheck = Get-IconHTML -IconName 'check'
$iconCross = Get-IconHTML -IconName 'cross'
$iconTarget = Get-IconHTML -IconName 'target'
$iconMemory = Get-IconHTML -IconName 'memory'
$iconDisk = Get-IconHTML -IconName 'disk'
$iconCpu = Get-IconHTML -IconName 'cpu'
$iconProcess = Get-IconHTML -IconName 'process'
$iconService = Get-IconHTML -IconName 'service'
$iconProgram = Get-IconHTML -IconName 'program'
$iconPort = Get-IconHTML -IconName 'port'
$iconFirewall = Get-IconHTML -IconName 'firewall'
$iconAntivirus = Get-IconHTML -IconName 'antivirus'
$iconCertificate = Get-IconHTML -IconName 'certificate'
$iconDns = Get-IconHTML -IconName 'dns'
$iconAudit = Get-IconHTML -IconName 'audit'
$iconTask = Get-IconHTML -IconName 'task'
$iconStartup = Get-IconHTML -IconName 'startup'
$iconLog = Get-IconHTML -IconName 'log'
$iconMenu = Get-IconHTML -IconName 'menu'
Write-Host "Icons loaded successfully" -ForegroundColor Green

# Create dynamic assessment areas based on menu selection
$assessmentAreas = ""
if ($collectSystemOnly) {
    $assessmentAreas = @"
                        <li>OS Details, CPU, Memory, Disk Information</li>
                        <li>Windows Features, Services, Programs</li>
                        <li>Updates and Processes</li>
"@
} elseif ($collectNetworkOnly) {
    $assessmentAreas = @"
                        <li>Network Interface Configuration</li>
                        <li>Traffic Statistics and Performance</li>
                        <li>Open Ports and Connections</li>
"@
} elseif ($collectSecurityOnly) {
    $assessmentAreas = @"
                        <li>Antivirus and Firewall Settings</li>
                        <li>User Accounts and Password Policies</li>
                        <li>Security Configurations and Certificates</li>
"@
} elseif ($collectTasksOnly) {
    $assessmentAreas = @"
                        <li>Startup Programs and Services</li>
                        <li>Scheduled Tasks Configuration</li>
                        <li>System, Application & Security Event Logs</li>
"@
} else {
    $assessmentAreas = @"
                        <li>System configuration and performance metrics</li>
                        <li>Network interface configuration and traffic</li>
                        <li>Security settings and policies</li>
                        <li>User accounts and access controls</li>
                        <li>Services and scheduled tasks</li>
                        <li>Event logs and system monitoring</li>
"@
}

# Create dynamic assessment categories based on menu selection
$assessmentCategories = ""
if ($collectSystemOnly) {
    $assessmentCategories = "System"
} elseif ($collectNetworkOnly) {
    $assessmentCategories = "Network"
} elseif ($collectSecurityOnly) {
    $assessmentCategories = "Security"
} elseif ($collectTasksOnly) {
    $assessmentCategories = "Scheduled Tasks, Startup Programs, and Logs"
} else {
    $assessmentCategories = "System, Network, Security, Scheduled Tasks, Startup Programs, and Logs"
}

# Report metadata and icons used in HTML
$reportTitle = "Windows Server Assessment Report"
$reportScope = switch ($menuChoice) {
    '1' { 'System Only' }
    '2' { 'Network Only' }
    '3' { 'Security Only' }
    '4' { 'Tasks/Startup/Logs Only' }
    default { 'All Sections' }
}

# Precompute icon variables
$iconChart = Get-IconHTML -IconName 'chart'
$iconClipboard = Get-IconHTML -IconName 'clipboard'
$iconComputer = Get-IconHTML -IconName 'computer'
$iconServer = Get-IconHTML -IconName 'server'
$iconGear = Get-IconHTML -IconName 'gear'
$iconShield = Get-IconHTML -IconName 'shield'
$iconNetwork = Get-IconHTML -IconName 'network'
$iconLock = Get-IconHTML -IconName 'lock'
$iconKey = Get-IconHTML -IconName 'key'
$iconUser = Get-IconHTML -IconName 'user'
$iconUsers = Get-IconHTML -IconName 'users'
$iconFolder = Get-IconHTML -IconName 'folder'
$iconClock = Get-IconHTML -IconName 'clock'
$iconWarning = Get-IconHTML -IconName 'warning'
$iconCheck = Get-IconHTML -IconName 'check'
$iconCross = Get-IconHTML -IconName 'cross'
$iconTarget = Get-IconHTML -IconName 'target'
$iconMemory = Get-IconHTML -IconName 'memory'
$iconDisk = Get-IconHTML -IconName 'disk'
$iconCpu = Get-IconHTML -IconName 'cpu'
$iconProcess = Get-IconHTML -IconName 'process'
$iconService = Get-IconHTML -IconName 'service'
$iconProgram = Get-IconHTML -IconName 'program'
$iconPort = Get-IconHTML -IconName 'port'
$iconFirewall = Get-IconHTML -IconName 'firewall'
$iconAntivirus = Get-IconHTML -IconName 'antivirus'
$iconCertificate = Get-IconHTML -IconName 'certificate'
$iconDns = Get-IconHTML -IconName 'dns'
$iconAudit = Get-IconHTML -IconName 'audit'
$iconTask = Get-IconHTML -IconName 'task'
$iconStartup = Get-IconHTML -IconName 'startup'
$iconLog = Get-IconHTML -IconName 'log'
$iconMenu = Get-IconHTML -IconName 'menu'

$fullHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>$reportTitle for Windows Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        /* Icon Styles */
        .icon-emoji {
            display: inline-block;
            vertical-align: middle;
            margin-right: 8px;
            font-size: 16px;
        }
        
        .nav-item .icon-emoji, .nav-submenu-item .icon-emoji {
            margin-right: 10px;
            font-size: 14px;
        }
        
        .section-header .icon-emoji, .subsection-header .icon-emoji {
            margin-right: 10px;
            font-size: 18px;
        }
        
        h2 .icon-emoji {
            font-size: 20px;
        }
        
        h3 .icon-emoji {
            font-size: 16px;
        }
        
        body {
            font-family: 'Segoe UI', sans-serif; 
            background-color: #f8f9fa; 
            line-height: 1.6;
        }
        
        /* Header Styles */
        .header {
            background: linear-gradient(135deg, #0078D7 0%, #005a9e 100%);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .header-info p {
            background: rgba(255, 255, 255, 0.1);
            padding: 8px 12px;
            border-radius: 5px;
            margin: 0;
        }
        
        /* Layout Container */
        .container {
            display: flex;
            min-height: calc(100vh - 140px);
        }
        
        /* Left Navigation Menu */
        .nav-menu {
            width: 320px;
            flex: 0 0 320px; /* lock width in flex layout */
            background: #2d3748;
            color: white;
            padding: 0;
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            transition: width 0.3s ease;
            position: relative;
            display: flex;
            flex-direction: column;
            height: calc(100vh - 140px); /* match container min-height */
            overflow: hidden; /* contain scroll to nav-items */
        }
        
        .nav-menu.collapsed {
            width: 60px;
            flex: 0 0 60px;
        }
        
        .nav-toggle {
            background: #4299e1;
            color: white;
            border: none;
            padding: 15px;
            width: 100%;
            text-align: left;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        
        .nav-toggle:hover {
            background: #3182ce;
        }
        
        .nav-toggle:after {
            content: '\25C0';
            float: right;
            transition: transform 0.3s;
        }
        
        .nav-menu.collapsed .nav-toggle:after {
            transform: rotate(180deg);
        }
        
        .nav-items {
            flex: 1 1 auto;
            overflow-y: auto; /* make menu scrollable */
            overflow-x: hidden;
            transition: all 0.3s ease;
        }
        
        .nav-menu.collapsed .nav-items {
            opacity: 0;
            overflow: hidden; /* disable scroll when collapsed */
        }
        
        .nav-item {
            border-bottom: 1px solid #4a5568;
        }
        
        .nav-item a {
            display: block;
            padding: 15px 20px;
            color: #e2e8f0;
            text-decoration: none;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .nav-item a:hover {
            background: #4a5568;
            color: white;
            padding-left: 25px;
        }
        
        .nav-item.active a {
            background: #4299e1;
            color: white;
            border-left: 4px solid #63b3ed;
        }
        
        /* Sub-section styles */
        .nav-item.has-submenu > a:after {
            content: '\25B6';
            float: right;
            transition: transform 0.3s;
            font-size: 12px;
        }
        
        .nav-item.has-submenu.expanded > a:after {
            transform: rotate(90deg);
        }
        
        .nav-submenu {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
            background: #1a202c;
        }
        
        .nav-item.expanded .nav-submenu {
            max-height: max-content;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .nav-submenu-item {
            border-bottom: 1px solid #2d3748;
        }
        
        .nav-submenu-item a {
            padding: 12px 40px;
            font-size: 14px;
            color: #cbd5e0;
            background: transparent;
        }
        
        .nav-submenu-item a:hover {
            background: #2d3748;
            color: white;
            padding-left: 45px;
        }
        
        .nav-submenu-item.active a {
            background: #2b77e6;
            color: white;
            border-left: 3px solid #63b3ed;
        }
        
        .section-count {
            float: right;
            background: #4299e1;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            margin-top: 2px;
        }
        
        /* Main Content Area */
        .main-content {
            flex: 1;
            padding: 20px;
            background: white;
            margin: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        /* Summary Cards */
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-item {
            background: rgba(255, 255, 255, 0.15);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            backdrop-filter: blur(10px);
        }
        
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
        }
        
        .summary-label {
            font-size: 1em;
            opacity: 0.9;
        }
        
        /* Section Styles */
        .section {
            margin-bottom: 30px;
            display: none;
        }
        
        .section.active {
            display: block;
            animation: fadeIn 0.3s ease-in;
        }
        
        .subsection {
            margin-bottom: 25px;
            display: none;
        }
        
        .subsection.active {
            display: block;
            animation: fadeIn 0.3s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section-header {
            background: linear-gradient(135deg, #0078D7 0%, #005a9e 100%);
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 0;
        }
        
        .section-header h2 {
            margin: 0;
            font-size: 1.8em;
        }
        
        .subsection-header {
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: white;
            padding: 15px 20px;
            border-radius: 8px 8px 0 0;
            margin-bottom: 0;
            margin-top: 20px;
        }
        
        .subsection-header:first-child {
            margin-top: 0;
        }
        
        .subsection-header h3 {
            margin: 0;
            font-size: 1.3em;
        }
        
        .section-content {
            background: white;
            border: 1px solid #e2e8f0;
            border-top: none;
            border-radius: 0 0 10px 10px;
            padding: 20px;
        }
        
        .subsection-content {
            background: white;
            border: 1px solid #e2e8f0;
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 15px 20px;
        }
          /* Table Styles */
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin: 15px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th, td { 
            padding: 12px 15px; 
            text-align: left; 
            border-bottom: 1px solid #e2e8f0;
        }
          th { 
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: white;
            font-weight: 600;
            text-transform: capitalize;
            font-size: 0.9em;
            position: relative;
        }
        
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
          tr:hover { 
            background-color: #e3f2fd; 
            transition: background-color 0.2s;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                flex-direction: column;
            }
            
            .nav-menu {
                width: 100%;
                flex: unset;
                height: auto; /* allow natural height on small screens */
                order: 2;
            }
            
            .main-content {
                order: 1;
                margin: 10px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
        
    </style>
    
    <script>
        // Navigation functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle navigation menu
            const navToggle = document.querySelector('.nav-toggle');
            const navMenu = document.querySelector('.nav-menu');
            
            navToggle.addEventListener('click', function() {
                navMenu.classList.toggle('collapsed');
            });
            
            // Handle main section and sub-section navigation
            const navLinks = document.querySelectorAll('.nav-item a, .nav-submenu-item a');
            const sections = document.querySelectorAll('.section');
            const subsections = document.querySelectorAll('.subsection');
            
            // Show summary section by default
            document.getElementById('summary').classList.add('active');
            document.querySelector('[data-section="summary"]').parentElement.classList.add('active');
            
            navLinks.forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    const sectionId = this.getAttribute('data-section');
                    const subsectionId = this.getAttribute('data-subsection');
                    
                    // Handle submenu toggle for main section links with submenus
                    if (this.parentElement.classList.contains('has-submenu') && !subsectionId) {
                        this.parentElement.classList.toggle('expanded');
                        return;
                    }
                    
                    // Remove active class from all nav items and sections
                    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
                    document.querySelectorAll('.nav-submenu-item').forEach(item => item.classList.remove('active'));
                    sections.forEach(s => s.classList.remove('active'));
                    subsections.forEach(s => s.classList.remove('active'));
                    
                    // Show the main section
                    const targetSection = document.getElementById(sectionId);
                    if (targetSection) {
                        targetSection.classList.add('active');
                    }
                    
                    // Handle subsection navigation
                    if (subsectionId) {
                        // Add active class to the submenu item
                        this.parentElement.classList.add('active');
                        
                        // Make sure the parent menu is expanded
                        const parentNavItem = this.closest('.nav-item.has-submenu');
                        if (parentNavItem) {
                            parentNavItem.classList.add('expanded');
                        }
                        
                        // Hide all subsections in the target section
                        const targetSectionSubsections = targetSection.querySelectorAll('.subsection');
                        targetSectionSubsections.forEach(sub => sub.classList.remove('active'));
                        
                        // Show the specific subsection
                        const targetSubsection = document.getElementById(subsectionId);
                        if (targetSubsection) {
                            targetSubsection.classList.add('active');
                        }
                    } else {
                        // If no subsection specified, show all subsections in the section
                        const targetSectionSubsections = targetSection.querySelectorAll('.subsection');
                        targetSectionSubsections.forEach(sub => sub.classList.add('active'));
                        
                        // Add active class to the main nav item
                        this.parentElement.classList.add('active');
                    }
                    
                    // Scroll to top of main content
                    document.querySelector('.main-content').scrollTop = 0;
                });
            });            // Auto-expand first menu item with submenus on load
            const firstSubmenu = document.querySelector('.nav-item.has-submenu');
            if (firstSubmenu) {
                firstSubmenu.classList.add('expanded');
            }
        });
    </script>
</head>
<body>
    <div class="header">
        <h1>$reportTitle</h1>
        <div class="header-info">
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Host Name:</strong> $(hostname)</p>
            <p><strong>User:</strong> $(whoami)</p>
            <p><strong>Scope:</strong> $reportScope</p>
        </div>
    </div>
    
    <div class="container">
        <nav class="nav-menu">
            <button class="nav-toggle">$iconMenu Navigation Menu</button>
            <div class="nav-items">
                <div class="nav-item">
                    <a href="#" data-section="summary">$iconClipboard Executive Summary</a>
                </div>
"@

# Build navigation menu based on selected sections
if (-not $collectNetworkOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly) {
    $systemSectionCount = 13
    $fullHtml += @"
                <div class="nav-item has-submenu">
                    <a href="#" data-section="system-info">$iconComputer System Information <span class="section-count">$systemSectionCount</span></a>
                    <div class="nav-submenu">
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="os-info">$iconServer Operating System</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="uptime">$iconClock System Uptime</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="cpu-info">$iconCpu CPU Information</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="cpu-usage">$iconChart CPU Usage</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="memory">$iconMemory Memory Information</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="disk">$iconDisk Disk Information</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="programs">$iconProgram Installed Programs</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="updates">$iconCheck Installed Updates</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="missing-updates">$iconWarning Missing Updates</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="processes">$iconProcess Running Processes</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="running-services">$iconService Running Services</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="stopped-services">$iconCross Stopped Services</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="system-info" data-subsection="features">$iconGear Windows Features</a>
                        </div>
                    </div>
                </div>
"@
}

if ($collectNetworkOnly -or (-not $collectSystemOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly)) {
    $networkSectionCount = 3
    $fullHtml += @"
                <div class="nav-item has-submenu">
                    <a href="#" data-section="network-info">$iconNetwork Network Information <span class="section-count">$networkSectionCount</span></a>
                    <div class="nav-submenu">
                        <div class="nav-submenu-item">
                            <a href="#" data-section="network-info" data-subsection="network-interfaces">$iconNetwork Network Interfaces</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="network-info" data-subsection="traffic">$iconChart Traffic Information</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="network-info" data-subsection="open-ports">$iconPort Open Ports</a>
                        </div>
                    </div>
                </div>
"@
}

if ($collectSecurityOnly -or (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectTasksOnly)) {
    $securitySectionCount = 17
    $fullHtml += @"
                <div class="nav-item has-submenu">
                    <a href="#" data-section="security-info">$iconShield Security Information <span class="section-count">$securitySectionCount</span></a>
                    <div class="nav-submenu">
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="user-rights">$iconShield User Rights Assignments</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="smbv1">$iconWarning SMBv1 Status</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="password-policy">$iconKey Password Policy</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="inactive-accounts">$iconUser Inactive Accounts</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="local-admins">$iconUsers Local Administrators</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="tls-settings">$iconLock TLS Settings</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="uac">$iconShield UAC Settings</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="antivirus">$iconAntivirus Antivirus Settings</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="firewall-status">$iconFirewall Firewall Status</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="firewall-settings">$iconGear Firewall Settings</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="ps-policy">$iconGear PowerShell Policy</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="rdp-security">$iconLock RDP Security</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="certificates">$iconCertificate Certificates</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="dns-settings">$iconDns DNS Settings</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="defender-asr">$iconShield Defender ASR</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="shares">$iconFolder SMB Shares</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="security-info" data-subsection="audit-settings">$iconAudit Audit Settings</a>
                        </div>
                    </div>
                </div>
"@
}

if (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectSecurityOnly) {
    $tasksSectionCount = 3
    $fullHtml += @"
                <div class="nav-item has-submenu">
                    <a href="#" data-section="tasks-logs">$iconTask Tasks, Startup, and Logs <span class="section-count">$tasksSectionCount</span></a>
                    <div class="nav-submenu">
                        <div class="nav-submenu-item">
                            <a href="#" data-section="tasks-logs" data-subsection="event-logs">$iconLog Event Logs Size and Retention</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="tasks-logs" data-subsection="startup-programs">$iconStartup Startup Programs</a>
                        </div>
                        <div class="nav-submenu-item">
                            <a href="#" data-section="tasks-logs" data-subsection="scheduled-tasks">$iconTask Scheduled Tasks</a>
                        </div>
                    </div>
                </div>
"@
}

# Close navigation menu and start main content
$fullHtml += @"
            </div>
        </nav>
        
        <main class="main-content">
            <!-- Executive Summary Section -->
            <div id="summary" class="section">
                <div class="summary-card">
                    <h2 style="color: white; margin-bottom: 20px;">$iconChart Windows Server Assessment Summary</h2>
                    <div class="summary-grid">
"@

# Add summary items based on selected sections
if (-not $collectNetworkOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly) {
    $fullHtml += @"
                        <div class="summary-item">
                            <span class="summary-number">13</span>
                            <span class="summary-label">System Sections</span>
                        </div>
"@
}

if ($collectNetworkOnly -or (-not $collectSystemOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly)) {
    $fullHtml += @"
                        <div class="summary-item">
                            <span class="summary-number">3</span>
                            <span class="summary-label">Network Sections</span>
                        </div>
"@
}

if ($collectSecurityOnly -or (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectTasksOnly)) {
    $fullHtml += @"
                        <div class="summary-item">
                            <span class="summary-number">17</span>
                            <span class="summary-label">Security Sections</span>
                        </div>
"@
}

if (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectSecurityOnly) {
    $fullHtml += @"
                        <div class="summary-item">
                            <span class="summary-number">3</span>
                            <span class="summary-label">Scheduled Tasks, Startup, and Logs Sections</span>
                        </div>
"@
}

$fullHtml += @"
                        <div class="summary-item">
                            <span class="summary-number">1</span>
                            <span class="summary-label">HTML Report</span>
                        </div>
                    </div>
                </div>
                
                <div class="section-header">
                    <h2>$iconClipboard Assessment Overview</h2>
                </div>
                <div class="section-content">
                    <p>This comprehensive Windows Server assessment report provides detailed analysis across multiple categories. The report includes both technical configuration details and security posture analysis.</p>
                    <br>
                    <h3>$iconFolder Report Components:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li><strong>Interactive HTML Report:</strong> This comprehensive report with collapsible navigation</li>
                        <li><strong>CSV Data Files:</strong> Individual CSV files for data analysis and integration</li>
                        <li><strong>Assessment Scope:</strong> Covering $assessmentCategories</li>
                    </ul>                    <br>
                    <h3>$iconTarget Key Areas Assessed:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
$assessmentAreas
                    </ul>
                </div>
            </div>
"@

# Add content sections based on selection
if (-not $collectNetworkOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly) {
    $fullHtml += @"
            
            <!-- System Information Section -->
            <div id="system-info" class="section">
                <div class="section-header">
                    <h2>$iconComputer System Information</h2>
                </div>
                <div class="section-content">
                    <div id="os-info" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconServer Operating System Information</h3>
                        </div>
                        <div class="subsection-content">
                            $osInfoHtml
                        </div>
                    </div>
                    
                    <div id="uptime" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconClock System Uptime</h3>
                        </div>
                        <div class="subsection-content">
                            $uptimeHtml
                        </div>
                    </div>
                    
                    <div id="cpu-info" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconCpu CPU Information</h3>
                        </div>
                        <div class="subsection-content">
                            $cpuInfoHtml
                        </div>
                    </div>
                    
                    <div id="cpu-usage" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconChart CPU Usage</h3>
                        </div>
                        <div class="subsection-content">
                            $cpuusageInfoHtml
                        </div>
                    </div>
                    
                    <div id="memory" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconMemory Memory Information</h3>
                        </div>
                        <div class="subsection-content">
                            $RAMHtml
                        </div>
                    </div>
                    
                    <div id="disk" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconDisk Disk Information</h3>
                        </div>
                        <div class="subsection-content">
                            $diskInfoHtml
                        </div>
                    </div>
                    
                    <div id="programs" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconProgram Installed Programs</h3>
                        </div>
                        <div class="subsection-content">
                            $installedprogsHtml
                        </div>
                    </div>
                    
                    <div id="updates" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconCheck Installed Updates</h3>
                        </div>
                        <div class="subsection-content">
                            $updatesHtml
                        </div>
                    </div>
                    
                    <div id="missing-updates" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconWarning Missing Updates</h3>
                        </div>
                        <div class="subsection-content">
                            $missingupdatesHtml
                        </div>
                    </div>
                    
                    <div id="processes" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconProcess Running Processes</h3>
                        </div>
                        <div class="subsection-content">
                            $CurrentProcessesHtml
                        </div>
                    </div>
                    
                    <div id="running-services" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconService Running Services</h3>
                        </div>
                        <div class="subsection-content">
                            $runningHtml
                        </div>
                    </div>
                    
                    <div id="stopped-services" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconCross Stopped Services</h3>
                        </div>
                        <div class="subsection-content">
                            $stoppedHtml
                        </div>
                    </div>
                    
                    <div id="features" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconGear Windows Features</h3>
                        </div>
                        <div class="subsection-content">
                            $FeaturesHtml
                        </div>
                    </div>
                </div>
            </div>
"@
}

if ($collectNetworkOnly -or (-not $collectSystemOnly -and -not $collectSecurityOnly -and -not $collectTasksOnly)) {
    $fullHtml += @"
            
            <!-- Network Information Section -->
            <div id="network-info" class="section">
                <div class="section-header">
                    <h2>$iconNetwork Network Information</h2>
                </div>
                <div class="section-content">
                    <div id="network-interfaces" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconNetwork Network Interfaces</h3>
                        </div>
                        <div class="subsection-content">
                            $nicInfoHtml
                        </div>
                    </div>
                    
                    <div id="traffic" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconChart Traffic Information</h3>
                        </div>
                        <div class="subsection-content">
                            $trafficInfoHtml
                        </div>
                    </div>
                    
                    <div id="open-ports" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconPort Open Ports</h3>
                        </div>
                        <div class="subsection-content">
                            $openportsHtml
                        </div>
                    </div>
                </div>
            </div>
"@
}

if ($collectSecurityOnly -or (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectTasksOnly)) {
    $fullHtml += @"
            
            <!-- Security Information Section -->
            <div id="security-info" class="section">
                <div class="section-header">
                    <h2>$iconShield Security Information</h2>
                </div>
                <div class="section-content">
                    <div id="user-rights" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconShield User Rights Assignments</h3>
                        </div>
                        <div class="subsection-content">
                            $userRightsAssignmentsHtml
                        </div>
                    </div>
                    <div id="smbv1" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconWarning SMBv1 Status</h3>
                        </div>
                        <div class="subsection-content">
                            $SMBv1Html
                        </div>
                    </div>
                    
                    <div id="password-policy" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconKey Password Policy</h3>
                        </div>
                        <div class="subsection-content">
                            $passwordPolicyHtml
                        </div>
                    </div>
                    
                    <div id="inactive-accounts" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconUser Inactive Accounts</h3>
                        </div>
                        <div class="subsection-content">
                            $inactiveAccountsHtml
                        </div>
                    </div>
                    
                    <div id="local-admins" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconUsers Local Administrators</h3>
                        </div>
                        <div class="subsection-content">
                            $localAdminsHtml
                        </div>
                    </div>
                    
                    <div id="tls-settings" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconLock TLS Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $TLSregSettingsHtml
                        </div>
                    </div>
                    
                    <div id="uac" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconShield UAC Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $uacHtml
                        </div>
                    </div>
                    
                    <div id="antivirus" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconAntivirus Antivirus Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $AVsettingsHtml
                        </div>
                    </div>
                    
                    <div id="firewall-status" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconFirewall Firewall Status</h3>
                        </div>
                        <div class="subsection-content">
                            $FWstatusHtml
                        </div>
                    </div>
                    
                    <div id="firewall-settings" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconGear Firewall Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $FWSettingsHtml
                        </div>
                    </div>
                    
                    <div id="ps-policy" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconGear PowerShell Execution Policy</h3>
                        </div>
                        <div class="subsection-content">
                            $psExecPolicyHtml
                        </div>
                    </div>
                    
                    <div id="rdp-security" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconLock RDP Security</h3>
                        </div>
                        <div class="subsection-content">
                            $rdpSecurityHtml
                        </div>
                    </div>
                    
                    <div id="certificates" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconCertificate Certificates</h3>
                        </div>
                        <div class="subsection-content">
                            $certificatesHtml
                        </div>
                    </div>
                    
                    <div id="dns-settings" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconDns DNS Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $dnsSettingsHtml
                        </div>
                    </div>
                    
                    <div id="defender-asr" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconShield Defender ASR Rules</h3>
                        </div>
                        <div class="subsection-content">
                            $defenderASRHtml
                        </div>
                    </div>
                    
                    <div id="shares" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconFolder SMB Shares</h3>
                        </div>
                        <div class="subsection-content">
                            $sharesHtml
                        </div>
                    </div>
                    
                    <div id="audit-settings" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconAudit Audit Settings</h3>
                        </div>
                        <div class="subsection-content">
                            $auditSettingsHtml
                        </div>
                    </div>
                </div>
            </div>
"@
}

if (-not $collectSystemOnly -and -not $collectNetworkOnly -and -not $collectSecurityOnly) {
    $fullHtml += @"
            
            <!-- Tasks, Startup & Logs Section -->
            <div id="tasks-logs" class="section">
                <div class="section-header">
                    <h2>$iconTask Scheduled Tasks, Startup, and Logs Retention</h2>
                </div>
                <div class="section-content">
                    <div id="event-logs" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconLog Event Logs Size and Retention</h3>
                        </div>
                        <div class="subsection-content">
                            $eventlogHtml
                        </div>
                    </div>
                    
                    <div id="startup-programs" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconStartup Startup Programs</h3>
                        </div>
                        <div class="subsection-content">
                            $startupprogsHtml
                        </div>
                    </div>
                    
                    <div id="scheduled-tasks" class="subsection">
                        <div class="subsection-header">
                            <h3>$iconTask Scheduled Tasks</h3>
                        </div>
                        <div class="subsection-content">
                            $ScheduledTasksHtml
                        </div>
                    </div>
                </div>
            </div>
"@
}

# Close main content
$fullHtml += @"
        </main>
    </div>
    
</body>
</html>
"@


# === Save the HTML report ===
$fullHtml | Out-File -FilePath $htmlFile -Encoding UTF8

# ----------------------------
# COMPLETION SUMMARY
# ----------------------------

Write-Host "`n=== SCRIPT EXECUTION COMPLETED ===" -ForegroundColor Green
Write-Host "Report generation finished successfully!" -ForegroundColor Cyan

$modeDescription = if ($collectSystemOnly) { 
    "System Information Only" 
} elseif ($collectNetworkOnly) { 
    "Network Checks Only" 
} elseif ($collectSecurityOnly) { 
    "Security Checks Only" 
} elseif ($collectTasksOnly) { 
    "Tasks & Logs Only" 
} else { 
    "Complete Health Check (All Sections)" 
}

Write-Host "`nExecution Summary:" -ForegroundColor Yellow
Write-Host "- Mode Selected: $modeDescription" -ForegroundColor White
Write-Host "- Server Name: $ServerName" -ForegroundColor White
Write-Host "- Output Directory: $path" -ForegroundColor White
Write-Host "- Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

Write-Host "`nGenerated Files:" -ForegroundColor Yellow
Write-Host "- HTML Report: $htmlFile" -ForegroundColor Green

# List CSV files based on mode
if ($collectSystemOnly -or $menuChoice -eq "5") {
    Write-Host "- System CSV Files:" -ForegroundColor Cyan
    Write-Host "  * OS Information: $csvosinfo" -ForegroundColor Gray
    Write-Host "  * CPU Information: $csvcpuinfo" -ForegroundColor Gray
    Write-Host "  * CPU Usage: $csvcpuusageinfo" -ForegroundColor Gray
    Write-Host "  * Memory Information: $csvraminfo" -ForegroundColor Gray
    Write-Host "  * Disk Information: $csvdiskinfo" -ForegroundColor Gray
    Write-Host "  * System Uptime: $csvuptimeinfo" -ForegroundColor Gray
    Write-Host "  * Windows Features: $csvWinFeatures" -ForegroundColor Gray
    Write-Host "  * Running Services: $csvRunning" -ForegroundColor Gray
    Write-Host "  * Stopped Services: $csvStopped" -ForegroundColor Gray
    Write-Host "  * Installed Programs: $csvinstalledprogsinfo" -ForegroundColor Gray
    Write-Host "  * Running Processes: $csvallProcesses" -ForegroundColor Gray
    Write-Host "  * Installed Updates: $csvupdatesinstalledinfo" -ForegroundColor Gray
    Write-Host "  * Missing Updates: $csvmissingupdatesinfo" -ForegroundColor Gray
}

if ($collectNetworkOnly -or $menuChoice -eq "5") {
    Write-Host "- Network CSV Files:" -ForegroundColor Cyan
    Write-Host "  * Network Interfaces: $csvnicinfo" -ForegroundColor Gray
    Write-Host "  * Traffic Information: $csvtrafficinfo" -ForegroundColor Gray
    Write-Host "  * Open Ports: $csvopenportsinfo" -ForegroundColor Gray
}

if ($collectSecurityOnly -or $menuChoice -eq "5") {
    Write-Host "- Security CSV Files:" -ForegroundColor Cyan
    Write-Host "  * Antivirus Settings: $csvAVsettingsinfo" -ForegroundColor Gray
    Write-Host "  * Firewall Status: $csvFWstatusinfo" -ForegroundColor Gray
    Write-Host "  * Firewall Settings: $csvFWSettingsinfo" -ForegroundColor Gray
    Write-Host "  * SMBv1 Status: $csvSMBv1" -ForegroundColor Gray
    Write-Host "  * Inactive Accounts: $csvinactiveaccountsinfo" -ForegroundColor Gray
    Write-Host "  * Local Administrators: $csvlocalAdmins" -ForegroundColor Gray
    Write-Host "  * Password Policy: $(Join-Path -Path $path -ChildPath "$ServerName-PasswordPolicyInfo.csv")" -ForegroundColor Gray
    Write-Host "  * SMB Shares: $csvShares" -ForegroundColor Gray
    Write-Host "  * Audit Settings: $csvauditSettings" -ForegroundColor Gray
    Write-Host "  * TLS Registry Settings: $csvTLSregSettings" -ForegroundColor Gray
    Write-Host "  * UAC Settings: $csvUACSettings" -ForegroundColor Gray
    Write-Host "  * PowerShell Execution Policy: $csvPSExecPolicy" -ForegroundColor Gray
    Write-Host "  * RDP Security: $csvRDPSecurity" -ForegroundColor Gray
    Write-Host "  * Certificates: $csvCertificates" -ForegroundColor Gray
    Write-Host "  * DNS Settings: $csvDNSSettings" -ForegroundColor Gray
    Write-Host "  * Defender ASR Rules: $csvDefenderASR" -ForegroundColor Gray
}

if ($collectTasksOnly -or $menuChoice -eq "5") {
    Write-Host "- Tasks & Logs CSV Files:" -ForegroundColor Cyan
    Write-Host "  * Startup Programs: $csvstartupprogsinfo" -ForegroundColor Gray
    Write-Host "  * Scheduled Tasks: $csvScheduledTasksinfo" -ForegroundColor Gray
    Write-Host "  * Event Viewer Logs: $csveventlog" -ForegroundColor Gray
    Write-Host "  * System Logs: $csvSystemlogs" -ForegroundColor Gray
    Write-Host "  * Application Logs: $csvApplicationlogs" -ForegroundColor Gray
    Write-Host "  * Security Logs: $csvSecuritylogs" -ForegroundColor Gray
}

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Review the HTML report: $htmlFile" -ForegroundColor White
Write-Host "2. Analyze individual CSV files for detailed data" -ForegroundColor White
Write-Host "3. Store reports securely and follow data retention policies" -ForegroundColor White
Write-Host "4. Schedule regular health checks for ongoing monitoring" -ForegroundColor White

Write-Host "`nThank you for using the Windows Server Health Check Script!" -ForegroundColor Green
Write-Host "Script created by Abdullah Zmaili - Version 1.0" -ForegroundColor Gray

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+9OAPvrWtKJi3TTOPqtdVxFj
# W3WgggMcMIIDGDCCAgCgAwIBAgIQHKHkSZVplbZEXmQNGpo5KjANBgkqhkiG9w0B
# AQsFADAkMSIwIAYDVQQDDBlBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nMB4XDTI1
# MDcxODA3Mzg1OVoXDTI2MDcxODA3NTg1OVowJDEiMCAGA1UEAwwZQWJkdWxsYWha
# bWFpbGlDb2RlU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AOONtHMcr1nlykF8FfhMzPISJZIonzgugEU2vajQIUnD5xfyamiBRlfNH30wZjcU
# Hz0HWLhvH2P7xS6J++2jHr+F05z4YS77nbkBF9pyn31pLKJeO5Avg7+Jzbcaw7ox
# Z/hL3iM2AY67TrF/iNPJ/tf75YukWyBR7BN6+uKft0C3EW+bl9mZRYDFOy7bNpbi
# 8l7Vt70n7Rsmo7zWnjxEO4NIzkexQk+69mVXt+Z2IfFuqDcphY0ZSbMpfPsOaEZu
# 3gzqw/y5YnWkvEBuPRCFx6MsjcYlx+xu0D+l2cIkuZ2qtytaDCzBjF4YXrnGpjlV
# d4XwNIYALwOFOMhpvJnP/9kCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTGfLNnWQCNSGf/f/Z1/FQboXykijAN
# BgkqhkiG9w0BAQsFAAOCAQEAIMgd4oUMnvkRaqN3cpEgDI1hCzQ8PnoJqQBk2GfE
# 1AzSAvDwyAPn3YkypRKzCQxmW8Yf7uxL0eCSA6j3ROavclIk5GWT1grFPbk6EnOX
# lVyripBDV6+6KyqRSupgGxRCQOgp0vkac0IQV06ncpB2+HuTDMLbskhWWOdCJ7AW
# Hamp472+fFmOzK4eSqHV6ccfpKxx3f8VG/2FxQX+cKYAioPg+QSEwC3ORAgN5f1P
# InCDxxhJGb9GcR1nBCAPUmfSgpl1nIazvoQeal/Ncgs8K10oMEGxVJgyB+YKediL
# KSAnTjY3SwwQaSK/cQ/64QYz0JvFmaLKQ1xf8NuLueTqKDGCAdkwggHVAgEBMDgw
# JDEiMCAGA1UEAwwZQWJkdWxsYWhabWFpbGlDb2RlU2lnbmluZwIQHKHkSZVplbZE
# XmQNGpo5KjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUjqAzJ3+o97BmABdXz3XRBIIpcaYwDQYJ
# KoZIhvcNAQEBBQAEggEA1F/9W87MWcem194CNaIryNlFr9MWWQuHynMWNMTvH4jP
# 1OKxS8wH7SGOyMx2SHCjBm8XegKSQgv74yAulOOtRBk118eHDW9E69+fZbOauzPw
# CdP7E94B+OTF2LBVCK6RC2QM+ulAye/a0N6JbQApOM5+jdaPP3XYIQYyPcSwvqR7
# tnA1u8GtE7kf9NmcraAzhFz2yqonvgTFehsusIv69w6xFjtQUisyNO6mhV5jvgSu
# CU0SxxCNaZC0gyyGn96EMbs/x5/Tr9G5bT22orI3h+hgE9hPwmnOmmhkR4R3RD/Y
# a900hqRVzuw/dnhSNxJhnoFZjJl0FCaBdYM6VA2pig==
# SIG # End signature block
