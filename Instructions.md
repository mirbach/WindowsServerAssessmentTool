# Windows Server Assessment Tool - Instructions

## Overview
**Script Name**: WindowsServerAssessmentTool_V1.0.ps1  
**Author**: Abdullah Zmaili  
**Version**: 1.0  
**Date**: June 16, 2025  
**Purpose**: Generates comprehensive Windows Server assessment reports in both HTML and CSV formats using a modular, function-based architecture with menu-driven selective data collection.

**Current Status**: This script includes modular functions for system information, network analysis, security assessments, and task/log collection. The tool provides five distinct assessment modes for targeted data collection based on user requirements.

## Script Architecture

### Modular Design
The script has been refactored with a modular approach using dedicated functions for each major assessment area:

1. **Get-SystemInformation Function**
   - Collects OS details, CPU, memory, disk, Windows features
   - Handles services, installed programs, and updates
   - Exports system-related CSV files

2. **Get-NetworkInformation Function**
   - Gathers network interface details and configuration
   - Collects real-time traffic statistics
   - Analyzes open TCP ports and connections

3. **Get-SecurityInformation Function**
   - Comprehensive security assessment including antivirus, firewall
   - User accounts, password policies, and audit settings
   - Certificate management and DNS security
   - Windows Defender and exploit protection settings

4. **Get-TasksStartupLogsInformation Function**
   - Startup programs and scheduled tasks
   - Event log analysis (System, Application, Security)
   - Recent error and warning collection

### Menu-Driven Assessment Modes
The script offers five distinct assessment modes:
- **System Information Only**: Hardware, software, and system configuration
- **Network Assessment Only**: Network interfaces, traffic, and connectivity
- **Security Assessment Only**: Security settings, policies, and configurations
- **Tasks & Logs Assessment Only**: Startup programs, tasks, and event logs
- **Complete Server Assessment**: All sections combined

## Prerequisites

### System Requirements
- **Operating System**: Windows Server 2012 R2 or later
- **PowerShell Version**: PowerShell 5.1 or later
- **Administrator Privileges**: Required for comprehensive security and system assessments
- **Network Access**: Required for Windows Update checks
- **Disk Space**: Minimum 100 MB free space for assessment report generation

### PowerShell Modules
The script uses built-in Windows PowerShell cmdlets and does not require additional module installations.

## What the Assessment Tool Does

### System Information Collected
1. **Operating System Details**
   - OS version, build, architecture
   - System uptime and last boot time
   - Domain/workgroup membership

2. **Hardware Information**
   - CPU details and current usage
   - Memory (RAM) information and utilization
   - Disk drives, free space, and health status
   - Network adapter configurations

3. **Security Analysis**
   - User Account Control (UAC) settings
   - PowerShell execution policy (all scopes)
   - BitLocker encryption status
   - RDP Network Level Authentication status
   - Certificate expiry analysis (LocalMachine\My store)
   - DNS client settings and security features
   - Windows Defender settings and policies
   - Attack Surface Reduction (ASR) rules
   - Exploit Guard settings
   - TLS/SSL registry settings
   - SMBv1 protocol status
   - Audit policy settings

4. **System Status**
   - Windows services (running/stopped)
   - Windows features and roles
   - Installed programs and applications
   - Startup programs
   - Scheduled tasks
   - Network shares and permissions
   - Open network ports and listening services
   - Running processes

5. **Updates and Patches**
   - Recently installed updates
   - Missing critical updates
   - Last update installation date

6. **Event Logs**
   - Recent system errors and warnings
   - Security events
   - Application errors

7. **User Account Management**
   - Local administrators
   - Inactive user accounts
   - Password policy settings

8. **Firewall Configuration**
   - Windows Firewall status
   - Firewall rules and settings

## How to Run the Script

### Step 1: Prepare the Environment
1. **Open PowerShell as Administrator**
   - Right-click on PowerShell
   - Select "Run as Administrator"

2. **Set Execution Policy (if needed)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Step 2: Navigate to Script Location
```powershell
cd "c:\temp\Server Check"
```

### Step 3: Run the Script
```powershell
.\SystemHealthCheckforWindowsServer_V1.0.ps1
```

### Step 4: Specify Output Directory
- The script will prompt you to enter a directory path
- Example: `C:\temp` or `C:\Reports`
- The script will create the directory if it doesn't exist

## Quick Reference

### Common Commands
```powershell
# Check execution policy
Get-ExecutionPolicy

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Navigate to script directory
cd "c:\temp\Server Check"

# Run the script
.\SystemHealthCheckforWindowsServer_V1.0.ps1

# Check for script errors (run in PowerShell ISE or VS Code)
powershell -File ".\SystemHealthCheckforWindowsServer_V1.0.ps1"
```

### Expected Runtime Indicators
- **Quick start**: Script initialization and directory creation (< 30 seconds)
- **System Information**: OS, CPU, memory, disk collection (1-3 minutes)
- **Security Analysis**: Antivirus, firewall, certificates, policies (2-5 minutes)
- **Network Analysis**: Interfaces, traffic, ports (1-2 minutes)
- **Tasks & Logs**: Startup programs, scheduled tasks, event logs (2-5 minutes)
- **Report Generation**: HTML creation and ZIP archive (< 1 minute)

## Output Files Generated

### HTML Report
- **Filename**: `[ServerName]-SystemReport.html`
- **Description**: Comprehensive HTML report with all collected information
- **Usage**: Open in web browser for easy viewing and printing

### CSV Files (Individual Data Sets)
1. `[ServerName]-OSInfo.csv` - Operating system details
2. `[ServerName]-CPUInfo.csv` - Processor information
3. `[ServerName]-CPUUsage.csv` - Current CPU utilization
4. `[ServerName]-RAMInfo.csv` - Memory information
5. `[ServerName]-DiskInfo.csv` - Disk drive details
6. `[ServerName]-NICInfo.csv` - Network adapter information
7. `[ServerName]-TrafficInfo.csv` - Network traffic statistics
8. `[ServerName]-RunningServices.csv` - Currently running services
9. `[ServerName]-StoppedServices.csv` - Stopped services
10. `[ServerName]-WinFeatures.csv` - Windows features and roles
11. `[ServerName]-StartupProgs.csv` - Startup programs
12. `[ServerName]-ScheduledTasks.csv` - Scheduled tasks
13. `[ServerName]-InstalledProgs.csv` - Installed programs
14. `[ServerName]-SMBShares.csv` - Network shares
15. `[ServerName]-OpenPorts.csv` - Open network ports
16. `[ServerName]-AllProcesses.csv` - Running processes
17. `[ServerName]-LocalAdmins.csv` - Local administrator accounts
18. `[ServerName]-InactiveAccountsInfo.csv` - Inactive user accounts
19. `[ServerName]-PasswordPolicyInfo.csv` - Password policy settings
20. `[ServerName]-UpdatesInstalledInfo.csv` - Recently installed updates
21. `[ServerName]-MissingUpdates.csv` - Missing updates
22. `[ServerName]-LastUpdateInstalled.csv` - Last update information
23. `[ServerName]-EventViewerLogs.csv` - Recent event log entries
24. `[ServerName]-FirewallStatus.csv` - Firewall status
25. `[ServerName]-FirewallSettings.csv` - Firewall rules
26. `[ServerName]-AVSettings.csv` - Antivirus settings
27. `[ServerName]-SMBv1.csv` - SMBv1 protocol status
28. `[ServerName]-AuditSettings.csv` - Audit policy settings
29. `[ServerName]-TLSregSettings.csv` - TLS/SSL registry settings
30. `[ServerName]-UACSettings.csv` - User Account Control settings
31. `[ServerName]-PSExecPolicy.csv` - PowerShell execution policy
32. `[ServerName]-RDPSecurity.csv` - RDP security settings
33. `[ServerName]-Certificates.csv` - Certificate expiry analysis
34. `[ServerName]-DNSSettings.csv` - DNS client settings
35. `[ServerName]-DefenderASR.csv` - Windows Defender ASR rules
36. `[ServerName]-DefenderExploit.csv` - Exploit Guard settings

### Additional Files
- `[ServerName]-GPOSettings.html` - Group Policy settings (if applicable)
- `[ServerName]-YYYYMMDD-HHMMSS.zip` - Compressed archive containing all reports (timestamped)

## Important Notes and Limitations

### Known Issues
1. **ZIP Archive Creation**: The script may fail to create the ZIP archive if any CSV files are missing due to failed data collection sections. This is typically caused by:
   - Insufficient permissions
   - Service availability issues
   - Network connectivity problems
   - Missing Windows features or roles

2. **Domain Controller Limitations**: Running on domain controllers may not provide all information due to security restrictions and different system configurations.

3. **PowerShell Module Dependencies**: Some advanced security checks require specific Windows versions or features to be enabled.

### Best Practices
- Always run the script as Administrator for complete data collection
- Ensure Windows Update service is running for update checks
- Run during maintenance windows to avoid performance impact
- Review the PowerShell console output for any errors or warnings
- Check that all expected CSV files are created before relying on the ZIP archive

## Script Execution Time
- **Typical Runtime**: 5-15 minutes depending on system size and complexity
- **Factors Affecting Runtime**:
  - Number of installed programs
  - Event log size
  - Windows Update check performance
  - Certificate store size

## Troubleshooting

### Common Issues and Solutions

#### 1. Execution Policy Error
**Error**: "Execution of scripts is disabled on this system"
**Solution**: 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 2. Access Denied Errors
**Issue**: Some checks require administrator privileges
**Solution**: Run PowerShell as Administrator

#### 3. Windows Update Check Failures
**Issue**: Update checks may fail if Windows Update service is disabled
**Solution**: Ensure Windows Update service is running or accept limited update information

#### 4. Certificate Store Access Issues
**Issue**: Certificate analysis may fail due to permissions
**Solution**: Run as Administrator or accept limited certificate information

#### 5. Long Execution Time
**Issue**: Script takes too long to complete
**Solutions**:
- Ensure good network connectivity for update checks
- Run during off-peak hours
- Consider running on a server with better performance

#### 6. ZIP Archive Creation Failures
**Issue**: "The path 'X' either does not exist or is not a valid file system path"
**Cause**: Some CSV files may not be created if certain data collection sections fail
**Solutions**:
- Check that all sections completed successfully
- Ensure adequate permissions for file creation
- Verify output directory is writable
- Run script as Administrator
- Review PowerShell error messages for specific failures

### Performance Optimization
- Close unnecessary applications before running
- Ensure adequate free disk space (minimum 100 MB)
- Run from local storage rather than network drives
- Use SSD storage for better performance

## Security Considerations

### Data Sensitivity
The reports contain sensitive system information including:
- System configuration details
- Network configuration
- Security settings
- User account information
- Installed software inventory

### Recommendations
1. **Secure Storage**: Store reports in secure locations with appropriate access controls
2. **Data Retention**: Implement appropriate data retention policies
3. **Access Control**: Limit access to reports to authorized personnel only
4. **Regular Cleanup**: Remove old reports that are no longer needed

## Use Cases

### Regular Health Checks
- Monthly system assessments
- Pre-maintenance health verification
- Security compliance audits

### Troubleshooting
- System performance issues
- Security incident investigation
- Configuration drift detection

### Documentation
- System inventory management
- Compliance reporting
- Change management baseline

## Support and Modifications

### Customization
The script can be modified to:
- Add additional checks
- Modify output formats
- Change report layouts
- Add custom branding

### Support
For issues or questions:
1. Check the troubleshooting section
2. Review PowerShell error messages
3. Ensure all prerequisites are met
4. Contact the script author: Abdullah Al Zmaili

## Version History
- **v1.0** (June 16, 2025): Initial release with comprehensive system health checks and modular function-based architecture
  - Includes Get-SystemInformation, Get-NetworkInformation, Get-SecurityInformation, and Get-TasksStartupLogsInformation functions
  - Comprehensive security analysis including TLS, UAC, PowerShell policies, RDP, certificates, DNS, and Windows Defender
  - Generates timestamped ZIP archives with all report files
  - Known issue: ZIP creation may fail if CSV files are missing due to data collection failures

---
**Note**: This script is designed for Windows Server environments. Running on domain controllers may not provide all information due to security restrictions and different system configurations.
