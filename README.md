# Windows Server Assessment Tool

## Overview
The **WindowsServerAssessmentTool_V1.0.ps1** script is a comprehensive PowerShell tool designed to perform detailed assessments on Windows Server systems. It features a modern, collapsible HTML interface with interactive navigation and provides a menu-driven selection system that allows users to selectively collect different types of system information. The tool generates professional HTML reports with corresponding CSV data exports for in-depth analysis.

## Key Features
- **Modern Interactive HTML Reports**: Collapsible left navigation menu with icons and smooth animations
- **Menu-Driven Assessment Modes**: Five targeted assessment options for focused data collection
- **Professional UI/UX**: Responsive design with color-coded sections and hover effects
- **Comprehensive CSV Exports**: Detailed data files for external analysis and reporting
- **Modular Architecture**: Efficient function-based design for optimal performance

## Version Information
- **File Name:** WindowsServerAssessmentTool_V1.0.ps1
- **Author:** Abdullah Zmaili
- **Version:** 1.0
- **Date Created:** June 16, 2025
- **Prerequisites:** PowerShell 5.1 or later, Administrator privileges for comprehensive assessments

## Features

### Interactive HTML Report Features
The generated HTML reports include:

1. **Modern Collapsible Navigation**
   - Left-aligned navigation menu with icon indicators
   - Expandable/collapsible sections for organized content
   - Smooth animations and professional styling
   - Section counters showing number of assessment areas

2. **Professional User Interface**
   - Responsive design optimized for desktop and tablet viewing
   - Color-coded sections with gradient backgrounds
   - Hover effects and smooth transitions
   - Executive summary dashboard with key metrics

3. **Interactive Content Organization**
   - Clickable navigation for instant section access
   - Subsection organization for detailed information
   - Search-friendly content structure
   - Print-optimized styling

### Menu-Driven Selection
The script offers five distinct assessment modes:

1. **SYSTEM INFORMATION ONLY**
   - OS Details, CPU, Memory, Disk Information
   - Windows Features, Services, Programs
   - Updates and Processes

2. **NETWORK ASSESSMENT ONLY**
   - Network Interface Configuration
   - Traffic Statistics and Performance
   - Open Ports and Connections

3. **SECURITY ASSESSMENT ONLY**
   - Antivirus and Firewall Settings
   - User Accounts and Password Policies
   - Security Configurations and Certificates

4. **SCHEDULED TASKS & STARTUP & LOGS ONLY**
   - Startup Programs and Services
   - Scheduled Tasks Configuration
   - System, Application & Security Event Logs

5. **ALL SECTIONS (Complete Server Assessment)**
   - Comprehensive collection of all above sections

### Output Files Generated

#### HTML Reports
- **Main Report:** `[ServerName]-SystemReport.html` - Comprehensive HTML assessment report based on selected mode
- **GPO Settings:** `[ServerName]-GPOSettings.html` - Group Policy Objects details (when applicable)

#### CSV Data Files
The script generates targeted CSV files based on the selected assessment mode:

**System Information Assessment Mode:**
- `[ServerName]-OSInfo.csv`
- `[ServerName]-CPUInfo.csv`
- `[ServerName]-CPUUsage.csv`
- `[ServerName]-RAMInfo.csv`
- `[ServerName]-DiskInfo.csv`
- `[ServerName]-UpTime.csv`
- `[ServerName]-WinFeatures.csv`
- `[ServerName]-RunningServices.csv`
- `[ServerName]-StoppedServices.csv`
- `[ServerName]-InstalledProgs.csv`
- `[ServerName]-allProcesses.csv`
- `[ServerName]-UpdatesInstalledInfo.csv`
- `[ServerName]-MissingUpdates.csv`

**Network Assessment Mode:**
- `[ServerName]-NICInfo.csv`
- `[ServerName]-TrafficInfo.csv`
- `[ServerName]-OpenPorts.csv`

**Security Assessment Mode:**
- `[ServerName]-AVSettings.csv`
- `[ServerName]-FirewallStatus.csv`
- `[ServerName]-FirewallSettings.csv`
- `[ServerName]-SMBv1.csv`
- `[ServerName]-InactiveAccountsInfo.csv`
- `[ServerName]-LocalAdmins.csv`
- `[ServerName]-PasswordPolicyInfo.csv`
- `[ServerName]-SMBShares.csv`
- `[ServerName]-auditSettings.csv`
- `[ServerName]-TLSregSettings.csv`
- `[ServerName]-UACSettings.csv`
- `[ServerName]-PSExecPolicy.csv`
- `[ServerName]-RDPSecurity.csv`
- `[ServerName]-Certificates.csv`
- `[ServerName]-DNSSettings.csv`
- `[ServerName]-DefenderASR.csv`
- `[ServerName]-DefenderExploit.csv`

**Tasks & Logs Assessment Mode:**
- `[ServerName]-StartupProgs.csv`
- `[ServerName]-ScheduledTasks.csv`
- `[ServerName]-EventViewerLogs.csv`
- `[ServerName]-Systemlogs.csv`
- `[ServerName]-Applicationlogs.csv`
- `[ServerName]-Securitylogs.csv`

## Usage Instructions

### Prerequisites
1. **PowerShell Version:** Ensure PowerShell 5.1 or later is installed
2. **Administrator Rights:** Run PowerShell as Administrator for comprehensive data collection
3. **Execution Policy:** Set execution policy to allow script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Running the Script

1. **Launch PowerShell as Administrator**
   - Right-click on PowerShell and select "Run as Administrator"

2. **Navigate to Script Location**
   ```powershell
   cd "C:\temp\WindowsServerAssessmentTool"
   ```

3. **Execute the Script**
   ```powershell
   .\WindowsServerAssessmentTool_V1.0.ps1
   ```

4. **Specify Output Directory**
   - When prompted, enter the full path where you want to save the assessment reports (e.g., `C:\temp`)
   - The script will create the directory if it doesn't exist

5. **Select Assessment Mode**
   - Choose from the 5 available options:
     - Enter `1` for System Information Assessment Only
     - Enter `2` for Network Assessment Only
     - Enter `3` for Security Assessment Only     - Enter `4` for Tasks & Logs Assessment Only
     - Enter `5` for Complete Server Assessment

6. **Wait for Completion**
   - The script will display progress messages as it collects information
   - Assessment time varies based on selected mode and system complexity

### Understanding the Output

#### HTML Assessment Report Structure
The HTML assessment report includes:
- **Executive Summary Dashboard:** Key metrics overview with visual indicators
- **Interactive Navigation Menu:** Collapsible left sidebar with icons and section counters
- **Modern Styling:** Professional gradient backgrounds, hover effects, and responsive design
- **Section-Based Organization:** Content organized by assessment areas with expandable subsections
- **Comprehensive Data Presentation:** Detailed information in professionally styled tables
- **Header Information:** Server name, generation timestamp, logged user, assessment scope
- **Print-Friendly Layout:** Optimized for both screen viewing and printing

#### CSV Files
- Each CSV file contains raw data for specific system components
- Files can be imported into Excel or other tools for further analysis
- Only relevant CSV files are generated based on the selected assessment mode

## Script Architecture

### Modern HTML Interface
The script generates HTML reports with:
- **Collapsible Navigation Menu:** Modern left-aligned sidebar with smooth animations
- **Interactive Elements:** Clickable sections with hover effects and transitions
- **Professional Styling:** Gradient backgrounds, icon integration, and responsive design
- **JavaScript Functionality:** Dynamic content switching and navigation management
- **CSS3 Features:** Modern styling with animations, gradients, and responsive layouts

### Modular Design
The script is built with a modular architecture featuring:
- **Separate Functions:** Individual functions for each assessment area
- **Conditional Logic:** Smart data collection based on user selection
- **Error Handling:** Graceful handling of assessment failures
- **Progress Reporting:** Real-time feedback during execution

### Key Functions
1. **Get-SystemInformation:** Collects comprehensive system details
2. **Get-NetworkInformation:** Gathers network configuration and statistics
3. **Get-SecurityInformation:** Retrieves security settings and configurations
4. **Get-TasksStartupLogsInformation:** Collects startup programs, tasks, and logs

### Performance Considerations
- **Selective Assessment:** Only gathers data for selected sections
- **Optimized Queries:** Efficient WMI and PowerShell cmdlet usage
- **Memory Management:** Proper variable cleanup and resource management
- **Background Process Handling:** Smart handling of long-running operations

## Troubleshooting

### HTML Report Navigation Issues
1. **Navigation Menu Not Responding**
   - **Solution:** Ensure JavaScript is enabled in your browser
   - **Alternative:** Use a modern browser (Chrome, Firefox, Edge)

2. **Sections Not Expanding/Collapsing**
   - **Cause:** JavaScript execution blocked or browser compatibility
   - **Solution:** Check browser console for errors, use updated browser

3. **Layout Corruption in Specific Sections**
   - **Symptoms:** Content overlapping or misaligned
   - **Solution:** Refresh the page, ensure browser zoom is at 100%

4. **Print Layout Issues**
   - **Cause:** Print-specific CSS not loading properly
   - **Solution:** Use browser's print preview and adjust print settings

### Performance Tips
- Use specific assessment modes for faster execution
- Ensure sufficient disk space in the output directory
- Close unnecessary applications to free up system resources
- Run during off-peak hours for comprehensive assessments

### Common Script Issues

1. **Permission Denied Errors**
   - **Solution:** Run PowerShell as Administrator
   - **Alternative:** Check file/folder permissions on output directory

2. **Execution Policy Restrictions**
   - **Error:** "cannot be loaded because running scripts is disabled"
   - **Solution:** `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

3. **WMI Access Issues**
   - **Symptoms:** Missing system information or errors during assessment
   - **Solution:** Ensure WMI service is running: `Get-Service Winmgmt`

4. **Network Information Missing**
   - **Cause:** Insufficient privileges or network adapter issues
   - **Solution:** Verify network adapters are properly configured and accessible

5. **Long Execution Times**
   - **Expected Behavior:** Complete server assessments can take several minutes
   - **Optimization:** Use specific assessment modes (1-4) instead of "ALL SECTIONS" for faster execution

## Security Considerations

### Data Sensitivity
The script collects various types of sensitive information:
- **System Configuration:** Hardware and software details
- **Security Settings:** Firewall rules, antivirus status, user accounts
- **Network Information:** IP configurations, open ports, traffic statistics
- **Event Logs:** System events, security events, application logs

### Best Practices
1. **Secure Storage:** Store assessment output files in secure locations
2. **Access Control:** Limit access to generated assessment reports
3. **Data Retention:** Implement appropriate data retention policies
4. **Regular Cleanup:** Remove old assessment reports that are no longer needed
5. **Network Security:** Be cautious when transmitting reports over networks

### Customization Options

### Modifying Assessment Scope
To customize what information is assessed:
1. Edit the respective `Get-*Information` functions
2. Add or remove specific data collection commands
3. Modify the CSV export sections as needed

### Changing Output Formats
- **HTML Styling:** Modify the CSS section in the HTML generation area
- **CSV Structure:** Adjust the `Select-Object` statements in collection functions
- **Additional Formats:** Add JSON or XML export options if needed

### Adding New Assessments
1. Create new collection logic within existing functions
2. Add corresponding CSV export paths
3. Update HTML generation sections
4. Test thoroughly with different system configurations

## Maintenance and Updates

### Regular Maintenance
- **Monthly Review:** Check for new Windows updates that might affect assessment
- **Quarterly Updates:** Review and update collection queries for new system features
- **Annual Overhaul:** Consider adding new sections based on evolving security requirements

### Version History
- **V1.0 (June 2025):** Initial release with menu-driven selective assessment

### Future Enhancements
Potential improvements for future versions:
- **Remote Assessment:** Support for remote server assessments
- **Scheduled Execution:** Built-in task scheduler integration  
- **Email Reports:** Automatic email delivery of assessment reports
- **Comparative Analysis:** Historical trending and comparison features
- **Custom Thresholds:** Configurable alert thresholds for various metrics

## Support and Contact

For questions, issues, or enhancement requests:
- **Author:** Abdullah Zmaili
- **Created:** June 16, 2025
- **Version:** WindowsServerAssessmentTool_V1.0

---
*This documentation covers the comprehensive Windows Server Assessment Tool designed for system administrators and IT professionals.*
