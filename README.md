# Windows Server Assessment Tool

## Overview
The **WindowsServerAssessmentTool_V1.0.ps1** script is a comprehensive PowerShell tool designed to perform detailed assessments on Windows Server systems. It features a modern, collapsible HTML interface with interactive navigation and provides a menu-driven selection system that allows users to selectively collect different types of system information. The tool generates professional HTML reports with corresponding CSV data exports for in-depth analysis.

## Key Features
- **Modern Interactive HTML Reports**: Collapsible left navigation menu with icons and smooth animations
- **Menu-Driven Assessment Modes**: Five targeted assessment options for focused data collection  
- **Professional UI/UX**: Responsive design with color-coded sections and hover effects
- **User-Friendly Data Presentation**: PSCustomObject implementation with descriptive column names
- **Responsive Tables**: Auto-sizing tables with horizontal scrolling for wide data
- **Dynamic Report Sections**: Report content dynamically reflects user's menu selection
- **Comprehensive CSV Exports**: Detailed data files for external analysis and reporting
- **Modular Architecture**: Efficient function-based design for optimal performance

## Recent Improvements (Latest Version)
### Enhanced User Experience
- **User-Friendly Column Names**: All major sections now use PSCustomObject with descriptive column headers instead of technical property names
- **Responsive Table Design**: Wide tables automatically scroll horizontally and resize appropriately
- **Dynamic Report Content**: "Key Areas Assessed" and "Assessment Categories" sections now dynamically reflect the user's menu selection
- **Improved Table Headers**: Header text uses proper capitalization (first letter of each word) instead of all uppercase
- **Search Functionality Removed**: Removed search input from "Running Windows Services" section for cleaner interface

### Technical Enhancements
- **Enhanced Error Handling**: Improved error handling throughout all collection functions
- **Optimized Data Processing**: Better memory management and performance optimization
- **Consistent Output Format**: Standardized HTML table formatting across all sections

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
   - Responsive table containers for wide data sets
   - Auto-sizing tables with horizontal scrolling capability
   - Print-optimized styling

4. **Enhanced Data Presentation**
   - User-friendly column names throughout all sections
   - PSCustomObject implementation for better readability
   - Proper table header capitalization
   - Clean, professional table styling
   - Dynamic report sections based on user selection

### Menu-Driven Selection
The script offers five distinct assessment modes:

1. **SYSTEM INFORMATION ONLY**
   - OS Details, CPU, Memory, Disk Information
   - Windows Features, Services, Programs  
   - Updates and Processes
   - **Generated Sections**: 13 comprehensive system assessment areas

2. **NETWORK ASSESSMENT ONLY**
   - Network Interface Configuration
   - Traffic Statistics and Performance
   - Open Ports and Connections
   - **Generated Sections**: 3 focused network assessment areas

3. **SECURITY ASSESSMENT ONLY**
   - Antivirus and Firewall Settings
   - User Accounts and Password Policies
   - Security Configurations and Certificates
   - **Generated Sections**: 17 comprehensive security assessment areas

4. **SCHEDULED TASKS & STARTUP & LOGS ONLY**
   - Startup Programs and Services
   - Scheduled Tasks Configuration
   - System, Application & Security Event Logs
   - **Generated Sections**: 3 focused task and log assessment areas

5. **ALL SECTIONS (Complete Server Assessment)**
   - Comprehensive collection of all above sections
   - **Generated Sections**: 36 total assessment areas covering all aspects

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
     - Enter `3` for Security Assessment Only 
     - Enter `4` for Tasks & Logs Assessment Only
     - Enter `5` for Complete Server Assessment

6. **Wait for Completion**
   - The script will display progress messages as it collects information
   - Assessment time varies based on selected mode and system complexity

### Understanding the Output

#### HTML Assessment Report Structure
The HTML assessment report includes:
- **Executive Summary Dashboard:** Key metrics overview with visual indicators
- **Interactive Navigation Menu:** Collapsible left sidebar with icons and section counters
- **Dynamic Content Sections:** Report content automatically reflects selected assessment mode
- **Modern Styling:** Professional gradient backgrounds, hover effects, and responsive design
- **Section-Based Organization:** Content organized by assessment areas with expandable subsections
- **Enhanced Data Tables:** User-friendly column names and responsive table design
- **Header Information:** Server name, generation timestamp, logged user, assessment scope
- **Print-Friendly Layout:** Optimized for both screen viewing and printing

#### Improved Data Presentation
- **User-Friendly Column Names:** All tables use descriptive headers instead of technical property names
- **Responsive Tables:** Wide tables automatically include horizontal scrolling and proper sizing
- **Dynamic Sections:** "Key Areas Assessed" and "Assessment Categories" reflect your menu selection
- **Professional Formatting:** Proper capitalization and clean styling throughout

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
- **Enhanced Data Tables:** Responsive table containers with horizontal scrolling for wide data
- **User-Friendly Headers:** Descriptive column names using PSCustomObject implementation
- **Dynamic Content:** Report sections automatically adjust based on user's menu selection

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

### Data Presentation Enhancements
The script now provides significantly improved data presentation:

#### PSCustomObject Implementation
All major sections now use PSCustomObject with user-friendly column names:
- **Antivirus Settings**: "AV Enabled", "Real Time Protection", "Behavior Monitor" (instead of technical property names)
- **SMB Shares**: "Share Name", "Share Path", "Share Type", "Folder Enumeration Mode"
- **Updates Installed**: "Update Title", "Installation Date", "Update Size (MB)", "Description"
- **DNS Client Settings**: "DNS Servers", "DNS Over HTTPS", "DNS Cache", "Secure Name Resolution"
- **PowerShell Execution Policy**: "Scope", "Execution Policy", "Security Risk Assessment"
- **Running Processes**: "Process Name", "Process ID", "Memory Usage (MB)", "CPU Time", "Window Title"
- **Windows Features**: "Feature Name", "Display Name", "Current State", "Restart Required"
- **TCP Ports Opened**: "Local Address", "Local Port", "Remote Address", "Remote Port", "Connection State", "Process Name"
- **Event Viewer Logs**: "Log Name", "Maximum Log Size (KB)", "Overflow Action", "Minimum Retention (Days)"

#### Responsive Table Design
- **Wide Tables**: Automatically wrapped in responsive containers with horizontal scrolling
- **Professional Styling**: Modern table headers with proper capitalization
- **Auto-sizing**: Tables adjust to content width while maintaining readability
- **Mobile-Friendly**: Responsive design works across different screen sizes

#### Dynamic Report Content
- **Assessment Categories**: Dynamically shows "System Information", "Network Configuration", "Security Assessment", etc. based on menu selection
- **Key Areas Assessed**: Content automatically reflects the chosen assessment mode
- **Section Counts**: Navigation menu shows accurate section counts for selected mode

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

4. **Tables Not Displaying Properly**
   - **Symptoms:** Wide tables overflowing or headers misaligned
   - **Solution:** Ensure browser supports CSS flexbox and CSS3 features
   - **Alternative:** Use horizontal scroll within table containers

5. **Dynamic Content Not Updating**
   - **Cause:** Report sections not reflecting selected assessment mode
   - **Solution:** Re-run the script if content doesn't match your selection
   - **Check:** Verify the correct menu option was selected during execution

6. **Print Layout Issues**
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
- **V1.0 (June 2025):** Initial release with menu-driven selective assessment, enhanced user interface, and improved data presentation

### Recent Updates (Current Version)
- **Enhanced Data Presentation:** Implemented PSCustomObject throughout all major sections for user-friendly column names
- **Responsive Table Design:** Added table containers with horizontal scrolling for wide data sets
- **Dynamic Report Content:** Assessment Categories and Key Areas Assessed sections now reflect user's menu selection
- **Improved Table Formatting:** Headers use proper capitalization instead of all uppercase
- **UI/UX Improvements:** Removed search functionality from Windows Services section for cleaner interface
- **Better Error Handling:** Enhanced error handling and performance optimization throughout

### Future Enhancements
Potential improvements for future versions:
- **Remote Assessment:** Support for remote server assessments
- **Scheduled Execution:** Built-in task scheduler integration  
- **Email Reports:** Automatic email delivery of assessment reports
- **Comparative Analysis:** Historical trending and comparison features
- **Custom Thresholds:** Configurable alert thresholds for various metrics
- **Export Options:** Additional export formats (JSON, XML)
- **Custom Branding:** Configurable report headers and styling
- **Advanced Filtering:** Interactive filtering options within HTML reports

## Support and Contact

For questions, issues, or enhancement requests:
- **Author:** Abdullah Zmaili
- **Created:** June 16, 2025
- **Version:** WindowsServerAssessmentTool_V1.0

---
*This documentation covers the comprehensive Windows Server Assessment Tool designed for system administrators and IT professionals.*
