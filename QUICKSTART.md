# Windows Server Assessment Tool - Quick Reference

## 🆕 What's New in Latest Version
- **User-Friendly Column Names**: Descriptive headers instead of technical property names
- **Responsive Tables**: Auto-sizing tables with horizontal scrolling for wide data
- **Dynamic Report Content**: Report sections automatically reflect your menu selection
- **Enhanced Data Presentation**: PSCustomObject implementation throughout
- **Improved Table Headers**: Proper capitalization (Title Case instead of ALL CAPS)

## Quick Start
1. **Run PowerShell as Administrator**
2. **Navigate to script directory**
3. **Execute:** `.\WindowsServerAssessmentTool_V1.0.ps1`
4. **Enter output path** (e.g., `C:\temp`)
5. **Select assessment mode** (1-5)
6. **Open HTML report** in modern browser for interactive navigation

## Key Features
- 🎨 **Modern HTML Interface** with collapsible navigation
- 📊 **Interactive Dashboard** with executive summary
- 🎯 **Targeted Assessment Modes** for focused analysis
- 📁 **Professional CSV Exports** for detailed data
- 📱 **Responsive Design** optimized for desktop/tablet
- 🔄 **Dynamic Content** that adapts to your selection
- 📋 **User-Friendly Data** with descriptive column names

## Menu Options
| Option | Mode | Sections | Description |
|--------|------|----------|-------------|
| 1 | System Assessment Only | 13 sections | OS, CPU, Memory, Disk, Services, Programs |
| 2 | Network Assessment Only | 3 sections | NICs, Traffic, Open Ports |
| 3 | Security Assessment Only | 17 sections | AV, Firewall, Users, Certificates |
| 4 | Tasks & Logs Assessment Only | 3 sections | Startup, Scheduled Tasks, Event Logs |
| 5 | All Sections | 36 sections | Complete comprehensive server assessment |

## Output Files by Assessment Mode

### Mode 1: System Information Assessment
- **HTML:** `[Server]-SystemReport.html` (Interactive navigation with System sections)
- **CSV Files:** OSInfo, CPUInfo, RAMInfo, DiskInfo, Services, Programs, Updates

### Mode 2: Network Assessment  
- **HTML:** `[Server]-SystemReport.html` (Interactive navigation with Network sections)
- **CSV Files:** NICInfo, TrafficInfo, OpenPorts

### Mode 3: Security Assessment
- **HTML:** `[Server]-SystemReport.html` (Interactive navigation with Security sections)
- **CSV Files:** AVSettings, FirewallStatus, LocalAdmins, Certificates, etc.

### Mode 4: Tasks & Logs Assessment
- **HTML:** `[Server]-SystemReport.html` (Interactive navigation with Tasks/Logs sections)
- **CSV Files:** StartupProgs, ScheduledTasks, EventLogs

### Mode 5: All Sections
- **HTML:** `[Server]-SystemReport.html` (Full interactive navigation with all sections)
- **CSV Files:** All applicable files from modes 1-4

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Permission Denied | Run as Administrator |
| Execution Policy Error | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Long Execution Time | Use specific modes (1-4) instead of mode 5 |
| Missing Data | Check WMI service status |

## Time Estimates
- **Mode 1 (System Assessment):** 2-5 minutes
- **Mode 2 (Network Assessment):** 1-3 minutes  
- **Mode 3 (Security Assessment):** 3-7 minutes
- **Mode 4 (Tasks/Logs Assessment):** 2-4 minutes
- **Mode 5 (Complete Assessment):** 8-15 minutes

## Prerequisites
- PowerShell 5.1+
- Administrator privileges
- Appropriate execution policy

## HTML Report Features
- **Collapsible Navigation:** Click sections to expand/collapse content
- **Interactive Menu:** Left sidebar with icons and section counters
- **Executive Summary:** Visual dashboard with key metrics
- **Professional Styling:** Modern gradients, animations, and responsive design
- **Browser Compatibility:** Optimized for Chrome, Firefox, Edge, Safari

## Navigation Tips
- **Expand Sections:** Click main sections to view subsections
- **Quick Access:** Use left navigation menu for instant section jumping  
- **Toggle Menu:** Click navigation toggle to expand/collapse sidebar
- **Print-Friendly:** Report is optimized for both screen and print viewing
