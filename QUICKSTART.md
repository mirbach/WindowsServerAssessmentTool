# Windows Server Assessment Tool - Quick Reference

## Quick Start
1. **Run PowerShell as Administrator**
2. **Navigate to script directory**
3. **Execute:** `.\WindowsServerAssessmentTool_V1.0.ps1`
4. **Enter output path** (e.g., `C:\temp`)
5. **Select assessment mode** (1-5)

## Menu Options
| Option | Mode | Description |
|--------|------|-------------|
| 1 | System Assessment Only | OS, CPU, Memory, Disk, Services, Programs |
| 2 | Network Assessment Only | NICs, Traffic, Open Ports |
| 3 | Security Assessment Only | AV, Firewall, Users, Certificates |
| 4 | Tasks & Logs Assessment Only | Startup, Scheduled Tasks, Event Logs |
| 5 | All Sections | Complete comprehensive server assessment |

## Output Files by Assessment Mode

### Mode 1: System Information Assessment
- **HTML:** `[Server]-SystemReport.html`
- **CSV Files:** OSInfo, CPUInfo, RAMInfo, DiskInfo, Services, Programs, Updates

### Mode 2: Network Assessment  
- **HTML:** `[Server]-SystemReport.html`
- **CSV Files:** NICInfo, TrafficInfo, OpenPorts

### Mode 3: Security Assessment
- **HTML:** `[Server]-SystemReport.html`
- **CSV Files:** AVSettings, FirewallStatus, LocalAdmins, Certificates, etc.

### Mode 4: Tasks & Logs Assessment
- **HTML:** `[Server]-SystemReport.html`
- **CSV Files:** StartupProgs, ScheduledTasks, EventLogs

### Mode 5: All Sections
- **HTML:** `[Server]-SystemReport.html`
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
