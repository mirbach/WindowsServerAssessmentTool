#requires -Version 5.1
<#
.SYNOPSIS
Package a PowerShell script into a self-contained .exe using PS2EXE.

.DESCRIPTION
Uses the PS2EXE module to compile target .ps1 into .exe. Supports icon, version info, STA/MTA, and console/GUI modes.

.EXAMPLE
./tools/Build-Exe.ps1 -Input .\WindowsServerAssessmentTool_UI.ps1 -Output .\dist\WSAT-UI.exe -NoConsole -Title "WSAT UI" -Company "Contoso"

.NOTES
Requires PS2EXE module (Install-Module ps2exe). Run in elevated shell if needed to install module for AllUsers.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$InputPath,
    [Parameter()] [string]$Output = (Join-Path -Path (Split-Path -Parent $InputPath) -ChildPath ((Split-Path -LeafBase $InputPath)+'.exe')),
    [Parameter()] [switch]$NoConsole,
    [Parameter()] [switch]$Sta,
    [Parameter()] [string]$Icon,
    [Parameter()] [string]$Title = 'Windows Server Assessment Tool',
    [Parameter()] [string]$Company = 'WSAT',
    [Parameter()] [string]$Description = 'Windows Server Assessment Tool',
    [Parameter()] [string]$Version = '1.0.0.0',
    [Parameter()] [string]$FileVersion = '1.0.0.0'
)

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing PS2EXE from PSGallery...' -ForegroundColor Cyan
    try { Install-Module -Name ps2exe -Scope CurrentUser -Force -ErrorAction Stop } catch { throw "Failed to install ps2exe: $($_.Exception.Message)" }
}
Import-Module ps2exe -ErrorAction Stop

# Resolve input and ensure output directory exists
$resolvedInput = (Resolve-Path -LiteralPath $InputPath).Path
$dir = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

# Ensure output directory exists
$dir = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$ps2exeArgs = @()
$ps2exeArgs += '-icon', ($Icon ? $Icon : '') | Where-Object { $_ }
$ps2exeArgs += '-title', $Title
$ps2exeArgs += '-company', $Company
$ps2exeArgs += '-description', $Description
$ps2exeArgs += '-product', $Title
$ps2exeArgs += '-version', $Version
$ps2exeArgs += '-fileversion', $FileVersion
if ($NoConsole) { $ps2exeArgs += '-noConsole' }
if ($Sta) { $ps2exeArgs += '-sta' } else { $ps2exeArgs += '-mta' }
$ps2exeArgs += '-inputFile', $resolvedInput
$ps2exeArgs += '-outputFile', $Output

Write-Host ("Building EXE: {0} -> {1}" -f $resolvedInput, $Output) -ForegroundColor Cyan
Invoke-ps2exe @ps2exeArgs

Write-Host 'Build complete.' -ForegroundColor Green
