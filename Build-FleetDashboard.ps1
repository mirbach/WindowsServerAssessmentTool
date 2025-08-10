#requires -Version 5.1
<#
Build-FleetDashboard.ps1
Aggregates per-server assessment CSVs under AssessmentResults/* and generates:
- AssessmentResults\fleet.json (array of server summaries)
- AssessmentResults\index.html (static dashboard with embedded JSON)

Usage:
  powershell -ExecutionPolicy Bypass -File .\Build-FleetDashboard.ps1
  powershell -ExecutionPolicy Bypass -File .\Build-FleetDashboard.ps1 -RootPath c:\path\to\AssessmentResults
#>
param(
    [string]$RootPath = (Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath 'AssessmentResults')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Try-ImportCsvFirstMatch {
    param(
        [string]$Folder,
        [string]$Pattern
    )
    try {
        $match = Get-ChildItem -LiteralPath $Folder -Filter $Pattern -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $match) {
            return Import-Csv -LiteralPath $match.FullName -ErrorAction SilentlyContinue
        }
    } catch {}
    return $null
}

function To-Bool {
    param([object]$v)
    if ($null -eq $v) { return $false }
    $s = [string]$v
    switch -Regex ($s.Trim()) {
        '^(true|yes|enabled|on|1)$' { return $true }
        default { return $false }
    }
}

function Sum-SizeMB {
    param([object[]]$rows, [string]$columnName)
    $sum = 0.0
    if ($rows) {
        foreach ($r in $rows) {
            $raw = $r.$columnName
            if ($null -ne $raw -and ($raw -is [string] -or $raw -is [double] -or $raw -is [int])) {
                $str = [string]$raw
                $str = $str -replace ',', '.'
                $val = $null
                if ([double]::TryParse($str, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$val)) {
                    $sum += [double]$val
                }
            }
        }
    }
    [math]::Round($sum, 2)
}

function Get-FirstValueByNames {
    param(
        [psobject]$row,
        [string[]]$names
    )
    if ($null -eq $row) { return $null }
    foreach ($n in $names) {
        $prop = $row.PSObject.Properties | Where-Object { $_.Name -ieq $n }
        if ($prop) { return $prop.Value }
    }
    return $null
}

function Any-RowContains {
    param([object[]]$rows,[string]$needle)
    if (-not $rows) { return $false }
    foreach ($r in $rows) {
        foreach ($p in $r.PSObject.Properties) {
            if ([string]$p.Value -match [Regex]::Escape($needle)) { return $true }
        }
    }
    return $false
}

if (-not (Test-Path -LiteralPath $RootPath)) {
    throw "RootPath not found: $RootPath"
}

$fleet = @()
$hostDirs = Get-ChildItem -LiteralPath $RootPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($dir in $hostDirs) {
    $server = $dir.Name
    $folder = $dir.FullName

    # Locate report
    $report = (Get-ChildItem -LiteralPath $folder -Filter '*-SystemReport.html' -File -ErrorAction SilentlyContinue | Select-Object -First 1)
    $assessedAt = if ($report) { $report.LastWriteTime } else { $dir.LastWriteTime }
    $reportRel = $null
    if ($report) {
        $reportRel = $report.FullName.Replace($RootPath + [IO.Path]::DirectorySeparatorChar, '')
    }

    # OS info
    $osRow = $null
    $osCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-OSInfo.csv'
    if ($osCsv) { $osRow = $osCsv | Select-Object -First 1 }
    $osName = if ($osRow) { [string]$osRow.OsName } else { '' }
    $osVersion = if ($osRow) { [string]$osRow.OsVersion } else { '' }
    $osBuild = if ($osRow) { [string]$osRow.OsBuildNumber } else { '' }
    $osArch = if ($osRow) { [string]$osRow.OsArchitecture } else { '' }

    # Uptime
    $uptimeHours = $null
    $upCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-UpTime.csv'
    if ($upCsv) {
        $u = $upCsv | Select-Object -First 1
        if ($u -and $u.TotalHours) {
            $tmp = $null
            if ([double]::TryParse([string]$u.TotalHours, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$tmp)) {
                $uptimeHours = [math]::Round([double]$tmp, 1)
            }
        }
    }
    if ($null -eq $uptimeHours -and $osRow -and $osRow.OsLastBootUpTime) {
        # Fallback: compute from last boot time if parseable
        $dt = $null
        if ([DateTime]::TryParse([string]$osRow.OsLastBootUpTime, [ref]$dt)) {
            $uptimeHours = [math]::Round(((Get-Date) - $dt).TotalHours, 1)
        }
    }

    # Missing updates
    $muCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-MissingUpdates.csv'
    $muCount = 0
    $muSize = 0.0
    if ($muCsv) {
        $muCount = ($muCsv | Measure-Object).Count
        $muSize = Sum-SizeMB -rows $muCsv -columnName 'Size (MB)'
    }

    # Firewall
    $fwCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-FirewallStatus.csv'
    $fwDom = $false; $fwPriv = $false; $fwPub = $false
    if ($fwCsv) {
        foreach ($row in $fwCsv) {
            $p = [string]$row.Profile
            $en = To-Bool $row.Enabled
            switch ($p) {
                'Domain' { $fwDom = $en }
                'Private' { $fwPriv = $en }
                'Public' { $fwPub = $en }
            }
        }
    }

    # RDP security
    $rdpCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-RDPSecurity.csv'
    $rdpNla = $true
    if ($rdpCsv) {
        $r = $rdpCsv | Select-Object -First 1
        if ($r) {
            $nla = [string]$r.'Network Level Authentication'
            if ($nla -match 'Disabled') { $rdpNla = $false } else { $rdpNla = $true }
        }
    }

    # SMBv1
    $smbCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-SMBv1.csv'
    $smb1 = $false
    if ($smbCsv) {
        foreach ($r in $smbCsv) {
            if (([string]$r.FeatureName) -eq 'SMB1Protocol') {
                $smb1 = (([string]$r.State) -eq 'Enabled')
            }
        }
    }

    # Risk score
    $risk = 0
    if ($smb1) { $risk += 50 }
    if (-not $rdpNla) { $risk += 40 }
    if (-not $fwDom) { $risk += 20 }
    if (-not $fwPriv) { $risk += 20 }
    if (-not $fwPub) { $risk += 20 }
    if ($muCount -gt 0) { $risk += 10 }
    if ($muCount -ge 10) { $risk += 10 }

    # AV / Defender status
    $avCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-AVSettings.csv'
    $avRealTime = $null; $avEngine = ''
    if ($avCsv) {
        $avr = $avCsv | Select-Object -First 1
        $rtVal = Get-FirstValueByNames -row $avr -names @('RealTimeProtectionEnabled','RealtimeProtection','RealtimeProtectionEnabled','AMServiceEnabled','AntivirusEnabled')
        if ($null -ne $rtVal) { $avRealTime = To-Bool $rtVal }
        $avEngine = [string](Get-FirstValueByNames -row $avr -names @('EngineVersion','AntivirusSignatureVersion','SignatureVersion'))
        if ($avRealTime -eq $false) { $risk += 40 }
    }

    # ASR rules
    # Known core ASR rules (names or GUIDs). Used to present a stable totalPossible even when a server reports none.
    $knownAsrRules = @(
        # Common Defender ASR rules (selection covering core Windows rules)
        'Block abuse of exploited vulnerable signed drivers',
        'Block Adobe Reader from creating child processes',
        'Block all Office applications from creating child processes',
        'Block credential stealing from the Windows local security authority subsystem (lsass.exe)',
        'Block executable content from email client and webmail',
        'Block executable files from running unless they meet a prevalence, age, or trusted list criterion',
        'Block execution of potentially obfuscated scripts',
        'Block JavaScript or VBScript from launching downloaded executable content',
        'Block LSASS from credential dumping from Windows SAM',
        'Block Office applications from creating executable content',
        'Block Office applications from injecting code into other processes',
        'Block persistence through WMI event subscription',
        'Block process creations originating from PSExec and WMI commands',
        'Block untrusted and unsigned processes that run from USB',
        'Block Win32 API calls from Office macros',
        'Use advanced protection against ransomware',
        'Block executable files from running unless they have a known good reputation',
        'Block ransomware activity',
        'Block credential stealing from web browsers',
        'Block vulnerability exploits'
    )
    $asrCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-DefenderASR.csv'
    $asrConfigured = 0; $asrEnabled = 0; $asrDisabled = 0; $asrAudit = 0
    if ($asrCsv) {
        foreach ($row in $asrCsv) {
            $asrConfigured++
            $state = [string](Get-FirstValueByNames -row $row -names @('State','Mode'))
            if ($state -match 'Enabled|On|Block') { $asrEnabled++ }
            elseif ($state -match 'Audit|Warn') { $asrAudit++ }
            else { $asrDisabled++ }
        }
        if ($asrDisabled -gt 0) { $risk += 20 }
    }

    # TLS/SSL protocols
    $tlsCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-TLSregSettings.csv'
    $tls10On=$false;$tls11On=$false;$tls12On=$true;$ssl3On=$false
    if ($tlsCsv) {
        foreach ($row in $tlsCsv) {
            $proto = [string](Get-FirstValueByNames -row $row -names @('Protocol','Name','Key'))
            $state = [string](Get-FirstValueByNames -row $row -names @('State','Enabled','Value','Setting'))
            $on = $false
            if ($state) { $on = To-Bool $state }
            switch -Regex ($proto) {
                'TLS\s*1\.?0' { $tls10On = $on }
                'TLS\s*1\.?1' { $tls11On = $on }
                'TLS\s*1\.?2' { $tls12On = $on }
                'SSL\s*3'     { $ssl3On  = $on }
            }
        }
        if ($tls10On) { $risk += 20 }
        if ($tls11On) { $risk += 20 }
        if ($ssl3On)  { $risk += 30 }
    }

    # UAC settings
    $uacCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-UACSettings.csv'
    $uacEnabled = $true
    if ($uacCsv) {
        $ur = $uacCsv | Select-Object -First 1
        $uacVal = Get-FirstValueByNames -row $ur -names @('UAC','EnableLUA','Status','Enabled')
        if ($null -ne $uacVal) { $uacEnabled = To-Bool $uacVal }
        if (-not $uacEnabled) { $risk += 30 }
    }

    # Execution Policy
    $epCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-PSExecPolicy.csv'
    $execPolicy = ''
    if ($epCsv) {
        $epr = $epCsv | Select-Object -First 1
        $execPolicy = [string](Get-FirstValueByNames -row $epr -names @('ExecutionPolicy','Policy','Scope'))
        if ($execPolicy -match 'Unrestricted|Bypass') { $risk += 20 }
    }

    # Password policy
    $ppCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-PasswordPolicyInfo.csv'
    $pwdComplex=$null; $pwdMinLen=$null; $pwdLockout=$null
    if ($ppCsv) {
        $ppr = $ppCsv | Select-Object -First 1
        $pwdComplex = To-Bool (Get-FirstValueByNames -row $ppr -names @('PasswordComplexity','ComplexityEnabled'))
        $pwdMinLen = [int]([string](Get-FirstValueByNames -row $ppr -names @('MinimumPasswordLength','MinLength')))
        $pwdLockout = [int]([string](Get-FirstValueByNames -row $ppr -names @('LockoutThreshold','AccountLockoutThreshold')))
        if ($pwdComplex -eq $false) { $risk += 10 }
        if ($pwdMinLen -and $pwdMinLen -lt 12) { $risk += 10 }
        if ($pwdLockout -eq 0) { $risk += 10 }
    }

    # Local admins
    $laCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-LocalAdmins.csv'
    $localAdminsCount = 0; $localAdminsHasDomainAdmins = $false
    if ($laCsv) {
        $localAdminsCount = ($laCsv | Measure-Object).Count
        $localAdminsHasDomainAdmins = Any-RowContains -rows $laCsv -needle 'Domain Admins'
        if ($localAdminsCount -gt 10) { $risk += 10 }
    }

    # Inactive accounts (local) – count if provided
    $inaCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-InactiveAccountsInfo.csv'
    $inactiveCount = 0
    if ($inaCsv) { $inactiveCount = ($inaCsv | Measure-Object).Count }

    # User rights – risky assignments for RDP
    $uraCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-UserRightsAssignments.csv'
    $rdpAllowEveryone = $false; $rdpAllowDomainUsers = $false
    $userRightsFull = @{}
    if ($uraCsv) {
        foreach ($row in $uraCsv) {
            $priv = [string](Get-FirstValueByNames -row $row -names @('Privilege','UserRight','Right'))
            $acct = [string](Get-FirstValueByNames -row $row -names @('Account','Identity','Principal'))
            if ($priv) {
                if (-not $userRightsFull.ContainsKey($priv)) { $userRightsFull[$priv] = New-Object System.Collections.ArrayList }
                if ($acct -and -not ($userRightsFull[$priv] -contains $acct)) { [void]$userRightsFull[$priv].Add($acct) }
            }
            if ($priv -match 'SeRemoteInteractiveLogonRight') {
                if ($acct -match 'Everyone') { $rdpAllowEveryone = $true }
                if ($acct -match 'Domain Users') { $rdpAllowDomainUsers = $true }
            }
        }
        if ($rdpAllowEveryone) { $risk += 50 } elseif ($rdpAllowDomainUsers) { $risk += 20 }
    }

    # Open ports
    $opCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-OpenPorts.csv'
    $openPortsTotal = 0; $openPortsRisky = @()
    if ($opCsv) {
        $openPortsTotal = ($opCsv | Measure-Object).Count
        foreach ($row in $opCsv) {
            $portStr = [string](Get-FirstValueByNames -row $row -names @('LocalPort','Port','LPort'))
            $proto = ([string](Get-FirstValueByNames -row $row -names @('Protocol','Proto'))).ToUpper()
            $p = 0; [void][int]::TryParse($portStr, [ref]$p)
            if ($p -in 21,23) { $openPortsRisky += ("${proto}/$p") }
        }
        if ($openPortsRisky.Count -gt 0) { $risk += 20 }
    }

    # SMB shares – Everyone permissions indicator if detectable
    $shCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-SMBShares.csv'
    $shareCount = 0; $shareEveryoneCount = 0
    if ($shCsv) {
        $shareCount = ($shCsv | Measure-Object).Count
        foreach ($row in $shCsv) {
            if (Any-RowContains -rows @($row) -needle 'Everyone') { $shareEveryoneCount++ }
        }
        if ($shareEveryoneCount -gt 0) { $risk += 20 }
    }

    # Audit settings – parse into key=>value map
    $auditCsv = Try-ImportCsvFirstMatch -Folder $folder -Pattern '*-auditSettings.csv'
    $auditMap = [ordered]@{}
    if ($auditCsv) {
        foreach ($row in $auditCsv) {
            $setting = [string](Get-FirstValueByNames -row $row -names @('Setting','Policy','Name'))
            if (-not $setting) { continue }
            # Skip category header rows where Setting equals Category
            $cat = [string](Get-FirstValueByNames -row $row -names @('Category'))
            if ($cat -and $setting -eq $cat) { continue }
            # Expect pattern: "Name<spaces>Status"; take the trailing token(s) after 2+ spaces as status
            $name = $setting; $status = ''
            $m = [regex]::Match($setting, '^(.*?)[\s]{2,}([^\s].*)$')
            if ($m.Success) { $name = $m.Groups[1].Value.Trim(); $status = $m.Groups[2].Value.Trim() }
            if (-not $status) { $status = $name; $name = $setting }
            if (-not $auditMap.Contains($name)) { $auditMap[$name] = $status } else { $auditMap[$name] = $status }
        }
    }

    $obj = [ordered]@{
        server = $server
        assessedAt = (Get-Date $assessedAt -Format 'yyyy-MM-dd HH:mm:ss')
        os = [ordered]@{
            name = $osName
            version = $osVersion
            build = $osBuild
            arch = $osArch
        }
        uptimeHours = $uptimeHours
        missingUpdates = [ordered]@{ count = $muCount; sizeMB = $muSize }
        firewall = [ordered]@{ domain = $fwDom; private = $fwPriv; public = $fwPub }
        rdpNlaEnabled = $rdpNla
        smb1Enabled = $smb1
    av = [ordered]@{ realTime=$avRealTime; engine=$avEngine; asrEnabled=$asrEnabled; asrDisabled=$asrDisabled; asrAudit=$asrAudit; asrConfigured=$asrConfigured; asrTotalPossible=$($knownAsrRules.Count) }
        tls = [ordered]@{ tls10=$tls10On; tls11=$tls11On; tls12=$tls12On; ssl3=$ssl3On }
        uacEnabled = $uacEnabled
        execPolicy = $execPolicy
        password = [ordered]@{ complexity = $pwdComplex; minLength = $pwdMinLen; lockoutThreshold = $pwdLockout }
        localAdmins = [ordered]@{ count=$localAdminsCount; hasDomainAdmins=$localAdminsHasDomainAdmins }
        userRights = [ordered]@{ rdpAllowEveryone=$rdpAllowEveryone; rdpAllowDomainUsers=$rdpAllowDomainUsers }
    userRightsFull = $userRightsFull
        openPorts = [ordered]@{ total=$openPortsTotal; risky=$openPortsRisky }
        smbShares = [ordered]@{ total=$shareCount; everyone=$shareEveryoneCount }
    audit = $auditMap
        riskScore = $risk
        reportPath = $reportRel
    }
    $fleet += [pscustomobject]$obj
}

# Save JSON
$json = $fleet | ConvertTo-Json -Depth 6 -Compress
$fleetPath = Join-Path -Path $RootPath -ChildPath 'fleet.json'
Set-Content -LiteralPath $fleetPath -Value $json -Encoding UTF8

# Build HTML (embedded JSON for local file viewing)
$summaryHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Server Assessment Dashboard</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
 header{padding:16px 20px;background:#1f2937;border-bottom:1px solid #334155}
 h1{font-size:20px;margin:0}
 .wrap{padding:16px 20px}
 .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
 .tile{background:#111827;border:1px solid #334155;border-radius:8px;padding:12px}
 .tile .num{font-size:22px;font-weight:700}
 .tile .lbl{font-size:12px;color:#94a3b8}
 .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
 input[type=text],select{background:#0b1220;border:1px solid #334155;border-radius:6px;color:#e2e8f0;padding:8px}
 table{width:100%;border-collapse:collapse;background:#0b1220;border:1px solid #334155;border-radius:8px;overflow:hidden}
 th,td{padding:8px 10px;border-bottom:1px solid #1f2937;font-size:12px}
 th{background:#0b1322;text-align:left;color:#a5b4fc;position:sticky;top:0}
 tr:hover{background:#0e1726}
 .badge{display:inline-block;padding:2px 6px;border-radius:12px;font-size:11px}
 .ok{background:#065f46;color:#d1fae5}
 .warn{background:#92400e;color:#ffedd5}
 .crit{background:#7f1d1d;color:#fee2e2}
 .muted{color:#94a3b8}
 a{color:#60a5fa;text-decoration:none}
 a:hover{text-decoration:underline}
 td.diff{outline:2px solid #eab308; background: rgba(234,179,8,0.08)}
</style>
</head>
<body>
<header><h1>Windows Server Assessment Dashboard</h1></header>
<div class="wrap">
 <div class="tiles" id="tiles"></div>
 <div class="filters">
  <input type="text" id="q" placeholder="Filter by server..." />
  <select id="risk">
    <option value="">All risk levels</option>
    <option value="crit">Critical (>=70)</option>
    <option value="warn">Warning (40-69)</option>
    <option value="info">Info (1-39)</option>
    <option value="ok">OK (0)</option>
  </select>
  <select id="baseline">
    <option value="">No baseline</option>
    <option value="__consensus">Baseline: Consensus</option>
  </select>
  <label><input type="checkbox" id="diffOnly"> Differences only</label>
 </div>
 <table id="grid"><thead><tr>
  <th>Server</th><th>&#916;</th><th>OS / Build</th><th>Uptime (h)</th><th>Missing Updates</th>
  <th>Firewall</th><th>RDP NLA</th><th>SMBv1</th><th>AV RT</th><th>ASR</th><th>TLS</th><th>UAC</th><th>ExecPolicy</th><th>Risk</th><th>Assessed</th><th>Details</th>
 </tr></thead><tbody></tbody></table>
</div>
<script id="fleet-data" type="application/json">$json</script>
<script>
(function(){
  function riskBand(score){ if(score>=70) return 'crit'; if(score>=40) return 'warn'; if(score>0) return 'info'; return 'ok'; }
  function fwBadge(b){ return b?'<span class=\"badge ok\">On</span>':'<span class=\"badge warn\">Off</span>'; }
  function riskBadge(s){ var b=riskBand(s); return '<span class=\"badge '+(b==='ok'?'ok':(b==='crit'?'crit':'warn'))+'\">'+s+'</span>'; }
  var data=[]; try{ data=JSON.parse(document.getElementById('fleet-data').textContent)||[] }catch(e){}
  data.sort(function(a,b){ return (b.riskScore||0)-(a.riskScore||0); });
  var tiles=document.getElementById('tiles');
  var total=data.length;
  var crit=data.filter(function(x){return (x.riskScore||0)>=70}).length;
  var nlaOff=data.filter(function(x){return x.rdpNlaEnabled===false}).length;
  var smb1On=data.filter(function(x){return x.smb1Enabled===true}).length;
  var fwOff=data.filter(function(x){return !(x.firewall && x.firewall.domain && x.firewall.private && x.firewall.public)}).length;
  var avOff=data.filter(function(x){return x.av && x.av.realTime===false}).length;
    var asrDisabled=data.filter(function(x){return x.av && ((x.av.asrDisabled||0)>0)}).length;
  var tlsWeak=data.filter(function(x){return x.tls && (x.tls.tls10||x.tls.tls11||x.tls.ssl3)}).length;
  var muTotal=data.reduce(function(s,x){return s+((x.missingUpdates&&x.missingUpdates.count)||0)},0);
  function tile(n,l){ return '<div class=\"tile\"><div class=\"num\">'+n+'</div><div class=\"lbl\">'+l+'</div></div>'; }
  tiles.innerHTML = tile(total,'Servers assessed')+tile(crit,'Critical issues')+tile(nlaOff,'RDP NLA disabled')+tile(smb1On,'SMBv1 enabled')+tile(fwOff,'Firewall profiles off')+tile(avOff,'AV realtime off')+tile(asrDisabled,'ASR rules disabled')+tile(tlsWeak,'Weak TLS/SSL enabled')+tile(muTotal,'Missing updates (count)');

  // Baseline selector options
  var baselineSel=document.getElementById('baseline');
  data.forEach(function(x){ var opt=document.createElement('option'); opt.value=x.server; opt.textContent='Baseline: '+x.server; baselineSel.appendChild(opt); });

  // Projection fields used for diffing
  var fields=[
    {id:'os', proj:function(x){ return (x.os&&x.os.name?x.os.name:'')+'|'+(x.os&&x.os.build?x.os.build:'')+'|'+(x.os&&x.os.arch?x.os.arch:''); }},
    {id:'uptime', proj:function(x){ return (x.uptimeHours==null?'':String(x.uptimeHours)); }},
    {id:'mu', proj:function(x){ var mu=x.missingUpdates||{}; return String(mu.count||0)+'|'+String(mu.sizeMB||0); }},
    {id:'fw', proj:function(x){ var f=x.firewall||{}; return String(!!f.domain)+'|'+String(!!f.private)+'|'+String(!!f.public); }},
    {id:'rdp', proj:function(x){ return String(!!x.rdpNlaEnabled); }},
    {id:'smb1', proj:function(x){ return String(!!x.smb1Enabled); }},
    {id:'avrt', proj:function(x){ return String(!!(x.av && x.av.realTime)); }},
    {id:'asr', proj:function(x){ var a=x.av||{}; return String(a.asrEnabled||0)+'/'+String(a.asrTotalPossible||0); }},
    {id:'tls', proj:function(x){ var t=x.tls||{}; return String(!!t.tls10)+'|'+String(!!t.tls11)+'|'+String(!!t.tls12)+'|'+String(!!t.ssl3); }},
    {id:'uac', proj:function(x){ return String(!(x.uacEnabled===false)); }},
    {id:'exec', proj:function(x){ return String(x.execPolicy||''); }},
    {id:'risk', proj:function(x){ return String(x.riskScore||0); }}
  ];

  function consensusFor(fid){
    var counts={};
    data.forEach(function(x){ var v=fields.find(function(f){return f.id===fid}).proj(x); counts[v]=(counts[v]||0)+1; });
    var best=null, bestN=-1; Object.keys(counts).forEach(function(k){ if(counts[k]>bestN){ best=k; bestN=counts[k]; }});
    return best;
  }
  function getBaselineMap(){
    var sel=baselineSel.value; if(!sel) return null; var map={};
    if(sel==='__consensus'){ fields.forEach(function(f){ map[f.id]=consensusFor(f.id); }); }
    else { var b=data.find(function(x){return x.server===sel}); if(!b) return null; fields.forEach(function(f){ map[f.id]=f.proj(b); }); }
    return map;
  }
  function cell(html,isDiff){ return '<td'+(isDiff?' class=\"diff\"':'')+'>'+html+'</td>'; }

  var tbody=document.querySelector('#grid tbody');
  function render(){
    var q=document.getElementById('q').value.toLowerCase();
    var rb=document.getElementById('risk').value;
    var diffOnly=document.getElementById('diffOnly').checked;
    var baseMap=getBaselineMap();
    var baselineSelVal=document.getElementById('baseline').value;
    var rows='';
    data.forEach(function(x){
      var band=riskBand(x.riskScore||0);
      if(q && x.server.toLowerCase().indexOf(q)===-1) return;
      if(rb && rb!==band) return;
      var fw=x.firewall||{};
      var osTxt=(x.os&&x.os.name?x.os.name:'')+ (x.os&&x.os.build?(' ('+x.os.build+')'):'')
      var mu=(x.missingUpdates?x.missingUpdates.count:0)+' / '+(x.missingUpdates?x.missingUpdates.sizeMB:0)+' MB';
      var srvCell=x.reportPath?('<a href="'+x.reportPath+'" target="_blank">'+x.server+'</a>'):x.server;

      var diffs=0; var fvals={};
      fields.forEach(function(f){ fvals[f.id]=f.proj(x); if(baseMap && baseMap[f.id]!==undefined && baseMap[f.id]!==fvals[f.id]) diffs++; });
      if(diffOnly && (!baseMap || diffs===0)) return;

      var cells='';
      cells += '<td>'+srvCell+'</td>';
      cells += '<td>'+(baseMap?('<span class=\"badge '+(diffs>0?'warn':'ok')+'\">'+(diffs>99?"99+":diffs)+'</span>'):'<span class=\"muted\">-</span>')+'</td>';
      cells += cell((osTxt||'<span class=\"muted\">n/a</span>'), baseMap && baseMap.os!==undefined && baseMap.os!==fvals.os);
      cells += cell((x.uptimeHours!=null?x.uptimeHours:'<span class=\"muted\">n/a</span>'), baseMap && baseMap.uptime!==undefined && baseMap.uptime!==fvals.uptime);
      cells += cell(mu, baseMap && baseMap.mu!==undefined && baseMap.mu!==fvals.mu);
      cells += cell('D '+fwBadge(!!fw.domain)+' / P '+fwBadge(!!fw.private)+' / Pu '+fwBadge(!!fw.public), baseMap && baseMap.fw!==undefined && baseMap.fw!==fvals.fw);
      cells += cell((x.rdpNlaEnabled?'<span class=\"badge ok\">On</span>':'<span class=\"badge warn\">Off</span>'), baseMap && baseMap.rdp!==undefined && baseMap.rdp!==fvals.rdp);
      cells += cell((x.smb1Enabled?'<span class=\"badge warn\">On</span>':'<span class=\"badge ok\">Off</span>'), baseMap && baseMap.smb1!==undefined && baseMap.smb1!==fvals.smb1);
      cells += cell((x.av && x.av.realTime===false?'<span class=\"badge warn\">Off</span>':'<span class=\"badge ok\">On</span>'), baseMap && baseMap.avrt!==undefined && baseMap.avrt!==fvals.avrt);
    var asrTxt = (x.av?((x.av.asrEnabled||0)+'/'+(x.av.asrTotalPossible||0)):'<span class=\"muted\">n/a</span>');
    if(x.av && (x.av.asrDisabled||0)>0){ asrTxt += ' <span class=\"badge warn\">'+String(x.av.asrDisabled)+' disabled</span>'; }
    if(x.av && (x.av.asrAudit||0)>0){ asrTxt += ' <span class=\"badge\" style=\"background:#334155;color:#e2e8f0\">'+String(x.av.asrAudit)+' audit</span>'; }
    cells += cell(asrTxt, baseMap && baseMap.asr!==undefined && baseMap.asr!==fvals.asr);
      cells += cell((x.tls?( (x.tls.tls10||x.tls.tls11||x.tls.ssl3?'<span class=\"badge warn\">Weak</span>':'<span class=\"badge ok\">OK</span>' ) ):'<span class=\"muted\">n/a</span>'), baseMap && baseMap.tls!==undefined && baseMap.tls!==fvals.tls);
      cells += cell((x.uacEnabled===false?'<span class=\"badge warn\">Off</span>':'<span class=\"badge ok\">On</span>'), baseMap && baseMap.uac!==undefined && baseMap.uac!==fvals.uac);
      cells += cell((x.execPolicy||'<span class=\"muted\">n/a</span>'), baseMap && baseMap.exec!==undefined && baseMap.exec!==fvals.exec);
      cells += '<td>'+riskBadge(x.riskScore||0)+'</td>';
      cells += '<td>'+(x.assessedAt||'')+'</td>';
      // Details panel
      var bObj=null; if(baselineSelVal && baselineSelVal!=='__consensus'){ bObj = data.find(function(d){ return d.server===baselineSelVal; }) || null; }
      function badge(val){ return val?'<span class="badge ok">On</span>':'<span class="badge warn">Off</span>'; }
      function list(arr){ return (arr && arr.length)?arr.join('; '):'<span class="muted">none</span>'; }
      function cmpUserRights(a,b){ a=a||{}; b=b||{}; var keys={}; var out='';
        Object.keys(a).forEach(function(k){keys[k]=true}); Object.keys(b).forEach(function(k){keys[k]=true});
        Object.keys(keys).sort().forEach(function(k){ var va=a[k]||[], vb=b[k]||[]; var same = JSON.stringify([].concat(va).sort())===JSON.stringify([].concat(vb).sort()); out+='<div><strong>'+k+':</strong> '+list(va)+(bObj?(' vs <em>'+list(vb)+'</em>'):'')+' '+(bObj?(same?'<span class="badge ok">same</span>':'<span class="badge warn">diff</span>'):'')+'</div>'; });
        if(!out){ out='<div class="muted">No user rights data</div>'; }
        return out;
      }
      function cmpAudit(a,b){ a=a||{}; b=b||{}; var keys={}; var out='';
        Object.keys(a).forEach(function(k){keys[k]=true}); Object.keys(b).forEach(function(k){keys[k]=true});
        Object.keys(keys).sort().forEach(function(k){ var va=a[k]||'', vb=b[k]||''; var same = (va===vb); out+='<div><strong>'+k+':</strong> '+(va||'<span class="muted">n/a</span>')+(bObj?(' vs <em>'+(vb||'n/a')+'</em>'):'')+' '+(bObj?(same?'<span class="badge ok">same</span>':'<span class="badge warn">diff</span>'):'')+'</div>'; });
        if(!out){ out='<div class="muted">No audit settings</div>'; }
        return out;
      }
      var detailsHtml = '<div style="display:none" class="detail">'+
        '<div><strong>UAC:</strong> '+badge(!(x.uacEnabled===false))+(bObj?(' vs <em>'+badge(!(bObj.uacEnabled===false))+'</em>'):'')+'</div>'+
        '<div><strong>AV Realtime:</strong> '+badge(!!(x.av&&x.av.realTime))+(bObj?(' vs <em>'+badge(!!(bObj.av&&bObj.av.realTime))+'</em>'):'')+'</div>'+
        '<div><strong>Firewall:</strong> D '+badge(!!fw.domain)+' / P '+badge(!!fw.private)+' / Pu '+badge(!!fw.public)+(bObj?(' vs <em>D '+badge(!!(bObj.firewall&&bObj.firewall.domain))+' / P '+badge(!!(bObj.firewall&&bObj.firewall.private))+' / Pu '+badge(!!(bObj.firewall&&bObj.firewall.public))+'</em>'):'')+'</div>'+
        '<div><strong>RDP NLA:</strong> '+badge(!!x.rdpNlaEnabled)+(bObj?(' vs <em>'+badge(!!(bObj&&bObj.rdpNlaEnabled))+'</em>'):'')+'</div>'+
        '<div><strong>SMBv1:</strong> '+badge(!!x.smb1Enabled)+(bObj?(' vs <em>'+badge(!!(bObj&&bObj.smb1Enabled))+'</em>'):'')+'</div>'+
    '<div><strong>ASR enabled/total possible:</strong> '+(x.av?((x.av.asrEnabled||0)+'/'+(x.av.asrTotalPossible||0)):'n/a')+(bObj?(' vs <em>'+(bObj.av?((bObj.av.asrEnabled||0)+'/'+(bObj.av.asrTotalPossible||0)):'n/a')+'</em>'):'')+'</div>'+
    (x.av?('<div><span class=\"muted\">Configured: '+String(x.av.asrConfigured||0)+', Disabled: '+String(x.av.asrDisabled||0)+', Audit: '+String(x.av.asrAudit||0)+'</span></div>'):'')+
        '<div><strong>Shares (Everyone count):</strong> '+String((x.smbShares&&x.smbShares.everyone)||0)+(bObj?(' vs <em>'+String((bObj.smbShares&&bObj.smbShares.everyone)||0)+'</em>'):'')+'</div>'+
        '<div style="margin-top:8px"><strong>User Rights</strong><div style="margin-left:8px">'+cmpUserRights(x.userRightsFull, bObj?(bObj.userRightsFull||{}):{})+'</div></div>'+
        '<div style="margin-top:8px"><strong>Audit Settings</strong><div style="margin-left:8px; max-height:240px; overflow:auto">'+cmpAudit(x.audit, bObj?(bObj.audit||{}):{})+'</div></div>'+
      '</div>';
      cells += '<td><button class="btn-details">View</button>'+detailsHtml+'</td>';
      rows += '<tr>'+cells+'</tr>';
    });
    tbody.innerHTML=rows||'<tr><td colspan="16" class="muted">No data</td></tr>';
    Array.prototype.slice.call(document.querySelectorAll('.btn-details')).forEach(function(btn){
      btn.addEventListener('click', function(){ var d=this.nextElementSibling; if(!d) return; d.style.display = (d.style.display==='none' || !d.style.display)?'block':'none'; this.textContent = d.style.display==='block'?'Hide':'View'; });
    });
  }
  document.getElementById('q').addEventListener('input',render);
  document.getElementById('risk').addEventListener('change',render);
  document.getElementById('baseline').addEventListener('change',render);
  document.getElementById('diffOnly').addEventListener('change',render);
  render();
})();
</script>
</body>
</html>
"@

$indexPath = Join-Path -Path $RootPath -ChildPath 'index.html'
Set-Content -LiteralPath $indexPath -Value $summaryHtml -Encoding UTF8

Write-Host ("Wrote {0}" -f $fleetPath)
Write-Host ("Wrote {0}" -f $indexPath)
