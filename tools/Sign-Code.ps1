#requires -Version 5.1
<#
.SYNOPSIS
Signs PowerShell scripts (and optionally .exe artifacts) with a code-signing certificate.

.DESCRIPTION
Locates a code-signing certificate by thumbprint from the certificate store, or loads a PFX from disk,
then applies Authenticode signatures to matching files using SHA256 and an optional timestamp server.

.EXAMPLE
./tools/Sign-Code.ps1 -Thumbprint ABCD1234... -Path . -Recurse

.EXAMPLE
./tools/Sign-Code.ps1 -PfxPath C:\secrets\codesign.pfx -PfxPassword (Read-Host -AsSecureString) -Path . -IncludeExe

.NOTES
Run in Windows PowerShell 5.1 or newer. Timestamp server defaults to DigiCert.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()] [string]$Path = (Split-Path -Parent $MyInvocation.MyCommand.Path + '\..'),
    [Parameter()] [switch]$Recurse = $true,
    [Parameter()] [string[]]$Include = @('*.ps1','*.psm1','*.psd1'),
    [Parameter()] [switch]$IncludeExe,
    [Parameter()] [string]$Thumbprint,
    [Parameter()] [string]$PfxPath,
    [Parameter()] [SecureString]$PfxPassword,
    [Parameter()] [string]$TimestampServer = 'http://timestamp.digicert.com',
    [Parameter()] [switch]$VerifyOnly,
    [Parameter()] [switch]$SkipValid
)

function Resolve-CodeSigningCertificate {
    param([string]$Thumbprint,[string]$PfxPath,[SecureString]$PfxPassword)
    if ($Thumbprint) {
        $tp = ($Thumbprint -replace '\s','').ToUpperInvariant()
        foreach ($loc in @('CurrentUser','LocalMachine')) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My',$loc)
                $store.Open('ReadOnly')
                $match = $store.Certificates | Where-Object { $_.Thumbprint -replace '\s','' -eq $tp }
                if ($match) {
                    # Ensure it has Code Signing EKU if present
                    return $match[0]
                }
            } finally { if ($store) { $store.Close() } }
        }
        throw "Certificate with thumbprint $Thumbprint not found in CurrentUser/LocalMachine My store."
    }
    if ($PfxPath) {
        if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }
        $plain = $null
        if ($PfxPassword) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
            try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        # Load PFX into memory with private key accessible to the process
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor \
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor \
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $plain, $flags)
        if (-not $cert -or -not $cert.HasPrivateKey) { throw 'Loaded certificate does not have a private key.' }
        return $cert
    }
    throw 'Provide -Thumbprint or -PfxPath.'
}

function Get-TargetFiles {
    param([string]$Root,[switch]$Recurse,[string[]]$Include,[switch]$IncludeExe)
    $patterns = @()
    $patterns += $Include
    if ($IncludeExe) { $patterns += '*.exe' }
    $files = @()
    foreach ($pat in $patterns) {
        $files += Get-ChildItem -LiteralPath $Root -File -Include $pat -Recurse:$Recurse -ErrorAction SilentlyContinue
    }
    # Filter out common output/third-party folders
    $skipDirs = @('AssessmentResults','_out','dist','bin','obj','node_modules','.git')
    $files = $files | Where-Object { $f = $_.FullName; -not ($skipDirs | Where-Object { $f -like (Join-Path -Path '*' -ChildPath ($_ + '*')) }) }
    # De-duplicate
    $files | Select-Object -Unique | Sort-Object FullName
}

$cert = $null
try { $cert = Resolve-CodeSigningCertificate -Thumbprint $Thumbprint -PfxPath $PfxPath -PfxPassword $PfxPassword } catch { throw $_ }
Write-Host ("Using certificate: {0}, Thumbprint={1}" -f $cert.Subject, $cert.Thumbprint) -ForegroundColor Cyan

$targets = Get-TargetFiles -Root $Path -Recurse:$Recurse -Include $Include -IncludeExe:$IncludeExe
if (-not $targets -or $targets.Count -eq 0) { Write-Warning 'No target files matched.'; return }

$results = @()
foreach ($file in $targets) {
    if ($VerifyOnly) {
        $sig = Get-AuthenticodeSignature -FilePath $file.FullName
        $results += [PSCustomObject]@{ File=$file.FullName; Status=$sig.Status; Signer=$sig.SignerCertificate.Subject }
        continue
    }
    $needsSign = $true
    if ($SkipValid) {
        try {
            $cur = Get-AuthenticodeSignature -FilePath $file.FullName
            if ($cur.Status -eq 'Valid') { $needsSign = $false }
        } catch {}
    }
    if (-not $needsSign) { $results += [PSCustomObject]@{ File=$file.FullName; Status='Skipped (Valid)'; Signer=$null }; continue }
    if ($PSCmdlet.ShouldProcess($file.FullName, 'Sign')) {
        try {
            $sig = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop
            $results += [PSCustomObject]@{ File=$file.FullName; Status=$sig.Status; Signer=$cert.Subject }
        } catch {
            $results += [PSCustomObject]@{ File=$file.FullName; Status=('ERROR: '+$_.Exception.Message); Signer=$null }
        }
    }
}

$results
