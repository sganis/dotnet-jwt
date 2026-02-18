# auth/keygen.ps1
# Generate a self-signed RSA certificate for JWT signing and install it into
# Cert:\LocalMachine\My. Run on the IIS server as a local Administrator.
#
# Usage:
#   .\keygen.ps1                            # creates cert with default subject
#   .\keygen.ps1 -Kid "2026-Q2"             # custom kid label
#   .\keygen.ps1 -AppPoolName "SEECloud-IIS" -Kid "2026-Q2"
#
# After running:
#   1. Copy the printed Thumbprint into appsettings.json JwtSettings.
#   2. Grant the IIS App Pool identity Read access to the private key
#      (done automatically if -AppPoolName is provided).

param(
    [string]$Kid          = "seecloud-$(Get-Date -Format 'yyyy-QQ')",
    [string]$Subject      = "CN=SEECloud-JWT-Signing",
    [string]$AppPoolName  = "",
    [int]   $ValidYears   = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Requires Administrator privileges to write to LocalMachine\My.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

Write-Host "Generating RSA-3072 self-signed certificate..." -ForegroundColor Cyan
Write-Host "  Subject : $Subject"
Write-Host "  Kid     : $Kid"
Write-Host "  Validity: $ValidYears year(s)"
Write-Host ""

$notAfter = (Get-Date).AddYears($ValidYears)

# Create the certificate directly in LocalMachine\My.
$cert = New-SelfSignedCertificate `
    -Subject            $Subject `
    -KeyAlgorithm       RSA `
    -KeyLength          3072 `
    -KeyUsage           DigitalSignature `
    -KeyExportPolicy    NonExportable `
    -CertStoreLocation  "Cert:\LocalMachine\My" `
    -NotAfter           $notAfter `
    -FriendlyName       "SEECloud JWT Signing - $Kid" `
    -HashAlgorithm      SHA256

$thumb = $cert.Thumbprint
Write-Host "Certificate installed." -ForegroundColor Green
Write-Host "  Thumbprint : $thumb"
Write-Host "  Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""

# Grant the IIS App Pool identity Read access to the private key.
if ($AppPoolName -ne "") {
    $iisAccount = "IIS AppPool\$AppPoolName"
    Write-Host "Granting private-key Read to: $iisAccount" -ForegroundColor Cyan

    $rsa     = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $keyName = $rsa.Key.UniqueName
    $keyPaths = @(
        "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyName",
        "$env:ProgramData\Microsoft\Crypto\Keys\$keyName"
    )
    $keyFile = $keyPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($keyFile) {
        $acl  = Get-Acl $keyFile
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $iisAccount,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl $keyFile $acl
        Write-Host "  ACL updated: $keyFile" -ForegroundColor Green
    } else {
        Write-Warning "Could not locate private key file. Grant access manually:"
        Write-Host "  certlm.msc → Personal → right-click cert → All Tasks → Manage Private Keys"
        Write-Host "  Add '$iisAccount' with Read permission."
    }
} else {
    Write-Host "No -AppPoolName provided. Grant private key access manually:" -ForegroundColor Yellow
    Write-Host "  certlm.msc → Personal → Certificates → right-click cert → All Tasks → Manage Private Keys"
    Write-Host "  Add 'IIS AppPool\<YourAppPool>' with Read permission."
    Write-Host ""
}

# Print config snippet.
Write-Host "--------------------------------------------------------------"
Write-Host "Paste into appsettings.json JwtSettings:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  `"ActiveKid`": `"$Kid`","
Write-Host "  `"ActiveSigningThumbprint`": `"$thumb`","
Write-Host "  `"JwksCerts`": ["
Write-Host "    { `"Thumbprint`": `"$thumb`", `"Kid`": `"$Kid`" }"
Write-Host "  ]"
Write-Host ""
Write-Host "During rotation, keep the OLD entry in JwksCerts until old tokens expire (~60 min)."
Write-Host "--------------------------------------------------------------"
