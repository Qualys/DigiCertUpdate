<#PSScriptInfo

.VERSION 1.4

.GUID e2cf497e-0a2c-49f4-90c4-f487ad1e78d8

.AUTHOR Qualys

.COMPANYNAME Qualys Inc

.COPYRIGHT Copyright (c) 2022 Qualys Inc. All rights reserved.

.LICENSEURI https://github.com/Qualys/DigiCertUpdate/blob/main/LICENSE.md

.PROJECTURI https://github.com/Qualys/DigiCertUpdate/

#>

<#
.NOTES
    Copyright (c) 2022 Qualys Inc. All rights reserved.

    THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, 
    QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. 
    IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS.

.SYNOPSIS
    Add the DigiCert Trusted Root G4 certificate to the Trusted Root Certification Authorities if it is not present.

.DESCRIPTION
    The script will check for the availability of the DigiCert Trusted Root G4 certificate in the Trusted Root Certification Authorities first.
    If it is not available, Script will try to fetch it from the digicert website and update to the store. If this step also fails, It will ask
    the customer to provide a local path to the certificate that is already downloaded.

.PARAMETER CertPath
    Path to the certificate file

.PARAMETER ProxyAddress
    Proxy address to be used while downloading the cert

.PARAMETER ProxyPort
    Proxy port to be used while downloading the cert

.PARAMETER ProxyUser
    Proxy username to be used while downloading the cert

.PARAMETER ProxyPassword
    Proxy password to be used while downloading the cert

.PARAMETER ProxyPassword
    Proxy users's domain to be used while downloading the cert

.EXAMPLE
    PS C:\> .\DigiCertUpdate.ps1

.EXAMPLE
    PS C:\> .\DigiCertUpdate.ps1 -CertPath "C:\DigiCertTrustedRootG4.crt"
    
.EXAMPLE
    PS C:\> .\DigiCertUpdate.ps1 -ProxyAddress "10.10.10.10" -ProxyPort 3128

.EXAMPLE
    PS C:\> .\DigiCertUpdate.ps1 -ProxyAddress "10.10.10.10" -ProxyPort 3128 -ProxyUser "admin" -ProxyPassword "abc123"
#>

#Requires -Version 2.0

param(
    [parameter(Mandatory = $false, Position = 0)]
    [string]$CertPath = "",
    [parameter(Mandatory = $false, Position = 1)]
    [string]$ProxyAddress = "",
    [parameter(Mandatory = $false, Position = 2)]
    [int]$ProxyPort = 0,
    [parameter(Mandatory = $false, Position = 3)]
    [string]$ProxyUser = "",
    [parameter(Mandatory = $false, Position = 4)]
    [string]$ProxyPassword = "",
    [parameter(Mandatory = $false, Position = 5)]
    [string]$ProxyUserDomain = ""
)

[string]$CertThumbprint = "ddfb16cd4931c973a2037d3fc83a4d7d775d05e4"
[string]$CertURL = "http://cacerts.digicert.com/DigiCertTrustedRootG4.crt"

function Write-Log {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateSet("WARNING", "ERROR", "INFO")]
        [string]$Severity
    )

    [string]$LogMessage = [System.String]::Format("[$(Get-Date)][$Severity] -"), $Message

    switch ($Severity) {
        { $_ -match 'WARNING' } { Write-Host $LogMessage -ForegroundColor Yellow -BackgroundColor Black; Break }
        { $_ -match 'ERROR' } { Write-Host $LogMessage -ForegroundColor Red -BackgroundColor Black; Break }
        { $_ -match 'INFO' } { Write-Host $LogMessage -ForegroundColor Green -BackgroundColor Black; Break }
        default { Write-Host $LogMessage }
    }
}

function Write-Info {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Info"
}

function Write-Warn {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Warning"
}

function Write-Err {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Error"
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Cert {
    Write-Info "Checking if the certificate is already present in the certificate store.."

    try {
        $ReturnHash = Get-ChildItem "cert:\" -Recurse | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -first 1 Thumbprint -ExpandProperty Thumbprint
        return $ReturnHash -eq $CertThumbprint 
    }
    catch {
        Write-Err $_.Exception.Message
        return $false
    }
}

function Add-CertificateFromFilePath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FilePath
    )

    $Status = $false

    Write-Info "Importing the certficate from the path: $FilePath"

    try {
        if ((Test-Path -Path $FilePath -PathType leaf) -eq $false) {
            Write-Err "Inavlid file path. File does not exist"
            return $Status
        } 

        if ($PSVersionTable.PSVersion.Major -gt 3) {
            $Status = Import-Certificate -FilePath $FilePath -CertStoreLocation cert:\LocalMachine\Root
        }
        else {
            $ImportCertCommand = "certutil -addstore -f root '$FilePath'"
            $Status = Invoke-Expression -Command $ImportCertCommand
        }

        if ($Status -eq $false) {
            Write-Err "Unable to import certificate to the root store"
            return $Status
        }

        Write-Info "Successfully imported the certificate to the root store"
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $Status
}

function Get-WebClient {
    $WebClient = new-object System.Net.WebClient

    if ($ProxyAddress.length -gt 0) { 
        if ($ProxyPort -gt 0) {
            Write-Info "Using proxy $ProxyAddress with port $ProxyPort"
            $CurrentProxy = New-Object System.Net.WebProxy($ProxyAddress, $ProxyPort)
        }
        else {
            Write-Info "Using proxy $ProxyAddress"
            $CurrentProxy = New-Object System.Net.WebProxy($ProxyAddress)
        }

        if ($ProxyUserName.length -gt 0) {
            Write-Info "Setting credentials"
            $CurrentProxy.credentials = New-Object System.Net.NetworkCredential($ProxyUserName, $ProxyUserPassword, $ProxyUserDomain)
        }
    
        $WebClient.proxy = $CurrentProxy
    }

    return $WebClient;
}

function Add-CertificateFromURL {
    Write-Info "Trying to download the certificate from the digicert website"
    $Status = $false

    try {
        $CertTempPath = $pwd.Path + "\DigiCertTrustedRootG4.crt"
        $WebClient = Get-WebClient
        $WebClient.DownloadFile($CertURL, $CertTempPath) 

        if ($? -eq $false) {
            Write-Err "Unable to download the certificate from the URL" 
            return $Status 
        }

        Write-Info "Downloaded the certificate successfully"
        Write-Info "Trying to import the certificate to the certificate store"

        $Status = Add-CertificateFromFilePath $CertTempPath

        Write-Info "Cleaning up temporary files"

        Remove-Item $CertTempPath

        if ($? -eq $false) { 
            Write-Warn "Unable to delete the temporary files" 
        }
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $Status
}

function Add-Certificate {
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string]$CertFilePath
    )

    try {
        if (Find-Cert -eq $true) {
            Write-Info "Certificate is already present at the root"
            return $true
        }

        Write-Info "Certificate is not present at the root"

        if ($PSBoundParameters.ContainsKey('CertFilePath') -eq $true) {
            Write-Info "Using the explicitly specified file path: $CertFilePath"
            return $(Add-CertificateFromFilePath -FilePath $CertFilePath)
        }

        if ((Add-CertificateFromURL) -eq $false) {
            Write-Info "Unable to add the certificate to the root store. Please try to download the certificate manually and use the -CertPath option"
            return $false 
        }
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $true
}

if (Test-IsAdmin -eq $true) {
    if ($PSBoundParameters.ContainsKey("CertPath") -or ($CertPath.length -gt 0)) {
        Add-Certificate -CertFilePath $CertPath
    }
    else {
        Add-Certificate
    }
}
else {
    Write-Err "Please run the script as admin"
}
