# What it does
Add the 'DigiCert Trusted Root G4' certificate to the Trusted Root Certification Authorities of the machine if it is not present. 

## Step by step working
1. Check certificate is existing on the machine. If already installed, exit.
2. If the file is passed as a parameter, Install the cert and exit. Else follow further steps
3. Try to download the file from the DigiCert website and add it. If this succeeds add the cert file to the root store. 
4. If nothing works, the script will ask the user to manually download it and pass the file as a parameter.

# How to use the script
Please check the script help to see the examples. To get the help, run

    Get-Help .\DigiCertUpdate.ps1 -Full

# Examples
* To update it from the internet 

        PS C:\> .\DigiCertUpdate.ps1

* To update it from a file path

        PS C:\> .\DigiCertUpdate.ps1 -CertPath <Cert File Path>

* Usage with proxy

        PS C:\> .\DigiCertUpdate.ps1 -ProxyAddress "10.10.10.10" -ProxyPort 3128 

* Proxy with credentials

        PS C:\> .\DigiCertUpdate.ps1 -ProxyAddress "10.10.10.10" -ProxyPort 3128 -ProxyUser "admin" -ProxyPassword "abc123"

# License
[License](/LICENSE.md)