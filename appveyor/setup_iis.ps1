$ErrorActionPreference = "Stop"

Import-Module -Name WebAdministration

Function Create-WebSite($name, $cert, $cbt) {
    $site = Get-Website -Name $name -ErrorAction SilentlyContinue
    # site already exists so return
    if ($site) {
        return
    }
    if ($cbt) {
        $http_port = 81
        $https_port = 441
        $token_checking_value = "Require"
    } else {
        $http_port = 82
        $https_port = 442
        $token_checking_value = "None"
    }

    # create site with http binding
    $site = New-Website -Name $name -PhysicalPath "C:\temp\iisroot" -Port $http_port -IP "*"

    # add https binding with certificate passed in
    New-WebBinding -Name $name -Protocol https -Port $https_port -IP "*"
    $binding = Get-WebBinding -Name $name -Protocol https
    $binding.AddSslCertificate($cert.Thumbprint, "My")

    # disable Anonymous authentication
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name Enabled -Value False -PSPath IIS:\ -Location $name

    # enable Windows authentication
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name Enabled -Value True -PSPath IIS:\ -Location $name
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name tokenChecking -Value $token_checking_value -PSPath IIS:\ -Location $name
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name Flags -Value None -PSPath IIS:\ -Location $name
}

$cert = New-SelfSignedCertificate -DnsName ("127.0.0.1") -CertStoreLocation cert:\LocalMachine\My
$rootStore = Get-Item cert:\LocalMachine\Root
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close();

New-Item C:\temp -Type Directory -Force > $null
New-Item C:\temp\iisroot -Type Directory -Force > $null
New-Item C:\temp\iisroot\contents.txt -Type File -Force -Value "contents" > $null

Create-WebSite -name "Site1" -cert $cert -cbt $true
Create-WebSite -name "Site2" -cert $cert -cbt $false
