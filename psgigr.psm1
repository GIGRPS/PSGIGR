#-----------------------------------------------
#--------- define private functions ------------
#-----------------------------------------------
function Install-M365OnlineModule {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )    

    # Check if the module is already installed
    if (Get-Module -ListAvailable -Name $ModuleName) {
            Write-Output "The '$ModuleName' module is already installed."
            Import-Module -Name $ModuleName
    }
    else {
        Write-Output "The '$ModuleName' module is not installed. Installing..."
        
        # Try to install the module using the PowerShellGet module (requires PowerShell 5.0+)
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Import-Module -Name $ModuleName
            Write-Output "Module '$ModuleName' has been installed successfully."
        }
        catch {
            Write-Output "Failed to install the module '$ModuleName'. Error: $_"
        }
    }    
}
Function Get-RandomCharacter {
    param (
        [string]$characters
    )
    # Get one random character
    $randomIndex = Get-Random -Minimum 0 -Maximum ($characters.Length - 1)
    return $characters[$randomIndex]
}

#-----------------------------------------------
#---------- define public functions ------------
#-----------------------------------------------
function Edit-WebpartExportMode {
    <#
        .Synopsis
        Fixes the Veeam M365 Backup error. Cannot Change Web Part Export Mode.

        .Description
        Automatically fixes the error.

        .PARAMETER LogEntry
        Paste here the complete Veeam M365 Backup error.

        .Example
        # Input example
        Edit-WebpartExportMode -logEntry [LogEntry]
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$logEntry
    )
    # Define a regular expression pattern to match the site URL
    $pattern = "https:\/\/([^.]+\.sharepoint\.com)\/sites\/([^/\s]+)"

    # Use the Select-String cmdlet to find matches based on the pattern
    $patternmatches = $logEntry | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches }

    # Loop through each match and print the results
    foreach ($match in $patternmatches) {
        $siteURL = $match.Groups[0].Value
        $siteName = $match.Groups[2].Value
    }

    # Define the regular expression pattern to match the domain in the source URL
    $pattern = "(https?://)([^/]+?)(?:-admin)?(\.sharepoint\.com)/.*"

    # Use the regular expression to replace the domain and everything after ".com/" in the source URL
    $adminUrl = [regex]::Replace($SiteUrl, $pattern, "`$1`$2-admin`$3/")

    #Modul Installieren falls nötig
    Install-M365OnlineModule -ModuleName "Microsoft.Online.SharePoint.PowerShell"

    Connect-SPOService -Url $adminurl
    try {
        Set-SPOSite $siteURL -DenyAddAndCustomizePages 0
        Write-Output "Site $siteurl successfully updated"
    }
    catch {
        Write-Output "Site $sitename not updated, error"
    }
}

function Set-ExchangeOnlineSetting {
    <#
        .Synopsis
        RMD Standard Exchange Online Settings.

        .Description
        RMD Standard Exchange Online Settings.
     
        .Example
        # Input example
        Set-ExchangeOnlineSettings
    #>
    [CmdletBinding()]
    param (
        
    )    
    begin {
        Install-M365OnlineModule -ModuleName "ExchangeOnlineManagement"
        Connect-ExchangeOnline
    }
        
    process {
        Get-Mailbox | Set-MailboxRegionalConfiguration -Language 2055 -TimeZone "W. Europe Standard Time" -LocalizeDefaultFolderName

        $users = Get-Mailbox -Resultsize Unlimited
        foreach ($user in $users) {
            Write-Output "Setting permission for $($user.alias)..."
            Set-MailboxFolderPermission -Identity "$($user.alias):\kalender" -User Default -AccessRights Reviewer
        }
        # Zweimal nötig, damit die Einstellung wirklich hilft.
        Set-OrganizationConfig -FocusedInboxOn $false
        Set-OrganizationConfig -FocusedInboxOn $false
    }
}

function Set-UserHomePermission {
    <#
        .Synopsis
        Grants all Users Full Access in der Homes Folder.

        .Description
        Grants all Users Full Access in der Homes Folder.

        .PARAMETER Homespath
        Path to the Rootfolder of the Userhomes.

        .Example
        # Input example
        Set-UserhomePermission -homespath "D:\Userdata\Homes\"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$homespath
    )
    
    begin {
        #Initalize Variables
        $userfolders = Get-ChildItem $homespath
        $AccessType = "Allow"
        $Access = "FullControl"
        $inheritance  = "ContainerInherit,ObjectInherit"

    }
    
    process {
        #Schlaufe für alle Ordner in den Homes
        foreach ($userpath in $userfolders){
            $upn = $userpath.Name
            $userhomepath = "$homespath\$upn"
            $acl = Get-Acl $userhomepath
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:userdomain\$upn", $Access, $inheritance, "None", $AccessType)
            $acl.SetAccessRule($AccessRule)
            $acl | Set-Acl $userhomepath
        }
    }
}

function New-DCInstallation {
    <#
        .Synopsis
        Performs a DC Installation.

        .Description
        Performs a DC Installation.

        .PARAMETER ipaddress
        IP Address of the Server and Primary DNS Server after the installation.

        .PARAMETER subnetadress
        Subnet ex. 24 means 255.255.255.0

        .PARAMETER gateway
        Default Gateway for the Server

        .PARAMETER NETBIOS
        NETBIOS Name of the new domain

        .PARAMETER DomainName
        Fully Qualified Domain Name

        .PARAMETER DSRMPW 
        Defines the DSRM Password

        .PARAMETER DHCP
        Set this to $true if you want the feature DHCP Server installed.

        .Example
        # Input 
        New-DCInstallation -ipaddress 192.168.1.11 -subnetadress 24 -gateway 192.168.1.1 -NETBIOS CONTOSO -DomainName contoso.com -DSRMPW Test123 -DHCP $true
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ipaddress,
        [Parameter(Mandatory=$true)]
        [string]$subnetaddress,
        [Parameter(Mandatory=$true)]
        [string]$gateway,
        [Parameter(Mandatory=$true)]
        [string]$NETBIOS,
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        [Parameter(Mandatory=$true)]
        [string]$DSRMPW,
        [bool]$DHCP
    )
    
    begin { 
        #DefineIP Address
        Get-NetAdapter | New-NetIPAddress -IPAddress $ipaddress -PrefixLength $subnetaddress -DefaultGateway $gateway
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses 8.8.8.8
    }  
    process {
        $DSRMPWSec = $DSRMPW | ConvertTo-SecureString -AsPlainText -Force
        if($dhcp -eq "$true"){
        Install-WindowsFeature AD-Domain-Services,DNS,DHCP -IncludeManagementTools
        }
        else {
            Install-WindowsFeature AD-Domain-Services,DNS -IncludeManagementTools
        }
        Install-ADDSForest -DomainName $DomainName -Domainnetbiosname $netbios -InstallDns:$true -SafeModeAdministratorPassword $DSRMPWSec
    }    
    end {
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $ipaddress
    }
}
function Set-DCConfiguration {
    <#
        .Synopsis
        Set-DCConfiguration

        .Description
        Set-DCConfiguration

        .PARAMETER networkid
        Set Networkid example: 192.168.1

        .PARAMETER dnsredirect
        DNS Server Redirect

        .PARAMETER ouCustomer
        Main OU Name

        .Example
        # Input example
        Set-DCConfiguration -networkid 192.168.1 -dnsredirect 1.1.1.1 -ouCustomer "SBB"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$networkid,
        [Parameter(Mandatory=$true)]
        [string]$dnsredirect,
        [Parameter(Mandatory=$true)]
        [string]$ouCustomer
    )
    
    begin {
        function CreateADFrastructure {
            $dnDom = (Get-ADDomain).DistinguishedName
            New-ADOrganizationalUnit -Name $ouCustomer -Path $dnDom
            $dnCustomer = "OU=$ouCustomer,$dnDom"
        
            ###
            # OU Structure
            ###
        
            ##
            # Main (Infrastructure) OU
            $ouMain = "Infrastruktur Shared Cloud"
            New-ADOrganizationalUnit -Name $ouMain -Path $dnCustomer
            $dnMain = "OU=$ouMain,$dnCustomer"
            ##
        
            ##
            # Servers
            $ouServers = "Servers"
            New-ADOrganizationalUnit -Name $ouServers -Path $dnMain
            $dnServers = "OU=$ouServers,$dnMain"
            ##
        
            @(
            "Memberservers",
            "Terminalservers"
            ) | ForEach-Object {New-ADOrganizationalUnit -Name $_ -Path $dnServers}
        
            ##
            # Groups
            $ouGroups = "Groups"
            New-ADOrganizationalUnit -Name $ouGroups -Path $dnMain
            $dnGroups = "OU=$ouGroups,$dnMain"
            ##
        
            @(
            "Access",
            "Applications",
            "Citrix",
            "Drives",
            "KDS",
            "Mail",
            "Printers",
            "Roles",
            "Service Groups"
            ) | ForEach-Object {New-ADOrganizationalUnit -Name $_ -Path $dnGroups}
        
            #
        
            ##
            # Accounts
            $ouAccounts = "Accounts"
            New-ADOrganizationalUnit -Name $ouAccounts -Path $dnMain
            $dnAccounts = "OU=$ouAccounts,$dnMain"
            ##
        
            @(
            "Administrators",
            "Service Accounts",
            "Users"
            ) | ForEach-Object {New-ADOrganizationalUnit -Name $_ -Path $dnAccounts}
        }
        $domain = $env:USERDNSDOMAIN
    }
    
    process {
        #Set Time Sync
        w32tm /config /update /manualpeerlist:"ch.pool.ntp.org,0x8" /syncfromflags:MANUAL
        #Set Timezone
        Set-TimeZone -Id "W. Europe Standard Time"
        #Enable AD Recycle Bin
        Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $domain
        #Disable Spooler
        Set-Service "Spooler" -StartupType Disabled
        #Restrict Domain Joins per User
        Set-ADDomain $domain -Replace @{"ms-ds-MachineAccountQuota"="2"}
        #DNS Settings
        Set-DnsServerScavenging -ScavengingInterval 7.00:00:00 -ScavengingState $true
        Set-DnsServerForwarder -IPAddress $dnsredirect

        #DNS Reverselookupzone
        $networkidandsubnet = $networkid + ".0/24"
        $array = $networkid.Split(".")
        $reversenetworkid = $array[2] + "." + $array[1] + "." + $array[0]
        $reversezonename = $reversenetworkid + ".in-addr.arpa"
        Add-DnsServerPrimaryZone -NetworkId $networkidandsubnet -ReplicationScope forest

        #DNSSEC
        Invoke-DnsServerZoneSign -ZoneName $domain -SignWithDefault -Force
        Invoke-DnsServerZoneSign -ZoneName $reversezonename -SignWithDefault -Force

        #Create OU structure
        CreateADFrastructure
    }

    end {
        
    }
}
function Convert-Cert {
    <#
        .Synopsis
        Split PFX Cert into PEM and KEY

        .Description
        Split PFX Cert into PEM and KEY

        .PARAMETER Quelldatei
        Source file to convert

        .PARAMETER PEMdatei
        Destination for the PEM File

        .PARAMETER KEYdatei
        Destination for the KEY File

        .Example
        # Input example
        Convert-Cert -Quelldatei "C:\Temp\cert.pfx" -PEMdatei "C:\Temp\cert.pem" -KEYdatei "C:\Temp\cert.key"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Quelldatei,
        [Parameter(Mandatory=$true)]
        [string]$PEMdatei,
        [Parameter(Mandatory=$true)]
        [string]$KEYdatei
    )
    begin {
        Install-M365OnlineModule -ModuleName "PSKI"
    }    
    process {
        Convert-PfxToPem -InputFile $Quelldatei -Outputfile $PEMdatei

        (Get-Content $PEMdatei -Raw) -match "(?ms)(\s*((?<privatekey>-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)|(?<certificate>-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----))\s*){2}"

        $Matches["privatekey"] | Set-Content $KEYdatei
        $Matches["certificate"] | Set-Content $PEMdatei
    }
}
Function Get-RMDRandomPasswordUser {
    [CmdletBinding()]
    param (
        [int]$length = 12
    )
    Begin {
        # Define lower- uppercase, special characters, numbers
        $lowercase = "abcdefghijklmnopqrstuvwxyz"
        $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        $specialChars = "!@#$%^&*()_+=<>?"
        $numbers = "0123456789"
        $separators = "-_"
        
        # Define Password
        $password = ""
    }
    Process {
        # Add 4 uppercase Letters
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 4 lowercase Letters
        $password += Get-RandomCharacter -characters $lowercase
        $password += Get-RandomCharacter -characters $lowercase
        $password += Get-RandomCharacter -characters $lowercase
        $password += Get-RandomCharacter -characters $lowercase
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 2 numbers
        $password += Get-RandomCharacter -characters $numbers
        $password += Get-RandomCharacter -characters $numbers
        # Add 2 special characters
        $password += Get-RandomCharacter -characters $specialChars
        $password += Get-RandomCharacter -characters $specialChars
    }
    End {
        Return $password
    }
}
Function Get-RMDRandomPasswordAdmin {
    [CmdletBinding()]
    param (
        [int]$length = 12
    )
    Begin {
        # Define lower- uppercase, special characters, numbers
        $lowercase = "abcdefghijklmnopqrstuvwxyz"
        $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        $specialChars = "!@#$%^&*()-+=<>?"
        $numbers = "0123456789"
        $separators = "_-"

        # Define Password
        $password = ""
    }
    Process {
        # Add 3 numbers
        $password += Get-RandomCharacter -characters $numbers
        $password += Get-RandomCharacter -characters $numbers
        $password += Get-RandomCharacter -characters $numbers
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 3 lowercase letters
        $password += Get-RandomCharacter -characters $lowercase
        $password += Get-RandomCharacter -characters $lowercase
        $password += Get-RandomCharacter -characters $lowercase
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 3 uppercase letters
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 3 special characters
        $password += Get-RandomCharacter -characters $specialChars
        $password += Get-RandomCharacter -characters $specialChars
        $password += Get-RandomCharacter -characters $specialChars
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 3 numbers
        $password += Get-RandomCharacter -characters $numbers
        $password += Get-RandomCharacter -characters $numbers
        $password += Get-RandomCharacter -characters $numbers
        # Add separator
        $password += Get-RandomCharacter -characters $separators
        # Add 3 uppercase letters
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
        $password += Get-RandomCharacter -characters $uppercase
    }
    End {
        Return $password
    }
}