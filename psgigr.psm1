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
    }
    else {
        Write-Output "The '$ModuleName' module is not installed. Installing..."
        
        # Try to install the module using the PowerShellGet module (requires PowerShell 5.0+)
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Output "Module '$ModuleName' has been installed successfully."
        }
        catch {
            Write-Output "Failed to install the module '$ModuleName'. Error: $_"
        }
    }    
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
        Show-Calendar
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
    Set-SPOSite $siteURL -DenyAddAndCustomizePages 0
    try {
        Write-Output "Site $siteurl successfully updated"
    }
    catch {
        Write-Output "Site $sitename not updated, error"
    }
}

function Set-ExchangeOnlineSettings {
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
            Write-Output -ForegroundColor green "Setting permission for $($user.alias)..."
            Set-MailboxFolderPermission -Identity "$($user.alias):\kalender" -User Default -AccessRights Reviewer
        }
        # Zweimal nötig, damit die Einstellung wirklich hilft.
        Set-OrganizationConfig -FocusedInboxOn $false
        Set-OrganizationConfig -FocusedInboxOn $false
    }
}