#Webpart Export Mode
#Module Initialisation

function Install-SharepointOnlineModule {
    #Define the name of the module you want to check/install
    $ModuleName = "Microsoft.Online.SharePoint.PowerShell"

    # Check if the module is already installed
    if (Get-Module -ListAvailable -Name $ModuleName) {
            Write-Host "The '$ModuleName' module is already installed."
    }
    else {
        Write-Host "The '$ModuleName' module is not installed. Installing..."
        
        # Try to install the module using the PowerShellGet module (requires PowerShell 5.0+)
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "Module '$ModuleName' has been installed successfully."
        }
        catch {
            Write-Host "Failed to install the module '$ModuleName'. Error: $_"
        }
    }    
}

#sites abfragen
$logEntry = Read-Host "Log Eintrag eingeben"

# Define a regular expression pattern to match the site URL
$pattern = "https:\/\/([^.]+\.sharepoint\.com)\/sites\/([^/\s]+)"

# Use the Select-String cmdlet to find matches based on the pattern
$matches = $logEntry | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches }

# Loop through each match and print the results
foreach ($match in $matches) {
    $siteURL = $match.Groups[0].Value
    $siteName = $match.Groups[2].Value
}

# Define the regular expression pattern to match the domain in the source URL
$pattern = "(https?://)([^/]+?)(?:-admin)?(\.sharepoint\.com)/.*"

# Use the regular expression to replace the domain and everything after ".com/" in the source URL
$adminUrl = [regex]::Replace($SiteUrl, $pattern, "`$1`$2-admin`$3/")

#Modul Installieren falls nötig
Install-SharepointOnlineModule

Connect-SPOService -Url $adminurl
Set-SPOSite $siteURL -DenyAddAndCustomizePages 0
try {
    Write-Host "Site $siteurl successfully updated"
}
catch {
    Write-Host "Site $sitename not updated, error"
}