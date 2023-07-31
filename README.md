# PSGIGR
Powershell Repository by Gian

## Installation
Installation with Powershell
```powershell
Install-Module PSGIGR
Import-Module PSGIGR
```

# Commands
All Commands explained

## Edit-WebpartExportMode
This command corrects the Veeam M365 Backup error. "Cannot change WebPart export mode."
```powershell
Edit-WebpartExportMode -logEntry [Complete Log of the Error]
```

## Set-ExchangeOnlineSetting
This command sets Exchange Online Defaults for each user. 
Settings:
- Language "Deutsch/Schweiz" and TimeZone W. Europe Standard Time
- Default Calendar Permissions "Reviewer" as Default
- Deactivate Focused Inbox for each user
```powershell
Set-ExchangeOnlineSetting
```

## Set-UserHomePermission
This command gives each user full access in his homefolder.
```powershell
Set-UserHomePermission -homespath [Path to Userhomes]
```