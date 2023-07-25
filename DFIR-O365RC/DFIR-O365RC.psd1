#
# Module manifest for module 'DFIR-O365RC'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\DFIR-O365RC.psm1'

# Version number of this module.
ModuleVersion = '1.2.0'

# Supported PSEditions
CompatiblePSEditions = 'Core', 'Desktop'

# ID used to uniquely identify this module
GUID = '84b1ed98-447f-4d4e-aa52-fd9339cf7cca'

# Author of this module
Author = 'leonard.savina@ssi.gouv.fr'

# Company or vendor of this module
CompanyName = 'CERT-FR'

# Description of the functionality provided by this module
Description = 'The DFIR-O365RC module will extract logs from O365 Unified audit logs, Azure AD signin logs, Azure AD audit logs, Azure RM and DevOps activity logs'


# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'



# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @(
    @{ModuleName = 'PoshRSJob'; ModuleVersion = '1.7.4.4'; },
    @{ModuleName = 'MSAL.PS'; ModuleVersion = '4.37.0.0'; }
    @{ModuleName = 'ExchangeOnlineManagement'; ModuleVersion = '3.1.0'; }
    )



# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess

NestedModules = @(
    'Get-O365Full.ps1',
    'Get-O365Light.ps1',
    'Get-AADApps.ps1',
    'Get-DefenderforO365.ps1',
    'Search-O365.ps1',
    'Get-AADDevices.ps1',
    'Get-AzRMActivityLogs.ps1',
    'Get-AzDevOpsActivityLogs.ps1',
    'Get-AADLogs.ps1'
)

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport =  'Get-OAuthToken', 'Get-RestAPIResponse', 'Connect-EXOPsearchUnified', 'Get-LargeUnifiedAuditLog', 'Get-MailboxAuditLog', 'Get-AADApps', 'Get-AADLogs', 'Get-O365Full', 'Get-O365Light', 'Get-DefenderforO365', 'Search-O365', 'Get-AADDevices', 'Get-AzRMActivityLogs', 'Write-Log', 'Get-AzDevOpsActivityLogs'


# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()


# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("O365","Security","Forensics","DFIR","Exchange","Defender","AzureAD","MSGraph","Azure", "DevOps")


        # ReleaseNotes of this module
        ReleaseNotes ='
        1.0.0 - Initial release
        1.1.0 - Added Get-AADDevices and Get-AzRMActivityLogs functions
        1.2.0 - Added Get-AzDevOpsActivityLogs function and added mailobx audit logs retrieval to the Search-o365 function
         '


    } # End of PSData hashtable

} # End of PrivateData hashtable



}
