#
# Module manifest for module 'DFIR-O365RC'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = '.\DFIR-O365RC.psm1'

    # Version number of this module.
    ModuleVersion = '2.0.6'

    # Supported PSEditions
    CompatiblePSEditions = 'Core', 'Desktop'

    # ID used to uniquely identify this module
    GUID = '84b1ed98-447f-4d4e-aa52-fd9339cf7cca'

    # Author of this module
    Author = 'INM-CLOUD@ssi.gouv.fr'

    # Company or vendor of this module
    CompanyName = 'CERT-FR'

    # Description of the functionality provided by this module
    Description = 'The DFIR-O365RC module will extract logs from the unified audit log (using Exchange Online and Purview), Entra ID Sign In logs, Entra ID Audit Logs, Azure Monitor and Azure DevOps activity logs'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{ModuleName = 'Az.Accounts'; ModuleVersion = '3.0.2'; }
        @{ModuleName = 'Az.Monitor'; ModuleVersion = '5.2.1'; }
        @{ModuleName = 'Az.Resources'; ModuleVersion = '7.2.0'; }
        @{ModuleName = 'ExchangeOnlineManagement'; ModuleVersion = '3.5.1'; }
        @{ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0'; }
        @{ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '2.20.0'; }
        @{ModuleName = 'Microsoft.Graph.Beta.Reports'; ModuleVersion = '2.20.0'; }
        @{ModuleName = 'Microsoft.Graph.Beta.Security'; ModuleVersion = '2.20.0'; }
        @{ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '2.20.0'; }
        @{ModuleName = 'PoshRSJob'; ModuleVersion = '1.7.4.4'; }
    )

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'Get-AADApps.ps1',
        'Get-AADDevices.ps1',
        'Get-AADLogs.ps1',
        'Get-AzDevOpsActivityLogs.ps1',
        'Get-AzRMActivityLogs.ps1',
        'Get-O365.ps1',
        'Manage-Applications.ps1'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Connect-AzApplication',
        'Connect-AzUser',
        'Connect-ExchangeOnlineApplication',
        'Connect-ExchangeOnlineUser',
        'Connect-MicrosoftGraphApplication',
        'Connect-MicrosoftGraphUser',
        'Get-AADApps',
        'Get-AADDevices',
        'Get-AADLogs',
        'Get-AzDevOpsActivityLogs',
        'Get-AzDevOpsAuditLogs',
        'Get-AzDevOpsRestAPIResponseUser',
        'Get-AzRMActivityLogs',
        'Get-AzureRMActivityLog',
        'Get-LargeUnifiedAuditLog',
        'Get-MailboxAuditLog',
        'Get-MicrosoftGraphLogs',
        'Get-O365Defender',
        'Get-O365Full',
        'Get-O365Light',
        'Get-UnifiedAuditLogPurview',
        'New-Application',
        'Remove-Application',
        'Import-Certificate',
        'Search-O365',
        'Update-Application',
        'Write-Log'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @("O365", "Security", "Forensics", "DFIR", "Exchange", "Defender", "AzureAD", "MSGraph", "Azure", "DevOps", "Purview", "EntraID", "Logs")

            # ReleaseNotes of this module
            ReleaseNotes = '
                1.0.0 - Initial release
                1.1.0 - Added Get-AADDevices and Get-AzRMActivityLogs functions
                1.2.0 - Added Get-AzDevOpsActivityLogs function and added mailobx audit logs retrieval to the Search-O365 function
                2.0.0 - Rework of the project: use of an application to do the log collection, instead of an authenticated user. Add Purview
            '
        } # End of PSData hashtable
    } # End of PrivateData hashtable
}
