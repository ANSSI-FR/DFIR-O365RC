function Get-AADApps {

    <#
    .SYNOPSIS
    The Get-AADApps function dumps in JSON files Entra ID applications and Service Principals related events for a specific time range and tries to enrich the objects with the application or service principal configurations.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"
    PS C:\>$endDate = Get-Date
    PS C:\>$startDate = $endDate.AddDays(-30)

    PS C:\>Get-AADApps -startDate $startDate -endDate $endDate -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID applications and Service Principals related events for the last 30 days.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$startDate,
        [Parameter(Mandatory = $true)]
        [DateTime]$endDate,
        [Parameter(Mandatory = $true)]
        [String]$certificatePath,
        [Parameter(Mandatory = $true)]
        [String]$appId,
        [Parameter(Mandatory = $true)]
        [String]$tenant,
        [Parameter(Mandatory = $false)]
        [String]$logFile = "Get-AADApps.log"
    )

    $currentPath = (Get-Location).path

    $logFile = $currentPath + "\" + $logFile

    $folderToProcess = $currentPath + '\azure_ad_apps'
    if ((Test-Path $folderToProcess) -eq $false){
        New-Item $folderToProcess -Type Directory | Out-Null
    }
    $outputFile = $folderToProcess + "\AADApps_" + $tenant + ".json"

    $maxStartDate = (Get-Date).AddDays(-30)
    if ($startDate -lt $maxStartDate){
        Write-Warning "You can only get events in the last 30 days with the Audit Log. Setting startDate to $maxStartDate"
        "You can only get events in the last 30 days with the Audit Log. Setting startDate to $maxStartDate" | Write-Log -LogPath $logFile -LogLevel "Warning"
        if ($endDate -lt $maxStartDate){
            Write-Host "Incompatible endDate: $endDate. Exiting"
            "Incompatible endDate: $endDate. Exiting" | Write-Log -LogPath $logFile
            exit
        }
        $startDate = $maxStartDate
    }

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile
    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile

    # Check if Microsoft Entra ID P1 is enabled
    "Checking Microsoft Entra ID P1"| Write-Log -LogPath $logFile
    try {
        $null = Get-MgBetaAuditLogSignIn -Top 1 -All -ErrorAction Stop
    }
    catch {
        if ($_.ErrorDetails.Message -like "*RequestFromNonPremiumTenant*"){
            Write-Warning "Entra ID P1 is not enabled tenant-wide. You should buy at least one Entra ID P1 licence to be able to retrieve the full audit log"
            "Entra ID P1 is not enabled tenant-wide. You should buy at least one Entra ID P1 licence to be able to retrieve the full audit log" | Write-Log -LogPath $logFile -LogLevel "Warning"
            $maxStartDate = (Get-Date).AddDays(-7)
            if ($startDate -lt $maxStartDate){
                Write-Warning "Entra ID P1 not enabled tenant-wide, you can only get 7 days of Audit Log. Setting startDate to $maxStartDate"
                "Entra ID P1 not enabled tenant-wide, you can only get 7 days of Audit Log. Setting startDate to $maxStartDate" | Write-Log -LogPath $logFile -LogLevel "Warning"
                $startDate = [DateTime]$maxStartDate.ToString("yyyy-MM-dd")
                if ($endDate -lt $startDate){
                    Write-Error "Incompatible endDate: $endDate. Exiting"
                    "Incompatible endDate: $endDate. Exiting" | Write-Log -LogPath $logFile -LogLevel "Error"
                    exit
                }
            }
        }
    }

    # Get service principal related events
    $auditStart = "{0:s}" -f $startDate + "Z"
    $auditEnd = "{0:s}" -f $endDate + "Z"
    "Getting all service principal related events via Audit Log" | Write-Log -LogPath $logFile
    $servicePrincipalEvents = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($auditStart) and activityDateTime lt $($auditEnd) and (activityDisplayName eq 'Consent to application' or activityDisplayName eq 'Add app role assignment to service principal' or activityDisplayName eq 'Add delegated permission grant' or activityDisplayName eq 'Add service principal credentials' or activityDisplayName eq 'Add service principal' or activityDisplayName eq 'Add OAuth2PermissionGrant')" -ErrorAction Stop
    if ($null -ne $servicePrincipalEvents){$servicePrincipalEvents = $servicePrincipalEvents.ToJsonString() | ConvertFrom-Json}

    # Get all service principals
    "Getting all service principals" | Write-Log -LogPath $logFile
    $allServicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
    if ($null -ne $allServicePrincipals){$allServicePrincipals = $allServicePrincipals.ToJsonString() | ConvertFrom-Json}
    $servicePrincipalsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_service_principals_raw.json"
    $allServicePrincipals | ConvertTo-Json -Depth 99 | Out-File $servicePrincipalsOutputFile -Encoding UTF8

    # Get all deleted service principals
    "Getting all deleted service principals" | Write-Log -LogPath $logFile
    $deletedServicePrincipals = Get-MgDirectoryDeletedItemAsServicePrincipal -All -ErrorAction Stop
    if ($null -ne $deletedServicePrincipals){$deletedServicePrincipals = $deletedServicePrincipals.ToJsonString() | ConvertFrom-Json}
    $deletedServicePrincipalsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_deleted_service_principals_raw.json"
    $deletedServicePrincipals | ConvertTo-Json -Depth 99 | Out-File $deletedServicePrincipalsOutputFile -Encoding UTF8

    $enrichedServicePrincipalEvents = @()
    $uniqueServicePrincipals = $servicePrincipalEvents | Select-Object -ExpandProperty targetResources | Group-Object -Property Id

    # Loop through Service Principals seen in Audit Log
    foreach ($uniqueServicePrincipal in $uniqueServicePrincipals){
        # Get Service Principal object
        $servicePrincipalObject = $allServicePrincipals | Where-Object {$_.Id -eq $uniqueServicePrincipal.Name}
        if ($null -eq $servicePrincipalObject){
            $servicePrincipalObject = $deletedServicePrincipals | Where-Object {$_.Id -eq $uniqueServicePrincipal.Name}
        }
        $eventsPerServicePrincipal = $servicePrincipalEvents | Where-Object { $_.targetResources.Id -eq $uniqueServicePrincipal.Name}

        if ($servicePrincipalObject){
            "Getting OAuth2PermissionGrants for $($uniqueServicePrincipal.Name) Service Principal" | Write-Log -LogPath $logFile
            try {
                $servicePrincipalOAuth = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $($uniqueServicePrincipal.Name) -All -ErrorAction Stop
                if ($null -ne $servicePrincipalOAuth){$servicePrincipalOAuth = $servicePrincipalOAuth.ToJsonString() | ConvertFrom-Json}
                $delegatedConsentAutorisations = (($servicePrincipalOAuth | Group-Object -Property Scope).Name) -join ","
                $delegatedConsentTypes = (($servicePrincipalOAuth | Group-Object -Property ConsentType).Name) -join ","
            }
            catch {
                "No OAuth2PermissionGrants for (deleted) $($uniqueServicePrincipal.Name) Service Principal" | Write-Log -LogPath $logFile -LogLevel "Warning"
                $delegatedConsentAutorisations = $null
                $delegatedConsentTypes = $null
            }

            "Getting appRoleAssignments for $($uniqueServicePrincipal.Name) Service Principal" | Write-Log -LogPath $logFile
            try {
                $servicePrincipalAppRoleAssignement = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $($uniqueServicePrincipal.Name) -All -ErrorAction Stop
                if ($null -ne $servicePrincipalAppRoleAssignement){$servicePrincipalAppRoleAssignement = $servicePrincipalAppRoleAssignement.ToJsonString() | ConvertFrom-Json}
                $appRoleIdAssignements = (($servicePrincipalAppRoleAssignement | Group-Object -Property AppRoleId).Name) -join ","
            }
            catch {
                "No appRoleAssignments for (deleted) $($uniqueServicePrincipal.Name) Service Principal" | Write-Log -LogPath $logFile -LogLevel "Warning"
                $appRoleIdAssignements = $null
            }

            if (-not ($null -eq $appRoleIdAssignements)){$eventsPerServicePrincipal | Add-Member -MemberType NoteProperty -Name "servicePrincipal_appRoleIdAssignements" -Value $appRoleIdAssignements -Force}
            if (-not ($null -eq $delegatedConsentAutorisations)){$eventsPerServicePrincipal | Add-Member -MemberType NoteProperty -Name "servicePrincipal_delegatedConsentAutorisations" -Value $delegatedConsentAutorisations -Force}
            if (-not ($null -eq $delegatedConsentTypes)){$eventsPerServicePrincipal | Add-Member -MemberType NoteProperty -Name "servicePrincipal_delegatedConsentTypes" -Value $delegatedConsentTypes -Force}

            $servicePrincipalObject.PSObject.Properties | ForEach-Object {
                $newPropertyName = "servicePrincipal_$($_.Name)"
                if (-not ($eventsPerServicePrincipal.PSObject.Properties.Name -contains $newPropertyName)){
                    $eventsPerServicePrincipal | Add-Member -MemberType NoteProperty -Name $newPropertyName -Value $_.Value -Force
                } 
            }
        }

        # If the consent is not successful or the ServicePrincipal was deleted.
        else {
            "The service principal $($uniqueServicePrincipal.Name) does not exist in the tenant, creation operation failed or the service principal was deleted" | Write-Log -LogPath $logFile
        }
        $enrichedServicePrincipalEvents += $eventsPerServicePrincipal
    }

    # Get application related events
    "Getting all application related events via Audit Log" | Write-Log -LogPath $logFile
    $auditStart = "{0:s}" -f $startDate + "Z"
    $auditEnd = "{0:s}" -f $endDate + "Z"

    $appEvents = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($auditStart) and activityDateTime lt $($auditEnd) and (activityDisplayName eq 'Add application' or startswith(activityDisplayName, 'Update application'))" -ErrorAction Stop
    if ($null -ne $appEvents){$appEvents = $appEvents.ToJsonString() | ConvertFrom-Json}

    # Get all applications
    "Getting all existing applications" | Write-Log -LogPath $logFile
    $existingApplications = Get-MgApplication -All -ErrorAction Stop
    if ($null -ne $existingApplications){$existingApplications = $existingApplications.ToJsonString() | ConvertFrom-Json}
    $existingApplicationsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_existing_applications_raw.json"
    $existingApplications | ConvertTo-Json -Depth 99 | Out-File $existingApplicationsOutputFile -Encoding UTF8

    # Get all deleted applications
    "Getting all deleted applications" | Write-Log -LogPath $logFile
    $deletedApplications = Get-MgDirectoryDeletedItemAsApplication -All -ErrorAction Stop
    if ($null -ne $deletedApplications){$deletedApplications = $deletedApplications.ToJsonString() | ConvertFrom-Json}
    $deletedApplicationsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_deleted_applications_raw.json"
    $deletedApplications | ConvertTo-Json -Depth 99 | Out-File $deletedApplicationsOutputFile -Encoding UTF8

    $enrichedAppEvents = @()
    $uniqueApplications = $appEvents | Select-Object -ExpandProperty targetResources | Group-Object -Property Id

    # Loop through applications present in audit log
    foreach ($uniqueApplication in $uniqueApplications){
        # Get Application object
        $applicationObject = $existingApplications | Where-Object {$_.Id -eq $uniqueApplication.Name}
        if ($null -eq $applicationObject){
            $applicationObject = $deletedApplications | Where-Object {$_.Id -eq $uniqueApplication.Name}
        }
        $eventsPerApplication = $appEvents | Where-Object { $_.targetResources.id -eq $uniqueApplication.Name}
        if ($applicationObject){
            $applicationObject.PSObject.Properties | ForEach-Object {
                $newPropertyName = "application_$($_.Name)"
                if (-not ($eventsPerApplication.PSObject.Properties.Name -contains $newPropertyName)){
                    $eventsPerApplication | Add-Member -MemberType NoteProperty -Name $newPropertyName -Value $_.Value -Force
                } 
            }
        }
        else {
            "The application $($uniqueApplication.Name) does not exist in the tenant" | Write-Log -LogPath $logFile
        }
        $enrichedAppEvents += $eventsPerApplication
    }

    $nbEnrichedApplicationEvents = ($enrichedAppEvents | Measure-Object).Count
    "Collected $($nbEnrichedApplicationEvents) enriched application related events" | Write-Log -LogPath $logFile

    $nbEnrichedServicePrincipalEvents = ($enrichedServicePrincipalEvents | Measure-Object).Count
    "Collected $($nbEnrichedServicePrincipalEvents) enriched service principal related events" | Write-Log -LogPath $logFile

    $totalEnrichedEvents = $nbEnrichedServicePrincipalEvents + $nbEnrichedApplicationEvents
    "Dumping $($totalEnrichedEvents) enriched events to $($outputFile)" | Write-Log -LogPath $logFile

    @($enrichedAppEvents; $enrichedServicePrincipalEvents) | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
