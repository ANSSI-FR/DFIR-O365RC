function Get-AADApps {

    <#
    .SYNOPSIS
    The Get-AADApps function dumps in JSON files Entra ID applications and (enriched) Service Principals. The objets are enriched with application, oauth2PermissionGrant and appRoleAssignment.

    .EXAMPLE

    PS C:\>$appId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    PS C:\>$tenant = "example.onmicrosoft.com"
    PS C:\>$certificatePath = "./example.pfx"

    PS C:\>Get-AADApps -appId $appId -tenant $tenant -certificatePath $certificatePath

    Dump all Entra ID applications and (enriched) Service Principals.
    #>

    param (
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

    $cert, $null, $null = Import-Certificate -certificatePath $certificatePath -logFile $logFile
    Connect-MicrosoftGraphApplication -certificate $cert -appId $appId -tenant $tenant -logFile $logFile
    
    # Get all existing existing applications
    "Getting all existing applications" | Write-Log -LogPath $logFile
    $existingApplications = Get-MgApplication -All -ErrorAction Stop

    # Get all deleted applications
    "Getting all deleted applications" | Write-Log -LogPath $logFile
    $deletedApplications = Get-MgDirectoryDeletedItemAsApplication -All -ErrorAction Stop
    $deletedApplications | ForEach-Object {$_.Add("deleted", $true)}
    
    $allApplications = @($existingApplications) + @($deletedApplications)
    if ($null -ne $allApplications -and $allApplications.Count -ne 0){$allApplications = $allApplications.ToJsonString() | ConvertFrom-Json}
    $allApplicationsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_applications_raw.json"
    $allApplications | ConvertTo-Json -Depth 99 | Out-File $allApplicationsOutputFile -Encoding UTF8
    "Got $($allApplications.Count) applications" | Write-Log -LogPath $logFile

    # Get all existing servicedeletedServicePrincipals principals
    "Getting all existing service principals" | Write-Log -LogPath $logFile
    $existingServicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop

    # Get all deleted service principals
    "Getting all deleted service principals" | Write-Log -LogPath $logFile
    $deletedServicePrincipals = Get-MgDirectoryDeletedItemAsServicePrincipal -All -ErrorAction Stop
    $deletedServicePrincipals | ForEach-Object {$_.Add("deleted", $true)}

    $allServicePrincipals = @($existingServicePrincipals) + @($deletedServicePrincipals)
    if ($null -ne $allServicePrincipals -and $allServicePrincipals.Count -ne 0){$allServicePrincipals = $allServicePrincipals.ToJsonString() | ConvertFrom-Json}
    $allServicePrincipalsOutputFile = $folderToProcess + "\AADApps_" + $tenant + "_service_principals_raw.json"
    $allServicePrincipals | ConvertTo-Json -Depth 99 | Out-File $allServicePrincipalsOutputFile -Encoding UTF8
    "Got $($allServicePrincipals.Count) service principals" | Write-Log -LogPath $logFile

    # Loop through Service Principals
    for ($i=0; $i -lt $allServicePrincipals.Length; $i += 1){
        $servicePrincipal = $allServicePrincipals[$i]
        "Getting corresponding application for $($servicePrincipal.displayName) Service Principal" | Write-Log -LogPath $logFile
        $applicationObject = $allApplications | Where-Object {$_.appId -eq $servicePrincipal.appId}
        if ($applicationObject -eq $null){
            "No corresponding application for $($servicePrincipal.displayName) Service Principal. This is expected if the application is made by Azure/another tenant" | Write-Log -LogPath $logFile
        }
        else {
            $allServicePrincipals[$i] | Add-Member -MemberType NoteProperty -Name "application" -Value $applicationObject -Force
        }

        if (-not $servicePrincipal.deleted){
            "Getting OAuth2PermissionGrants for $($servicePrincipal.displayName) Service Principal" | Write-Log -LogPath $logFile
            $servicePrincipalOAuth = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $($servicePrincipal.id) -All -ErrorAction Stop
            if ($null -ne $servicePrincipalOAuth){
                $servicePrincipalOAuth = $servicePrincipalOAuth.ToJsonString() | ConvertFrom-Json
                $allServicePrincipals[$i] | Add-Member -MemberType NoteProperty -Name "oauth2PermissionGrant" -Value $servicePrincipalOAuth -Force
            }

            "Getting appRoleAssignments for $($servicePrincipal.displayName) Service Principal" | Write-Log -LogPath $logFile
            $servicePrincipalAppRoleAssignement = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $($servicePrincipal.id) -All -ErrorAction Stop
            if ($null -ne $servicePrincipalAppRoleAssignement){
                $servicePrincipalAppRoleAssignement = $servicePrincipalAppRoleAssignement.ToJsonString() | ConvertFrom-Json
                $allServicePrincipals[$i] | Add-Member -MemberType NoteProperty -Name "appRoleAssignment" -Value $servicePrincipalAppRoleAssignement -Force
            }
        }
    }
    $allServicePrincipals | ConvertTo-Json -Depth 99 | Out-File $outputFile -Encoding UTF8
}
